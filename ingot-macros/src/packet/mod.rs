use bitfield::PrimitiveInBitfield;
use darling::ast;
use darling::ast::Fields;
use darling::FromDeriveInput;
use darling::FromField;
use darling::FromMeta;
use proc_macro2::Ident;
use proc_macro2::Span;
use proc_macro2::TokenStream;
use quote::quote;
use regex::Regex;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use syn::spanned::Spanned;
use syn::Error;
use syn::Expr;
use syn::ExprLit;
use syn::Lit;
use syn::Type;
use syn::TypeArray;

mod bitfield;

type Shared<T> = Rc<RefCell<T>>;

#[derive(Clone, FromDeriveInput)]
#[darling(attributes(ingot), supports(struct_named))]
pub struct IngotArgs {
    ident: Ident,
    data: ast::Data<(), FieldArgs>,
}

#[derive(Clone, FromMeta, Default)]
#[darling(default)]
pub struct NextLayerSpec {
    #[darling(default)]
    or_extension: bool,
}

#[derive(Clone, FromField)]
#[darling(attributes(ingot))]
pub struct FieldArgs {
    is: Option<Type>,
    next_layer: Option<NextLayerSpec>,
    var_len: Option<Expr>,
    #[darling(default)]
    subparse: bool,

    ident: Option<syn::Ident>,
    ty: Type,
}

struct ValidField2 {
    /// The name of this field.
    ident: Ident,
    /// The index of this field.
    idx: usize,
    /// The user-facing type for this field.
    user_ty: Type,
    /// The subelement within a `Valid` block this field
    /// is stored within. This field may *be* that subelement.
    sub_field_idx: usize,

    // per-el state.
    state: FieldState,
}

enum FieldState {
    /// Simple fields. May be
    FixedWidth {
        /// The base representation of a type in terms of primitives.
        underlying_ty: Type,
        ///
        first_bit_in_chunk: usize,

        // from analysed
        /// Number of bits contained within this field.
        cached_bits: usize,
        ty: ReprType,
        is_all_rust_primitives: bool,

        /// Extra state needed to unpack this field if we have
        /// stuck it in a bitfield
        bitfield_info: Option<PrimitiveInBitfield>,
    },
    /// Byte-aligned (sz + offset) variable-width fields.
    /// (Really, just byte arrays.)
    VarWidth { length_fn: Expr },
    /// Byte-aligned (sz + offset) var-width fields which may have a
    /// capped length assigned.
    Parsable {
        /// Parsable blocks don't *need* to be length delimited,
        /// but we can occasionally make the guarantee
        length_fn: Option<Expr>,
    },
}

struct StructParseDeriveCtx {
    ident: Ident,
    data: Fields<FieldArgs>,

    validated: HashMap<Ident, Shared<ValidField2>>,
    validated_order: Vec<Shared<ValidField2>>,

    nominated_next_header: Option<Ident>,
}

impl StructParseDeriveCtx {
    pub fn new(input: IngotArgs) -> Result<Self, syn::Error> {
        let IngotArgs { ident, data } = input;
        let field_data = data.take_struct().unwrap();
        let mut validated = HashMap::new();
        let validated_order: RefCell<Vec<Shared<ValidField2>>> = vec![].into();
        let mut nominated_next_header = None;

        let sub_field_idx = RefCell::new(0);
        let curr_chunk_bits: RefCell<Option<usize>> = None.into();

        let finalize_chunk = || {
            let mut q = sub_field_idx.borrow_mut();
            *q += 1;
            let bits = curr_chunk_bits.take();

            match bits {
                Some(v) if v % 8 != 0 => Err(Error::new(
                    validated_order
                        .borrow()
                        .last()
                        .unwrap()
                        .borrow()
                        .user_ty
                        .span(),
                    format!("fields are not byte-aligned -- total {v}b"),
                )),
                _ => Ok(()),
            }
        };

        for (idx, field) in field_data.fields.iter().enumerate() {
            let field_ident = field.ident.as_ref().unwrap().clone();
            let user_ty = field.ty.clone();

            let state = match (
                field.subparse,
                &field.var_len,
                &field.next_layer,
            ) {
                (true, length_fn, None) => {
                    finalize_chunk()?;
                    FieldState::Parsable { length_fn: length_fn.clone() }
                }
                (_, Some(length_fn), None) => {
                    finalize_chunk()?;
                    FieldState::VarWidth { length_fn: length_fn.clone() }
                }
                (false, None, next_layer) => {
                    let underlying_ty =
                        if let Some(ty) = &field.is { ty } else { &field.ty }
                            .clone();
                    let analysis = FixedWidth::from_ty(&underlying_ty)?;
                    let n_bits = analysis.cached_bits;

                    let mut ccb_ref = curr_chunk_bits.borrow_mut();
                    let curr_chunk_bits = ccb_ref.get_or_insert(0);
                    let first_bit_in_chunk = *curr_chunk_bits;
                    *curr_chunk_bits += analysis.cached_bits;

                    if analysis.ty.is_aggregate()
                        && (*curr_chunk_bits % 8 != 0 || n_bits % 8 != 0)
                    {
                        return Err(Error::new(
                            underlying_ty.span(),
                            "aggregate types must be byte-aligned at their start and end",
                        ));
                    }

                    if let Some(nl) = next_layer {
                        if nominated_next_header.is_some() {
                            return Err(Error::new(
                                field_ident.span(),
                                "only one field can be nominated as a next-header hint",
                            ));
                        }

                        if nl.or_extension {
                            todo!("integrated extension parsing not yet ready")
                        }

                        nominated_next_header = Some(field_ident.clone());
                    }

                    FieldState::FixedWidth {
                        underlying_ty,
                        first_bit_in_chunk,
                        cached_bits: analysis.cached_bits,
                        ty: analysis.ty,
                        is_all_rust_primitives: analysis.is_all_rust_primitives,
                        bitfield_info: None,
                    }
                }
                _ => {
                    return Err(syn::Error::new(
                        field.ty.span(),
                        "only fixed-width field can be used as next header",
                    ))
                }
            };

            let valid_field = ValidField2 {
                ident: field_ident.clone(),
                idx,
                user_ty,
                sub_field_idx: *sub_field_idx.borrow(),
                state,
            };

            let shared_field = Rc::new(RefCell::new(valid_field));
            validated.insert(field_ident, shared_field.clone());
            validated_order.borrow_mut().push(shared_field);
        }

        finalize_chunk()?;

        let validated_order = validated_order.into_inner();

        Ok(Self {
            ident,
            data: field_data,
            validated,
            validated_order,
            nominated_next_header,
        })
    }

    pub fn validated_ident(&self) -> Ident {
        let ident = &self.ident;
        Ident::new(&format!("Valid{ident}"), ident.span())
    }
    pub fn ref_ident(&self) -> Ident {
        let ident = &self.ident;
        Ident::new(&format!("{ident}Ref"), ident.span())
    }
    pub fn mut_ident(&self) -> Ident {
        let ident = &self.ident;
        Ident::new(&format!("{ident}Mut"), ident.span())
    }
    pub fn pkt_ident(&self) -> Ident {
        let ident = &self.ident;
        Ident::new(&format!("{ident}Packet"), ident.span())
    }
    pub fn private_mod_ident(&self) -> Ident {
        let ident = &self.ident;
        Ident::new(&format!("_{ident}_ingot_impl"), ident.span())
    }

    pub fn gen_next_header_lookup(&self) -> TokenStream {
        let ident = &self.ident;
        let validated_ident = self.validated_ident();

        if let Some(field_ident) = &self.nominated_next_header {
            let user_ty =
                &self.validated.get(&field_ident).unwrap().borrow().user_ty;
            quote! {
                impl<V: ::zerocopy::ByteSlice> ::ingot_types::NextLayer for #validated_ident<V> {
                    type Denom = #user_ty;

                    #[inline]
                    fn next_layer(&self) -> ::ingot_types::ParseResult<Self::Denom> {
                        ::core::result::Result::Ok(self.#field_ident())
                    }
                }

                impl ::ingot_types::NextLayer for #ident {
                    type Denom = #user_ty;

                    #[inline]
                    fn next_layer(&self) -> ::ingot_types::ParseResult<Self::Denom> {
                        ::core::result::Result::Ok(self.#field_ident)
                    }
                }
            }
        } else {
            quote! {
                impl<V: ::zerocopy::ByteSlice> ::ingot_types::NextLayer for #validated_ident<V> {
                    type Denom = ();

                    #[inline]
                    fn next_layer(&self) -> ::ingot_types::ParseResult<Self::Denom> {
                        ::core::result::Result::Err(::ingot_types::ParseError::NoHint)
                    }
                }

                impl ::ingot_types::NextLayer for #ident {
                    type Denom = ();

                    #[inline]
                    fn next_layer(&self) -> ::ingot_types::ParseResult<Self::Denom> {
                        ::core::result::Result::Err(::ingot_types::ParseError::NoHint)
                    }
                }
            }
        }
    }
}

struct FirstPass {
    variant: FieldType,
    base_args: FieldArgs,
}

enum FieldType {
    FixedWidth,
    VarWidth,
    Parsable,
}

#[derive(Clone, Debug)]
struct HybridField {
    ident: Ident,
    n_bits: usize,
    first_bit: usize,
}

struct ValidField {
    repr: Type,
    ident: Ident,
    user_ty: Type,

    first_bit: usize,
    analysis: Analysed,

    /// indicates child field of the
    sub_ref_idx: usize,
    hybrid: Option<PrimitiveInBitfield>,
}

impl ValidField {
    fn getter_name(&self) -> &Ident {
        &self.ident
    }

    fn ref_name(&self) -> Ident {
        Ident::new(&format!("{}_ref", self.ident), self.ident.span())
    }

    fn mut_name(&self) -> Ident {
        Ident::new(&format!("{}_mut", self.ident), self.ident.span())
    }

    fn setter_name(&self) -> Ident {
        Ident::new(&format!("set_{}", self.ident), self.ident.span())
    }

    fn is_primitive(&self) -> bool {
        if let Analysed::FixedWidth(fw) = &self.analysis {
            matches!(fw.ty, ReprType::Primitive { .. })
        } else {
            false
        }
    }
}

#[derive(Copy, Clone)]
enum Endianness {
    Big,
    Little,
    Host,
}

impl Endianness {
    fn std_from_bytes_method(self) -> Ident {
        let label = match self {
            Endianness::Big => "be",
            Endianness::Little => "le",
            Endianness::Host => "ne",
        };

        Ident::new(&format!("from_{label}_bytes"), Span::mixed_site())
    }

    fn std_to_bytes_method(self) -> Ident {
        let label = match self {
            Endianness::Big => "be",
            Endianness::Little => "le",
            Endianness::Host => "ne",
        };

        Ident::new(&format!("to_{label}_bytes"), Span::mixed_site())
    }

    fn is_little_endian(self) -> bool {
        match self {
            Endianness::Big => false,
            Endianness::Little => true,
            Endianness::Host => cfg!(target_endian = "little"),
        }
    }
}

enum ReprType {
    Array { child: Box<FixedWidth>, length: usize },
    Tuple { children: Vec<FixedWidth> },
    Primitive { base_ident: Ident, bits: usize, endian: Option<Endianness> },
}

impl ReprType {
    fn is_aggregate(&self) -> bool {
        !matches!(self, ReprType::Primitive { .. })
    }
}

enum Analysed {
    FixedWidth(FixedWidth),
    VarWidth(Expr),
    Parsable,
}

struct FixedWidth {
    cached_bits: usize,
    ty: ReprType,
    is_all_rust_primitives: bool,
}

impl FixedWidth {
    fn get_primitive_endianness(&self) -> Option<Endianness> {
        match self.ty {
            ReprType::Primitive { endian, .. } => endian,
            _ => None,
        }
    }
}

struct ZcType {
    repr: Type,
    transformed: bool,
}

impl FixedWidth {
    fn from_ty(ty: &Type) -> Result<Self, syn::Error> {
        match ty {
            e @ Type::Array(TypeArray{ elem, len: Expr::Lit(ExprLit{lit: Lit::Int(l), ..}), .. })  => {
                let analysed = Self::from_ty(elem)?;
                let length = l.base10_parse::<usize>()?;

                // TODO: allow only [u8; N]?
                if analysed.cached_bits != 8 && !matches!(analysed.ty, ReprType::Primitive { .. }) {
                    return Err(Error::new(e.span(), "array reprs may only contain `u8`s"));
                }

                Ok(FixedWidth {
                    cached_bits: analysed.cached_bits * length,
                    is_all_rust_primitives: analysed.is_all_rust_primitives,
                    ty: ReprType::Array { child: analysed.into(), length },
                })
            },
            e @ Type::Array(TypeArray{ .. })  => {
                Err(Error::new(e.span(), "array length must be an integer literal"))
            }
            Type::Tuple(a) => {
                // TODO: outlaw this while I work on more big-ticket issues.
                return Err(Error::new(a.span(), "tuple types are not currently allowed as reprs"));

                let mut n_bits = 0;
                let mut children = vec![];
                let mut is_all_rust_primitives = true;

                for elem in &a.elems {
                    let analysed = Self::from_ty(elem)?;
                    n_bits += analysed.cached_bits;
                    children.push(analysed);
                    is_all_rust_primitives &= analysed.is_all_rust_primitives;
                }

                // Ok(n_bits)
                Ok(FixedWidth { cached_bits: n_bits, ty: ReprType::Tuple { children }, is_all_rust_primitives })
            },
            Type::Path(a) => {
                let b = a.path.require_ident()?;
                bits_in_primitive(b)
            },

            Type::Paren(a) => FixedWidth::from_ty(&a.elem),

            e => Err(Error::new(e.span(), "field must be constructed from a literal, tuple, or array of integral types")),
        }
    }
}

impl FixedWidth {
    fn to_zerocopy_type(&self) -> Option<ZcType> {
        // TODO: figure out hybrid types in here, too.
        match &self.ty {
            ReprType::Array { child, length } => {
                let ZcType { repr, transformed } = child.to_zerocopy_type()?;
                Some(ZcType {
                    repr: syn::parse(quote! {[#repr; #length]}.into()).unwrap(),
                    transformed,
                })
            }
            ReprType::Tuple { children } => {
                let mut child_types = vec![];
                let mut any_transformed = false;

                for child in children {
                    let ZcType { repr, transformed } =
                        child.to_zerocopy_type()?;
                    child_types.push(repr);
                    any_transformed |= transformed;
                }

                Some(ZcType {
                    repr: syn::parse(quote! {(#( #child_types ),*)}.into())
                        .unwrap(),
                    transformed: any_transformed,
                })
            }
            ReprType::Primitive { base_ident, bits, endian } => {
                if *bits == 8 {
                    return Some(ZcType {
                        repr: syn::parse(quote! {#base_ident}.into()).unwrap(),
                        transformed: false,
                    });
                }
                endian.and_then(|end| {
                    if !bits.is_power_of_two() || *bits > 128 || *bits < 16 {
                        return None;
                    }

                    let tail =
                        Ident::new(&format!("U{}", bits), base_ident.span());

                    let repr = syn::parse(
                        match end {
                            Endianness::Big => {
                                quote! {::zerocopy::big_endian::#tail}
                            }
                            Endianness::Little => {
                                quote! {::zerocopy::little_endian::#tail}
                            }
                            Endianness::Host => {
                                quote! {::zerocopy::native_endian::#tail}
                            }
                        }
                        .into(),
                    )
                    .unwrap();

                    Some(ZcType { repr, transformed: true })
                })
            }
        }
    }
}

fn bits_in_primitive(ident: &Ident) -> Result<FixedWidth, syn::Error> {
    let name = ident.to_string();

    // validation rules:
    // 1) begins with 'u'.
    // 2) followed by number 1--64. Retval.
    // 3) if >=8, followed by endianness.
    let re = Regex::new(r"^u([0-9]+)(be|le|he)?$").unwrap();
    let Some(fields) = re.captures(&name) else {
        return Err(Error::new(
            name.span(),
            "type not of form 'u<width>[<endian>]",
        ));
    };

    let bits: usize = fields.get(1).unwrap().as_str().parse().unwrap();

    let endian = match fields.get(2).map(|v| v.as_str()) {
        _ if bits <= 8 => None,
        Some("be") => Some(Endianness::Big),
        Some("le") => Some(Endianness::Little),
        Some("he") => Some(Endianness::Host),
        None => {
            return Err(Error::new(
                ident.span(),
                "types > 8 bits require explicit endianness",
            ))
        }
        _ => {
            return Err(Error::new(
                ident.span(),
                "illegal endianness specifier",
            ))
        }
    };

    let base_ident = ident.clone();

    let ty = ReprType::Primitive { base_ident, bits, endian };

    Ok(FixedWidth {
        cached_bits: bits,
        ty,
        is_all_rust_primitives: bits >= 8
            && bits.is_power_of_two()
            && bits <= 128,
    })
}

pub fn derive(input: IngotArgs) -> TokenStream {
    let x = StructParseDeriveCtx::new(input.clone()).unwrap();

    let IngotArgs { ident, data } = input;

    let validated_ident = Ident::new(&format!("Valid{ident}"), ident.span());
    let ref_ident = Ident::new(&format!("{ident}Ref"), ident.span());
    let mut_ident = Ident::new(&format!("{ident}Mut"), ident.span());
    let pkt_ident = Ident::new(&format!("{ident}Packet"), ident.span());
    let private_mod_ident =
        Ident::new(&format!("_{ident}_ingot_impl"), ident.span());

    let mut fields: Vec<ValidField> = vec![];

    let mut trait_defs: Vec<TokenStream> = vec![];
    let mut trait_mut_defs: Vec<TokenStream> = vec![];

    let mut trait_impls: Vec<TokenStream> = vec![];
    let mut trait_mut_impls: Vec<TokenStream> = vec![];

    let mut direct_trait_impls: Vec<TokenStream> = vec![];
    let mut direct_trait_mut_impls: Vec<TokenStream> = vec![];

    let mut packet_impls: Vec<TokenStream> = vec![];
    let mut packet_mut_impls: Vec<TokenStream> = vec![];

    let field_data = data.take_struct().unwrap();

    let mut t_bits = 0;
    let mut next_layer: Option<TokenStream> = None;

    // note: concept of first_bit is broken for now.
    // need to rethink & rework.

    for field in field_data.fields {
        let underlying_ty =
            if let Some(ty) = &field.is { ty } else { &field.ty };
        let user_ty = &field.ty;

        // let analysis = match field.var_len {
        //     Some(expr) => todo!(),
        //     None => todo!(),
        // };

        // NOTE: can't analyse anything with a generic using this fn.
        let analysis = match FixedWidth::from_ty(&underlying_ty) {
            Ok(v) => v,
            Err(v) => return v.into_compile_error().into(),
        };

        let n_bits = analysis.cached_bits;

        if analysis.ty.is_aggregate() && (t_bits % 8 != 0 || n_bits % 8 != 0) {
            return Error::new(
                underlying_ty.span(),
                "aggregate types must be byte-aligned at their start and end",
            )
            .into_compile_error()
            .into();
        }

        let marker = format!("my offset is {t_bits}+={n_bits} bits");

        let field_ident = field.ident.unwrap();
        let valid_field = ValidField {
            repr: underlying_ty.clone(),
            ident: field_ident.clone(),
            first_bit: t_bits,
            analysis: Analysed::FixedWidth(analysis),
            hybrid: None,
            user_ty: user_ty.clone(),
            // TODO: increment as we pass by varwidth fields
            sub_ref_idx: 0,
        };

        t_bits += n_bits;

        if let Some(nl) = field.next_layer {
            if next_layer.is_some() {
                return Error::new(
                    field_ident.span(),
                    "only one field can be nominated as a next-header hint",
                )
                .into_compile_error()
                .into();
            }

            if nl.or_extension {
                todo!("integrated extension parsing not yet ready")
            }

            next_layer = Some(quote! {
                impl<V: ::zerocopy::ByteSlice> ::ingot_types::NextLayer for #validated_ident<V> {
                    type Denom = #user_ty;

                    #[inline]
                    fn next_layer(&self) -> ::ingot_types::ParseResult<Self::Denom> {
                        ::core::result::Result::Ok(self.#field_ident())
                    }
                }

                impl ::ingot_types::NextLayer for #ident {
                    type Denom = #user_ty;

                    #[inline]
                    fn next_layer(&self) -> ::ingot_types::ParseResult<Self::Denom> {
                        ::core::result::Result::Ok(self.#field_ident)
                    }
                }
            });
        }

        fields.push(valid_field);
    }

    let next_layer = next_layer.unwrap_or_else(|| quote! {
        impl<V: ::zerocopy::ByteSlice> ::ingot_types::NextLayer for #validated_ident<V> {
            type Denom = ();

            #[inline]
            fn next_layer(&self) -> ::ingot_types::ParseResult<Self::Denom> {
                ::core::result::Result::Err(::ingot_types::ParseError::NoHint)
            }
        }

        impl ::ingot_types::NextLayer for #ident {
            type Denom = ();

            #[inline]
            fn next_layer(&self) -> ::ingot_types::ParseResult<Self::Denom> {
                ::core::result::Result::Err(::ingot_types::ParseError::NoHint)
            }
        }
    });

    if t_bits % 8 != 0 {
        return Error::new(
            fields.last().unwrap().repr.span(),
            format!("fields are not byte-aligned -- total {t_bits}b"),
        )
        .into_compile_error()
        .into();
    }

    // Zerocopy type construction.

    #[derive(Clone, Debug)]
    struct HyState {
        bits_seen: usize,
        field_data: Rc<RefCell<HybridField>>,
    }

    // TODO: partition based on var-width fields.
    let mut zc_impls: Vec<TokenStream> = vec![];
    let mut zc_fields: Vec<TokenStream> = vec![];
    let mut hybrid_field: Option<HyState> = None;
    let mut zc_ty_names: Vec<Ident> = vec![];

    let mut hybrid_count = 0;

    for field in &mut fields {
        let Analysed::FixedWidth(ref analysis) = field.analysis else {
            continue;
        };
        if hybrid_field.is_none()
            && field.first_bit % 8 == 0
            && analysis.is_all_rust_primitives
        {
            let ident = &field.ident;
            // guaranteed defined for U8/U16/U32/U64/...
            let ty = analysis.to_zerocopy_type().unwrap();
            let zc_repr = ty.repr;
            zc_fields.push(quote! {
                pub #ident: #zc_repr
            })
        } else {
            let ty_ident =
                Ident::new(&format!("hybrid{}", hybrid_count), ident.span());

            let hybrid_state = hybrid_field.get_or_insert_with(|| HyState {
                bits_seen: 0,
                field_data: Rc::new(RefCell::new(HybridField {
                    ident: ty_ident.clone(),
                    n_bits: 0,
                    first_bit: field.first_bit,
                })),
            });
            // let hybrid_len =
            //     hybrid_field.unwrap_or_default() + field.analysis.cached_bits;

            hybrid_state.bits_seen += analysis.cached_bits;
            hybrid_state.field_data.borrow_mut().n_bits += analysis.cached_bits;

            // field.

            let first_bit_inner =
                field.first_bit - hybrid_state.field_data.borrow().first_bit;

            field.hybrid = Some(PrimitiveInBitfield {
                parent_field: hybrid_state.field_data.clone(),
                first_bit_inner,
                n_bits: analysis.cached_bits,
                endianness: analysis.get_primitive_endianness(),
            });

            if hybrid_state.bits_seen % 8 == 0 {
                // push field out
                let n_bytes = hybrid_state.bits_seen / 8;
                zc_fields.push(quote! {
                    pub #ty_ident: [u8; #n_bytes]
                });
                hybrid_count += 1;
                hybrid_field = None;
            }
        }
    }
    if !zc_fields.is_empty() {
        let ty_ident =
            Ident::new(&format!("Zc{}", zc_impls.len()), ident.span());
        zc_impls.push(quote! {
            #[derive(zerocopy::IntoBytes, Clone, Debug, zerocopy::FromBytes, zerocopy::Unaligned, zerocopy::Immutable, zerocopy::KnownLayout)]
            #[repr(C, packed)]
            pub struct #ty_ident {
                #( #zc_fields ),*
            }
        });

        zc_ty_names.push(ty_ident)
    }

    for field in &fields {
        let Analysed::FixedWidth(ref analysis) = field.analysis else {
            continue;
        };
        let field_ident = &field.ident;
        let user_ty = &field.user_ty;
        let get_name = field.getter_name();

        let field_ref = Ident::new(&format!("{field_ident}_ref"), ident.span());
        let field_mut = Ident::new(&format!("{field_ident}_mut"), ident.span());

        // Used to determine whether we need both:
        // - use of NetworkRepr conversion
        // - include &<ty>, &mut <ty> in trait.
        let zc_ty = analysis.to_zerocopy_type();
        let do_into = field.user_ty == field.repr;
        let allow_ref_access =
            do_into && zc_ty.map(|v| !v.transformed).unwrap_or_default();

        if let Some(hybrid) = &field.hybrid {
            let (get_conv, set_conv) = if do_into {
                (quote! {val.into()}, quote! {val})
            } else {
                (
                    quote! {::ingot_types::NetworkRepr::from_network(val)},
                    quote! {::ingot_types::NetworkRepr::to_network(val)},
                )
            };

            // Can't have refs/muts if hybrid.
            trait_defs.push(quote! {
                fn #field_ident(&self) -> #user_ty;
            });
            direct_trait_impls.push(quote! {
                #[inline]
                fn #get_name(&self) -> #user_ty {
                    self.#field_ident
                }
            });
            let subty_get = hybrid.get(field);
            trait_impls.push(quote! {
                #[inline]
                fn #get_name(&self) -> #user_ty {
                    // todo!("getters on subtypes not yet done")
                    #subty_get
                    #get_conv
                }
            });

            // zc_impls.push(quote! {
            //     #[derive(zerocopy::IntoBytes, Clone, Debug, zerocopy::FromBytes, zerocopy::Unaligned, zerocopy::Immutable, zerocopy::KnownLayout)]
            //     #[repr(C, packed)]
            //     pub struct #ty_ident {
            //         #( #zc_fields ),*
            //     }
            // });

            let mut_name = field.setter_name();
            trait_mut_defs.push(quote! {
                fn #mut_name(&mut self, val: #user_ty);
            });
            direct_trait_mut_impls.push(quote! {
                #[inline]
                fn #mut_name(&mut self, val: #user_ty) {
                    self.#field_ident = val;
                }
            });
            let subty_set = hybrid.set(field);
            trait_mut_impls.push(quote! {
                #[inline]
                fn #mut_name(&mut self, val: #user_ty) {
                    let val_raw = #set_conv;
                    #subty_set
                }
            });

            packet_impls.push(quote! {
                #[inline]
                fn #get_name(&self) -> #user_ty {
                    match self {
                        ::ingot_types::Packet::Repr(o) => o.#field_ident(),
                        ::ingot_types::Packet::Raw(b) => b.#field_ident(),
                    }
                }
            });
            packet_mut_impls.push(quote! {
                #[inline]
                fn #mut_name(&mut self, val: #user_ty) {
                    match self {
                        ::ingot_types::Packet::Repr(o) => o.#mut_name(val),
                        ::ingot_types::Packet::Raw(b) => b.#mut_name(val),
                    };
                }
            });
        } else {
            // normal types!
            trait_defs.push(quote! {
                fn #get_name(&self) -> #user_ty;
            });
            direct_trait_impls.push(quote! {
                #[inline]
                fn #get_name(&self) -> #user_ty {
                    self.#field_ident
                }
            });

            let mut_name = field.setter_name();
            trait_mut_defs.push(quote! {
                fn #mut_name(&mut self, val: #user_ty);
            });
            direct_trait_mut_impls.push(quote! {
                #[inline]
                fn #mut_name(&mut self, val: #user_ty) {
                    self.#field_ident = val;
                }
            });

            packet_impls.push(quote! {
                #[inline]
                fn #field_ident(&self) -> #user_ty {
                    match self {
                        ::ingot_types::Packet::Repr(o) => o.#field_ident(),
                        ::ingot_types::Packet::Raw(b) => b.#field_ident(),
                    }
                }
            });
            packet_mut_impls.push(quote! {
                #[inline]
                fn #mut_name(&mut self, val: #user_ty) {
                    match self {
                        ::ingot_types::Packet::Repr(o) => o.#mut_name(val),
                        ::ingot_types::Packet::Raw(b) => b.#mut_name(val),
                    };
                }
            });

            if do_into {
                trait_impls.push(quote! {
                    #[inline]
                    fn #get_name(&self) -> #user_ty {
                        // my zc_ty was #zc_ty
                        self.0.#field_ident.into()
                    }
                });
                trait_mut_impls.push(quote! {
                    #[inline]
                    fn #mut_name(&mut self, val: #user_ty) {
                        self.0.#field_ident = val.into();
                    }
                });
            } else {
                trait_impls.push(quote! {
                    #[inline]
                    fn #get_name(&self) -> #user_ty {
                        // my zc_ty was #zc_ty
                        ::ingot_types::NetworkRepr::from_network(self.0.#field_ident)
                    }
                });
                trait_mut_impls.push(quote! {
                    #[inline]
                    fn #mut_name(&mut self, val: #user_ty) {
                        self.0.#field_ident = ::ingot_types::NetworkRepr::to_network(val);
                    }
                });
            }

            if allow_ref_access {
                trait_defs.push(quote! {
                    fn #field_ref(&self) -> &#user_ty;
                });
                direct_trait_impls.push(quote! {
                    #[inline]
                    fn #field_ref(&self) -> &#user_ty {
                        &self.#field_ident
                    }
                });

                trait_impls.push(quote! {
                    #[inline]
                    fn #field_ref(&self) -> &#user_ty {
                        &self.0.#field_ident
                    }
                });
                trait_mut_impls.push(quote! {
                    #[inline]
                    fn #field_mut(&mut self) -> &mut #user_ty {
                        &mut self.0.#field_ident
                    }
                });

                trait_mut_defs.push(quote! {
                    fn #field_mut(&mut self) -> &mut #user_ty;
                });
                direct_trait_mut_impls.push(quote! {
                    #[inline]
                    fn #field_mut(&mut self) -> &mut #user_ty {
                        &mut self.#field_ident
                    }
                });

                packet_impls.push(quote! {
                    #[inline]
                    fn #field_ref(&self) -> &#user_ty {
                        match self {
                            ::ingot_types::Packet::Repr(o) => o.#field_ref(),
                            ::ingot_types::Packet::Raw(b) => b.#field_ref(),
                        }
                    }
                });
                packet_mut_impls.push(quote! {
                    #[inline]
                    fn #field_mut(&mut self) -> &mut #user_ty {
                        match self {
                            ::ingot_types::Packet::Repr(o) => o.#field_mut(),
                            ::ingot_types::Packet::Raw(b) => b.#field_mut(),
                        }
                    }
                });
            }
        }
    }

    // let valid_body = todo!();

    quote! {
        // pub struct #validated_ident<V>(V);

        pub struct #validated_ident<V>(#(pub ::zerocopy::Ref<V, #private_mod_ident::#zc_ty_names> ),*);

        impl<V> ::ingot_types::Header for #validated_ident<V> {
            const MINIMUM_LENGTH: usize = (#t_bits / 8);

            fn packet_length(&self) -> usize {
                // TODO: varwidth types.
                Self::MINIMUM_LENGTH
            }
        }

        impl ::ingot_types::Header for #ident {
            const MINIMUM_LENGTH: usize = (#t_bits / 8);

            fn packet_length(&self) -> usize {
                // TODO: varwidth types.
                Self::MINIMUM_LENGTH
            }
        }

        pub trait #ref_ident {
            #( #trait_defs )*
        }

        pub trait #mut_ident {
            #( #trait_mut_defs )*
        }

        #[allow(non_snake_case)]
        pub mod #private_mod_ident {
            use super::*;

            #( #zc_impls )*

            impl<V: ::zerocopy::ByteSlice> #ref_ident for #validated_ident<V> {
                #( #trait_impls )*
            }

            impl #ref_ident for #ident {
                #( #direct_trait_impls )*
            }

            impl<V: ::zerocopy::ByteSliceMut> #mut_ident for #validated_ident<V> {
                #( #trait_mut_impls )*
            }

            impl #mut_ident for #ident {
                #( #direct_trait_mut_impls )*
            }
        }

        impl<O, B> #ref_ident for ::ingot_types::Packet<O, B>
        where
            O: #ref_ident,
            B: #ref_ident,
        {
            #( #packet_impls )*
        }

        impl<O, B> #mut_ident for ::ingot_types::Packet<O, B>
        where
            O: #mut_ident,
            B: #mut_ident,
        {
            #( #packet_mut_impls )*
        }

        impl<V: ::ingot_types::Chunk> ::ingot_types::HasBuf for #validated_ident<V> {
            type BufType = V;
        }

        impl<V: ::ingot_types::Chunk> ::ingot_types::HeaderParse for #validated_ident<V> {
            type Target = Self;
            fn parse(from: V) -> ::ingot_types::ParseResult<(Self, V)> {
                use ::ingot_types::Header;

                // TODO!
                if from.as_ref().len() < #ident::MINIMUM_LENGTH {
                    ::core::result::Result::Err(::ingot_types::ParseError::TooSmall)
                } else {
                    let (l, r) = from.split_at(#ident::MINIMUM_LENGTH);
                    let v0 = ::zerocopy::Ref::from_bytes(l)
                        .map_err(|_| ::ingot_types::ParseError::TooSmall)?;
                    ::core::result::Result::Ok((
                        #validated_ident(v0),
                        r,
                    ))
                }
            }
        }

        impl<V, T> ::core::convert::From<#validated_ident<V>> for ::ingot_types::Packet<T, #validated_ident<V>> {
            fn from(value: #validated_ident<V>) -> Self {
                ::ingot_types::Packet::Raw(value)
            }
        }

        impl<T> ::core::convert::From<#ident> for ::ingot_types::Packet<#ident, T> {
            fn from(value: #ident) -> Self {
                ::ingot_types::Packet::Repr(value)
            }
        }

        pub type #pkt_ident<V> = ::ingot_types::Packet<#ident, #validated_ident<V>>;

        impl<V> ::ingot_types::HasRepr for #validated_ident<V> {
            type ReprType = #ident;
        }

        #next_layer
    }
}
