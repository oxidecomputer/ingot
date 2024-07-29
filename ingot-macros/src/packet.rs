use darling::ast;
use darling::FromDeriveInput;
use darling::FromField;
use darling::FromMeta;
use proc_macro2::Ident;
use proc_macro2::TokenStream;
use quote::quote;
use regex::Regex;
use syn::spanned::Spanned;
use syn::Error;
use syn::Expr;
use syn::ExprLit;
use syn::Lit;
use syn::Type;
use syn::TypeArray;

#[derive(FromDeriveInput)]
#[darling(attributes(ingot), supports(struct_named))]
pub struct IngotArgs {
    ident: Ident,
    data: ast::Data<(), FieldArgs>,
}

#[derive(FromMeta, Default)]
#[darling(default)]
pub struct NextLayerSpec {
    #[darling(default)]
    or_extension: bool,
}

#[derive(FromField)]
#[darling(attributes(ingot, is))]
pub struct FieldArgs {
    is: Option<Type>,
    next_layer: Option<NextLayerSpec>,

    ident: Option<syn::Ident>,
    ty: Type,
}

struct ValidField {
    repr: Type,
    ident: Ident,
    user_ty: Type,

    first_bit: usize,
    analysis: Analysed,

    /// indicates child field of the
    sub_ref_idx: usize,
    hybrid: Option<HybridFieldState>,
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
        matches!(self.analysis.ty, ReprType::Primitive { .. })
    }
}

struct HybridFieldState {}

// struct TyData {
//     n_bits:
// }

#[derive(Copy, Clone)]
enum Endianness {
    Big,
    Little,
    Host,
}

enum ReprType {
    Array { child: Box<Analysed>, length: usize },
    Tuple { children: Vec<Analysed> },
    Primitive { base_ident: Ident, bits: usize, endian: Option<Endianness> },
}

impl ReprType {
    fn is_aggregate(&self) -> bool {
        !matches!(self, ReprType::Primitive { .. })
    }
}

struct Analysed {
    cached_bits: usize,
    ty: ReprType,
}

impl Analysed {
    fn from_ty(ty: &Type) -> Result<Self, syn::Error> {
        match ty {
            Type::Array(TypeArray{ elem, len: Expr::Lit(ExprLit{lit: Lit::Int(l), ..}), .. })  => {
                let analysed = Self::from_ty(elem)?;
                let length = l.base10_parse::<usize>()?;

                Ok(Analysed { cached_bits: analysed.cached_bits * length, ty: ReprType::Array { child: analysed.into(), length } })
            },
            e @ Type::Array(TypeArray{ .. })  => {
                Err(Error::new(e.span(), "array length must be an integer literal"))
            }
            Type::Tuple(a) => {
                let mut n_bits = 0;
                let mut children = vec![];
                for elem in &a.elems {
                    let analysed = Self::from_ty(elem)?;
                    n_bits += analysed.cached_bits;
                    children.push(analysed);
                }

                // Ok(n_bits)
                Ok(Analysed { cached_bits: n_bits, ty: ReprType::Tuple { children } })
            },
            Type::Path(a) => {
                let b = a.path.require_ident()?;
                bits_in_primitive(b)
            },

            Type::Paren(a) => Analysed::from_ty(&a.elem),

            e => Err(Error::new(e.span(), "field must be constructed from a literal, tuple, or array of integral types")),
        }
    }
}

impl Analysed {
    fn to_zerocopy_type(&self) -> Option<Type> {
        // TODO: figure out hybrid types in here, too.
        match &self.ty {
            ReprType::Array { child, length } => {
                let child_repr = child.to_zerocopy_type();
                Some(
                    syn::parse(quote! {[#child_repr; #length]}.into()).unwrap(),
                )
            }
            ReprType::Tuple { children } => {
                let mut child_types = vec![];
                for child in children {
                    child_types.push(child.to_zerocopy_type());
                }

                Some(syn::parse(quote! {(#( #child_types ),*)}.into()).unwrap())
            }
            ReprType::Primitive { base_ident, bits, endian } => {
                if *bits == 8 {
                    return Some(
                        syn::parse(quote! {#base_ident}.into()).unwrap(),
                    );
                }
                endian.and_then(|end| {
                    if !bits.is_power_of_two() || *bits > 128 || *bits < 16 {
                        return None;
                    }

                    let tail =
                        Ident::new(&format!("U{}", bits), base_ident.span());

                    Some(
                        syn::parse(
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
                        .unwrap(),
                    )
                })
            }
        }
    }
}

fn bits_in_primitive(ident: &Ident) -> Result<Analysed, syn::Error> {
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

    Ok(Analysed { cached_bits: bits, ty })
}

pub fn derive(input: IngotArgs) -> TokenStream {
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

    for field in field_data.fields {
        let underlying_ty =
            if let Some(ty) = &field.is { ty } else { &field.ty };
        let user_ty = &field.ty;

        let analysis = match Analysed::from_ty(&underlying_ty) {
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
            analysis,
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

    // TODO: partition based on var-width fields.
    let mut zc_impls: Vec<TokenStream> = vec![];
    let mut zc_fields: Vec<TokenStream> = vec![];
    let mut hybrid_field: Option<usize> = None;
    let mut zc_ty_names: Vec<Ident> = vec![];

    let mut hybrid_count = 0;
    for field in &mut fields {
        if hybrid_field.is_none()
            && field.first_bit % 8 == 0
            && field.analysis.cached_bits % 8 == 0
        {
            let ident = &field.ident;
            let ty = field.analysis.to_zerocopy_type();
            zc_fields.push(quote! {
                #ident: #ty
            })
        } else {
            let hybrid_len =
                hybrid_field.unwrap_or_default() + field.analysis.cached_bits;
            let ty_ident =
                Ident::new(&format!("hybrid{}", hybrid_count), ident.span());

            field.hybrid = Some(HybridFieldState {});

            if hybrid_len % 8 == 0 {
                // push field out
                let n_bytes = hybrid_len / 8;
                zc_fields.push(quote! {
                    #ty_ident: [u8; #n_bytes]
                });
                hybrid_field = None;
            } else {
                if hybrid_field.is_none() {
                    hybrid_count += 1;
                }
                hybrid_field = Some(hybrid_len);
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
        let field_ident = &field.ident;
        let user_ty = &field.user_ty;
        let get_name = field.getter_name();
        let mut_name = field.setter_name();

        let field_ref = Ident::new(&format!("{field_ident}_ref"), ident.span());
        let field_mut = Ident::new(&format!("{field_ident}_mut"), ident.span());

        // Used to determine whether we need both:
        // - use of NetworkRepr conversion
        // - include &<ty>, &mut <ty> in trait.
        let identical_tys = field.user_ty != field.repr;

        if let Some(hybrid) = &field.hybrid {
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
            trait_impls.push(quote! {
                #[inline]
                fn #get_name(&self) -> #user_ty {
                    todo!("getters on subtypes not yet done")
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
            trait_mut_impls.push(quote! {
                #[inline]
                fn #mut_name(&mut self, val: #user_ty) {
                    todo!("setters on subtypes not yet done");
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
                fn #field_ref(&self) -> &#user_ty;
            });
            direct_trait_impls.push(quote! {
                #[inline]
                fn #get_name(&self) -> #user_ty {
                    self.#field_ident
                }
                #[inline]
                fn #field_ref(&self) -> &#user_ty {
                    &self.#field_ident
                }
            });

            if field.user_ty != field.repr {
                trait_impls.push(quote! {
                    #[inline]
                    fn #get_name(&self) -> #user_ty {
                        ::ingot_types::NetworkRepr::from_network(self.0.#field_ident)
                    }
                    #[inline]
                    fn #field_ref(&self) -> &#user_ty {
                        todo!()
                    }
                });
                trait_mut_impls.push(quote! {
                    #[inline]
                    fn #mut_name(&mut self, val: #user_ty) {
                        self.0.#field_ident = ::ingot_types::NetworkRepr::to_network(val);
                    }
                    #[inline]
                    fn #field_mut(&mut self) -> &mut #user_ty {
                        todo!()
                    }
                });
            } else {
                trait_impls.push(quote! {
                    #[inline]
                    fn #get_name(&self) -> #user_ty {
                        self.0.#field_ident.into()
                    }
                    #[inline]
                    fn #field_ref(&self) -> &#user_ty {
                        todo!()
                    }
                });
                trait_mut_impls.push(quote! {
                    #[inline]
                    fn #mut_name(&mut self, val: #user_ty) {
                        self.0.#field_ident = val.into();
                    }
                    #[inline]
                    fn #field_mut(&mut self) -> &mut #user_ty {
                        todo!()
                    }
                });
            }

            let mut_name = field.setter_name();
            trait_mut_defs.push(quote! {
                fn #mut_name(&mut self, val: #user_ty);
                fn #field_mut(&mut self) -> &mut #user_ty;
            });
            direct_trait_mut_impls.push(quote! {
                #[inline]
                fn #mut_name(&mut self, val: #user_ty) {
                    self.#field_ident = val;
                }
                #[inline]
                fn #field_mut(&mut self) -> &mut #user_ty {
                    &mut self.#field_ident
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
                fn #mut_name(&mut self, val: #user_ty) {
                    match self {
                        ::ingot_types::Packet::Repr(o) => o.#mut_name(val),
                        ::ingot_types::Packet::Raw(b) => b.#mut_name(val),
                    };
                }
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

    // let valid_body = todo!();

    quote! {
        // pub struct #validated_ident<V>(V);

        pub struct #validated_ident<V>(#( ::zerocopy::Ref<V, #private_mod_ident::#zc_ty_names> ),*);

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
        mod #private_mod_ident {
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
