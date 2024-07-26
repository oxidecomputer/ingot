use darling::ast;
use darling::ast::NestedMeta;
use darling::Error as DarlingError;
use darling::FromDeriveInput;
use darling::FromField;
use darling::FromMeta;
use proc_macro2::Ident;
use proc_macro2::TokenStream;
use quote::format_ident;
use quote::quote;
use regex::Regex;
use syn::parse;
use syn::parse_macro_input;
use syn::spanned::Spanned;
use syn::Data;
use syn::DeriveInput;
use syn::Error;
use syn::Expr;
use syn::ExprLit;
use syn::GenericArgument;
use syn::ItemEnum;
use syn::Lit;
use syn::Path;
use syn::PathArguments;
use syn::Token;
use syn::Type;
use syn::TypeArray;
use syn::TypeInfer;
use syn::TypePath;

#[derive(FromDeriveInput)]
#[darling(attributes(oxp), supports(struct_named, struct_tuple))]
struct ParserArgs {}

#[derive(FromField)]
#[darling(attributes(oxpopt, ingot))]
struct LayerArgs {
    from: Option<syn::Path>,
}

#[proc_macro_derive(Parse, attributes(oxp, oxpopt, ingot))]
pub fn derive_parse(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let d_input = parse_macro_input!(input);

    let _parsed_args = match ParserArgs::from_derive_input(&d_input) {
        Ok(o) => o,
        Err(e) => return e.write_errors().into(),
    };

    let DeriveInput { ref ident, ref data, ref generics, .. } = d_input;

    let Data::Struct(data) = data else {
        return Error::new(
            d_input.span(),
            "packet parsing must be derived on a struct",
        )
        .into_compile_error()
        .into();
    };

    let mut parse_points: Vec<TokenStream> = vec![];
    let mut fnames: Vec<Ident> = vec![];

    let n_fields = data.fields.len();
    for (i, field) in data.fields.iter().enumerate() {
        let args = match LayerArgs::from_field(field) {
            Ok(o) => o,
            Err(e) => return e.write_errors().into(),
        };

        let Type::Path(ref ty) = field.ty else { panic!() };

        let fname = if let Some(ref v) = field.ident {
            v.clone()
        } else {
            format_ident!("f_{i}")
        };

        let hint_frag = if i != n_fields - 1 {
            quote! {
                let hint = #fname.next_layer()?;
            }
        } else {
            quote! {}
        };

        let first_ty = if let Some(a) = args.from {
            &TypePath { qself: None, path: a }
        } else {
            ty
        };

        let conv_frag = quote! {
            let #fname = #fname.try_into()?;
        };

        // panic!("{first_ty}, {conv_frag}");

        let slice_frag = if i == n_fields - 1 {
            quote! {}
        } else {
            quote! {
                let slice = if remainder.as_ref().is_empty() {
                    data.next_chunk()?
                } else {
                    remainder
                };
            }
        };

        let contents = if i == 0 {
            // Hacky generic handling.
            let mut local_ty = first_ty.clone();
            local_ty.qself = None;
            if let Some(el) = local_ty.path.segments.last_mut() {
                el.arguments = PathArguments::None;
            }

            quote! {
                let (#fname, remainder) = #local_ty::parse(slice)?;
                #hint_frag
                #slice_frag
                #conv_frag
            }
        } else {
            // Hackier generic handling.
            let mut local_ty = first_ty.clone();
            local_ty.qself = None;
            if let Some(el) = local_ty.path.segments.last_mut() {
                // replace all generic args with inferred.
                match &mut el.arguments {
                    PathArguments::AngleBracketed(args) => {
                        for arg in args.args.iter_mut() {
                            if let GenericArgument::Type(t) = arg {
                                *t = Type::Infer(TypeInfer {
                                    underscore_token: Token![_](t.span()),
                                })
                            }
                        }
                    }
                    PathArguments::None => todo!(),
                    PathArguments::Parenthesized(_) => todo!(),
                }
            }

            quote! {
                let (#fname, remainder) = <#local_ty as HasView>::ViewType::parse_choice(slice, hint)?;
                #hint_frag
                #slice_frag
                #conv_frag
            }
        };

        parse_points.push(contents);
        fnames.push(fname);
    }

    let ctor = match data.fields {
        syn::Fields::Named(_) => quote! { #ident{ #( #fnames ),* } },
        syn::Fields::Unnamed(_) => quote! { #ident( #( #fnames ),* ) },
        syn::Fields::Unit => {
            return Error::new(
                d_input.span(),
                "packet parsing must be derived on a non-unit struct",
            )
            .into_compile_error()
            .into();
        }
    };

    quote! {
        impl<Q: ::ingot_types::Read> Parsed2<#ident<Q::Chunk>, Q> {
            pub fn newy(mut data: Q) -> ::ingot_types::ParseResult<Self> {
                let slice = data.next_chunk()?;

                #( #parse_points )*

                ::core::result::Result::Ok(Self {
                    stack: HeaderStack(#ctor),
                    data,
                    _self_referential: PhantomPinned,
                })
            }
        }
    }
    .into()
}

// per-packet

#[derive(FromDeriveInput)]
#[darling(attributes(ingot), supports(struct_named))]
struct IngotArgs {
    ident: Ident,
    data: ast::Data<(), FieldArgs>,
}

#[derive(FromMeta, Default)]
#[darling(default)]
struct NextLayerSpec {
    #[darling(default)]
    or_extension: bool,
}

#[derive(FromField)]
#[darling(attributes(ingot, is))]
struct FieldArgs {
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

#[proc_macro_derive(Ingot, attributes(ingot, is))]
pub fn derive_ingot(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let d_input = parse_macro_input!(input);

    let IngotArgs { ident, data } = match IngotArgs::from_derive_input(&d_input)
    {
        Ok(o) => o,
        Err(e) => return e.write_errors().into(),
    };

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

        // trait_defs.push(quote! {
        //     fn #field_ident(&self) -> #user_ty;
        //     fn #field_ref(&self) -> &#user_ty;
        // });
        // direct_trait_impls.push(quote! {
        //     #[inline]
        //     fn #field_ident(&self) -> #user_ty {
        //         self.#field_ident
        //     }
        // });

        // let mut_name =
        //     field.setter_name();
        // trait_mut_defs.push(quote! {
        //     fn #mut_name(&mut self, val: #user_ty);
        //     fn #field_mut(&self) -> &#user_ty;
        // });
        // direct_trait_mut_impls.push(quote! {
        //     #[inline]
        //     fn #mut_name(&mut self, val: #user_ty) {
        //         self.#field_ident = val;
        //     }
        // });

        // packet_impls.push(quote! {
        //     #[inline]
        //     fn #field_ident(&self) -> #user_ty {
        //         match self {
        //             ::ingot_types::Packet::Repr(o) => o.#field_ident(),
        //             ::ingot_types::Packet::Raw(b) => b.#field_ident(),
        //         }
        //     }
        // });
        // packet_mut_impls.push(quote! {
        //     #[inline]
        //     fn #mut_name(&mut self, val: #user_ty) {
        //         match self {
        //             ::ingot_types::Packet::Repr(o) => o.#mut_name(val),
        //             ::ingot_types::Packet::Raw(b) => b.#mut_name(val),
        //         };
        //     }
        // });

        // NOTE: need to do a custom get/set for primitives.

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
    .into()
}

// #[proc_macro_attribute]
// pub fn ingot(_attr: proc_macro::TokenStream, item: proc_macro::TokenStream) -> proc_macro::TokenStream {
//     let structdef = parse_macro_input!(item as ItemStruct);

//     quote!{
//         #[derive(Ingot)]
//         #structdef
//     }.into()
// }

// #[proc_macro]
// pub fn choice(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
//     // println!("attr: \"{attr}\"");
//     panic!("item: \"{item}\"");
//     item
// }

#[derive(FromMeta)]
struct ChoiceArgs {
    on: Path,
}

#[proc_macro_attribute]
pub fn choice(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let attr_args = match NestedMeta::parse_meta_list(attr.into()) {
        Ok(v) => v,
        Err(e) => {
            return DarlingError::from(e).write_errors().into();
        }
    };
    let item = syn::parse_macro_input!(item as ItemEnum);

    let ChoiceArgs { on } = match ChoiceArgs::from_list(&attr_args) {
        Ok(v) => v,
        Err(e) => {
            return e.write_errors().into();
        }
    };

    let ident = item.ident;

    let validated_ident = Ident::new(&format!("Valid{ident}"), ident.span());
    let repr_ident = Ident::new(&format!("{ident}Repr"), ident.span());

    let mut top_vars: Vec<TokenStream> = vec![];
    let mut validated_vars: Vec<TokenStream> = vec![];
    let mut repr_vars: Vec<TokenStream> = vec![];

    let mut match_arms: Vec<TokenStream> = vec![];
    let mut parse_match_arms: Vec<TokenStream> = vec![];
    let mut repr_match_arms: Vec<TokenStream> = vec![];

    let mut next_layer_wheres: Vec<TokenStream> = vec![];
    let mut next_layer_match_arms: Vec<TokenStream> = vec![];

    let mut unpacks: Vec<TokenStream> = vec![];

    for var in item.variants {
        let Some((_, disc)) = var.discriminant else {
            return Error::new(
                var.span(),
                "variant must have a valid discriminant",
            )
            .into_compile_error()
            .into();
        };

        let field_ident = var.ident;
        let valid_field_ident =
            Ident::new(&format!("Valid{field_ident}"), ident.span());

        top_vars.push(quote!{
            #field_ident(::ingot_types::Packet<#field_ident, #valid_field_ident<V>>)
        });

        validated_vars.push(quote! {
            #field_ident(#valid_field_ident<V>)
        });

        repr_vars.push(quote! {
            #field_ident(#field_ident)
        });

        match_arms.push(quote! {
            v if v == #disc => {
                #valid_field_ident::parse(data)
                    .map(|(pkt, rest)| (#validated_ident::#field_ident(pkt), rest))
            }
        });

        parse_match_arms.push(quote! {
            #validated_ident::#field_ident(v) => #ident::#field_ident(::ingot_types::Packet::Raw(v))
        });

        repr_match_arms.push(quote! {
            #repr_ident::#field_ident(v) => #ident::#field_ident(::ingot_types::Packet::Repr(v))
        });

        next_layer_wheres.push(quote! {
            #valid_field_ident<V>: ::ingot_types::NextLayer<Denom=T>
        });

        next_layer_match_arms.push(quote! {
            #validated_ident::#field_ident(v) => v.next_layer()
        });

        unpacks.push(quote! {
            impl<V> ::core::convert::TryFrom<#ident<V>> for ::ingot_types::Packet<#field_ident, #valid_field_ident<V>> {
                type Error = ::ingot_types::ParseError;

                fn try_from(value: #ident<V>) -> ::core::result::Result<Self, Self::Error> {
                    match value {
                        #ident::#field_ident(v) => Ok(v),
                        _ => ::core::result::Result::Err(ParseError::Unwanted),
                    }
                }
            }

            impl<V> ::core::convert::TryFrom<#validated_ident<V>> for ::ingot_types::Packet<#field_ident, #valid_field_ident<V>> {
                type Error = ::ingot_types::ParseError;

                fn try_from(value: #validated_ident<V>) -> ::core::result::Result<Self, Self::Error> {
                    match value {
                        #validated_ident::#field_ident(v) => Ok(v.into()),
                        _ => ::core::result::Result::Err(ParseError::Unwanted),
                    }
                }
            }
        });
    }

    quote!{
        pub enum #ident<V> {
            #( #top_vars ),*
        }

        pub enum #validated_ident<V> {
            #( #validated_vars ),*
        }

        pub enum #repr_ident {
            #( #repr_vars ),*
        }

        impl<V: ::ingot_types::Chunk> ::ingot_types::ParseChoice<V> for #validated_ident<V> {
            type Denom = #on;

            #[inline]
            fn parse_choice(data: V, hint: Self::Denom) -> ::ingot_types::ParseResult<(Self, V)> {
                match hint {
                    #( #match_arms ),*
                    _ => ::core::result::Result::Err(::ingot_types::ParseError::Unwanted)
                }
            }
        }

        impl<V> ::core::convert::From<#validated_ident<V>> for #ident<V> {
            #[inline]
            fn from(value: #validated_ident<V>) -> Self {
                match value {
                    #( #parse_match_arms ),*
                }
            }
        }

        impl<V> ::core::convert::From<#repr_ident> for #ident<V> {
            #[inline]
            fn from(value: #repr_ident) -> Self {
                match value {
                    #( #repr_match_arms ),*
                }
            }
        }

        impl<V: ::zerocopy::ByteSlice, T: Copy> ::ingot_types::NextLayer for #validated_ident<V>
        where #( #next_layer_wheres ),*
        {
            type Denom = T;

            #[inline]
            fn next_layer(&self) -> ::ingot_types::ParseResult<Self::Denom> {
                match self {
                    #( #next_layer_match_arms ),*
                }
            }
        }

        impl<V> ::ingot_types::HasView for #ident<V> {
            type ViewType = #validated_ident<V>;
        }

        #( #unpacks )*
    }.into()
}
