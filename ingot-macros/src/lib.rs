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
use syn::parse_macro_input;
use syn::spanned::Spanned;
use syn::Data;
use syn::DeriveInput;
use syn::Error;
use syn::Expr;
use syn::ExprLit;
use syn::ItemEnum;
use syn::Lit;
use syn::Path;
use syn::Type;
use syn::TypeArray;

#[derive(FromDeriveInput)]
#[darling(attributes(oxp), supports(struct_named, struct_tuple))]
struct ParserArgs {}

#[derive(FromField)]
#[darling(attributes(oxpopt))]
struct LayerArgs {
    from: Option<syn::Path>,
}

#[proc_macro_derive(Parse, attributes(oxp, oxpopt))]
pub fn derive_parse(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let d_input = parse_macro_input!(input);

    let parsed_args = match ParserArgs::from_derive_input(&d_input) {
        Ok(o) => o,
        Err(e) => return e.write_errors().into(),
    };

    let DeriveInput { ref ident, ref data, .. } = d_input;

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

        let (first_ty, conv_frag) = if let Some(a) = args.from {
            (
                quote! {#a},
                quote! {
                    let #fname: #ty = #fname.try_into()?;
                },
            )
        } else {
            (quote! {#ty}, quote! {})
        };

        let contents = if i == 0 {
            quote! {
                let #fname = #first_ty::parse(&mut cursor)?;
                #hint_frag
                #conv_frag
            }
        } else {
            quote! {
                let #fname = #first_ty::parse_choice(&mut cursor, Some(hint))?;
                #hint_frag
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
        impl<'a> Parsed<'a, #ident> {
            pub fn new(data: &'a mut [u8]) -> ParseResult<Self> {
                // todo: hygiene
                let mut cursor = Cursor { data, pos: 0 };

                #( #parse_points )*

                Ok(Self {
                    stack: HeaderStack(#ctor),
                    data: Cursor {
                        data: Pin::new(cursor.data),
                        pos: cursor.pos,
                    },
                    _self_referential: PhantomPinned,
                })
            }
        }
    }
    .into()
}

#[proc_macro_derive(Parse2, attributes(oxp, oxpopt))]
pub fn derive_parse2(
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let d_input = parse_macro_input!(input);

    let parsed_args = match ParserArgs::from_derive_input(&d_input) {
        Ok(o) => o,
        Err(e) => return e.write_errors().into(),
    };

    let DeriveInput { ref ident, ref data, .. } = d_input;

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

        let (first_ty, conv_frag) = if let Some(a) = args.from {
            (
                quote! {#a},
                quote! {
                    let #fname: #ty = #fname.try_into()?;
                },
            )
        } else {
            (quote! {#ty}, quote! {})
        };

        let contents = if i == 0 {
            quote! {
                let #fname = #first_ty::parse(&mut cursor)?;
                #hint_frag
                #conv_frag
            }
        } else {
            quote! {
                let #fname = #first_ty::parse_choice(&mut cursor, Some(hint))?;
                #hint_frag
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
        impl<Q> Parsed2<#ident, Q: ::ingot_types::Read> {
            pub fn new(data: Q) -> ParseResult<Self> {

                #( #parse_points )*

                Ok(Self {
                    stack: HeaderStack(#ctor),
                    data: Cursor {
                        data: Pin::new(cursor.data),
                        pos: cursor.pos,
                    },
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

    first_bit: usize,
    n_bits: usize,
}

// struct TyData {
//     n_bits:
// }

fn bits_in_primitive(ident: &Ident) -> Result<usize, syn::Error> {
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

    let n_spec: usize = fields.get(1).unwrap().as_str().parse().unwrap();

    // TODO: apply endianness here or figure out wtf users want.
    let end_spec = fields.get(2).map(|v| v.as_str());

    Ok(n_spec)
}

fn bits_in_type(ty: &Type) -> Result<usize, syn::Error> {
    match ty {
        Type::Array(TypeArray{ elem, len: Expr::Lit(ExprLit{lit: Lit::Int(l), ..}), .. })  => {
            Ok(bits_in_type(elem)? * l.base10_parse::<usize>()?)
        },
        e @ Type::Array(TypeArray{ .. })  => {
            Err(Error::new(e.span(), "array length must be an integer literal"))
        }
        Type::Tuple(a) => {
            let mut n_bits = 0;
            for elem in &a.elems {
                n_bits += bits_in_type(elem)?;
            }
            Ok(n_bits)
        },
        Type::Path(a) => {
            let b = a.path.require_ident()?;
            bits_in_primitive(b)
        },

        Type::Paren(a) => bits_in_type(&a.elem),

        e => Err(Error::new(e.span(), "field must be constructed from a literal, tuple, or array of integral types")),
    }
}

#[proc_macro_derive(Ingot, attributes(ingot, is))]
pub fn derive_ingot(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let d_input = parse_macro_input!(input);

    let mut parsed_args = match IngotArgs::from_derive_input(&d_input) {
        Ok(o) => o,
        Err(e) => return e.write_errors().into(),
    };

    let IngotArgs { ident, data } = parsed_args;

    let validated_ident = Ident::new(&format!("Valid{ident}"), ident.span());
    let ref_ident = Ident::new(&format!("{ident}Ref"), ident.span());
    let mut_ident = Ident::new(&format!("{ident}Mut"), ident.span());

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

        let n_bits = match bits_in_type(&underlying_ty) {
            Ok(v) => v,
            Err(v) => return v.into_compile_error().into(),
        };

        let marker = format!("my offset is {t_bits}+={n_bits} bits");

        let ident = field.ident.unwrap();

        fields.push(ValidField {
            repr: underlying_ty.clone(),
            ident: ident.clone(),
            first_bit: t_bits,
            n_bits,
        });

        t_bits += n_bits;

        trait_defs.push(quote! {
            fn #ident(&self) -> #user_ty;
        });
        trait_impls.push(quote! {
            fn #ident(&self) -> #user_ty {
                let a = #marker;
                todo!()
            }
        });
        direct_trait_impls.push(quote! {
            fn #ident(&self) -> #user_ty {
                self.#ident
            }
        });

        let mut_name = Ident::new(&format!("set_{ident}"), ident.span());
        trait_mut_defs.push(quote! {
            fn #mut_name(&mut self, val: #user_ty);
        });
        trait_mut_impls.push(quote! {
            fn #mut_name(&mut self, val: #user_ty) {
                todo!()
            }
        });
        direct_trait_mut_impls.push(quote! {
            fn #mut_name(&mut self, val: #user_ty) {
                self.#ident = val;
            }
        });

        packet_impls.push(quote! {
            fn #ident(&self) -> #user_ty {
                match self {
                    ::ingot_types::Packet::Repr(o) => o.#ident(),
                    ::ingot_types::Packet::Raw(b) => b.#ident(),
                }
            }
        });
        packet_mut_impls.push(quote! {
            fn #mut_name(&mut self, val: #user_ty) {
                match self {
                    ::ingot_types::Packet::Repr(o) => o.#mut_name(val),
                    ::ingot_types::Packet::Raw(b) => b.#mut_name(val),
                };
            }
        });

        if let Some(nl) = field.next_layer {
            if next_layer.is_some() {
                return Error::new(
                    ident.span(),
                    "only one field can be nominated as a next-header hint",
                )
                .into_compile_error()
                .into();
            }

            if nl.or_extension {
                todo!("integrated extension parsing not yet ready")
            }

            next_layer = Some(quote! {
                impl<V: AsRef<[u8]>> ::ingot_types::NextLayer for #validated_ident<V> {
                    type Denom = #user_ty;

                    #[inline]
                    fn next_layer(&self) -> ::ingot_types::ParseResult<Self::Denom> {
                        Ok(self.#ident())
                    }
                }
            });
        }
    }

    if t_bits % 8 != 0 {
        return Error::new(
            fields.last().unwrap().repr.span(),
            format!("fields are not byte-aligned -- total {t_bits}b"),
        )
        .into_compile_error()
        .into();
    }

    quote! {
        pub struct #validated_ident<V>(V);

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

        impl<V: AsRef<[u8]>> #ref_ident for #validated_ident<V> {
            #( #trait_impls )*
        }

        impl #ref_ident for #ident {
            #( #direct_trait_impls )*
        }

        pub trait #mut_ident {
            #( #trait_mut_defs )*
        }

        impl<V: AsMut<[u8]>> #mut_ident for #validated_ident<V> {
            #( #trait_mut_impls )*
        }

        impl #mut_ident for #ident {
            #( #direct_trait_mut_impls )*
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
            fn parse(from: V) -> ::ingot_types::ParseResult<(Self, V)> {
                use ::ingot_types::Header;

                if from.as_ref().len() < #ident::MINIMUM_LENGTH {
                    Err(::ingot_types::ParseError::TooSmall)
                } else {
                    let (l, r) = from.split(#ident::MINIMUM_LENGTH);
                    Ok((#validated_ident(l), r))
                }
            }
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

        unpacks.push(quote! {
            impl<V> ::core::convert::TryFrom<#ident<V>> for ::ingot_types::Packet<#field_ident, #valid_field_ident<V>> {
                type Error = ::ingot_types::ParseError;

                fn try_from(value: #ident<V>) -> Result<Self, Self::Error> {
                    match value {
                        #ident::#field_ident(v) => Ok(v),
                        _ => Err(ParseError::Unwanted),
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

        impl<V: ::ingot_types::Chunk> ::ingot_types::ParseChoice2<V> for #validated_ident<V> {
            type Denom = #on;

            fn parse_choice(data: V, hint: Self::Denom) -> ::ingot_types::ParseResult<(Self, V)> {
                match hint {
                    #( #match_arms ),*
                    _ => Err(::ingot_types::ParseError::Unwanted)
                }
            }
        }

        impl<V> ::core::convert::From<#validated_ident<V>> for #ident<V> {
            fn from(value: #validated_ident<V>) -> Self {
                match value {
                    #( #parse_match_arms ),*
                }
            }
        }

        impl<V> ::core::convert::From<#repr_ident> for #ident<V> {
            fn from(value: #repr_ident) -> Self {
                match value {
                    #( #repr_match_arms ),*
                }
            }
        }

        #( #unpacks )*
    }.into()
}
