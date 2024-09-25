use darling::ast;
use darling::FromDeriveInput;
use darling::FromField;
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
use syn::Field;
use syn::Fields;
use syn::ItemStruct;
use syn::Lit;
use syn::PatLit;
use syn::Type;
use syn::TypeArray;
use syn::TypePath;

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

#[derive(FromField)]
#[darling(attributes(ingot, is))]
struct FieldArgs {
    is: Option<Type>,

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

    for field in field_data.fields {
        let underlying_ty =
            if let Some(ty) = &field.is { ty } else { &field.ty };
        let user_ty = &field.ty;

        let n_bits = match bits_in_type(&underlying_ty) {
            Ok(v) => v,
            Err(v) => return v.into_compile_error().into(),
        };

        let marker = format!("my offset is {n_bits} bits");

        let ident = field.ident.unwrap();

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
    }

    let validated_ident = Ident::new(&format!("Valid{ident}"), ident.span());

    let ref_ident = Ident::new(&format!("{ident}Ref"), ident.span());
    let mut_ident = Ident::new(&format!("{ident}Mut"), ident.span());

    quote! {
        pub struct #validated_ident<V>(V);

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