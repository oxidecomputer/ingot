use darling::FromDeriveInput;
use darling::FromField;
use proc_macro2::Ident;
use proc_macro2::TokenStream;
use quote::format_ident;
use quote::quote;
use syn::spanned::Spanned;
use syn::Data;
use syn::DeriveInput;
use syn::Error;
use syn::GenericArgument;
use syn::PathArguments;
use syn::Token;
use syn::Type;
use syn::TypeInfer;
use syn::TypePath;

#[derive(FromDeriveInput)]
#[darling(attributes(oxp), supports(struct_named, struct_tuple))]
pub struct ParserArgs {}

#[derive(FromField)]
#[darling(attributes(oxpopt, ingot))]
struct LayerArgs {
    from: Option<syn::Path>,
}

pub fn derive(input: DeriveInput, _args: ParserArgs) -> TokenStream {
    let DeriveInput { ref ident, ref data, ref generics, .. } = input;

    let Data::Struct(data) = data else {
        return Error::new(
            input.span(),
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
                input.span(),
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
