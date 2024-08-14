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
use syn::Field;
use syn::GenericArgument;
use syn::PathArguments;
use syn::Token;
use syn::Type;
use syn::TypeInfer;
use syn::TypePath;

#[derive(FromDeriveInput)]
#[darling(supports(struct_named, struct_tuple))]
pub struct ParserArgs {}

#[derive(FromField)]
#[darling(attributes(ingot))]
struct LayerArgs {
    from: Option<syn::Path>,
}

struct AnalysedField {
    args: LayerArgs,
    field: Field,
    first_ty: TypePath,
}

pub fn derive(input: DeriveInput, _args: ParserArgs) -> TokenStream {
    // TODO: enforce no lifetimes, one type param.

    let DeriveInput { ref ident, ref data, .. } = input;

    let Data::Struct(data) = data else {
        return Error::new(
            input.span(),
            "packet parsing must be derived on a struct",
        )
        .into_compile_error();
    };

    let mut parse_points: Vec<TokenStream> = vec![];
    let mut onechunk_parse_points: Vec<TokenStream> = vec![];
    let mut fnames: Vec<Ident> = vec![];

    let mut analysed = vec![];
    for field in &data.fields {
        let args = match LayerArgs::from_field(field) {
            Ok(o) => o,
            Err(e) => return e.write_errors(),
        };

        let Type::Path(ref ty) = field.ty else { panic!() };

        let first_ty = if let Some(a) = &args.from {
            TypePath { qself: None, path: a.clone() }
        } else {
            ty.clone()
        };

        analysed.push(AnalysedField { args, field: field.clone(), first_ty });
    }

    let n_fields = data.fields.len();
    for (i, AnalysedField { args, field, first_ty }) in
        analysed.iter().enumerate()
    {
        let next = analysed.get(i + 1);

        let Type::Path(ref ty) = field.ty else { panic!() };

        let fname = if let Some(ref v) = field.ident {
            v.clone()
        } else {
            format_ident!("f_{i}")
        };

        let hint_frag = if let Some(next) = next {
            // next.ty
            // let first_ty = next.first_ty
            quote! {
                let hint = #fname.next_layer()?;
            }
        } else {
            quote! {}
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

        let (contents, ns_contents) = if i == 0 {
            // Hacky generic handling.
            let mut local_ty = first_ty.clone();
            local_ty.qself = None;
            if let Some(el) = local_ty.path.segments.last_mut() {
                el.arguments = PathArguments::None;
            }

            (
                quote! {
                    let (#fname, remainder) = #local_ty::parse(slice)?;
                    #hint_frag
                    #slice_frag
                    #conv_frag
                },
                quote! {
                    let (#fname, remainder) = #local_ty::parse(slice)?;
                    #hint_frag
                    let slice = remainder;
                    #conv_frag
                },
            )
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

            (
                quote! {
                    let (#fname, remainder) = <#local_ty as HasView>::ViewType::parse_choice(slice, hint)?;
                    #hint_frag
                    #slice_frag
                    #conv_frag
                },
                quote! {
                    let (#fname, remainder) = <#local_ty as HasView>::ViewType::parse_choice(slice, hint)?;
                    #hint_frag
                    let slice = remainder;
                    #conv_frag
                },
            )
        };

        parse_points.push(contents);
        onechunk_parse_points.push(ns_contents);
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
            .into_compile_error();
        }
    };

    quote! {
        impl<V: ::ingot_types::Chunk> ::ingot_types::HasBuf for #ident<V> {
            type BufType = V;
        }

        impl<V: ::ingot_types::Chunk> ::ingot_types::HeaderParse for #ident<V> {
            type Target = Self;
            fn parse(from: V) -> ::ingot_types::ParseResult<(Self, V)> {
                let slice = from;

                #( #onechunk_parse_points )*

                Ok((#ctor, slice))
            }
        }

        impl<V: ::ingot_types::Chunk> #ident<V> {
            pub fn parse_read<Q: ::ingot_types::Read<Chunk = V>>(mut data: Q) -> ::ingot_types::ParseResult<::ingot_types::Parsed<#ident<Q::Chunk>, Q>> {
                let slice = data.next_chunk()?;

                #( #parse_points )*

                let last_chunk = match remainder.len() {
                    // Attempt to pull another slice out.
                    0 => data.next_chunk().ok(),
                    _ => Some(remainder),
                };

                ::core::result::Result::Ok(::ingot_types::Parsed {
                    stack: ::ingot_types::HeaderStack(#ctor),
                    data,
                    last_chunk,
                    // _self_referential: PhantomPinned,
                })
            }
        }
    }
}
