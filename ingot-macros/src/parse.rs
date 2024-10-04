use darling::{FromDeriveInput, FromField};
use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};
use syn::{
    spanned::Spanned, Data, DeriveInput, Error, Field, GenericArgument, Path,
    PathArguments, Token, Type, TypeInfer, TypePath,
};

#[derive(FromDeriveInput)]
#[darling(supports(struct_named, struct_tuple))]
pub struct ParserArgs {}

#[derive(FromField)]
#[darling(attributes(ingot))]
struct LayerArgs {
    from: Option<Path>,
    control: Option<Path>,
}

#[allow(unused)]
struct AnalysedField {
    args: LayerArgs,
    field: Field,
    first_ty: TypePath,
    // holds an inner type
    optional: Option<Type>,
    fname: Ident,
    target_ty: TypePath,
}

pub fn derive(input: DeriveInput, _args: ParserArgs) -> TokenStream {
    let DeriveInput { ref ident, ref data, ref generics, .. } = input;
    let validated_ident = Ident::new(&format!("Valid{ident}"), ident.span());

    let Data::Struct(data) = data else {
        return Error::new(
            input.span(),
            "packet parsing must be derived on a struct",
        )
        .into_compile_error();
    };

    if let Some(lifetime) = generics.lifetimes().next() {
        return Error::new(
            lifetime.span(),
            "packet parsing cannot have explicit lifetimes",
        )
        .into_compile_error();
    }

    let type_params: Vec<_> = generics.type_params().cloned().collect();
    if type_params.is_empty() || type_params.len() > 1 {
        return Error::new(
            generics.span(),
            "parsed packets must be generic over exactly one buffer type",
        )
        .into_compile_error();
    }
    let type_param = &type_params[0].ident;

    let mut parse_points: Vec<TokenStream> = vec![];
    let mut onechunk_parse_points: Vec<TokenStream> = vec![];
    let mut valid_fields: Vec<TokenStream> = vec![];
    let mut into_fields: Vec<TokenStream> = vec![];

    let mut analysed = vec![];
    for (i, field) in data.fields.iter().enumerate() {
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

        let optional = match (ty.path.segments.len(), ty.path.segments.first())
        {
            (1, Some(el)) if el.ident == "Option" => {
                if let PathArguments::AngleBracketed(args) = &el.arguments {
                    if args.args.len() != 1 {
                        None
                    } else if let Some(GenericArgument::Type(t)) =
                        args.args.first()
                    {
                        Some(t.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        };

        let fname = if let Some(ref v) = field.ident {
            v.clone()
        } else {
            format_ident!("f_{i}")
        };

        analysed.push(AnalysedField {
            args,
            field: field.clone(),
            first_ty,
            optional,
            fname,
            target_ty: ty.clone(),
        });
    }

    // handle the case where we have a sled of Option<>s at the end
    let mut accept_allowed_from = analysed.len();
    for (i, AnalysedField { optional, .. }) in analysed.iter().enumerate().rev()
    {
        if optional.is_some() {
            accept_allowed_from = i - 1;
        } else {
            break;
        }
    }
    let any_options = analysed.iter().any(|v| v.optional.is_some());
    let any_controls = analysed.iter().any(|v| v.args.control.is_some());
    let all_fnames = analysed.iter().map(|v| &v.fname).collect::<Vec<_>>();

    let ctor = match data.fields {
        syn::Fields::Named(_) => quote! { Self { #( #all_fnames ),* } },
        syn::Fields::Unnamed(_) => quote! { Self ( #( #all_fnames ),* ) },
        syn::Fields::Unit => {
            return Error::new(
                input.span(),
                "packet parsing must be derived on a non-unit struct",
            )
            .into_compile_error();
        }
    };

    let n_fields = data.fields.len();
    for (i, AnalysedField { first_ty, optional, fname, args, target_ty, .. }) in
        analysed.iter().enumerate()
    {
        let hint_frag = if i < n_fields {
            // next.ty
            // let first_ty = next.first_ty
            quote! {
                let hint = #fname.next_layer();
            }
        } else {
            quote! {}
        };

        let conv_frag = if optional.is_none() {
            quote! {
                let #fname = #fname.try_into()?;
            }
        } else {
            quote! {
                let #fname = #fname.map(|v| v.try_into()).transpose()?;
            }
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

        if any_options && any_controls && i == accept_allowed_from {
            let allow = quote! {
                can_accept = true;
            };
            parse_points.push(allow.clone());
            onechunk_parse_points.push(allow);
        }

        let ctl_fn_chunk = args.control.as_ref().map(|ctl_fn| {
            quote! {
                match #ctl_fn(&#fname) {
                    ::ingot::types::ParseControl::Continue => {},
                    ::ingot::types::ParseControl::Accept if can_accept => {
                        accepted = true;
                    },
                    ::ingot::types::ParseControl::Accept => {
                        return ::core::result::Result::Err(
                            ::ingot::types::ParseError::CannotAccept
                        );
                    }
                    ::ingot::types::ParseControl::Reject => {
                        return ::core::result::Result::Err(
                            ::ingot::types::ParseError::Reject
                        );
                    },
                }
            }
        });

        let base_ty = match optional {
            Some(ty) => ty.clone(),
            None => syn::Type::Path(first_ty.clone()),
        };
        let mut local_ty = base_ty.clone();
        let mut bare_ty = target_ty.clone();

        if let Type::Path(ref mut t) = local_ty {
            t.qself = None;
            if let Some(el) = t.path.segments.last_mut() {
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
        }

        // target_ty.qself = None;
        // if let Some(el) = target_ty.path.segments.last_mut() {
        //     // replace all generic args with inferred.
        //     match &mut el.arguments {
        //         PathArguments::AngleBracketed(args) => {
        //             for arg in args.args.iter_mut() {
        //                 if let GenericArgument::Type(t) = arg {
        //                     *t = Type::Infer(TypeInfer {
        //                         underscore_token: Token![_](t.span()),
        //                     })
        //                 }
        //             }
        //         }
        //         PathArguments::None => todo!(),
        //         PathArguments::Parenthesized(_) => todo!(),
        //     }
        // }

        bare_ty.qself = None;
        if let Some(el) = bare_ty.path.segments.last_mut() {
            el.arguments = PathArguments::None;
        }

        let destructure = quote! {
            (#fname, hint, remainder)
        };

        // TODO: implement and figure in conditions (when/skip_if)
        let (parse_chunk, parse_choice) = if optional.is_some() {
            (
                quote! {
                    let (#fname, remainder, hint) = if accepted {
                        (::core::option::Option::None, slice, None)
                    } else {
                        let #destructure = <#local_ty as HasView<_>>::ViewType::parse(slice)?;
                        #hint_frag
                        (::core::option::Option::Some(#fname), remainder)
                    };
                },
                quote! {
                    let (#fname, remainder, hint) = if accepted {
                        // should this be last??
                        (::core::option::Option::None, slice, None)
                    } else {
                        let #destructure = <#local_ty as HasView<_>>::ViewType::parse_choice(slice, hint)?;
                        // #hint_frag
                        (::core::option::Option::Some(#fname), remainder, hint)
                    };
                },
            )
        } else {
            (
                quote! {
                    let #destructure = <#local_ty as HasView<_>>::ViewType::parse(slice)?;
                    // #hint_frag
                },
                quote! {
                    let #destructure = <#local_ty as HasView<_>>::ViewType::parse_choice(slice, hint)?;
                    // #hint_frag
                },
            )
        };

        let (contents, ns_contents) = if i == 0 {
            // Hacky generic handling.
            if let Type::Path(ref mut t) = local_ty {
                t.qself = None;
                if let Some(el) = t.path.segments.last_mut() {
                    el.arguments = PathArguments::None;
                }
            }

            (
                quote! {
                    #parse_chunk
                    #ctl_fn_chunk
                    // #hint_frag
                    #slice_frag
                    #conv_frag
                },
                quote! {
                    #parse_chunk
                    #ctl_fn_chunk
                    // #hint_frag
                    let slice = remainder;
                    #conv_frag
                },
            )
        } else {
            // Hackier generic handling.
            // let mut local_ty = first_ty.clone();
            if let Type::Path(ref mut t) = local_ty {
                t.qself = None;
                if let Some(el) = t.path.segments.last_mut() {
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
            }

            (
                quote! {
                    #parse_choice
                    #ctl_fn_chunk
                    // #hint_frag
                    #slice_frag
                    #conv_frag
                },
                quote! {
                    #parse_choice
                    #ctl_fn_chunk
                    // #hint_frag
                    let slice = remainder;
                    #conv_frag
                },
            )
        };

        parse_points.push(contents);
        onechunk_parse_points.push(ns_contents);
        if let Some(prior_target) = optional {
            valid_fields.push(quote! {
                pub #fname: ::core::option::Option<<#prior_target as ::ingot::types::HasView<#type_param>>::ViewType>
            });
            into_fields.push(quote! {
                let #fname = val.#fname.map(Into::into);
            });
        } else {
            valid_fields.push(quote! {
                pub #fname: <#target_ty as ::ingot::types::HasView<#type_param>>::ViewType
            });
            into_fields.push(quote! {
                let #fname = #bare_ty::from(val.#fname).into();
            });
        }
    }

    let accept_state = quote! {
        let mut can_accept = false;
        let mut accepted = false;
    };

    let imports = quote! {
        use ::ingot::types::HasView;
        use ::ingot::types::NextLayer;
        use ::ingot::types::ParseChoice;
        use ::ingot::types::HeaderParse;
    };

    quote! {
        pub struct #validated_ident<#type_param: ByteSlice> {
            #( #valid_fields ),*
        }

        impl<V: ::ingot::types::ByteSlice> ::core::convert::From<#validated_ident<V>> for #ident<V> {
            #[inline]
            fn from(val: #validated_ident<V>) -> Self {
                #( #into_fields )*

                #ctor
            }
        }

        impl<V: ::ingot::types::ByteSlice> ::ingot::types::NextLayer for #ident<V> {
            type Denom = ();
        }

        impl<'a, V: ::ingot::types::SplitByteSlice + ::ingot::types::IntoBufPointer<'a> + 'a> ::ingot::types::HeaderParse<V> for #ident<V> {
            #[inline]
            fn parse(from: V) -> ::ingot::types::ParseResult<::ingot::types::Success<Self, V>> {
                #imports

                let slice = from;
                #accept_state

                #( #onechunk_parse_points )*

                Ok((#ctor, None, slice))
            }
        }

        impl<V: ::ingot::types::ByteSlice> ::ingot::types::NextLayer for #validated_ident<V> {
            type Denom = ();
        }

        impl<'a, V: ::ingot::types::SplitByteSlice + ::ingot::types::IntoBufPointer<'a> + 'a> ::ingot::types::HeaderParse<V> for #validated_ident<V> {
            #[inline]
            fn parse(from: V) -> ::ingot::types::ParseResult<::ingot::types::Success<Self, V>> {
                #imports

                let slice = from;
                #accept_state

                #( #onechunk_parse_points )*

                Ok((#ctor, None, slice))
            }
        }

        impl<'a, V: ::ingot::types::SplitByteSlice + ::ingot::types::IntoBufPointer<'a> + 'a> #ident<V> {
            #[inline]
            pub fn parse_read<Q: ::ingot::types::Read<Chunk = V>>(mut data: Q) -> ::ingot::types::ParseResult<::ingot::types::Parsed<#ident<Q::Chunk>, Q>> {
                #imports

                let slice = data.next_chunk()?;
                #accept_state

                #( #parse_points )*

                let last_chunk = match remainder.len() {
                    // Attempt to pull another slice out.
                    0 => data.next_chunk().ok(),
                    _ => Some(remainder),
                };

                ::core::result::Result::Ok(::ingot::types::Parsed {
                    stack: #ctor,
                    data,
                    last_chunk,
                })
            }
        }

        impl<'a, V: ::ingot::types::SplitByteSlice + ::ingot::types::IntoBufPointer<'a> + 'a> #validated_ident<V> {
            #[inline]
            pub fn parse_read<Q: ::ingot::types::Read<Chunk = V>>(mut data: Q) -> ::ingot::types::ParseResult<::ingot::types::Parsed<#validated_ident<Q::Chunk>, Q>> {
                #imports

                let slice = data.next_chunk()?;
                #accept_state

                #( #parse_points )*

                let last_chunk = match remainder.len() {
                    // Attempt to pull another slice out.
                    0 => data.next_chunk().ok(),
                    _ => Some(remainder),
                };

                ::core::result::Result::Ok(::ingot::types::Parsed {
                    stack: #ctor,
                    data,
                    last_chunk,
                })
            }
        }
    }
}
