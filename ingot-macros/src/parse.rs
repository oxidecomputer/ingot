// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

impl AnalysedField {
    fn crstr_name(&self) -> Ident {
        Ident::new(
            &format!("{}_LABEL", self.fname).to_uppercase(),
            self.fname.span(),
        )
    }

    fn crstr_defn(&self) -> TokenStream {
        let fname_str = format!("{}\0", self.fname);
        let fname_ident = self.crstr_name();
        quote! {
            static #fname_ident: ::ingot::types::CRStr =
                ::ingot::types::CRStr::new_unchecked(#fname_str);
        }
    }
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
    let mut layer_name_defs: Vec<TokenStream> = vec![];

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

        let done = AnalysedField {
            args,
            field: field.clone(),
            first_ty,
            optional,
            fname,
            target_ty: ty.clone(),
        };

        layer_name_defs.push(done.crstr_defn());

        analysed.push(done);
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

    let mut first_err_location = None;
    let n_fields = data.fields.len();
    for (
        i,
        analysed @ AnalysedField {
            first_ty,
            optional,
            fname,
            args,
            target_ty,
            ..
        },
    ) in analysed.iter().enumerate()
    {
        let err_location = analysed.crstr_name();
        if first_err_location.is_none() {
            first_err_location = Some(err_location.clone());
        }
        let hint_frag = if i < n_fields {
            quote! {
                let hint = #fname.next_layer();
            }
        } else {
            quote! {}
        };

        let conv_frag = if optional.is_none() {
            quote! {
                let #fname = #fname.try_into()
                    .map_err(|e| ::ingot::types::PacketParseError::new(::ingot::types::ParseError::from(e), &#err_location))?;
            }
        } else {
            quote! {
                let #fname = #fname.map(|v| v.try_into()).transpose()
                    .map_err(|e| ::ingot::types::PacketParseError::new(::ingot::types::ParseError::from(e), &#err_location))?;
            }
        };

        let slice_frag = if i == n_fields - 1 {
            quote! {}
        } else {
            quote! {
                let slice = if remainder.as_ref().is_empty() {
                    data.next_chunk()
                        .map_err(|e| ::ingot::types::PacketParseError::new(e, &#err_location))?
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
                            ::ingot::types::PacketParseError::new(
                                ::ingot::types::ParseError::CannotAccept,
                                &#err_location
                            )
                        );
                    }
                    ::ingot::types::ParseControl::Reject => {
                        return ::core::result::Result::Err(
                            ::ingot::types::PacketParseError::new(
                                ::ingot::types::ParseError::Reject,
                                &#err_location
                            )
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

        bare_ty.qself = None;
        if let Some(el) = bare_ty.path.segments.last_mut() {
            el.arguments = PathArguments::None;
        }

        let destructure = quote! {
            (#fname, hint, remainder)
        };

        let (parse_chunk, parse_chunk_slice, parse_choice, parse_choice_slice) =
            if optional.is_some() {
                (
                    quote! {
                        let (#fname, remainder, hint) = if accepted {
                            (::core::option::Option::None, slice, None)
                        } else {
                            let #destructure = <#local_ty as HasView<_>>::ViewType::parse(slice)
                                .map_err(|e| ::ingot::types::PacketParseError::new(e.convert_read_parse(&mut data), &#err_location))?;
                            #hint_frag
                            (::core::option::Option::Some(#fname), remainder)
                        };
                    },
                    quote! {
                        let (#fname, remainder, hint) = if accepted {
                            (::core::option::Option::None, slice, None)
                        } else {
                            let #destructure = <#local_ty as HasView<_>>::ViewType::parse(slice)
                                .map_err(|e| ::ingot::types::PacketParseError::new(e, &#err_location))?;
                            #hint_frag
                            (::core::option::Option::Some(#fname), remainder)
                        };
                    },
                    quote! {
                        let (#fname, remainder, hint) = if accepted {
                            // should this be last??
                            (::core::option::Option::None, slice, None)
                        } else {
                            let #destructure = <#local_ty as HasView<_>>::ViewType::parse_choice(slice, hint)
                                .map_err(|e| ::ingot::types::PacketParseError::new(e.convert_read_parse(&mut data), &#err_location))?;
                            (::core::option::Option::Some(#fname), remainder, hint)
                        };
                    },
                    quote! {
                        let (#fname, remainder, hint) = if accepted {
                            // should this be last??
                            (::core::option::Option::None, slice, None)
                        } else {
                            let #destructure = <#local_ty as HasView<_>>::ViewType::parse_choice(slice, hint)
                                .map_err(|e| ::ingot::types::PacketParseError::new(e, &#err_location))?;
                            (::core::option::Option::Some(#fname), remainder, hint)
                        };
                    },
                )
            } else {
                (
                    quote! {
                        let #destructure = <#local_ty as HasView<_>>::ViewType::parse(slice)
                            .map_err(|e| ::ingot::types::PacketParseError::new(e.convert_read_parse(&mut data), &#err_location))?;
                    },
                    quote! {
                        let #destructure = <#local_ty as HasView<_>>::ViewType::parse(slice)
                            .map_err(|e| ::ingot::types::PacketParseError::new(e, &#err_location))?;
                    },
                    quote! {
                        let #destructure = <#local_ty as HasView<_>>::ViewType::parse_choice(slice, hint)
                            .map_err(|e| ::ingot::types::PacketParseError::new(e.convert_read_parse(&mut data), &#err_location))?;
                    },
                    quote! {
                        let #destructure = <#local_ty as HasView<_>>::ViewType::parse_choice(slice, hint)
                            .map_err(|e| ::ingot::types::PacketParseError::new(e, &#err_location))?;
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
                    #slice_frag
                    #conv_frag
                },
                quote! {
                    #parse_chunk_slice
                    #ctl_fn_chunk
                    let slice = remainder;
                    #conv_frag
                },
            )
        } else {
            // Hackier generic handling.
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
                    #slice_frag
                    #conv_frag
                },
                quote! {
                    #parse_choice_slice
                    #ctl_fn_chunk
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

    let Some(first_err_location) = first_err_location else {
        return Error::new(
            input.span(),
            "packet must contain at least one header",
        )
        .into_compile_error();
    };

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
            type Hint = ();
        }

        impl<'a, V: ::ingot::types::SplitByteSlice + ::ingot::types::IntoBufPointer<'a> + 'a> ::ingot::types::HeaderParse<V> for #ident<V> {
            #[inline]
            fn parse(from: V) -> ::ingot::types::ParseResult<::ingot::types::Success<Self, V>> {
                Self::parse_slice(from)
                    .map_err(|e| e.into())
            }
        }

        impl<V: ::ingot::types::ByteSlice> ::ingot::types::NextLayer for #validated_ident<V> {
            type Denom = ();
            type Hint = ();
        }

        impl<'a, V: ::ingot::types::SplitByteSlice + ::ingot::types::IntoBufPointer<'a> + 'a> ::ingot::types::HeaderParse<V> for #validated_ident<V> {
            #[inline]
            fn parse(from: V) -> ::ingot::types::ParseResult<::ingot::types::Success<Self, V>> {
                Self::parse_slice(from)
                    .map_err(|e| e.into())
            }
        }

        impl<'a, V: ::ingot::types::SplitByteSlice + ::ingot::types::IntoBufPointer<'a> + 'a> #ident<V> {
            #[inline]
            pub fn parse_slice(from: V) -> ::ingot::types::PacketParseResult<::ingot::types::Success<Self, V>> {
                #imports
                #( #layer_name_defs )*

                let slice = from;
                #accept_state

                #( #onechunk_parse_points )*

                Ok((#ctor, None, slice))
            }

            #[inline]
            pub fn parse_read<Q: ::ingot::types::Read<Chunk = V>>(mut data: Q) -> ::ingot::types::PacketParseResult<::ingot::types::Parsed<#ident<Q::Chunk>, Q>> {
                #imports
                #( #layer_name_defs )*

                let slice = data.next_chunk()
                    .map_err(|e| ::ingot::types::PacketParseError::new(e, &#first_err_location))?;
                #accept_state

                #( #parse_points )*

                let last_chunk = match remainder.len() {
                    // Do not attempt to pull another slice out.
                    // Some clients need to be able to make strong
                    // assumptions about which segments are allowed
                    // to be read in one shot (e.g., needing a pullup of
                    // any segments after the headers block).
                    0 => None,
                    _ => Some(remainder),
                };

                ::core::result::Result::Ok(::ingot::types::Parsed {
                    headers: #ctor,
                    data,
                    last_chunk,
                })
            }
        }

        impl<'a, V: ::ingot::types::SplitByteSlice + ::ingot::types::IntoBufPointer<'a> + 'a> #validated_ident<V> {
            #[inline]
            pub fn parse_slice(from: V) -> ::ingot::types::PacketParseResult<::ingot::types::Success<Self, V>> {
                #imports
                #( #layer_name_defs )*

                let slice = from;
                #accept_state

                #( #onechunk_parse_points )*

                Ok((#ctor, None, slice))
            }

            #[inline]
            pub fn parse_read<Q: ::ingot::types::Read<Chunk = V>>(mut data: Q)
                -> ::ingot::types::PacketParseResult<::ingot::types::Parsed<#validated_ident<Q::Chunk>, Q>>
            {
                #imports
                #( #layer_name_defs )*

                let slice = data.next_chunk()
                    .map_err(|e| ::ingot::types::PacketParseError::new(e, &#first_err_location))?;
                #accept_state

                #( #parse_points )*

                let last_chunk = match remainder.len() {
                    // Do not attempt to pull another slice out.
                    // Some clients need to be able to make strong
                    // assumptions about which segments are allowed
                    // to be read in one shot (e.g., needing a pullup of
                    // any segments after the headers block).
                    0 => None,
                    _ => Some(remainder),
                };

                ::core::result::Result::Ok(::ingot::types::Parsed {
                    headers: #ctor,
                    data,
                    last_chunk,
                })
            }
        }
    }
}
