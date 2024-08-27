use darling::{ast::NestedMeta, Error as DarlingError, FromMeta, FromVariant};
use proc_macro2::{Ident, TokenStream};
use quote::quote;
use syn::{spanned::Spanned, Error, Path};

#[derive(FromMeta)]
struct ChoiceArgs {
    on: Path,
    map_on: Option<Path>,
}

#[derive(FromVariant)]
#[darling(attributes(ingot))]
struct VariantArgs {
    #[darling(default)]
    generic: bool,
}

pub fn attr_impl(attr: TokenStream, item: syn::ItemEnum) -> TokenStream {
    let attr_args = match NestedMeta::parse_meta_list(attr) {
        Ok(v) => v,
        Err(e) => {
            return DarlingError::from(e).write_errors();
        }
    };

    let ChoiceArgs { on, map_on } = match ChoiceArgs::from_list(&attr_args) {
        Ok(v) => v,
        Err(e) => {
            return e.write_errors();
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

    let mut packet_len_arms: Vec<TokenStream> = vec![];

    let mut unpacks: Vec<TokenStream> = vec![];

    let mut needs_generic = false;

    for var in item.variants {
        let state = VariantArgs::from_variant(&var).unwrap();

        needs_generic |= state.generic;

        let Some((_, disc)) = var.discriminant else {
            return Error::new(
                var.span(),
                "variant must have a valid discriminant",
            )
            .into_compile_error();
        };

        let id = var.ident;
        let field_ident = if state.generic {
            quote! {#id<V>}
        } else {
            quote! {#id}
        };

        let valid_field_ident = Ident::new(&format!("Valid{id}"), ident.span());

        top_vars.push(quote! {
            #id(::ingot::types::Packet<#field_ident, #valid_field_ident<V>>)
        });

        validated_vars.push(quote! {
            #id(#valid_field_ident<V>)
        });

        repr_vars.push(quote! {
            #id(#field_ident)
        });

        match_arms.push(quote! {
            v if v == #disc => {
                #valid_field_ident::parse(data)
                    .map(|(val, hint, remainder)|{
                        let val = #validated_ident::#id(val);
                        (val, hint, remainder)
                    })
            }
        });

        parse_match_arms.push(quote! {
            #validated_ident::#id(v) => #ident::#id(::ingot::types::Packet::Raw(v))
        });

        repr_match_arms.push(quote! {
            #repr_ident::#id(v) => #ident::#id(::ingot::types::Packet::Repr(v.into()))
        });

        next_layer_wheres.push(quote! {
            #valid_field_ident<V>: ::ingot::types::NextLayer<Denom=T>
        });

        next_layer_match_arms.push(quote! {
            #validated_ident::#id(v) => v.next_layer()
        });

        packet_len_arms.push(quote! {
            Self::#id(v) => v.packet_length(),
        });

        unpacks.push(quote! {
            impl<V> ::core::convert::TryFrom<#ident<V>> for ::ingot::types::Packet<#field_ident, #valid_field_ident<V>> {
                type Error = ::ingot::types::ParseError;

                fn try_from(value: #ident<V>) -> ::core::result::Result<Self, Self::Error> {
                    match value {
                        #ident::#id(v) => Ok(v),
                        _ => ::core::result::Result::Err(::ingot::types::ParseError::Unwanted),
                    }
                }
            }

            impl<V> ::core::convert::TryFrom<#validated_ident<V>> for ::ingot::types::Packet<#field_ident, #valid_field_ident<V>> {
                type Error = ::ingot::types::ParseError;

                fn try_from(value: #validated_ident<V>) -> ::core::result::Result<Self, Self::Error> {
                    match value {
                        #validated_ident::#id(v) => Ok(v.into()),
                        _ => ::core::result::Result::Err(::ingot::types::ParseError::Unwanted),
                    }
                }
            }
        });
    }

    let repr_head = if needs_generic {
        quote! {#repr_ident<V>}
    } else {
        quote! {#repr_ident}
    };

    let choice_convert = map_on.map(|v| {
        quote! {
            let hint2 = #v(hint);
        }
    });

    let match_hint = if choice_convert.is_none() {
        quote! {hint}
    } else {
        quote! {hint2}
    };

    quote! {
        pub enum #ident<V> {
            #( #top_vars ),*
        }

        pub enum #validated_ident<V> {
            #( #validated_vars ),*
        }

        pub enum #repr_head {
            #( #repr_vars ),*
        }

        impl<V: ::ingot::types::SplitByteSlice> ::ingot::types::ParseChoice<V, #on> for #validated_ident<V> {
            #[inline]
            fn parse_choice(data: V, hint: ::core::option::Option<#on>) -> ::ingot::types::ParseResult<::ingot::types::Success<Self>> {
                use ::ingot::types::HeaderParse;
                let ::core::option::Option::Some(hint) = hint else {
                    return ::core::result::Result::Err(::ingot::types::ParseError::NeedsHint);
                };

                #choice_convert

                match #match_hint {
                    #( #match_arms ),*
                    _ => ::core::result::Result::Err(::ingot::types::ParseError::Unwanted)
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

        impl<V> ::core::convert::From<#repr_head> for #ident<V> {
            #[inline]
            fn from(value: #repr_head) -> Self {
                match value {
                    #( #repr_match_arms ),*
                }
            }
        }

        impl<V: ::zerocopy::ByteSlice, T: Copy> ::ingot::types::NextLayer for #validated_ident<V>
        where #( #next_layer_wheres ),*
        {
            type Denom = T;

            #[inline]
            fn next_layer(&self) -> ::core::option::Option<Self::Denom> {
                match self {
                    #( #next_layer_match_arms ),*
                }
            }
        }

        impl<V: ::ingot::types::ByteSlice> ::ingot::types::Header for #ident<V> {
            const MINIMUM_LENGTH: usize = 0; // TODO

            fn packet_length(&self) -> usize {
                match self {
                    #( #packet_len_arms )*
                }
            }
        }

        impl<V> ::ingot::types::HasView for #ident<V> {
            type ViewType = #validated_ident<V>;
        }

        impl<V: ::ingot::types::ByteSlice> ::ingot::types::HasBuf for #ident<V> {
            type BufType = V;
        }

        impl<V: ::ingot::types::ByteSlice> ::ingot::types::HasBuf for #validated_ident<V> {
            type BufType = V;
        }

        #( #unpacks )*
    }
}
