use darling::ast::NestedMeta;
use darling::Error as DarlingError;
use darling::FromMeta;
use proc_macro2::Ident;
use proc_macro2::TokenStream;
use quote::quote;
use syn::spanned::Spanned;
use syn::Error;
use syn::Path;

#[derive(FromMeta)]
struct ChoiceArgs {
    on: Path,
}

pub fn attr_impl(attr: TokenStream, item: syn::ItemEnum) -> TokenStream {
    let attr_args = match NestedMeta::parse_meta_list(attr.into()) {
        Ok(v) => v,
        Err(e) => {
            return DarlingError::from(e).write_errors().into();
        }
    };

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

    quote! {
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
    }
}
