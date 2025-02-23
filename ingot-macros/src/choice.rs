// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
struct VariantArgs {}

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
    let mut next_layer_wheres_repr: Vec<TokenStream> = vec![];
    let mut next_layer_match_arms: Vec<TokenStream> = vec![];

    let mut from_ref_arms: Vec<TokenStream> = vec![];

    let mut unpacks: Vec<TokenStream> = vec![];

    let mut repr_wheres: Vec<TokenStream> = vec![];
    let mut valid_wheres: Vec<TokenStream> = vec![];
    let mut hybrid_wheres: Vec<TokenStream> = vec![];

    for var in &item.variants {
        let _state = VariantArgs::from_variant(var).unwrap();

        let Some((_, disc)) = &var.discriminant else {
            return Error::new(
                var.span(),
                "variant must have a valid discriminant",
            )
            .into_compile_error();
        };

        let id = &var.ident;
        let field_ident = quote! {
            #id
        };

        let valid_field_ident = Ident::new(&format!("Valid{id}"), ident.span());

        top_vars.push(quote! {
            #id(::ingot::types::Header<#field_ident, #valid_field_ident<V>>)
        });

        validated_vars.push(quote! {
            #id(#valid_field_ident<V>)
        });

        repr_vars.push(quote! {
            #id(#field_ident)
        });

        // where clauses for EmitDoesNotRelyOnBufContents
        let repr = quote! {
            #id
        };
        hybrid_wheres.push(repr.clone());
        repr_wheres.push(repr);

        let valid = quote! {
            #valid_field_ident<V>
        };
        hybrid_wheres.push(valid.clone());
        valid_wheres.push(valid);
        // where clauses done.

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
            #validated_ident::#id(v) => #ident::#id(::ingot::types::Header::Raw(v))
        });

        repr_match_arms.push(quote! {
            #repr_ident::#id(v) => #ident::#id(::ingot::types::Header::Repr(v.into()))
        });

        next_layer_wheres.push(quote! {
            #valid_field_ident<V>: ::ingot::types::NextLayer<Denom=T>
        });

        next_layer_wheres_repr.push(quote! {
            #id: ::ingot::types::NextLayer<Denom=T>
        });

        next_layer_match_arms.push(quote! {
            Self::#id(v) => v.next_layer()
        });

        from_ref_arms.push(quote! {
            #validated_ident::#id(v) => ::core::result::Result::Ok(#repr_ident::#id(v.try_into()?))
        });

        unpacks.push(quote! {
            impl ::core::convert::From<#id> for #repr_ident {
                #[inline]
                fn from(value: #id) -> Self {
                    Self::#id(value)
                }
            }

            impl<V: ::ingot::types::ByteSlice> ::core::convert::From<#id> for #ident<V> {
                #[inline]
                fn from(value: #id) -> Self {
                    Self::#id(::ingot::types::Header::Repr(value.into()))
                }
            }

            impl<V: ::ingot::types::ByteSlice> ::core::convert::TryFrom<#ident<V>> for ::ingot::types::Header<#field_ident, #valid_field_ident<V>> {
                type Error = ::ingot::types::ParseError;

                #[inline]
                fn try_from(value: #ident<V>) -> ::core::result::Result<Self, Self::Error> {
                    match value {
                        #ident::#id(v) => Ok(v),
                        _ => ::core::result::Result::Err(::ingot::types::ParseError::Unwanted),
                    }
                }
            }

            impl<V: ::ingot::types::ByteSlice> ::core::convert::TryFrom<#validated_ident<V>> for ::ingot::types::Header<#field_ident, #valid_field_ident<V>> {
                type Error = ::ingot::types::ParseError;

                #[inline]
                fn try_from(value: #validated_ident<V>) -> ::core::result::Result<Self, Self::Error> {
                    match value {
                        #validated_ident::#id(v) => Ok(v.into()),
                        _ => ::core::result::Result::Err(::ingot::types::ParseError::Unwanted),
                    }
                }
            }

            impl<V: ::ingot::types::ByteSlice> ::core::convert::TryFrom<#validated_ident<V>> for #valid_field_ident<V> {
                type Error = ::ingot::types::ParseError;

                #[inline]
                fn try_from(value: #validated_ident<V>) -> ::core::result::Result<Self, Self::Error> {
                    match value {
                        #validated_ident::#id(v) => Ok(v.into()),
                        _ => ::core::result::Result::Err(::ingot::types::ParseError::Unwanted),
                    }
                }
            }
        });
    }

    let repr_head = quote! {#repr_ident};

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

    let idents: Vec<_> = item.variants.iter().map(|item| &item.ident).collect();
    let first_ident = idents.first();

    let mut minimum_len = quote! {
        #first_ident::MINIMUM_LENGTH
    };
    for el in idents.iter().skip(1) {
        minimum_len = quote! {
            ::ingot::types::min(#minimum_len, #el::MINIMUM_LENGTH)
        }
    }

    quote! {
        pub enum #ident<V: ::ingot::types::ByteSlice> {
            #( #top_vars ),*
        }

        pub enum #validated_ident<V: ::ingot::types::ByteSlice> {
            #( #validated_vars ),*
        }

        #[derive(Debug, Clone, Eq, PartialEq)]
        pub enum #repr_head {
            #( #repr_vars ),*
        }

        impl<'a, V: ::ingot::types::SplitByteSlice + ::ingot::types::IntoBufPointer<'a> + 'a> ::ingot::types::HeaderParse<V> for #validated_ident<V> {
            #[inline]
            fn parse_choice(data: V, hint: ::core::option::Option<Self::Hint>) -> ::ingot::types::ParseResult<::ingot::types::Success<Self, V>> {
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

        impl<V: ::ingot::types::ByteSlice> ::core::convert::From<#validated_ident<V>> for #ident<V> {
            #[inline]
            fn from(value: #validated_ident<V>) -> Self {
                match value {
                    #( #parse_match_arms ),*
                }
            }
        }

        impl<V: ::ingot::types::ByteSlice> ::core::convert::From<#repr_head> for #ident<V> {
            #[inline]
            fn from(value: #repr_head) -> Self {
                match value {
                    #( #repr_match_arms ),*
                }
            }
        }

        impl<V: ::ingot::types::ByteSlice, T: Copy + Eq> ::ingot::types::NextLayer for #validated_ident<V>
        where #( #next_layer_wheres ),*
        {
            type Denom = T;
            type Hint = #on;

            #[inline]
            fn next_layer_choice(&self, hint: ::core::option::Option<Self::Hint>) -> ::core::option::Option<Self::Denom> {
                match self {
                    #( #next_layer_match_arms ),*
                }
            }
        }

        impl<T: Copy + Eq> ::ingot::types::NextLayer for #repr_head
        where #( #next_layer_wheres_repr ),*
        {
            type Denom = T;
            type Hint = #on;

            #[inline]
            fn next_layer_choice(&self, hint: ::core::option::Option<Self::Hint>) -> ::core::option::Option<Self::Denom> {
                match self {
                    #( #next_layer_match_arms ),*
                }
            }
        }

        impl<V: ::ingot::types::SplitByteSlice> ::ingot::types::ToOwnedPacket for #validated_ident<V> {
            type Target = #repr_head;
            #[inline]
            fn to_owned(&self, _hint: ::core::option::Option<Self::Hint>) -> ::ingot::types::ParseResult<Self::Target> {
                self.try_into()
            }
        }

        impl<V: ::ingot::types::ByteSlice> ::ingot::types::HeaderLen for #ident<V> {
            const MINIMUM_LENGTH: usize = #minimum_len;

            #[inline]
            fn packet_length(&self) -> usize {
                match self {
                    #( Self::#idents(v) => v.packet_length(), )*
                }
            }
        }

        impl<V: ::ingot::types::ByteSlice> ::ingot::types::HeaderLen for #validated_ident<V> {
            const MINIMUM_LENGTH: usize = #minimum_len;

            #[inline]
            fn packet_length(&self) -> usize {
                match self {
                    #( Self::#idents(v) => v.packet_length(), )*
                }
            }
        }

        impl ::ingot::types::HeaderLen for #repr_head {
            const MINIMUM_LENGTH: usize = #minimum_len;

            #[inline]
            fn packet_length(&self) -> usize {
                match self {
                    #( Self::#idents(v) => v.packet_length(), )*
                }
            }
        }

        impl<V: ::ingot::types::ByteSlice> ::ingot::types::Emit for #ident<V> {
            #[inline]
            fn emit_raw<B: ::ingot::types::ByteSliceMut>(&self, mut buf: B) -> usize {
                match self {
                    #( Self::#idents(v) => v.emit_raw(buf) ),*
                }
            }

            #[inline]
            fn needs_emit(&self) -> bool {
                match self {
                    #( Self::#idents(v) => v.needs_emit() ),*
                }
            }
        }

        impl<V: ::ingot::types::ByteSlice> ::ingot::types::Emit for #validated_ident<V> {
            #[inline]
            fn emit_raw<B: ::ingot::types::ByteSliceMut>(&self, mut buf: B) -> usize {
                match self {
                    #( Self::#idents(v) => v.emit_raw(buf) ),*
                }
            }

            #[inline]
            fn needs_emit(&self) -> bool {
                match self {
                    #( Self::#idents(v) => v.needs_emit() ),*
                }
            }
        }

        impl ::ingot::types::Emit for #repr_head {
            #[inline]
            fn emit_raw<B: ::ingot::types::ByteSliceMut>(&self, mut buf: B) -> usize {
                match self {
                    #( Self::#idents(v) => v.emit_raw(buf) ),*
                }
            }

            #[inline]
            fn needs_emit(&self) -> bool {
                match self {
                    #( Self::#idents(v) => v.needs_emit() ),*
                }
            }
        }

        unsafe impl ::ingot::types::EmitDoesNotRelyOnBufContents for #repr_head
            where #( #repr_wheres: ::ingot::types::EmitDoesNotRelyOnBufContents ),*
        {}
        unsafe impl<V: ::ingot::types::ByteSlice> ::ingot::types::EmitDoesNotRelyOnBufContents for #validated_ident<V>
            where #( #valid_wheres: ::ingot::types::EmitDoesNotRelyOnBufContents ),*
        {}
        unsafe impl<V: ::ingot::types::ByteSlice> ::ingot::types::EmitDoesNotRelyOnBufContents for #ident<V>
            where
                #( #hybrid_wheres: ::ingot::types::EmitDoesNotRelyOnBufContents ),*
        {}

        impl<V: ::ingot::types::ByteSlice> ::ingot::types::HasView<V> for #ident<V> {
            type ViewType = #validated_ident<V>;
        }

        impl<V: ::ingot::types::ByteSlice> ::ingot::types::HasView<V> for #repr_head {
            type ViewType = #validated_ident<V>;
        }

        impl<V: ::ingot::types::ByteSlice> ::ingot::types::HasRepr for #validated_ident<V> {
            type ReprType = #repr_head;
        }

        // from Valid -> Repr
        impl<V: ::ingot::types::SplitByteSlice> ::core::convert::TryFrom<&#validated_ident<V>> for #repr_head {
            type Error = ::ingot::types::ParseError;

            #[inline]
            fn try_from(value: & #validated_ident<V>) -> ::core::result::Result<Self, Self::Error> {
                match value {
                    #( #from_ref_arms ),*
                }
            }
        }

        #( #unpacks )*
    }
}
