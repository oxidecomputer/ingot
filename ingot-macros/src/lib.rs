use darling::FromDeriveInput;
use parse::ParserArgs;
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{parse_macro_input, Ident, ItemEnum};

mod choice;
mod packet;
mod parse;

#[proc_macro_derive(Parse, attributes(oxp, oxpopt, ingot))]
pub fn derive_parse(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let d_input = parse_macro_input!(input);

    let parsed_args = match ParserArgs::from_derive_input(&d_input) {
        Ok(o) => o,
        Err(e) => return e.write_errors().into(),
    };

    parse::derive(d_input, parsed_args).into()
}

// per-packet
#[proc_macro_derive(Ingot, attributes(ingot, is))]
pub fn derive_ingot(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let d_input = parse_macro_input!(input);

    let args = match packet::IngotArgs::from_derive_input(&d_input) {
        Ok(o) => o,
        Err(e) => return e.write_errors().into(),
    };

    packet::derive(args).into()
}

#[proc_macro_attribute]
pub fn choice(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let item = syn::parse_macro_input!(item as ItemEnum);
    choice::attr_impl(attr.into(), item).into()
}

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
enum IntEndianClass {
    Big,
    Little,
    Host,
}

impl IntEndianClass {
    pub fn suffix(&self) -> &str {
        match self {
            IntEndianClass::Big => "be",
            IntEndianClass::Little => "le",
            IntEndianClass::Host => "he",
        }
    }
}

#[proc_macro]
pub fn define_primitive_types(
    _arg: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    // TODO: signed integers.
    let prefixes = ["u"];
    let bitwidths = 9..=128usize;
    let suffixes =
        [IntEndianClass::Big, IntEndianClass::Little, IntEndianClass::Host];

    let mut body = vec![];
    for (prefix, width, suffix) in
        itertools::iproduct!(prefixes, bitwidths, suffixes)
    {
        let t_name = Ident::new(
            &format!("{prefix}{width}{}", suffix.suffix()),
            Span::call_site(),
        );
        let expand_width = width.next_power_of_two();
        let base_name =
            Ident::new(&format!("{prefix}{expand_width}"), Span::call_site());
        body.push(quote! {
            pub type #t_name = #base_name;
        })
    }

    quote! {
        #( #body )*
    }
    .into()
}

#[proc_macro]
pub fn define_tuple_trait_impls(
    _arg: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let mut tys_so_far: Vec<_> = vec![];
    let mut vars_so_far: Vec<_> = vec![];
    let mut impl_set: Vec<TokenStream> = vec![];
    for i in 0..16 {
        let this_ty = Ident::new(&format!("T{i}"), Span::call_site());
        let this_var = Ident::new(&format!("v{i}"), Span::call_site());
        tys_so_far.push(this_ty.clone());
        vars_so_far.push(this_var.clone());

        let curr_ty = quote! {(#( #tys_so_far, )*)};

        impl_set.push(quote! {
            impl<#( #tys_so_far ),*> crate::Header for #curr_ty
            where
                #( #tys_so_far: crate::Header ),*
            {
                const MINIMUM_LENGTH: usize = #( #tys_so_far::MINIMUM_LENGTH + )* 0;

                #[inline]
                fn packet_length(&self) -> usize {
                    let (#( #vars_so_far, )*) = self;
                    #( #vars_so_far.packet_length() + )* 0
                }
            }
        });

        impl_set.push(quote! {
            impl<#( #tys_so_far ),*> crate::Emit for #curr_ty
            where
                #( #tys_so_far: crate::Emit ),*
            {
                #[inline]
                fn emit_raw<V: crate::ByteSliceMut>(&self, mut buf: V) -> usize {
                    let (#( ref #vars_so_far, )*) = &self;
                    let mut pos = 0;
                    let rest = &mut buf[..];

                    #(
                        let out_now = #vars_so_far.emit_raw(&mut rest[..]);
                        let (_, rest) = rest.split_at_mut(out_now);
                        pos += out_now;
                    )*

                    pos
                }

                #[inline]
                fn needs_emit(&self) -> bool {
                    let (#( ref #vars_so_far, )*) = &self;
                    #( #vars_so_far.needs_emit() || )* false
                }
            }
        });

        impl_set.push(quote! {
            unsafe impl<#( #tys_so_far ),*> crate::EmitDoesNotRelyOnBufContents for #curr_ty
            where
                #( #tys_so_far: crate::EmitDoesNotRelyOnBufContents ),*
            {}
        });
    }

    quote! {
        #( #impl_set )*
    }
    .into()
}
