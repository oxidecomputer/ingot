use darling::FromDeriveInput;
use parse::ParserArgs;
use proc_macro2::Span;
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
enum IntClass {
    BigEndian,
    LittleEndian,
    HostEndian,
}

impl IntClass {
    pub fn suffix(&self) -> &str {
        match self {
            IntClass::BigEndian => "be",
            IntClass::LittleEndian => "le",
            IntClass::HostEndian => "he",
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
        [IntClass::BigEndian, IntClass::LittleEndian, IntClass::HostEndian];

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
