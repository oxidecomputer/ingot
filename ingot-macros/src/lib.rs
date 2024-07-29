use darling::FromDeriveInput;
use parse::ParserArgs;
use syn::parse_macro_input;
use syn::ItemEnum;

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
