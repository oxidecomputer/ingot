use darling::FromDeriveInput;
use darling::FromField;
use proc_macro2::Ident;
use proc_macro2::TokenStream;
use quote::format_ident;
use quote::quote;
use syn::parse_macro_input;
use syn::spanned::Spanned;
use syn::Data;
use syn::DeriveInput;
use syn::Error;
use syn::Expr;
use syn::ItemStruct;
use syn::Type;

#[derive(FromDeriveInput)]
#[darling(attributes(oxp))]
struct Args {
    // leaf_data: Option<syn::Path>,
}

#[derive(FromField)]
#[darling(attributes(oxpopt))]
struct LayerArgs {
    from: Option<syn::Path>,
}

#[proc_macro_derive(Parse, attributes(oxp, oxpopt))]
pub fn derive_parse(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let d_input = parse_macro_input!(input);

    let parsed_args = match Args::from_derive_input(&d_input) {
        Ok(o) => o,
        Err(e) => return e.write_errors().into(),
    };

    let DeriveInput { ref ident, ref data, .. } = d_input;

    let Data::Struct(data) = data else {
        return Error::new(
            d_input.span(),
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

        let (first_ty, conv_frag) = if let Some(a) = args.from {
            (
                quote! {#a},
                quote! {
                    let #fname: #ty = #fname.try_into()?;
                },
            )
        } else {
            (quote! {#ty}, quote! {})
        };

        let contents = if i == 0 {
            quote! {
                let #fname = #first_ty::parse(&mut cursor)?;
                #hint_frag
                #conv_frag
            }
        } else {
            quote! {
                let #fname = #first_ty::parse_choice(&mut cursor, Some(hint))?;
                #hint_frag
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
                d_input.span(),
                "packet parsing must be derived on a non-unit struct",
            )
            .into_compile_error()
            .into();
        }
    };

    quote! {
        impl<'a> Parsed<'a, #ident> {
            pub fn new(data: &'a mut [u8]) -> ParseResult<Self> {
                // todo: hygiene
                let mut cursor = Cursor { data, pos: 0 };

                #( #parse_points )*

                Ok(Self {
                    stack: HeaderStack(#ctor),
                    data: Cursor {
                        data: Pin::new(cursor.data),
                        pos: cursor.pos,
                    },
                })
            }
        }
    }
    .into()
}
