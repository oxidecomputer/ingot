use syn::parse::Parse;
use syn::parse_macro_input;
use syn::spanned::Spanned;
use syn::Error;
use syn::ItemType;
use syn::Type;
use syn::TypeTuple;

struct TypeInput {
    ty: ItemType,
    inner: TypeTuple,
}

impl Parse for TypeInput {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let ty: ItemType = input.parse()?;

        let Type::Tuple(inner) = *ty.ty.clone() else {
            return Err(Error::new(
                ty.span(),
                "parse stack must be a tuple type",
            ));
        };

        Ok(Self { ty, inner })
    }
}

/// ```rust,no_compile
/// #[parse]
/// type
/// ```
#[proc_macro_attribute]
pub fn parse(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let i = item.clone();
    let input = parse_macro_input!(i as TypeInput);

    item
}
