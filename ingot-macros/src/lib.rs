use darling::FromDeriveInput;
use parse::ParserArgs;
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{parse_macro_input, Ident, ItemEnum};

mod choice;
mod packet;
mod parse;

/// Derive macro for parsing complete packets, potentially spanning
/// several byte slices.
///
/// The macro consumes a struct definition where each field is an
/// owned/borrowed `Packet` type:
///
/// ```rust,ignore
/// #[derive(Parse)]
/// pub struct UdpParser<Q: ByteSlice> {
///     pub eth: EthernetPacket<Q>,
///     pub l3: L3<Q>,
///     #[ingot(from = "L4<Q>")]
///     pub l4: UdpPacket<Q>,
/// }
/// ```
///
/// The input struct must be generic over a single `ByteSlice` parameter.
///
/// Headers are parsed in order, where the hint from each layer (if available)
/// is used to choose which header is parsed at the next layer. Individual
/// (non-`choice`) headers will be parsed unconditionally, disregarding input
/// hints.
///
/// The example defines two struct types: an owned/borrowed hybrid `UdpParser`
/// and a purely borrowed `ValidUdpParser`. Each can be parsed via the `HeaderParse`
/// trait (single slice), or the `parse_read` method (multi-slice via `Read`).
///
/// ## Per-field attributes
/// * `#[ingot(from = "<type>")]` – specifies that this field must be parsed first
///   via `<type>`, before converting to its final type via `TryInto<Error=ParseError>`.
///   `choice` types automatically implement `TryInto` for each element.
/// * `#[ingot(control = <fn>)]` – specifies a control function to execute after parsing
///   this layer, allowing parsing to continue or terminate (accept/reject the packet).
///   This function takes as its input a `&<field_ty>::ViewType`, and returns a `ParseControl`.
///
/// Either mechanism can be used to validate packets or admit only specific protocols.
#[proc_macro_derive(Parse, attributes(ingot))]
pub fn derive_parse(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let d_input = parse_macro_input!(input);

    let parsed_args = match ParserArgs::from_derive_input(&d_input) {
        Ok(o) => o,
        Err(e) => return e.write_errors().into(),
    };

    parse::derive(d_input, parsed_args).into()
}

/// Derive macro for defining individual protocol headers.
///
/// The macro takes the owned representation of a header as its input (e.g.,
/// `MyHdr`), and defines a packed wire-format equivalent (`ValidMyHdr`).
///
/// ```rust,ignore
/// use ingot::types::primitives::*;
///
/// #[derive(Ingot)]
/// #[ingot(impl_default)]
/// pub struct MyHdr {
///     pub field1: u8,
///     #[ingot(is = "u1", default = true)]
///     pub field2: bool,
///     pub field3: u3,
///     pub field4: u20be,
///     #[ingot(var_len = "field3 * 4")]
///     pub field5: Vec<u8>,
/// }
/// ```
///
/// Fields are defined in terms of *primitive integer types*, variable-length
/// byteslices (`Vec<u8>`), and parsed sub-headers.
/// Primitive types are:
/// * Signed/unsigned integers <= 1 byte (`u1`, `i8`).
/// * Longer integers with a defined endianness (`u27be`).
/// * Byte arrays of fixed length (`[u8; 12]`).
///
/// All fields in a header must be aligned to an 8-bit boundary, and integer
/// type aliases are defined via `ingot::types::primitives`.
///
/// Ingot will define `ValidMyHdr::parse`, implement `Emit` on both types,
/// and will define the traits `MyHdrRef` and `MyHdrMut` for both types.
/// Both types can reference one another via the `HasView` and `HasRepr` traits.
/// `ValidMyHdr` will be split into a series of fixed-width and variable-width
/// chunks internally -- these can be directly accessed if required.
///
/// ## Top-level attributes
/// * `#[ingot(impl_default)]` – derives `Default` on the owned struct using
///   each field's type default, or the field-specific default when given.
///
/// ## Per-field attributes
/// * `#[ingot(is = "<type>")]` – allows the use of higher-level types and conversions
///   of fields using the `NetworkRepr` trait. The field will be parsed as the primitive
///   `<type>` before converting to the desired type.
/// * `#[ingot(default = <expr>)]` – specifies a default value for this field
///   when deriving `Default`.
/// * `#[ingot(next_layer)]` – indicates that this field is to be used as a hint
///   for choosing the next header during full packet parsing.
/// * `#[ingot(subparse())]` – extract this field by explicitly parsing the
///   indicated struct. This is intended for extension headers. Incompatible
///   with the `is` attribute.
///   - `#[ingot(subparse(on_next_layer))]` – parses this field using the `next_layer`
///     field to make a choice. This field will be used as the source of the next header.
/// * `#[ingot(var_len = "<expr>")]` – Determines the length of a `Vec<u8>` field,
///   or provides an exact length for a variable-length subparse. This expression
///   can access any prior fixed-width field.
#[proc_macro_derive(Ingot, attributes(ingot))]
pub fn derive_ingot(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let d_input = parse_macro_input!(input);

    let args = match packet::IngotArgs::from_derive_input(&d_input) {
        Ok(o) => o,
        Err(e) => return e.write_errors().into(),
    };

    packet::derive(args).into()
}

/// Attribute macro for a selection over one or more individual headers,
/// conditional on an input hint.
///
/// A choice is defined using the attribute macro as follows:
/// ```rust,ignore
/// #[choice(on = IpProtocol)]
/// pub enum L4 {
///     Tcp = IpProtocol::TCP,
///     Udp = IpProtocol::UDP,
/// }
/// ```
/// Each identifier on the left hand side is the name of an *owned* type
/// defined using the `Ingot` macro, while the right hand side is the
/// hint mapped to each internal header type.
/// Hints not captured by a choice will parse as `Err(ParseError::Unwanted)`.
///
/// Ingot will define three `enum`s from this definition: `L4` (owned/borrowed),
/// `ValidL4` (borrowed), and `L4Repr` (owned).
/// All implement `Emit`, while `ValidL4`will implement `ParseChoice`.
///
/// ## Top-level attributes
/// * `#[choice(on = <type>)]` – The input type of hint used for selection
///   in `parse_choice`. **Mandatory**.
/// * `#[choice(map_on = <fn>)]` – An optional function used to transform the
///   input hint.
///
/// Hint types must implement `Eq` and `PartialEq`.
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

/// Proc macro which defines primitive integers of various endianness
/// from 9 to 128 bits.
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

/// Defines `Header` and `Emit` for tuple types up to length 16 elements.
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
            impl<#( #tys_so_far ),*> crate::HeaderLen for #curr_ty
            where
                #( #tys_so_far: crate::HeaderLen ),*
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
