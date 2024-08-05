use darling::ast;
use darling::FromDeriveInput;
use darling::FromField;
use darling::FromMeta;
use proc_macro2::Ident;
use proc_macro2::Span;
use proc_macro2::TokenStream;
use quote::quote;
use regex::Regex;
use std::cell::RefCell;
use std::rc::Rc;
use syn::spanned::Spanned;
use syn::Error;
use syn::Expr;
use syn::ExprLit;
use syn::Lit;
use syn::Type;
use syn::TypeArray;

#[derive(FromDeriveInput)]
#[darling(attributes(ingot), supports(struct_named))]
pub struct IngotArgs {
    ident: Ident,
    data: ast::Data<(), FieldArgs>,
}

#[derive(FromMeta, Default)]
#[darling(default)]
pub struct NextLayerSpec {
    #[darling(default)]
    or_extension: bool,
}

#[derive(FromField)]
#[darling(attributes(ingot, is))]
pub struct FieldArgs {
    is: Option<Type>,
    next_layer: Option<NextLayerSpec>,

    ident: Option<syn::Ident>,
    ty: Type,
}

#[derive(Clone, Debug)]
struct HybridField {
    ident: Ident,
    n_bits: usize,
    first_bit: usize,
}

struct ValidField {
    repr: Type,
    ident: Ident,
    user_ty: Type,

    first_bit: usize,
    analysis: Analysed,

    /// indicates child field of the
    sub_ref_idx: usize,
    hybrid: Option<PrimitiveInHybrid>,
}

impl ValidField {
    fn getter_name(&self) -> &Ident {
        &self.ident
    }

    fn ref_name(&self) -> Ident {
        Ident::new(&format!("{}_ref", self.ident), self.ident.span())
    }

    fn mut_name(&self) -> Ident {
        Ident::new(&format!("{}_mut", self.ident), self.ident.span())
    }

    fn setter_name(&self) -> Ident {
        Ident::new(&format!("set_{}", self.ident), self.ident.span())
    }

    fn is_primitive(&self) -> bool {
        matches!(self.analysis.ty, ReprType::Primitive { .. })
    }
}

struct PrimitiveInHybrid {
    parent_field: Rc<RefCell<HybridField>>,
    first_bit_inner: usize,
    n_bits: usize,
    endianness: Option<Endianness>,
}

#[derive(Clone, Copy)]
enum FieldOp {
    Get,
    Set,
}

impl PrimitiveInHybrid {
    fn first_byte(&self) -> usize {
        self.first_bit_inner / 8
    }

    fn last_byte_exclusive(&self) -> usize {
        self.first_byte() + self.byteslice_len()
    }

    fn byteslice_len(&self) -> usize {
        let whole_bytes = self.n_bits / 8;
        whole_bytes + if self.n_bits % 8 != 0 { 1 } else { 0 }
    }

    fn get_set_body(&self, field: &ValidField, op: FieldOp) -> TokenStream {
        // NOTE: we might be able to optimise this by just reading the largest
        // possible int we can and fixing it up, but the endianness considerations
        // are finicky to say the least.

        // NOTE: if we're reading a POT-size int here, we're already unaligned
        // from a byte boundary, so we need to read more bytes than the dtype.
        // Start with a read of the biggest u<x> we can fit.
        let next_int_sz = self.n_bits.next_power_of_two().max(8);
        let ceiled_bits = self.n_bits.max(8);
        let repr_sz = if ceiled_bits.max(8).is_power_of_two() {
            ceiled_bits
        } else {
            next_int_sz
        };

        // Straddle over byte boundaries, where applicable.
        let left_to_lose = self.first_bit_inner as u32 % 8;
        let left_overspill = (8 - left_to_lose) % 8;
        let right_overspill = (self.first_bit_inner + self.n_bits) as u32 % 8;
        let right_to_lose = (8 - right_overspill) % 8;

        let left_include_mask =
            0xffu8.wrapping_shl(left_to_lose).wrapping_shr(left_to_lose);
        let right_include_mask =
            0xffu8.wrapping_shr(right_to_lose).wrapping_shl(right_to_lose);

        let left_exclude_mask = !left_include_mask;
        let right_exclude_mask = !right_include_mask;

        let little_endian =
            self.endianness.map(|v| v.is_little_endian()).unwrap_or_default();

        let (general_shift_amt, general_mask, last_mask, last_shift) =
            if !little_endian {
                let shift_amt = (8 - right_overspill) % 8;
                let other_shift_amt = (8 - left_overspill) % 8;
                (
                    shift_amt,
                    right_include_mask,
                    left_include_mask,
                    other_shift_amt,
                )
            } else {
                let shift_amt = (8 - left_overspill) % 8;
                let other_shift_amt = (8 - right_overspill) % 8;
                (
                    shift_amt,
                    left_exclude_mask,
                    right_exclude_mask,
                    other_shift_amt,
                )
            };

        let needed_bytes = repr_sz / 8;
        // let spare_bits = self.n_bits as u32 % 8;
        let first_byte = self.first_byte();
        let last_byte_ex = self.last_byte_exclusive();

        let target_ty = &field.repr;

        let conv_frag = match (op, self.n_bits) {
            (FieldOp::Get, n) if n < 8 => {
                quote! { in_bytes[0] }
            }
            (FieldOp::Get, _) => {
                let Some(e) = self.endianness else {
                    panic!("u>8 without known endian")
                };
                let method = e.std_from_bytes_method();
                quote! { #target_ty::#method(in_bytes) }
            }
            (FieldOp::Set, n) if n < 8 => {
                quote! { [val_raw] }
            }
            (FieldOp::Set, _) => {
                let Some(e) = self.endianness else {
                    panic!("u>8 without known endian")
                };
                let method = e.std_to_bytes_method();
                quote! { #target_ty::#method(val) }
            }
        };

        let on_wire_len = self.byteslice_len();

        let mut byte_reads = vec![];
        let mut byte_stores = vec![];

        let desired_align = if !little_endian {
            self.byte_aligned_at_end()
        } else {
            self.byte_aligned_at_start()
        };

        match (little_endian, desired_align, op) {
            // good align -- memcpy, then fixup last byte
            (false, true, FieldOp::Get) => {
                let first_filled_byte = needed_bytes - self.byteslice_len();
                byte_reads.push(quote! {
                    in_bytes[#first_filled_byte..].copy_from_slice(slice);
                });

                if last_mask != 0 {
                    byte_reads.push(quote! {
                        in_bytes[#first_filled_byte] &= #last_mask;
                    });
                }
            }
            (true, true, FieldOp::Get) => {
                // NOTE: this will need to be left aligned for little endian
                let last_filled_byte = self.byteslice_len()
                    - if right_overspill != 0 { 1 } else { 0 };
                byte_reads.push(quote! {
                    in_bytes[..#on_wire_len].copy_from_slice(&slice[..#on_wire_len]);
                });

                if right_overspill != 0 {
                    byte_reads.push(quote! {
                        in_bytes[#last_filled_byte] &= #last_mask;
                        in_bytes[#last_filled_byte] >>= #general_shift_amt;
                    });
                }
            }

            (false, false, FieldOp::Get) => {
                for (i, src_byte) in
                    (first_byte..last_byte_ex).rev().enumerate()
                {
                    let write_this_cycle =
                        (src_byte - first_byte).min(needed_bytes - 1);

                    byte_reads.push(quote! {
                        let b = slice[#write_this_cycle];
                    });

                    // don't carry the masked portion of this byte
                    // back into the previous one if we're the first.
                    if i != 0 {
                        byte_reads.push(quote! {
                            // let m = b & #general_mask;
                            in_bytes[(#write_this_cycle + 1)] |= (b << (#right_overspill));
                        });
                    }

                    if i != self.byteslice_len() - 1 || last_mask == 0 {
                        byte_reads.push(quote! {
                            in_bytes[#write_this_cycle] = (b >> #general_shift_amt);
                        });
                    } else {
                        byte_reads.push(quote! {
                            in_bytes[#write_this_cycle] = (b & #last_mask) >> #general_shift_amt;
                        });
                    }
                }
            }
            (false, true, FieldOp::Set) => {
                let first_filled_byte = needed_bytes - self.byteslice_len();
                let (copy_from, copy_into): (usize, usize) = if left_overspill
                    != 0
                {
                    // mask out bits we're inserting in leftmost byte
                    // ||= in that byte
                    byte_stores.push(quote! {
                        slice[0] &= #left_exclude_mask;
                        slice[0] |= (val_as_bytes[#first_filled_byte] & #left_include_mask);
                    });

                    (first_filled_byte + 1, 1)
                } else {
                    (first_filled_byte, 0)
                };

                byte_stores.push(quote! {
                    slice[#copy_into..].copy_from_slice(&val_as_bytes[#copy_from..]);
                });
            }
            (true, true, FieldOp::Set) => {
                let last_filled_byte = self.byteslice_len();
                let last_byte_idx = last_filled_byte - 1;
                let bytes_limit: usize = if right_overspill != 0 {
                    // mask out bits we're inserting in rightmost byte
                    // ||= in that byte
                    byte_stores.push(quote! {
                        slice[#last_byte_idx] &= #right_include_mask;
                        slice[#last_byte_idx] |= (val_as_bytes[#last_byte_idx] & #right_exclude_mask);
                    });

                    last_filled_byte - 1
                } else {
                    last_filled_byte
                };

                byte_stores.push(quote! {
                    slice[..#bytes_limit].copy_from_slice(&val_as_bytes[..#bytes_limit]);
                });
            }
            (false, false, FieldOp::Set) => {
                let n_repr_bytes =
                    (self.n_bits / 8) + ((self.n_bits % 8) != 0) as usize;
                let bs_len = self.byteslice_len();
                byte_stores.push(quote! {
                    #[cfg(test)]
                    std::eprintln!("iter {} vs. {} vs {}", #needed_bytes, #n_repr_bytes, #bs_len);
                    let last_el = slice.len() - 1;
                });

                if left_overspill != 0 {
                    byte_stores.push(quote! {
                        slice[0] &= #left_exclude_mask;
                    });
                }

                if right_overspill != 0 {
                    byte_stores.push(quote! {
                        slice[last_el] &= #right_exclude_mask;
                    });
                }

                // let shift = right_overspill;
                let shift = general_shift_amt;

                for (i, src_byte) in
                    (needed_bytes - n_repr_bytes..needed_bytes).enumerate()
                {
                    let dst_byte = first_byte + i;

                    // first byte and left overspill: be careful on first set
                    byte_stores.push(quote! {
                        let b = val_as_bytes[#src_byte];
                        let base = b << #shift;
                        let rem = b >> ((8 - #shift) % 8);
                    });

                    if i == 0 && left_overspill == 0 {
                        byte_stores.push(quote! {
                            slice[#i] = base;
                        });
                    } else {
                        byte_stores.push(quote! {
                            slice[#i] |= base;
                        });
                    }

                    if i > 0 {
                        byte_stores.push(quote! {
                            slice[#i - 1] |= rem;
                        });
                    }
                }
            }
            (false, false, FieldOp::Set) => {
                // TODO
                byte_stores.push(quote! {
                    todo!()
                });
            }
            (true, false, _) => {
                // TODO
                // byte_reads.push(quote! {
                //     todo!()
                // });
            }
        }

        let read_from = self.parent_field.borrow().ident.clone();
        let chunk = syn::Index::from(field.sub_ref_idx);

        match op {
            FieldOp::Get => quote! {
                let mut in_bytes = [0u8; #needed_bytes];
                let slice = &self.#chunk.#read_from[#first_byte..#last_byte_ex];

                #( #byte_reads )*

                #[cfg(test)]
                {
                    std::eprintln!("---");
                    std::eprintln!("{} {} {:08b} {:08b} {}", #left_overspill, #right_overspill, #general_mask, #last_mask, #general_shift_amt);
                    std::eprintln!("{in_bytes:x?}");
                    // std::eprintln!("{in_bytes:02x}");
                }

                let val = #conv_frag;
            },
            FieldOp::Set => quote! {
                #[cfg(test)]
                {
                    std::eprintln!("BEFORE ---");

                    std::eprintln!("{:08b} {:08b}", #left_include_mask, #left_exclude_mask);
                    std::eprintln!("{:08b} {:08b}", #right_include_mask, #right_exclude_mask);
                    std::eprintln!("{:x?}", self.#chunk.#read_from);
                }
                let val_as_bytes = #conv_frag;
                let slice: &mut [u8] = &mut self.#chunk.#read_from[#first_byte..#last_byte_ex];

                #[cfg(test)]
                {
                    std::eprintln!("val {val_as_bytes:x?}");
                    std::eprintln!("{slice:x?}");
                }

                #( #byte_stores )*;

                #[cfg(test)]
                {
                    std::eprintln!("AFTER ---");
                    std::eprintln!("{slice:x?}");
                    std::eprintln!("{:x?}", &self.#chunk.#read_from[..]);
                }
            },
        }
    }

    fn get(&self, field: &ValidField) -> TokenStream {
        self.get_set_body(field, FieldOp::Get)
    }

    fn set(&self, field: &ValidField) -> TokenStream {
        self.get_set_body(field, FieldOp::Set)
    }

    fn byte_aligned_at_end(&self) -> bool {
        (self.first_bit_inner + self.n_bits) % 8 == 0
    }

    fn byte_aligned_at_start(&self) -> bool {
        self.first_bit_inner % 8 == 0
    }
}

#[derive(Copy, Clone)]
enum Endianness {
    Big,
    Little,
    Host,
}

impl Endianness {
    fn std_from_bytes_method(self) -> Ident {
        let label = match self {
            Endianness::Big => "be",
            Endianness::Little => "le",
            Endianness::Host => "ne",
        };

        Ident::new(&format!("from_{label}_bytes"), Span::mixed_site())
    }

    fn std_to_bytes_method(self) -> Ident {
        let label = match self {
            Endianness::Big => "be",
            Endianness::Little => "le",
            Endianness::Host => "ne",
        };

        Ident::new(&format!("to_{label}_bytes"), Span::mixed_site())
    }

    fn is_little_endian(self) -> bool {
        match self {
            Endianness::Big => false,
            Endianness::Little => true,
            Endianness::Host => cfg!(target_endian = "little"),
        }
    }
}

enum ReprType {
    Array { child: Box<Analysed>, length: usize },
    Tuple { children: Vec<Analysed> },
    Primitive { base_ident: Ident, bits: usize, endian: Option<Endianness> },
}

impl ReprType {
    fn is_aggregate(&self) -> bool {
        !matches!(self, ReprType::Primitive { .. })
    }
}

struct Analysed {
    cached_bits: usize,
    ty: ReprType,
    is_all_rust_primitives: bool,
}

impl Analysed {
    fn get_primitive_endianness(&self) -> Option<Endianness> {
        match self.ty {
            ReprType::Primitive { endian, .. } => endian,
            _ => None,
        }
    }
}

struct ZcType {
    repr: Type,
    transformed: bool,
}

impl Analysed {
    fn from_ty(ty: &Type) -> Result<Self, syn::Error> {
        match ty {
            e @ Type::Array(TypeArray{ elem, len: Expr::Lit(ExprLit{lit: Lit::Int(l), ..}), .. })  => {
                let analysed = Self::from_ty(elem)?;
                let length = l.base10_parse::<usize>()?;

                // TODO: allow only [u8; N]?
                if analysed.cached_bits != 8 && !matches!(analysed.ty, ReprType::Primitive { .. }) {
                    return Err(Error::new(e.span(), "array reprs may only contain `u8`s"));
                }

                Ok(Analysed {
                    cached_bits: analysed.cached_bits * length,
                    is_all_rust_primitives: analysed.is_all_rust_primitives,
                    ty: ReprType::Array { child: analysed.into(), length },
                })
            },
            e @ Type::Array(TypeArray{ .. })  => {
                Err(Error::new(e.span(), "array length must be an integer literal"))
            }
            Type::Tuple(a) => {
                // TODO: outlaw this while I work on more big-ticket issues.
                return Err(Error::new(a.span(), "tuple types are not currently allowed as reprs"));

                let mut n_bits = 0;
                let mut children = vec![];
                let mut is_all_rust_primitives = true;

                for elem in &a.elems {
                    let analysed = Self::from_ty(elem)?;
                    n_bits += analysed.cached_bits;
                    children.push(analysed);
                    is_all_rust_primitives &= analysed.is_all_rust_primitives;
                }

                // Ok(n_bits)
                Ok(Analysed { cached_bits: n_bits, ty: ReprType::Tuple { children }, is_all_rust_primitives })
            },
            Type::Path(a) => {
                let b = a.path.require_ident()?;
                bits_in_primitive(b)
            },

            Type::Paren(a) => Analysed::from_ty(&a.elem),

            e => Err(Error::new(e.span(), "field must be constructed from a literal, tuple, or array of integral types")),
        }
    }
}

impl Analysed {
    fn to_zerocopy_type(&self) -> Option<ZcType> {
        // TODO: figure out hybrid types in here, too.
        match &self.ty {
            ReprType::Array { child, length } => {
                let ZcType { repr, transformed } = child.to_zerocopy_type()?;
                Some(ZcType {
                    repr: syn::parse(quote! {[#repr; #length]}.into()).unwrap(),
                    transformed,
                })
            }
            ReprType::Tuple { children } => {
                let mut child_types = vec![];
                let mut any_transformed = false;

                for child in children {
                    let ZcType { repr, transformed } =
                        child.to_zerocopy_type()?;
                    child_types.push(repr);
                    any_transformed |= transformed;
                }

                Some(ZcType {
                    repr: syn::parse(quote! {(#( #child_types ),*)}.into())
                        .unwrap(),
                    transformed: any_transformed,
                })
            }
            ReprType::Primitive { base_ident, bits, endian } => {
                if *bits == 8 {
                    return Some(ZcType {
                        repr: syn::parse(quote! {#base_ident}.into()).unwrap(),
                        transformed: false,
                    });
                }
                endian.and_then(|end| {
                    if !bits.is_power_of_two() || *bits > 128 || *bits < 16 {
                        return None;
                    }

                    let tail =
                        Ident::new(&format!("U{}", bits), base_ident.span());

                    let repr = syn::parse(
                        match end {
                            Endianness::Big => {
                                quote! {::zerocopy::big_endian::#tail}
                            }
                            Endianness::Little => {
                                quote! {::zerocopy::little_endian::#tail}
                            }
                            Endianness::Host => {
                                quote! {::zerocopy::native_endian::#tail}
                            }
                        }
                        .into(),
                    )
                    .unwrap();

                    Some(ZcType { repr, transformed: true })
                })
            }
        }
    }
}

fn bits_in_primitive(ident: &Ident) -> Result<Analysed, syn::Error> {
    let name = ident.to_string();

    // validation rules:
    // 1) begins with 'u'.
    // 2) followed by number 1--64. Retval.
    // 3) if >=8, followed by endianness.
    let re = Regex::new(r"^u([0-9]+)(be|le|he)?$").unwrap();
    let Some(fields) = re.captures(&name) else {
        return Err(Error::new(
            name.span(),
            "type not of form 'u<width>[<endian>]",
        ));
    };

    let bits: usize = fields.get(1).unwrap().as_str().parse().unwrap();

    let endian = match fields.get(2).map(|v| v.as_str()) {
        _ if bits <= 8 => None,
        Some("be") => Some(Endianness::Big),
        Some("le") => Some(Endianness::Little),
        Some("he") => Some(Endianness::Host),
        None => {
            return Err(Error::new(
                ident.span(),
                "types > 8 bits require explicit endianness",
            ))
        }
        _ => {
            return Err(Error::new(
                ident.span(),
                "illegal endianness specifier",
            ))
        }
    };

    let base_ident = ident.clone();

    let ty = ReprType::Primitive { base_ident, bits, endian };

    Ok(Analysed {
        cached_bits: bits,
        ty,
        is_all_rust_primitives: bits >= 8
            && bits.is_power_of_two()
            && bits <= 128,
    })
}

pub fn derive(input: IngotArgs) -> TokenStream {
    let IngotArgs { ident, data } = input;

    let validated_ident = Ident::new(&format!("Valid{ident}"), ident.span());
    let ref_ident = Ident::new(&format!("{ident}Ref"), ident.span());
    let mut_ident = Ident::new(&format!("{ident}Mut"), ident.span());
    let pkt_ident = Ident::new(&format!("{ident}Packet"), ident.span());
    let private_mod_ident =
        Ident::new(&format!("_{ident}_ingot_impl"), ident.span());

    let mut fields: Vec<ValidField> = vec![];

    let mut trait_defs: Vec<TokenStream> = vec![];
    let mut trait_mut_defs: Vec<TokenStream> = vec![];

    let mut trait_impls: Vec<TokenStream> = vec![];
    let mut trait_mut_impls: Vec<TokenStream> = vec![];

    let mut direct_trait_impls: Vec<TokenStream> = vec![];
    let mut direct_trait_mut_impls: Vec<TokenStream> = vec![];

    let mut packet_impls: Vec<TokenStream> = vec![];
    let mut packet_mut_impls: Vec<TokenStream> = vec![];

    let field_data = data.take_struct().unwrap();

    let mut t_bits = 0;
    let mut next_layer: Option<TokenStream> = None;

    for field in field_data.fields {
        let underlying_ty =
            if let Some(ty) = &field.is { ty } else { &field.ty };
        let user_ty = &field.ty;

        let analysis = match Analysed::from_ty(&underlying_ty) {
            Ok(v) => v,
            Err(v) => return v.into_compile_error().into(),
        };

        let n_bits = analysis.cached_bits;

        if analysis.ty.is_aggregate() && (t_bits % 8 != 0 || n_bits % 8 != 0) {
            return Error::new(
                underlying_ty.span(),
                "aggregate types must be byte-aligned at their start and end",
            )
            .into_compile_error()
            .into();
        }

        let marker = format!("my offset is {t_bits}+={n_bits} bits");

        let field_ident = field.ident.unwrap();
        let valid_field = ValidField {
            repr: underlying_ty.clone(),
            ident: field_ident.clone(),
            first_bit: t_bits,
            analysis,
            hybrid: None,
            user_ty: user_ty.clone(),
            // TODO: increment as we pass by varwidth fields
            sub_ref_idx: 0,
        };

        t_bits += n_bits;

        if let Some(nl) = field.next_layer {
            if next_layer.is_some() {
                return Error::new(
                    field_ident.span(),
                    "only one field can be nominated as a next-header hint",
                )
                .into_compile_error()
                .into();
            }

            if nl.or_extension {
                todo!("integrated extension parsing not yet ready")
            }

            next_layer = Some(quote! {
                impl<V: ::zerocopy::ByteSlice> ::ingot_types::NextLayer for #validated_ident<V> {
                    type Denom = #user_ty;

                    #[inline]
                    fn next_layer(&self) -> ::ingot_types::ParseResult<Self::Denom> {
                        ::core::result::Result::Ok(self.#field_ident())
                    }
                }

                impl ::ingot_types::NextLayer for #ident {
                    type Denom = #user_ty;

                    #[inline]
                    fn next_layer(&self) -> ::ingot_types::ParseResult<Self::Denom> {
                        ::core::result::Result::Ok(self.#field_ident)
                    }
                }
            });
        }

        fields.push(valid_field);
    }

    let next_layer = next_layer.unwrap_or_else(|| quote! {
        impl<V: ::zerocopy::ByteSlice> ::ingot_types::NextLayer for #validated_ident<V> {
            type Denom = ();

            #[inline]
            fn next_layer(&self) -> ::ingot_types::ParseResult<Self::Denom> {
                ::core::result::Result::Err(::ingot_types::ParseError::NoHint)
            }
        }

        impl ::ingot_types::NextLayer for #ident {
            type Denom = ();

            #[inline]
            fn next_layer(&self) -> ::ingot_types::ParseResult<Self::Denom> {
                ::core::result::Result::Err(::ingot_types::ParseError::NoHint)
            }
        }
    });

    if t_bits % 8 != 0 {
        return Error::new(
            fields.last().unwrap().repr.span(),
            format!("fields are not byte-aligned -- total {t_bits}b"),
        )
        .into_compile_error()
        .into();
    }

    // Zerocopy type construction.

    #[derive(Clone, Debug)]
    struct HyState {
        bits_seen: usize,
        field_data: Rc<RefCell<HybridField>>,
    }

    // TODO: partition based on var-width fields.
    let mut zc_impls: Vec<TokenStream> = vec![];
    let mut zc_fields: Vec<TokenStream> = vec![];
    let mut hybrid_field: Option<HyState> = None;
    let mut zc_ty_names: Vec<Ident> = vec![];

    let mut hybrid_count = 0;

    for field in &mut fields {
        if hybrid_field.is_none()
            && field.first_bit % 8 == 0
            && field.analysis.is_all_rust_primitives
        {
            let ident = &field.ident;
            // guaranteed defined for U8/U16/U32/U64/...
            let ty = field.analysis.to_zerocopy_type().unwrap();
            let zc_repr = ty.repr;
            zc_fields.push(quote! {
                pub #ident: #zc_repr
            })
        } else {
            let ty_ident =
                Ident::new(&format!("hybrid{}", hybrid_count), ident.span());

            let hybrid_state = hybrid_field.get_or_insert_with(|| HyState {
                bits_seen: 0,
                field_data: Rc::new(RefCell::new(HybridField {
                    ident: ty_ident.clone(),
                    n_bits: 0,
                    first_bit: field.first_bit,
                })),
            });
            // let hybrid_len =
            //     hybrid_field.unwrap_or_default() + field.analysis.cached_bits;

            hybrid_state.bits_seen += field.analysis.cached_bits;
            hybrid_state.field_data.borrow_mut().n_bits +=
                field.analysis.cached_bits;

            // field.

            let first_bit_inner =
                field.first_bit - hybrid_state.field_data.borrow().first_bit;

            field.hybrid = Some(PrimitiveInHybrid {
                parent_field: hybrid_state.field_data.clone(),
                first_bit_inner,
                n_bits: field.analysis.cached_bits,
                endianness: field.analysis.get_primitive_endianness(),
            });

            if hybrid_state.bits_seen % 8 == 0 {
                // push field out
                let n_bytes = hybrid_state.bits_seen / 8;
                zc_fields.push(quote! {
                    pub #ty_ident: [u8; #n_bytes]
                });
                hybrid_count += 1;
                hybrid_field = None;
            }
        }
    }
    if !zc_fields.is_empty() {
        let ty_ident =
            Ident::new(&format!("Zc{}", zc_impls.len()), ident.span());
        zc_impls.push(quote! {
            #[derive(zerocopy::IntoBytes, Clone, Debug, zerocopy::FromBytes, zerocopy::Unaligned, zerocopy::Immutable, zerocopy::KnownLayout)]
            #[repr(C, packed)]
            pub struct #ty_ident {
                #( #zc_fields ),*
            }
        });

        zc_ty_names.push(ty_ident)
    }

    for field in &fields {
        let field_ident = &field.ident;
        let user_ty = &field.user_ty;
        let get_name = field.getter_name();

        let field_ref = Ident::new(&format!("{field_ident}_ref"), ident.span());
        let field_mut = Ident::new(&format!("{field_ident}_mut"), ident.span());

        // Used to determine whether we need both:
        // - use of NetworkRepr conversion
        // - include &<ty>, &mut <ty> in trait.
        let zc_ty = field.analysis.to_zerocopy_type();
        let do_into = field.user_ty == field.repr;
        let allow_ref_access =
            do_into && zc_ty.map(|v| !v.transformed).unwrap_or_default();

        if let Some(hybrid) = &field.hybrid {
            let (get_conv, set_conv) = if do_into {
                (quote! {val.into()}, quote! {val})
            } else {
                (
                    quote! {::ingot_types::NetworkRepr::from_network(val)},
                    quote! {::ingot_types::NetworkRepr::to_network(val)},
                )
            };

            // Can't have refs/muts if hybrid.
            trait_defs.push(quote! {
                fn #field_ident(&self) -> #user_ty;
            });
            direct_trait_impls.push(quote! {
                #[inline]
                fn #get_name(&self) -> #user_ty {
                    self.#field_ident
                }
            });
            let subty_get = hybrid.get(field);
            trait_impls.push(quote! {
                #[inline]
                fn #get_name(&self) -> #user_ty {
                    // todo!("getters on subtypes not yet done")
                    #subty_get
                    #get_conv
                }
            });

            let mut_name = field.setter_name();
            trait_mut_defs.push(quote! {
                fn #mut_name(&mut self, val: #user_ty);
            });
            direct_trait_mut_impls.push(quote! {
                #[inline]
                fn #mut_name(&mut self, val: #user_ty) {
                    self.#field_ident = val;
                }
            });
            let subty_set = hybrid.set(field);
            trait_mut_impls.push(quote! {
                #[inline]
                fn #mut_name(&mut self, val: #user_ty) {
                    let val_raw = #set_conv;
                    #subty_set
                }
            });

            packet_impls.push(quote! {
                #[inline]
                fn #get_name(&self) -> #user_ty {
                    match self {
                        ::ingot_types::Packet::Repr(o) => o.#field_ident(),
                        ::ingot_types::Packet::Raw(b) => b.#field_ident(),
                    }
                }
            });
            packet_mut_impls.push(quote! {
                #[inline]
                fn #mut_name(&mut self, val: #user_ty) {
                    match self {
                        ::ingot_types::Packet::Repr(o) => o.#mut_name(val),
                        ::ingot_types::Packet::Raw(b) => b.#mut_name(val),
                    };
                }
            });
        } else {
            // normal types!
            trait_defs.push(quote! {
                fn #get_name(&self) -> #user_ty;
            });
            direct_trait_impls.push(quote! {
                #[inline]
                fn #get_name(&self) -> #user_ty {
                    self.#field_ident
                }
            });

            let mut_name = field.setter_name();
            trait_mut_defs.push(quote! {
                fn #mut_name(&mut self, val: #user_ty);
            });
            direct_trait_mut_impls.push(quote! {
                #[inline]
                fn #mut_name(&mut self, val: #user_ty) {
                    self.#field_ident = val;
                }
            });

            packet_impls.push(quote! {
                #[inline]
                fn #field_ident(&self) -> #user_ty {
                    match self {
                        ::ingot_types::Packet::Repr(o) => o.#field_ident(),
                        ::ingot_types::Packet::Raw(b) => b.#field_ident(),
                    }
                }
            });
            packet_mut_impls.push(quote! {
                #[inline]
                fn #mut_name(&mut self, val: #user_ty) {
                    match self {
                        ::ingot_types::Packet::Repr(o) => o.#mut_name(val),
                        ::ingot_types::Packet::Raw(b) => b.#mut_name(val),
                    };
                }
            });

            if do_into {
                trait_impls.push(quote! {
                    #[inline]
                    fn #get_name(&self) -> #user_ty {
                        // my zc_ty was #zc_ty
                        self.0.#field_ident.into()
                    }
                });
                trait_mut_impls.push(quote! {
                    #[inline]
                    fn #mut_name(&mut self, val: #user_ty) {
                        self.0.#field_ident = val.into();
                    }
                });
            } else {
                trait_impls.push(quote! {
                    #[inline]
                    fn #get_name(&self) -> #user_ty {
                        // my zc_ty was #zc_ty
                        ::ingot_types::NetworkRepr::from_network(self.0.#field_ident)
                    }
                });
                trait_mut_impls.push(quote! {
                    #[inline]
                    fn #mut_name(&mut self, val: #user_ty) {
                        self.0.#field_ident = ::ingot_types::NetworkRepr::to_network(val);
                    }
                });
            }

            if allow_ref_access {
                trait_defs.push(quote! {
                    fn #field_ref(&self) -> &#user_ty;
                });
                direct_trait_impls.push(quote! {
                    #[inline]
                    fn #field_ref(&self) -> &#user_ty {
                        &self.#field_ident
                    }
                });

                trait_impls.push(quote! {
                    #[inline]
                    fn #field_ref(&self) -> &#user_ty {
                        &self.0.#field_ident
                    }
                });
                trait_mut_impls.push(quote! {
                    #[inline]
                    fn #field_mut(&mut self) -> &mut #user_ty {
                        &mut self.0.#field_ident
                    }
                });

                trait_mut_defs.push(quote! {
                    fn #field_mut(&mut self) -> &mut #user_ty;
                });
                direct_trait_mut_impls.push(quote! {
                    #[inline]
                    fn #field_mut(&mut self) -> &mut #user_ty {
                        &mut self.#field_ident
                    }
                });

                packet_impls.push(quote! {
                    #[inline]
                    fn #field_ref(&self) -> &#user_ty {
                        match self {
                            ::ingot_types::Packet::Repr(o) => o.#field_ref(),
                            ::ingot_types::Packet::Raw(b) => b.#field_ref(),
                        }
                    }
                });
                packet_mut_impls.push(quote! {
                    #[inline]
                    fn #field_mut(&mut self) -> &mut #user_ty {
                        match self {
                            ::ingot_types::Packet::Repr(o) => o.#field_mut(),
                            ::ingot_types::Packet::Raw(b) => b.#field_mut(),
                        }
                    }
                });
            }
        }
    }

    // let valid_body = todo!();

    quote! {
        // pub struct #validated_ident<V>(V);

        pub struct #validated_ident<V>(#(pub ::zerocopy::Ref<V, #private_mod_ident::#zc_ty_names> ),*);

        impl<V> ::ingot_types::Header for #validated_ident<V> {
            const MINIMUM_LENGTH: usize = (#t_bits / 8);

            fn packet_length(&self) -> usize {
                // TODO: varwidth types.
                Self::MINIMUM_LENGTH
            }
        }

        impl ::ingot_types::Header for #ident {
            const MINIMUM_LENGTH: usize = (#t_bits / 8);

            fn packet_length(&self) -> usize {
                // TODO: varwidth types.
                Self::MINIMUM_LENGTH
            }
        }

        pub trait #ref_ident {
            #( #trait_defs )*
        }

        pub trait #mut_ident {
            #( #trait_mut_defs )*
        }

        #[allow(non_snake_case)]
        pub mod #private_mod_ident {
            use super::*;

            #( #zc_impls )*

            impl<V: ::zerocopy::ByteSlice> #ref_ident for #validated_ident<V> {
                #( #trait_impls )*
            }

            impl #ref_ident for #ident {
                #( #direct_trait_impls )*
            }

            impl<V: ::zerocopy::ByteSliceMut> #mut_ident for #validated_ident<V> {
                #( #trait_mut_impls )*
            }

            impl #mut_ident for #ident {
                #( #direct_trait_mut_impls )*
            }
        }

        impl<O, B> #ref_ident for ::ingot_types::Packet<O, B>
        where
            O: #ref_ident,
            B: #ref_ident,
        {
            #( #packet_impls )*
        }

        impl<O, B> #mut_ident for ::ingot_types::Packet<O, B>
        where
            O: #mut_ident,
            B: #mut_ident,
        {
            #( #packet_mut_impls )*
        }

        impl<V: ::ingot_types::Chunk> ::ingot_types::HasBuf for #validated_ident<V> {
            type BufType = V;
        }

        impl<V: ::ingot_types::Chunk> ::ingot_types::HeaderParse for #validated_ident<V> {
            type Target = Self;
            fn parse(from: V) -> ::ingot_types::ParseResult<(Self, V)> {
                use ::ingot_types::Header;

                // TODO!
                if from.as_ref().len() < #ident::MINIMUM_LENGTH {
                    ::core::result::Result::Err(::ingot_types::ParseError::TooSmall)
                } else {
                    let (l, r) = from.split_at(#ident::MINIMUM_LENGTH);
                    let v0 = ::zerocopy::Ref::from_bytes(l)
                        .map_err(|_| ::ingot_types::ParseError::TooSmall)?;
                    ::core::result::Result::Ok((
                        #validated_ident(v0),
                        r,
                    ))
                }
            }
        }

        impl<V, T> ::core::convert::From<#validated_ident<V>> for ::ingot_types::Packet<T, #validated_ident<V>> {
            fn from(value: #validated_ident<V>) -> Self {
                ::ingot_types::Packet::Raw(value)
            }
        }

        impl<T> ::core::convert::From<#ident> for ::ingot_types::Packet<#ident, T> {
            fn from(value: #ident) -> Self {
                ::ingot_types::Packet::Repr(value)
            }
        }

        pub type #pkt_ident<V> = ::ingot_types::Packet<#ident, #validated_ident<V>>;

        impl<V> ::ingot_types::HasRepr for #validated_ident<V> {
            type ReprType = #ident;
        }

        #next_layer
    }
}
