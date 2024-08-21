use super::*;
use proc_macro2::TokenStream;
use quote::quote;
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Clone, Debug)]
pub struct PrimitiveInBitfield {
    pub parent_field: Rc<RefCell<Bitfield>>,
    pub first_bit_inner: usize,
    pub n_bits: usize,
    pub endianness: Option<Endianness>,
}

#[derive(Clone, Copy)]
enum FieldOp {
    Get,
    Set,
}

impl PrimitiveInBitfield {
    fn first_byte(&self) -> usize {
        self.first_bit_inner / 8
    }

    fn last_byte_exclusive(&self) -> usize {
        let last_bit_inner = self.first_bit_inner + self.n_bits;
        let whole_bytes = last_bit_inner / 8;
        whole_bytes + if last_bit_inner % 8 != 0 { 1 } else { 0 }
    }

    fn byteslice_len(&self) -> usize {
        let whole_bytes = self.n_bits / 8;
        whole_bytes + if self.n_bits % 8 != 0 { 1 } else { 0 }
    }

    fn get_set_body(&self, field: &ValidField, op: FieldOp) -> TokenStream {
        let FieldState::FixedWidth { underlying_ty, .. } = &field.state else {
            panic!(
                "tried to compute bitfield get/set on non-fixedwidth field."
            );
        };
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
        let short_bits = ((8 - (self.n_bits % 8)) % 8) as u32;

        // Straddle over byte boundaries, where applicable.
        let left_to_lose = self.first_bit_inner as u32 % 8;
        let left_overspill = (8 - left_to_lose) % 8;
        let right_overspill = (self.first_bit_inner + self.n_bits) as u32 % 8;
        let right_to_lose = (8 - right_overspill) % 8;

        let left_include_mask =
            0xffu8.wrapping_shl(left_to_lose).wrapping_shr(left_to_lose);
        let right_include_mask =
            0xffu8.wrapping_shr(right_to_lose).wrapping_shl(right_to_lose);
        let spare_bits_mask =
            0xffu8.wrapping_shl(short_bits).wrapping_shr(short_bits);

        let left_exclude_mask = !left_include_mask;
        let right_exclude_mask = !right_include_mask;

        let little_endian =
            self.endianness.map(|v| v.is_little_endian()).unwrap_or_default();

        let (general_shift_amt, last_mask) = if !little_endian {
            let shift_amt = (8 - right_overspill) % 8;
            (shift_amt, left_include_mask)
        } else {
            let shift_amt = (8 - left_overspill) % 8;
            (shift_amt, right_exclude_mask)
        };

        let needed_bytes = repr_sz / 8;
        // let spare_bits = self.n_bits as u32 % 8;
        let first_byte = self.first_byte();
        let last_byte_ex = self.last_byte_exclusive();

        let conv_frag = match (op, self.n_bits) {
            (FieldOp::Get, n) if n < 8 => {
                quote! { in_bytes[0] }
            }
            (FieldOp::Get, _) => {
                let Some(e) = self.endianness else {
                    panic!("u>8 without known endian")
                };
                let method = e.std_from_bytes_method();
                quote! { #underlying_ty::#method(in_bytes) }
            }
            (FieldOp::Set, n) if n < 8 => {
                quote! { [val_raw] }
            }
            (FieldOp::Set, _) => {
                let Some(e) = self.endianness else {
                    panic!("u>8 without known endian")
                };
                let method = e.std_to_bytes_method();
                quote! { #underlying_ty::#method(val) }
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
                    let write_this_cycle: isize =
                        (needed_bytes as isize - i as isize) - 1;
                    let read_this_cycle = (last_byte_ex - first_byte) - i - 1;

                    byte_reads.push(quote! {
                        let b = slice[#read_this_cycle];
                    });

                    // don't carry the masked portion of this byte
                    // back into the previous one if we're the first.
                    if i != 0 {
                        let wrote_last_cycle = (write_this_cycle + 1) as usize;
                        byte_reads.push(quote! {
                            in_bytes[#wrote_last_cycle] |= (b << (#right_overspill));
                        });
                    }

                    if write_this_cycle >= 0 {
                        let write_this_cycle = write_this_cycle as usize;
                        byte_reads.push(quote! {
                            in_bytes[#write_this_cycle] = (b >> #general_shift_amt);
                        });
                    }

                    if src_byte == first_byte && last_mask != 0 {
                        let capped_min = write_this_cycle.max(0) as usize;
                        byte_reads.push(quote! {
                            in_bytes[#capped_min] &= #spare_bits_mask;
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
                byte_stores.push(quote! {
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
                    // first byte and left overspill: be careful on first set
                    byte_stores.push(quote! {
                        let b = val_as_bytes[#src_byte];
                        let base = b << #shift;
                        let rem = b >> ((8 - #shift) % 8);
                    });

                    if i == 0 && left_overspill == 0 && self.n_bits >= 8 {
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
            (true, false, _) => {
                // TODO
                // byte_reads.push(quote! {
                //     todo!()
                // });

                byte_stores.push(quote! {
                    todo!()
                });
            }
        }

        let read_from = self.parent_field.borrow().ident.clone();

        match op {
            FieldOp::Get => quote! {
                let mut in_bytes = [0u8; #needed_bytes];
                let slice = &self.#read_from[#first_byte..#last_byte_ex];

                #( #byte_reads )*

                let val = #conv_frag;
            },
            FieldOp::Set => quote! {
                let val_as_bytes = #conv_frag;
                let slice: &mut [u8] = &mut self.#read_from[#first_byte..#last_byte_ex];

                #( #byte_stores )*;
            },
        }
    }

    pub fn get(&self, field: &ValidField) -> TokenStream {
        self.get_set_body(field, FieldOp::Get)
    }

    pub fn set(&self, field: &ValidField) -> TokenStream {
        self.get_set_body(field, FieldOp::Set)
    }

    fn byte_aligned_at_end(&self) -> bool {
        (self.first_bit_inner + self.n_bits) % 8 == 0
    }

    fn byte_aligned_at_start(&self) -> bool {
        self.first_bit_inner % 8 == 0
    }
}
