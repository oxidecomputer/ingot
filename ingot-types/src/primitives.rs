//! Primitive types -- integers of known endianness,
//! and base buffer types.

// The type aliases here are *fairly* self-describing.
#![allow(non_camel_case_types)]
#![allow(missing_docs)]

use super::*;

pub type u1 = u8;
pub type u2 = u8;
pub type u3 = u8;
pub type u4 = u8;
pub type u5 = u8;
pub type u6 = u8;
pub type u7 = u8;

pub type i1 = i8;
pub type i2 = i8;
pub type i3 = i8;
pub type i4 = i8;
pub type i5 = i8;
pub type i6 = i8;
pub type i7 = i8;
ingot_macros::define_primitive_types!();

#[cfg(feature = "alloc")]
/// Buffer type which can be owned or a view.
pub type VarBytes<V> = Packet<Vec<u8>, V>;
#[cfg(not(feature = "alloc"))]
/// Buffer type which can be owned or a view.
pub type VarBytes<V> = Packet<Vec<u8, 256>, V>;

impl<B: ByteSlice> HasView<B> for Vec<u8> {
    type ViewType = RawBytes<B>;
}

impl<B: ByteSlice, const N: usize> HasView<B> for heapless::Vec<u8, N> {
    type ViewType = RawBytes<B>;
}

impl<V: ByteSlice> From<&VarBytes<V>> for Vec<u8> {
    fn from(value: &VarBytes<V>) -> Self {
        match value {
            Packet::Repr(v) => *v.clone(),
            Packet::Raw(v) => v.to_vec(),
        }
    }
}

/// Newtype-wrapped buffers for use in Header view-types.
pub struct RawBytes<B: ByteSlice>(B);

impl<B: ByteSlice> From<B> for RawBytes<B> {
    #[inline]
    fn from(value: B) -> Self {
        Self(value)
    }
}

impl<B: ByteSlice> Deref for RawBytes<B> {
    type Target = B;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<B: ByteSlice> DerefMut for RawBytes<B> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<B: ByteSlice> AsRef<[u8]> for RawBytes<B> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self[..]
    }
}

impl<B: ByteSliceMut> AsMut<[u8]> for RawBytes<B> {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self[..]
    }
}

impl<B: ByteSlice> From<RawBytes<B>> for Vec<u8> {
    fn from(val: RawBytes<B>) -> Self {
        val.to_vec()
    }
}

impl<B: ByteSlice> Header for RawBytes<B> {
    const MINIMUM_LENGTH: usize = 0;

    #[inline]
    fn packet_length(&self) -> usize {
        self.len()
    }
}

impl<V: ByteSlice> AsRef<[u8]> for VarBytes<V> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        match self {
            Packet::Repr(o) => o.as_ref(),
            Packet::Raw(b) => b.as_ref(),
        }
    }
}

impl<V: ByteSliceMut> AsMut<[u8]> for VarBytes<V> {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            Packet::Repr(o) => o.as_mut(),
            Packet::Raw(b) => b.as_mut(),
        }
    }
}

impl<B: ByteSlice> Emit for RawBytes<B> {
    #[inline]
    fn emit_raw<V: ByteSliceMut>(&self, mut buf: V) -> usize {
        buf.copy_from_slice(self);

        self.len()
    }

    #[inline]
    fn needs_emit(&self) -> bool {
        false
    }
}

// Safety: We know this holds true for all our derived emits, by design.
unsafe impl<B: ByteSlice> EmitDoesNotRelyOnBufContents for RawBytes<B> {}
