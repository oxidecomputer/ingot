// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

impl NetworkRepr<u1> for bool {
    fn to_network(self) -> u1 {
        self as u1
    }

    fn from_network(val: u1) -> Self {
        val != 0
    }
}

#[cfg(feature = "alloc")]
/// Buffer type which can be owned or a view.
pub type VarBytes<V> = Header<Vec<u8>, V>;
#[cfg(not(feature = "alloc"))]
/// Buffer type which can be owned or a view.
pub type VarBytes<V> = Header<Vec<u8, 256>, V>;

impl<B: ByteSlice> HasView<B> for Vec<u8> {
    type ViewType = RawBytes<B>;
}

impl<B: zerocopy::ByteSlice, T> HasView<ObjectSlice<B, T>> for Vec<T> {
    type ViewType = ObjectSlice<B, T>;
}

impl<V: ByteSlice> From<&VarBytes<V>> for Vec<u8> {
    fn from(value: &VarBytes<V>) -> Self {
        match value {
            Header::Repr(v) => *v.clone(),
            Header::Raw(v) => v.to_vec(),
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

impl<B: ByteSlice> HeaderLen for RawBytes<B> {
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
            Header::Repr(o) => o.as_ref(),
            Header::Raw(b) => b.as_ref(),
        }
    }
}

impl<V: ByteSliceMut> AsMut<[u8]> for VarBytes<V> {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            Header::Repr(o) => o.as_mut(),
            Header::Raw(b) => b.as_mut(),
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

/// Newtype-wrapped zerocopy object buffers for use in Header view-types.
///
/// The byteslice must be an even multiple of object size (checked at
/// construction time).
pub struct ObjectSlice<B: ByteSlice, V>(B, core::marker::PhantomData<V>);

impl<B: ByteSlice, V> HeaderLen for ObjectSlice<B, V> {
    const MINIMUM_LENGTH: usize = 0;
    #[inline]
    fn packet_length(&self) -> usize {
        self.0.len()
    }
}

impl<B: ByteSlice, V> Emit for ObjectSlice<B, V> {
    #[inline]
    fn emit_raw<O: ByteSliceMut>(&self, mut buf: O) -> usize {
        buf.copy_from_slice(self.0.deref());

        self.0.len()
    }

    #[inline]
    fn needs_emit(&self) -> bool {
        false
    }
}

#[cfg(feature = "alloc")]
impl<B: ByteSlice, T> From<&BoxedHeader<Vec<T>, ObjectSlice<B, T>>> for Vec<T>
where
    T: FromBytes + IntoBytes + KnownLayout + Immutable + Clone,
{
    fn from(value: &Header<Vec<T>, ObjectSlice<B, T>>) -> Self {
        match value {
            Header::Repr(v) => v.deref().clone(),
            Header::Raw(v) => {
                <[T]>::ref_from_bytes(v.0.as_ref()).unwrap().to_vec()
            }
        }
    }
}

impl<B: ByteSlice, V: FromBytes> From<B> for ObjectSlice<B, V> {
    fn from(b: B) -> Self {
        assert_eq!(
            b.len() % core::mem::size_of::<V>(),
            0,
            "invalid slice size"
        );
        Self(b, core::marker::PhantomData)
    }
}

impl<B: ByteSlice, V: FromBytes + Immutable> Deref for ObjectSlice<B, V> {
    type Target = [V];
    fn deref(&self) -> &[V] {
        // Size is checked at construction, so this should be infallible
        <[V]>::ref_from_bytes(self.0.as_ref()).unwrap()
    }
}

impl<B: ByteSliceMut, V: FromBytes + Immutable + IntoBytes> DerefMut
    for ObjectSlice<B, V>
{
    fn deref_mut(&mut self) -> &mut [V] {
        // Size is checked at construction, so this should be infallible
        <[V]>::mut_from_bytes(self.0.as_mut()).unwrap()
    }
}
