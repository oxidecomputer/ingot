// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! An abstraction layer over in-buffer and owned packets and headers.

use super::*;

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use primitives::RawBytes;

#[cfg(not(feature = "alloc"))]
/// Convenience type choosing [`InlineHeader`] when `BoxedHeader` is
/// unavailable.
pub type Header<O, B> = InlineHeader<O, B>;

#[cfg(feature = "alloc")]
/// Convenience type preferring [`BoxedHeader`] when available.
pub type Header<O, B> = BoxedHeader<O, B>;

/// The [`Header`] type corresponding to an owned representation
/// type `T` on buffer `B`.
pub type HeaderOf<T, B> = Header<T, <T as HasView<B>>::ViewType>;

/// A header which is either owned or read from a buffer.
///
/// Generated traits which allow reading/modifying/emitting either type
/// are re-implemented on the `Packet` types.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum InlineHeader<O, B> {
    /// Owned representation of a header.
    Repr(O),
    /// Packed representation of a header, read from an existing buffer.
    Raw(B),
}

/// A header which is either owned or read from a buffer, which
/// heap-allocates if the data is owned.
///
/// Generally, use of boxed `Repr` values reduces output struct sizes
/// when parsing full packets and is preferred when compiling with the
/// `alloc` feature. See [`InlineHeader`] if stack allocation is needed.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum BoxedHeader<O, B> {
    /// Owned, in-memory representation of a header.
    #[cfg(feature = "alloc")]
    Repr(Box<O>),
    /// Packed representation of a header, read from an existing buffer.
    Raw(B),
}

#[cfg(feature = "alloc")]
impl<O, B> From<InlineHeader<O, B>> for BoxedHeader<O, B> {
    fn from(value: InlineHeader<O, B>) -> Self {
        match value {
            InlineHeader::Repr(o) => Self::Repr(o.into()),
            InlineHeader::Raw(b) => Self::Raw(b),
        }
    }
}

#[cfg(feature = "alloc")]
impl<O, B> From<BoxedHeader<O, B>> for InlineHeader<O, B> {
    fn from(value: BoxedHeader<O, B>) -> Self {
        match value {
            BoxedHeader::Repr(o) => Self::Repr(*o),
            BoxedHeader::Raw(b) => Self::Raw(b),
        }
    }
}

//
// Indirect impls.
//
#[cfg(feature = "alloc")]
impl<O, B> BoxedHeader<O, B> {
    /// Return a reference to this packet's contents if
    /// they are owned.
    pub fn repr(&self) -> Option<&O> {
        match self {
            Self::Repr(o) => Some(o),
            _ => None,
        }
    }

    /// Return a mutable reference to this packet's contents if
    /// they are owned.
    pub fn repr_mut(&mut self) -> Option<&mut O> {
        match self {
            Self::Repr(o) => Some(o),
            _ => None,
        }
    }

    /// Return a reference to this packet's contents if
    /// they are borrowed.
    pub fn raw(&self) -> Option<&B> {
        match self {
            Self::Raw(b) => Some(b),
            _ => None,
        }
    }

    /// Return a mutable reference to this packet's contents if
    /// they are borrowed.
    pub fn raw_mut(&mut self) -> Option<&mut B> {
        match self {
            Self::Raw(b) => Some(b),
            _ => None,
        }
    }
}

#[cfg(feature = "alloc")]
impl<
        O: NextLayer + Clone,
        B: NextLayer<Denom = O::Denom, Hint = O::Hint> + ToOwnedPacket<Target = O>,
    > ToOwnedPacket for BoxedHeader<O, B>
{
    type Target = O;

    fn to_owned(&self, hint: Option<Self::Hint>) -> ParseResult<Self::Target> {
        match self {
            Header::Repr(o) => Ok(*o.clone()),
            Header::Raw(v) => v.to_owned(hint),
        }
    }
}

#[cfg(feature = "alloc")]
impl<B: ByteSlice, T> From<&BoxedHeader<Vec<T>, RawBytes<B>>> for Vec<T>
where
    T: FromBytes + IntoBytes + KnownLayout + Immutable + Clone,
{
    fn from(value: &Header<Vec<T>, RawBytes<B>>) -> Self {
        match value {
            Header::Repr(v) => v.deref().clone(),
            Header::Raw(v) => {
                <[T]>::ref_from_bytes(v.as_ref()).unwrap().to_vec()
            }
        }
    }
}

#[cfg(feature = "alloc")]
impl<O: HasView<V, ViewType = B>, B, V> HasView<V> for BoxedHeader<O, B> {
    type ViewType = B;
}

#[cfg(feature = "alloc")]
impl<O, B> HasRepr for BoxedHeader<O, B> {
    type ReprType = O;
}

#[cfg(feature = "alloc")]
impl<O, B> HeaderLen for BoxedHeader<O, B>
where
    O: HeaderLen,
    B: HeaderLen,
{
    const MINIMUM_LENGTH: usize = O::MINIMUM_LENGTH;

    #[inline]
    fn packet_length(&self) -> usize {
        match self {
            Self::Repr(o) => o.packet_length(),
            Self::Raw(b) => b.packet_length(),
        }
    }
}

// This implementation allows us to call e.g. Packet<A,ValidA>::parse
// if ValidA is also Parse, and its owned type has a matching next layer
// Denom.
#[cfg(feature = "alloc")]
impl<
        V: SplitByteSlice,
        B: HeaderParse<V> + HasRepr + NextLayer + Into<Self>,
    > HeaderParse<V> for BoxedHeader<B::ReprType, B>
where
    B: NextLayer,
    B::ReprType: NextLayer<Denom = B::Denom, Hint = B::Hint>,
{
    #[inline]
    fn parse_choice(
        from: V,
        hint: Option<Self::Hint>,
    ) -> ParseResult<Success<Self, V>> {
        <B as HeaderParse<V>>::parse_choice(from, hint)
            .map(|(val, hint, remainder)| (val.into(), hint, remainder))
    }
}

#[cfg(feature = "alloc")]
impl<O: NextLayer, B> NextLayer for BoxedHeader<O, B>
where
    B: NextLayer<Denom = O::Denom, Hint = O::Hint>,
{
    type Denom = O::Denom;
    type Hint = O::Hint;

    #[inline]
    fn next_layer_choice(
        &self,
        hint: Option<Self::Hint>,
    ) -> Option<Self::Denom> {
        match self {
            Self::Repr(v) => v.next_layer_choice(hint),
            Self::Raw(v) => v.next_layer_choice(hint),
        }
    }
}

#[cfg(feature = "alloc")]
unsafe impl<O: EmitDoesNotRelyOnBufContents, B: EmitDoesNotRelyOnBufContents>
    EmitDoesNotRelyOnBufContents for BoxedHeader<O, B>
{
}

#[cfg(feature = "alloc")]
impl<O: Emit, B: Emit> Emit for BoxedHeader<O, B> {
    #[inline]
    fn emit_raw<V: ByteSliceMut>(&self, buf: V) -> usize {
        match self {
            Self::Repr(o) => o.emit_raw(buf),
            Self::Raw(b) => b.emit_raw(buf),
        }
    }

    #[inline]
    fn needs_emit(&self) -> bool {
        match self {
            Self::Repr(_) => true,
            Self::Raw(b) => b.needs_emit(),
        }
    }
}

//
// Direct impls.
//
impl<O, B> InlineHeader<O, B> {
    /// Return a reference to this packet's contents if
    /// they are owned.
    pub fn repr(&self) -> Option<&O> {
        match self {
            Self::Repr(o) => Some(o),
            _ => None,
        }
    }

    /// Return a mutable reference to this packet's contents if
    /// they are owned.
    pub fn repr_mut(&mut self) -> Option<&mut O> {
        match self {
            Self::Repr(o) => Some(o),
            _ => None,
        }
    }

    /// Return a reference to this packet's contents if
    /// they are borrowed.
    pub fn raw(&self) -> Option<&B> {
        match self {
            Self::Raw(b) => Some(b),
            _ => None,
        }
    }

    /// Return a mutable reference to this packet's contents if
    /// they are borrowed.
    pub fn raw_mut(&mut self) -> Option<&mut B> {
        match self {
            Self::Raw(b) => Some(b),
            _ => None,
        }
    }
}

impl<
        O: NextLayer + Clone,
        B: NextLayer<Denom = O::Denom, Hint = O::Hint> + ToOwnedPacket<Target = O>,
    > ToOwnedPacket for InlineHeader<O, B>
{
    type Target = O;

    fn to_owned(&self, hint: Option<Self::Hint>) -> ParseResult<Self::Target> {
        match self {
            Self::Repr(o) => Ok(o.clone()),
            Self::Raw(v) => v.to_owned(hint),
        }
    }
}

impl<O: HasView<V, ViewType = B>, B, V> HasView<V> for InlineHeader<O, B> {
    type ViewType = B;
}

impl<O, B> HasRepr for InlineHeader<O, B> {
    type ReprType = O;
}

impl<O, B> HeaderLen for InlineHeader<O, B>
where
    O: HeaderLen,
    B: HeaderLen,
{
    const MINIMUM_LENGTH: usize = O::MINIMUM_LENGTH;

    #[inline]
    fn packet_length(&self) -> usize {
        match self {
            Self::Repr(o) => o.packet_length(),
            Self::Raw(b) => b.packet_length(),
        }
    }
}

// This implementation allows us to call e.g. Packet<A,ValidA>::parse
// if ValidA is also Parse, and its owned type has a matching next layer
// Denom.
impl<
        V: SplitByteSlice,
        B: HeaderParse<V> + HasRepr + NextLayer + Into<Self>,
    > HeaderParse<V> for InlineHeader<B::ReprType, B>
where
    B: NextLayer,
    B::ReprType: NextLayer<Denom = B::Denom, Hint = B::Hint>,
{
    #[inline]
    fn parse_choice(
        from: V,
        hint: Option<Self::Hint>,
    ) -> ParseResult<Success<Self, V>> {
        <B as HeaderParse<V>>::parse_choice(from, hint)
            .map(|(val, hint, remainder)| (val.into(), hint, remainder))
    }
}

impl<O: NextLayer, B> NextLayer for InlineHeader<O, B>
where
    B: NextLayer<Denom = O::Denom, Hint = O::Hint>,
{
    type Denom = O::Denom;
    type Hint = O::Hint;

    #[inline]
    fn next_layer_choice(
        &self,
        hint: Option<Self::Hint>,
    ) -> Option<Self::Denom> {
        match self {
            Self::Repr(v) => v.next_layer_choice(hint),
            Self::Raw(v) => v.next_layer_choice(hint),
        }
    }
}

unsafe impl<O: EmitDoesNotRelyOnBufContents, B: EmitDoesNotRelyOnBufContents>
    EmitDoesNotRelyOnBufContents for InlineHeader<O, B>
{
}

impl<O: Emit, B: Emit> Emit for InlineHeader<O, B> {
    #[inline]
    fn emit_raw<V: ByteSliceMut>(&self, buf: V) -> usize {
        match self {
            Self::Repr(o) => o.emit_raw(buf),
            Self::Raw(b) => b.emit_raw(buf),
        }
    }

    #[inline]
    fn needs_emit(&self) -> bool {
        match self {
            Self::Repr(_) => true,
            Self::Raw(b) => b.needs_emit(),
        }
    }
}
