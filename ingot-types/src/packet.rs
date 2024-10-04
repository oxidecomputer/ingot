//! An abstraction layer over in-buffer and owned packets and headers.

use super::*;

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
pub use alloc::vec::Vec;
#[allow(unused)]
use heapless::Vec as HVec;

#[cfg(not(feature = "alloc"))]
pub type Packet<O, B> = DirectPacket<O, B>;

#[cfg(feature = "alloc")]
pub type Packet<O, B> = IndirectPacket<O, B>;

/// The `Packet` type corresponding to an owned representation
/// type `T` on buffer `B`.
pub type PacketOf<T, B> = Packet<T, <T as HasView<B>>::ViewType>;

/// A header which is either owned or read from a buffer.
///
/// Generated traits which allow reading/modifying/emitting either type
/// are re-implemented on the `Packet` types.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum DirectPacket<O, B> {
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
/// `alloc` feature. See [`DirectPacket`] if stack allocation is needed.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum IndirectPacket<O, B> {
    /// Owned, in-memory representation of a header.
    #[cfg(feature = "alloc")]
    Repr(Box<O>),
    /// Packed representation of a header, read from an existing buffer.
    Raw(B),
}

#[cfg(feature = "alloc")]
impl<O, B> From<DirectPacket<O, B>> for IndirectPacket<O, B> {
    fn from(value: DirectPacket<O, B>) -> Self {
        match value {
            DirectPacket::Repr(o) => Self::Repr(o.into()),
            DirectPacket::Raw(b) => Self::Raw(b),
        }
    }
}

#[cfg(feature = "alloc")]
impl<O, B> From<IndirectPacket<O, B>> for DirectPacket<O, B> {
    fn from(value: IndirectPacket<O, B>) -> Self {
        match value {
            IndirectPacket::Repr(o) => Self::Repr(*o),
            IndirectPacket::Raw(b) => Self::Raw(b),
        }
    }
}

// Indirect impls.
#[cfg(feature = "alloc")]
impl<O, B> IndirectPacket<O, B> {
    pub fn repr(&self) -> Option<&O> {
        match self {
            Self::Repr(o) => Some(o),
            _ => None,
        }
    }

    pub fn repr_mut(&mut self) -> Option<&mut O> {
        match self {
            Self::Repr(o) => Some(o),
            _ => None,
        }
    }

    pub fn raw(&self) -> Option<&B> {
        match self {
            Self::Raw(b) => Some(b),
            _ => None,
        }
    }

    pub fn raw_mut(&mut self) -> Option<&mut B> {
        match self {
            Self::Raw(b) => Some(b),
            _ => None,
        }
    }
}

#[cfg(feature = "alloc")]
impl<
        D: Copy + Eq,
        O: NextLayer<Denom = D> + Clone,
        B: NextLayer<Denom = D> + ToOwnedPacket<Target = O>,
    > ToOwnedPacket for IndirectPacket<O, B>
{
    type Target = O;

    fn to_owned(&self, hint: Option<Self::Denom>) -> ParseResult<Self::Target> {
        match self {
            Packet::Repr(o) => Ok(*o.clone()),
            Packet::Raw(v) => v.to_owned(hint),
        }
    }
}

#[cfg(feature = "alloc")]
impl<'a, B: ByteSlice> From<&'a IndirectPacket<Vec<u8>, RawBytes<B>>>
    for Vec<u8>
{
    fn from(value: &Packet<Vec<u8>, RawBytes<B>>) -> Self {
        match value {
            Packet::Repr(v) => v.to_vec(),
            Packet::Raw(v) => v.to_vec(),
        }
    }
}

#[cfg(feature = "alloc")]
impl<O: HasView<V, ViewType = B>, B, V> HasView<V> for IndirectPacket<O, B> {
    type ViewType = B;
}

#[cfg(feature = "alloc")]
impl<O, B> HasRepr for IndirectPacket<O, B> {
    type ReprType = O;
}

#[cfg(feature = "alloc")]
impl<O, B> Header for IndirectPacket<O, B>
where
    O: Header,
    B: Header,
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
    > HeaderParse<V> for IndirectPacket<B::ReprType, B>
where
    B: NextLayer,
    B::ReprType: NextLayer<Denom = B::Denom>,
{
    #[inline]
    fn parse(from: V) -> ParseResult<Success<Self, V>> {
        <B as HeaderParse<V>>::parse(from)
            .map(|(val, hint, remainder)| (val.into(), hint, remainder))
    }
}

#[cfg(feature = "alloc")]
impl<O: NextLayer, B> NextLayer for IndirectPacket<O, B>
where
    B: NextLayer<Denom = O::Denom>,
{
    type Denom = O::Denom;

    #[inline]
    fn next_layer(&self) -> Option<Self::Denom> {
        match self {
            Self::Repr(v) => v.next_layer(),
            Self::Raw(v) => v.next_layer(),
        }
    }
}

#[cfg(feature = "alloc")]
impl<D: Copy + Eq, D2, O: NextLayerChoice<D> + NextLayer<Denom = D2>, B>
    NextLayerChoice<D> for IndirectPacket<O, B>
where
    B: NextLayerChoice<D> + NextLayer<Denom = D2>,
{
    #[inline]
    fn next_layer_choice(&self, hint: Option<D>) -> Option<Self::Denom> {
        match self {
            Self::Repr(v) => v.next_layer_choice(hint),
            Self::Raw(v) => v.next_layer_choice(hint),
        }
    }
}

#[cfg(feature = "alloc")]
unsafe impl<O: EmitDoesNotRelyOnBufContents, B: EmitDoesNotRelyOnBufContents>
    EmitDoesNotRelyOnBufContents for IndirectPacket<O, B>
{
}

#[cfg(feature = "alloc")]
impl<O: Emit, B: Emit> Emit for IndirectPacket<O, B> {
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
impl<O, B> DirectPacket<O, B> {
    pub fn repr(&self) -> Option<&O> {
        match self {
            Self::Repr(o) => Some(o),
            _ => None,
        }
    }

    pub fn repr_mut(&mut self) -> Option<&mut O> {
        match self {
            Self::Repr(o) => Some(o),
            _ => None,
        }
    }

    pub fn raw(&self) -> Option<&B> {
        match self {
            Self::Raw(b) => Some(b),
            _ => None,
        }
    }

    pub fn raw_mut(&mut self) -> Option<&mut B> {
        match self {
            Self::Raw(b) => Some(b),
            _ => None,
        }
    }
}

impl<
        D: Copy + Eq,
        O: NextLayer<Denom = D> + Clone,
        B: NextLayer<Denom = D> + ToOwnedPacket<Target = O>,
    > ToOwnedPacket for DirectPacket<O, B>
{
    type Target = O;

    fn to_owned(&self, hint: Option<Self::Denom>) -> ParseResult<Self::Target> {
        match self {
            Self::Repr(o) => Ok(o.clone()),
            Self::Raw(v) => v.to_owned(hint),
        }
    }
}

impl<O: HasView<V, ViewType = B>, B, V> HasView<V> for DirectPacket<O, B> {
    type ViewType = B;
}

impl<O, B> HasRepr for DirectPacket<O, B> {
    type ReprType = O;
}

impl<O, B> Header for DirectPacket<O, B>
where
    O: Header,
    B: Header,
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
    > HeaderParse<V> for DirectPacket<B::ReprType, B>
where
    B: NextLayer,
    B::ReprType: NextLayer<Denom = B::Denom>,
{
    #[inline]
    fn parse(from: V) -> ParseResult<Success<Self, V>> {
        <B as HeaderParse<V>>::parse(from)
            .map(|(val, hint, remainder)| (val.into(), hint, remainder))
    }
}

impl<O: NextLayer, B> NextLayer for DirectPacket<O, B>
where
    B: NextLayer<Denom = O::Denom>,
{
    type Denom = O::Denom;

    #[inline]
    fn next_layer(&self) -> Option<Self::Denom> {
        match self {
            Self::Repr(v) => v.next_layer(),
            Self::Raw(v) => v.next_layer(),
        }
    }
}

unsafe impl<O: EmitDoesNotRelyOnBufContents, B: EmitDoesNotRelyOnBufContents>
    EmitDoesNotRelyOnBufContents for DirectPacket<O, B>
{
}

impl<O: Emit, B: Emit> Emit for DirectPacket<O, B> {
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
