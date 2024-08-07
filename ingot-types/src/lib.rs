#![no_std]

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::convert::Infallible;
use core::net::Ipv4Addr;
use core::net::Ipv6Addr;
#[cfg(not(feature = "alloc"))]
use heapless::Vec;

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod primitives {
    pub use pnet_macros_support::types::*;
}

pub enum Packet<O, B> {
    /// Owned, in-memory representation of a ...
    Repr(O),
    /// Packed representation of a ...
    Raw(B),
}

#[cfg(feature = "alloc")]
pub type VarBytes<V> = Packet<Vec<u8>, V>;
#[cfg(not(feature = "alloc"))]
pub type VarBytes<V> = Packet<Vec<u8, 256>, V>;

pub trait Header {
    const MINIMUM_LENGTH: usize;

    fn packet_length(&self) -> usize;
}

pub trait HasView {
    type ViewType;
}

pub trait HasRepr {
    type ReprType;
}

pub trait HasBuf: Sized {
    type BufType: Chunk;
}

impl<O, B: HeaderParse> HasBuf for Packet<O, B> {
    type BufType = <<B as HeaderParse>::Target as HasBuf>::BufType;
}

pub trait HeaderParse {
    type Target: HasBuf;

    fn parse(
        from: <Self::Target as HasBuf>::BufType,
    ) -> ParseResult<(Self::Target, <Self::Target as HasBuf>::BufType)>;
}

impl<B: HeaderParse<Target = B> + HasBuf + HasRepr + Into<Self>> HeaderParse
    for Packet<B::ReprType, B>
{
    type Target = Self;

    #[inline]
    fn parse(
        from: <Self::Target as HasBuf>::BufType,
    ) -> ParseResult<(Self::Target, <Self::Target as HasBuf>::BufType)> {
        <B as HeaderParse>::parse(from)
            .map(|(header, buf)| (header.into(), buf))
    }
}

impl<O: NextLayer, B> NextLayer for Packet<O, B>
where
    B: NextLayer<Denom = O::Denom>,
{
    type Denom = O::Denom;

    #[inline]
    fn next_layer(&self) -> ParseResult<Self::Denom> {
        match self {
            Packet::Repr(v) => v.next_layer(),
            Packet::Raw(v) => v.next_layer(),
        }
    }
}

/// Takes contiguous byte slices from a packet.
pub trait Read {
    type Chunk: Chunk;
    fn next_chunk(&mut self) -> ParseResult<Self::Chunk>;
}

pub use zerocopy::SplitByteSlice as Chunk;

pub struct OneChunk<V>(Option<V>);

impl<V> From<V> for OneChunk<V> {
    fn from(value: V) -> Self {
        OneChunk(Some(value))
    }
}

impl<'a> Read for OneChunk<&'a [u8]> {
    type Chunk = &'a [u8];

    fn next_chunk(&mut self) -> ParseResult<Self::Chunk> {
        self.0.take().ok_or(ParseError::TooSmall)
    }
}

impl<'a> Read for OneChunk<&'a mut [u8]> {
    type Chunk = &'a mut [u8];

    fn next_chunk(&mut self) -> ParseResult<Self::Chunk> {
        self.0.take().ok_or(ParseError::TooSmall)
    }
}

// pub trait Emit {
//     fn emit()
// }

pub type ParseResult<T> = Result<T, ParseError>;

pub trait NextLayer {
    type Denom: Copy;

    fn next_layer(&self) -> ParseResult<Self::Denom>;
}

#[derive(Clone, Copy, Debug)]
pub enum ParseError {
    Unspec,
    Unwanted,
    NeedsHint,
    NoHint,
    TooSmall,
}

impl From<Infallible> for ParseError {
    fn from(_: Infallible) -> Self {
        // XXX: benchmark this one.
        //      `cargo asm` suggests the compiler is smart enough.
        // unsafe { core::hint::unreachable_unchecked() }
        unreachable!()
    }
}

pub trait ParseChoice<V: Chunk>: Sized {
    type Denom: Copy;

    fn parse_choice(data: V, hint: Self::Denom) -> ParseResult<(Self, V)>;
}

pub enum ParseControl<Denom: Copy> {
    Continue(Denom),
    Reject,
    Accept,
}

pub trait NetworkRepr<U: Copy> {
    fn to_network(self) -> U;
    fn from_network(val: U) -> Self;
}

impl NetworkRepr<[u8; 4]> for Ipv4Addr {
    #[inline]
    fn to_network(self) -> [u8; 4] {
        self.octets()
    }

    #[inline]
    fn from_network(val: [u8; 4]) -> Self {
        Ipv4Addr::from(val)
    }
}

impl NetworkRepr<[u8; 16]> for Ipv6Addr {
    #[inline]
    fn to_network(self) -> [u8; 16] {
        self.octets()
    }

    #[inline]
    fn from_network(val: [u8; 16]) -> Self {
        Ipv6Addr::from(val)
    }
}

impl NetworkRepr<[u8; 6]> for macaddr::MacAddr6 {
    #[inline]
    fn to_network(self) -> [u8; 6] {
        self.into_array()
    }

    #[inline]
    fn from_network(val: [u8; 6]) -> Self {
        macaddr::MacAddr6::from(val)
    }
}
