#![no_std]

use core::convert::Infallible;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod primitives {
    pub use pnet_macros_support::types::*;
    pub use zerocopy;
}

pub enum Packet<O, B> {
    /// Owned, in-memory representation of a ...
    Repr(O),
    /// Packed representation of a ...
    Raw(B),
}

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

pub trait HeaderParse {
    type Target: HasBuf;

    fn parse(from: <Self::Target as HasBuf>::BufType) -> ParseResult<(Self::Target, <Self::Target as HasBuf>::BufType)>;
}

impl<B: HeaderParse<Target = B> + HasBuf + HasRepr + Into<Self>>  Packet<B::ReprType, B> {
    #[inline]
    pub fn parse(from: B::BufType) -> ParseResult<(Self, B::BufType)> {
        <B as HeaderParse>::parse(from)
            .map(|(header, buf)| (header.into(), buf))
    }
}

impl<O: NextLayer, B> NextLayer for Packet<O, B>
where B: NextLayer<Denom = O::Denom>
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

// impl<O, B> PacketParse for Packet<O, B>
// where
//     O: PacketParse,
//     B: PacketParse,
// {

// }

// base operations needed on a storage type.
//

// the model we're working on is still the same: a packet must not
// straddle slice boundaries.
// Packet parse needs to be able to return remainder.

/// Takes contiguous byte slices from a packet.
pub trait Read {
    type Chunk: Chunk;
    fn next_chunk(&mut self) -> ParseResult<Self::Chunk>;
}

pub trait Chunk: Sized + AsRef<[u8]> {
    fn split(self, index: usize) -> (Self, Self);
}

impl Chunk for &[u8] {
    #[inline]
    fn split(self, index: usize) -> (Self, Self) {
        self.split_at(index)
    }
}

impl Chunk for &mut [u8] {
    #[inline]
    fn split(self, index: usize) -> (Self, Self) {
        self.split_at_mut(index)
    }
}

#[cfg(feature="alloc")]
impl Chunk for Vec<u8> {
    #[inline]
    fn split(mut self, index: usize) -> (Self, Self) {
        let new = self.split_off(index);

        (self, new)
    }
}

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

    fn parse_choice(
        data: V,
        hint: Self::Denom,
    ) -> ParseResult<(Self, V)>;
}

pub enum ParseControl<Denom: Copy> {
    Continue(Denom),
    Reject,
    Accept,
}
