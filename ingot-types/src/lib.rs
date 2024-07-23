#![no_std]

pub mod primitives {
    pub use pnet_macros_support::types::*;
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

pub trait HasBuf: Sized {
    type BufType: Chunk;
}

pub trait HeaderParse: HasBuf {
    fn parse(from: Self::BufType) -> Result<(Self, Self::BufType), ()>;
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
    fn next_chunk(&mut self) -> Result<Self::Chunk, ()>;
}

pub trait Chunk: Sized + AsRef<[u8]> {
    fn split(self, index: usize) -> (Self, Self);
}

impl Chunk for &[u8] {
    fn split(self, index: usize) -> (Self, Self) {
        self.split_at(index)
    }
}

impl<'a> Chunk for &'a mut [u8] {
    fn split(self, index: usize) -> (Self, Self) {
        self.split_at_mut(index)
    }
}

// pub struct OneChunk<V>(V, bool);

// impl<V> Read for OneChunk<V> {
//     type Chunk = &'static mut V;

//     fn next_chunk(&mut self) -> Result<Self::Chunk, ()> {
//         Ok(&mut self.0)
//     }
// }

// pub trait Emit {
//     fn emit()
// }
