//! Primitive types and core traits needed to generate and use
//! `ingot` packets.

#![no_std]

use alloc::vec;
#[cfg(feature = "alloc")]
pub use alloc::vec::Vec;
use core::{
    marker::PhantomData,
    mem::MaybeUninit,
    net::{Ipv4Addr, Ipv6Addr},
    ops::{Deref, DerefMut},
};
#[cfg(not(feature = "alloc"))]
pub use heapless::Vec;
use zerocopy::{
    FromBytes, Immutable, IntoByteSliceMut, IntoBytes, KnownLayout, Ref,
};

pub use zerocopy::{
    ByteSlice, ByteSliceMut, IntoByteSlice, SplitByteSlice, SplitByteSliceMut,
};

#[cfg(feature = "alloc")]
extern crate alloc;

mod accessor;
mod error;
pub mod field;
pub mod packet;
pub mod primitives;
pub mod util;

// Defines relevant packetish traits (mainly Emit) on tuples of
// size 1--16.
ingot_macros::define_tuple_trait_impls!();

pub use accessor::Accessor;
pub use error::*;
pub use field::*;
pub use packet::*;

/// Converts a borrowed view of a header into an owned version, possibly
/// reparsing to do so.
///
/// This trait is used to support cases which are ambiguous on their own,
/// such as [`Repeated`] views over extension headers.
pub trait ToOwnedPacket: NextLayer {
    type Target;

    fn to_owned(&self, hint: Option<Self::Denom>) -> ParseResult<Self::Target>;
}

impl<T: HasView<B>, B> HasView<B> for Option<T> {
    type ViewType = T;
}

impl<T: HasRepr> HasRepr for Option<T> {
    type ReprType = T;
}

///
#[cfg(feature = "alloc")]
pub type VarBytes<V> = Packet<Vec<u8>, V>;
#[cfg(not(feature = "alloc"))]
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

pub trait Header {
    const MINIMUM_LENGTH: usize;

    fn packet_length(&self) -> usize;
}

impl<T: Header> Header for Vec<T> {
    const MINIMUM_LENGTH: usize = 0;

    #[inline]
    fn packet_length(&self) -> usize {
        self.iter().map(|v| v.packet_length()).sum()
    }
}

impl<T: Header> Header for Option<T> {
    const MINIMUM_LENGTH: usize = 0;

    #[inline]
    fn packet_length(&self) -> usize {
        self.as_ref().map(|v| v.packet_length()).unwrap_or_default()
    }
}

impl Header for Vec<u8> {
    const MINIMUM_LENGTH: usize = 0;

    #[inline]
    fn packet_length(&self) -> usize {
        self.len()
    }
}

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

pub trait HasView<B> {
    type ViewType;
}

pub trait HasRepr {
    type ReprType;
}

pub trait HeaderParse<B: SplitByteSlice>: NextLayer + Sized {
    fn parse(from: B) -> ParseResult<Success<Self, B>>;
}

/// An iterator over contiguous byte slices which can be parsed
/// as a packet.
pub trait Read {
    type Chunk: SplitByteSlice;
    fn next_chunk(&mut self) -> ParseResult<Self::Chunk>;
}

#[cfg(feature = "alloc")]
impl<'a> Read for alloc::collections::linked_list::Iter<'a, Vec<u8>> {
    type Chunk = &'a [u8];

    #[inline]
    fn next_chunk(&mut self) -> ParseResult<Self::Chunk> {
        self.next().ok_or(ParseError::TooSmall).map(|v| v.as_ref())
    }
}

#[cfg(feature = "alloc")]
impl<'a> Read for alloc::collections::linked_list::IterMut<'a, Vec<u8>> {
    type Chunk = &'a mut [u8];

    #[inline]
    fn next_chunk(&mut self) -> ParseResult<Self::Chunk> {
        self.next().ok_or(ParseError::TooSmall).map(|v| v.as_mut())
    }
}

pub trait Emit: Header {
    fn emit_raw<V: ByteSliceMut>(&self, buf: V) -> usize;
    fn needs_emit(&self) -> bool;

    #[inline]
    fn emit<V: ByteSliceMut>(&self, buf: V) -> ParseResult<usize> {
        if buf.len() < self.packet_length() {
            return Err(ParseError::TooSmall);
        }

        Ok(self.emit_raw(buf))
    }

    #[inline]
    fn emit_prefix<V: SplitByteSliceMut>(&self, buf: V) -> ParseResult<V> {
        let (into, out) = buf
            .split_at(self.packet_length())
            .map_err(|_| ParseError::TooSmall)?;

        self.emit_raw(into);
        Ok(out)
    }

    #[inline]
    fn emit_suffix<V: SplitByteSliceMut>(&self, buf: V) -> ParseResult<V> {
        let l = buf.len();

        let (into, out) = buf
            .split_at(l - self.packet_length())
            .map_err(|_| ParseError::TooSmall)?;

        self.emit_raw(into);

        Ok(out)
    }

    /// Prefer [`Self::emit_vec`] when it is available.
    #[inline]
    fn to_vec(&self) -> Vec<u8> {
        let len = self.packet_length();

        let mut out = vec![0u8; len];

        let o_len = self.emit(&mut out[..]).expect(
            "mismatch between packet requested length and required length",
        );

        assert_eq!(o_len, len);

        out
    }

    #[inline]
    fn emit_uninit(&self, buf: &mut [MaybeUninit<u8>]) -> ParseResult<usize>
    where
        Self: EmitDoesNotRelyOnBufContents,
    {
        // SAFETY: `u8` does not have any validity constraints or Drop.
        // Accordingly, assuming their initialisation will not trigger
        // any adverse dropck behaviour, and any value is trivially a valid u8.
        // We are here if the implementor *promises* not to rely on
        // buf's contents.
        // We do not return a reference to the initialised region,
        // it is up to the caller to inform their datastructre that
        // bytes are initialised.

        // NOTE: reimpl'ing `slice_assume_init_mut` (unstable).
        let buf = unsafe { &mut *(buf as *mut [_] as *mut [u8]) };

        self.emit(buf)
    }

    // TODO: prefix and suffix?

    #[inline]
    fn emit_vec(&self) -> Vec<u8>
    where
        Self: EmitDoesNotRelyOnBufContents,
    {
        let len = self.packet_length();

        let mut out = Vec::with_capacity(len);

        let o_len = self.emit_uninit(out.spare_capacity_mut()).expect(
            "mismatch between packet requested length and required length",
        );
        assert_eq!(o_len, len);
        unsafe {
            out.set_len(o_len);
        }

        out
    }
}

impl<T: Emit> Emit for Vec<T> {
    #[inline]
    fn emit_raw<V: ByteSliceMut>(&self, mut buf: V) -> usize {
        let mut emitted = 0;

        for el in self {
            emitted += el.emit_raw(&mut buf[emitted..]);
        }

        emitted
    }

    #[inline]
    fn needs_emit(&self) -> bool {
        true
    }
}

impl Header for &[u8] {
    const MINIMUM_LENGTH: usize = 0;

    #[inline]
    fn packet_length(&self) -> usize {
        self.len()
    }
}

impl Emit for &[u8] {
    #[inline]
    fn emit_raw<V: ByteSliceMut>(&self, mut buf: V) -> usize {
        buf[..self.len()].copy_from_slice(self);

        self.len()
    }

    #[inline]
    fn needs_emit(&self) -> bool {
        false
    }
}

impl Emit for Vec<u8> {
    #[inline]
    fn emit_raw<V: ByteSliceMut>(&self, mut buf: V) -> usize {
        buf.copy_from_slice(self);

        self.len()
    }

    #[inline]
    fn needs_emit(&self) -> bool {
        true
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

/// TODO: explain this one.
///
/// # Safety
/// Implementors will be given an uninitialised slice of bytes, and must
/// not meaningfully read from its contents. They are obligated to have
/// written all bytes which they promise...
pub unsafe trait EmitDoesNotRelyOnBufContents {}

// Safety: We know this holds true for all our derived emits, by design.
unsafe impl EmitDoesNotRelyOnBufContents for &[u8] {}
unsafe impl EmitDoesNotRelyOnBufContents for Vec<u8> {}
unsafe impl<B: ByteSlice> EmitDoesNotRelyOnBufContents for RawBytes<B> {}
unsafe impl<T: EmitDoesNotRelyOnBufContents> EmitDoesNotRelyOnBufContents
    for Vec<T>
{
}

pub type Success<T, B> = (T, Option<<T as NextLayer>::Denom>, B);

pub trait NextLayer {
    type Denom: Copy;

    #[inline]
    fn next_layer(&self) -> Option<Self::Denom> {
        None
    }
}

pub trait NextLayerChoice<Denom: Copy + Eq>: NextLayer {
    #[inline]
    fn next_layer_choice(&self, _hint: Option<Denom>) -> Option<Self::Denom> {
        self.next_layer()
    }
}

pub trait ParseChoice<V: SplitByteSlice, Denom: Copy + Eq>:
    Sized + NextLayer
{
    fn parse_choice(
        data: V,
        hint: Option<Denom>,
    ) -> ParseResult<Success<Self, V>>;
}

pub enum ParseControl {
    Accept,
    Continue,
    Reject,
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

pub struct Parsed<Stack, RawPkt: Read> {
    // this needs to be a struct with all the right names.
    pub stack: Stack,
    // want generic data type here:
    // can be:
    //  ref or owned
    //  contig or chunked
    //  can be optional iff the proto stack is all dynamic!
    // what is right emit API?
    // need to wrap in a cursor, kinda.
    pub data: RawPkt,

    pub last_chunk: Option<RawPkt::Chunk>,
    // Not yet, but soon.
    // _self_referential: PhantomPinned,
}

impl<Stack, RawPkt: Read> Parsed<Stack, RawPkt> {
    pub fn headers(&self) -> &Stack {
        &self.stack
    }

    pub fn body(&self) -> Option<&RawPkt::Chunk> {
        self.last_chunk.as_ref()
    }
}

impl<Stack, RawPkt: Read> Parsed<Stack, RawPkt>
where
    RawPkt::Chunk: ByteSliceMut,
{
    pub fn headers_mut(&mut self) -> &mut Stack {
        &mut self.stack
    }

    pub fn body_mut(&mut self) -> Option<&mut RawPkt::Chunk> {
        self.last_chunk.as_mut()
    }
}

/// Convert a byte slice into a pointer to its base.
///
/// # Safety
/// This requires that the invariants expressed on zerocopy's
/// [`ByteSlice`] and [`IntoByteSlice`] around stability are upheld.
pub unsafe trait IntoBufPointer<'a>: IntoByteSlice<'a> {
    /// Convert a buffer into the *most exclusive pointer type
    /// permitted*, to be read by an [`Accessor`].
    ///
    /// The pointer must be cast to a `*mut u8` regardless of
    /// the source's mutability. Mutability of this buffer type
    /// ([`ByteSlice`]/[`ByteSliceMut`]) is then used to determine
    /// whether the pointer is in fact used as a `&mut T` or `&T`.
    ///
    /// # Safety
    /// This requires that the invariants expressed on zerocopy's
    /// [`ByteSlice`] and [`IntoByteSlice`] around stability are upheld,
    /// and the pointer *must* be derived from [`IntoByteSlice::into_byte_slice`]
    /// or [`IntoByteSliceMut::into_byte_slice_mut`].
    unsafe fn into_buf_ptr(self) -> *mut u8;
}

unsafe impl<'a> IntoBufPointer<'a> for &'a [u8] {
    #[inline(always)]
    unsafe fn into_buf_ptr(self) -> *mut u8 {
        self.into_byte_slice().as_ptr() as *mut _
    }
}

unsafe impl<'a> IntoBufPointer<'a> for &'a mut [u8] {
    #[inline(always)]
    unsafe fn into_buf_ptr(self) -> *mut u8 {
        self.into_byte_slice_mut().as_mut_ptr()
    }
}

// Used to gate impls on IndirectPacket in downstream derives.
#[cfg(feature = "alloc")]
#[doc(hidden)]
#[macro_export]
macro_rules! __cfg_alloc {
    ( $( $tok:tt )* ) => { $( $tok )* }
}

#[cfg(not(feature = "alloc"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __cfg_alloc {
    ( $( $tok:tt )* ) => {};
}
