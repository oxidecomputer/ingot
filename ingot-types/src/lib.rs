//! Primitive types and core traits needed to generate and use
//! `ingot` packets.

#![no_std]

use alloc::vec;
#[cfg(feature = "alloc")]
pub use alloc::vec::Vec;
use core::{
    convert::Infallible,
    marker::PhantomData,
    mem::MaybeUninit,
    net::{Ipv4Addr, Ipv6Addr},
    ops::{Deref, DerefMut},
};
#[cfg(not(feature = "alloc"))]
pub use heapless::Vec;
use zerocopy::{
    FromBytes, Immutable, IntoByteSlice, IntoByteSliceMut, IntoBytes,
    KnownLayout, Ref,
};

pub use zerocopy::{
    ByteSlice, ByteSliceMut, SplitByteSlice, SplitByteSliceMut,
};

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod field;
pub mod packet;
pub mod primitives;
pub mod util;

ingot_macros::define_tuple_trait_impls!();

pub use field::*;
pub use packet::*;

pub trait ToOwnedPacket: NextLayer {
    type Target;

    fn to_owned(&self, hint: Option<Self::Denom>) -> ParseResult<Self::Target>;
}

/// The `Packet` type corresponding to an owned representation
/// type `T` on buffer `B`.
pub type PacketOf<T, B> = Packet<T, <T as HasView<B>>::ViewType>;

impl<T: HasView<B>, B> HasView<B> for Option<T> {
    type ViewType = T;
}

impl<T: HasRepr> HasRepr for Option<T> {
    type ReprType = T;
}

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

// impl<O, B: HeaderParse> HasBuf for Packet<O, B> {
//     type BufType = <<B as HeaderParse>::Target as HasBuf>::BufType;
// }

pub trait HeaderParse<B: SplitByteSlice>: NextLayer + Sized {
    fn parse(from: B) -> ParseResult<Success<Self, B>>;
}

/// Takes contiguous byte slices from a packet.
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

unsafe impl EmitDoesNotRelyOnBufContents for &[u8] {}
unsafe impl EmitDoesNotRelyOnBufContents for Vec<u8> {}
unsafe impl<B: ByteSlice> EmitDoesNotRelyOnBufContents for RawBytes<B> {}
unsafe impl<T: EmitDoesNotRelyOnBufContents> EmitDoesNotRelyOnBufContents
    for Vec<T>
{
}

/// Thinking about what we'll need for more generic emit tracking.
///
/// # Safety
/// * Pointers must refer to the same allocation.
/// * The region `valid_start[..valid_sz]` must be contained entirely
///   within `alloc_start[..alloc_sz]`.
pub unsafe trait BufHeadroom {
    fn alloc_start(&self) -> *const u8;
    fn alloc_sz(&self) -> usize;

    fn valid_start(&self) -> *const u8;
    fn valid_sz(&self) -> usize;

    fn headroom(&self) -> usize {
        let a = self.alloc_start();
        let b = self.valid_start();
        assert!(b >= a);
        unsafe { b.offset_from(a) as usize }
    }
}

unsafe impl BufHeadroom for &[u8] {
    #[inline]
    fn alloc_start(&self) -> *const u8 {
        self.as_ptr()
    }

    #[inline]
    fn alloc_sz(&self) -> usize {
        self.len()
    }

    #[inline]
    fn valid_start(&self) -> *const u8 {
        self.alloc_start()
    }

    #[inline]
    fn valid_sz(&self) -> usize {
        self.alloc_sz()
    }
}

unsafe impl BufHeadroom for &mut [u8] {
    #[inline]
    fn alloc_start(&self) -> *const u8 {
        self.as_ptr()
    }

    #[inline]
    fn alloc_sz(&self) -> usize {
        self.len()
    }

    #[inline]
    fn valid_start(&self) -> *const u8 {
        self.alloc_start()
    }

    #[inline]
    fn valid_sz(&self) -> usize {
        self.alloc_sz()
    }
}

pub type ParseResult<T> = Result<T, ParseError>;
pub struct BufState<T, H, B> {
    pub val: T,
    pub hint: Option<H>,
    pub remainder: B,
}

pub type Success<T, B> = (T, Option<<T as NextLayer>::Denom>, B);
// BufState<T, <T as NextLayer>::Denom, <T as HasBuf>::BufType>;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ParseError {
    Unspec,
    Unwanted,
    NeedsHint,
    TooSmall,
    NoRemainingChunks,
    CannotAccept,
    Reject,
}

impl From<Infallible> for ParseError {
    fn from(_: Infallible) -> Self {
        // XXX: benchmark this one.
        //      `cargo asm` suggests the compiler is smart enough.
        //      some benchmark runs suggest marginal improvement on
        //      longer chains?
        unsafe { core::hint::unreachable_unchecked() }
        // unreachable!()
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
    pub stack: HeaderStack<Stack>,
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
        &self.stack.0
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
        &mut self.stack.0
    }

    pub fn body_mut(&mut self) -> Option<&mut RawPkt::Chunk> {
        self.last_chunk.as_mut()
    }
}

pub struct HeaderStack<T>(pub T);

// idea:
// Each layer is parse.
// Each stack is parse.
// Tuples of stacks are parse.

// impl<T, U> Parse for (T, U)
// where
//     HeaderStack<T>: Parse,
//     HeaderStack<U>: Parse,
// {
//     fn parse(data: &mut Cursor<Data<'b>>) -> ParseResult<Self>
//     where
//         Self: Sized {
//         todo!()
//     }
// }

impl<T, U> TryFrom<HeaderStack<(Option<T>, U)>> for HeaderStack<(T, U)> {
    type Error = ();

    #[inline]
    fn try_from(
        _value: HeaderStack<(Option<T>, U)>,
    ) -> Result<Self, Self::Error> {
        todo!()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Repeated<T> {
    inner: Vec<T>,
}

// Thanks to rustc's excellent Debug generic detection...
impl<T> Default for Repeated<T> {
    fn default() -> Self {
        Self { inner: Default::default() }
    }
}

impl<T> Repeated<T> {
    pub fn new(data: Vec<T>) -> Self {
        Self { inner: data }
    }
}

impl<T> From<Vec<T>> for Repeated<T> {
    fn from(value: Vec<T>) -> Self {
        Self::new(value)
    }
}

impl<T> Deref for Repeated<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for Repeated<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T: Header> Header for Repeated<T> {
    const MINIMUM_LENGTH: usize = 0;

    #[inline]
    fn packet_length(&self) -> usize {
        self.iter().map(|v| v.packet_length()).sum()
    }
}

impl<T: Emit> Emit for Repeated<T> {
    #[inline]
    fn emit_raw<V: ByteSliceMut>(&self, buf: V) -> usize {
        self.inner.emit_raw(buf)
    }

    #[inline]
    fn needs_emit(&self) -> bool {
        true
    }
}

unsafe impl<T: Emit> EmitDoesNotRelyOnBufContents for Repeated<T> where
    Vec<T>: EmitDoesNotRelyOnBufContents
{
}

pub struct RepeatedView<B, T: HasView<B> + NextLayer> {
    inner: B,
    // first_hint: Option<T::Denom>,
    marker: PhantomData<T>,
}

impl<B: ByteSlice, T: Header + NextLayer + HasView<B>> Header
    for RepeatedView<B, T>
{
    const MINIMUM_LENGTH: usize = 0;

    #[inline]
    fn packet_length(&self) -> usize {
        self.inner.len()
    }
}

impl<T: NextLayer> NextLayer for Repeated<T> {
    type Denom = T::Denom;

    fn next_layer(&self) -> Option<Self::Denom> {
        // Idea: scan to the last item
        self.inner.last().and_then(|v| v.next_layer())
    }
}

impl<D: Copy + Eq, T: NextLayer> NextLayerChoice<D> for Repeated<T> {}

impl<B: ByteSlice, T: Header + NextLayer + HasView<B>> Emit
    for RepeatedView<B, T>
{
    #[inline]
    fn emit_raw<V: ByteSliceMut>(&self, mut buf: V) -> usize {
        buf.copy_from_slice(&self.inner);

        self.inner.len()
    }

    #[inline]
    fn needs_emit(&self) -> bool {
        false
    }
}

impl<B: ByteSlice, T: HasView<B> + NextLayer> HasView<B> for Repeated<T>
where
    T::ViewType: NextLayer,
{
    type ViewType = RepeatedView<B, T>;
}

// 🧙‍♂️ Type magic abounds 🧙‍♂️
// Effectively, this works by determining, for an owned type T, which
// ViewType is associated with it and then validating that we can parse
// it identically on B and &[u8]. This allows us to split B in
// the right place by borrowing from its derived byteslice (noting that
// it is very unsound to attempt to recombine slices in general, let alone
// on arbitrary T with a deref).
impl<B: SplitByteSlice, T: HasView<B> + NextLayer<Denom = D>, D: Copy + Eq>
    ParseChoice<B, D> for RepeatedView<B, T>
where
    T: for<'a> HasView<&'a [u8]>,
    <T as HasView<B>>::ViewType: ParseChoice<B, D> + NextLayer<Denom = D>,
    for<'a> <T as HasView<&'a [u8]>>::ViewType:
        ParseChoice<&'a [u8], D> + NextLayer<Denom = D>,
{
    #[inline]
    fn parse_choice(
        data: B,
        mut hint: Option<D>,
    ) -> ParseResult<Success<Self, B>> {
        let original_len = data.deref().len();
        let mut bytes_read = 0;

        while bytes_read < original_len {
            let slice = &data[bytes_read..];
            match <T as HasView<&[u8]>>::ViewType::parse_choice(slice, hint) {
                Ok((.., l_hint, remainder)) => {
                    bytes_read = original_len - remainder.len();
                    hint = l_hint;
                }
                Err(ParseError::Unwanted) => break,
                Err(e) => return Err(e),
            }
        }

        // SAFETY:
        // We have read exactly bytes_read from data already, and
        // ByteSlice requires the base ptr + len on derived byteslices
        // to be identical/stable.
        let (inner, remainder) = unsafe { data.split_at_unchecked(bytes_read) };

        let val = Self { inner, marker: PhantomData };

        Ok((val, hint, remainder))
    }
}

// 🧙‍♂️ Type magic abounds 🧙‍♂️
// This works on a similar trick as above: we reparse target Ts out from
// the stored buffer and individually convert *those* to their owned types.
// We do not go via B in practice.
impl<D: Copy + Eq, B: SplitByteSlice, T: NextLayer<Denom = D> + HasView<B>>
    ToOwnedPacket for RepeatedView<B, T>
where
    T: for<'a> HasView<&'a [u8]>,
    for<'a> <T as HasView<&'a [u8]>>::ViewType:
        ParseChoice<&'a [u8], D> + NextLayer<Denom = D>,
    for<'a, 'b> &'b <T as HasView<&'a [u8]>>::ViewType:
        TryInto<T, Error = ParseError>,
{
    type Target = Repeated<T>;

    fn to_owned(
        &self,
        mut hint: Option<Self::Denom>,
    ) -> ParseResult<Self::Target> {
        let mut inner = vec![];
        let mut slice = &self.inner[..];

        while !slice.is_empty() {
            let (pkt, h2, rest) =
                <T as HasView<&[u8]>>::ViewType::parse_choice(slice, hint)?;
            slice = rest;
            hint = h2;

            inner.push((&pkt).try_into()?);
        }

        Ok(Repeated { inner })
    }
}

impl<
        B: ByteSlice,
        T: for<'a> HasView<&'a [u8]> + HasView<B> + NextLayer<Denom = D>,
        D: Copy + Eq,
    > RepeatedView<B, T>
{
    pub fn iter(&self, hint: Option<D>) -> RepeatedViewIter<T> {
        RepeatedViewIter { slice: &self.inner[..], hint }
    }
}

pub struct RepeatedViewIter<'a, T: HasView<&'a [u8]> + NextLayer> {
    slice: &'a [u8],
    hint: Option<T::Denom>,
}

impl<'a, D: Copy + Eq, T: HasView<&'a [u8]> + NextLayer<Denom = D>> Iterator
    for RepeatedViewIter<'a, T>
where
    <T as HasView<&'a [u8]>>::ViewType:
        ParseChoice<&'a [u8], T::Denom> + NextLayer<Denom = T::Denom>,
{
    type Item = ParseResult<<T as HasView<&'a [u8]>>::ViewType>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.slice.is_empty() {
            return None;
        }

        match T::ViewType::parse_choice(self.slice, self.hint) {
            Ok((item, hint, slice)) => {
                self.hint = hint;
                self.slice = slice;

                Some(Ok(item))
            }
            Err(e) => {
                self.slice = &[];
                Some(Err(e))
            }
        }
    }
}

// impl<B: ByteSlice, T: NextLayer + HasView<B>> NextLayer for RepeatedView<B, T> {
//     type Denom = T::Denom;

//     // #[inline]
//     // fn next_layer(&self) -> Option<Self::Denom> {
//     //     self.first_hint
//     // }
// }

impl<
        B: ByteSlice,
        T: for<'a> HasView<&'a [u8]> + HasView<B> + NextLayer<Denom = D>,
        D: Copy + Eq,
    > NextLayer for RepeatedView<B, T>
where
    for<'a> <T as HasView<&'a [u8]>>::ViewType:
        ParseChoice<&'a [u8], D> + NextLayer<Denom = D>,
{
    type Denom = T::Denom;

    fn next_layer(&self) -> Option<Self::Denom> {
        self.next_layer_choice(None)
    }
}

impl<
        B: ByteSlice,
        T: for<'a> HasView<&'a [u8]> + HasView<B> + NextLayer<Denom = D>,
        D: Copy + Eq,
    > NextLayerChoice<D> for RepeatedView<B, T>
where
    for<'a> <T as HasView<&'a [u8]>>::ViewType:
        ParseChoice<&'a [u8], D> + NextLayer<Denom = D>,
{
    fn next_layer_choice(&self, hint: Option<D>) -> Option<Self::Denom> {
        // This applies te same trick: parse through self as
        self.iter(hint).last().and_then(|v| v.ok()).and_then(|v| v.next_layer())
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

/// A tool for converting zerocopy's `Ref<_, T>`s into `&T`/`&mut T`
/// based on need and input B mutability.
///
/// This primarily reduces pointer sizes for fixed-width packet parts as
/// an internal component of all `Valid` packets.
///
/// Zerocopy issue [#368](https://github.com/google/zerocopy/issues/368)
/// would obviate the need for this, but I do not believe it is under active
/// development. It would also open us back up to allowing any `B` rather than
/// simply those which are [`IntoByteSlice`].
pub struct Accessor<B, T> {
    item_ptr: *mut T,
    storage: PhantomData<B>,
}

impl<B: SplitByteSlice, T: FromBytes + IntoBytes + KnownLayout + Immutable>
    Accessor<B, T>
{
    pub fn read_from_prefix<'a>(buf: B) -> Result<(Self, B), ParseError>
    where
        B: 'a + IntoBufPointer<'a>,
        T: 'a,
    {
        // SAFETY:
        // We use the exact same bounds on T as Ref::into_mut,
        // allowing us to grant both read/write access to the
        // T depending on B's mutability.
        // Additionally, a valid parse via Ref guarantees that ptr
        // alignment and length are as required for the type to be considered
        // as a T.
        // Unfortunately, we can't escape a Ref back into its inner B,
        // so we need to check this on the derived &[u8] first.
        // ByteSlice / IntoByteSlice guarantee stability, e.g.
        // that the deref, stored, and into buffers all have identical
        // pointers and lengths.
        let len = {
            let (r, _): (Ref<&[u8], T>, _) =
                Ref::from_prefix(buf.as_bytes())
                    .map_err(|_| ParseError::TooSmall)?;
            Ref::bytes(&r).len()
        };

        let (acc, rest) = unsafe {
            let (keep, rest) = buf.split_at_unchecked(len);

            (
                Self {
                    item_ptr: keep.into_buf_ptr() as *mut _,
                    storage: PhantomData,
                },
                rest,
            )
        };

        Ok((acc, rest))
    }
}

impl<B: ByteSlice, T: FromBytes + KnownLayout + Immutable> Deref
    for Accessor<B, T>
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY:
        // Self was created from a valid reference to T (guaranteed by `Ref::into_ref`).
        unsafe { &*(self.item_ptr) }
    }
}

impl<B: ByteSliceMut, T: FromBytes + KnownLayout + Immutable> DerefMut
    for Accessor<B, T>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY:
        // The ByteSliceMut bound informs us that the base reference must have been
        // exclusive. Given that we have &mut self here, we can recreate the mutable
        // reference.
        unsafe { &mut (*self.item_ptr) }
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
