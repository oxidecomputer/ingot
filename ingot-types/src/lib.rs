#![no_std]

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::{
    convert::Infallible,
    net::{Ipv4Addr, Ipv6Addr},
};
#[cfg(not(feature = "alloc"))]
use heapless::Vec;

pub use zerocopy::{
    ByteSlice, ByteSliceMut, SplitByteSlice, SplitByteSliceMut,
};

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod primitives {
    #![allow(non_camel_case_types)]

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
}

pub enum Packet<O, B> {
    #[cfg(feature = "alloc")]
    /// Owned, in-memory representation of a ...
    Repr(Box<O>),
    #[cfg(not(feature = "alloc"))]
    /// Owned, in-memory representation of a ...
    Repr(O),
    /// Packed representation of a ...
    Raw(B),
}

impl<O, B> Packet<O, B> {
    pub fn repr(&self) -> Option<&O> {
        match self {
            Packet::Repr(o) => Some(o),
            _ => None,
        }
    }

    pub fn repr_mut(&mut self) -> Option<&mut O> {
        match self {
            Packet::Repr(o) => Some(o),
            _ => None,
        }
    }

    pub fn raw(&self) -> Option<&B> {
        match self {
            Packet::Raw(b) => Some(b),
            _ => None,
        }
    }

    pub fn raw_mut(&mut self) -> Option<&mut B> {
        match self {
            Packet::Raw(b) => Some(b),
            _ => None,
        }
    }
}

impl<O, B> HasView for Packet<O, B> {
    type ViewType = B;
}

impl<O, B> HasRepr for Packet<O, B> {
    type ReprType = O;
}

impl<T: HasView> HasView for Option<T> {
    type ViewType = T;
}

impl<T: HasRepr> HasRepr for Option<T> {
    type ReprType = T;
}

#[cfg(feature = "alloc")]
pub type VarBytes<V> = Packet<Vec<u8>, V>;
#[cfg(not(feature = "alloc"))]
pub type VarBytes<V> = Packet<Vec<u8, 256>, V>;

pub trait Header {
    const MINIMUM_LENGTH: usize;

    fn packet_length(&self) -> usize;
}

impl<O, B> Header for Packet<O, B>
where
    O: Header,
    B: Header,
    // B: HasRepr<ReprType = O>,
{
    const MINIMUM_LENGTH: usize = O::MINIMUM_LENGTH;

    #[inline]
    fn packet_length(&self) -> usize {
        match self {
            Packet::Repr(o) => o.packet_length(),
            Packet::Raw(b) => b.packet_length(),
        }
    }
}

impl<V> Header for VarBytes<V>
where
    V: ByteSlice,
{
    const MINIMUM_LENGTH: usize = 0;

    #[inline]
    fn packet_length(&self) -> usize {
        match self {
            Packet::Repr(o) => o.len(),
            Packet::Raw(b) => b.len(),
        }
    }
}

impl<T: Header> Header for Vec<T> {
    const MINIMUM_LENGTH: usize = 0;

    fn packet_length(&self) -> usize {
        self.iter().map(|v| v.packet_length()).sum()
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

pub trait HasView {
    type ViewType;
}

pub trait HasRepr {
    type ReprType;
}

pub trait HasBuf: Sized {
    type BufType: ByteSlice;
}

impl<O, B: HeaderParse> HasBuf for Packet<O, B> {
    type BufType = <<B as HeaderParse>::Target as HasBuf>::BufType;
}

pub trait HeaderParse {
    type Target: HasBuf + NextLayer;

    fn parse(
        from: <Self::Target as HasBuf>::BufType,
    ) -> ParseResult<Success<Self::Target>>;
}

// allows us to call e.g. Packet<A,ValidA>::parse if ValidA is also Parse
// and its owned type has a matching next layer Denom.
impl<
        B: HeaderParse<Target = B> + HasBuf + HasRepr + NextLayer + Into<Self>,
    > HeaderParse for Packet<B::ReprType, B>
where
    B: NextLayer,
    B::ReprType: NextLayer<Denom = B::Denom>,
{
    type Target = Self;

    #[inline]
    fn parse(
        from: <Self::Target as HasBuf>::BufType,
    ) -> ParseResult<Success<Self::Target>> {
        <B as HeaderParse>::parse(from).map(
            |Success { val, hint, remainder }| Success {
                val: val.into(),
                hint,
                remainder,
            },
        )
    }
}

impl<O: NextLayer, B> NextLayer for Packet<O, B>
where
    B: NextLayer<Denom = O::Denom>,
{
    type Denom = O::Denom;

    #[inline]
    fn next_layer(&self) -> Option<Self::Denom> {
        match self {
            Packet::Repr(v) => v.next_layer(),
            Packet::Raw(v) => v.next_layer(),
        }
    }
}

/// Takes contiguous byte slices from a packet.
pub trait Read {
    type Chunk: SplitByteSlice;
    fn next_chunk(&mut self) -> ParseResult<Self::Chunk>;
}

#[cfg(feature = "alloc")]
impl<'a> Read for alloc::collections::linked_list::Iter<'a, Vec<u8>> {
    type Chunk = &'a [u8];

    fn next_chunk(&mut self) -> ParseResult<Self::Chunk> {
        self.next().ok_or(ParseError::TooSmall).map(|v| v.as_ref())
    }
}

#[cfg(feature = "alloc")]
impl<'a> Read for alloc::collections::linked_list::IterMut<'a, Vec<u8>> {
    type Chunk = &'a mut [u8];

    fn next_chunk(&mut self) -> ParseResult<Self::Chunk> {
        self.next().ok_or(ParseError::TooSmall).map(|v| v.as_mut())
    }
}

// pub trait Emit {
//     fn emit()
// }

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

pub type Success<T> =
    BufState<T, <T as NextLayer>::Denom, <T as HasBuf>::BufType>;

pub trait NextLayer {
    type Denom: Copy;

    fn next_layer(&self) -> Option<Self::Denom> {
        None
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ParseError {
    Unspec,
    Unwanted,
    NeedsHint,
    TooSmall,
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
    Sized + HasBuf + NextLayer
{
    fn parse_choice(data: V, hint: Option<Denom>)
        -> ParseResult<Success<Self>>;
}

// Allow unconditional parsing of any valid standalone header in a #choice.
impl<T: HeaderParse<Target = T> + HasBuf + NextLayer, AnyDenom: Copy + Eq>
    ParseChoice<T::BufType, AnyDenom> for T
where
    <T as HasBuf>::BufType: SplitByteSlice,
{
    #[inline]
    fn parse_choice(
        data: T::BufType,
        _hint: Option<AnyDenom>,
    ) -> ParseResult<Success<Self>> {
        T::parse(data)
    }
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

    fn try_from(
        _value: HeaderStack<(Option<T>, U)>,
    ) -> Result<Self, Self::Error> {
        todo!()
    }
}
