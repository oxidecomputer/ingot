#![no_std]

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
pub use alloc::vec::Vec;
use core::{
    convert::Infallible,
    net::{Ipv4Addr, Ipv6Addr},
    ops::{Deref, DerefMut},
};
#[cfg(not(feature = "alloc"))]
pub use heapless::Vec;

pub use zerocopy::{
    ByteSlice, ByteSliceMut, SplitByteSlice, SplitByteSliceMut,
};

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod primitives;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Packet<O, B> {
    /// Owned, in-memory representation of a ...
    #[cfg(feature = "alloc")]
    Repr(Box<O>),
    /// Owned, in-memory representation of a ...
    #[cfg(not(feature = "alloc"))]
    Repr(O),
    /// Packed representation of a ...
    Raw(B),
}

pub enum FieldRef<'a, T: HasView<V>, V> {
    Repr(&'a T),
    Raw(&'a PacketOf<T, V>),
}

impl<'a, T: HasView<V, ViewType = Q> + AsRef<[u8]>, V, Q: AsRef<[u8]>>
    AsRef<[u8]> for FieldRef<'a, T, V>
{
    fn as_ref(&self) -> &[u8] {
        match self {
            FieldRef::Repr(t) => t.as_ref(),
            FieldRef::Raw(Packet::Repr(a)) => a.deref().as_ref(),
            FieldRef::Raw(Packet::Raw(a)) => a.as_ref(),
        }
    }
}

pub enum FieldMut<'a, T: HasView<V>, V> {
    Repr(&'a mut T),
    Raw(&'a mut PacketOf<T, V>),
}

impl<'a, T: HasView<V, ViewType = Q> + AsRef<[u8]>, V, Q: AsRef<[u8]>>
    AsRef<[u8]> for FieldMut<'a, T, V>
{
    fn as_ref(&self) -> &[u8] {
        match self {
            FieldMut::Repr(t) => t.as_ref(),
            FieldMut::Raw(Packet::Repr(a)) => a.deref().as_ref(),
            FieldMut::Raw(Packet::Raw(a)) => a.as_ref(),
        }
    }
}

impl<'a, T: HasView<V, ViewType = Q> + AsMut<[u8]>, V, Q: AsMut<[u8]>>
    AsMut<[u8]> for FieldMut<'a, T, V>
{
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            FieldMut::Repr(t) => t.as_mut(),
            FieldMut::Raw(Packet::Repr(a)) => a.deref_mut().as_mut(),
            FieldMut::Raw(Packet::Raw(a)) => a.as_mut(),
        }
    }
}

/// The `Packet` type corresponding to an owned representation
/// type `T` on buffer `B`.
pub type PacketOf<T, B> = Packet<T, <T as HasView<B>>::ViewType>;

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

    pub fn to_owned(&self) -> Self
    where
        for<'a> &'a B: Into<O>,
    {
        match self {
            Packet::Repr(_) => todo!(),
            Packet::Raw(v) => Packet::Repr(Box::new(v.into())),
        }
    }
}

impl<O, B: HasBuf> HasBuf for Packet<O, B> {
    type BufType = B::BufType;
}

impl<O: HasView<V, ViewType = B>, B: HasBuf<BufType = V>, V> HasView<V>
    for Packet<O, B>
{
    type ViewType = B;
}

impl<O, B> HasRepr for Packet<O, B> {
    type ReprType = O;
}

impl<T: HasView<B> + HasBuf<BufType = B>, B> HasView<B> for Option<T> {
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

impl<B: ByteSlice> HasBuf for B {
    type BufType = Self;
}

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

impl<T: Header> Header for Vec<T> {
    const MINIMUM_LENGTH: usize = 0;

    fn packet_length(&self) -> usize {
        self.iter().map(|v| v.packet_length()).sum()
    }
}

impl Header for Vec<u8> {
    const MINIMUM_LENGTH: usize = 0;

    fn packet_length(&self) -> usize {
        self.len()
    }
}

pub struct RawBytes<B: ByteSlice>(B);

impl<B: ByteSlice> From<B> for RawBytes<B> {
    fn from(value: B) -> Self {
        Self(value)
    }
}

impl<B: ByteSlice> Deref for RawBytes<B> {
    type Target = B;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<B: ByteSlice> DerefMut for RawBytes<B> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<B: ByteSlice> AsRef<[u8]> for RawBytes<B> {
    fn as_ref(&self) -> &[u8] {
        &self[..]
    }
}

impl<B: ByteSliceMut> AsMut<[u8]> for RawBytes<B> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self[..]
    }
}

impl<B: ByteSlice> Header for RawBytes<B> {
    const MINIMUM_LENGTH: usize = 0;

    fn packet_length(&self) -> usize {
        self.len()
    }
}

impl<B: zerocopy::ByteSlice> HasBuf for RawBytes<B> {
    type BufType = B;
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
    type ViewType: HasBuf<BufType = B>;
}

pub trait HasRepr {
    type ReprType;
}

pub trait HasBuf: Sized {
    type BufType: ByteSlice;
}

// impl<O, B: HeaderParse> HasBuf for Packet<O, B> {
//     type BufType = <<B as HeaderParse>::Target as HasBuf>::BufType;
// }

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
        <B as HeaderParse>::parse(from)
            .map(|(val, hint, remainder)| (val.into(), hint, remainder))
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
    (T, Option<<T as NextLayer>::Denom>, <T as HasBuf>::BufType);
// BufState<T, <T as NextLayer>::Denom, <T as HasBuf>::BufType>;

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

pub trait Emit {}

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

#[derive(Clone)]
pub struct Repeated<T> {
    inner: Vec<T>,
}

impl<T: Header> Header for Repeated<T> {
    const MINIMUM_LENGTH: usize = 0;

    fn packet_length(&self) -> usize {
        todo!()
    }
}

pub struct RepeatedView<B, T: NextLayer> {
    inner: B,
    first_hint: Option<T::Denom>,
}

impl<B, T: Header + NextLayer> Header for RepeatedView<B, T> {
    const MINIMUM_LENGTH: usize = 0;

    fn packet_length(&self) -> usize {
        todo!()
    }
}

impl<B: ByteSlice, T: NextLayer> HasBuf for RepeatedView<B, T> {
    type BufType = B;
}

impl<T: NextLayer> NextLayer for Repeated<T> {
    type Denom = T::Denom;
}

impl<B: ByteSlice, T: NextLayer> NextLayer for RepeatedView<B, T> {
    type Denom = T::Denom;

    fn next_layer(&self) -> Option<Self::Denom> {
        self.first_hint
    }
}

impl<B: ByteSlice, T: HasView<B> + NextLayer> HasView<B> for Repeated<T>
where
    T::ViewType: NextLayer,
{
    type ViewType = RepeatedView<B, T::ViewType>;
}

impl<
        D: Copy + Eq,
        B: SplitByteSlice,
        T: ParseChoice<B, D> + NextLayer<Denom = D>,
    > ParseChoice<B, D> for RepeatedView<B, T>
where
    T: for<'a> ParseChoice<&'a [u8], D>, // T: ParseChoice<&'static [u8], D>
                                         // <T as HasBuf>::BufType: SplitByteSlice
{
    fn parse_choice(
        data: B,
        mut hint: Option<D>,
    ) -> ParseResult<Success<Self>> {
        let original_len = data.len();
        let mut bytes_read = 0;
        let first_hint = hint;

        loop {
            let slice = &data[bytes_read..];
            match <T as ParseChoice<&[u8], D>>::parse_choice(slice, hint) {
                Ok((.., l_hint, remainder)) => {
                    bytes_read = original_len - remainder.len();
                    hint = l_hint;
                }
                Err(ParseError::Unwanted) => break,
                Err(e) => return Err(e),
            }
        }

        let (inner, remainder) = data.split_at(bytes_read);

        let val = Self { inner, first_hint };

        Ok((val, hint, remainder))
    }
}
