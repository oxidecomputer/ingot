// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Primitive types and core traits needed to generate and use `ingot` packets.

#![no_std]
#![deny(missing_docs)]

use alloc::vec;
#[cfg(feature = "alloc")]
pub use alloc::vec::Vec;
use core::{
    marker::PhantomData,
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
};
use zerocopy::{
    FromBytes, Immutable, IntoByteSliceMut, IntoBytes, KnownLayout, Ref,
};

pub use zerocopy::{
    ByteSlice, ByteSliceMut, IntoByteSlice, SplitByteSlice, SplitByteSliceMut,
};

#[cfg(feature = "alloc")]
extern crate alloc;

mod accessor;
mod emit;
mod error;
pub mod field;
pub mod header;
pub mod ip;
pub mod primitives;
pub mod util;

// Defines relevant packetish traits (mainly Emit) on tuples of
// size 1--16.
ingot_macros::define_tuple_trait_impls!();

pub use accessor::Accessor;
pub use emit::*;
pub use error::*;
pub use field::*;
pub use header::*;
pub use ip::*;

/// Converts a borrowed view of a header into an owned version, possibly
/// reparsing to do so.
///
/// This trait is used to support cases which are ambiguous on their own,
/// such as [`Repeated`] views over extension headers.
///
/// [`Repeated`]: util::Repeated
pub trait ToOwnedPacket: NextLayer {
    /// The output type of this conversion.
    type Target;

    /// Converts a borrowed view of a header into an owned version, possibly
    /// reparsing to do so with the aid of `hint`.
    fn to_owned(&self, hint: Option<Self::Denom>) -> ParseResult<Self::Target>;
}

/// Base trait for header/packet types.
pub trait HeaderLen {
    /// The minimum number of bytes a packet of this kind occupies
    /// when serialised.
    const MINIMUM_LENGTH: usize;

    /// The number of bytes which this packet would occupy when serialised.
    ///
    /// This should always return a value greater than or equal to
    /// [`Header::MINIMUM_LENGTH`].
    fn packet_length(&self) -> usize;
}

impl<H: HeaderLen> HeaderLen for &H {
    const MINIMUM_LENGTH: usize = H::MINIMUM_LENGTH;

    #[inline]
    fn packet_length(&self) -> usize {
        H::packet_length(self)
    }
}

impl<T: HeaderLen> HeaderLen for Vec<T> {
    const MINIMUM_LENGTH: usize = 0;

    #[inline]
    fn packet_length(&self) -> usize {
        self.iter().map(|v| v.packet_length()).sum()
    }
}

impl<T: HeaderLen> HeaderLen for Option<T> {
    const MINIMUM_LENGTH: usize = 0;

    #[inline]
    fn packet_length(&self) -> usize {
        self.as_ref().map(|v| v.packet_length()).unwrap_or_default()
    }
}

impl HeaderLen for Vec<u8> {
    const MINIMUM_LENGTH: usize = 0;

    #[inline]
    fn packet_length(&self) -> usize {
        self.len()
    }
}

/// A type which has a corresponding view-type over any buffer `B`.
pub trait HasView<B> {
    /// The type containing an equivalent to `Self`, as a network packet
    /// in a buffer `B`.
    type ViewType;
}

/// A type which has a corresponding static/owned representation type.
pub trait HasRepr {
    /// The type containing an equivalent to `Self`, as an owned struct.
    type ReprType;
}

impl<T: HasView<B>, B> HasView<B> for Option<T> {
    type ViewType = T;
}

impl<T: HasRepr> HasRepr for Option<T> {
    type ReprType = T;
}

/// A header/packet type which can be unconditionally parsed from any
/// buffer `B`.
pub trait HeaderParse<B: SplitByteSlice>: NextLayer + Sized {
    /// Parse a view-type from a given buffer.
    fn parse(from: B) -> ParseResult<Success<Self, B>>;
}

/// A header/packet type which may require a hint to be parsed from
/// any buffer `B`.
pub trait ParseChoice<B: SplitByteSlice>: Sized + NextLayer {
    /// Parse a view-type from a given buffer, using an optional
    /// hint of type.
    fn parse_choice(
        data: B,
        hint: Option<Self::Hint>,
    ) -> ParseResult<Success<Self, B>>;
}

/// An iterator over contiguous byte slices which can be parsed
/// as a packet.
pub trait Read {
    /// The type of each byte slice.
    type Chunk: SplitByteSlice;

    /// Attempts to fetch the next available byte slice from `self`.
    fn next_chunk(&mut self) -> ParseResult<Self::Chunk>;

    /// Returns the number of segments remaining.
    fn chunks_len(&self) -> usize;

    /// Returns whether there are any segments remaining.
    fn is_empty(&self) -> bool {
        self.chunks_len() == 0
    }
}

#[cfg(feature = "alloc")]
impl<'a> Read for alloc::collections::linked_list::Iter<'a, Vec<u8>> {
    type Chunk = &'a [u8];

    #[inline]
    fn next_chunk(&mut self) -> ParseResult<Self::Chunk> {
        self.next().ok_or(ParseError::TooSmall).map(|v| v.as_ref())
    }

    #[inline]
    fn chunks_len(&self) -> usize {
        ExactSizeIterator::len(self)
    }
}

#[cfg(feature = "alloc")]
impl<'a> Read for alloc::collections::linked_list::IterMut<'a, Vec<u8>> {
    type Chunk = &'a mut [u8];

    #[inline]
    fn next_chunk(&mut self) -> ParseResult<Self::Chunk> {
        self.next().ok_or(ParseError::TooSmall).map(|v| v.as_mut())
    }

    #[inline]
    fn chunks_len(&self) -> usize {
        ExactSizeIterator::len(self)
    }
}

impl HeaderLen for &[u8] {
    const MINIMUM_LENGTH: usize = 0;

    #[inline]
    fn packet_length(&self) -> usize {
        self.len()
    }
}

/// Helper alias for methods which return tuples of
/// `(header, next_layer_hint, buf_remainder)`.
pub type Success<T, B> = (T, Option<<T as NextLayer>::Denom>, B);

/// Headers which can be queried for a hint, used to select the
/// next layer in a packet.
pub trait NextLayer {
    /// The type of this header's next-layer hint.
    type Denom: Copy + Eq;

    /// A type used to help parse the header
    type Hint: Copy + Eq;

    /// Retrieve this header's next-layer hint, if possible.
    #[inline]
    fn next_layer(&self) -> Option<Self::Denom> {
        self.next_layer_choice(None)
    }

    /// Try to retrieve this header's next-layer hint, using a provided hint
    #[inline]
    fn next_layer_choice(
        &self,
        _hint: Option<Self::Hint>,
    ) -> Option<Self::Denom> {
        None
    }
}

/// Action to be taken as part of an `#[ingot(control)]` block
/// during packet parsing.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ParseControl {
    /// Proceeds with parsing the remaining layers of a packet.
    Continue,
    /// Accepts the packet if all remaining fields are `Option`al,
    /// terminating parsing.
    Accept,
    /// Explicitly rejects the packet.
    Reject,
}

/// Types which can be converted to and from bitstrings and byte arrays
/// for serialisation as fields of network packets.
///
/// This can be used for better type-checking (e.g., `bitfield`s or newtypes).
/// We might represent a next-header type using a primitive:
/// ```rust
/// # use ingot_types::{primitives::u16be, NetworkRepr};
/// #[derive(Clone, Copy, Hash, Debug, PartialEq, Eq, Ord, PartialOrd, Default)]
/// struct Ethertype(u16);
///
/// impl NetworkRepr<u16be> for Ethertype {
///     #[inline]
///     fn to_network(self) -> u16be {
///         self.0
///     }
///
///     #[inline]
///     fn from_network(val: u16be) -> Self {
///         Self(val)
///     }
/// }
/// ```
///
/// ...or, a byte array (such as `[u8; 16]`).
pub trait NetworkRepr<U: Copy> {
    /// Converts a local value into raw bytes or integer type.
    fn to_network(self) -> U;
    /// Converts a raw value into a local type.
    fn from_network(val: U) -> Self;
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

/// Successful return value from parsing a full packet header stack
/// over a base packet buffer which is [`Read`].
pub struct Parsed<Stack, RawPkt: Read> {
    /// A fully-parsed header stack.
    pub headers: Stack,
    /// The remainder of the last chunk accessed during parsing.
    pub last_chunk: Option<RawPkt::Chunk>,
    /// The leftover packet cursor.
    ///
    /// Remaining bytes can be accessed using [`Read`].
    pub data: RawPkt,
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

// Used to gate impls on BoxedHeader in downstream derives.
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

/// Needed to compute MINIMUM_LENGTH for choices.
#[doc(hidden)]
pub const fn min(a: usize, b: usize) -> usize {
    if a < b {
        a
    } else {
        b
    }
}
