// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Utilities for parsing more complex packet types or specific inputs.

use super::*;
use crate::{ParseError, ParseResult, Read};
use zerocopy::SplitByteSlice;

/// Convenience wrapper to use byte slices where a [`Read`] is expected.
pub struct OneChunk<T>(Option<T>);

impl<T: SplitByteSlice> Read for OneChunk<T> {
    type Chunk = T;

    fn next_chunk(&mut self) -> ParseResult<Self::Chunk> {
        self.0.take().ok_or(ParseError::NoRemainingChunks)
    }

    fn chunks_len(&self) -> usize {
        self.0.is_some() as usize
    }
}

impl<T: SplitByteSlice> From<T> for OneChunk<T> {
    fn from(value: T) -> Self {
        Self(Some(value))
    }
}

/// A owned block of headers whose elements are parsed identically (i.e., using the same
/// `choice` or `Ingot type), and may be chained using `hint` values.
///
/// This is mostly useful for implementing extension headers.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Repeated<T> {
    inner: Vec<T>,
}

// Thanks to rustc's excellent Default generic detection...
impl<T> Default for Repeated<T> {
    fn default() -> Self {
        Self { inner: Default::default() }
    }
}

impl<T> Repeated<T> {
    /// Wrap a list of `T`s in the [`Repeated`] newtype.
    pub fn new(data: Vec<T>) -> Self {
        Self { inner: data }
    }

    /// Unwrap a list of `T`s from the [`Repeated`] newtype.
    pub fn into_inner(self) -> Vec<T> {
        self.inner
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

impl<T: HeaderLen> HeaderLen for Repeated<T> {
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

impl<T: NextLayer> NextLayer for Repeated<T> {
    type Denom = T::Denom;
    type Hint = T::Hint;

    fn next_layer_choice(
        &self,
        _hint: Option<Self::Hint>,
    ) -> Option<Self::Denom> {
        // Choose the hint attached to the last item contained herein.
        self.inner.last().and_then(|v| v.next_layer())
    }
}

// Safety: We know this holds true for all our derived emits.
unsafe impl<T: Emit> EmitDoesNotRelyOnBufContents for Repeated<T> where
    Vec<T>: EmitDoesNotRelyOnBufContents
{
}

/// A borrowed block of headers whose elements are parsed identically (i.e., using the same
/// `choice` or `Ingot` type), and may be chained using `hint` values.
pub struct RepeatedView<B, T: HasView<B> + NextLayer> {
    inner: B,
    marker: PhantomData<T>,
}

impl<B: ByteSlice, T: HasView<B> + NextLayer> AsRef<[u8]>
    for RepeatedView<B, T>
{
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl<B: ByteSliceMut, T: HasView<B> + NextLayer> AsMut<[u8]>
    for RepeatedView<B, T>
{
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }
}

impl<B: ByteSlice, T: HeaderLen + NextLayer + HasView<B>> HeaderLen
    for RepeatedView<B, T>
{
    const MINIMUM_LENGTH: usize = 0;

    #[inline]
    fn packet_length(&self) -> usize {
        self.inner.len()
    }
}

impl<B: ByteSlice, T: HeaderLen + NextLayer + HasView<B>> Emit
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
// ViewType is associated with T and then validating that we can parse
// it identically on B and &[u8]. This allows us to split B in
// the right place by borrowing from its derived byteslice (noting that
// it is very unsound to attempt to recombine slices in general, let alone
// on arbitrary T with a deref).
impl<
        B: SplitByteSlice,
        T: HasView<B> + NextLayer<Hint = <T as NextLayer>::Denom>,
    > HeaderParse<B> for RepeatedView<B, T>
where
    T: for<'a> HasView<&'a [u8]>,
    for<'a> <T as HasView<&'a [u8]>>::ViewType:
        HeaderParse<&'a [u8]> + NextLayer<Denom = T::Denom, Hint = T::Hint>,
{
    #[inline]
    fn parse_choice(
        data: B,
        mut hint: Option<T::Hint>,
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
impl<
        B: SplitByteSlice,
        T: NextLayer<Hint = <T as NextLayer>::Denom> + HasView<B>,
        E,
    > ToOwnedPacket for RepeatedView<B, T>
where
    T: for<'a> HasView<&'a [u8]>,
    for<'a> <T as HasView<&'a [u8]>>::ViewType:
        HeaderParse<&'a [u8]> + NextLayer<Denom = T::Denom, Hint = T::Hint>,
    for<'a, 'b> &'b <T as HasView<&'a [u8]>>::ViewType: TryInto<T, Error = E>,
    // Bound needed to account for `Infallible` errors via pure `From`/`Into`.
    ParseError: From<E>,
{
    type Target = Repeated<T>;

    fn to_owned(&self, mut hint: Option<T::Hint>) -> ParseResult<Self::Target> {
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

impl<B: ByteSlice, T: for<'a> HasView<&'a [u8]> + HasView<B> + NextLayer>
    RepeatedView<B, T>
{
    /// Iterates over all sub-parsed elements.
    ///
    /// Offsets are not stored, so individual elements are re-parsed one by one.
    pub fn iter(&self, hint: Option<T::Hint>) -> RepeatedViewIter<T> {
        RepeatedViewIter { slice: &self.inner[..], hint }
    }
}

/// An iterator over all parsable values contained within a [`RepeatedView`].
///
/// Offsets are not stored, so individual elements are re-parsed one by one.
pub struct RepeatedViewIter<'a, T: HasView<&'a [u8]> + NextLayer> {
    slice: &'a [u8],
    hint: Option<T::Hint>,
}

impl<'a, T: HasView<&'a [u8]> + NextLayer<Hint = <T as NextLayer>::Denom>>
    Iterator for RepeatedViewIter<'a, T>
where
    <T as HasView<&'a [u8]>>::ViewType:
        HeaderParse<&'a [u8]> + NextLayer<Denom = T::Denom, Hint = T::Hint>,
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

impl<
        B: ByteSlice,
        T: for<'a> HasView<&'a [u8]>
            + HasView<B>
            + NextLayer<Hint = <T as NextLayer>::Denom>,
    > NextLayer for RepeatedView<B, T>
where
    for<'a> <T as HasView<&'a [u8]>>::ViewType:
        HeaderParse<&'a [u8]> + NextLayer<Denom = T::Denom, Hint = T::Hint>,
{
    type Denom = T::Denom;
    type Hint = T::Hint;

    fn next_layer_choice(
        &self,
        hint: Option<Self::Hint>,
    ) -> Option<Self::Denom> {
        self.iter(hint).last().and_then(|v| v.ok()).and_then(|v| v.next_layer())
    }
}

/// Macro which declares a zerocopy-flavored type, which can be used in a field
///
/// The type implements all of the required `derive` traits, as well as
/// `HeaderLen` and `Emit`.
#[macro_export]
macro_rules! zerocopy_type {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident($inner_vis:vis $t:ty) $(;)?
    ) => {
        $crate::zerocopy_struct!(
            $(#[$meta])*
            $vis struct $name($inner_vis $t);
        );

        impl From<$t> for $name {
            fn from(t: $t) -> Self {
                Self(t)
            }
        }
        $crate::zerocopy_impls!($name);
    };
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $inner_vis:vis $inner_name:ident: $t:ty $(,)?
        }
    ) => {
        $crate::zerocopy_struct!(
            $(#[$meta])*
            $vis struct $name { $inner_vis $inner_name: $t }
        );

        impl From<$t> for $name {
            fn from(t: $t) -> Self {
                Self { $inner_name: t }
            }
        }
        $crate::zerocopy_impls!($name);
    };
}

/// Macro which defines `HeaderLen` and `Emit` for a zerocopy-type
///
/// These are necessary for the type to be used in a variable-length field.
#[macro_export]
macro_rules! zerocopy_impls {
    ($t:ty) => {
        impl $crate::HeaderLen for $t {
            const MINIMUM_LENGTH: usize = core::mem::size_of::<Self>();
            #[inline]
            fn packet_length(&self) -> usize {
                Self::MINIMUM_LENGTH
            }
        }

        impl $crate::Emit for $t {
            #[inline]
            fn emit_raw<V: zerocopy::ByteSliceMut>(&self, mut buf: V) -> usize {
                use zerocopy::IntoBytes;
                let len = core::mem::size_of::<Self>();
                buf[..len].copy_from_slice(self.as_bytes());
                len
            }
            #[inline]
            fn needs_emit(&self) -> bool {
                false
            }
        }
    };
}

/// Helper to build a struct with all zerocopy derives
///
/// This is overly general to capture both tuple and named-field structs, so
/// it's hidden in the docs.
#[macro_export]
#[doc(hidden)]
macro_rules! zerocopy_struct {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident $($body:tt)*
    ) => {
        $(#[$meta])*
        #[derive(
            Clone,
            Copy,
            Debug,
            Eq,
            Hash,
            Ord,
            PartialEq,
            PartialOrd,
            ::zerocopy::FromBytes,
            ::zerocopy::IntoBytes,
            ::zerocopy::KnownLayout,
            ::zerocopy::Immutable,
        )]
        $vis struct $name $($body)*
    }
}
