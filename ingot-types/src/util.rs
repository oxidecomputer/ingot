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

    fn next_layer(&self) -> Option<Self::Denom> {
        // Choose the hint attached to the last item contained herein.
        self.inner.last().and_then(|v| v.next_layer())
    }
}

impl<D: Copy + Eq, T: NextLayer> NextLayerChoice<D> for Repeated<T> {}

// Safety: We know this holds true for all our derived emits.
unsafe impl<T: Emit> EmitDoesNotRelyOnBufContents for Repeated<T> where
    Vec<T>: EmitDoesNotRelyOnBufContents
{
}

/// A borrowed block of headers whose elements are parsed identically (i.e., using the same
/// `choice` or `Ingot type), and may be chained using `hint` values.
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
impl<
        D: Copy + Eq,
        B: SplitByteSlice,
        T: NextLayer<Denom = D> + HasView<B>,
        E,
    > ToOwnedPacket for RepeatedView<B, T>
where
    T: for<'a> HasView<&'a [u8]>,
    for<'a> <T as HasView<&'a [u8]>>::ViewType:
        ParseChoice<&'a [u8], D> + NextLayer<Denom = D>,
    for<'a, 'b> &'b <T as HasView<&'a [u8]>>::ViewType: TryInto<T, Error = E>,
    // Bound needed to account for `Infallible` errors via pure `From`/`Into`.
    ParseError: From<E>,
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
    /// Iterates over all sub-parsed elements.
    ///
    /// Offsets are not stored, so individual elements are re-parsed one by one.
    pub fn iter(&self, hint: Option<D>) -> RepeatedViewIter<T> {
        RepeatedViewIter { slice: &self.inner[..], hint }
    }
}

/// An iterator over all parsable values contained within a [`RepeatedView`].
///
/// Offsets are not stored, so individual elements are re-parsed one by one.
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
