//! Primitive types and core traits needed to generate and use
//! `ingot` packets.

use super::*;

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
    /// Parses out a fixed-width packet chunk `T` from the start of a given
    /// buffer.
    pub fn read_from_prefix<'a>(buf: B) -> Result<(Self, B), ParseError>
    where
        B: 'a + IntoBufPointer<'a>,
        T: 'a,
    {
        // SAFETY:
        // We use the exact same bounds on T as Ref::into_mut from zerocopy,
        // allowing us to grant both read/write access to the T depending
        // on B's mutability.
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
