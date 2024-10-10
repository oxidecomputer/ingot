use super::*;

/// Serialise a network packet/header into a byte buffer.
pub trait Emit: HeaderLen {
    /// Writes this packet's contents into a target buffer without
    /// performing length checks.
    ///
    /// `buf` must have a length equal to [`Header::packet_length`].
    fn emit_raw<V: ByteSliceMut>(&self, buf: V) -> usize;

    /// Returns whether this packet needs a full re-emit, and
    /// has not been simply modified in-place.
    ///
    /// A header requires a full emit if it is either owned, or
    /// a variable-length field needs to be emitted.
    fn needs_emit(&self) -> bool;

    /// Writes this packet's contents into a target buffer.
    #[inline]
    fn emit<V: ByteSliceMut>(&self, buf: V) -> ParseResult<usize> {
        if buf.len() != self.packet_length() {
            return Err(ParseError::TooSmall);
        }

        Ok(self.emit_raw(buf))
    }

    /// Writes this packet's contents into the start of a target buffer.
    #[inline]
    fn emit_prefix<V: SplitByteSliceMut>(&self, buf: V) -> ParseResult<V> {
        let (into, out) = buf
            .split_at(self.packet_length())
            .map_err(|_| ParseError::TooSmall)?;

        self.emit_raw(into);
        Ok(out)
    }

    /// Writes this packet's contents at the end of a target buffer.
    #[inline]
    fn emit_suffix<V: SplitByteSliceMut>(&self, buf: V) -> ParseResult<V> {
        let l = buf.len();

        let (into, out) = buf
            .split_at(l - self.packet_length())
            .map_err(|_| ParseError::TooSmall)?;

        self.emit_raw(into);

        Ok(out)
    }

    /// Writes this packet's contents into a newly allocated `Vec` of length
    /// [`Header::packet_length`].
    ///
    /// Prefer [`Self::emit_vec`] when it is available. This method
    /// zero-initialises memory, whereas `emit_vec` avoids doing so if
    /// the type has declared its `emit_raw` can handle this case soundly.
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

    /// Writes this packet's contents into uninitialised memory.
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
        // it is up to the caller to inform their datastructure that
        // bytes are initialised.

        // NOTE: reimpl'ing `slice_assume_init_mut` (unstable).
        let buf = unsafe { &mut *(buf as *mut [_] as *mut [u8]) };

        self.emit(buf)
    }

    /// Writes this packet's contents into a newly allocated `Vec` of length
    /// [`Header::packet_length`], without zero-filling the contents.
    ///
    /// This method is faster than [`Emit::to_vec`], but requires programmer
    /// assurance via [`EmitDoesNotRelyOnBufContents`].
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

impl<E: Emit> Emit for &E {
    #[inline]
    fn emit_raw<V: ByteSliceMut>(&self, buf: V) -> usize {
        E::emit_raw(self, buf)
    }

    #[inline]
    fn needs_emit(&self) -> bool {
        E::needs_emit(self)
    }
}

/// A promise from the programmer to the compiler that an implementation
/// of [`Emit`] does not perform any reads from uninitialised memory.
///
/// # Safety
/// Implementors will be given an uninitialised slice of bytes, and must
/// not meaningfully read from its contents. They are obligated, when
/// implementing [`Emit`], to have written a value to all bytes when
/// given a slice by `emit_uninit`.
pub unsafe trait EmitDoesNotRelyOnBufContents {}

// Safety: We know this holds true for all our derived emits, by design.
unsafe impl<E: Emit + EmitDoesNotRelyOnBufContents> EmitDoesNotRelyOnBufContents
    for &E
{
}
unsafe impl EmitDoesNotRelyOnBufContents for &[u8] {}
unsafe impl EmitDoesNotRelyOnBufContents for Vec<u8> {}
unsafe impl<T: EmitDoesNotRelyOnBufContents> EmitDoesNotRelyOnBufContents
    for Vec<T>
{
}
