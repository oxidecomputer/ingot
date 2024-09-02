use crate::{ParseError, ParseResult, Read};
use zerocopy::SplitByteSlice;

/// Convenience wrapper to use byte slices where a [`Read`] is expected.
pub struct OneChunk<T>(Option<T>);

impl<T: SplitByteSlice> Read for OneChunk<T> {
    type Chunk = T;

    fn next_chunk(&mut self) -> ParseResult<Self::Chunk> {
        self.0.take().ok_or(ParseError::Unspec)
    }
}

impl<T: SplitByteSlice> From<T> for OneChunk<T> {
    fn from(value: T) -> Self {
        Self(Some(value))
    }
}
