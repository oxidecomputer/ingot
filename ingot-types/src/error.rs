use core::convert::Infallible;
// use core::error::Error; //TODO

/// Convenience type for fallible operations done while parsing headers.
pub type ParseResult<T> = Result<T, ParseError>;

/// Convenience type for fallible operations done while parsing full packets.
pub type PacketParseResult<T> = Result<T, PacketParseError>;

/// An error encountered while parsing an individual header.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ParseError {
    /// Encountered a header which was not allowed by a `choice`.
    Unwanted,
    /// No hint was provided from a previous header, but the current
    /// header requires a hint to choose
    NeedsHint,
    /// There are insufficient bytes in the buffer to read the intended
    /// header.
    TooSmall,
    /// There are no remaining chunks in the [`Read`].
    ///
    /// [`Read`]: crate::Read
    NoRemainingChunks,
    /// A parser control attempted to accept an input packet as complete,
    /// however the remaining layers are non-optional.
    CannotAccept,
    /// The packet was explicitly rejected by a parser control block.
    Reject,
    /// A field in the header had an illegal value for the target datatype.
    IllegalValue,
}

impl From<Infallible> for ParseError {
    fn from(_: Infallible) -> Self {
        // There appears to be no perf improvement via
        // unreachable_unchecked! here.
        unreachable!()
    }
}

// TODO: below.
/// TODO.
#[allow(dead_code)]
pub struct PacketParseError {
    label: CRstr,
    inner: ParseError,
}

struct CRstr;
