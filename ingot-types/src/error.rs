use core::{
    convert::Infallible,
    error::Error,
    ffi::CStr,
    fmt::{Debug, Display},
};

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

impl ParseError {
    /// Return the name of the error variant as a [`CStr`].
    #[inline]
    pub fn as_cstr(&self) -> &'static CStr {
        match self {
            ParseError::Unwanted => c"Unwanted",
            ParseError::NeedsHint => c"NeedsHint",
            ParseError::TooSmall => c"TooSmall",
            ParseError::NoRemainingChunks => c"NoRemainingChunks",
            ParseError::CannotAccept => c"CannotAccept",
            ParseError::Reject => c"Reject",
            ParseError::IllegalValue => c"IllegalValue",
        }
    }
}

impl From<Infallible> for ParseError {
    #[inline]
    fn from(_: Infallible) -> Self {
        // There appears to be no perf improvement via
        // unreachable_unchecked! here.
        unreachable!()
    }
}

impl Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseError::Unwanted => {
                write!(f, "encountered header not permitted by the parser")
            }
            ParseError::NeedsHint => write!(
                f,
                "header/choice requires a hint to parse and none was provided"
            ),
            ParseError::TooSmall => {
                write!(f, "insufficient bytes in buffer to read current header")
            }
            ParseError::NoRemainingChunks => write!(
                f,
                "packet contains no more chunks for parsing outstanding headers"
            ),
            ParseError::CannotAccept => write!(
                f,
                "tried to accept packet with unfilled mandatory headers"
            ),
            ParseError::Reject => write!(f, "packet was explicitly rejected"),
            ParseError::IllegalValue => {
                write!(f, "encountered field value not permitted by the parser")
            }
        }
    }
}

impl Error for ParseError {}

/// An error encountered while parsing a complete packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PacketParseError {
    label: &'static CRStr,
    inner: ParseError,
}

impl PacketParseError {
    #[inline]
    /// Tag a [`ParseError`] with a location.
    pub const fn new(err: ParseError, label: &'static CRStr) -> Self {
        Self { label, inner: err }
    }

    #[inline]
    /// Return the underlying error.
    pub fn error(&self) -> &ParseError {
        &self.inner
    }

    #[inline]
    /// Return the name of the header where parsing failed.
    pub fn header(&self) -> &CRStr {
        self.label
    }
}

impl From<Infallible> for PacketParseError {
    #[inline]
    fn from(_: Infallible) -> Self {
        // There appears to be no perf improvement via
        // unreachable_unchecked! here.
        unreachable!()
    }
}

impl From<PacketParseError> for ParseError {
    #[inline]
    fn from(value: PacketParseError) -> Self {
        value.inner
    }
}

impl Display for PacketParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "error while parsing {}: {}", self.label, self.inner)
    }
}

impl Error for PacketParseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.inner)
    }
}

/// A static string which is jointly usable as a [`CStr`] and [`str`].
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct CRStr(&'static str, &'static CStr);

/// Error encountered while constructing a [`CRStr`] (the string was not
/// null-terminated, or was invalid UTF-8).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct CRStrError;

impl Display for CRStrError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "input string was not null-terminated")
    }
}

impl Error for CRStrError {}

impl CRStr {
    #[inline]
    /// Validate that an input UTF-8 string is null-terminated, and
    /// attempt to construct references to each kind of string.
    ///
    /// To use, an input string must be null-terminated:
    ///
    /// ```rust
    /// # use ingot_types::CRStr;
    /// # use core::ffi::CStr;
    /// let my_crstr = CRStr::new("some text\0").unwrap();
    ///
    /// let str: &str = my_crstr.as_ref();
    /// let cstr: &CStr = my_crstr.as_ref();
    /// assert_eq!(str, "some text");
    /// assert_eq!(cstr, c"some text");
    ///
    /// let will_fail = CRStr::new("not null-terminated");
    /// assert!(will_fail.is_err());
    /// ```
    pub const fn new(data: &'static str) -> Result<Self, CRStrError> {
        if let Ok(cs) = CStr::from_bytes_with_nul(data.as_bytes()) {
            if let Some((_nul, actual_str)) = data.as_bytes().split_last() {
                Ok(Self(
                    // SAFETY: We have been given a valid &str, and we know
                    // its last character *must* be \0 due to the success of
                    // from_bytes_with_nul. Additionally, \0 cannot be an interior
                    // byte of a UTF8 multibyte character (which are `0x10xx_xxxx`).
                    unsafe { core::str::from_utf8_unchecked(actual_str) },
                    cs,
                ))
            } else {
                Err(CRStrError)
            }
        } else {
            Err(CRStrError)
        }
    }

    #[inline]
    /// [`CRStr::new`] which panics on an invalid input.
    /// Intended for `static`/`const` definitions.
    ///
    /// ```rust
    /// # use ingot_types::CRStr;
    /// # use core::ffi::CStr;
    /// static MY_STR: CRStr = CRStr::new_unchecked("some text\0");
    ///
    /// let str: &str = MY_STR.as_ref();
    /// let cstr: &CStr = MY_STR.as_ref();
    /// assert_eq!(str, "some text");
    /// assert_eq!(cstr, c"some text");
    /// ```
    pub const fn new_unchecked(data: &'static str) -> Self {
        match Self::new(data) {
            Ok(v) => v,
            Err(_) => panic!(),
        }
    }

    #[inline]
    /// Use this string as a [`str`].
    pub fn as_str(&self) -> &'static str {
        self.0
    }

    #[inline]
    /// Use this string as a [`CStr`].
    pub fn as_cstr(&self) -> &'static CStr {
        self.1
    }
}

impl AsRef<str> for CRStr {
    #[inline]
    fn as_ref(&self) -> &'static str {
        self.as_str()
    }
}

impl AsRef<CStr> for CRStr {
    #[inline]
    fn as_ref(&self) -> &'static CStr {
        self.as_cstr()
    }
}

impl Error for CRStr {}

impl Debug for CRStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Display for CRStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}
