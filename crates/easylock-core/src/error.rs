//! Error type shared across the crate. No `std::error::Error` dependency so the
//! crate stays `no_std`-friendly; a `From` bridge is provided under `std`.

use core::fmt;

/// Result alias used throughout `easylock-core`.
pub type Result<T> = core::result::Result<T, Error>;

/// All failure modes exposed by the library.
///
/// Variants are intentionally coarse: callers must not branch on the *reason* an
/// authenticated decryption failed, only on success vs. failure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// An input buffer had the wrong length (e.g. a 15-byte AES key).
    InvalidLength {
        /// What was being parsed.
        what: &'static str,
        /// Byte length the API requires.
        expected: usize,
        /// Byte length that was supplied.
        got: usize,
    },
    /// AEAD tag verification failed, or a signature did not verify.
    /// Deliberately carries no detail.
    Authentication,
    /// A decoded string contained a byte outside the alphabet.
    InvalidEncoding {
        /// Encoding name, e.g. `"base64"`.
        scheme: &'static str,
    },
    /// A big-integer / field operation received an out-of-range value
    /// (e.g. a scalar >= the group order where that is rejected).
    OutOfRange {
        /// Operation name.
        what: &'static str,
    },
    /// A counter-mode / stream cipher would overflow its counter.
    CounterExhausted,
    /// A KDF parameter was unacceptable (e.g. zero iterations).
    InvalidParameter {
        /// Parameter name.
        what: &'static str,
    },
    /// The requested operation is not supported by this build.
    Unsupported {
        /// Feature name.
        what: &'static str,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidLength {
                what,
                expected,
                got,
            } => {
                write!(
                    f,
                    "invalid length for {what}: expected {expected} bytes, got {got}"
                )
            }
            Error::Authentication => f.write_str("authentication failed"),
            Error::InvalidEncoding { scheme } => write!(f, "invalid {scheme} input"),
            Error::OutOfRange { what } => write!(f, "value out of range for {what}"),
            Error::CounterExhausted => f.write_str("stream cipher counter exhausted"),
            Error::InvalidParameter { what } => write!(f, "invalid parameter: {what}"),
            Error::Unsupported { what } => write!(f, "unsupported in this build: {what}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl Error {
    pub(crate) const fn len(what: &'static str, expected: usize, got: usize) -> Self {
        Error::InvalidLength {
            what,
            expected,
            got,
        }
    }
}
