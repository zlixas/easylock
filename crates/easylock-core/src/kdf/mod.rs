//! Key-derivation / password-hashing functions:
//!
//! * [`pbkdf2`] (RFC 8018) and [`Hkdf`] (RFC 5869) over HMAC + any
//!   [`Hash`](crate::hash::Hash) in this crate,
//! * [`argon2`] (RFC 9106) — memory-hard, the recommended choice for passwords.

pub mod argon2;
pub mod hkdf;
pub mod pbkdf2;

pub use hkdf::Hkdf;
pub use pbkdf2::pbkdf2;
