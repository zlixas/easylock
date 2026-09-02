//! Key-derivation functions: PBKDF2 (RFC 8018) and HKDF (RFC 5869), both
//! instantiated over HMAC with any [`Hash`](crate::hash::Hash) in this crate.
//!
//! Argon2id is scheduled for a later milestone.

pub mod hkdf;
pub mod pbkdf2;

pub use hkdf::Hkdf;
pub use pbkdf2::pbkdf2;
