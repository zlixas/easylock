//! Curve25519: X25519 ECDH (RFC 7748) and Ed25519 signatures (RFC 8032).
//!
//! Field arithmetic is radix 2^51 (five `u64` limbs, `u128` products); group
//! arithmetic follows ref10's point representations with a precomputed
//! fixed-base table. Everything that touches a secret — scalar clamping, the
//! Montgomery ladder, fixed-base table lookups — is branch-free on the secret
//! bits. Only signature verification (public inputs) uses variable-time code.

mod base_table;
pub mod ed25519;
pub mod edwards;
pub mod field25519;
pub mod x25519;

pub use ed25519::{Signature, SigningKey, VerifyingKey};
pub use x25519::{x25519, x25519_base, PublicKey, SharedSecret, StaticSecret};
