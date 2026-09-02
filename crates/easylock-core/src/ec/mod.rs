//! Curve25519: X25519 ECDH (RFC 7748) and Ed25519 signatures (RFC 8032).
//!
//! The field and group arithmetic is a Rust port of the public-domain
//! **TweetNaCl** reference (D. J. Bernstein et al.), chosen because it is tiny,
//! widely cross-checked, and uses only 64-bit integer math (portable, no
//! `u128`-in-`no_std` concerns). Scalar clamping, the Montgomery ladder, and the
//! Edwards `cswap` are branch-free on the secret bits.

pub mod ed25519;
pub mod field25519;
pub mod x25519;

pub use ed25519::{Signature, SigningKey, VerifyingKey};
pub use x25519::{x25519, x25519_base, PublicKey, SharedSecret, StaticSecret};
