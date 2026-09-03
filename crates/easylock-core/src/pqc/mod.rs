//! Post-quantum cryptography.
//!
//! * [`mlkem`] — ML-KEM (FIPS 203, formerly Kyber): a lattice key-encapsulation
//!   mechanism for quantum-resistant key exchange. Parameter sets
//!   [`mlkem::MlKem512`], [`mlkem::MlKem768`], [`mlkem::MlKem1024`].
//!
//! Signatures (ML-DSA / SLH-DSA) are not yet implemented.

pub mod mlkem;

pub use mlkem::{MlKem1024, MlKem512, MlKem768};
