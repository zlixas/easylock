//! # easylock-core
//!
//! From-scratch cryptographic primitives, a constant-time big-integer engine, and a
//! C-ABI surface for `easylock`.
//!
//! ## Security status
//!
//! These implementations are written from first principles and validated against
//! published test vectors (NIST CAVP, RFC 8439, RFC 7748, RFC 8032). They have **not**
//! been independently audited. Constant-time routines are written to avoid
//! secret-dependent branches, memory indexing, and division, and use volatile /
//! optimization-barrier techniques, but the language provides no formal guarantee.
//! Do not use this to protect production secrets without an audit.
//!
//! ## Layout
//!
//! | Module      | Contents                                                            |
//! |-------------|---------------------------------------------------------------------|
//! | [`secure`]  | `write_volatile` zeroization, `Zeroizing<T>`, `Secret<N>`           |
//! | [`ct`]      | constant-time equality, selection, conditional swap                |
//! | [`hash`]    | SHA-256, SHA-512, Keccak-256, SHA3-256                             |
//! | [`mac`]     | HMAC, Poly1305                                                     |
//! | [`kdf`]     | PBKDF2, HKDF                                                        |
//! | [`cipher`]  | AES-256 (portable + AES-NI + ARMv8), CTR mode, multi-byte XOR       |
//! | [`aead`]    | ChaCha20, ChaCha20-Poly1305, AES-256-GCM                          |
//! | [`bigint`]  | `BigUint<N>`: constant-time add/sub/mul (Karatsuba) + Montgomery    |
//! | [`ec`]      | Curve25519 field, X25519 ECDH, Ed25519 sign/verify                 |
//! | [`encode`]  | Hex, Base64, Base64URL, Base58, ROT13                             |
//! | [`ffi`]     | `extern "C"` bindings                                              |

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![allow(clippy::doc_markdown)]

extern crate alloc;

pub mod bigint;
pub mod cpu;
pub mod ct;
pub mod encode;
pub mod error;
pub mod secure;

pub mod aead;
pub mod cipher;
pub mod ec;
pub mod hash;
pub mod kdf;
pub mod mac;
pub mod rsa;

#[cfg(feature = "std")]
pub mod ffi;

pub use error::{Error, Result};

/// Library version string, pinned to the crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Target architecture this crate was compiled for.
pub const TARGET_ARCH: &str = cpu::TARGET_ARCH;

/// Human-readable description of the active build (target, AES backend).
#[must_use]
pub fn build_info() -> alloc::string::String {
    alloc::format!(
        "easylock-core {VERSION} (arch={TARGET_ARCH}) aes-backend={aes}",
        aes = cipher::aes::active_backend(),
    )
}
