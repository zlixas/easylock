//! Authenticated encryption with associated data.
//!
//! * [`chacha20::ChaCha20`] — the raw RFC 8439 stream cipher.
//! * [`ChaCha20Poly1305`] — RFC 8439 AEAD.
//! * [`Aes256Gcm`] — NIST SP 800-38D AEAD, with a hardware GHASH path.
//!
//! All `open` / `decrypt` paths verify the tag in constant time and return
//! [`crate::Error::Authentication`] (no detail) on failure, leaving no plaintext
//! for the caller.

use alloc::vec::Vec;

pub mod aes_gcm;
pub mod chacha20;
pub mod chacha20poly1305;
pub mod ghash;

pub use aes_gcm::Aes256Gcm;
pub use chacha20poly1305::ChaCha20Poly1305;

/// 128-bit authentication tag.
pub type Tag = [u8; 16];

/// Common interface for the AEADs in this crate (96-bit nonce, 128-bit tag).
pub trait Aead {
    /// Key length in bytes.
    const KEY_LEN: usize;
    /// Nonce length in bytes (always 12 here).
    const NONCE_LEN: usize = 12;

    /// Encrypt `plaintext`, returning `ciphertext || tag`.
    fn seal(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8>;

    /// Decrypt `ciphertext || tag`. Returns the plaintext or
    /// [`crate::Error::Authentication`].
    fn open(&self, nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> crate::Result<Vec<u8>>;
}
