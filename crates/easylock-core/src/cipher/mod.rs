//! Symmetric ciphers.
//!
//! * [`aes::Aes256`] — AES-256 block encryption with runtime dispatch to
//!   AES-NI (x86), the ARMv8 crypto extension (aarch64), or a constant-time
//!   portable S-box.
//! * [`ctr::Ctr`] — CTR mode stream generation over any 128-bit block cipher.
//! * [`xor::XorStream`] — repeating multi-byte XOR keystream (toy cipher, kept
//!   for the transform pipeline).

pub mod aes;
pub mod ctr;
pub mod xor;

/// A 128-bit block cipher usable in CTR mode / GCM.
pub trait BlockCipher {
    /// Encrypt one 16-byte block in place.
    fn encrypt_block(&self, block: &mut [u8; 16]);
}
