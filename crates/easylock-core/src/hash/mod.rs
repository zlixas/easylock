//! Cryptographic hash functions: SHA-256, SHA-512 (FIPS 180-4), Keccak-256
//! (original Keccak padding, as used by Ethereum) and SHA3-256 (FIPS 202).
//!
//! All are streaming: `init` / `update` / `finalize`. Internal block state is
//! scrubbed on drop.

use alloc::vec::Vec;

pub mod blake2b;
pub mod blake3;
pub mod keccak;
pub mod sha256;
pub mod sha3;
pub mod sha512;

pub use blake2b::Blake2b;
pub use blake3::Blake3;
pub use keccak::{Keccak256, Sha3_256};
pub use sha256::Sha256;
pub use sha3::{shake128, shake256, Shake128, Shake256};
pub use sha512::Sha512;

/// A streaming fixed-output hash function.
pub trait Hash: Clone {
    /// Digest size in bytes.
    const OUTPUT_LEN: usize;
    /// Input block size in bytes (needed by HMAC).
    const BLOCK_LEN: usize;
    /// Short lowercase identifier, e.g. `"sha256"`.
    const NAME: &'static str;

    /// Fresh state.
    fn init() -> Self;
    /// Absorb more input. May be called any number of times.
    fn update(&mut self, data: &[u8]);
    /// Consume the state and write exactly `OUTPUT_LEN` bytes into `out`.
    ///
    /// # Panics
    /// Panics if `out.len() != OUTPUT_LEN`.
    fn finalize_into(self, out: &mut [u8]);

    /// Convenience: allocate a `Vec` for the digest.
    fn finalize_vec(self) -> Vec<u8>
    where
        Self: Sized,
    {
        let mut v = alloc::vec![0u8; Self::OUTPUT_LEN];
        self.finalize_into(&mut v);
        v
    }
}

/// One-shot helper: `digest::<Sha256>(data)`.
pub fn digest<H: Hash>(data: &[u8]) -> Vec<u8> {
    let mut h = H::init();
    h.update(data);
    h.finalize_vec()
}

/// Identifier accepted by the CLI and FFI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha256,
    Sha512,
    Keccak256,
    Sha3_256,
    Blake3,
}

impl Algorithm {
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Some(
            match name
                .trim()
                .to_ascii_lowercase()
                .replace(['-', '_'], "")
                .as_str()
            {
                "sha256" => Algorithm::Sha256,
                "sha512" => Algorithm::Sha512,
                "keccak256" => Algorithm::Keccak256,
                "sha3256" | "sha3" => Algorithm::Sha3_256,
                "blake3" | "b3" => Algorithm::Blake3,
                _ => return None,
            },
        )
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha512 => "sha512",
            Algorithm::Keccak256 => "keccak256",
            Algorithm::Sha3_256 => "sha3-256",
            Algorithm::Blake3 => "blake3",
        }
    }

    #[must_use]
    pub fn output_len(self) -> usize {
        match self {
            Algorithm::Sha512 => 64,
            _ => 32,
        }
    }

    /// Hash `data` with this algorithm.
    #[must_use]
    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            Algorithm::Sha256 => digest::<Sha256>(data),
            Algorithm::Sha512 => digest::<Sha512>(data),
            Algorithm::Keccak256 => digest::<Keccak256>(data),
            Algorithm::Sha3_256 => digest::<Sha3_256>(data),
            Algorithm::Blake3 => digest::<Blake3>(data),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_digests() {
        assert_eq!(
            crate::encode::hex::encode(&Algorithm::Sha256.hash(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            crate::encode::hex::encode(&Algorithm::Keccak256.hash(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            crate::encode::hex::encode(&Algorithm::Sha3_256.hash(b"")),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
    }
}
