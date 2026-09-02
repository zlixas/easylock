//! Repeating multi-byte XOR keystream.
//!
//! This is **not** a secure cipher — a repeating key is trivially broken. It is
//! provided for the CLI transform pipeline and for obfuscation use cases only.

use crate::secure::Zeroize;
use crate::{Error, Result};
use alloc::vec::Vec;

/// A repeating-key XOR transformer that keeps its phase across calls.
#[derive(Clone)]
pub struct XorStream {
    key: Vec<u8>,
    pos: usize,
}

impl XorStream {
    /// Create from a non-empty key.
    ///
    /// # Errors
    /// [`Error::InvalidParameter`] if the key is empty.
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.is_empty() {
            return Err(Error::InvalidParameter { what: "xor key" });
        }
        Ok(Self {
            key: key.to_vec(),
            pos: 0,
        })
    }

    /// XOR `data` in place, continuing the keystream phase.
    pub fn apply(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            *byte ^= self.key[self.pos];
            self.pos += 1;
            if self.pos == self.key.len() {
                self.pos = 0;
            }
        }
    }

    /// Convenience one-shot that does not require a mutable stream.
    #[must_use]
    pub fn xor(key: &[u8], data: &[u8]) -> Vec<u8> {
        if key.is_empty() {
            return data.to_vec();
        }
        data.iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % key.len()])
            .collect()
    }
}

impl Drop for XorStream {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl core::fmt::Debug for XorStream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XorStream").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::hex::encode;

    #[test]
    fn single_byte_xor_known() {
        assert_eq!(encode(&XorStream::xor(&[0x2a], b"hello")), "424f464645");
    }

    #[test]
    fn multi_byte_roundtrip_with_phase() {
        let key = b"KEY";
        let mut s = XorStream::new(key).unwrap();
        let mut data = b"streaming across chunks".to_vec();
        let orig = data.clone();
        // apply in uneven chunks
        {
            let (a, b) = data.split_at_mut(5);
            s.apply(a);
            s.apply(b);
        }
        assert_ne!(data, orig);
        let mut s2 = XorStream::new(key).unwrap();
        s2.apply(&mut data);
        assert_eq!(data, orig);
    }

    #[test]
    fn empty_key_rejected() {
        assert!(XorStream::new(&[]).is_err());
    }
}
