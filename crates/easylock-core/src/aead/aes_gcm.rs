//! AES-256-GCM (NIST SP 800-38D) with a 96-bit nonce.
//!
//! AES block encryption dispatches to hardware (see [`crate::cipher::aes`]);
//! GHASH currently uses the constant-time portable multiply.

use super::ghash::GHash;
use super::{Aead, Tag};
use crate::cipher::aes::Aes256;
use crate::cipher::ctr::Ctr;
use crate::ct::ct_eq_fixed;
use crate::secure::Zeroize;
use crate::{Error, Result};
use alloc::vec::Vec;

/// AES-256-GCM AEAD.
pub struct Aes256Gcm {
    aes: Aes256,
    h: [u8; 16],
}

impl Aes256Gcm {
    /// Build from a 32-byte key.
    ///
    /// # Errors
    /// [`Error::InvalidLength`] unless `key.len() == 32`.
    pub fn new(key: &[u8]) -> Result<Self> {
        let aes = Aes256::new(key)?;
        let mut h = [0u8; 16];
        aes.encrypt_block_into(&mut h); // H = E_K(0^128)
        Ok(Self { aes, h })
    }

    /// The AES backend selected for this key ("aes-ni", "armv8-crypto", ...).
    #[must_use]
    pub fn backend(&self) -> &'static str {
        self.aes.backend().as_str()
    }

    fn j0(nonce: &[u8; 12]) -> [u8; 16] {
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;
        j0
    }

    fn compute_tag(&self, j0: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> Tag {
        let mut gh = GHash::new(&self.h);
        gh.update_padded(aad);
        gh.update_padded(ciphertext);
        let mut s = gh.finalize((aad.len() as u64) * 8, (ciphertext.len() as u64) * 8);

        // T = E_K(J0) XOR S
        let mut ek_j0 = *j0;
        self.aes.encrypt_block_into(&mut ek_j0);
        for (t, k) in s.iter_mut().zip(ek_j0.iter()) {
            *t ^= *k;
        }
        ek_j0.zeroize();
        s
    }

    /// Encrypt `buf` in place; return the tag.
    pub fn seal_in_place(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> Tag {
        let j0 = Self::j0(nonce);
        // GCTR starts at inc32(J0), i.e. counter value 2 for a 96-bit nonce.
        Ctr::from_nonce96_inc32(&self.aes, nonce, 2).apply(buf);
        self.compute_tag(&j0, aad, buf)
    }

    /// Verify the tag, then decrypt `buf` in place. On failure `buf` is
    /// unchanged and [`Error::Authentication`] is returned.
    pub fn open_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &Tag,
    ) -> Result<()> {
        let j0 = Self::j0(nonce);
        let expected = self.compute_tag(&j0, aad, buf);
        if !bool::from(ct_eq_fixed(&expected, tag)) {
            return Err(Error::Authentication);
        }
        Ctr::from_nonce96_inc32(&self.aes, nonce, 2).apply(buf);
        Ok(())
    }
}

impl Aead for Aes256Gcm {
    const KEY_LEN: usize = 32;

    fn seal(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(plaintext.len() + 16);
        out.extend_from_slice(plaintext);
        let tag = self.seal_in_place(nonce, aad, &mut out);
        out.extend_from_slice(&tag);
        out
    }

    fn open(&self, nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 16 {
            return Err(Error::Authentication);
        }
        let (ct, tag) = ciphertext.split_at(ciphertext.len() - 16);
        let mut buf = ct.to_vec();
        let mut tag_arr = [0u8; 16];
        tag_arr.copy_from_slice(tag);
        self.open_in_place(nonce, aad, &mut buf, &tag_arr)?;
        Ok(buf)
    }
}

impl Drop for Aes256Gcm {
    fn drop(&mut self) {
        self.h.zeroize();
    }
}

impl core::fmt::Debug for Aes256Gcm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Aes256Gcm")
            .field("backend", &self.backend())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::hex::{decode, encode};

    // NIST GCM spec, Test Case 13/14 (AES-256).
    #[test]
    fn nist_test_case_13_empty() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let aead = Aes256Gcm::new(&key).unwrap();
        let sealed = aead.seal(&nonce, &[], &[]);
        assert_eq!(encode(&sealed), "530f8afbc74536b9a963b4f1c4cb738b");
    }

    #[test]
    fn nist_test_case_14() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let pt = [0u8; 16];
        let aead = Aes256Gcm::new(&key).unwrap();
        let sealed = aead.seal(&nonce, &[], &pt);
        let (ct, tag) = sealed.split_at(16);
        assert_eq!(encode(ct), "cea7403d4d606b6e074ec5d3baf39d18");
        assert_eq!(encode(tag), "d0d1c8a799996bf0265b98b5d48ab919");
    }

    // NIST GCM spec, Test Case 16 (AES-256, with AAD).
    #[test]
    fn nist_test_case_16() {
        let key: [u8; 32] =
            decode("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
                .unwrap()
                .try_into()
                .unwrap();
        let nonce: [u8; 12] = decode("cafebabefacedbaddecaf888")
            .unwrap()
            .try_into()
            .unwrap();
        let pt = decode(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        )
        .unwrap();
        let aad = decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
        let aead = Aes256Gcm::new(&key).unwrap();
        let sealed = aead.seal(&nonce, &aad, &pt);
        let (ct, tag) = sealed.split_at(sealed.len() - 16);
        assert_eq!(
            encode(ct),
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
             8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
        );
        assert_eq!(encode(tag), "76fc6ece0f4e1768cddf8853bb2d551b");

        let opened = aead.open(&nonce, &aad, &sealed).unwrap();
        assert_eq!(opened, pt);
    }

    #[test]
    fn tamper_detected() {
        let aead = Aes256Gcm::new(&[3u8; 32]).unwrap();
        let mut sealed = aead.seal(&[7u8; 12], b"aad", b"the plaintext here");
        sealed[2] ^= 0x40;
        assert_eq!(
            aead.open(&[7u8; 12], b"aad", &sealed),
            Err(Error::Authentication)
        );
    }
}
