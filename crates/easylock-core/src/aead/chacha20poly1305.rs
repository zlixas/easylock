//! ChaCha20-Poly1305 AEAD (RFC 8439 §2.8).

use super::{Aead, Tag};
use crate::aead::chacha20::{self, ChaCha20};
use crate::ct::ct_eq_fixed;
use crate::mac::Poly1305;
use crate::secure::{Secret, Zeroize};
use crate::{Error, Result};
use alloc::vec::Vec;

/// ChaCha20-Poly1305 with a 256-bit key and 96-bit nonce.
pub struct ChaCha20Poly1305 {
    key: Secret<32>,
}

impl ChaCha20Poly1305 {
    /// Build from a 32-byte key.
    ///
    /// # Errors
    /// [`Error::InvalidLength`] unless `key.len() == 32`.
    pub fn new(key: &[u8]) -> Result<Self> {
        Ok(Self {
            key: Secret::from_slice(key)?,
        })
    }

    fn poly_key(&self, nonce: &[u8; 12]) -> [u8; 32] {
        let blk = chacha20::block(self.key.expose(), nonce, 0);
        let mut otk = [0u8; 32];
        otk.copy_from_slice(&blk[..32]);
        otk
    }

    fn tag(otk: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> Tag {
        let mut mac = Poly1305::new(otk);
        mac.update(aad);
        mac.update(&pad16(aad.len()));
        mac.update(ciphertext);
        mac.update(&pad16(ciphertext.len()));
        let mut lens = [0u8; 16];
        lens[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
        lens[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
        mac.update(&lens);
        mac.finalize()
    }

    /// Encrypt in place: `buf` holds the plaintext on entry and the ciphertext
    /// on return; the tag is returned separately.
    pub fn seal_in_place(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> Tag {
        let mut otk = self.poly_key(nonce);
        ChaCha20::new(self.key.expose(), nonce, 1).apply(buf);
        let tag = Self::tag(&otk, aad, buf);
        otk.zeroize();
        tag
    }

    /// Decrypt in place after verifying the tag. On failure `buf` is left
    /// untouched (still ciphertext) and an error is returned.
    pub fn open_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &Tag,
    ) -> Result<()> {
        let mut otk = self.poly_key(nonce);
        let expected = Self::tag(&otk, aad, buf);
        let ok = ct_eq_fixed(&expected, tag);
        if !bool::from(ok) {
            otk.zeroize();
            return Err(Error::Authentication);
        }
        ChaCha20::new(self.key.expose(), nonce, 1).apply(buf);
        otk.zeroize();
        Ok(())
    }
}

impl Aead for ChaCha20Poly1305 {
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

impl core::fmt::Debug for ChaCha20Poly1305 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChaCha20Poly1305").finish_non_exhaustive()
    }
}

#[inline]
fn pad16(len: usize) -> Vec<u8> {
    let rem = len % 16;
    if rem == 0 {
        Vec::new()
    } else {
        alloc::vec![0u8; 16 - rem]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::hex::{decode, encode};

    // RFC 8439 §2.8.2
    #[test]
    fn rfc8439_aead_vector() {
        let key: [u8; 32] =
            decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .unwrap()
                .try_into()
                .unwrap();
        let nonce: [u8; 12] = decode("070000004041424344454647")
            .unwrap()
            .try_into()
            .unwrap();
        let aad = decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let aead = ChaCha20Poly1305::new(&key).unwrap();
        let sealed = aead.seal(&nonce, &aad, plaintext);
        let (ct, tag) = sealed.split_at(sealed.len() - 16);
        assert_eq!(
            encode(ct),
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b6116"
        );
        assert_eq!(encode(tag), "1ae10b594f09e26a7e902ecbd0600691");

        let opened = aead.open(&nonce, &aad, &sealed).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn tampered_tag_rejected() {
        let aead = ChaCha20Poly1305::new(&[0u8; 32]).unwrap();
        let mut sealed = aead.seal(&[0u8; 12], b"", b"secret");
        let n = sealed.len();
        sealed[n - 1] ^= 0x01;
        assert_eq!(
            aead.open(&[0u8; 12], b"", &sealed),
            Err(Error::Authentication)
        );
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let aead = ChaCha20Poly1305::new(&[9u8; 32]).unwrap();
        let mut sealed = aead.seal(&[1u8; 12], b"hdr", b"secret payload");
        sealed[0] ^= 0x80;
        assert!(aead.open(&[1u8; 12], b"hdr", &sealed).is_err());
    }
}
