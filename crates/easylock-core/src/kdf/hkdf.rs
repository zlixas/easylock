//! HKDF (RFC 5869): extract-then-expand over HMAC.

use crate::hash::Hash;
use crate::mac::Hmac;
use crate::secure::Zeroize;
use crate::{Error, Result};
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

/// An HKDF instance bound to a pseudo-random key (the output of `extract`).
pub struct Hkdf<H: Hash> {
    prk: Vec<u8>,
    _marker: PhantomData<H>,
}

impl<H: Hash> Hkdf<H> {
    /// `HKDF-Extract(salt, ikm) -> PRK`. An empty `salt` is replaced with
    /// `H::OUTPUT_LEN` zero bytes, per the RFC.
    pub fn extract(salt: &[u8], ikm: &[u8]) -> Self {
        let zero_salt;
        let salt = if salt.is_empty() {
            zero_salt = vec![0u8; H::OUTPUT_LEN];
            &zero_salt[..]
        } else {
            salt
        };
        let prk = Hmac::<H>::mac(salt, ikm);
        Self {
            prk,
            _marker: PhantomData,
        }
    }

    /// Construct directly from an existing PRK (skips extract).
    pub fn from_prk(prk: &[u8]) -> Result<Self> {
        if prk.len() < H::OUTPUT_LEN {
            return Err(Error::InvalidParameter { what: "prk length" });
        }
        Ok(Self {
            prk: prk.to_vec(),
            _marker: PhantomData,
        })
    }

    /// `HKDF-Expand(PRK, info, L) -> OKM` into a caller buffer.
    ///
    /// # Errors
    /// Fails if `out.len() > 255 * H::OUTPUT_LEN`.
    pub fn expand(&self, info: &[u8], out: &mut [u8]) -> Result<()> {
        let h_len = H::OUTPUT_LEN;
        if out.len() > 255 * h_len {
            return Err(Error::InvalidParameter { what: "okm length" });
        }
        let mut t: Vec<u8> = Vec::new();
        let mut counter: u8 = 1;
        for chunk in out.chunks_mut(h_len) {
            let mut mac = Hmac::<H>::new(&self.prk);
            mac.update(&t);
            mac.update(info);
            mac.update(&[counter]);
            t.zeroize();
            t = mac.finalize();
            chunk.copy_from_slice(&t[..chunk.len()]);
            counter = counter.wrapping_add(1);
        }
        t.zeroize();
        Ok(())
    }

    /// Allocate and return `len` bytes of output key material.
    pub fn expand_vec(&self, info: &[u8], len: usize) -> Result<Vec<u8>> {
        let mut out = vec![0u8; len];
        self.expand(info, &mut out)?;
        Ok(out)
    }

    /// One-shot extract + expand.
    pub fn derive(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
        Self::extract(salt, ikm).expand_vec(info, len)
    }
}

impl<H: Hash> Drop for Hkdf<H> {
    fn drop(&mut self) {
        self.prk.zeroize();
    }
}

impl<H: Hash> core::fmt::Debug for Hkdf<H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Hkdf<{}>(<prk redacted>)", H::NAME)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::hex::encode;
    use crate::hash::Sha256;

    // RFC 5869 Appendix A.1
    #[test]
    fn rfc5869_case1() {
        let ikm = [0x0b; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let hk = Hkdf::<Sha256>::extract(&salt, &ikm);
        assert_eq!(
            encode(&hk.prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        let okm = hk.expand_vec(&info, 42).unwrap();
        assert_eq!(
            encode(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865"
        );
    }

    // RFC 5869 Appendix A.3 (zero-length salt and info)
    #[test]
    fn rfc5869_case3() {
        let ikm = [0x0b; 22];
        let hk = Hkdf::<Sha256>::extract(&[], &ikm);
        let okm = hk.expand_vec(&[], 42).unwrap();
        assert_eq!(
            encode(&okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8"
        );
    }
}
