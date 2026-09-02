//! HMAC, generic over any [`Hash`] in this crate.

use crate::ct::{ct_eq, Choice};
use crate::hash::Hash;
use crate::secure::Zeroize;
use alloc::vec;
use alloc::vec::Vec;

/// HMAC keyed-hash MAC.
///
/// ```
/// use easylock_core::hash::Sha256;
/// use easylock_core::mac::Hmac;
/// let tag = Hmac::<Sha256>::mac(b"key", b"message");
/// assert_eq!(tag.len(), 32);
/// ```
pub struct Hmac<H: Hash> {
    inner: H,
    outer_key: Vec<u8>,
}

impl<H: Hash> Hmac<H> {
    /// Start an HMAC computation with `key`.
    pub fn new(key: &[u8]) -> Self {
        let block = H::BLOCK_LEN;
        let mut k0 = vec![0u8; block];
        if key.len() > block {
            let mut h = H::init();
            h.update(key);
            let d = h.finalize_vec();
            k0[..d.len()].copy_from_slice(&d);
        } else {
            k0[..key.len()].copy_from_slice(key);
        }

        let mut ipad = vec![0x36u8; block];
        let mut opad = vec![0x5cu8; block];
        for i in 0..block {
            ipad[i] ^= k0[i];
            opad[i] ^= k0[i];
        }

        let mut inner = H::init();
        inner.update(&ipad);

        k0.zeroize();
        ipad.zeroize();

        Self {
            inner,
            outer_key: opad,
        }
    }

    /// Feed message bytes.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finish and return the tag (`H::OUTPUT_LEN` bytes).
    pub fn finalize(mut self) -> Vec<u8> {
        let inner_digest = core::mem::replace(&mut self.inner, H::init()).finalize_vec();
        let mut outer = H::init();
        outer.update(&self.outer_key);
        outer.update(&inner_digest);
        self.outer_key.zeroize();
        outer.finalize_vec()
    }

    /// Verify `tag` in constant time.
    #[must_use]
    pub fn verify(self, tag: &[u8]) -> Choice {
        ct_eq(&self.finalize(), tag)
    }

    /// One-shot: `Hmac::<H>::mac(key, msg)`.
    pub fn mac(key: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut m = Self::new(key);
        m.update(msg);
        m.finalize()
    }
}

impl<H: Hash> Drop for Hmac<H> {
    fn drop(&mut self) {
        self.outer_key.zeroize();
    }
}

impl<H: Hash> core::fmt::Debug for Hmac<H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Hmac<{}>(<state>)", H::NAME)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::hex::encode;
    use crate::hash::{Sha256, Sha512};

    // RFC 4231 test cases.
    #[test]
    fn rfc4231_case1() {
        let key = [0x0b; 20];
        let data = b"Hi There";
        assert_eq!(
            encode(&Hmac::<Sha256>::mac(&key, data)),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            encode(&Hmac::<Sha512>::mac(&key, data)),
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
             daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        );
    }

    #[test]
    fn rfc4231_case2_short_key() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        assert_eq!(
            encode(&Hmac::<Sha256>::mac(key, data)),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn rfc4231_case6_long_key() {
        let key = [0xaa; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        assert_eq!(
            encode(&Hmac::<Sha256>::mac(&key, data)),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn verify_is_constant_time_boolean() {
        let t = Hmac::<Sha256>::mac(b"k", b"m");
        assert!(bool::from(Hmac::<Sha256>::new(b"k").also(b"m").verify(&t)));
        let mut bad = t.clone();
        bad[0] ^= 1;
        assert!(!bool::from(
            Hmac::<Sha256>::new(b"k").also(b"m").verify(&bad)
        ));
    }

    impl<H: Hash> Hmac<H> {
        fn also(mut self, m: &[u8]) -> Self {
            self.update(m);
            self
        }
    }
}
