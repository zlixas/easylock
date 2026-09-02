//! X25519 ECDH (RFC 7748). Port of TweetNaCl `crypto_scalarmult`.

use super::field25519::{
    fadd, fmul, fsq, fsub, inv25519, sel25519, to_bytes, unpack25519, Gf, D121665, GF0,
};
use crate::ct::ct_eq_fixed;
use crate::secure::{Secret, Zeroize};

/// Length of every X25519 value in bytes.
pub const X25519_LEN: usize = 32;

/// A raw X25519 public key / u-coordinate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PublicKey(pub [u8; 32]);

/// A clamped-at-use X25519 secret scalar. Scrubbed on drop.
pub struct StaticSecret(Secret<32>);

/// The result of a Diffie-Hellman exchange. Scrubbed on drop.
pub struct SharedSecret(Secret<32>);

impl PublicKey {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl StaticSecret {
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Secret::from_bytes(bytes))
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        *self.0.expose()
    }

    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(x25519_base(self.0.expose()))
    }

    #[must_use]
    pub fn diffie_hellman(&self, peer: &PublicKey) -> SharedSecret {
        SharedSecret(Secret::from_bytes(x25519(self.0.expose(), &peer.0)))
    }
}

impl SharedSecret {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.expose()
    }

    /// Constant-time check that the exchange did not yield the all-zero output
    /// (which signals a small-order peer point).
    #[must_use]
    pub fn was_contributory(&self) -> bool {
        !bool::from(ct_eq_fixed(self.0.expose(), &[0u8; 32]))
    }
}

impl core::fmt::Debug for StaticSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("StaticSecret(<redacted>)")
    }
}

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SharedSecret(<redacted>)")
    }
}

/// Raw scalar multiplication `X25519(scalar, u_coordinate)`.
#[must_use]
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut z = [0u8; 32];
    z[..31].copy_from_slice(&scalar[..31]);
    z[31] = (scalar[31] & 127) | 64;
    z[0] &= 248;

    let x = unpack25519(point);

    let mut a: Gf = GF0;
    let mut b: Gf = x;
    let mut c: Gf = GF0;
    let mut d: Gf = GF0;
    a[0] = 1;
    d[0] = 1;

    for i in (0..=254).rev() {
        let bit = i64::from((z[i >> 3] >> (i & 7)) & 1);
        sel25519(&mut a, &mut b, bit);
        sel25519(&mut c, &mut d, bit);

        let e = fadd(a, c);
        a = fsub(a, c);
        c = fadd(b, d);
        b = fsub(b, d);
        d = fsq(e);
        let f = fsq(a);
        a = fmul(c, a);
        c = fmul(b, e);
        let e2 = fadd(a, c);
        a = fsub(a, c);
        b = fsq(a);
        c = fsub(d, f);
        a = fmul(c, D121665);
        a = fadd(a, d);
        c = fmul(c, a);
        a = fmul(d, f);
        d = fmul(b, x);
        b = fsq(e2);

        sel25519(&mut a, &mut b, bit);
        sel25519(&mut c, &mut d, bit);
    }

    let result = fmul(a, inv25519(c));
    let out = to_bytes(result);

    z.zeroize();
    for arr in [&mut a, &mut b, &mut c, &mut d] {
        arr.zeroize();
    }
    out
}

/// `X25519(scalar, 9)` — public key from a secret scalar.
#[must_use]
pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    let mut nine = [0u8; 32];
    nine[0] = 9;
    x25519(scalar, &nine)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::hex::{decode, encode};

    fn h32(s: &str) -> [u8; 32] {
        decode(s).unwrap().try_into().unwrap()
    }

    // RFC 7748 §5.2
    #[test]
    fn rfc7748_scalarmult_vectors() {
        let scalar = h32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = h32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        assert_eq!(
            encode(&x25519(&scalar, &u)),
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
        );

        let scalar = h32("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let u = h32("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        assert_eq!(
            encode(&x25519(&scalar, &u)),
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"
        );
    }

    // RFC 7748 §6.1
    #[test]
    fn rfc7748_dh() {
        let a_priv = h32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let b_priv = h32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let a_pub = x25519_base(&a_priv);
        let b_pub = x25519_base(&b_priv);
        assert_eq!(
            encode(&a_pub),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
        assert_eq!(
            encode(&b_pub),
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        );
        let k1 = x25519(&a_priv, &b_pub);
        let k2 = x25519(&b_priv, &a_pub);
        assert_eq!(k1, k2);
        assert_eq!(
            encode(&k1),
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        );
    }

    #[test]
    fn wrapper_api_agrees() {
        let s = StaticSecret::from_bytes(h32(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        assert_eq!(
            encode(s.public_key().as_bytes()),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
    }
}
