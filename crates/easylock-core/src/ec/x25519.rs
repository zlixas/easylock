//! X25519 ECDH (RFC 7748). Port of TweetNaCl `crypto_scalarmult`.

use super::field25519::{
    fadd, fmul, fmul121666, fsq, fsub, inv25519, sel25519, to_bytes, unpack25519, GF0, GF1,
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
    /// X25519 that rejects small-order peer points (all-zero shared secret) with
    /// [`crate::Error::InvalidParameter`].
    pub fn diffie_hellman_checked(&self, peer: &PublicKey) -> crate::Result<SharedSecret> {
        let ss = self.diffie_hellman(peer);
        if ss.was_contributory() {
            Ok(ss)
        } else {
            Err(crate::Error::InvalidParameter {
                what: "x25519 peer key (small-order point)",
            })
        }
    }

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

    /// Raw X25519 (RFC 7748). A small-order `peer` yields the all-zero secret;
    /// protocols should use [`StaticSecret::diffie_hellman_checked`] or check
    /// [`SharedSecret::was_contributory`].
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

fn clamp(scalar: &[u8; 32]) -> [u8; 32] {
    let mut z = *scalar;
    z[31] = (z[31] & 127) | 64;
    z[0] &= 248;
    z
}

/// Raw scalar multiplication `X25519(scalar, u_coordinate)`: the RFC 7748
/// Montgomery ladder, swapping only when consecutive scalar bits differ.
#[must_use]
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut z = clamp(scalar);
    let x1 = unpack25519(point);

    let (mut x2, mut z2, mut x3, mut z3) = (GF1, GF0, x1, GF1);
    let mut swap = 0i64;

    for i in (0..=254).rev() {
        let bit = i64::from((z[i >> 3] >> (i & 7)) & 1);
        swap ^= bit;
        sel25519(&mut x2, &mut x3, swap);
        sel25519(&mut z2, &mut z3, swap);
        swap = bit;

        let a = fadd(x2, z2);
        let b = fsub(x2, z2);
        let c = fadd(x3, z3);
        let d = fsub(x3, z3);
        let aa = fsq(a);
        let bb = fsq(b);
        let da = fmul(d, a);
        let cb = fmul(c, b);
        let e = fsub(aa, bb);
        x3 = fsq(fadd(da, cb));
        z3 = fmul(x1, fsq(fsub(da, cb)));
        x2 = fmul(aa, bb);
        z2 = fmul(e, fadd(bb, fmul121666(e)));
    }
    sel25519(&mut x2, &mut x3, swap);
    sel25519(&mut z2, &mut z3, swap);

    let out = to_bytes(fmul(x2, inv25519(z2)));

    z.zeroize();
    for fe in [&mut x2, &mut z2, &mut x3, &mut z3] {
        fe.zeroize();
    }
    out
}

/// `X25519(scalar, 9)` — public key from a secret scalar.
///
/// Computed as a fixed-base Edwards multiplication (precomputed table) mapped
/// to the Montgomery `u`-coordinate, which is several times faster than the
/// ladder and gives the identical result.
#[must_use]
pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    let mut z = clamp(scalar);
    let out = super::edwards::base_mul_montgomery_u(&z);
    z.zeroize();
    out
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

    /// The fixed-base Edwards path must agree with the generic ladder on `u = 9`.
    #[test]
    fn base_matches_ladder() {
        let mut nine = [0u8; 32];
        nine[0] = 9;
        let mut s = [0u8; 32];
        for i in 0..64u8 {
            for (j, b) in s.iter_mut().enumerate() {
                *b = (j as u8).wrapping_mul(29).wrapping_add(i.wrapping_mul(131)) ^ i;
            }
            assert_eq!(x25519_base(&s), x25519(&s, &nine), "scalar {i}");
        }
        assert_eq!(x25519_base(&[0xff; 32]), x25519(&[0xff; 32], &nine));
        assert_eq!(x25519_base(&[0; 32]), x25519(&[0; 32], &nine));
    }

    /// RFC 7748 §5.2 iterated test (1 000 iterations).
    #[test]
    fn rfc7748_iterated_1000() {
        let mut k = [0u8; 32];
        k[0] = 9;
        let mut u = k;
        for _ in 0..1000 {
            let r = x25519(&k, &u);
            u = k;
            k = r;
        }
        assert_eq!(
            encode(&k),
            "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"
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
