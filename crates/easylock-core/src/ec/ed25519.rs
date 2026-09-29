//! Ed25519 signatures (RFC 8032), after TweetNaCl's `crypto_sign` /
//! `crypto_sign_open`, restructured for detached signatures and using this
//! crate's SHA-512.
//!
//! Verification follows the permissive TweetNaCl check (`[S]B = R + [h]A`); it
//! additionally rejects non-canonical `S >= L` to remove signature malleability.

use super::edwards::{base_mul, double_scalarmult_vartime, P3};
use super::field25519::{to_bytes, unpack25519, L};
use crate::ct::ct_eq_fixed;
use crate::hash::{Hash, Sha512};
use crate::secure::{Secret, Zeroize};

/// Byte length of an Ed25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Byte length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;
/// Byte length of an Ed25519 seed / secret key.
pub const SEED_LEN: usize = 32;

/// A detached Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Signature {
    #[must_use]
    pub fn from_bytes(b: [u8; 64]) -> Self {
        Self(b)
    }
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Signature({})", crate::encode::hex::encode(&self.0))
    }
}

/// An Ed25519 public (verifying) key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VerifyingKey([u8; 32]);

impl VerifyingKey {
    #[must_use]
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Verify a detached signature over `msg`.
    #[must_use]
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> bool {
        verify(&self.0, msg, &sig.0)
    }
}

/// An Ed25519 signing key (holds the 32-byte seed; scrubbed on drop).
pub struct SigningKey {
    seed: Secret<32>,
    public: [u8; 32],
}

impl SigningKey {
    /// Derive the key pair from a 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let mut d = expand_seed(&seed);
        let a = clamp_scalar(&mut d);
        let public = base_mul(&a).compress();
        d.zeroize();
        Self {
            seed: Secret::from_bytes(seed),
            public,
        }
    }

    /// The matching verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.public)
    }

    /// The raw seed bytes.
    #[must_use]
    pub fn to_seed(&self) -> [u8; 32] {
        *self.seed.expose()
    }

    /// Produce a detached signature over `msg`.
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(sign(self.seed.expose(), &self.public, msg))
    }
}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigningKey")
            .field("public", &crate::encode::hex::encode(&self.public))
            .finish_non_exhaustive()
    }
}

// --- internals -------------------------------------------------------------

fn expand_seed(seed: &[u8; 32]) -> [u8; 64] {
    let mut h = Sha512::init();
    h.update(seed);
    let mut out = [0u8; 64];
    h.finalize_into(&mut out);
    out
}

/// Clamp the low half of the expanded seed and return it as a scalar.
fn clamp_scalar(d: &mut [u8; 64]) -> [u8; 32] {
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;
    let mut a = [0u8; 32];
    a.copy_from_slice(&d[..32]);
    a
}

/// Reduce a 64-byte little-endian value modulo `L`, returning 32 bytes.
fn reduce(hash: &[u8; 64]) -> [u8; 32] {
    let mut x = [0i64; 64];
    for i in 0..64 {
        x[i] = i64::from(hash[i]);
    }
    modl(&mut x)
}

/// TweetNaCl `modL` on `x[64]`, returning the 32-byte reduced scalar.
fn modl(x: &mut [i64; 64]) -> [u8; 32] {
    for i in (32..64).rev() {
        let mut carry = 0i64;
        let base = i - 32;
        let mut j = base;
        while j < i - 12 {
            x[j] += carry - 16 * x[i] * L[j - base];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
            j += 1;
        }
        x[j] += carry; // j == i - 12
        x[i] = 0;
    }
    let mut carry = 0i64;
    for j in 0..32 {
        x[j] += carry - (x[31] >> 4) * L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for j in 0..32 {
        x[j] -= carry * L[j];
    }
    let mut r = [0u8; 32];
    for i in 0..32 {
        x[i + 1] += x[i] >> 8;
        r[i] = (x[i] & 255) as u8;
    }
    r
}

/// `true` iff the little-endian 32-byte scalar `s` is `< L` (canonical).
fn scalar_is_canonical(s: &[u8; 32]) -> bool {
    // Compare against L byte-by-byte, MSB first.
    let mut lt = 0i32;
    let mut gt = 0i32;
    for i in (0..32).rev() {
        let si = i32::from(s[i]);
        let li = i32::from(L[i] as u8);
        let undecided = 1 - (lt | gt);
        lt |= undecided & i32::from(si < li);
        gt |= undecided & i32::from(si > li);
    }
    lt == 1
}

fn sign(seed: &[u8; 32], public: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    let mut d = expand_seed(seed);
    let a = clamp_scalar(&mut d);

    // r = SHA512(prefix || msg)
    let mut hr = Sha512::init();
    hr.update(&d[32..64]);
    hr.update(msg);
    let mut r_wide = [0u8; 64];
    hr.finalize_into(&mut r_wide);
    let r = reduce(&r_wide);

    let rr = base_mul(&r).compress();

    // h = SHA512(R || A || msg)
    let mut hh = Sha512::init();
    hh.update(&rr);
    hh.update(public);
    hh.update(msg);
    let mut h_wide = [0u8; 64];
    hh.finalize_into(&mut h_wide);
    let h = reduce(&h_wide);

    // s = (r + h * a) mod L
    let mut x = [0i64; 64];
    for i in 0..32 {
        x[i] = i64::from(r[i]);
    }
    for i in 0..32 {
        for j in 0..32 {
            x[i + j] += i64::from(h[i]) * i64::from(a[j]);
        }
    }
    let s = modl(&mut x);

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&rr);
    sig[32..].copy_from_slice(&s);

    d.zeroize();
    x.zeroize();
    sig
}

/// `true` if `enc` is the canonical encoding of its y-coordinate (y < p).
fn is_canonical_encoding(enc: &[u8; 32]) -> bool {
    let mut y = *enc;
    y[31] &= 0x7f;
    to_bytes(unpack25519(&y)) == y
}

/// Strict Ed25519 verification (the semantics of `ed25519-dalek`'s `verify_strict`):
/// on top of RFC 8032, reject non-canonical `S` and `A` encodings and small-order
/// `A` or `R`. Without these checks the identity public key `01 00…00` "verifies"
/// the forged signature `R = B, S = 1` for every message.
fn verify(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let mut s = [0u8; 32];
    s.copy_from_slice(&sig[32..]);
    if !scalar_is_canonical(&s) || !is_canonical_encoding(public) {
        return false;
    }
    let Some(neg_a) = P3::decompress_neg(public) else {
        return false;
    };
    let mut r = [0u8; 32];
    r.copy_from_slice(&sig[..32]);
    let Some(r_point) = P3::decompress_neg(&r) else {
        return false;
    };
    if neg_a.is_small_order() || r_point.is_small_order() {
        return false;
    }

    let mut hh = Sha512::init();
    hh.update(&r);
    hh.update(public);
    hh.update(msg);
    let mut h_wide = [0u8; 64];
    hh.finalize_into(&mut h_wide);
    let h = reduce(&h_wide);

    // R' = [s]B - [h]A; accept iff it encodes to R.
    let check = double_scalarmult_vartime(&h, &neg_a, &s).compress();
    bool::from(ct_eq_fixed(&check, &r))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::hex::{decode, encode};

    fn h(s: &str) -> alloc::vec::Vec<u8> {
        decode(s).unwrap()
    }

    // RFC 8032 §7.1 test vectors.
    #[test]
    fn rfc8032_vector_1_empty_message() {
        let seed: [u8; 32] = h("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .try_into()
            .unwrap();
        let sk = SigningKey::from_seed(seed);
        assert_eq!(
            encode(sk.verifying_key().as_bytes()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let sig = sk.sign(b"");
        assert_eq!(
            encode(&sig.to_bytes()),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555\
             fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        assert!(sk.verifying_key().verify(b"", &sig));
    }

    // RFC 8032 §7.1 test vector 2 (1-byte message).
    #[test]
    fn rfc8032_vector_2() {
        let seed: [u8; 32] = h("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
            .try_into()
            .unwrap();
        let sk = SigningKey::from_seed(seed);
        assert_eq!(
            encode(sk.verifying_key().as_bytes()),
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        );
        let sig = sk.sign(&[0x72]);
        assert_eq!(
            encode(&sig.to_bytes()),
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da0\
             85ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        );
        assert!(sk.verifying_key().verify(&[0x72], &sig));
    }

    #[test]
    fn rejects_tampered_signature_and_message() {
        let sk = SigningKey::from_seed([7u8; 32]);
        let vk = sk.verifying_key();
        let msg = b"attack at dawn";
        let sig = sk.sign(msg);
        assert!(vk.verify(msg, &sig));
        assert!(!vk.verify(b"attack at dusk", &sig));

        let mut bad = sig.to_bytes();
        bad[10] ^= 0x01;
        assert!(!vk.verify(msg, &Signature::from_bytes(bad)));
    }

    #[test]
    fn wrong_key_rejected() {
        let sk = SigningKey::from_seed([1u8; 32]);
        let other = SigningKey::from_seed([2u8; 32]).verifying_key();
        let sig = sk.sign(b"hi");
        assert!(!other.verify(b"hi", &sig));
    }

    /// Regression test for the small-order public key forgery: the identity key and
    /// every other small-order point must never verify anything.
    #[test]
    fn small_order_keys_and_r_are_rejected() {
        let forged = {
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(&h(
                "5866666666666666666666666666666666666666666666666666666666666666",
            ));
            sig[32] = 1; // S = 1
            Signature::from_bytes(sig)
        };
        // The 8 small-order points (canonical encodings), incl. the identity.
        let small_order = [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "0000000000000000000000000000000000000000000000000000000000000080",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        ];
        for pk in small_order {
            let vk = VerifyingKey::from_bytes(h(pk).try_into().unwrap());
            for msg in [&b""[..], b"any message", b"pay mallory 1000"] {
                assert!(
                    !vk.verify(msg, &forged),
                    "small-order key {pk} accepted a forgery"
                );
            }
        }
        // A real key still works, but not with a small-order R.
        let sk = SigningKey::from_seed([9u8; 32]);
        let vk = sk.verifying_key();
        let good = sk.sign(b"hello");
        assert!(vk.verify(b"hello", &good));
        let mut bad_r = good.to_bytes();
        bad_r[..32].copy_from_slice(&h(small_order[0]));
        assert!(!vk.verify(b"hello", &Signature::from_bytes(bad_r)));
    }

    #[test]
    fn non_canonical_public_key_encoding_rejected() {
        // y = p + 1 ≡ 1 (the identity, encoded non-canonically) must not decode.
        let mut enc = h("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        enc[31] &= 0x7f;
        assert!(!is_canonical_encoding(&enc.try_into().unwrap()));
    }
}
