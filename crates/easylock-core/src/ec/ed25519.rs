//! Ed25519 signatures (RFC 8032). Port of TweetNaCl's `crypto_sign` /
//! `crypto_sign_open`, restructured for detached signatures and using this
//! crate's SHA-512.
//!
//! Verification follows the permissive TweetNaCl check (`[S]B = R + [h]A`); it
//! additionally rejects non-canonical `S >= L` to remove signature malleability.

use super::field25519::{
    fadd, fmul, fsq, fsub, inv25519, par25519, pow2523, sel25519, to_bytes, unpack25519, Gf, D, D2,
    GF0, GF1, L, SQRTM1, X, Y,
};
use crate::ct::ct_eq_fixed;
use crate::hash::{Hash, Sha512};
use crate::secure::{Secret, Zeroize};

/// Byte length of an Ed25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Byte length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;
/// Byte length of an Ed25519 seed / secret key.
pub const SEED_LEN: usize = 32;

type Point = [Gf; 4];

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
        let public = point_pack(&scalarbase(&a));
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

fn point_add(p: &mut Point, q: &Point) {
    let a = fmul(fsub(p[1], p[0]), fsub(q[1], q[0]));
    let b = fmul(fadd(p[0], p[1]), fadd(q[0], q[1]));
    let c = fmul(fmul(p[3], q[3]), D2);
    let dd = fmul(p[2], q[2]);
    let d = fadd(dd, dd);
    let e = fsub(b, a);
    let f = fsub(d, c);
    let g = fadd(d, c);
    let h = fadd(b, a);
    p[0] = fmul(e, f);
    p[1] = fmul(h, g);
    p[2] = fmul(g, f);
    p[3] = fmul(e, h);
}

fn point_cswap(p: &mut Point, q: &mut Point, b: i64) {
    for i in 0..4 {
        sel25519(&mut p[i], &mut q[i], b);
    }
}

fn scalarmult(q: &Point, s: &[u8; 32]) -> Point {
    let mut p: Point = [GF0, GF1, GF1, GF0];
    let mut qq = *q;
    for i in (0..=255).rev() {
        let b = i64::from((s[i >> 3] >> (i & 7)) & 1);
        point_cswap(&mut p, &mut qq, b);
        point_add(&mut qq, &p);
        let pc = p;
        point_add(&mut p, &pc);
        point_cswap(&mut p, &mut qq, b);
    }
    p
}

fn scalarbase(s: &[u8; 32]) -> Point {
    let q: Point = [X, Y, GF1, fmul(X, Y)];
    scalarmult(&q, s)
}

fn point_pack(p: &Point) -> [u8; 32] {
    let zi = inv25519(p[2]);
    let tx = fmul(p[0], zi);
    let ty = fmul(p[1], zi);
    let mut r = to_bytes(ty);
    r[31] ^= par25519(tx) << 7;
    r
}

fn point_unpack_neg(p: &[u8; 32]) -> Option<Point> {
    let mut r: Point = [GF0, GF0, GF1, GF0];
    r[1] = unpack25519(p);

    let mut num = fsq(r[1]);
    let mut den = fmul(num, D);
    num = fsub(num, r[2]);
    den = fadd(r[2], den);

    let den2 = fsq(den);
    let den4 = fsq(den2);
    let den6 = fmul(den4, den2);
    let mut t = fmul(den6, num);
    t = fmul(t, den);

    t = pow2523(t);
    t = fmul(t, num);
    t = fmul(t, den);
    t = fmul(t, den);
    r[0] = fmul(t, den);

    let mut chk = fmul(fsq(r[0]), den);
    if !super::field25519::eq25519(chk, num) {
        r[0] = fmul(r[0], SQRTM1);
    }
    chk = fmul(fsq(r[0]), den);
    if !super::field25519::eq25519(chk, num) {
        return None;
    }

    if par25519(r[0]) == (p[31] >> 7) {
        r[0] = fsub(GF0, r[0]);
    }
    r[3] = fmul(r[0], r[1]);
    Some(r)
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

    let rr = point_pack(&scalarbase(&r));

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

fn verify(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let mut s = [0u8; 32];
    s.copy_from_slice(&sig[32..]);
    if !scalar_is_canonical(&s) {
        return false;
    }
    let Some(q) = point_unpack_neg(public) else {
        return false;
    };

    let mut hh = Sha512::init();
    hh.update(&sig[..32]);
    hh.update(public);
    hh.update(msg);
    let mut h_wide = [0u8; 64];
    hh.finalize_into(&mut h_wide);
    let h = reduce(&h_wide);

    let mut p = scalarmult(&q, &h);
    let q2 = scalarbase(&s);
    point_add(&mut p, &q2);
    let check = point_pack(&p);

    let mut r = [0u8; 32];
    r.copy_from_slice(&sig[..32]);
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
}
