//! RSA key generation: random-prime search (Miller-Rabin) and CRT-parameter
//! derivation, producing an [`RsaPrivateKey`].
//!
//! This is **slow** (seconds for RSA-2048 in debug, a fraction of that in
//! release) and **not constant-time** — key generation runs once, off any
//! attacker-observable path. The public exponent is fixed at `F4 = 65537`.

use super::{RsaPrivateKey, RsaPublicKey};
use crate::bigint::montgomery::Montgomery;
use crate::bigint::BigUint;
use crate::secure::Zeroize;
use crate::{Error, Result};
use alloc::vec::Vec;

/// `e = 65537` (Fermat's F4), the near-universal RSA public exponent.
pub const E: u64 = 65537;

const SMALL_PRIMES: [u64; 54] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
];

/// Generate an RSA-2048 private key (two 1024-bit primes).
pub fn generate_rsa2048(rng: &mut impl FnMut(&mut [u8])) -> Result<RsaPrivateKey<32, 16>> {
    generate::<32, 16>(rng)
}

/// Generate an RSA-4096 private key (two 2048-bit primes). Considerably slower.
pub fn generate_rsa4096(rng: &mut impl FnMut(&mut [u8])) -> Result<RsaPrivateKey<64, 32>> {
    generate::<64, 32>(rng)
}

fn generate<const N: usize, const H: usize>(
    rng: &mut impl FnMut(&mut [u8]),
) -> Result<RsaPrivateKey<N, H>> {
    assert_eq!(H * 2, N);
    let p = gen_prime::<H>(rng);
    let mut q;
    let mut n_be;
    loop {
        q = gen_prime::<H>(rng);
        if q == p {
            continue;
        }
        // n = p * q, require the top bit set so |n| is exactly 64*N bits.
        let prod = p.mul_wide(&q); // 2H = N limbs
        let n = BigUint::<N>::from_limbs(to_array::<N>(&prod));
        if n.bit(64 * N - 1) == 1 {
            n_be = n.to_be_bytes();
            break;
        }
    }

    let one = BigUint::<H>::one();
    let mut p_minus_1 = p;
    p_minus_1.sub_assign(&one);
    let mut q_minus_1 = q;
    q_minus_1.sub_assign(&one);

    let dp = mod_inv_e(&p_minus_1).ok_or(Error::InvalidParameter {
        what: "rsa: gcd(e, p-1) != 1",
    })?;
    let dq = mod_inv_e(&q_minus_1).ok_or(Error::InvalidParameter {
        what: "rsa: gcd(e, q-1) != 1",
    })?;

    // qinv = q^{-1} mod p ; p is prime, so use Fermat: q^(p-2) mod p.
    let mont_p = Montgomery::<H>::new(p).ok_or(Error::InvalidParameter {
        what: "rsa prime p",
    })?;
    let mut p_minus_2 = p;
    let two = {
        let mut t = BigUint::<H>::ZERO;
        t.limbs[0] = 2;
        t
    };
    p_minus_2.sub_assign(&two);
    let qinv = mont_p.pow(&q, &p_minus_2);

    let key = RsaPrivateKey::<N, H>::from_components(
        &n_be,
        E,
        &p.to_be_bytes(),
        &q.to_be_bytes(),
        &dp.to_be_bytes(),
        &dq.to_be_bytes(),
        &qinv.to_be_bytes(),
    );

    p_minus_1.zeroize();
    q_minus_1.zeroize();
    n_be.zeroize();
    key
}

fn to_array<const N: usize>(limbs: &[u64]) -> [u64; N] {
    let mut a = [0u64; N];
    a.copy_from_slice(&limbs[..N]);
    a
}

fn random_biguint<const H: usize>(rng: &mut impl FnMut(&mut [u8])) -> BigUint<H> {
    let mut bytes = alloc::vec![0u8; H * 8];
    rng(&mut bytes);
    // interpret little-endian into limbs
    let mut limbs = [0u64; H];
    for (i, chunk) in bytes.chunks_exact(8).enumerate() {
        limbs[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    bytes.zeroize();
    BigUint::from_limbs(limbs)
}

fn gen_prime<const H: usize>(rng: &mut impl FnMut(&mut [u8])) -> BigUint<H> {
    loop {
        let mut cand = random_biguint::<H>(rng);
        cand.limbs[H - 1] |= 1 << 63; // full bit width
        cand.limbs[H - 1] |= 1 << 62; // helps p*q reach full width
        cand.limbs[0] |= 1; // odd

        // gcd(e, cand-1) == 1  <=>  e does not divide (cand - 1)
        let mut cm1 = cand;
        let one = BigUint::<H>::one();
        cm1.sub_assign(&one);
        if cm1.rem_u64(E) == 0 {
            continue;
        }

        if is_probable_prime::<H>(&cand, rng) {
            return cand;
        }
    }
}

fn is_probable_prime<const H: usize>(n: &BigUint<H>, rng: &mut impl FnMut(&mut [u8])) -> bool {
    for &sp in &SMALL_PRIMES {
        if n.rem_u64(sp) == 0 {
            return false;
        }
    }

    let one = BigUint::<H>::one();
    let mut n_minus_1 = *n;
    n_minus_1.sub_assign(&one);
    let s = n_minus_1.trailing_zeros();
    let mut d = n_minus_1;
    d.shr_bits(s);

    let Some(mont) = Montgomery::<H>::new(*n) else {
        return false;
    };

    // Deterministic small bases plus a few random ones (>= 2^-80 error).
    let mut witnesses: Vec<BigUint<H>> = [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
        .iter()
        .map(|&a| {
            let mut w = BigUint::<H>::ZERO;
            w.limbs[0] = a;
            w
        })
        .collect();
    for _ in 0..8 {
        let mut a = random_biguint::<H>(rng);
        a.conditional_sub(n);
        if !bool::from(a.is_zero()) {
            witnesses.push(a);
        }
    }

    for a in &witnesses {
        let mut x = mont.pow(a, &d);
        if x == one || x == n_minus_1 {
            continue;
        }
        let mut composite = true;
        for _ in 0..s.saturating_sub(1) {
            x = mont.mul_mod(&x, &x);
            if x == n_minus_1 {
                composite = false;
                break;
            }
        }
        if composite {
            return false;
        }
    }
    true
}

/// `e^{-1} mod m` via the extended Euclidean algorithm; the first quotient makes
/// every subsequent operand small (`e` is a 17-bit constant).
fn mod_inv_e<const H: usize>(m: &BigUint<H>) -> Option<BigUint<H>> {
    let r0 = m.rem_u64(E); // m mod e, < e
    if r0 == 0 {
        return None; // e | m  =>  gcd != 1
    }
    let (q0, _) = m.div_rem_u64(E); // m = q0*e + r0

    // egcd(r0, e): r0*s + e*t = g
    let (g, s, _t) = egcd(i128::from(r0), i128::from(E));
    if g != 1 {
        return None;
    }
    // Solve for t' with e*(t - q0*s) ≡ 1 (mod m); i.e. d ≡ (t - q0*s) mod m.
    // Recompute t from the identity r0*s + e*t = 1  ->  t = (1 - r0*s)/e.
    let t = (1 - i128::from(r0) * s) / i128::from(E);

    let m_val = *m;
    // term_t = t mod m
    let term_t = small_to_mod::<H>(t, &m_val);
    // qs = (q0 * s) mod m
    let s_abs = s.unsigned_abs() as u64;
    let mut qs = mul_mod_small::<H>(&q0, s_abs, &m_val);
    if s < 0 && !bool::from(qs.is_zero()) {
        let mut neg = m_val;
        neg.sub_assign(&qs); // qs < m  =>  no borrow
        qs = neg;
    }

    // d = (term_t - qs) mod m, both operands already in [0, m).
    let mut d = term_t;
    if bool::from(d.ct_gte(&qs)) {
        d.sub_assign(&qs);
    } else {
        d.sub_assign(&qs); // wraps to d - qs + 2^(64H)
        d.add_assign(&m_val); // + m, wraps back to d - qs + m  (< m)
    }

    // sanity: e * d ≡ 1 (mod m)
    if mul_mod_small::<H>(&d, E, &m_val) == BigUint::<H>::one() {
        Some(d)
    } else {
        None
    }
}

/// `a += b (mod m)` where `a, b < m`; correct even when `m` uses the full width.
fn add_mod<const H: usize>(a: &mut BigUint<H>, b: &BigUint<H>, m: &BigUint<H>) {
    let carry = a.add_assign(b);
    // real value = carry * 2^(64H) + a, which is < 2m.
    if carry == 1 || bool::from(a.ct_gte(m)) {
        a.sub_assign(m); // wrapping subtraction is exact here
    }
}

fn egcd(a: i128, b: i128) -> (i128, i128, i128) {
    if b == 0 {
        return (a, 1, 0);
    }
    let (g, x1, y1) = egcd(b, a % b);
    (g, y1, x1 - (a / b) * y1)
}

/// A small (possibly negative) integer reduced mod `m` into `[0, m)`.
fn small_to_mod<const H: usize>(v: i128, m: &BigUint<H>) -> BigUint<H> {
    let mut acc = BigUint::<H>::ZERO;
    acc.limbs[0] = v.unsigned_abs() as u64;
    acc.limbs[1] = (v.unsigned_abs() >> 64) as u64;
    acc.conditional_sub(m);
    if v < 0 && !bool::from(acc.is_zero()) {
        let mut neg = *m;
        neg.sub_assign(&acc);
        neg
    } else {
        acc
    }
}

/// `(a * k) mod m` for a small `k`, via double-and-add over the bits of `k`.
/// `a` may be `>= m`; it is reduced first.
fn mul_mod_small<const H: usize>(a: &BigUint<H>, k: u64, m: &BigUint<H>) -> BigUint<H> {
    let mut result = BigUint::<H>::ZERO;
    let mut base = *a;
    if bool::from(base.ct_gte(m)) {
        base.sub_assign(m);
    }
    let mut kk = k;
    while kk != 0 {
        if kk & 1 == 1 {
            add_mod(&mut result, &base, m);
        }
        let snapshot = base;
        add_mod(&mut base, &snapshot, m);
        kk >>= 1;
    }
    result
}

impl<const N: usize> RsaPublicKey<N> {
    /// Reconstruct the public key `(n, e)` shape from a generated private key's
    /// modulus bytes (helper used by front-ends after `generate_*`).
    pub fn from_generated(n_be: &[u8]) -> Result<Self> {
        Self::from_components(n_be, E)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Algorithm;

    fn seeded_rng(seed: u64) -> impl FnMut(&mut [u8]) {
        let mut s = seed;
        move |buf: &mut [u8]| {
            for b in buf.iter_mut() {
                s = s
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *b = (s >> 33) as u8;
            }
        }
    }

    #[test]
    fn egcd_small_case() {
        let (g, x, y) = egcd(240, 46);
        assert_eq!(g, 2);
        assert_eq!(240 * x + 46 * y, 2);
    }

    // Full RSA-2048 keygen is slow; run in release with `--ignored`.
    #[test]
    #[ignore = "slow: ~seconds; run with --release --ignored"]
    fn generated_key_signs_and_verifies() {
        let mut rng = seeded_rng(0xC0FFEE);
        let sk = generate_rsa2048(&mut rng).unwrap();
        let msg = b"generated RSA key round-trip";
        let sig = sk.sign_pkcs1v15(Algorithm::Sha256, msg).unwrap();
        sk.public_key()
            .verify_pkcs1v15(Algorithm::Sha256, msg, &sig)
            .unwrap();

        let seed = [0x5au8; 32];
        let ct = sk
            .public_key()
            .encrypt_oaep(Algorithm::Sha256, b"", b"hi", &seed)
            .unwrap();
        assert_eq!(sk.decrypt_oaep(Algorithm::Sha256, b"", &ct).unwrap(), b"hi");
    }
}
