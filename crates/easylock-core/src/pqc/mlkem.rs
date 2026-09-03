//! ML-KEM (FIPS 203) — the NIST standard lattice KEM, formerly CRYSTALS-Kyber.
//!
//! From-scratch port of the specification: `R_q = Z_3329[X]/(X^256+1)`, the
//! length-256 NTT, centered-binomial sampling, and the Fujisaki-Okamoto
//! transform with implicit rejection. Validated against the pure-Python
//! `kyber-py` reference (deterministic KATs below).
//!
//! Parameter sets: [`MlKem512`], [`MlKem768`], [`MlKem1024`].

// The FIPS parameter-set constants keep their spec spelling (`ML-KEM-768`).
#![allow(non_upper_case_globals)]

use crate::ct::ct_eq;
use crate::hash::sha3::{sha3_256, sha3_512, Shake128, Shake256};
use crate::secure::Zeroize;
use crate::{Error, Result};
use alloc::vec;
use alloc::vec::Vec;

const Q: u32 = 3329;
const N: usize = 256;

/// `zeta^BitRev7(i) mod q`, `i = 0..128` — forward/inverse NTT twiddles.
const ZETAS: [u16; 128] = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296,
    2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331,
    3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319, 1435,
    807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910, 17, 2761, 583,
    2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050, 1703, 1651, 2789,
    1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298, 2037,
    3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403,
    1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
];

/// `zeta^(2*BitRev7(i)+1) mod q` — base-case multiplication twiddles.
const GAMMAS: [u16; 128] = [
    17, 3312, 2761, 568, 583, 2746, 2649, 680, 1637, 1692, 723, 2606, 2288, 1041, 1100, 2229, 1409,
    1920, 2662, 667, 3281, 48, 233, 3096, 756, 2573, 2156, 1173, 3015, 314, 3050, 279, 1703, 1626,
    1651, 1678, 2789, 540, 1789, 1540, 1847, 1482, 952, 2377, 1461, 1868, 2687, 642, 939, 2390,
    2308, 1021, 2437, 892, 2388, 941, 733, 2596, 2337, 992, 268, 3061, 641, 2688, 1584, 1745, 2298,
    1031, 2037, 1292, 3220, 109, 375, 2954, 2549, 780, 2090, 1239, 1645, 1684, 1063, 2266, 319,
    3010, 2773, 556, 757, 2572, 2099, 1230, 561, 2768, 2466, 863, 2594, 735, 2804, 525, 1092, 2237,
    403, 2926, 1026, 2303, 1143, 2186, 2150, 1179, 2775, 554, 886, 2443, 1722, 1607, 1212, 2117,
    1874, 1455, 1029, 2300, 2110, 1219, 2935, 394, 885, 2444, 2154, 1175,
];

const INV128: u32 = 3303; // 128^{-1} mod q

// --- polynomial arithmetic (coefficients kept reduced in [0, q)) -------------

type Poly = [u16; N];

#[inline(always)]
fn addq(a: u16, b: u16) -> u16 {
    let s = u32::from(a) + u32::from(b);
    (if s >= Q { s - Q } else { s }) as u16
}

#[inline(always)]
fn subq(a: u16, b: u16) -> u16 {
    (u32::from(a) + Q - u32::from(b)) as u16 % Q as u16
}

#[inline(always)]
fn mulq(a: u16, b: u16) -> u16 {
    ((u32::from(a) * u32::from(b)) % Q) as u16
}

fn poly_add(a: &Poly, b: &Poly) -> Poly {
    core::array::from_fn(|i| addq(a[i], b[i]))
}

fn poly_sub(a: &Poly, b: &Poly) -> Poly {
    core::array::from_fn(|i| subq(a[i], b[i]))
}

/// In-place forward NTT (FIPS 203 Algorithm 9).
fn ntt(f: &mut Poly) {
    let mut i = 1usize;
    let mut len = 128usize;
    while len >= 2 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[i];
            i += 1;
            for j in start..start + len {
                let t = mulq(zeta, f[j + len]);
                f[j + len] = subq(f[j], t);
                f[j] = addq(f[j], t);
            }
            start += 2 * len;
        }
        len /= 2;
    }
}

/// In-place inverse NTT (FIPS 203 Algorithm 10).
fn ntt_inv(f: &mut Poly) {
    let mut i = 127usize;
    let mut len = 2usize;
    while len <= 128 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[i];
            i -= 1;
            for j in start..start + len {
                let t = f[j];
                f[j] = addq(t, f[j + len]);
                f[j + len] = mulq(zeta, subq(f[j + len], t));
            }
            start += 2 * len;
        }
        len *= 2;
    }
    for c in &mut *f {
        *c = ((u32::from(*c) * INV128) % Q) as u16;
    }
}

/// Base-case multiply of two degree-1 polynomials mod `X^2 - gamma`.
#[inline(always)]
fn base_mul(a0: u16, a1: u16, b0: u16, b1: u16, gamma: u16) -> (u16, u16) {
    let c0 = addq(mulq(a0, b0), mulq(mulq(a1, b1), gamma));
    let c1 = addq(mulq(a0, b1), mulq(a1, b0));
    (c0, c1)
}

/// Multiply two NTT-domain polynomials (FIPS 203 Algorithm 11).
fn ntt_mul(a: &Poly, b: &Poly) -> Poly {
    let mut h = [0u16; N];
    for i in 0..128 {
        let (c0, c1) = base_mul(a[2 * i], a[2 * i + 1], b[2 * i], b[2 * i + 1], GAMMAS[i]);
        h[2 * i] = c0;
        h[2 * i + 1] = c1;
    }
    h
}

// --- compression / encoding -------------------------------------------------

#[inline(always)]
fn compress(x: u16, d: u32) -> u16 {
    // round(2^d / q * x) mod 2^d
    let t = ((u32::from(x) << d) + (Q >> 1)) / Q;
    (t & ((1 << d) - 1)) as u16
}

#[inline(always)]
fn decompress(y: u16, d: u32) -> u16 {
    ((u32::from(y) * Q + (1 << (d - 1))) >> d) as u16
}

/// `ByteEncode_d`: pack 256 `d`-bit coefficients, LSB first, into `32*d` bytes.
fn byte_encode(f: &Poly, d: u32) -> Vec<u8> {
    let mut out = vec![0u8; 32 * d as usize];
    let mut acc: u32 = 0;
    let mut acc_bits: u32 = 0;
    let mut oi = 0usize;
    for &coeff in f {
        acc |= u32::from(coeff) << acc_bits;
        acc_bits += d;
        while acc_bits >= 8 {
            out[oi] = (acc & 0xff) as u8;
            oi += 1;
            acc >>= 8;
            acc_bits -= 8;
        }
    }
    out
}

/// `ByteDecode_d`: inverse of [`byte_encode`]. Coefficients are reduced mod `q`
/// for `d == 12`, else mod `2^d`.
fn byte_decode(bytes: &[u8], d: u32) -> Poly {
    debug_assert_eq!(bytes.len(), 32 * d as usize);
    let modulus: u32 = if d == 12 { Q } else { 1 << d };
    let mut f = [0u16; N];
    let mut acc: u32 = 0;
    let mut acc_bits: u32 = 0;
    let mut bi = 0usize;
    for coeff in &mut f {
        while acc_bits < d {
            acc |= u32::from(bytes[bi]) << acc_bits;
            bi += 1;
            acc_bits += 8;
        }
        let val = acc & ((1 << d) - 1);
        acc >>= d;
        acc_bits -= d;
        *coeff = (val % modulus) as u16;
    }
    f
}

// --- sampling --------------------------------------------------------------

/// `SampleNTT` (FIPS 203 Algorithm 7): rejection-sample a poly in the NTT domain
/// from a SHAKE128 stream seeded by `seed = rho || j || i`.
fn sample_ntt(seed: &[u8; 34]) -> Poly {
    let mut xof = Shake128::new();
    xof.absorb(seed);
    let mut f = [0u16; N];
    let mut count = 0usize;
    let mut block = [0u8; 168];
    while count < N {
        xof.squeeze(&mut block);
        let mut k = 0;
        while k + 3 <= 168 && count < N {
            let b0 = u32::from(block[k]);
            let b1 = u32::from(block[k + 1]);
            let b2 = u32::from(block[k + 2]);
            let d1 = b0 | ((b1 & 0x0f) << 8);
            let d2 = (b1 >> 4) | (b2 << 4);
            if d1 < Q {
                f[count] = d1 as u16;
                count += 1;
            }
            if d2 < Q && count < N {
                f[count] = d2 as u16;
                count += 1;
            }
            k += 3;
        }
    }
    f
}

/// `SamplePolyCBD_eta` (FIPS 203 Algorithm 8) from `64*eta` bytes.
fn sample_cbd(bytes: &[u8], eta: usize) -> Poly {
    debug_assert_eq!(bytes.len(), 64 * eta);
    let bit = |idx: usize| -> u16 { u16::from((bytes[idx / 8] >> (idx % 8)) & 1) };
    let mut f = [0u16; N];
    for i in 0..N {
        let mut x = 0u16;
        let mut y = 0u16;
        for j in 0..eta {
            x += bit(2 * i * eta + j);
            y += bit(2 * i * eta + eta + j);
        }
        // (x - y) mod q
        f[i] = addq(x % Q as u16, Q as u16 - (y % Q as u16)) % Q as u16;
    }
    f
}

fn prf(eta: usize, seed: &[u8; 32], nonce: u8) -> Vec<u8> {
    let mut x = Shake256::new();
    x.absorb(seed);
    x.absorb(&[nonce]);
    let mut out = vec![0u8; 64 * eta];
    x.squeeze(&mut out);
    out
}

// --- parameter sets --------------------------------------------------------

/// An ML-KEM parameter set.
#[derive(Debug, Clone, Copy)]
pub struct Params {
    pub k: usize,
    pub eta1: usize,
    pub eta2: usize,
    pub du: u32,
    pub dv: u32,
    /// Short identifier, e.g. `"ML-KEM-768"`.
    pub name: &'static str,
}

/// ML-KEM-512 (NIST security category 1).
pub const MlKem512: Params = Params {
    k: 2,
    eta1: 3,
    eta2: 2,
    du: 10,
    dv: 4,
    name: "ML-KEM-512",
};
/// ML-KEM-768 (NIST security category 3). The recommended default.
pub const MlKem768: Params = Params {
    k: 3,
    eta1: 2,
    eta2: 2,
    du: 10,
    dv: 4,
    name: "ML-KEM-768",
};
/// ML-KEM-1024 (NIST security category 5).
pub const MlKem1024: Params = Params {
    k: 4,
    eta1: 2,
    eta2: 2,
    du: 11,
    dv: 5,
    name: "ML-KEM-1024",
};

impl Params {
    /// Encapsulation-key length in bytes.
    #[must_use]
    pub const fn ek_len(&self) -> usize {
        384 * self.k + 32
    }
    /// Decapsulation-key length in bytes.
    #[must_use]
    pub const fn dk_len(&self) -> usize {
        768 * self.k + 96
    }
    /// Ciphertext length in bytes.
    #[must_use]
    pub const fn ct_len(&self) -> usize {
        32 * (self.du as usize * self.k + self.dv as usize)
    }
    fn pke_sk_len(&self) -> usize {
        384 * self.k
    }
}

// --- K-PKE ---------------------------------------------------------------

fn build_matrix(rho: &[u8; 32], k: usize, transpose: bool) -> Vec<Vec<Poly>> {
    let mut a = Vec::with_capacity(k);
    for i in 0..k {
        let mut row = Vec::with_capacity(k);
        for j in 0..k {
            let mut seed = [0u8; 34];
            seed[..32].copy_from_slice(rho);
            if transpose {
                seed[32] = i as u8;
                seed[33] = j as u8;
            } else {
                seed[32] = j as u8;
                seed[33] = i as u8;
            }
            row.push(sample_ntt(&seed));
        }
        a.push(row);
    }
    a
}

fn pke_keygen(p: &Params, d: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let mut g_in = [0u8; 33];
    g_in[..32].copy_from_slice(d);
    g_in[32] = p.k as u8;
    let g = sha3_512(&g_in);
    let mut rho = [0u8; 32];
    let mut sigma = [0u8; 32];
    rho.copy_from_slice(&g[..32]);
    sigma.copy_from_slice(&g[32..]);

    let a = build_matrix(&rho, p.k, false);

    let mut s: Vec<Poly> = Vec::with_capacity(p.k);
    let mut e: Vec<Poly> = Vec::with_capacity(p.k);
    let mut nonce = 0u8;
    for _ in 0..p.k {
        s.push(sample_cbd(&prf(p.eta1, &sigma, nonce), p.eta1));
        nonce += 1;
    }
    for _ in 0..p.k {
        e.push(sample_cbd(&prf(p.eta1, &sigma, nonce), p.eta1));
        nonce += 1;
    }
    for poly in &mut s {
        ntt(poly);
    }
    for poly in &mut e {
        ntt(poly);
    }

    // t_hat[i] = sum_j A[i][j] * s_hat[j] + e_hat[i]
    let mut t: Vec<Poly> = Vec::with_capacity(p.k);
    for i in 0..p.k {
        let mut acc = [0u16; N];
        for j in 0..p.k {
            let prod = ntt_mul(&a[i][j], &s[j]);
            acc = poly_add(&acc, &prod);
        }
        t.push(poly_add(&acc, &e[i]));
    }

    let mut ek = Vec::with_capacity(p.ek_len());
    for poly in &t {
        ek.extend_from_slice(&byte_encode(poly, 12));
    }
    ek.extend_from_slice(&rho);

    let mut dk = Vec::with_capacity(p.pke_sk_len());
    for poly in &s {
        dk.extend_from_slice(&byte_encode(poly, 12));
    }

    sigma.zeroize();
    for poly in &mut s {
        poly.zeroize();
    }
    (ek, dk)
}

fn pke_encrypt(p: &Params, ek: &[u8], m: &[u8; 32], r: &[u8; 32]) -> Vec<u8> {
    let split = 384 * p.k;
    let mut t: Vec<Poly> = Vec::with_capacity(p.k);
    for i in 0..p.k {
        t.push(byte_decode(&ek[i * 384..(i + 1) * 384], 12));
    }
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&ek[split..split + 32]);

    let a_t = build_matrix(&rho, p.k, true); // A^T

    let mut y: Vec<Poly> = Vec::with_capacity(p.k);
    let mut e1: Vec<Poly> = Vec::with_capacity(p.k);
    let mut nonce = 0u8;
    for _ in 0..p.k {
        y.push(sample_cbd(&prf(p.eta1, r, nonce), p.eta1));
        nonce += 1;
    }
    for _ in 0..p.k {
        e1.push(sample_cbd(&prf(p.eta2, r, nonce), p.eta2));
        nonce += 1;
    }
    let e2 = sample_cbd(&prf(p.eta2, r, nonce), p.eta2);

    for poly in &mut y {
        ntt(poly);
    }

    // u = NTT_inv(A^T . y_hat) + e1
    let mut u: Vec<Poly> = Vec::with_capacity(p.k);
    for i in 0..p.k {
        let mut acc = [0u16; N];
        for j in 0..p.k {
            acc = poly_add(&acc, &ntt_mul(&a_t[i][j], &y[j]));
        }
        ntt_inv(&mut acc);
        u.push(poly_add(&acc, &e1[i]));
    }

    // v = NTT_inv(t_hat . y_hat) + e2 + Decompress_1(m)
    let mut vacc = [0u16; N];
    for i in 0..p.k {
        vacc = poly_add(&vacc, &ntt_mul(&t[i], &y[i]));
    }
    ntt_inv(&mut vacc);
    let mu = {
        let bits = byte_decode(m, 1);
        core::array::from_fn(|i| decompress(bits[i], 1))
    };
    let v = poly_add(&poly_add(&vacc, &e2), &mu);

    let mut ct = Vec::with_capacity(p.ct_len());
    for poly in &u {
        let compressed: Poly = core::array::from_fn(|i| compress(poly[i], p.du));
        ct.extend_from_slice(&byte_encode(&compressed, p.du));
    }
    let vc: Poly = core::array::from_fn(|i| compress(v[i], p.dv));
    ct.extend_from_slice(&byte_encode(&vc, p.dv));
    ct
}

fn pke_decrypt(p: &Params, dk: &[u8], ct: &[u8]) -> [u8; 32] {
    let c1_len = 32 * p.du as usize * p.k;
    let mut u: Vec<Poly> = Vec::with_capacity(p.k);
    for i in 0..p.k {
        let seg = &ct[i * 32 * p.du as usize..(i + 1) * 32 * p.du as usize];
        let decoded = byte_decode(seg, p.du);
        u.push(core::array::from_fn(|j| decompress(decoded[j], p.du)));
    }
    let vseg = &ct[c1_len..c1_len + 32 * p.dv as usize];
    let vd = byte_decode(vseg, p.dv);
    let v: Poly = core::array::from_fn(|i| decompress(vd[i], p.dv));

    let mut s: Vec<Poly> = Vec::with_capacity(p.k);
    for i in 0..p.k {
        s.push(byte_decode(&dk[i * 384..(i + 1) * 384], 12));
    }

    // w = v - NTT_inv(s_hat . NTT(u))
    let mut acc = [0u16; N];
    for i in 0..p.k {
        let mut uh = u[i];
        ntt(&mut uh);
        acc = poly_add(&acc, &ntt_mul(&s[i], &uh));
    }
    ntt_inv(&mut acc);
    let w = poly_sub(&v, &acc);

    let bits: Poly = core::array::from_fn(|i| compress(w[i], 1));
    let mut out = [0u8; 32];
    out.copy_from_slice(&byte_encode(&bits, 1));
    for poly in &mut s {
        poly.zeroize();
    }
    out
}

// --- ML-KEM ------------------------------------------------------------------

/// ML-KEM key generation from explicit randomness `d`, `z` (FIPS 203 Algorithm
/// 16, `KeyGen_internal`). Prefer [`keygen`] with an OS RNG.
#[must_use]
pub fn keygen_derand(p: &Params, d: &[u8; 32], z: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let (ek, dk_pke) = pke_keygen(p, d);
    let mut dk = Vec::with_capacity(p.dk_len());
    dk.extend_from_slice(&dk_pke);
    dk.extend_from_slice(&ek);
    dk.extend_from_slice(&sha3_256(&ek));
    dk.extend_from_slice(z);
    (ek, dk)
}

/// ML-KEM key generation using a caller-provided RNG.
pub fn keygen(p: &Params, rng: impl FnMut(&mut [u8])) -> (Vec<u8>, Vec<u8>) {
    let mut rng = rng;
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    rng(&mut d);
    rng(&mut z);
    let out = keygen_derand(p, &d, &z);
    d.zeroize();
    z.zeroize();
    out
}

/// Encapsulate to `ek` with explicit message randomness `m` (FIPS 203 Algorithm
/// 17, `Encaps_internal`).
pub fn encaps_derand(p: &Params, ek: &[u8], m: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>)> {
    if ek.len() != p.ek_len() {
        return Err(Error::InvalidLength {
            what: "ml-kem ek",
            expected: p.ek_len(),
            got: ek.len(),
        });
    }
    // Modulus check (FIPS 203 §7.2): every 12-bit coeff must be < q.
    for i in 0..p.k {
        let re = byte_encode(&byte_decode(&ek[i * 384..(i + 1) * 384], 12), 12);
        if re != ek[i * 384..(i + 1) * 384] {
            return Err(Error::OutOfRange {
                what: "ml-kem ek coefficient",
            });
        }
    }

    let mut g_in = Vec::with_capacity(64);
    g_in.extend_from_slice(m);
    g_in.extend_from_slice(&sha3_256(ek));
    let g = sha3_512(&g_in);
    let mut k_bytes = [0u8; 32];
    let mut r = [0u8; 32];
    k_bytes.copy_from_slice(&g[..32]);
    r.copy_from_slice(&g[32..]);

    let ct = pke_encrypt(p, ek, m, &r);
    r.zeroize();
    Ok((k_bytes.to_vec(), ct))
}

/// Encapsulate using a caller-provided RNG; returns `(shared_secret, ciphertext)`.
pub fn encaps(p: &Params, ek: &[u8], rng: impl FnMut(&mut [u8])) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = rng;
    let mut m = [0u8; 32];
    rng(&mut m);
    let out = encaps_derand(p, ek, &m);
    m.zeroize();
    out
}

/// Decapsulate (`Decaps_internal`, FIPS 203 Algorithm 18) with implicit
/// rejection: an invalid ciphertext yields a pseudo-random shared secret rather
/// than an error, so this never reveals decryption failure.
pub fn decaps(p: &Params, dk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    if dk.len() != p.dk_len() {
        return Err(Error::InvalidLength {
            what: "ml-kem dk",
            expected: p.dk_len(),
            got: dk.len(),
        });
    }
    if ct.len() != p.ct_len() {
        return Err(Error::InvalidLength {
            what: "ml-kem ciphertext",
            expected: p.ct_len(),
            got: ct.len(),
        });
    }

    let sk = 384 * p.k;
    let dk_pke = &dk[..sk];
    let ek_pke = &dk[sk..sk + p.ek_len()];
    let h = &dk[sk + p.ek_len()..sk + p.ek_len() + 32];
    let z = &dk[sk + p.ek_len() + 32..];

    let mut m_prime = pke_decrypt(p, dk_pke, ct);

    let mut g_in = Vec::with_capacity(64);
    g_in.extend_from_slice(&m_prime);
    g_in.extend_from_slice(h);
    let g = sha3_512(&g_in);
    let mut k_prime = [0u8; 32];
    let mut r_prime = [0u8; 32];
    k_prime.copy_from_slice(&g[..32]);
    r_prime.copy_from_slice(&g[32..]);

    // K_bar = J(z || c)
    let mut j = Shake256::new();
    j.absorb(z);
    j.absorb(ct);
    let mut k_bar = [0u8; 32];
    j.squeeze(&mut k_bar);

    let c_prime = pke_encrypt(p, ek_pke, &m_prime, &r_prime);
    let matches = ct_eq(ct, &c_prime);

    // Constant-time select: k_prime if ct == c', else k_bar.
    let mut out = k_prime;
    crate::ct::conditional_copy(&mut out, &k_bar, matches.negate());

    m_prime.zeroize();
    r_prime.zeroize();
    k_prime.zeroize();
    k_bar.zeroize();
    Ok(out.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::hex::encode;
    use crate::hash::sha256::hash as sha256;

    fn kat_inputs() -> ([u8; 32], [u8; 32], [u8; 32]) {
        let d: [u8; 32] = core::array::from_fn(|i| i as u8);
        let z: [u8; 32] = core::array::from_fn(|i| 0xff - i as u8);
        let m: [u8; 32] = core::array::from_fn(|i| (i % 7) as u8);
        (d, z, m)
    }

    // KATs cross-checked against the `kyber-py` reference implementation.
    #[test]
    fn mlkem512_kat() {
        let (d, z, m) = kat_inputs();
        let (ek, dk) = keygen_derand(&MlKem512, &d, &z);
        assert_eq!(ek.len(), 800);
        assert_eq!(dk.len(), 1632);
        assert_eq!(
            encode(&sha256(&ek)),
            "3ae268dccc5456ac0d0f9b39257dc48fe081383b97c400512d712b739762daee"
        );
        assert_eq!(
            encode(&sha256(&dk)),
            "07734f212fe7e6c6dc89036cd3411165a31d07458e34b2b4cd182870845071a2"
        );

        let (k_enc, ct) = encaps_derand(&MlKem512, &ek, &m).unwrap();
        assert_eq!(ct.len(), 768);
        assert_eq!(
            encode(&sha256(&ct)),
            "df6dbc97de985ce4936977f425f2bc488d143639f79e7c515ecc79a8cc3f1e22"
        );
        assert_eq!(
            encode(&k_enc),
            "df49f5bcc6c31b9fca80d9dcc3dec54f30e20dc8a48969b024e62a95fd26349a"
        );

        let k_dec = decaps(&MlKem512, &dk, &ct).unwrap();
        assert_eq!(k_dec, k_enc);
    }

    #[test]
    fn mlkem768_kat() {
        let (d, z, m) = kat_inputs();
        let (ek, dk) = keygen_derand(&MlKem768, &d, &z);
        assert_eq!(ek.len(), 1184);
        assert_eq!(dk.len(), 2400);
        assert_eq!(
            encode(&sha256(&ek)),
            "0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9"
        );
        let (k_enc, ct) = encaps_derand(&MlKem768, &ek, &m).unwrap();
        assert_eq!(ct.len(), 1088);
        assert_eq!(
            encode(&sha256(&ct)),
            "44dd72979fd00fb0e4c2f520eb725068c775d595417ca1e4dc96b38fbbd81b63"
        );
        assert_eq!(
            encode(&k_enc),
            "cd80129e0a5ae02c71795ee665f870b4f0f9c99420cd0a5b636c8455332d2e94"
        );
        assert_eq!(decaps(&MlKem768, &dk, &ct).unwrap(), k_enc);
    }

    #[test]
    fn implicit_rejection_on_tampered_ct() {
        let (d, z, m) = kat_inputs();
        let (ek, dk) = keygen_derand(&MlKem768, &d, &z);
        let (k_enc, mut ct) = encaps_derand(&MlKem768, &ek, &m).unwrap();
        ct[5] ^= 0x01;
        let k_bad = decaps(&MlKem768, &dk, &ct).unwrap();
        // No error, but a different (pseudo-random) shared secret.
        assert_ne!(k_bad, k_enc);
        assert_eq!(k_bad.len(), 32);
    }

    #[test]
    fn random_roundtrip_all_params() {
        let mut seed = 0x1234_5678u64;
        let mut rng = |b: &mut [u8]| {
            for x in b.iter_mut() {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                *x = (seed >> 33) as u8;
            }
        };
        for p in [&MlKem512, &MlKem768, &MlKem1024] {
            let (ek, dk) = keygen(p, &mut rng);
            let (k1, ct) = encaps(p, &ek, &mut rng).unwrap();
            let k2 = decaps(p, &dk, &ct).unwrap();
            assert_eq!(k1, k2, "{}", p.name);
        }
    }
}
