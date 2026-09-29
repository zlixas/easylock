//! GF(2^255 - 19) arithmetic in radix 2^51: five `u64` limbs, products in
//! `u128`. This is the representation used by `curve25519-donna-64`, ref10's
//! 64-bit backend and `curve25519-dalek`'s `u64` backend.
//!
//! Limb bounds: `fmul`/`fsq` accept limbs below 2^54 and return limbs below
//! 2^51 + 2^13 ("weakly reduced"). `fadd` does not carry, so the sum of two
//! weakly reduced values (or of a sum and a weakly reduced value) is still a
//! valid multiplication input. `fsub` adds 16p before subtracting and carries,
//! so its subtrahend may have limbs up to 2^55. `to_bytes` fully reduces.
//!
//! Every operation here is straight-line code: no branches or indices depend on
//! the values, so the arithmetic is constant-time.

const MASK51: u64 = (1 << 51) - 1;

/// A field element: five little-endian 51-bit limbs (possibly unreduced).
#[derive(Clone, Copy, Debug)]
pub struct Gf(pub [u64; 5]);

pub const GF0: Gf = Gf([0; 5]);
pub const GF1: Gf = Gf([1, 0, 0, 0, 0]);

/// Edwards curve constant `d = -121665/121666`.
pub const D: Gf = from_tweetnacl([
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7,
    0xfe73, 0x2b6f, 0x6cee, 0x5203,
]);

/// `2 * d`.
pub const D2: Gf = from_tweetnacl([
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e,
    0xfce7, 0x56df, 0xd9dc, 0x2406,
]);

/// Base point `x`.
pub const X: Gf = from_tweetnacl([
    0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4,
    0x53fe, 0xcd6e, 0x36d3, 0x2169,
]);

/// Base point `y` (= 4/5).
pub const Y: Gf = from_tweetnacl([
    0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666,
]);

/// `sqrt(-1) mod p`.
pub const SQRTM1: Gf = from_tweetnacl([
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d,
    0xdf0b, 0x4fc1, 0x2480, 0x2b83,
]);

/// Group order `L`, little-endian bytes.
pub const L: [i64; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// Convert a constant written as TweetNaCl's sixteen 16-bit limbs.
const fn from_tweetnacl(t: [u16; 16]) -> Gf {
    let mut b = [0u8; 32];
    let mut i = 0;
    while i < 16 {
        b[2 * i] = t[i] as u8;
        b[2 * i + 1] = (t[i] >> 8) as u8;
        i += 1;
    }
    unpack25519(&b)
}

#[inline(always)]
const fn load8(b: &[u8; 32], at: usize) -> u64 {
    let mut v = 0u64;
    let mut i = 0;
    while i < 8 {
        v |= (b[at + i] as u64) << (8 * i);
        i += 1;
    }
    v
}

/// Parse 32 little-endian bytes into a field element (ignores the top bit).
#[must_use]
pub const fn unpack25519(n: &[u8; 32]) -> Gf {
    Gf([
        load8(n, 0) & MASK51,
        (load8(n, 6) >> 3) & MASK51,
        (load8(n, 12) >> 6) & MASK51,
        (load8(n, 19) >> 1) & MASK51,
        (load8(n, 24) >> 12) & MASK51,
    ])
}

/// Carry every limb into the next, folding the top carry back as `* 19`.
#[inline(always)]
fn weak_reduce(mut l: [u64; 5]) -> Gf {
    let c0 = l[0] >> 51;
    let c1 = l[1] >> 51;
    let c2 = l[2] >> 51;
    let c3 = l[3] >> 51;
    let c4 = l[4] >> 51;
    l[0] &= MASK51;
    l[1] &= MASK51;
    l[2] &= MASK51;
    l[3] &= MASK51;
    l[4] &= MASK51;
    l[0] += c4 * 19;
    l[1] += c0;
    l[2] += c1;
    l[3] += c2;
    l[4] += c3;
    Gf(l)
}

/// Constant-time conditional swap of `p` and `q` when `b == 1`.
#[inline(always)]
pub fn sel25519(p: &mut Gf, q: &mut Gf, b: i64) {
    let mask = core::hint::black_box((b as u64).wrapping_neg());
    for i in 0..5 {
        let t = mask & (p.0[i] ^ q.0[i]);
        p.0[i] ^= t;
        q.0[i] ^= t;
    }
}

/// Constant-time conditional move: `*p = q` when `b == 1`.
#[inline(always)]
pub fn cmov(p: &mut Gf, q: &Gf, b: u64) {
    let mask = b.wrapping_neg();
    for i in 0..5 {
        p.0[i] ^= mask & (p.0[i] ^ q.0[i]);
    }
}

#[inline(always)]
#[must_use]
pub fn fadd(a: Gf, b: Gf) -> Gf {
    Gf([
        a.0[0] + b.0[0],
        a.0[1] + b.0[1],
        a.0[2] + b.0[2],
        a.0[3] + b.0[3],
        a.0[4] + b.0[4],
    ])
}

#[inline(always)]
#[must_use]
pub fn fsub(a: Gf, b: Gf) -> Gf {
    // 16p in radix 2^51, large enough that no limb underflows.
    const P16_0: u64 = 36_028_797_018_963_664; // 16 * (2^51 - 19)
    const P16_N: u64 = 36_028_797_018_963_952; // 16 * (2^51 - 1)
    weak_reduce([
        (a.0[0] + P16_0) - b.0[0],
        (a.0[1] + P16_N) - b.0[1],
        (a.0[2] + P16_N) - b.0[2],
        (a.0[3] + P16_N) - b.0[3],
        (a.0[4] + P16_N) - b.0[4],
    ])
}

/// `-a`.
#[inline(always)]
#[must_use]
pub fn fneg(a: Gf) -> Gf {
    fsub(GF0, a)
}

#[inline(always)]
fn m(x: u64, y: u64) -> u128 {
    u128::from(x) * u128::from(y)
}

/// Carry a 5-limb `u128` product accumulator back into 51-bit limbs.
#[inline(always)]
fn carry_wide(c: [u128; 5]) -> Gf {
    let mut c = c;
    c[1] += c[0] >> 51;
    let mut o0 = (c[0] as u64) & MASK51;
    c[2] += c[1] >> 51;
    let o1 = (c[1] as u64) & MASK51;
    c[3] += c[2] >> 51;
    let o2 = (c[2] as u64) & MASK51;
    c[4] += c[3] >> 51;
    let o3 = (c[3] as u64) & MASK51;
    let carry = (c[4] >> 51) as u64;
    let o4 = (c[4] as u64) & MASK51;
    // carry < 2^64 / 19 for in-bound inputs, so `* 19` cannot overflow.
    o0 += carry * 19;
    let o1 = o1 + (o0 >> 51);
    o0 &= MASK51;
    Gf([o0, o1, o2, o3, o4])
}

#[inline(always)]
#[must_use]
pub fn fmul(a: Gf, b: Gf) -> Gf {
    let [a0, a1, a2, a3, a4] = a.0;
    let [b0, b1, b2, b3, b4] = b.0;
    debug_assert!(a.0.iter().chain(&b.0).all(|&l| l < 1 << 54));
    let (b1_19, b2_19, b3_19, b4_19) = (b1 * 19, b2 * 19, b3 * 19, b4 * 19);
    carry_wide([
        m(a0, b0) + m(a4, b1_19) + m(a3, b2_19) + m(a2, b3_19) + m(a1, b4_19),
        m(a1, b0) + m(a0, b1) + m(a4, b2_19) + m(a3, b3_19) + m(a2, b4_19),
        m(a2, b0) + m(a1, b1) + m(a0, b2) + m(a4, b3_19) + m(a3, b4_19),
        m(a3, b0) + m(a2, b1) + m(a1, b2) + m(a0, b3) + m(a4, b4_19),
        m(a4, b0) + m(a3, b1) + m(a2, b2) + m(a1, b3) + m(a0, b4),
    ])
}

#[inline(always)]
#[must_use]
pub fn fsq(a: Gf) -> Gf {
    let [a0, a1, a2, a3, a4] = a.0;
    debug_assert!(a.0.iter().all(|&l| l < 1 << 54));
    let (a0_2, a1_2, a2_2) = (a0 * 2, a1 * 2, a2 * 2);
    let (a3_19, a4_19) = (a3 * 19, a4 * 19);
    carry_wide([
        m(a0, a0) + m(a1_2, a4_19) + m(a2_2, a3_19),
        m(a0_2, a1) + m(a2_2, a4_19) + m(a3, a3_19),
        m(a0_2, a2) + m(a1, a1) + m(a3 * 2, a4_19),
        m(a0_2, a3) + m(a1_2, a2) + m(a4, a4_19),
        m(a0_2, a4) + m(a1_2, a3) + m(a2, a2),
    ])
}

/// `a` squared `n` times.
#[inline]
#[must_use]
pub fn fsq_n(mut a: Gf, n: u32) -> Gf {
    for _ in 0..n {
        a = fsq(a);
    }
    a
}

/// `a * 121666` (the X25519 ladder constant `(A + 2) / 4`).
#[inline(always)]
#[must_use]
pub fn fmul121666(a: Gf) -> Gf {
    const K: u64 = 121_666;
    carry_wide([
        m(a.0[0], K),
        m(a.0[1], K),
        m(a.0[2], K),
        m(a.0[3], K),
        m(a.0[4], K),
    ])
}

/// Returns `(z^(2^250 - 1), z^11)`, the shared prefix of the inversion and
/// square-root addition chains.
fn pow22501(z: Gf) -> (Gf, Gf) {
    let t0 = fsq(z); // 2
    let t1 = fmul(fsq_n(t0, 2), z); // 9
    let t0 = fmul(t0, t1); // 11
    let t2 = fmul(fsq(t0), t1); // 2^5 - 1
    let t3 = fmul(fsq_n(t2, 5), t2); // 2^10 - 1
    let t4 = fmul(fsq_n(t3, 10), t3); // 2^20 - 1
    let t5 = fmul(fsq_n(t4, 20), t4); // 2^40 - 1
    let t6 = fmul(fsq_n(t5, 10), t3); // 2^50 - 1
    let t7 = fmul(fsq_n(t6, 50), t6); // 2^100 - 1
    let t8 = fmul(fsq_n(t7, 100), t7); // 2^200 - 1
    let t9 = fmul(fsq_n(t8, 50), t6); // 2^250 - 1
    (t9, t0)
}

/// Multiplicative inverse `z^(p-2)` (254 squarings, 11 multiplications).
#[must_use]
pub fn inv25519(z: Gf) -> Gf {
    let (t, z11) = pow22501(z);
    fmul(fsq_n(t, 5), z11) // 2^255 - 21
}

/// `z^((p-5)/8)`, used for the Ed25519 square root.
#[must_use]
pub fn pow2523(z: Gf) -> Gf {
    let (t, _) = pow22501(z);
    fmul(fsq_n(t, 2), z) // 2^252 - 3
}

/// Serialize a field element to 32 little-endian bytes (fully reduced).
#[must_use]
pub fn to_bytes(n: Gf) -> [u8; 32] {
    let mut l = weak_reduce(n.0).0;
    // q = 1 iff the value is >= p; adding 19q and dropping bit 255 subtracts p.
    let mut q = (l[0] + 19) >> 51;
    q = (l[1] + q) >> 51;
    q = (l[2] + q) >> 51;
    q = (l[3] + q) >> 51;
    q = (l[4] + q) >> 51;
    l[0] += 19 * q;
    l[1] += l[0] >> 51;
    l[0] &= MASK51;
    l[2] += l[1] >> 51;
    l[1] &= MASK51;
    l[3] += l[2] >> 51;
    l[2] &= MASK51;
    l[4] += l[3] >> 51;
    l[3] &= MASK51;
    l[4] &= MASK51;

    let words = [
        l[0] | (l[1] << 51),
        (l[1] >> 13) | (l[2] << 38),
        (l[2] >> 26) | (l[3] << 25),
        (l[3] >> 39) | (l[4] << 12),
    ];
    let mut o = [0u8; 32];
    for (chunk, w) in o.chunks_exact_mut(8).zip(words) {
        chunk.copy_from_slice(&w.to_le_bytes());
    }
    o
}

/// Serialize into `o` (TweetNaCl-style signature).
pub fn pack25519(o: &mut [u8; 32], n: Gf) {
    *o = to_bytes(n);
}

/// Constant-time equality.
#[must_use]
pub fn eq25519(a: Gf, b: Gf) -> bool {
    bool::from(crate::ct::ct_eq_fixed(&to_bytes(a), &to_bytes(b)))
}

/// Constant-time "is zero" (after full reduction).
#[must_use]
pub fn is_zero(a: Gf) -> bool {
    bool::from(crate::ct::ct_eq_fixed(&to_bytes(a), &[0u8; 32]))
}

/// Low bit of the reduced representation.
#[must_use]
pub fn par25519(a: Gf) -> u8 {
    to_bytes(a)[0] & 1
}

impl crate::secure::Zeroize for Gf {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fe(seed: u8) -> Gf {
        let b: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(seed).wrapping_add(seed));
        unpack25519(&b)
    }

    #[test]
    fn inverse_roundtrip() {
        for s in 1..20u8 {
            let x = fe(s);
            assert!(eq25519(fmul(x, inv25519(x)), GF1));
        }
    }

    #[test]
    fn pack_unpack_roundtrip() {
        let bytes: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(11) | 1);
        let f = unpack25519(&bytes);
        let mut expect = bytes;
        expect[31] &= 0x7f;
        assert_eq!(to_bytes(f), expect);
    }

    #[test]
    fn add_sub_roundtrip() {
        let (a, b) = (fe(3), fe(91));
        assert!(eq25519(fsub(fadd(a, b), b), a));
        assert!(eq25519(fadd(fneg(a), a), GF0));
    }

    #[test]
    fn square_matches_mul() {
        for s in 1..40u8 {
            let a = fe(s);
            assert_eq!(to_bytes(fsq(a)), to_bytes(fmul(a, a)));
            let big = fadd(fadd(a, a), a); // limbs near 2^53
            assert_eq!(to_bytes(fsq(big)), to_bytes(fmul(big, big)));
        }
    }

    #[test]
    fn reduces_values_at_and_above_p() {
        // p itself, p + 1 and 2^255 - 1 (= p + 18) must reduce to 0, 1, 18.
        let p = Gf([MASK51 - 18, MASK51, MASK51, MASK51, MASK51]);
        assert_eq!(to_bytes(p), [0u8; 32]);
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(to_bytes(fadd(p, GF1)), one);
        let top = Gf([MASK51; 5]);
        let mut eighteen = [0u8; 32];
        eighteen[0] = 18;
        assert_eq!(to_bytes(top), eighteen);
    }

    #[test]
    fn sqrt_minus_one_squares_to_minus_one() {
        assert!(eq25519(fsq(SQRTM1), fneg(GF1)));
    }

    #[test]
    fn mul121666_matches_generic() {
        let a = fe(77);
        let k = Gf([121_666, 0, 0, 0, 0]);
        assert_eq!(to_bytes(fmul121666(a)), to_bytes(fmul(a, k)));
    }

    #[test]
    fn d2_is_twice_d() {
        assert!(eq25519(fadd(D, D), D2));
    }
}
