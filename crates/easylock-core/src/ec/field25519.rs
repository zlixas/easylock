//! GF(2^255 - 19) arithmetic in the TweetNaCl `gf` representation: 16 limbs of
//! ~16 bits each held in `i64`. Algorithms and magic constants are from
//! TweetNaCl (public domain). Inputs are taken by value (`Gf` is `Copy`, 128
//! bytes) so aliasing is a non-issue and call sites read like the C.

/// A field element: 16 little-endian ~16-bit limbs.
pub type Gf = [i64; 16];

pub const GF0: Gf = [0; 16];
pub const GF1: Gf = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

/// `121665`, used by the X25519 ladder.
pub const D121665: Gf = [0xdb41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

/// Edwards curve constant `d`.
pub const D: Gf = [
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7,
    0xfe73, 0x2b6f, 0x6cee, 0x5203,
];

/// `2 * d`.
pub const D2: Gf = [
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e,
    0xfce7, 0x56df, 0xd9dc, 0x2406,
];

/// Base point `x`.
pub const X: Gf = [
    0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4,
    0x53fe, 0xcd6e, 0x36d3, 0x2169,
];

/// Base point `y` (= 4/5).
pub const Y: Gf = [
    0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666,
];

/// `sqrt(-1) mod p`.
pub const SQRTM1: Gf = [
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d,
    0xdf0b, 0x4fc1, 0x2480, 0x2b83,
];

/// Group order `L`, little-endian bytes.
pub const L: [i64; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// Carry-propagate limbs back to ~16 bits (with the `2^255 = 19` wrap).
pub fn car25519(o: &mut Gf) {
    for i in 0..16 {
        o[i] += 1i64 << 16;
        let c = o[i] >> 16;
        if i < 15 {
            o[i + 1] += c - 1;
        } else {
            o[0] += 38 * (c - 1);
        }
        o[i] -= c << 16;
    }
}

/// Constant-time conditional swap of `p` and `q` when `b == 1`.
pub fn sel25519(p: &mut Gf, q: &mut Gf, b: i64) {
    let c = !(b - 1);
    for i in 0..16 {
        let t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

#[must_use]
pub fn fadd(a: Gf, b: Gf) -> Gf {
    core::array::from_fn(|i| a[i] + b[i])
}

#[must_use]
pub fn fsub(a: Gf, b: Gf) -> Gf {
    core::array::from_fn(|i| a[i] - b[i])
}

#[must_use]
pub fn fmul(a: Gf, b: Gf) -> Gf {
    let mut t = [0i64; 31];
    for i in 0..16 {
        for j in 0..16 {
            t[i + j] += a[i] * b[j];
        }
    }
    for i in 0..15 {
        t[i] += 38 * t[i + 16];
    }
    let mut o: Gf = GF0;
    o.copy_from_slice(&t[..16]);
    car25519(&mut o);
    car25519(&mut o);
    o
}

#[must_use]
pub fn fsq(a: Gf) -> Gf {
    fmul(a, a)
}

/// Multiplicative inverse via `x^(p-2)`.
#[must_use]
pub fn inv25519(i: Gf) -> Gf {
    let mut c = i;
    let mut a = 253i32;
    while a >= 0 {
        c = fsq(c);
        if a != 2 && a != 4 {
            c = fmul(c, i);
        }
        a -= 1;
    }
    c
}

/// `x^((p-5)/8)`, used for the Ed25519 square root.
#[must_use]
pub fn pow2523(i: Gf) -> Gf {
    let mut c = i;
    let mut a = 250i32;
    while a >= 0 {
        c = fsq(c);
        if a != 1 {
            c = fmul(c, i);
        }
        a -= 1;
    }
    c
}

/// Serialize a field element to 32 little-endian bytes (fully reduced).
pub fn pack25519(o: &mut [u8; 32], n: Gf) {
    let mut t: Gf = n;
    car25519(&mut t);
    car25519(&mut t);
    car25519(&mut t);
    for _ in 0..2 {
        let mut m: Gf = GF0;
        m[0] = t[0] - 0xffed;
        for i in 1..15 {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        let b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(&mut t, &mut m, 1 - b);
    }
    for i in 0..16 {
        o[2 * i] = (t[i] & 0xff) as u8;
        o[2 * i + 1] = (t[i] >> 8) as u8;
    }
}

/// Serialize to a fresh array.
#[must_use]
pub fn to_bytes(n: Gf) -> [u8; 32] {
    let mut o = [0u8; 32];
    pack25519(&mut o, n);
    o
}

/// Constant-time equality.
#[must_use]
pub fn eq25519(a: Gf, b: Gf) -> bool {
    bool::from(crate::ct::ct_eq_fixed(&to_bytes(a), &to_bytes(b)))
}

/// Low bit of the reduced representation.
#[must_use]
pub fn par25519(a: Gf) -> u8 {
    to_bytes(a)[0] & 1
}

/// Parse 32 little-endian bytes into a field element (clears the top bit).
#[must_use]
pub fn unpack25519(n: &[u8; 32]) -> Gf {
    let mut o: Gf = GF0;
    for i in 0..16 {
        o[i] = i64::from(n[2 * i]) + (i64::from(n[2 * i + 1]) << 8);
    }
    o[15] &= 0x7fff;
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inverse_roundtrip() {
        let mut x: Gf = GF0;
        x[0] = 12345;
        x[1] = 678;
        let one = fmul(x, inv25519(x));
        assert!(eq25519(one, GF1));
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
        let a: Gf = core::array::from_fn(|i| (i as i64) * 313 + 7);
        let b: Gf = core::array::from_fn(|i| (i as i64) * 91 + 1);
        assert!(eq25519(fsub(fadd(a, b), b), a));
    }
}
