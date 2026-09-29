//! Edwards25519 group arithmetic in the ref10 layout (Bernstein, Duif, Lange,
//! Schwabe, Yang — "High-speed high-security signatures").
//!
//! Point forms:
//! - [`P3`] extended `(X:Y:Z:T)`, `x = X/Z`, `y = Y/Z`, `xy = T/Z`;
//! - [`P2`] projective `(X:Y:Z)`, enough for doubling;
//! - [`P1p1`] "completed" `((X:Z),(Y:T))`, the output of add/double;
//! - [`Cached`] `(Y+X, Y-X, Z, 2dT)` for repeated additions of a variable point;
//! - [`Precomp`] affine `(y+x, y-x, 2dxy)` for table points (Z = 1).
//!
//! Fixed-base multiplication ([`base_mul`]) is constant-time: signed radix-16
//! digits, a full scan of each 8-entry table row, and a conditional negation.
//! [`double_scalarmult_vartime`] is variable-time and only used on public data
//! (signature verification).

use super::base_table::{BASE, BASE_ODD};
use super::field25519::{
    cmov, eq25519, fadd, fmul, fneg, fsq, fsub, inv25519, is_zero, par25519, pow2523, to_bytes,
    unpack25519, Gf, D, D2, GF0, GF1, SQRTM1,
};
use crate::secure::Zeroize;

/// Extended coordinates.
#[derive(Clone, Copy, Debug)]
pub struct P3 {
    x: Gf,
    y: Gf,
    z: Gf,
    t: Gf,
}

/// Projective coordinates.
#[derive(Clone, Copy, Debug)]
pub struct P2 {
    x: Gf,
    y: Gf,
    z: Gf,
}

/// Completed coordinates.
#[derive(Clone, Copy, Debug)]
pub struct P1p1 {
    x: Gf,
    y: Gf,
    z: Gf,
    t: Gf,
}

/// Projective Niels form of a variable point.
#[derive(Clone, Copy, Debug)]
pub struct Cached {
    ypx: Gf,
    ymx: Gf,
    z: Gf,
    t2d: Gf,
}

/// Affine Niels form of a precomputed point.
#[derive(Clone, Copy, Debug)]
pub struct Precomp {
    ypx: Gf,
    ymx: Gf,
    xy2d: Gf,
}

impl Precomp {
    pub const IDENTITY: Self = Self {
        ypx: GF1,
        ymx: GF1,
        xy2d: GF0,
    };

    /// Build from raw limbs (used by the generated table).
    pub(super) const fn from_limbs(ypx: [u64; 5], ymx: [u64; 5], xy2d: [u64; 5]) -> Self {
        Self {
            ypx: Gf(ypx),
            ymx: Gf(ymx),
            xy2d: Gf(xy2d),
        }
    }

    fn cmov(&mut self, other: &Self, b: u64) {
        cmov(&mut self.ypx, &other.ypx, b);
        cmov(&mut self.ymx, &other.ymx, b);
        cmov(&mut self.xy2d, &other.xy2d, b);
    }

    fn neg(&self) -> Self {
        Self {
            ypx: self.ymx,
            ymx: self.ypx,
            xy2d: fneg(self.xy2d),
        }
    }
}

impl P3 {
    pub const IDENTITY: Self = Self {
        x: GF0,
        y: GF1,
        z: GF1,
        t: GF0,
    };

    /// The standard base point `B`.
    #[must_use]
    pub fn base() -> Self {
        use super::field25519::{X, Y};
        Self {
            x: X,
            y: Y,
            z: GF1,
            t: fmul(X, Y),
        }
    }

    fn to_p2(self) -> P2 {
        P2 {
            x: self.x,
            y: self.y,
            z: self.z,
        }
    }

    fn to_cached(self) -> Cached {
        Cached {
            ypx: fadd(self.y, self.x),
            ymx: fsub(self.y, self.x),
            z: self.z,
            t2d: fmul(self.t, D2),
        }
    }

    fn dbl(self) -> P1p1 {
        self.to_p2().dbl()
    }

    /// Encode as 32 bytes (`y` with the sign of `x` in the top bit).
    #[must_use]
    pub fn compress(&self) -> [u8; 32] {
        self.to_p2().compress()
    }

    /// Decode an encoded point and return its **negation** (what verification
    /// needs). `None` if the encoding is not on the curve.
    #[must_use]
    pub fn decompress_neg(s: &[u8; 32]) -> Option<Self> {
        let y = unpack25519(s);
        let y2 = fsq(y);
        let u = fsub(y2, GF1); // y^2 - 1
        let v = fadd(fmul(y2, D), GF1); // d y^2 + 1

        // x = u v^3 (u v^7)^((p-5)/8)
        let v3 = fmul(fsq(v), v);
        let mut x = fmul(fmul(pow2523(fmul(fmul(fsq(v3), v), u)), v3), u);

        let vxx = fmul(fsq(x), v);
        if !eq25519(vxx, u) {
            if !eq25519(vxx, fneg(u)) {
                return None;
            }
            x = fmul(x, SQRTM1);
        }
        if par25519(x) == (s[31] >> 7) {
            x = fneg(x);
        }
        Some(Self {
            x,
            y,
            z: GF1,
            t: fmul(x, y),
        })
    }

    /// `true` if `[8]P` is the identity (P has order 1, 2, 4 or 8). Variable-time.
    #[must_use]
    pub fn is_small_order(&self) -> bool {
        let q = self.dbl().to_p2().dbl().to_p2().dbl().to_p2();
        is_zero(q.x) && eq25519(q.y, q.z)
    }

    /// `(Z + Y) / (Z - Y)`: the Montgomery `u`-coordinate of this point.
    #[must_use]
    pub fn to_montgomery_u(&self) -> [u8; 32] {
        to_bytes(fmul(fadd(self.z, self.y), inv25519(fsub(self.z, self.y))))
    }
}

impl P2 {
    const IDENTITY: Self = Self {
        x: GF0,
        y: GF1,
        z: GF1,
    };

    fn dbl(self) -> P1p1 {
        let xx = fsq(self.x);
        let yy = fsq(self.y);
        let zz2 = {
            let zz = fsq(self.z);
            fadd(zz, zz)
        };
        let aa = fsq(fadd(self.x, self.y));
        let y = fadd(yy, xx);
        let z = fsub(yy, xx);
        P1p1 {
            x: fsub(aa, y),
            y,
            z,
            t: fsub(zz2, z),
        }
    }

    /// Encode as 32 bytes (`y` with the sign of `x` in the top bit).
    #[must_use]
    pub fn compress(&self) -> [u8; 32] {
        let zi = inv25519(self.z);
        let mut r = to_bytes(fmul(self.y, zi));
        r[31] ^= par25519(fmul(self.x, zi)) << 7;
        r
    }
}

impl P1p1 {
    fn to_p2(self) -> P2 {
        P2 {
            x: fmul(self.x, self.t),
            y: fmul(self.y, self.z),
            z: fmul(self.z, self.t),
        }
    }

    fn to_p3(self) -> P3 {
        P3 {
            x: fmul(self.x, self.t),
            y: fmul(self.y, self.z),
            z: fmul(self.z, self.t),
            t: fmul(self.x, self.y),
        }
    }
}

fn add(p: &P3, q: &Cached) -> P1p1 {
    let a = fmul(fadd(p.y, p.x), q.ypx);
    let b = fmul(fsub(p.y, p.x), q.ymx);
    let c = fmul(q.t2d, p.t);
    let zz = fmul(p.z, q.z);
    let d = fadd(zz, zz);
    P1p1 {
        x: fsub(a, b),
        y: fadd(a, b),
        z: fadd(d, c),
        t: fsub(d, c),
    }
}

fn sub(p: &P3, q: &Cached) -> P1p1 {
    let a = fmul(fadd(p.y, p.x), q.ymx);
    let b = fmul(fsub(p.y, p.x), q.ypx);
    let c = fmul(q.t2d, p.t);
    let zz = fmul(p.z, q.z);
    let d = fadd(zz, zz);
    P1p1 {
        x: fsub(a, b),
        y: fadd(a, b),
        z: fsub(d, c),
        t: fadd(d, c),
    }
}

fn madd(p: &P3, q: &Precomp) -> P1p1 {
    let a = fmul(fadd(p.y, p.x), q.ypx);
    let b = fmul(fsub(p.y, p.x), q.ymx);
    let c = fmul(q.xy2d, p.t);
    let d = fadd(p.z, p.z);
    P1p1 {
        x: fsub(a, b),
        y: fadd(a, b),
        z: fadd(d, c),
        t: fsub(d, c),
    }
}

fn msub(p: &P3, q: &Precomp) -> P1p1 {
    let a = fmul(fadd(p.y, p.x), q.ymx);
    let b = fmul(fsub(p.y, p.x), q.ypx);
    let c = fmul(q.xy2d, p.t);
    let d = fadd(p.z, p.z);
    P1p1 {
        x: fsub(a, b),
        y: fadd(a, b),
        z: fsub(d, c),
        t: fadd(d, c),
    }
}

/// `P + Q` for two extended points.
#[must_use]
pub fn add_p3(p: &P3, q: &P3) -> P3 {
    add(p, &q.to_cached()).to_p3()
}

/// `1` if `a == b`, else `0`, without branches.
#[inline(always)]
fn ct_eq_u8(a: u8, b: u8) -> u64 {
    let x = u64::from(a ^ b);
    core::hint::black_box(x.wrapping_sub(1) >> 63)
}

/// Constant-time `digit * 16^(2 * pos) * B` for `digit` in `-8..=8`.
fn select(pos: usize, digit: i8) -> Precomp {
    let neg = u64::from((digit as u8) >> 7);
    let sign = digit >> 7; // 0 or -1
    let abs = ((digit ^ sign) - sign) as u8;
    let mut t = Precomp::IDENTITY;
    for (j, entry) in BASE[pos].iter().enumerate() {
        t.cmov(entry, ct_eq_u8(abs, j as u8 + 1));
    }
    let minus = t.neg();
    t.cmov(&minus, neg);
    t
}

/// Constant-time `[a]B` for a scalar with `a[31] <= 127`.
#[must_use]
pub fn base_mul(a: &[u8; 32]) -> P3 {
    debug_assert!(a[31] <= 127);
    // Signed radix-16 digits e[i] in -8..8, a = sum e[i] 16^i.
    let mut e = [0i8; 64];
    for (i, &byte) in a.iter().enumerate() {
        e[2 * i] = (byte & 15) as i8;
        e[2 * i + 1] = (byte >> 4) as i8;
    }
    let mut carry = 0i8;
    for d in &mut e[..63] {
        *d += carry;
        carry = (*d + 8) >> 4;
        *d -= carry << 4;
    }
    e[63] += carry;

    let mut h = P3::IDENTITY;
    for i in (1..64).step_by(2) {
        h = madd(&h, &select(i / 2, e[i])).to_p3();
    }
    h = h.dbl().to_p2().dbl().to_p2().dbl().to_p2().dbl().to_p3();
    for i in (0..64).step_by(2) {
        h = madd(&h, &select(i / 2, e[i])).to_p3();
    }
    let mut e_bytes = e.map(|d| d as u8);
    e_bytes.zeroize();
    h
}

/// Montgomery `u` of `[a]B` (for X25519 public keys).
#[must_use]
pub fn base_mul_montgomery_u(a: &[u8; 32]) -> [u8; 32] {
    let mut p = base_mul(a);
    let u = p.to_montgomery_u();
    for fe in [&mut p.x, &mut p.y, &mut p.z, &mut p.t] {
        fe.zeroize();
    }
    u
}

/// Width-5 signed sliding-window recoding (odd digits in `-15..=15`).
fn slide(a: &[u8; 32]) -> [i8; 256] {
    let mut r = [0i8; 256];
    for (i, d) in r.iter_mut().enumerate() {
        *d = ((a[i >> 3] >> (i & 7)) & 1) as i8;
    }
    for i in 0..256 {
        if r[i] == 0 {
            continue;
        }
        let mut b = 1;
        while b <= 6 && i + b < 256 {
            if r[i + b] != 0 {
                let ri = i32::from(r[i]);
                let rb = i32::from(r[i + b]) << b;
                if ri + rb <= 15 {
                    r[i] = (ri + rb) as i8;
                    r[i + b] = 0;
                } else if ri - rb >= -15 {
                    r[i] = (ri - rb) as i8;
                    for k in (i + b)..256 {
                        if r[k] == 0 {
                            r[k] = 1;
                            break;
                        }
                        r[k] = 0;
                    }
                } else {
                    break;
                }
            }
            b += 1;
        }
    }
    r
}

/// `[a]A + [b]B` in variable time (Straus/Shamir with sliding windows).
/// Only for public inputs.
#[must_use]
pub fn double_scalarmult_vartime(a: &[u8; 32], big_a: &P3, b: &[u8; 32]) -> P2 {
    let aslide = slide(a);
    let bslide = slide(b);

    // A, 3A, 5A, ..., 15A.
    let mut ai = [big_a.to_cached(); 8];
    let a2 = big_a.dbl().to_p3();
    for i in 1..8 {
        ai[i] = add(&a2, &ai[i - 1]).to_p3().to_cached();
    }

    let Some(top) = (0..256).rev().find(|&i| aslide[i] != 0 || bslide[i] != 0) else {
        return P2::IDENTITY;
    };

    let mut r = P2::IDENTITY;
    for i in (0..=top).rev() {
        let mut t = r.dbl();
        let (da, db) = (aslide[i], bslide[i]);
        if da > 0 {
            t = add(&t.to_p3(), &ai[(da / 2) as usize]);
        } else if da < 0 {
            t = sub(&t.to_p3(), &ai[(-da / 2) as usize]);
        }
        if db > 0 {
            t = madd(&t.to_p3(), &BASE_ODD[(db / 2) as usize]);
        } else if db < 0 {
            t = msub(&t.to_p3(), &BASE_ODD[(-db / 2) as usize]);
        }
        r = t.to_p2();
    }
    r
}

// --- table generation --------------------------------------------------------

/// Affine Niels form of `p` with every coordinate fully reduced.
fn to_precomp(p: &P3) -> Precomp {
    let canon = |f: Gf| unpack25519(&to_bytes(f));
    let zi = inv25519(p.z);
    let x = fmul(p.x, zi);
    let y = fmul(p.y, zi);
    Precomp {
        ypx: canon(fadd(y, x)),
        ymx: canon(fsub(y, x)),
        xy2d: canon(fmul(fmul(x, y), D2)),
    }
}

/// Recompute `(BASE, BASE_ODD)` from scratch:
/// `BASE[i][j] = (j + 1) * 256^i * B` and `BASE_ODD[j] = (2j + 1) * B`.
#[must_use]
pub fn compute_tables() -> (alloc::vec::Vec<[Precomp; 8]>, [Precomp; 8]) {
    let b = P3::base();
    let mut rows = alloc::vec::Vec::with_capacity(32);
    let mut row_base = b;
    for _ in 0..32 {
        let step = row_base.to_cached();
        let mut p = row_base;
        let mut row = [Precomp::IDENTITY; 8];
        for entry in &mut row {
            *entry = to_precomp(&p);
            p = add(&p, &step).to_p3();
        }
        rows.push(row);
        for _ in 0..8 {
            row_base = row_base.dbl().to_p3();
        }
    }
    let b2 = b.dbl().to_p3().to_cached();
    let mut odd = [Precomp::IDENTITY; 8];
    let mut p = b;
    for entry in &mut odd {
        *entry = to_precomp(&p);
        p = add(&p, &b2).to_p3();
    }
    (rows, odd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write as _;

    fn limbs_eq(a: &Precomp, b: &Precomp) -> bool {
        a.ypx.0 == b.ypx.0 && a.ymx.0 == b.ymx.0 && a.xy2d.0 == b.xy2d.0
    }

    /// The committed table must equal a fresh computation.
    #[test]
    fn base_table_is_correct() {
        let (rows, odd) = compute_tables();
        for (i, row) in rows.iter().enumerate() {
            for j in 0..8 {
                assert!(limbs_eq(&row[j], &BASE[i][j]), "BASE[{i}][{j}]");
            }
        }
        for j in 0..8 {
            assert!(limbs_eq(&odd[j], &BASE_ODD[j]), "BASE_ODD[{j}]");
        }
    }

    /// Regenerate `base_table.rs`:
    /// `EASYLOCK_GEN_BASE_TABLE=1 cargo test -p easylock-core gen_base_table`.
    #[test]
    fn gen_base_table() {
        if std::env::var_os("EASYLOCK_GEN_BASE_TABLE").is_none() {
            return;
        }
        let (rows, odd) = compute_tables();
        let fmt = |p: &Precomp, out: &mut alloc::string::String| {
            let l = |g: Gf| {
                let [a, b, c, d, e] = g.0;
                alloc::format!("[{a}, {b}, {c}, {d}, {e}]")
            };
            let _ = writeln!(out, "    pc({}, {}, {}),", l(p.ypx), l(p.ymx), l(p.xy2d));
        };
        let mut s = alloc::string::String::new();
        s.push_str(
            "//! Precomputed Ed25519 base-point multiples (affine Niels form, radix 2^51).\n\
             //!\n\
             //! @generated by `EASYLOCK_GEN_BASE_TABLE=1 cargo test -p easylock-core \
             gen_base_table`;\n\
             //! verified against a fresh computation by `edwards::tests::base_table_is_correct`.\n\
             \n\
             use super::edwards::Precomp;\n\
             \n\
             const fn pc(a: [u64; 5], b: [u64; 5], c: [u64; 5]) -> Precomp {\n    \
             Precomp::from_limbs(a, b, c)\n}\n\n\
             /// `BASE[i][j] = (j + 1) * 256^i * B`.\n\
             pub(super) static BASE: [[Precomp; 8]; 32] = [\n",
        );
        for row in &rows {
            s.push_str("  [\n");
            for p in row {
                fmt(p, &mut s);
            }
            s.push_str("  ],\n");
        }
        s.push_str("];\n\n/// `BASE_ODD[j] = (2j + 1) * B`.\npub(super) static BASE_ODD: [Precomp; 8] = [\n");
        for p in &odd {
            fmt(p, &mut s);
        }
        s.push_str("];\n");
        let file = concat!(env!("CARGO_MANIFEST_DIR"), "/src/ec/base_table.rs");
        std::fs::write(file, s).unwrap();
    }

    fn scalar(seed: u8) -> [u8; 32] {
        let mut s: [u8; 32] =
            core::array::from_fn(|i| (i as u8).wrapping_mul(seed).wrapping_add(seed ^ 0x5a));
        s[31] &= 0x7f;
        s
    }

    /// Reference `[a]P` by plain double-and-add.
    fn naive_mul(p: &P3, a: &[u8; 32]) -> P3 {
        let mut r = P3::IDENTITY;
        for i in (0..256).rev() {
            r = r.dbl().to_p3();
            if (a[i >> 3] >> (i & 7)) & 1 == 1 {
                r = add_p3(&r, p);
            }
        }
        r
    }

    #[test]
    fn base_mul_matches_naive() {
        let b = P3::base();
        for seed in 0..24u8 {
            let a = scalar(seed);
            assert_eq!(
                base_mul(&a).compress(),
                naive_mul(&b, &a).compress(),
                "seed {seed}"
            );
        }
        assert_eq!(base_mul(&[0; 32]).compress(), P3::IDENTITY.compress());
    }

    #[test]
    fn double_scalarmult_matches_naive() {
        let b = P3::base();
        let big_a = base_mul(&scalar(200));
        for seed in 0..16u8 {
            let (x, y) = (scalar(seed), scalar(seed.wrapping_add(100)));
            let expect = add_p3(&naive_mul(&big_a, &x), &naive_mul(&b, &y)).compress();
            assert_eq!(double_scalarmult_vartime(&x, &big_a, &y).compress(), expect);
        }
        assert_eq!(
            double_scalarmult_vartime(&[0; 32], &big_a, &[0; 32]).compress(),
            P3::IDENTITY.compress()
        );
    }

    #[test]
    fn decompress_negates() {
        let p = base_mul(&scalar(9));
        let enc = p.compress();
        let neg = P3::decompress_neg(&enc).unwrap();
        assert_eq!(add_p3(&p, &neg).compress(), P3::IDENTITY.compress());
    }
}
