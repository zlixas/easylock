//! Fixed-width unsigned big integers for modular / RSA arithmetic.
//!
//! [`BigUint<N>`] is `N` little-endian 64-bit limbs. Addition, subtraction and
//! comparison are constant time in the limb count (no early exit on a differing
//! limb). Multiplication offers schoolbook and Karatsuba paths; modular
//! exponentiation goes through [`montgomery::Montgomery`].
//!
//! Curve25519 has its own dedicated field implementation ([`crate::ec`]); this
//! module targets RSA-sized moduli (2048 / 4096 bit).

use crate::ct::{self, Choice};
use crate::secure::Zeroize;
use alloc::vec;
use alloc::vec::Vec;

pub mod montgomery;
pub use montgomery::Montgomery;

/// An `N`-limb little-endian unsigned integer (`limbs[0]` is least significant).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BigUint<const N: usize> {
    /// Little-endian 64-bit limbs.
    pub limbs: [u64; N],
}

impl<const N: usize> BigUint<N> {
    /// Zero.
    pub const ZERO: Self = Self { limbs: [0; N] };

    /// The value `1`.
    #[must_use]
    pub const fn one() -> Self {
        let mut limbs = [0u64; N];
        if N > 0 {
            limbs[0] = 1;
        }
        Self { limbs }
    }

    /// Construct from little-endian limbs.
    #[must_use]
    pub const fn from_limbs(limbs: [u64; N]) -> Self {
        Self { limbs }
    }

    /// Parse from a big-endian byte string. Extra leading bytes must be zero;
    /// the value is truncated to `N` limbs (`8 * N` bytes).
    #[must_use]
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut limbs = [0u64; N];
        // Walk from the least-significant end of `bytes`.
        for (i, chunk) in bytes.rchunks(8).enumerate() {
            if i >= N {
                break;
            }
            let mut buf = [0u8; 8];
            buf[8 - chunk.len()..].copy_from_slice(chunk);
            limbs[i] = u64::from_be_bytes(buf);
        }
        Self { limbs }
    }

    /// Serialize to a big-endian byte string of exactly `8 * N` bytes.
    #[must_use]
    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut out = vec![0u8; N * 8];
        for (i, limb) in self.limbs.iter().enumerate() {
            let start = (N - 1 - i) * 8;
            out[start..start + 8].copy_from_slice(&limb.to_be_bytes());
        }
        out
    }

    /// `true` iff the value is zero (constant time).
    #[must_use]
    pub fn is_zero(&self) -> Choice {
        let mut acc = 0u64;
        for &l in &self.limbs {
            acc |= l;
        }
        ct::is_zero_u64(acc)
    }

    /// `true` iff the value is odd.
    #[must_use]
    pub fn is_odd(&self) -> bool {
        N > 0 && (self.limbs[0] & 1) == 1
    }

    /// Bit at position `i` (0 = LSB).
    #[must_use]
    pub fn bit(&self, i: usize) -> u64 {
        let limb = i / 64;
        if limb >= N {
            return 0;
        }
        (self.limbs[limb] >> (i % 64)) & 1
    }

    /// Constant-time equality.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> Choice {
        let mut acc = 0u64;
        for i in 0..N {
            acc |= self.limbs[i] ^ other.limbs[i];
        }
        ct::is_zero_u64(acc)
    }

    /// Constant-time `self >= other`.
    #[must_use]
    pub fn ct_gte(&self, other: &Self) -> Choice {
        // Compute self - other and inspect the final borrow.
        let mut borrow = 0u128;
        for i in 0..N {
            let diff = u128::from(self.limbs[i]).wrapping_sub(u128::from(other.limbs[i]) + borrow);
            borrow = (diff >> 64) & 1;
        }
        // borrow == 0  =>  self >= other
        ct::is_zero_u64(borrow as u64)
    }

    /// `self += other`, returning the carry out of the top limb.
    pub fn add_assign(&mut self, other: &Self) -> u64 {
        let mut carry = 0u128;
        for i in 0..N {
            let sum = u128::from(self.limbs[i]) + u128::from(other.limbs[i]) + carry;
            self.limbs[i] = sum as u64;
            carry = sum >> 64;
        }
        carry as u64
    }

    /// `self -= other`, returning the borrow out of the top limb (1 if it
    /// underflowed).
    pub fn sub_assign(&mut self, other: &Self) -> u64 {
        let mut borrow = 0i128;
        for i in 0..N {
            let diff = i128::from(self.limbs[i]) - i128::from(other.limbs[i]) - borrow;
            self.limbs[i] = diff as u64;
            borrow = i128::from(diff < 0);
        }
        borrow as u64
    }

    /// Conditionally add `other` iff `choice`; always touches every limb.
    pub fn ct_add_assign(&mut self, other: &Self, choice: Choice) {
        let mask = 0u64.wrapping_sub(u64::from(choice.unwrap_u8()));
        let mut carry = 0u128;
        for i in 0..N {
            let addend = other.limbs[i] & mask;
            let sum = u128::from(self.limbs[i]) + u128::from(addend) + carry;
            self.limbs[i] = sum as u64;
            carry = sum >> 64;
        }
    }

    /// Reduce `self` modulo `m` once (assumes `self < 2m`). Constant time.
    pub fn conditional_sub(&mut self, m: &Self) {
        let mut trial = *self;
        let borrow = trial.sub_assign(m);
        // borrow == 0  =>  self >= m  =>  keep the subtraction
        let take = ct::is_zero_u64(borrow);
        ct::conditional_copy(
            bytemuck_limbs_mut(&mut self.limbs),
            bytemuck_limbs(&trial.limbs),
            take,
        );
    }

    /// Number of trailing zero bits (`self.trailing_zeros()`), or `64 * N` if
    /// `self` is zero.
    #[must_use]
    pub fn trailing_zeros(&self) -> usize {
        for (i, &limb) in self.limbs.iter().enumerate() {
            if limb != 0 {
                return i * 64 + limb.trailing_zeros() as usize;
            }
        }
        64 * N
    }

    /// Shift right by `bits` (logical), in place.
    pub fn shr_bits(&mut self, bits: usize) {
        if bits == 0 {
            return;
        }
        let limb_shift = bits / 64;
        let bit_shift = bits % 64;
        let mut out = [0u64; N];
        for i in 0..N {
            let src = i + limb_shift;
            if src >= N {
                break;
            }
            let mut v = self.limbs[src] >> bit_shift;
            if bit_shift != 0 && src + 1 < N {
                v |= self.limbs[src + 1] << (64 - bit_shift);
            }
            out[i] = v;
        }
        self.limbs = out;
    }

    /// `self mod m` for a small modulus (non-constant-time; used off the hot path).
    #[must_use]
    pub fn rem_u64(&self, m: u64) -> u64 {
        debug_assert!(m > 0);
        let mut r: u128 = 0;
        for &limb in self.limbs.iter().rev() {
            r = ((r << 64) | u128::from(limb)) % u128::from(m);
        }
        r as u64
    }

    /// Long division by a small divisor: returns `(quotient, remainder)`.
    /// Non-constant-time; used only in RSA key generation.
    #[must_use]
    pub fn div_rem_u64(&self, d: u64) -> (Self, u64) {
        debug_assert!(d > 0);
        let mut q = [0u64; N];
        let mut r: u128 = 0;
        for i in (0..N).rev() {
            let acc = (r << 64) | u128::from(self.limbs[i]);
            q[i] = (acc / u128::from(d)) as u64;
            r = acc % u128::from(d);
        }
        (Self { limbs: q }, r as u64)
    }

    /// Widening multiply: returns `2N` limbs (schoolbook).
    #[must_use]
    pub fn mul_wide(&self, other: &Self) -> Vec<u64> {
        let mut out = vec![0u64; 2 * N];
        schoolbook(&self.limbs, &other.limbs, &mut out);
        out
    }

    /// Widening multiply via Karatsuba (falls back to schoolbook for small `N`).
    #[must_use]
    pub fn mul_wide_karatsuba(&self, other: &Self) -> Vec<u64> {
        let mut out = vec![0u64; 2 * N];
        karatsuba(&self.limbs, &other.limbs, &mut out);
        out
    }
}

impl<const N: usize> Zeroize for BigUint<N> {
    fn zeroize(&mut self) {
        self.limbs.zeroize();
    }
}

impl<const N: usize> core::fmt::Debug for BigUint<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BigUint<{N}>(0x")?;
        for limb in self.limbs.iter().rev() {
            write!(f, "{limb:016x}")?;
        }
        f.write_str(")")
    }
}

// --- limb-slice helpers ------------------------------------------------------

fn bytemuck_limbs(l: &[u64]) -> &[u8] {
    // SAFETY: `[u64]` is always safely reinterpretable as `[u8]`; length scaled.
    unsafe { core::slice::from_raw_parts(l.as_ptr().cast::<u8>(), l.len() * 8) }
}

fn bytemuck_limbs_mut(l: &mut [u64]) -> &mut [u8] {
    // SAFETY: as above; exclusive borrow preserved.
    unsafe { core::slice::from_raw_parts_mut(l.as_mut_ptr().cast::<u8>(), l.len() * 8) }
}

/// `out[..a.len()+b.len()] = a * b`. `out` must be zeroed and long enough.
pub fn schoolbook(a: &[u64], b: &[u64], out: &mut [u64]) {
    debug_assert!(out.len() >= a.len() + b.len());
    for (i, &ai) in a.iter().enumerate() {
        let mut carry = 0u128;
        for (j, &bj) in b.iter().enumerate() {
            let cur = u128::from(out[i + j]) + u128::from(ai) * u128::from(bj) + carry;
            out[i + j] = cur as u64;
            carry = cur >> 64;
        }
        let mut k = i + b.len();
        while carry != 0 {
            let cur = u128::from(out[k]) + carry;
            out[k] = cur as u64;
            carry = cur >> 64;
            k += 1;
        }
    }
}

fn add_into(dst: &mut [u64], src: &[u64]) -> u64 {
    let mut carry = 0u128;
    for i in 0..src.len() {
        let s = u128::from(dst[i]) + u128::from(src[i]) + carry;
        dst[i] = s as u64;
        carry = s >> 64;
    }
    let mut i = src.len();
    while carry != 0 && i < dst.len() {
        let s = u128::from(dst[i]) + carry;
        dst[i] = s as u64;
        carry = s >> 64;
        i += 1;
    }
    carry as u64
}

fn sub_into(dst: &mut [u64], src: &[u64]) {
    let mut borrow = 0i128;
    for i in 0..src.len() {
        let d = i128::from(dst[i]) - i128::from(src[i]) - borrow;
        dst[i] = d as u64;
        borrow = i128::from(d < 0);
    }
    let mut i = src.len();
    while borrow != 0 && i < dst.len() {
        let d = i128::from(dst[i]) - borrow;
        dst[i] = d as u64;
        borrow = i128::from(d < 0);
        i += 1;
    }
}

/// Recursive Karatsuba multiply: `out[..2n] = a * b` where `n = a.len() = b.len()`.
///
/// Uses heap allocation per recursion level (sized by the public limb count, not
/// by any secret) for clarity; the schoolbook base case cuts the recursion at 32
/// limbs.
pub fn karatsuba(a: &[u64], b: &[u64], out: &mut [u64]) {
    let n = a.len();
    debug_assert_eq!(n, b.len());
    debug_assert!(out.len() >= 2 * n);
    out[..2 * n].fill(0);

    if n <= 32 {
        schoolbook(a, b, out);
        return;
    }

    let half = n / 2;
    let hi = n - half;
    let (a_lo, a_hi) = a.split_at(half);
    let (b_lo, b_hi) = b.split_at(half);

    let mut z0 = vec![0u64; 2 * half];
    let mut z2 = vec![0u64; 2 * hi];
    karatsuba(a_lo, b_lo, &mut z0);
    karatsuba(a_hi, b_hi, &mut z2);

    // sum_a = a_lo + a_hi, sum_b = b_lo + b_hi  (hi + 1 limbs each; no carry out
    // because each operand is < 2^(64*hi))
    let mut sum_a = vec![0u64; hi + 1];
    let mut sum_b = vec![0u64; hi + 1];
    sum_a[..half].copy_from_slice(a_lo);
    sum_b[..half].copy_from_slice(b_lo);
    let ca = add_into(&mut sum_a, a_hi);
    let cb = add_into(&mut sum_b, b_hi);
    debug_assert_eq!(ca | cb, 0);

    let mut z1 = vec![0u64; 2 * (hi + 1)];
    karatsuba(&sum_a, &sum_b, &mut z1);
    sub_into(&mut z1, &z0);
    sub_into(&mut z1, &z2);

    // out = z0 + (z1 << (64*half)) + (z2 << (64*2*half))
    add_into(&mut out[..2 * half], &z0);
    add_into(&mut out[2 * half..], &z2);
    add_into(&mut out[half..], &z1);

    z0.zeroize();
    z1.zeroize();
    z2.zeroize();
    sum_a.zeroize();
    sum_b.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    type U256 = BigUint<4>;

    #[test]
    fn be_bytes_roundtrip() {
        let bytes: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
        let n = U256::from_be_bytes(&bytes);
        assert_eq!(n.to_be_bytes(), bytes);
    }

    #[test]
    fn add_sub_inverse() {
        let a = U256::from_be_bytes(&[0x11; 32]);
        let b = U256::from_be_bytes(&[0x22; 32]);
        let mut s = a;
        let carry = s.add_assign(&b);
        assert_eq!(carry, 0);
        let borrow = s.sub_assign(&b);
        assert_eq!(borrow, 0);
        assert_eq!(s, a);
    }

    #[test]
    fn compare() {
        let a = U256::from_be_bytes(&[1]);
        let b = U256::from_be_bytes(&[2]);
        assert!(bool::from(b.ct_gte(&a)));
        assert!(bool::from(a.ct_gte(&a)));
        assert!(!bool::from(a.ct_gte(&b)));
    }

    #[test]
    fn schoolbook_matches_known_product() {
        // (2^64) * (2^64) = 2^128
        let a = BigUint::<2>::from_limbs([0, 1]);
        let b = BigUint::<2>::from_limbs([0, 1]);
        let p = a.mul_wide(&b);
        assert_eq!(p, vec![0, 0, 1, 0]);
    }

    #[test]
    fn karatsuba_matches_schoolbook() {
        let a = BigUint::<64>::from_be_bytes(&[0xAB; 512]);
        let b = BigUint::<64>::from_be_bytes(&[0xCD; 512]);
        assert_eq!(a.mul_wide(&b), a.mul_wide_karatsuba(&b));
    }
}
