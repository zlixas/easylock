//! Constant-time building blocks.
//!
//! All comparisons of secret data (AEAD tags, MACs, hashes, scalars) must go
//! through here. The rules followed:
//!
//! * no `if`/`match` on secret bits,
//! * no early return whose timing depends on a secret,
//! * no array indexing by a secret,
//! * fold differences with XOR/OR into a single accumulator, then reduce once.
//!
//! [`core::hint::black_box`] is used as an optimization barrier so the compiler
//! does not turn the accumulator back into a branch.

use core::hint::black_box;

/// A byte that is statically known to be `0` (false) or `1` (true), kept opaque
/// so surrounding code cannot branch on it "for free".
#[derive(Clone, Copy, Debug)]
pub struct Choice(u8);

impl Choice {
    /// Wrap a raw `0`/`1`. Any non-zero input is normalized to `1`.
    #[inline]
    #[must_use]
    pub fn from_u8(v: u8) -> Self {
        // 0 -> 0, anything else -> 1, branchlessly.
        let nz = (u32::from(v) | u32::from(v).wrapping_neg()) >> 31;
        Choice(nz as u8)
    }

    /// The raw `0` or `1`.
    #[inline]
    #[must_use]
    pub fn unwrap_u8(self) -> u8 {
        self.0
    }

    /// Logical negation (`0 <-> 1`) without branching.
    #[inline]
    #[must_use]
    pub fn negate(self) -> Choice {
        Choice(self.0 ^ 1)
    }

    /// All-ones (`0xFF..`) when true, all-zeros when false. Handy as a mask.
    #[inline]
    #[must_use]
    pub fn mask_u8(self) -> u8 {
        0u8.wrapping_sub(self.0)
    }
}

impl From<Choice> for bool {
    #[inline]
    fn from(c: Choice) -> bool {
        c.0 == 1
    }
}

impl core::ops::BitAnd for Choice {
    type Output = Choice;
    #[inline]
    fn bitand(self, rhs: Choice) -> Choice {
        Choice(self.0 & rhs.0)
    }
}

impl core::ops::BitOr for Choice {
    type Output = Choice;
    #[inline]
    fn bitor(self, rhs: Choice) -> Choice {
        Choice(self.0 | rhs.0)
    }
}

/// Constant-time slice equality.
///
/// Returns [`Choice`] `false` immediately (in constant time w.r.t. contents) when
/// the lengths differ — length is not considered secret. When lengths match,
/// every byte pair is compared and the result depends only on whether *all*
/// pairs were equal, never on *which* pair differed or *where*.
#[inline]
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> Choice {
    if a.len() != b.len() {
        return Choice(0);
    }
    let mut acc = 0u8;
    for i in 0..a.len() {
        acc |= a[i] ^ b[i];
    }
    // acc == 0  =>  equal
    is_zero_u8(black_box(acc))
}

/// Constant-time equality for fixed-size arrays (no length branch at all).
#[inline]
#[must_use]
pub fn ct_eq_fixed<const N: usize>(a: &[u8; N], b: &[u8; N]) -> Choice {
    let mut acc = 0u8;
    for i in 0..N {
        acc |= a[i] ^ b[i];
    }
    is_zero_u8(black_box(acc))
}

/// `true` iff `x == 0`, branchless.
#[inline]
#[must_use]
pub fn is_zero_u8(x: u8) -> Choice {
    let x = u32::from(x);
    // (x | -x) >> 31  ==  0 iff x == 0, else 1.  Negate to get "is zero".
    let nonzero = ((x | x.wrapping_neg()) >> 31) as u8;
    Choice(nonzero ^ 1)
}

/// `true` iff `x == 0` for a 64-bit limb, branchless.
#[inline]
#[must_use]
pub fn is_zero_u64(x: u64) -> Choice {
    let nonzero = ((x | x.wrapping_neg()) >> 63) as u8;
    Choice(nonzero ^ 1)
}

/// Branchless select: returns `a` when `choice` is true, else `b`.
#[inline]
#[must_use]
pub fn select_u8(a: u8, b: u8, choice: Choice) -> u8 {
    let m = choice.mask_u8();
    (a & m) | (b & !m)
}

/// Branchless select for 64-bit limbs.
#[inline]
#[must_use]
pub fn select_u64(a: u64, b: u64, choice: Choice) -> u64 {
    let m = 0u64.wrapping_sub(u64::from(choice.0));
    (a & m) | (b & !m)
}

/// Copy `src` into `dst` iff `choice` is true; both paths touch every byte.
#[inline]
pub fn conditional_copy(dst: &mut [u8], src: &[u8], choice: Choice) {
    debug_assert_eq!(dst.len(), src.len());
    let m = choice.mask_u8();
    for i in 0..dst.len() {
        dst[i] = (src[i] & m) | (dst[i] & !m);
    }
}

/// Swap the contents of `a` and `b` iff `choice` is true, in constant time.
#[inline]
pub fn conditional_swap(a: &mut [u64], b: &mut [u64], choice: Choice) {
    debug_assert_eq!(a.len(), b.len());
    let m = 0u64.wrapping_sub(u64::from(choice.0));
    for i in 0..a.len() {
        let t = m & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

/// Constant-time greater-than-or-equal for two equal-length big-endian byte
/// strings. Used to compare scalars against a group order.
#[inline]
#[must_use]
pub fn ct_ge_be(a: &[u8], b: &[u8]) -> Choice {
    debug_assert_eq!(a.len(), b.len());
    // Walk MSB->LSB tracking "still equal so far" and "a > b decided".
    let mut gt = 0u8;
    let mut lt = 0u8;
    for i in 0..a.len() {
        let ai = i16::from(a[i]);
        let bi = i16::from(b[i]);
        // Sign bit of (bi - ai) is 1 exactly when ai > bi; likewise for lt.
        let cur_gt = (((bi - ai) >> 8) & 1) as u8;
        let cur_lt = (((ai - bi) >> 8) & 1) as u8;
        let undecided = (gt | lt) ^ 1;
        gt |= cur_gt & undecided;
        lt |= cur_lt & undecided;
    }
    // a >= b  <=>  not (a < b)
    Choice(lt ^ 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_matches_plain_eq() {
        assert!(bool::from(ct_eq(b"hello", b"hello")));
        assert!(!bool::from(ct_eq(b"hello", b"world")));
        assert!(!bool::from(ct_eq(b"hello", b"hell")));
        assert!(bool::from(ct_eq(b"", b"")));
    }

    #[test]
    fn choice_normalizes() {
        assert_eq!(Choice::from_u8(0).unwrap_u8(), 0);
        assert_eq!(Choice::from_u8(1).unwrap_u8(), 1);
        assert_eq!(Choice::from_u8(200).unwrap_u8(), 1);
    }

    #[test]
    fn select_picks_correct_side() {
        assert_eq!(select_u8(0xAA, 0xBB, Choice::from_u8(1)), 0xAA);
        assert_eq!(select_u8(0xAA, 0xBB, Choice::from_u8(0)), 0xBB);
        assert_eq!(select_u64(1, 2, Choice::from_u8(1)), 1);
        assert_eq!(select_u64(1, 2, Choice::from_u8(0)), 2);
    }

    #[test]
    fn conditional_swap_respects_choice() {
        let mut a = [1u64, 2, 3];
        let mut b = [4u64, 5, 6];
        conditional_swap(&mut a, &mut b, Choice::from_u8(0));
        assert_eq!((a, b), ([1, 2, 3], [4, 5, 6]));
        conditional_swap(&mut a, &mut b, Choice::from_u8(1));
        assert_eq!((a, b), ([4, 5, 6], [1, 2, 3]));
    }

    #[test]
    fn ct_ge_be_orders_correctly() {
        assert!(bool::from(ct_ge_be(&[0, 0, 5], &[0, 0, 5])));
        assert!(bool::from(ct_ge_be(&[0, 1, 0], &[0, 0, 255])));
        assert!(!bool::from(ct_ge_be(&[0, 0, 4], &[0, 0, 5])));
    }
}
