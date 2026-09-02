//! Montgomery modular arithmetic for odd moduli (CIOS multiplication + a
//! constant-time powering ladder).

use super::BigUint;
use crate::ct::{self, Choice};
use crate::secure::Zeroize;
use alloc::vec;

/// Precomputed Montgomery parameters for a fixed odd modulus `n` with
/// `R = 2^(64*N)`.
#[derive(Clone)]
pub struct Montgomery<const N: usize> {
    n: BigUint<N>,
    /// `-n^{-1} mod 2^64`.
    n_prime: u64,
    /// `R^2 mod n`, used to enter the Montgomery domain.
    r2: BigUint<N>,
}

/// `a^{-1} mod 2^64` for odd `a`, via Newton iteration.
fn inv64(a: u64) -> u64 {
    debug_assert_eq!(a & 1, 1);
    let mut x = 1u64;
    // Each step doubles the number of correct low bits: 1,2,4,8,16,32,64.
    for _ in 0..6 {
        x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x)));
    }
    x
}

impl<const N: usize> Montgomery<N> {
    /// Build the context. Returns `None` if `n` is even or zero.
    #[must_use]
    pub fn new(n: BigUint<N>) -> Option<Self> {
        if N == 0 || !n.is_odd() {
            return None;
        }
        let n_prime = inv64(n.limbs[0]).wrapping_neg();

        // r2 = 2^(128*N) mod n, by 128*N modular doublings of 1.
        let mut r2 = BigUint::<N>::one();
        for _ in 0..(128 * N) {
            let snapshot = r2; // BigUint is Copy
            let carry = r2.add_assign(&snapshot);
            // Reduce: if there was a carry out, or r2 >= n, subtract n.
            let overflowed = ct::is_zero_u64(carry).negate();
            let ge = r2.ct_gte(&n);
            let need_sub = overflowed | ge;
            let mut trial = r2;
            trial.sub_assign(&n);
            ct::conditional_copy(
                limbs_as_bytes_mut(&mut r2.limbs),
                limbs_as_bytes(&trial.limbs),
                need_sub,
            );
        }

        Some(Self { n, n_prime, r2 })
    }

    /// The modulus.
    #[must_use]
    pub fn modulus(&self) -> &BigUint<N> {
        &self.n
    }

    /// CIOS Montgomery multiplication: returns `a * b * R^{-1} mod n`.
    #[must_use]
    pub fn mont_mul(&self, a: &BigUint<N>, b: &BigUint<N>) -> BigUint<N> {
        let n = &self.n.limbs;
        let mut t = vec![0u64; N + 2];

        for i in 0..N {
            // t += a * b[i]
            let bi = b.limbs[i];
            let mut carry = 0u128;
            for j in 0..N {
                let cur = u128::from(t[j]) + u128::from(a.limbs[j]) * u128::from(bi) + carry;
                t[j] = cur as u64;
                carry = cur >> 64;
            }
            let cur = u128::from(t[N]) + carry;
            t[N] = cur as u64;
            t[N + 1] = (cur >> 64) as u64;

            // m = t[0] * n' mod 2^64 ; t += m * n ; t >>= 64
            let m = t[0].wrapping_mul(self.n_prime);
            let mut carry = 0u128;
            let cur = u128::from(t[0]) + u128::from(m) * u128::from(n[0]) + carry;
            carry = cur >> 64;
            for j in 1..N {
                let cur = u128::from(t[j]) + u128::from(m) * u128::from(n[j]) + carry;
                t[j - 1] = cur as u64;
                carry = cur >> 64;
            }
            let cur = u128::from(t[N]) + carry;
            t[N - 1] = cur as u64;
            t[N] = t[N + 1] + (cur >> 64) as u64;
        }

        // Result is t[0..N] with a possible extra bit in t[N]. Conditionally
        // subtract n.
        let mut result = BigUint::<N>::ZERO;
        result.limbs.copy_from_slice(&t[..N]);

        let extra = ct::is_zero_u64(t[N]).negate();
        let ge = result.ct_gte(&self.n);
        let need_sub = extra | ge;
        let mut trial = result;
        trial.sub_assign(&self.n);
        ct::conditional_copy(
            limbs_as_bytes_mut(&mut result.limbs),
            limbs_as_bytes(&trial.limbs),
            need_sub,
        );

        t.zeroize();
        result
    }

    /// Enter the Montgomery domain: `a -> a * R mod n`.
    #[must_use]
    pub fn to_mont(&self, a: &BigUint<N>) -> BigUint<N> {
        self.mont_mul(a, &self.r2)
    }

    /// Plain modular multiply `a * b mod n` (neither operand in Montgomery form).
    #[must_use]
    pub fn mul_mod(&self, a: &BigUint<N>, b: &BigUint<N>) -> BigUint<N> {
        self.mont_mul(&self.to_mont(a), b)
    }

    /// Leave the Montgomery domain: `aR -> a mod n`.
    #[must_use]
    pub fn from_mont(&self, a: &BigUint<N>) -> BigUint<N> {
        let one = BigUint::<N>::one();
        self.mont_mul(a, &one)
    }

    /// Modular exponentiation `base^exp mod n` via a constant-time Montgomery
    /// powering ladder over all `64*N` exponent bits.
    #[must_use]
    pub fn pow(&self, base: &BigUint<N>, exp: &BigUint<N>) -> BigUint<N> {
        let mut reduced = *base;
        reduced.conditional_sub(&self.n); // ensure base < n if base in [n, 2n)

        let mut r0 = self.to_mont(&BigUint::<N>::one());
        let mut r1 = self.to_mont(&reduced);

        for i in (0..(64 * N)).rev() {
            let bit = Choice::from_u8((exp.bit(i) & 1) as u8);
            ct::conditional_swap(&mut r0.limbs, &mut r1.limbs, bit);
            r1 = self.mont_mul(&r0, &r1);
            r0 = self.mont_mul(&r0, &r0);
            ct::conditional_swap(&mut r0.limbs, &mut r1.limbs, bit);
        }

        r1.zeroize();
        self.from_mont(&r0)
    }
}

impl<const N: usize> Zeroize for Montgomery<N> {
    fn zeroize(&mut self) {
        self.n.zeroize();
        self.n_prime.zeroize();
        self.r2.zeroize();
    }
}

impl<const N: usize> core::fmt::Debug for Montgomery<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Montgomery").finish_non_exhaustive()
    }
}

fn limbs_as_bytes(l: &[u64]) -> &[u8] {
    // SAFETY: `[u64]` reinterprets as `[u8]` with 8x the length.
    unsafe { core::slice::from_raw_parts(l.as_ptr().cast::<u8>(), l.len() * 8) }
}

fn limbs_as_bytes_mut(l: &mut [u64]) -> &mut [u8] {
    // SAFETY: as above, exclusive borrow preserved.
    unsafe { core::slice::from_raw_parts_mut(l.as_mut_ptr().cast::<u8>(), l.len() * 8) }
}

/// A small `Vec`-backed helper: reduce arbitrary-width `x` (2N limbs) mod `n`
/// using schoolbook long division. Used to precondition RSA inputs; not
/// constant time, and only used on non-secret CRT recombination boundaries.
#[must_use]
pub fn reduce_wide<const N: usize>(x: &[u64], n: &BigUint<N>) -> BigUint<N> {
    // Convert to big-endian bytes and do byte-wise long division by `n`.
    let mut rem = BigUint::<N>::ZERO;
    let total_bits = x.len() * 64;
    for i in (0..total_bits).rev() {
        // rem = (rem << 1) | bit_i(x)
        let mut carry = 0u64;
        for limb in &mut rem.limbs {
            let new_carry = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = new_carry;
        }
        let overflow = carry; // bit shifted past the top limb
        let bit = (x[i / 64] >> (i % 64)) & 1;
        rem.limbs[0] |= bit;
        // Real value is `overflow * 2^(64N) + rem`; it is < 2n, so one
        // subtraction of n normalises it (wrapping handles the overflow term).
        if overflow == 1 || bool::from(rem.ct_gte(n)) {
            rem.sub_assign(n);
        }
    }
    rem
}

#[cfg(test)]
mod tests {
    use super::*;

    type U = BigUint<4>;

    fn from_u64<const M: usize>(v: u64) -> BigUint<M> {
        let mut b = BigUint::<M>::ZERO;
        b.limbs[0] = v;
        b
    }

    #[test]
    fn inv64_is_correct() {
        for a in [1u64, 3, 5, 0x9e37_79b9_7f4a_7c15, u64::MAX] {
            assert_eq!(a.wrapping_mul(inv64(a)), 1);
        }
    }

    #[test]
    fn mont_mul_small() {
        // n = 97 (prime), compute 5 * 7 mod 97 = 35
        let n = from_u64::<4>(97);
        let m = Montgomery::new(n).unwrap();
        let a = m.to_mont(&from_u64::<4>(5));
        let b = m.to_mont(&from_u64::<4>(7));
        let prod = m.from_mont(&m.mont_mul(&a, &b));
        assert_eq!(prod.limbs[0], 35);
    }

    #[test]
    fn modpow_small() {
        // 7^13 mod 97 = 96 -> check against direct computation
        let n = from_u64::<4>(97);
        let m = Montgomery::new(n).unwrap();
        let mut expect = 1u64;
        for _ in 0..13 {
            expect = (expect * 7) % 97;
        }
        let got = m.pow(&from_u64::<4>(7), &from_u64::<4>(13));
        assert_eq!(got.limbs[0], expect);
    }

    #[test]
    fn modpow_fermat_256bit() {
        // A 256-bit prime p; a^(p-1) mod p == 1 for gcd(a,p)=1 (Fermat).
        let p = U::from_be_bytes(&[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
            0xff, 0xff, 0xfc, 0x2f,
        ]); // secp256k1 field prime
        let m = Montgomery::new(p).unwrap();
        let mut pm1 = p;
        pm1.sub_assign(&BigUint::<4>::one());
        let a = U::from_be_bytes(&[2]);
        let r = m.pow(&a, &pm1);
        assert_eq!(r, BigUint::<4>::one());
    }

    #[test]
    fn reduce_wide_matches() {
        let n = from_u64::<4>(1_000_003);
        let x = vec![123_456_789u64, 987u64, 0, 0, 0, 0, 0, 0];
        let r = reduce_wide(&x, &n);
        // value = 987 * 2^64 + 123456789
        let val = (987u128 << 64) + 123_456_789u128;
        assert_eq!(u128::from(r.limbs[0]), val % 1_000_003);
    }
}
