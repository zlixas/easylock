//! GHASH — the GF(2^128) universal hash underlying AES-GCM (NIST SP 800-38D).
//!
//! Two backends, selected once per key by [`GHash::new`]:
//!
//! * **portable** — the bit-at-a-time right-shift multiply (McGrew & Viega):
//!   128 iterations, no secret-dependent branches or table lookups.
//! * **carry-less** — a single `PCLMULQDQ` (x86-64) / `PMULL` (aarch64)
//!   `64x64 -> 128` multiply, 3-way Karatsuba for the `128x128` product, and a
//!   shift-only reduction modulo `x^128 + x^7 + x^2 + x + 1`. Operands are
//!   bit-reversed into "polynomial" order so the reduction constant is the plain
//!   `0x87` instead of the reflected form.
//!
//! Both are constant time. The carry-less path is validated against the portable
//! one by a differential test over random inputs.

use crate::secure::Zeroize;

/// Reduction constant R = 0xE1 || 0^120 (field poly x^128 + x^7 + x^2 + x + 1)
/// in GCM bit order, used by the portable multiply.
const R: u128 = 0xe100_0000_0000_0000_0000_0000_0000_0000;

/// Portable GF(2^128) multiply (GCM bit convention: block byte 0 bit 7 is the
/// most significant coefficient).
#[must_use]
pub fn gf_mul(x: u128, h: u128) -> u128 {
    let mut z = 0u128;
    let mut v = h;
    let mut i = 0;
    while i < 128 {
        let xi = (x >> (127 - i)) & 1;
        z ^= 0u128.wrapping_sub(xi) & v;

        let lsb = v & 1;
        v >>= 1;
        v ^= 0u128.wrapping_sub(lsb) & R;

        i += 1;
    }
    z
}

/// Low 64 bits of the carry-less product `x * y`, using ordinary integer
/// multiplication on operands with 3-bit "holes" between the bits of each
/// residue class mod 4 (BearSSL `ghash_ctmul64`). The holes absorb the carries,
/// and integer multiplication is constant-time on every mainstream CPU.
#[inline(always)]
fn bmul64(x: u64, y: u64) -> u64 {
    const M0: u64 = 0x1111_1111_1111_1111;
    const M1: u64 = 0x2222_2222_2222_2222;
    const M2: u64 = 0x4444_4444_4444_4444;
    const M3: u64 = 0x8888_8888_8888_8888;
    let (x0, x1, x2, x3) = (x & M0, x & M1, x & M2, x & M3);
    let (y0, y1, y2, y3) = (y & M0, y & M1, y & M2, y & M3);
    let m = u64::wrapping_mul;
    let z0 = m(x0, y0) ^ m(x1, y3) ^ m(x2, y2) ^ m(x3, y1);
    let z1 = m(x0, y1) ^ m(x1, y0) ^ m(x2, y3) ^ m(x3, y2);
    let z2 = m(x0, y2) ^ m(x1, y1) ^ m(x2, y0) ^ m(x3, y3);
    let z3 = m(x0, y3) ^ m(x1, y2) ^ m(x2, y1) ^ m(x3, y0);
    (z0 & M0) | (z1 & M1) | (z2 & M2) | (z3 & M3)
}

/// Portable constant-time GF(2^128) multiply (same bit convention as
/// [`gf_mul`]): three 64x64 carry-less products per half via Karatsuba (the
/// high halves via bit reversal), then a shift-only reduction. Roughly an
/// order of magnitude faster than the bit-at-a-time loop, especially on
/// 32-bit targets such as `wasm32` where `u128` is emulated.
#[must_use]
pub fn gf_mul_ct64(x: u128, h: u128) -> u128 {
    let (y1, y0) = ((x >> 64) as u64, x as u64);
    let (h1, h0) = ((h >> 64) as u64, h as u64);
    let (h0r, h1r) = (h0.reverse_bits(), h1.reverse_bits());
    let (h2, h2r) = (h0 ^ h1, h0r ^ h1r);
    let (y0r, y1r) = (y0.reverse_bits(), y1.reverse_bits());
    let (y2, y2r) = (y0 ^ y1, y0r ^ y1r);

    let z0 = bmul64(y0, h0);
    let z1 = bmul64(y1, h1);
    let mut z2 = bmul64(y2, h2);
    let mut z0h = bmul64(y0r, h0r);
    let mut z1h = bmul64(y1r, h1r);
    let mut z2h = bmul64(y2r, h2r);
    z2 ^= z0 ^ z1;
    z2h ^= z0h ^ z1h;
    z0h = z0h.reverse_bits() >> 1;
    z1h = z1h.reverse_bits() >> 1;
    z2h = z2h.reverse_bits() >> 1;

    let mut v0 = z0;
    let mut v1 = z0h ^ z2;
    let mut v2 = z1 ^ z2h;
    let mut v3 = z1h;

    // The product of two bit-reflected values is off by one bit: shift left.
    v3 = (v3 << 1) | (v2 >> 63);
    v2 = (v2 << 1) | (v1 >> 63);
    v1 = (v1 << 1) | (v0 >> 63);
    v0 <<= 1;

    // Reduce modulo x^128 + x^7 + x^2 + x + 1 (reflected).
    v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
    v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
    v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
    v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);

    (u128::from(v3) << 64) | u128::from(v2)
}

/// Which multiply [`GHash`] dispatched to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Portable,
    /// `PCLMULQDQ` / `PMULL`.
    ClMul,
}

impl Backend {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Backend::Portable => "portable-ct",
            Backend::ClMul => "clmul",
        }
    }
}

/// The GHASH backend that would be selected on this CPU.
#[must_use]
pub fn active_backend() -> &'static str {
    select_backend().as_str()
}

fn select_backend() -> Backend {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    if crate::cpu::features().clmul {
        return Backend::ClMul;
    }
    Backend::Portable
}

// --- carry-less backend ----------------------------------------------------
//
// Values are kept *bit-reflected* (x.reverse_bits()) so that polynomial
// multiplication is a plain carry-less product. Bulk input uses aggregated
// reduction: Y' = (Y ⊕ X1)·H^8 ⊕ X2·H^7 ⊕ … ⊕ X8·H, summing eight unreduced
// 256-bit products and reducing once.

/// Reduce `hi·x^128 + lo` modulo `x^128 + x^7 + x^2 + x + 1` (reflected domain).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[inline(always)]
fn reduce(lo: u128, hi: u128) -> u128 {
    // x^128 ≡ x^7 + x^2 + x + 1, i.e. multiply by 0b1000_0111 = fold().
    let fold = |v: u128| v ^ (v << 1) ^ (v << 2) ^ (v << 7);
    let a_lo = fold(hi);
    let a_high = (hi >> 127) ^ (hi >> 126) ^ (hi >> 121); // bits that spilled past x^128
    lo ^ a_lo ^ fold(a_high)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
macro_rules! clmul_backend {
    ($feature:literal, $clmul64:item) => {
        $clmul64

        /// 128×128 → 256-bit carry-less product (3-way Karatsuba), as `(lo, hi)`.
        ///
        /// # Safety
        /// Requires the carry-less multiply target feature.
        #[target_feature(enable = $feature)]
        #[inline]
        unsafe fn clmul128(a: u128, b: u128) -> (u128, u128) {
            let (a0, a1) = (a as u64, (a >> 64) as u64);
            let (b0, b1) = (b as u64, (b >> 64) as u64);
            // SAFETY: this function has the same target feature as `clmul64`.
            let (z0, z2, zm) = unsafe { (clmul64(a0, b0), clmul64(a1, b1), clmul64(a0 ^ a1, b0 ^ b1)) };
            let zm = zm ^ z0 ^ z2;
            (z0 ^ (zm << 64), z2 ^ (zm >> 64))
        }

        /// `x · H` in the GCM convention, given `h_rev = H.reverse_bits()`.
        ///
        /// # Safety
        /// Requires the carry-less multiply target feature.
        #[target_feature(enable = $feature)]
        pub unsafe fn mul(x: u128, h_rev: u128) -> u128 {
            // SAFETY: same target feature.
            let (lo, hi) = unsafe { clmul128(x.reverse_bits(), h_rev) };
            super::reduce(lo, hi).reverse_bits()
        }

        /// Absorb `data` (a multiple of 16 bytes) into accumulator `y` (GCM
        /// convention). `pows_rev[i]` must be `(H^(i+1)).reverse_bits()`.
        ///
        /// # Safety
        /// Requires the carry-less multiply target feature.
        #[target_feature(enable = $feature)]
        pub unsafe fn update_blocks(pows_rev: &[u128; 8], y: u128, data: &[u8]) -> u128 {
            let block = |c: &[u8]| u128::from_be_bytes(c.try_into().expect("16 bytes")).reverse_bits();
            let mut acc = y.reverse_bits();
            let mut groups = data.chunks_exact(128);
            for g in &mut groups {
                let (mut lo, mut hi) = (0u128, 0u128);
                for (i, c) in g.chunks_exact(16).enumerate() {
                    let x = if i == 0 { block(c) ^ acc } else { block(c) };
                    // SAFETY: same target feature.
                    let (l, h) = unsafe { clmul128(x, pows_rev[7 - i]) };
                    lo ^= l;
                    hi ^= h;
                }
                acc = super::reduce(lo, hi);
            }
            for c in groups.remainder().chunks_exact(16) {
                // SAFETY: same target feature.
                let (l, h) = unsafe { clmul128(block(c) ^ acc, pows_rev[0]) };
                acc = super::reduce(l, h);
            }
            acc.reverse_bits()
        }
    };
}

#[cfg(target_arch = "x86_64")]
mod clmul {
    use core::arch::x86_64::{__m128i, _mm_clmulepi64_si128, _mm_set_epi64x};

    clmul_backend!(
        "pclmulqdq",
        /// Carry-less `64 x 64 -> 128`.
        ///
        /// # Safety
        /// Requires the `pclmulqdq` target feature (checked by the caller).
        #[target_feature(enable = "pclmulqdq")]
        #[inline]
        unsafe fn clmul64(a: u64, b: u64) -> u128 {
            // SAFETY: intrinsics valid with this feature; __m128i is bit-compatible with u128.
            unsafe {
                let av: __m128i = _mm_set_epi64x(0, a as i64);
                let bv: __m128i = _mm_set_epi64x(0, b as i64);
                core::mem::transmute::<__m128i, u128>(_mm_clmulepi64_si128(av, bv, 0x00))
            }
        }
    );
}

#[cfg(target_arch = "aarch64")]
mod clmul {
    use core::arch::aarch64::vmull_p64;

    clmul_backend!(
        "aes",
        /// Carry-less `64 x 64 -> 128` (`PMULL`).
        ///
        /// # Safety
        /// Requires the `aes`/`pmull` target feature (checked by the caller).
        #[target_feature(enable = "aes")]
        #[inline]
        unsafe fn clmul64(a: u64, b: u64) -> u128 {
            vmull_p64(a, b)
        }
    );
}

// --- streaming accumulator ----------------------------------------------------

/// Streaming GHASH accumulator keyed by `H = E_K(0^128)`.
#[derive(Clone)]
pub struct GHash {
    h: u128,
    /// Bit-reversed `H`, for the carry-less backend.
    h_rev: u128,
    /// `(H^(i+1)).reverse_bits()` for aggregated reduction (carry-less backend).
    pows_rev: [u128; 8],
    y: u128,
    backend: Backend,
}

impl GHash {
    /// New accumulator from the 16-byte hash subkey. Precomputes `H^1..H^8` when
    /// the carry-less backend is active; clone the result to reuse it per message.
    #[must_use]
    pub fn new(h: &[u8; 16]) -> Self {
        let h = u128::from_be_bytes(*h);
        let mut g = Self {
            h,
            h_rev: h.reverse_bits(),
            pows_rev: [0; 8],
            y: 0,
            backend: select_backend(),
        };
        if g.backend == Backend::ClMul {
            let mut p = h;
            for i in 0..8 {
                g.pows_rev[i] = p.reverse_bits();
                p = g.mul(p);
            }
        }
        g
    }

    /// The multiply backend chosen for this key.
    #[must_use]
    pub fn backend(&self) -> Backend {
        self.backend
    }

    #[inline]
    fn mul(&self, x: u128) -> u128 {
        match self.backend {
            #[cfg(target_arch = "x86_64")]
            Backend::ClMul => {
                // SAFETY: `select_backend` only returns `ClMul` after runtime
                // detection confirmed `pclmulqdq`.
                unsafe { clmul::mul(x, self.h_rev) }
            }
            #[cfg(target_arch = "aarch64")]
            Backend::ClMul => {
                // SAFETY: `select_backend` only returns `ClMul` after runtime
                // detection confirmed `pmull`.
                unsafe { clmul::mul(x, self.h_rev) }
            }
            _ => gf_mul_ct64(x, self.h),
        }
    }

    /// Absorb exactly one 16-byte block.
    pub fn update_block(&mut self, block: &[u8; 16]) {
        self.y = self.mul(self.y ^ u128::from_be_bytes(*block));
    }

    /// Absorb an arbitrary-length byte string, zero-padding the final partial
    /// block on the right (GCM convention for AAD and ciphertext).
    pub fn update_padded(&mut self, data: &[u8]) {
        let full = data.len() - data.len() % 16;
        match self.backend {
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            Backend::ClMul => {
                // SAFETY: `ClMul` is only selected after runtime feature detection.
                self.y = unsafe { clmul::update_blocks(&self.pows_rev, self.y, &data[..full]) };
            }
            _ => {
                for c in data[..full].chunks_exact(16) {
                    self.update_block(c.try_into().expect("16 bytes"));
                }
            }
        }
        let rem = &data[full..];
        if !rem.is_empty() {
            let mut b = [0u8; 16];
            b[..rem.len()].copy_from_slice(rem);
            self.update_block(&b);
        }
    }

    /// Finish: absorb the `[len(A)]_64 || [len(C)]_64` block and return the tag
    /// pre-image `S` (still needs `E_K(J0)` XORed in by the caller).
    #[must_use]
    pub fn finalize(mut self, aad_bits: u64, ct_bits: u64) -> [u8; 16] {
        let mut lenblock = [0u8; 16];
        lenblock[..8].copy_from_slice(&aad_bits.to_be_bytes());
        lenblock[8..].copy_from_slice(&ct_bits.to_be_bytes());
        self.update_block(&lenblock);
        let out = self.y.to_be_bytes();
        self.zeroize();
        out
    }
}

impl Zeroize for GHash {
    fn zeroize(&mut self) {
        self.h.zeroize();
        self.h_rev.zeroize();
        for p in &mut self.pows_rev {
            p.zeroize();
        }
        self.y.zeroize();
    }
}

impl Drop for GHash {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl core::fmt::Debug for GHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GHash")
            .field("backend", &self.backend)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::hex::{decode, encode};

    #[test]
    fn ghash_single_block() {
        let h: [u8; 16] = decode("66e94bd4ef8a2c3b884cfa59ca342b2e")
            .unwrap()
            .try_into()
            .unwrap();
        let g = GHash::new(&h);
        let s = g.finalize(0, 0);
        assert_eq!(encode(&s), "00000000000000000000000000000000");
    }

    #[test]
    fn gf_mul_identity_and_zero() {
        assert_eq!(gf_mul(0x1234_5678_9abc_def0_1122_3344_5566_7788, 0), 0);
        let one = 1u128 << 127;
        let x = 0xdead_beef_0000_0000_cafe_babe_0000_0001u128;
        assert_eq!(gf_mul(x, one), x);
    }

    /// The fast portable multiply agrees with the bit-at-a-time reference,
    /// including the edge operands (0, 1, all-ones, single high/low bits).
    #[test]
    fn ct64_matches_bitwise_reference() {
        let mut s = 0x243f_6a88_85a3_08d3_1319_8a2e_0370_7344_u128;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let edges = [0u128, 1, 1 << 127, u128::MAX, 1 << 63, 1 << 64, 0x87];
        for &a in &edges {
            for &b in &edges {
                assert_eq!(gf_mul_ct64(a, b), gf_mul(a, b), "{a:x} * {b:x}");
            }
        }
        for _ in 0..2000 {
            let (a, b) = (next(), next());
            assert_eq!(gf_mul_ct64(a, b), gf_mul(a, b));
        }
    }

    /// The carry-less backend must agree with the portable one on random inputs.
    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn clmul_matches_portable() {
        if !crate::cpu::features().clmul {
            eprintln!("skipping: no clmul on this CPU");
            return;
        }
        // xorshift128+ PRNG for reproducibility without deps.
        let mut s0 = 0x9E37_79B9_7F4A_7C15u64;
        let mut s1 = 0xBF58_476D_1CE4_E5B9u64;
        let mut next = || {
            let mut x = s0;
            let y = s1;
            s0 = y;
            x ^= x << 23;
            s1 = x ^ y ^ (x >> 17) ^ (y >> 26);
            s1.wrapping_add(y)
        };
        for _ in 0..5000 {
            let x = (u128::from(next()) << 64) | u128::from(next());
            let h = (u128::from(next()) << 64) | u128::from(next());
            let portable = gf_mul(x, h);
            // SAFETY: guarded by the `features().clmul` check above.
            let hw = unsafe { clmul::mul(x, h.reverse_bits()) };
            assert_eq!(portable, hw, "mismatch for x={x:032x} h={h:032x}");
        }
    }

    #[test]
    fn backend_is_reported() {
        let g = GHash::new(&[0u8; 16]);
        assert!(matches!(g.backend(), Backend::Portable | Backend::ClMul));
    }

    #[test]
    fn aggregated_update_matches_portable_blockwise() {
        let mut s = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for len in [0usize, 5, 16, 100, 127, 128, 129, 255, 256, 1000, 4096 + 7] {
            let mut h = [0u8; 16];
            for b in &mut h {
                *b = next() as u8;
            }
            let data: alloc::vec::Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let mut fast = GHash::new(&h);
            fast.update_padded(&data[..len / 3]);
            fast.update_padded(&data[len / 3..]);
            // reference: portable multiply, one block at a time, same padding points
            let hv = u128::from_be_bytes(h);
            let mut y = 0u128;
            for part in [&data[..len / 3], &data[len / 3..]] {
                for c in part.chunks(16) {
                    let mut b = [0u8; 16];
                    b[..c.len()].copy_from_slice(c);
                    y = gf_mul(y ^ u128::from_be_bytes(b), hv);
                }
            }
            assert_eq!(fast.y, y, "len {len}");
        }
    }
}
