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

#[cfg(target_arch = "x86_64")]
mod clmul {
    use core::arch::x86_64::{__m128i, _mm_clmulepi64_si128, _mm_set_epi64x};

    /// Carry-less `64 x 64 -> 128`.
    ///
    /// # Safety
    /// Requires the `pclmulqdq` target feature (checked by the caller).
    #[target_feature(enable = "pclmulqdq")]
    unsafe fn clmul64(a: u64, b: u64) -> u128 {
        // SAFETY: `_mm_set_epi64x` / `_mm_clmulepi64_si128` are always valid with
        // this feature enabled; the __m128i result is bit-compatible with u128.
        unsafe {
            let av: __m128i = _mm_set_epi64x(0, a as i64);
            let bv: __m128i = _mm_set_epi64x(0, b as i64);
            let prod = _mm_clmulepi64_si128(av, bv, 0x00);
            core::mem::transmute::<__m128i, u128>(prod)
        }
    }

    /// # Safety
    /// Requires the `pclmulqdq` target feature.
    #[target_feature(enable = "pclmulqdq")]
    pub unsafe fn mul(x: u128, h_rev: u128) -> u128 {
        // SAFETY: feature guaranteed by caller.
        unsafe { super::clmul_mul_generic(x, h_rev, clmul64) }
    }
}

#[cfg(target_arch = "aarch64")]
mod clmul {
    use core::arch::aarch64::vmull_p64;

    /// Carry-less `64 x 64 -> 128`.
    ///
    /// # Safety
    /// Requires the `aes`/`pmull` target feature (checked by the caller).
    #[target_feature(enable = "aes")]
    unsafe fn clmul64(a: u64, b: u64) -> u128 {
        // `vmull_p64` shares this function's `aes` feature, so no `unsafe` block
        // is needed; its `p128` result is `u128` in `core::arch::aarch64`.
        vmull_p64(a, b)
    }

    /// # Safety
    /// Requires the `aes`/`pmull` target feature.
    #[target_feature(enable = "aes")]
    pub unsafe fn mul(x: u128, h_rev: u128) -> u128 {
        // SAFETY: feature guaranteed by caller.
        unsafe { super::clmul_mul_generic(x, h_rev, clmul64) }
    }
}

/// Shared body of the carry-less multiply: bit-reverse into polynomial order,
/// 3-way Karatsuba `128x128`, shift-only reduction, bit-reverse back.
///
/// # Safety
/// `clmul64` must be safe to call (its target feature is present).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[inline]
unsafe fn clmul_mul_generic(x: u128, h_rev: u128, clmul64: unsafe fn(u64, u64) -> u128) -> u128 {
    let a = x.reverse_bits();
    let b = h_rev; // caller passes an already bit-reversed H

    let (a0, a1) = (a as u64, (a >> 64) as u64);
    let (b0, b1) = (b as u64, (b >> 64) as u64);

    // SAFETY: the caller guarantees the carry-less target feature is enabled, so
    // every `clmul64` call below is sound.
    let z0 = unsafe { clmul64(a0, b0) };
    // SAFETY: as z0.
    let z2 = unsafe { clmul64(a1, b1) };
    // SAFETY: as z0.
    let zm = unsafe { clmul64(a0 ^ a1, b0 ^ b1) } ^ z0 ^ z2;

    let lo = z0 ^ (zm << 64);
    let hi = z2 ^ (zm >> 64);

    // Reduce  hi*x^128 + lo  mod  x^128 + x^7 + x^2 + x + 1.
    // x^128 ≡ x^7 + x^2 + x + 1, i.e. multiply by 0b1000_0111 = fold().
    let fold = |v: u128| v ^ (v << 1) ^ (v << 2) ^ (v << 7);
    let a_lo = fold(hi);
    let a_high = (hi >> 127) ^ (hi >> 126) ^ (hi >> 121); // bits that spilled past x^128
    let reduced = lo ^ a_lo ^ fold(a_high);

    reduced.reverse_bits()
}

// --- streaming accumulator ----------------------------------------------------

/// Streaming GHASH accumulator keyed by `H = E_K(0^128)`.
#[derive(Clone)]
pub struct GHash {
    h: u128,
    /// Bit-reversed `H`, for the carry-less backend.
    h_rev: u128,
    y: u128,
    backend: Backend,
}

impl GHash {
    /// New accumulator from the 16-byte hash subkey.
    #[must_use]
    pub fn new(h: &[u8; 16]) -> Self {
        let h = u128::from_be_bytes(*h);
        Self {
            h,
            h_rev: h.reverse_bits(),
            y: 0,
            backend: select_backend(),
        }
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
            _ => gf_mul(x, self.h),
        }
    }

    /// Absorb exactly one 16-byte block.
    pub fn update_block(&mut self, block: &[u8; 16]) {
        self.y = self.mul(self.y ^ u128::from_be_bytes(*block));
    }

    /// Absorb an arbitrary-length byte string, zero-padding the final partial
    /// block on the right (GCM convention for AAD and ciphertext).
    pub fn update_padded(&mut self, data: &[u8]) {
        let mut chunks = data.chunks_exact(16);
        for c in &mut chunks {
            let mut b = [0u8; 16];
            b.copy_from_slice(c);
            self.update_block(&b);
        }
        let rem = chunks.remainder();
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
}
