//! GHASH — the GF(2^128) universal hash underlying AES-GCM (NIST SP 800-38D).
//!
//! The portable multiply is the bit-at-a-time right-shift algorithm from
//! McGrew & Viega: 128 iterations, no secret-dependent branches or table
//! lookups, so it is constant time. A carry-less-multiply path (PCLMULQDQ /
//! PMULL) can be dropped in behind [`GHash`] later without changing callers.

use crate::secure::Zeroize;

/// Reduction constant R = 0xE1 || 0^120 (field poly x^128 + x^7 + x^2 + x + 1).
const R: u128 = 0xe100_0000_0000_0000_0000_0000_0000_0000;

/// Multiply two GF(2^128) elements (GCM bit convention: block byte 0 bit 7 is
/// the most significant coefficient).
#[must_use]
pub fn gf_mul(x: u128, h: u128) -> u128 {
    let mut z = 0u128;
    let mut v = h;
    let mut i = 0;
    while i < 128 {
        // NIST bit i of x == u128 bit (127 - i).
        let xi = (x >> (127 - i)) & 1;
        z ^= 0u128.wrapping_sub(xi) & v;

        let lsb = v & 1;
        v >>= 1;
        v ^= 0u128.wrapping_sub(lsb) & R;

        i += 1;
    }
    z
}

/// Streaming GHASH accumulator keyed by `H = E_K(0^128)`.
#[derive(Clone)]
pub struct GHash {
    h: u128,
    y: u128,
}

impl GHash {
    /// New accumulator from the 16-byte hash subkey.
    #[must_use]
    pub fn new(h: &[u8; 16]) -> Self {
        Self {
            h: u128::from_be_bytes(*h),
            y: 0,
        }
    }

    /// Absorb exactly one 16-byte block.
    pub fn update_block(&mut self, block: &[u8; 16]) {
        self.y = gf_mul(self.y ^ u128::from_be_bytes(*block), self.h);
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
        f.debug_struct("GHash").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::hex::{decode, encode};

    // NIST GCM spec worked example: H and a single-block GHASH step.
    #[test]
    fn ghash_single_block() {
        let h: [u8; 16] = decode("66e94bd4ef8a2c3b884cfa59ca342b2e")
            .unwrap()
            .try_into()
            .unwrap();
        // GHASH of the empty message with only the length block (A=C=empty).
        let g = GHash::new(&h);
        let s = g.finalize(0, 0);
        assert_eq!(encode(&s), "00000000000000000000000000000000");
    }

    #[test]
    fn gf_mul_identity_and_zero() {
        // x * 0 == 0
        assert_eq!(gf_mul(0x1234_5678_9abc_def0_1122_3344_5566_7788, 0), 0);
        // The multiplicative identity in this bit convention is 0x80||0^120.
        let one = 1u128 << 127;
        let x = 0xdead_beef_0000_0000_cafe_babe_0000_0001u128;
        assert_eq!(gf_mul(x, one), x);
    }
}
