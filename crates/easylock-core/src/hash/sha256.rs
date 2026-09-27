//! SHA-256 (FIPS 180-4).

use super::Hash;
use crate::secure::Zeroize;

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Streaming SHA-256 state.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha256 {
    /// Compress every 64-byte block of `blocks` (length must be a multiple of 64),
    /// using the SHA-256 instructions when the CPU has them.
    fn compress_blocks(state: &mut [u32; 8], blocks: &[u8]) {
        debug_assert_eq!(blocks.len() % 64, 0);
        if blocks.is_empty() {
            return;
        }
        #[cfg(all(target_arch = "aarch64", not(feature = "force-portable")))]
        if crate::cpu::features().sha2 {
            // SAFETY: the `sha2` feature was detected at runtime.
            unsafe { hw_arm::compress_blocks(state, blocks) };
            return;
        }
        #[cfg(all(target_arch = "x86_64", not(feature = "force-portable")))]
        if crate::cpu::features().sha2 && std_detect_sse41() {
            // SAFETY: `sha`, `sse2`, `ssse3` and `sse4.1` were detected at runtime.
            unsafe { hw_x86::compress_blocks(state, blocks) };
            return;
        }
        for b in blocks.chunks_exact(64) {
            Self::compress(state, b.try_into().expect("64 bytes"));
        }
    }

    fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (i, chunk) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);

        w.zeroize();
    }
}

#[cfg(all(target_arch = "x86_64", not(feature = "force-portable")))]
fn std_detect_sse41() -> bool {
    #[cfg(feature = "std")]
    {
        std::arch::is_x86_feature_detected!("sse4.1")
            && std::arch::is_x86_feature_detected!("ssse3")
    }
    #[cfg(not(feature = "std"))]
    {
        cfg!(all(target_feature = "sse4.1", target_feature = "ssse3"))
    }
}

/// ARMv8 SHA-256 instructions (`SHA256H`, `SHA256H2`, `SHA256SU0/1`).
#[cfg(all(target_arch = "aarch64", not(feature = "force-portable")))]
mod hw_arm {
    use super::K;
    use core::arch::aarch64::{
        vaddq_u32, vld1q_u32, vld1q_u8, vreinterpretq_u32_u8, vrev32q_u8, vsha256h2q_u32,
        vsha256hq_u32, vsha256su0q_u32, vsha256su1q_u32, vst1q_u32,
    };

    /// # Safety
    /// Requires the `sha2` target feature; `blocks.len()` must be a multiple of 64.
    #[target_feature(enable = "sha2")]
    pub(super) unsafe fn compress_blocks(state: &mut [u32; 8], blocks: &[u8]) {
        // SAFETY: all loads/stores address 16-byte windows inside `state`, `K`
        // (64 words) or the current 64-byte block; NEON accesses are unaligned-safe.
        unsafe {
            let mut abcd = vld1q_u32(state.as_ptr());
            let mut efgh = vld1q_u32(state.as_ptr().add(4));
            for block in blocks.chunks_exact(64) {
                let (abcd0, efgh0) = (abcd, efgh);
                let p = block.as_ptr();
                let mut m = [
                    vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p))),
                    vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p.add(16)))),
                    vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p.add(32)))),
                    vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p.add(48)))),
                ];
                for i in 0..16 {
                    let wk = vaddq_u32(m[i % 4], vld1q_u32(K.as_ptr().add(4 * i)));
                    let prev = abcd;
                    abcd = vsha256hq_u32(abcd, efgh, wk);
                    efgh = vsha256h2q_u32(efgh, prev, wk);
                    if i < 12 {
                        m[i % 4] = vsha256su1q_u32(
                            vsha256su0q_u32(m[i % 4], m[(i + 1) % 4]),
                            m[(i + 2) % 4],
                            m[(i + 3) % 4],
                        );
                    }
                }
                abcd = vaddq_u32(abcd, abcd0);
                efgh = vaddq_u32(efgh, efgh0);
            }
            vst1q_u32(state.as_mut_ptr(), abcd);
            vst1q_u32(state.as_mut_ptr().add(4), efgh);
        }
    }
}

/// Intel/AMD SHA extensions (`SHA256RNDS2`, `SHA256MSG1/2`).
#[cfg(all(target_arch = "x86_64", not(feature = "force-portable")))]
mod hw_x86 {
    use super::K;
    use core::arch::x86_64::{
        __m128i, _mm_add_epi32, _mm_alignr_epi8, _mm_blend_epi16, _mm_loadu_si128, _mm_set_epi64x,
        _mm_sha256msg1_epu32, _mm_sha256msg2_epu32, _mm_sha256rnds2_epu32, _mm_shuffle_epi32,
        _mm_shuffle_epi8, _mm_storeu_si128,
    };

    /// # Safety
    /// Requires `sha`, `sse2`, `ssse3` and `sse4.1`; `blocks.len()` must be a multiple of 64.
    #[allow(clippy::cast_ptr_alignment)] // only unaligned loadu/storeu
    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    pub(super) unsafe fn compress_blocks(state: &mut [u32; 8], blocks: &[u8]) {
        // SAFETY: loads/stores are unaligned and stay within `state`, `K` or the
        // current 64-byte block.
        unsafe {
            let mask = _mm_set_epi64x(0x0c0d_0e0f_0809_0a0b, 0x0405_0607_0001_0203);
            let tmp = _mm_shuffle_epi32(_mm_loadu_si128(state.as_ptr().cast::<__m128i>()), 0xB1); // CDAB
            let mut s1 = _mm_shuffle_epi32(
                _mm_loadu_si128(state.as_ptr().add(4).cast::<__m128i>()),
                0x1B,
            ); // EFGH
            let mut s0 = _mm_alignr_epi8(tmp, s1, 8); // ABEF
            s1 = _mm_blend_epi16(s1, tmp, 0xF0); // CDGH

            for block in blocks.chunks_exact(64) {
                let (abef, cdgh) = (s0, s1);
                let p = block.as_ptr().cast::<__m128i>();
                let mut m = [
                    _mm_shuffle_epi8(_mm_loadu_si128(p), mask),
                    _mm_shuffle_epi8(_mm_loadu_si128(p.add(1)), mask),
                    _mm_shuffle_epi8(_mm_loadu_si128(p.add(2)), mask),
                    _mm_shuffle_epi8(_mm_loadu_si128(p.add(3)), mask),
                ];
                for i in 0..16 {
                    let wk = _mm_add_epi32(
                        m[i % 4],
                        _mm_loadu_si128(K.as_ptr().add(4 * i).cast::<__m128i>()),
                    );
                    s1 = _mm_sha256rnds2_epu32(s1, s0, wk);
                    s0 = _mm_sha256rnds2_epu32(s0, s1, _mm_shuffle_epi32(wk, 0x0E));
                    if i < 12 {
                        // W[4i+16 .. 4i+20] from W[4i .. 4i+16]
                        let mut next = _mm_sha256msg1_epu32(m[i % 4], m[(i + 1) % 4]);
                        next =
                            _mm_add_epi32(next, _mm_alignr_epi8(m[(i + 3) % 4], m[(i + 2) % 4], 4));
                        m[i % 4] = _mm_sha256msg2_epu32(next, m[(i + 3) % 4]);
                    }
                }
                s0 = _mm_add_epi32(s0, abef);
                s1 = _mm_add_epi32(s1, cdgh);
            }

            let tmp = _mm_shuffle_epi32(s0, 0x1B); // FEBA
            s1 = _mm_shuffle_epi32(s1, 0xB1); // DCHG
            let dcba = _mm_blend_epi16(tmp, s1, 0xF0);
            let hgfe = _mm_alignr_epi8(s1, tmp, 8);
            _mm_storeu_si128(state.as_mut_ptr().cast::<__m128i>(), dcba);
            _mm_storeu_si128(state.as_mut_ptr().add(4).cast::<__m128i>(), hgfe);
        }
    }
}

impl Hash for Sha256 {
    const OUTPUT_LEN: usize = 32;
    const BLOCK_LEN: usize = 64;
    const NAME: &'static str = "sha256";

    fn init() -> Self {
        Self {
            state: H0,
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < 64 {
                return; // buffer still partial; input exhausted
            }
            let block = self.buf;
            Self::compress_blocks(&mut self.state, &block);
            self.buf_len = 0;
        }

        let full = data.len() - data.len() % 64;
        Self::compress_blocks(&mut self.state, &data[..full]);
        let rem = &data[full..];
        self.buf[..rem.len()].copy_from_slice(rem);
        self.buf_len = rem.len();
    }

    fn finalize_into(mut self, out: &mut [u8]) {
        assert_eq!(
            out.len(),
            Self::OUTPUT_LEN,
            "sha256 output must be 32 bytes"
        );
        let bit_len = self.total_len.wrapping_mul(8);

        // Pad: 0x80, then zeros, then 64-bit big-endian bit length.
        let mut pad = [0u8; 72];
        pad[0] = 0x80;
        let pad_len = if self.buf_len < 56 {
            56 - self.buf_len
        } else {
            120 - self.buf_len
        };
        self.update_no_count(&pad[..pad_len]);
        self.update_no_count(&bit_len.to_be_bytes());
        debug_assert_eq!(self.buf_len, 0);

        for (chunk, s) in out.chunks_exact_mut(4).zip(self.state.iter()) {
            chunk.copy_from_slice(&s.to_be_bytes());
        }
    }
}

impl Sha256 {
    /// Feed bytes without touching the length counter (used during padding).
    fn update_no_count(&mut self, data: &[u8]) {
        let saved = self.total_len;
        self.update(data);
        self.total_len = saved;
    }
}

impl Drop for Sha256 {
    fn drop(&mut self) {
        self.state.zeroize();
        self.buf.zeroize();
    }
}

impl core::fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sha256").finish_non_exhaustive()
    }
}

/// One-shot SHA-256.
#[must_use]
pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::init();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize_into(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::hex::encode;

    #[test]
    fn nist_and_common_vectors() {
        assert_eq!(
            encode(&hash(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            encode(&hash(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            encode(&hash(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn million_a() {
        let mut h = Sha256::init();
        for _ in 0..1000 {
            h.update(&[b'a'; 1000]);
        }
        assert_eq!(
            encode(&h.finalize_vec()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn streaming_matches_oneshot() {
        let data: alloc::vec::Vec<u8> = (0..500u32).map(|i| i as u8).collect();
        let one = hash(&data);
        let mut h = Sha256::init();
        for c in data.chunks(7) {
            h.update(c);
        }
        assert_eq!(h.finalize_vec(), one);
    }

    #[test]
    fn hardware_matches_portable() {
        let data: alloc::vec::Vec<u8> = (0..64 * 37).map(|i| (i * 7 % 256) as u8).collect();
        let mut hw = H0;
        Sha256::compress_blocks(&mut hw, &data);
        let mut sw = H0;
        for b in data.chunks_exact(64) {
            Sha256::compress(&mut sw, b.try_into().unwrap());
        }
        assert_eq!(hw, sw);
        eprintln!("sha2 hardware available: {}", crate::cpu::features().sha2);
    }
}
