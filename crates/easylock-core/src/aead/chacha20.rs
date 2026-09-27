//! ChaCha20 stream cipher (RFC 8439 §2.4), 96-bit nonce + 32-bit block counter.

use crate::secure::Zeroize;

const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

#[inline(always)]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// Produce one 64-byte ChaCha20 block for the given key/nonce/counter.
#[must_use]
pub fn block(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&CONSTANTS);
    for i in 0..8 {
        state[4 + i] =
            u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    state[12] = counter;
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes([
            nonce[4 * i],
            nonce[4 * i + 1],
            nonce[4 * i + 2],
            nonce[4 * i + 3],
        ]);
    }

    let mut working = state;
    for _ in 0..10 {
        // column rounds
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        // diagonal rounds
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        let word = working[i].wrapping_add(state[i]);
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_le_bytes());
    }
    working.zeroize();
    state.zeroize();
    out
}

/// Streaming ChaCha20 keystream / XOR transformer.
/// One keystream block from prepared state words.
fn block_from_state(state: &[u32; 16], ctr: u32) -> [u8; 64] {
    let mut init = *state;
    init[12] = ctr;
    let mut w = init;
    for _ in 0..10 {
        quarter_round(&mut w, 0, 4, 8, 12);
        quarter_round(&mut w, 1, 5, 9, 13);
        quarter_round(&mut w, 2, 6, 10, 14);
        quarter_round(&mut w, 3, 7, 11, 15);
        quarter_round(&mut w, 0, 5, 10, 15);
        quarter_round(&mut w, 1, 6, 11, 12);
        quarter_round(&mut w, 2, 7, 8, 13);
        quarter_round(&mut w, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&w[i].wrapping_add(init[i]).to_le_bytes());
    }
    w.zeroize();
    out
}

/// Initial state words for `(key, nonce)`; word 12 (the counter) is filled per block.
fn init_state(key: &[u8; 32], nonce: &[u8; 12]) -> [u32; 16] {
    let mut s = [0u32; 16];
    s[..4].copy_from_slice(&CONSTANTS);
    for i in 0..8 {
        s[4 + i] = u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    for i in 0..3 {
        s[13 + i] = u32::from_le_bytes([
            nonce[4 * i],
            nonce[4 * i + 1],
            nonce[4 * i + 2],
            nonce[4 * i + 3],
        ]);
    }
    s
}

#[cfg_attr(
    all(
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "force-portable")
    ),
    allow(dead_code)
)]
type Lanes = [u32; 4];

#[cfg_attr(
    all(
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "force-portable")
    ),
    allow(dead_code)
)]
#[inline(always)]
fn add4(a: &mut Lanes, b: &Lanes) {
    for i in 0..4 {
        a[i] = a[i].wrapping_add(b[i]);
    }
}

#[cfg_attr(
    all(
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "force-portable")
    ),
    allow(dead_code)
)]
#[inline(always)]
fn xor_rot4(d: &mut Lanes, a: &Lanes, r: u32) {
    for i in 0..4 {
        d[i] = (d[i] ^ a[i]).rotate_left(r);
    }
}

#[cfg_attr(
    all(
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "force-portable")
    ),
    allow(dead_code)
)]
#[inline(always)]
fn qr4(x: &mut [Lanes; 16], a: usize, b: usize, c: usize, d: usize) {
    let (xb, xd) = (x[b], x[d]);
    add4(&mut x[a], &xb);
    let xa = x[a];
    xor_rot4(&mut x[d], &xa, 16);
    let xd2 = x[d];
    add4(&mut x[c], &xd2);
    let xc = x[c];
    xor_rot4(&mut x[b], &xc, 12);
    let xb2 = x[b];
    add4(&mut x[a], &xb2);
    let xa2 = x[a];
    xor_rot4(&mut x[d], &xa2, 8);
    let xd3 = x[d];
    add4(&mut x[c], &xd3);
    let xc2 = x[c];
    xor_rot4(&mut x[b], &xc2, 7);
    let _ = xd;
}

/// Four consecutive keystream blocks (counters `ctr..ctr+4`) computed side by side.
/// The lane-major layout (`[word][block]`) lets the compiler use 128-bit SIMD
/// (NEON / SSE2) for every add, xor and rotate, with no data-dependent branches.
#[cfg_attr(
    all(
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "force-portable")
    ),
    allow(dead_code)
)]
fn blocks4_portable(state: &[u32; 16], ctr: u32, out: &mut [u8; 256]) {
    let mut init = [[0u32; 4]; 16];
    for (w, lanes) in init.iter_mut().enumerate() {
        *lanes = [state[w]; 4];
    }
    init[12] = [
        ctr,
        ctr.wrapping_add(1),
        ctr.wrapping_add(2),
        ctr.wrapping_add(3),
    ];
    let mut x = init;
    for _ in 0..10 {
        qr4(&mut x, 0, 4, 8, 12);
        qr4(&mut x, 1, 5, 9, 13);
        qr4(&mut x, 2, 6, 10, 14);
        qr4(&mut x, 3, 7, 11, 15);
        qr4(&mut x, 0, 5, 10, 15);
        qr4(&mut x, 1, 6, 11, 12);
        qr4(&mut x, 2, 7, 8, 13);
        qr4(&mut x, 3, 4, 9, 14);
    }
    for w in 0..16 {
        for blk in 0..4 {
            let v = x[w][blk].wrapping_add(init[w][blk]);
            out[blk * 64 + w * 4..blk * 64 + w * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
    }
    x.zeroize_lanes();
}

/// Four keystream blocks, using NEON / SSE2 when available (both are baseline on
/// their architectures, so no runtime detection is needed).
#[inline]
fn blocks4(state: &[u32; 16], ctr: u32, out: &mut [u8; 256]) {
    #[cfg(all(
        target_arch = "aarch64",
        target_endian = "little",
        not(feature = "force-portable")
    ))]
    {
        // SAFETY: NEON is mandatory on aarch64; the function only reads `state` and
        // writes exactly 256 bytes into `out`.
        unsafe { simd_neon::blocks4(state, ctr, out) };
    }
    #[cfg(all(target_arch = "x86_64", not(feature = "force-portable")))]
    {
        // SAFETY: SSE2 is part of the x86-64 baseline; same bounds as above.
        unsafe { simd_sse2::blocks4(state, ctr, out) };
    }
    #[cfg(any(
        feature = "force-portable",
        not(any(
            all(target_arch = "aarch64", target_endian = "little"),
            target_arch = "x86_64"
        ))
    ))]
    blocks4_portable(state, ctr, out);
}

#[cfg(all(
    target_arch = "aarch64",
    target_endian = "little",
    not(feature = "force-portable")
))]
mod simd_neon {
    use core::arch::aarch64::{
        uint32x4_t, vaddq_u32, vdupq_n_u32, veorq_u32, vld1q_u32, vreinterpretq_u16_u32,
        vreinterpretq_u32_u16, vreinterpretq_u32_u64, vreinterpretq_u64_u32, vreinterpretq_u8_u32,
        vrev32q_u16, vshlq_n_u32, vsriq_n_u32, vst1q_u8, vtrn1q_u32, vtrn1q_u64, vtrn2q_u32,
        vtrn2q_u64,
    };

    macro_rules! rotl {
        ($v:expr, 16) => {
            vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32($v)))
        };
        ($v:expr, $n:literal) => {
            vsriq_n_u32::<{ 32 - $n }>(vshlq_n_u32::<$n>($v), $v)
        };
    }

    macro_rules! qr {
        ($x:ident, $a:literal, $b:literal, $c:literal, $d:literal) => {
            $x[$a] = vaddq_u32($x[$a], $x[$b]);
            $x[$d] = rotl!(veorq_u32($x[$d], $x[$a]), 16);
            $x[$c] = vaddq_u32($x[$c], $x[$d]);
            $x[$b] = rotl!(veorq_u32($x[$b], $x[$c]), 12);
            $x[$a] = vaddq_u32($x[$a], $x[$b]);
            $x[$d] = rotl!(veorq_u32($x[$d], $x[$a]), 8);
            $x[$c] = vaddq_u32($x[$c], $x[$d]);
            $x[$b] = rotl!(veorq_u32($x[$b], $x[$c]), 7);
        };
    }

    /// # Safety
    /// Requires NEON (always present on aarch64).
    #[target_feature(enable = "neon")]
    pub(super) unsafe fn blocks4(state: &[u32; 16], ctr: u32, out: &mut [u8; 256]) {
        let mut init: [uint32x4_t; 16] = [vdupq_n_u32(0); 16];
        for (w, v) in init.iter_mut().enumerate() {
            *v = vdupq_n_u32(state[w]);
        }
        let ctrs = [
            ctr,
            ctr.wrapping_add(1),
            ctr.wrapping_add(2),
            ctr.wrapping_add(3),
        ];
        // SAFETY: `ctrs` is 4 initialised u32s, exactly one 128-bit load.
        init[12] = unsafe { vld1q_u32(ctrs.as_ptr()) };
        let mut x = init;
        for _ in 0..10 {
            qr!(x, 0, 4, 8, 12);
            qr!(x, 1, 5, 9, 13);
            qr!(x, 2, 6, 10, 14);
            qr!(x, 3, 7, 11, 15);
            qr!(x, 0, 5, 10, 15);
            qr!(x, 1, 6, 11, 12);
            qr!(x, 2, 7, 8, 13);
            qr!(x, 3, 4, 9, 14);
        }
        for w in 0..16 {
            x[w] = vaddq_u32(x[w], init[w]);
        }
        // Transpose each group of 4 words from [word][block] to [block][word].
        let p = out.as_mut_ptr();
        for g in 0..4 {
            let (a, b, c, d) = (x[4 * g], x[4 * g + 1], x[4 * g + 2], x[4 * g + 3]);
            let t0 = vreinterpretq_u64_u32(vtrn1q_u32(a, b));
            let t1 = vreinterpretq_u64_u32(vtrn2q_u32(a, b));
            let t2 = vreinterpretq_u64_u32(vtrn1q_u32(c, d));
            let t3 = vreinterpretq_u64_u32(vtrn2q_u32(c, d));
            let rows = [
                vreinterpretq_u32_u64(vtrn1q_u64(t0, t2)),
                vreinterpretq_u32_u64(vtrn1q_u64(t1, t3)),
                vreinterpretq_u32_u64(vtrn2q_u64(t0, t2)),
                vreinterpretq_u32_u64(vtrn2q_u64(t1, t3)),
            ];
            for (blk, row) in rows.iter().enumerate() {
                // SAFETY: blk, g < 4, so the 16-byte store ends at byte
                // blk*64 + g*16 + 16 <= 256, within `out`; byte stores need no alignment.
                unsafe { vst1q_u8(p.add(blk * 64 + g * 16), vreinterpretq_u8_u32(*row)) };
            }
        }
    }
}

#[cfg(all(target_arch = "x86_64", not(feature = "force-portable")))]
mod simd_sse2 {
    use core::arch::x86_64::{
        __m128i, _mm_add_epi32, _mm_or_si128, _mm_set1_epi32, _mm_setr_epi32, _mm_setzero_si128,
        _mm_slli_epi32, _mm_srli_epi32, _mm_storeu_si128, _mm_unpackhi_epi32, _mm_unpackhi_epi64,
        _mm_unpacklo_epi32, _mm_unpacklo_epi64, _mm_xor_si128,
    };

    macro_rules! rotl {
        ($v:expr, $n:literal) => {
            _mm_or_si128(_mm_slli_epi32::<$n>($v), _mm_srli_epi32::<{ 32 - $n }>($v))
        };
    }

    macro_rules! qr {
        ($x:ident, $a:literal, $b:literal, $c:literal, $d:literal) => {
            $x[$a] = _mm_add_epi32($x[$a], $x[$b]);
            $x[$d] = rotl!(_mm_xor_si128($x[$d], $x[$a]), 16);
            $x[$c] = _mm_add_epi32($x[$c], $x[$d]);
            $x[$b] = rotl!(_mm_xor_si128($x[$b], $x[$c]), 12);
            $x[$a] = _mm_add_epi32($x[$a], $x[$b]);
            $x[$d] = rotl!(_mm_xor_si128($x[$d], $x[$a]), 8);
            $x[$c] = _mm_add_epi32($x[$c], $x[$d]);
            $x[$b] = rotl!(_mm_xor_si128($x[$b], $x[$c]), 7);
        };
    }

    /// # Safety
    /// Requires SSE2 (always present on x86-64).
    #[target_feature(enable = "sse2")]
    pub(super) unsafe fn blocks4(state: &[u32; 16], ctr: u32, out: &mut [u8; 256]) {
        let mut init = [_mm_setzero_si128(); 16];
        for (w, v) in init.iter_mut().enumerate() {
            *v = _mm_set1_epi32(state[w] as i32);
        }
        init[12] = _mm_setr_epi32(
            ctr as i32,
            ctr.wrapping_add(1) as i32,
            ctr.wrapping_add(2) as i32,
            ctr.wrapping_add(3) as i32,
        );
        let mut x = init;
        for _ in 0..10 {
            qr!(x, 0, 4, 8, 12);
            qr!(x, 1, 5, 9, 13);
            qr!(x, 2, 6, 10, 14);
            qr!(x, 3, 7, 11, 15);
            qr!(x, 0, 5, 10, 15);
            qr!(x, 1, 6, 11, 12);
            qr!(x, 2, 7, 8, 13);
            qr!(x, 3, 4, 9, 14);
        }
        for w in 0..16 {
            x[w] = _mm_add_epi32(x[w], init[w]);
        }
        #[allow(clippy::cast_ptr_alignment)] // only used with the unaligned `storeu`
        let p = out.as_mut_ptr().cast::<__m128i>();
        for g in 0..4 {
            let (a, b, c, d) = (x[4 * g], x[4 * g + 1], x[4 * g + 2], x[4 * g + 3]);
            let t0 = _mm_unpacklo_epi32(a, b); // a0 b0 a1 b1
            let t1 = _mm_unpackhi_epi32(a, b); // a2 b2 a3 b3
            let t2 = _mm_unpacklo_epi32(c, d); // c0 d0 c1 d1
            let t3 = _mm_unpackhi_epi32(c, d); // c2 d2 c3 d3
            let rows = [
                _mm_unpacklo_epi64(t0, t2),
                _mm_unpackhi_epi64(t0, t2),
                _mm_unpacklo_epi64(t1, t3),
                _mm_unpackhi_epi64(t1, t3),
            ];
            for (blk, row) in rows.iter().enumerate() {
                // SAFETY: blk, g < 4, so lane blk*4 + g < 16; 16 lanes × 16 bytes
                // = the 256-byte `out`. `storeu` has no alignment requirement.
                unsafe { _mm_storeu_si128(p.add(blk * 4 + g), *row) };
            }
        }
    }
}

#[cfg_attr(
    all(
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "force-portable")
    ),
    allow(dead_code)
)]
trait ZeroLanes {
    fn zeroize_lanes(&mut self);
}
#[cfg_attr(
    all(
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "force-portable")
    ),
    allow(dead_code)
)]
impl ZeroLanes for [Lanes; 16] {
    fn zeroize_lanes(&mut self) {
        for l in self.iter_mut() {
            l.zeroize();
        }
    }
}

#[inline(always)]
fn xor_into(data: &mut [u8], ks: &[u8]) {
    let mut d = data.chunks_exact_mut(8);
    let mut k = ks.chunks_exact(8);
    for (a, b) in (&mut d).zip(&mut k) {
        let v = u64::from_ne_bytes(a.try_into().expect("8"))
            ^ u64::from_ne_bytes(b.try_into().expect("8"));
        a.copy_from_slice(&v.to_ne_bytes());
    }
    for (a, b) in d.into_remainder().iter_mut().zip(k.remainder()) {
        *a ^= b;
    }
}

/// Streaming ChaCha20 (RFC 8439) keystream XOR.
pub struct ChaCha20 {
    state: [u32; 16],
    counter: u32,
    ks: [u8; 256],
    ks_len: usize,
    ks_pos: usize,
}

impl ChaCha20 {
    #[must_use]
    pub fn new(key: &[u8; 32], nonce: &[u8; 12], initial_counter: u32) -> Self {
        Self {
            state: init_state(key, nonce),
            counter: initial_counter,
            ks: [0u8; 256],
            ks_len: 0,
            ks_pos: 0,
        }
    }

    fn refill(&mut self) {
        blocks4(&self.state, self.counter, &mut self.ks);
        self.counter = self.counter.wrapping_add(4);
        self.ks_len = 256;
        self.ks_pos = 0;
    }

    /// XOR the keystream into `data` (encrypts or decrypts in place).
    pub fn apply(&mut self, mut data: &mut [u8]) {
        // 1. use up buffered keystream
        if self.ks_pos < self.ks_len {
            let n = (self.ks_len - self.ks_pos).min(data.len());
            xor_into(&mut data[..n], &self.ks[self.ks_pos..self.ks_pos + n]);
            self.ks_pos += n;
            data = &mut data[n..];
        }
        // 2. whole 256-byte groups straight from fresh keystream
        let mut buf = [0u8; 256];
        while data.len() >= 256 {
            blocks4(&self.state, self.counter, &mut buf);
            self.counter = self.counter.wrapping_add(4);
            xor_into(&mut data[..256], &buf);
            data = &mut data[256..];
        }
        buf.zeroize();
        // 3. tail: buffer fresh keystream (one block if that suffices) for later calls
        if !data.is_empty() {
            if data.len() <= 64 {
                let one = block_from_state(&self.state, self.counter);
                self.ks[..64].copy_from_slice(&one);
                self.counter = self.counter.wrapping_add(1);
                self.ks_len = 64;
                self.ks_pos = 0;
            } else {
                self.refill();
            }
            let n = data.len();
            xor_into(data, &self.ks[..n]);
            self.ks_pos = n;
        }
    }
}

impl Drop for ChaCha20 {
    fn drop(&mut self) {
        self.state.zeroize();
        self.ks.zeroize();
        self.counter.zeroize();
    }
}

impl core::fmt::Debug for ChaCha20 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChaCha20").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::hex::{decode, encode};

    // RFC 8439 §2.3.2
    #[test]
    fn rfc8439_block_function() {
        let key: [u8; 32] = (0..32).collect::<alloc::vec::Vec<u8>>().try_into().unwrap();
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let b = block(&key, &nonce, 1);
        assert_eq!(
            encode(&b),
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
             d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
        );
    }

    // RFC 8439 §2.4.2
    #[test]
    fn rfc8439_encryption() {
        let key: [u8; 32] = (0..32).collect::<alloc::vec::Vec<u8>>().try_into().unwrap();
        let nonce: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut buf = plaintext.to_vec();
        ChaCha20::new(&key, &nonce, 1).apply(&mut buf);
        let want = "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b\
                    f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8\
                    07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736\
                    5af90bbf74a35be6b40b8eedf2785e42874d";
        assert_eq!(encode(&buf), want);

        ChaCha20::new(&key, &nonce, 1).apply(&mut buf);
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn streaming_matches_block() {
        let key = [7u8; 32];
        let nonce = [3u8; 12];
        let mut a = alloc::vec![0u8; 200];
        let mut b = a.clone();
        ChaCha20::new(&key, &nonce, 0).apply(&mut a);
        let mut c = ChaCha20::new(&key, &nonce, 0);
        for chunk in b.chunks_mut(17) {
            c.apply(chunk);
        }
        assert_eq!(a, b);
        let _ = decode("00");
    }

    #[test]
    fn any_split_matches_single_block_function() {
        let key = [9u8; 32];
        let nonce = [5u8; 12];
        let mut reference = alloc::vec![0u8; 1500];
        for (i, chunk) in reference.chunks_mut(64).enumerate() {
            let ks = block(&key, &nonce, 7 + i as u32);
            for (b, k) in chunk.iter_mut().zip(ks.iter()) {
                *b ^= k;
            }
        }
        for splits in [
            &[1usize, 63, 64, 300, 1072][..],
            &[256, 256, 988],
            &[1500],
            &[7; 214],
        ] {
            let mut buf = alloc::vec![0u8; 1500];
            let mut c = ChaCha20::new(&key, &nonce, 7);
            let mut pos = 0;
            for &n in splits {
                let end = (pos + n).min(1500);
                c.apply(&mut buf[pos..end]);
                pos = end;
            }
            c.apply(&mut buf[pos..]);
            assert_eq!(buf, reference, "splits {splits:?}");
        }
    }

    #[test]
    fn simd_blocks_match_portable() {
        let state = init_state(&[0xa5; 32], &[0x3c; 12]);
        for ctr in [0u32, 1, 7, u32::MAX - 1] {
            let (mut a, mut b) = ([0u8; 256], [0u8; 256]);
            blocks4(&state, ctr, &mut a);
            blocks4_portable(&state, ctr, &mut b);
            assert_eq!(a, b, "ctr {ctr}");
        }
    }
}
