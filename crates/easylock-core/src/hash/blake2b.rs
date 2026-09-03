//! BLAKE2b (RFC 7693), with keying and arbitrary (1..=64 byte) output.
//!
//! Primarily here as the building block for [`crate::kdf::argon2`], but it is a
//! perfectly good standalone hash / MAC.

use crate::secure::Zeroize;

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

const BLOCK_LEN: usize = 128;

#[inline(always)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn compress(h: &mut [u64; 8], block: &[u8; BLOCK_LEN], t: u128, last: bool) {
    let mut m = [0u64; 16];
    for (i, chunk) in block.chunks_exact(8).enumerate() {
        m[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }

    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    if last {
        v[14] = !v[14];
    }

    for s in &SIGMA {
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
    m.zeroize();
}

/// Streaming BLAKE2b state.
#[derive(Clone)]
pub struct Blake2b {
    h: [u64; 8],
    buf: [u8; BLOCK_LEN],
    buf_len: usize,
    counter: u128,
    out_len: usize,
}

impl Blake2b {
    /// New hasher producing `out_len` bytes (1..=64), optionally keyed.
    ///
    /// # Panics
    /// Panics if `out_len` is 0 or > 64, or `key.len() > 64`.
    #[must_use]
    pub fn new(out_len: usize, key: &[u8]) -> Self {
        assert!(
            (1..=64).contains(&out_len),
            "blake2b output must be 1..=64 bytes"
        );
        assert!(key.len() <= 64, "blake2b key must be <= 64 bytes");

        let mut h = IV;
        h[0] ^= 0x0101_0000 ^ ((key.len() as u64) << 8) ^ (out_len as u64);

        let mut state = Self {
            h,
            buf: [0u8; BLOCK_LEN],
            buf_len: 0,
            counter: 0,
            out_len,
        };
        if !key.is_empty() {
            let mut block = [0u8; BLOCK_LEN];
            block[..key.len()].copy_from_slice(key);
            state.update(&block);
            block.zeroize();
        }
        state
    }

    /// Absorb input.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let take = (BLOCK_LEN - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < BLOCK_LEN || data.is_empty() {
                return;
            }
            self.counter += BLOCK_LEN as u128;
            let block = self.buf;
            compress(&mut self.h, &block, self.counter, false);
            self.buf_len = 0;
        }
        while data.len() > BLOCK_LEN {
            self.counter += BLOCK_LEN as u128;
            let mut block = [0u8; BLOCK_LEN];
            block.copy_from_slice(&data[..BLOCK_LEN]);
            compress(&mut self.h, &block, self.counter, false);
            data = &data[BLOCK_LEN..];
        }
        self.buf[..data.len()].copy_from_slice(data);
        self.buf_len = data.len();
    }

    /// Finish and write exactly `out_len` bytes.
    pub fn finalize_into(mut self, out: &mut [u8]) {
        assert_eq!(out.len(), self.out_len, "blake2b output length mismatch");
        self.counter += self.buf_len as u128;
        for b in &mut self.buf[self.buf_len..] {
            *b = 0;
        }
        let block = self.buf;
        compress(&mut self.h, &block, self.counter, true);

        let mut full = [0u8; 64];
        for (i, word) in self.h.iter().enumerate() {
            full[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        out.copy_from_slice(&full[..self.out_len]);
        full.zeroize();
    }
}

impl Drop for Blake2b {
    fn drop(&mut self) {
        self.h.zeroize();
        self.buf.zeroize();
    }
}

impl core::fmt::Debug for Blake2b {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Blake2b").finish_non_exhaustive()
    }
}

/// One-shot BLAKE2b with `out_len` output bytes.
pub fn hash(out_len: usize, key: &[u8], data: &[u8]) -> alloc::vec::Vec<u8> {
    let mut h = Blake2b::new(out_len, key);
    h.update(data);
    let mut out = alloc::vec![0u8; out_len];
    h.finalize_into(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::hex::encode;

    // RFC 7693 Appendix A.
    #[test]
    fn rfc7693_abc() {
        assert_eq!(
            encode(&hash(64, &[], b"abc")),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
    }

    #[test]
    fn empty_blake2b_512() {
        assert_eq!(
            encode(&hash(64, &[], b"")),
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
             d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        );
    }

    // BLAKE2b-256 keyed (from the official blake2 test vectors: key = 00..3f,
    // input = 00).
    #[test]
    fn keyed_one_byte() {
        let key: [u8; 64] = core::array::from_fn(|i| i as u8);
        assert_eq!(
            encode(&hash(64, &key, &[0x00])),
            "961f6dd1e4dd30f63901690c512e78e4b45e4742ed197c3c5e45c549fd25f2e4\
             187b0bc9fe30492b16b0d0bc4ef9b0f34c7003fac09a5ef1532e69430234cebd"
        );
    }

    #[test]
    fn streaming_matches_oneshot() {
        let data: alloc::vec::Vec<u8> = (0..500u32).map(|i| i as u8).collect();
        let one = hash(48, &[], &data);
        let mut h = Blake2b::new(48, &[]);
        for c in data.chunks(7) {
            h.update(c);
        }
        let mut got = [0u8; 48];
        h.finalize_into(&mut got);
        assert_eq!(&got[..], &one[..]);
    }
}
