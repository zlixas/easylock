//! Poly1305 one-time authenticator (RFC 8439 §2.5).
//!
//! Implemented with 26-bit limbs over five `u32`s, accumulating products in
//! `u64`. The key (`r`, `s`) is single-use; reusing it across messages breaks
//! the security proof. [`Poly1305`] scrubs `r`/`s`/`h` on drop.

use crate::ct::{ct_eq_fixed, Choice};
use crate::secure::Zeroize;

/// Poly1305 state. Construct with a 32-byte one-time key.
#[derive(Clone)]
pub struct Poly1305 {
    r: [u32; 5],
    s: [u32; 4],
    h: [u32; 5],
    buf: [u8; 16],
    buf_len: usize,
}

impl Poly1305 {
    /// Initialize from a 32-byte key: first 16 bytes are `r` (clamped), last 16 `s`.
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        let t0 = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
        let t1 = u32::from_le_bytes([key[4], key[5], key[6], key[7]]);
        let t2 = u32::from_le_bytes([key[8], key[9], key[10], key[11]]);
        let t3 = u32::from_le_bytes([key[12], key[13], key[14], key[15]]);

        // Clamp r per RFC 8439 and split into 26-bit limbs.
        let r = [
            t0 & 0x03ff_ffff,
            ((t0 >> 26) | (t1 << 6)) & 0x03ff_ff03,
            ((t1 >> 20) | (t2 << 12)) & 0x03ff_c0ff,
            ((t2 >> 14) | (t3 << 18)) & 0x03f0_3fff,
            (t3 >> 8) & 0x000f_ffff,
        ];

        let s = [
            u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
            u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
            u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
            u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
        ];

        Self {
            r,
            s,
            h: [0u32; 5],
            buf: [0u8; 16],
            buf_len: 0,
        }
    }

    fn block(&mut self, chunk: &[u8; 16], final_block: bool) {
        let hibit = u32::from(!final_block) << 24; // 2^128 for full blocks

        let t0 = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let t1 = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
        let t2 = u32::from_le_bytes([chunk[8], chunk[9], chunk[10], chunk[11]]);
        let t3 = u32::from_le_bytes([chunk[12], chunk[13], chunk[14], chunk[15]]);

        self.h[0] += t0 & 0x03ff_ffff;
        self.h[1] += ((t0 >> 26) | (t1 << 6)) & 0x03ff_ffff;
        self.h[2] += ((t1 >> 20) | (t2 << 12)) & 0x03ff_ffff;
        self.h[3] += ((t2 >> 14) | (t3 << 18)) & 0x03ff_ffff;
        self.h[4] += (t3 >> 8) | hibit;

        let r = self.r;
        let h = self.h;
        // Precompute 5*r[i] for the reduction modulo 2^130 - 5.
        let r5 = [r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5];

        let d0 = u64::from(h[0]) * u64::from(r[0])
            + u64::from(h[1]) * u64::from(r5[3])
            + u64::from(h[2]) * u64::from(r5[2])
            + u64::from(h[3]) * u64::from(r5[1])
            + u64::from(h[4]) * u64::from(r5[0]);
        let d1 = u64::from(h[0]) * u64::from(r[1])
            + u64::from(h[1]) * u64::from(r[0])
            + u64::from(h[2]) * u64::from(r5[3])
            + u64::from(h[3]) * u64::from(r5[2])
            + u64::from(h[4]) * u64::from(r5[1]);
        let d2 = u64::from(h[0]) * u64::from(r[2])
            + u64::from(h[1]) * u64::from(r[1])
            + u64::from(h[2]) * u64::from(r[0])
            + u64::from(h[3]) * u64::from(r5[3])
            + u64::from(h[4]) * u64::from(r5[2]);
        let d3 = u64::from(h[0]) * u64::from(r[3])
            + u64::from(h[1]) * u64::from(r[2])
            + u64::from(h[2]) * u64::from(r[1])
            + u64::from(h[3]) * u64::from(r[0])
            + u64::from(h[4]) * u64::from(r5[3]);
        let d4 = u64::from(h[0]) * u64::from(r[4])
            + u64::from(h[1]) * u64::from(r[3])
            + u64::from(h[2]) * u64::from(r[2])
            + u64::from(h[3]) * u64::from(r[1])
            + u64::from(h[4]) * u64::from(r[0]);

        let mut c: u64;
        c = d0 >> 26;
        self.h[0] = (d0 as u32) & 0x03ff_ffff;
        let d1 = d1 + c;
        c = d1 >> 26;
        self.h[1] = (d1 as u32) & 0x03ff_ffff;
        let d2 = d2 + c;
        c = d2 >> 26;
        self.h[2] = (d2 as u32) & 0x03ff_ffff;
        let d3 = d3 + c;
        c = d3 >> 26;
        self.h[3] = (d3 as u32) & 0x03ff_ffff;
        let d4 = d4 + c;
        c = d4 >> 26;
        self.h[4] = (d4 as u32) & 0x03ff_ffff;
        self.h[0] += (c as u32) * 5;
        c = u64::from(self.h[0] >> 26);
        self.h[0] &= 0x03ff_ffff;
        self.h[1] += c as u32;
    }

    /// Absorb message bytes.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let take = (16 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < 16 {
                return; // buffer still partial; input exhausted
            }
            let b = self.buf;
            self.block(&b, false);
            self.buf_len = 0;
        }
        let mut chunks = data.chunks_exact(16);
        for chunk in &mut chunks {
            let mut b = [0u8; 16];
            b.copy_from_slice(chunk);
            self.block(&b, false);
        }
        let rem = chunks.remainder();
        self.buf[..rem.len()].copy_from_slice(rem);
        self.buf_len = rem.len();
    }

    /// Finish and produce the 16-byte tag.
    ///
    /// Reduction and final serialization follow the public-domain
    /// `poly1305-donna` 32-bit reference (5x26-bit limbs).
    #[must_use]
    pub fn finalize(mut self) -> [u8; 16] {
        if self.buf_len > 0 {
            let n = self.buf_len;
            self.buf[n] = 1;
            for b in &mut self.buf[n + 1..] {
                *b = 0;
            }
            let b = self.buf;
            self.block(&b, true);
        }

        let (mut h0, mut h1, mut h2, mut h3, mut h4) =
            (self.h[0], self.h[1], self.h[2], self.h[3], self.h[4]);

        // Fully carry h.
        let mut c = h1 >> 26;
        h1 &= 0x03ff_ffff;
        h2 += c;
        c = h2 >> 26;
        h2 &= 0x03ff_ffff;
        h3 += c;
        c = h3 >> 26;
        h3 &= 0x03ff_ffff;
        h4 += c;
        c = h4 >> 26;
        h4 &= 0x03ff_ffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x03ff_ffff;
        h1 += c;

        // Compute h + -p.
        let mut g0 = h0 + 5;
        c = g0 >> 26;
        g0 &= 0x03ff_ffff;
        let mut g1 = h1 + c;
        c = g1 >> 26;
        g1 &= 0x03ff_ffff;
        let mut g2 = h2 + c;
        c = g2 >> 26;
        g2 &= 0x03ff_ffff;
        let mut g3 = h3 + c;
        c = g3 >> 26;
        g3 &= 0x03ff_ffff;
        let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

        // mask = all-ones when h >= p (use g), zero otherwise.
        let mut mask = (g4 >> 31).wrapping_sub(1);
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        let g4 = g4 & mask;
        mask = !mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;

        // Pack the low 128 bits into four 32-bit words.
        let w0 = h0 | (h1 << 26);
        let w1 = (h1 >> 6) | (h2 << 20);
        let w2 = (h2 >> 12) | (h3 << 14);
        let w3 = (h3 >> 18) | (h4 << 8);

        // mac = (h + s) mod 2^128
        let mut f = 0u64;
        let mut out = [0u8; 16];
        for (i, &w) in [w0, w1, w2, w3].iter().enumerate() {
            f += u64::from(w) + u64::from(self.s[i]);
            out[i * 4..i * 4 + 4].copy_from_slice(&(f as u32).to_le_bytes());
            f >>= 32;
        }
        out
    }

    /// Verify `tag` in constant time.
    #[must_use]
    pub fn verify(self, tag: &[u8; 16]) -> Choice {
        ct_eq_fixed(&self.finalize(), tag)
    }

    /// One-shot MAC.
    #[must_use]
    pub fn mac(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
        let mut m = Self::new(key);
        m.update(msg);
        m.finalize()
    }
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        self.r.zeroize();
        self.s.zeroize();
        self.h.zeroize();
        self.buf.zeroize();
    }
}

impl core::fmt::Debug for Poly1305 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Poly1305").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::hex::encode;

    // RFC 8439 §2.5.2
    #[test]
    fn rfc8439_vector() {
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let msg = b"Cryptographic Forum Research Group";
        assert_eq!(
            encode(&Poly1305::mac(&key, msg)),
            "a8061dc1305136c6c22b8baf0c0127a9"
        );
    }

    #[test]
    fn rfc8439_a3_all_zero() {
        let key = [0u8; 32];
        let msg = [0u8; 64];
        assert_eq!(
            encode(&Poly1305::mac(&key, &msg)),
            "00000000000000000000000000000000"
        );
    }

    #[test]
    fn streaming_matches_oneshot() {
        let key = [7u8; 32];
        let msg: alloc::vec::Vec<u8> = (0..333u32).map(|i| i as u8).collect();
        let one = Poly1305::mac(&key, &msg);
        let mut m = Poly1305::new(&key);
        for c in msg.chunks(5) {
            m.update(c);
        }
        assert_eq!(m.finalize(), one);
    }
}
