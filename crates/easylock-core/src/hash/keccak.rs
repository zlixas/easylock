//! `Keccak-f[1600]` sponge, exposing:
//!
//! * [`Keccak256`] — original Keccak padding (`0x01` domain byte). This is what
//!   Ethereum calls `keccak256`.
//! * [`Sha3_256`] — FIPS 202 SHA3-256 (`0x06` domain byte).
//!
//! Both use rate = 1088 bits (136 bytes), capacity = 512 bits.

use super::Hash;
use crate::secure::Zeroize;

const ROUNDS: usize = 24;
const RATE: usize = 136; // (1600 - 512) / 8

const RC: [u64; ROUNDS] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

const ROTC: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PILN: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

fn keccak_f(st: &mut [u64; 25]) {
    for round in RC.iter().take(ROUNDS) {
        // Theta
        let mut bc = [0u64; 5];
        for i in 0..5 {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }
        for i in 0..5 {
            let t = bc[(i + 4) % 5] ^ bc[(i + 1) % 5].rotate_left(1);
            for j in (0..25).step_by(5) {
                st[j + i] ^= t;
            }
        }

        // Rho + Pi
        let mut t = st[1];
        for i in 0..24 {
            let j = PILN[i];
            let tmp = st[j];
            st[j] = t.rotate_left(ROTC[i]);
            t = tmp;
        }

        // Chi
        for j in (0..25).step_by(5) {
            let row = [st[j], st[j + 1], st[j + 2], st[j + 3], st[j + 4]];
            for i in 0..5 {
                st[j + i] = row[i] ^ ((!row[(i + 1) % 5]) & row[(i + 2) % 5]);
            }
        }

        // Iota
        st[0] ^= *round;
    }
}

/// Shared sponge state parameterized by domain-separation byte.
#[derive(Clone)]
struct Sponge<const DOMAIN: u8> {
    state: [u64; 25],
    buf: [u8; RATE],
    buf_len: usize,
}

impl<const DOMAIN: u8> Sponge<DOMAIN> {
    fn new() -> Self {
        Self {
            state: [0u64; 25],
            buf: [0u8; RATE],
            buf_len: 0,
        }
    }

    fn absorb_block(&mut self) {
        for (i, chunk) in self.buf.chunks_exact(8).enumerate() {
            self.state[i] ^= u64::from_le_bytes(chunk.try_into().unwrap());
        }
        keccak_f(&mut self.state);
    }

    fn update(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let take = (RATE - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < RATE {
                return; // buffer still partial; input exhausted
            }
            self.absorb_block();
            self.buf_len = 0;
        }
        let mut chunks = data.chunks_exact(RATE);
        for chunk in &mut chunks {
            self.buf.copy_from_slice(chunk);
            self.absorb_block();
        }
        let rem = chunks.remainder();
        self.buf[..rem.len()].copy_from_slice(rem);
        self.buf_len = rem.len();
    }

    fn finalize(mut self, out: &mut [u8]) {
        // Pad10*1 with the domain byte folded into the first pad byte.
        let n = self.buf_len;
        for b in &mut self.buf[n..] {
            *b = 0;
        }
        self.buf[n] ^= DOMAIN;
        self.buf[RATE - 1] ^= 0x80;
        self.absorb_block();

        // Squeeze (all supported outputs are <= RATE, one squeeze suffices).
        debug_assert!(out.len() <= RATE);
        let mut squeezed = [0u8; RATE];
        for (i, chunk) in squeezed.chunks_exact_mut(8).enumerate() {
            chunk.copy_from_slice(&self.state[i].to_le_bytes());
        }
        out.copy_from_slice(&squeezed[..out.len()]);
        squeezed.zeroize();
    }
}

impl<const DOMAIN: u8> Drop for Sponge<DOMAIN> {
    fn drop(&mut self) {
        self.state.zeroize();
        self.buf.zeroize();
    }
}

macro_rules! keccak_hash {
    ($name:ident, $domain:literal, $id:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name(Sponge<$domain>);

        impl Hash for $name {
            const OUTPUT_LEN: usize = 32;
            const BLOCK_LEN: usize = RATE;
            const NAME: &'static str = $id;

            fn init() -> Self {
                Self(Sponge::new())
            }
            fn update(&mut self, data: &[u8]) {
                self.0.update(data);
            }
            fn finalize_into(self, out: &mut [u8]) {
                assert_eq!(out.len(), 32, concat!($id, " output must be 32 bytes"));
                self.0.finalize(out);
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct($id).finish_non_exhaustive()
            }
        }
    };
}

keccak_hash!(
    Keccak256,
    0x01,
    "keccak256",
    "Original Keccak-256 (Ethereum's `keccak256`)."
);
keccak_hash!(Sha3_256, 0x06, "sha3-256", "FIPS 202 SHA3-256.");

/// One-shot Keccak-256.
#[must_use]
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::init();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize_into(&mut out);
    out
}

/// One-shot SHA3-256.
#[must_use]
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::init();
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
    fn keccak256_vectors() {
        assert_eq!(
            encode(&keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            encode(&keccak256(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
        // "The quick brown fox jumps over the lazy dog"
        assert_eq!(
            encode(&keccak256(b"The quick brown fox jumps over the lazy dog")),
            "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"
        );
    }

    #[test]
    fn sha3_256_vectors() {
        assert_eq!(
            encode(&sha3_256(b"")),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(
            encode(&sha3_256(b"abc")),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }

    #[test]
    fn streaming_matches_oneshot_across_rate_boundary() {
        let data = alloc::vec![0x5au8; RATE * 3 + 17];
        let one = keccak256(&data);
        let mut h = Keccak256::init();
        for c in data.chunks(13) {
            h.update(c);
        }
        assert_eq!(h.finalize_vec(), one);
    }
}
