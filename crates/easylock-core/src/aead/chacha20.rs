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
pub struct ChaCha20 {
    key: [u8; 32],
    nonce: [u8; 12],
    counter: u32,
    ks: [u8; 64],
    ks_pos: usize,
}

impl ChaCha20 {
    /// New cipher with an explicit starting block counter (RFC 8439 uses 1 for
    /// the AEAD payload, 0 when generating the Poly1305 key).
    #[must_use]
    pub fn new(key: &[u8; 32], nonce: &[u8; 12], initial_counter: u32) -> Self {
        Self {
            key: *key,
            nonce: *nonce,
            counter: initial_counter,
            ks: [0u8; 64],
            ks_pos: 64,
        }
    }

    fn refill(&mut self) {
        self.ks = block(&self.key, &self.nonce, self.counter);
        self.counter = self.counter.wrapping_add(1);
        self.ks_pos = 0;
    }

    /// XOR `data` in place (encrypt == decrypt).
    pub fn apply(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.ks_pos == 64 {
                self.refill();
            }
            *byte ^= self.ks[self.ks_pos];
            self.ks_pos += 1;
        }
    }
}

impl Drop for ChaCha20 {
    fn drop(&mut self) {
        self.key.zeroize();
        self.nonce.zeroize();
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
}
