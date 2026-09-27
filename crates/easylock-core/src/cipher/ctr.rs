//! CTR mode (NIST SP 800-38A) over any [`BlockCipher`].
//!
//! The 128-bit counter block is treated as big-endian and wraps on overflow
//! (defined behavior; after 2^128 blocks it is the caller's problem). This
//! matches AES-CTR test vectors and the GCM `J0` / `inc32` construction.

use super::BlockCipher;
use crate::secure::Zeroize;

/// A CTR-mode keystream generator / XOR transformer.
pub struct Ctr<'c, C: BlockCipher> {
    cipher: &'c C,
    counter: [u8; 16],
    keystream: [u8; 16],
    ks_pos: usize,
    /// When `Some(n)`, only the low `n` bytes of the counter increment (GCM uses 4).
    inc_width: usize,
}

impl<'c, C: BlockCipher> Ctr<'c, C> {
    /// Start CTR with an explicit 16-byte initial counter block; the whole
    /// 128-bit block increments.
    pub fn with_counter(cipher: &'c C, counter: [u8; 16]) -> Self {
        Self {
            cipher,
            counter,
            keystream: [0u8; 16],
            ks_pos: 16,
            inc_width: 16,
        }
    }

    /// Start CTR from a 96-bit nonce and a 32-bit initial counter value
    /// (`nonce || counter_be32`), incrementing only the low 32 bits (GCM style).
    pub fn from_nonce96_inc32(cipher: &'c C, nonce: &[u8; 12], initial: u32) -> Self {
        let mut counter = [0u8; 16];
        counter[..12].copy_from_slice(nonce);
        counter[12..].copy_from_slice(&initial.to_be_bytes());
        Self {
            cipher,
            counter,
            keystream: [0u8; 16],
            ks_pos: 16,
            inc_width: 4,
        }
    }

    /// Increment the low `inc_width` bytes of the counter (big-endian, wrapping).
    fn increment(&mut self) {
        let start = 16 - self.inc_width;
        let mut carry = 1u16;
        let mut i = 16;
        while i > start && carry != 0 {
            i -= 1;
            let v = u16::from(self.counter[i]) + carry;
            self.counter[i] = v as u8;
            carry = v >> 8;
        }
    }

    fn refill(&mut self) {
        self.keystream = self.counter;
        self.cipher.encrypt_block(&mut self.keystream);
        self.ks_pos = 0;
        self.increment();
    }

    /// XOR `data` in place with the keystream (encrypt == decrypt).
    pub fn apply(&mut self, mut data: &mut [u8]) {
        // Drain buffered keystream first.
        while self.ks_pos < 16 && !data.is_empty() {
            data[0] ^= self.keystream[self.ks_pos];
            self.ks_pos += 1;
            data = &mut data[1..];
        }
        // Bulk: 8 counter blocks per batch, encrypted together.
        let mut ks = [[0u8; 16]; 8];
        while data.len() >= 128 {
            for b in &mut ks {
                *b = self.counter;
                self.increment();
            }
            self.cipher.encrypt_blocks(&mut ks);
            for (chunk, k) in data[..128].chunks_exact_mut(16).zip(ks.iter()) {
                let v = u128::from_ne_bytes(chunk.try_into().expect("16 bytes"))
                    ^ u128::from_ne_bytes(*k);
                chunk.copy_from_slice(&v.to_ne_bytes());
            }
            data = &mut data[128..];
        }
        for b in &mut ks {
            b.zeroize();
        }
        for byte in data.iter_mut() {
            if self.ks_pos == 16 {
                self.refill();
            }
            *byte ^= self.keystream[self.ks_pos];
            self.ks_pos += 1;
        }
    }

    /// Fill `out` with raw keystream bytes (no plaintext).
    pub fn keystream_into(&mut self, out: &mut [u8]) {
        for byte in out.iter_mut() {
            if self.ks_pos == 16 {
                self.refill();
            }
            *byte = self.keystream[self.ks_pos];
            self.ks_pos += 1;
        }
    }
}

impl<C: BlockCipher> Drop for Ctr<'_, C> {
    fn drop(&mut self) {
        self.counter.zeroize();
        self.keystream.zeroize();
    }
}

impl<C: BlockCipher> core::fmt::Debug for Ctr<'_, C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ctr").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::aes::Aes256;
    use crate::encode::hex::{decode, encode};

    // NIST SP 800-38A F.5.5 CTR-AES256.Encrypt
    #[test]
    fn sp800_38a_ctr_aes256() {
        let key =
            decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4").unwrap();
        let ic: [u8; 16] = decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
            .unwrap()
            .try_into()
            .unwrap();
        let pt = decode(
            "6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef\
             f69f2445df4f9b17ad2b417be66c3710",
        )
        .unwrap();
        let want = "601ec313775789a5b7a7f504bbf3d228\
                    f443e3ca4d62b59aca84e990cacaf5c5\
                    2b0930daa23de94ce87017ba2d84988d\
                    dfc9c58db67aada613c2dd08457941a6";

        let aes = Aes256::new(&key).unwrap();
        let mut buf = pt.clone();
        Ctr::with_counter(&aes, ic).apply(&mut buf);
        assert_eq!(encode(&buf), want);

        Ctr::with_counter(&aes, ic).apply(&mut buf);
        assert_eq!(buf, pt);
    }

    #[test]
    fn counter_wraps_without_panic() {
        let aes = Aes256::new(&[0u8; 32]).unwrap();
        let mut ctr = Ctr::with_counter(&aes, [0xff; 16]);
        let mut a = [0u8; 48];
        ctr.keystream_into(&mut a);
    }

    #[test]
    fn bulk_path_matches_bytewise_for_any_split() {
        use crate::cipher::aes::Aes256;
        let aes = Aes256::new(&[0x11; 32]).unwrap();
        let mut reference = alloc::vec![0u8; 1000];
        {
            let mut c = Ctr::from_nonce96_inc32(&aes, &[7; 12], u32::MAX - 3); // wraps inside
            c.keystream_into(&mut reference);
        }
        for splits in [&[1000usize][..], &[1, 127, 128, 129, 615], &[17; 59]] {
            let mut buf = alloc::vec![0u8; 1000];
            let mut c = Ctr::from_nonce96_inc32(&aes, &[7; 12], u32::MAX - 3);
            let mut pos = 0;
            for &n in splits {
                let end = (pos + n).min(1000);
                c.apply(&mut buf[pos..end]);
                pos = end;
            }
            c.apply(&mut buf[pos..]);
            assert_eq!(buf, reference, "{splits:?}");
        }
    }
}
