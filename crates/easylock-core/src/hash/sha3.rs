//! FIPS 202 SHA3-256 / SHA3-512 and the SHAKE128 / SHAKE256 extendable-output
//! functions, sharing the `Keccak-f[1600]` permutation with [`super::keccak`].
//!
//! The XOF type absorbs any amount of input and then squeezes any amount of
//! output; ML-KEM ([`crate::pqc`]) relies on it heavily.

use super::keccak::keccak_f;
use crate::secure::Zeroize;

/// A Keccak sponge with byte `RATE` and domain-separation byte `DOMAIN`.
#[derive(Clone)]
pub struct Xof<const RATE: usize, const DOMAIN: u8> {
    state: [u64; 25],
    buf: [u8; RATE],
    buf_len: usize,
    // squeeze phase bookkeeping
    squeezing: bool,
    out_pos: usize,
}

impl<const RATE: usize, const DOMAIN: u8> Xof<RATE, DOMAIN> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: [0u64; 25],
            buf: [0u8; RATE],
            buf_len: 0,
            squeezing: false,
            out_pos: RATE,
        }
    }

    fn absorb_buf(&mut self) {
        for i in 0..RATE / 8 {
            let w = u64::from_le_bytes(self.buf[i * 8..i * 8 + 8].try_into().unwrap());
            self.state[i] ^= w;
        }
        keccak_f(&mut self.state);
    }

    /// Absorb more input. Must not be called after squeezing starts.
    pub fn absorb(&mut self, mut data: &[u8]) {
        assert!(!self.squeezing, "Xof: absorb after squeeze");
        while !data.is_empty() {
            let take = (RATE - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == RATE {
                self.absorb_buf();
                self.buf_len = 0;
            }
        }
    }

    fn state_to_buf(&mut self) {
        for i in 0..RATE / 8 {
            self.buf[i * 8..i * 8 + 8].copy_from_slice(&self.state[i].to_le_bytes());
        }
        self.out_pos = 0;
    }

    /// Squeeze `out.len()` bytes. May be called repeatedly.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        if !self.squeezing {
            // pad10*1 with the domain byte, absorb, then expose the first block.
            for b in &mut self.buf[self.buf_len..] {
                *b = 0;
            }
            self.buf[self.buf_len] ^= DOMAIN;
            self.buf[RATE - 1] ^= 0x80;
            self.absorb_buf();
            self.buf_len = 0;
            self.squeezing = true;
            self.state_to_buf();
        }
        let mut written = 0;
        while written < out.len() {
            if self.out_pos == RATE {
                keccak_f(&mut self.state);
                self.state_to_buf();
            }
            let take = (RATE - self.out_pos).min(out.len() - written);
            out[written..written + take]
                .copy_from_slice(&self.buf[self.out_pos..self.out_pos + take]);
            self.out_pos += take;
            written += take;
        }
    }
}

impl<const RATE: usize, const DOMAIN: u8> Default for Xof<RATE, DOMAIN> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const RATE: usize, const DOMAIN: u8> Drop for Xof<RATE, DOMAIN> {
    fn drop(&mut self) {
        self.state.zeroize();
        self.buf.zeroize();
    }
}

impl<const RATE: usize, const DOMAIN: u8> core::fmt::Debug for Xof<RATE, DOMAIN> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Xof").finish_non_exhaustive()
    }
}

/// SHAKE128 (rate 168, domain `0x1F`).
pub type Shake128 = Xof<168, 0x1F>;
/// SHAKE256 (rate 136, domain `0x1F`).
pub type Shake256 = Xof<136, 0x1F>;

/// One-shot SHAKE128.
pub fn shake128(data: &[u8], out: &mut [u8]) {
    let mut x = Shake128::new();
    x.absorb(data);
    x.squeeze(out);
}

/// One-shot SHAKE256.
pub fn shake256(data: &[u8], out: &mut [u8]) {
    let mut x = Shake256::new();
    x.absorb(data);
    x.squeeze(out);
}

/// SHA3-256 (FIPS 202).
#[must_use]
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut x: Xof<136, 0x06> = Xof::new();
    x.absorb(data);
    let mut out = [0u8; 32];
    x.squeeze(&mut out);
    out
}

/// SHA3-512 (FIPS 202).
#[must_use]
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut x: Xof<72, 0x06> = Xof::new();
    x.absorb(data);
    let mut out = [0u8; 64];
    x.squeeze(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::hex::encode;

    #[test]
    fn sha3_vectors() {
        assert_eq!(
            encode(&sha3_256(b"")),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(
            encode(&sha3_256(b"abc")),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
        assert_eq!(
            encode(&sha3_512(b"")),
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6\
             15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        );
        assert_eq!(
            encode(&sha3_512(b"abc")),
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
             10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        );
    }

    // FIPS 202 / NIST examples for SHAKE with empty input.
    #[test]
    fn shake_empty_vectors() {
        let mut o = [0u8; 32];
        shake128(b"", &mut o);
        assert_eq!(
            encode(&o),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        );
        let mut o = [0u8; 32];
        shake256(b"", &mut o);
        assert_eq!(
            encode(&o),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        );
    }

    #[test]
    fn shake128_long_output_and_incremental_match() {
        let mut whole = [0u8; 512];
        shake128(b"easylock shake test", &mut whole);

        let mut x = Shake128::new();
        x.absorb(b"easylock ");
        x.absorb(b"shake test");
        let mut a = [0u8; 200];
        let mut b = [0u8; 312];
        x.squeeze(&mut a);
        x.squeeze(&mut b);
        assert_eq!(&whole[..200], &a[..]);
        assert_eq!(&whole[200..], &b[..]);
    }

    #[test]
    fn shake256_nist_100_bytes() {
        // NIST CAVP SHAKE256, Msg="" (Len 0), first 100 output bytes.
        let mut o = [0u8; 100];
        shake256(b"", &mut o);
        assert_eq!(
            encode(&o),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f\
             d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be\
             141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853\
             349ec755"
        );
    }
}
