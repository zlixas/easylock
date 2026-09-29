//! AES-256 block encryption.
//!
//! Only the forward (encryption) direction is implemented — CTR and GCM, the two
//! modes this library exposes, never use the inverse cipher.
//!
//! Backend selection happens once, in [`Aes256::new`], based on
//! [`crate::cpu::features`]:
//!
//! | Target   | Fast path                              | Fallback              |
//! |----------|----------------------------------------|-----------------------|
//! | x86-64   | AES-NI (`aesenc` / `aesenclast`)       | constant-time S-box   |
//! | aarch64  | ARMv8 crypto (`aese` / `aesmc`)        | constant-time S-box   |
//! | other    | —                                      | constant-time S-box   |
//!
//! The portable path is bitsliced (four blocks per pass, Boyar–Peralta S-box
//! circuit): pure register logic with no secret-dependent memory access or
//! control flow.

use super::BlockCipher;
use crate::secure::Zeroize;
use crate::{Error, Result};

mod soft;

#[cfg(target_arch = "x86_64")]
mod x86;

#[cfg(target_arch = "aarch64")]
mod arm;

const AES256_KEY_LEN: usize = 32;
const ROUND_KEYS: usize = 15; // Nr + 1 for AES-256

/// Which implementation [`Aes256`] dispatched to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// Constant-time portable software.
    Portable,
    /// x86 AES-NI.
    AesNi,
    /// ARMv8 AES extension.
    Armv8,
}

impl Backend {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Backend::Portable => "portable-ct",
            Backend::AesNi => "aes-ni",
            Backend::Armv8 => "armv8-crypto",
        }
    }
}

/// Report the backend that *would* be selected on this CPU (without a key).
#[must_use]
pub fn active_backend() -> &'static str {
    select_backend().as_str()
}

fn select_backend() -> Backend {
    let f = crate::cpu::features();
    #[cfg(target_arch = "x86_64")]
    if f.aes {
        return Backend::AesNi;
    }
    #[cfg(target_arch = "aarch64")]
    if f.aes {
        return Backend::Armv8;
    }
    let _ = f;
    Backend::Portable
}

/// An expanded AES-256 encryption key.
///
/// The 15 round keys are scrubbed on drop.
#[derive(Clone)]
pub struct Aes256 {
    round_keys: [[u8; 16]; ROUND_KEYS],
    /// Bitsliced round keys; only filled for [`Backend::Portable`].
    sliced: soft::SlicedKeys,
    backend: Backend,
}

impl Aes256 {
    /// Expand a 32-byte key.
    ///
    /// # Errors
    /// [`Error::InvalidLength`] if `key.len() != 32`.
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != AES256_KEY_LEN {
            return Err(Error::len("AES-256 key", AES256_KEY_LEN, key.len()));
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(key);
        let round_keys = soft::expand_key_256(&k);
        k.zeroize();
        let backend = select_backend();
        let sliced = if backend == Backend::Portable {
            soft::slice_keys(&round_keys)
        } else {
            [[0; 8]; ROUND_KEYS]
        };
        Ok(Self {
            round_keys,
            sliced,
            backend,
        })
    }

    /// The backend chosen for this key.
    #[must_use]
    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// Encrypt a single block in place.
    #[inline]
    pub fn encrypt_block_into(&self, block: &mut [u8; 16]) {
        match self.backend {
            #[cfg(target_arch = "x86_64")]
            Backend::AesNi => {
                // SAFETY: `select_backend` only returns `AesNi` after runtime
                // detection confirmed the `aes` feature is present.
                unsafe { x86::encrypt_block(&self.round_keys, block) }
            }
            #[cfg(target_arch = "aarch64")]
            Backend::Armv8 => {
                // SAFETY: `select_backend` only returns `Armv8` after runtime
                // detection confirmed the `aes` feature is present.
                unsafe { arm::encrypt_block(&self.round_keys, block) }
            }
            _ => {
                let mut four = [*block, [0; 16], [0; 16], [0; 16]];
                soft::encrypt4(&self.sliced, &mut four);
                *block = four[0];
                four[0].zeroize();
            }
        }
    }

    /// Encrypt many independent blocks in place (8 at a time on hardware backends).
    pub fn encrypt_blocks(&self, blocks: &mut [[u8; 16]]) {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        if self.backend != Backend::Portable {
            let mut groups = blocks.chunks_exact_mut(8);
            for g in &mut groups {
                let g: &mut [[u8; 16]; 8] = g.try_into().expect("chunk of 8");
                match self.backend {
                    // SAFETY: `AesNi` is only selected after detecting `aes`.
                    #[cfg(target_arch = "x86_64")]
                    Backend::AesNi => unsafe { x86::encrypt_blocks8(&self.round_keys, g) },
                    // SAFETY: `Armv8` is only selected after detecting `aes`.
                    #[cfg(target_arch = "aarch64")]
                    Backend::Armv8 => unsafe { arm::encrypt_blocks8(&self.round_keys, g) },
                    _ => unreachable!("hardware backend"),
                }
            }
            for b in groups.into_remainder() {
                self.encrypt_block_into(b);
            }
            return;
        }

        // Portable: bitsliced, four blocks per pass; a short tail is padded.
        let mut fours = blocks.chunks_exact_mut(4);
        for g in &mut fours {
            soft::encrypt4(&self.sliced, g.try_into().expect("chunk of 4"));
        }
        let rest = fours.into_remainder();
        if !rest.is_empty() {
            let mut four = [[0u8; 16]; 4];
            four[..rest.len()].copy_from_slice(rest);
            soft::encrypt4(&self.sliced, &mut four);
            rest.copy_from_slice(&four[..rest.len()]);
            for b in &mut four {
                b.zeroize();
            }
        }
    }

    /// Encrypt a block, returning a fresh array.
    #[must_use]
    pub fn encrypt_block(&self, mut block: [u8; 16]) -> [u8; 16] {
        self.encrypt_block_into(&mut block);
        block
    }
}

impl BlockCipher for Aes256 {
    fn encrypt_block(&self, block: &mut [u8; 16]) {
        self.encrypt_block_into(block);
    }
    fn encrypt_blocks(&self, blocks: &mut [[u8; 16]]) {
        Aes256::encrypt_blocks(self, blocks);
    }
}

impl Drop for Aes256 {
    fn drop(&mut self) {
        for rk in &mut self.round_keys {
            rk.zeroize();
        }
        for sk in &mut self.sliced {
            sk.zeroize();
        }
    }
}

impl core::fmt::Debug for Aes256 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Aes256")
            .field("backend", &self.backend)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::hex::{decode, encode};

    // FIPS-197 Appendix C.3 — AES-256 single-block known-answer.
    #[test]
    fn fips197_c3() {
        let key =
            decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let pt = decode("00112233445566778899aabbccddeeff").unwrap();
        let mut block = [0u8; 16];
        block.copy_from_slice(&pt);
        let aes = Aes256::new(&key).unwrap();
        aes.encrypt_block_into(&mut block);
        assert_eq!(encode(&block), "8ea2b7ca516745bfeafc49904b496089");
    }

    // NIST SP 800-38A F.1.5 CTR-AES256 first block key stream check via ECB.
    #[test]
    fn sp80038a_ecb_vectors() {
        let key =
            decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4").unwrap();
        let aes = Aes256::new(&key).unwrap();
        let cases = [
            (
                "6bc1bee22e409f96e93d7e117393172a",
                "f3eed1bdb5d2a03c064b5a7e3db181f8",
            ),
            (
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "591ccb10d410ed26dc5ba74a31362870",
            ),
        ];
        for (pt, ct) in cases {
            let mut b = [0u8; 16];
            b.copy_from_slice(&decode(pt).unwrap());
            aes.encrypt_block_into(&mut b);
            assert_eq!(encode(&b), ct);
        }
    }

    #[test]
    fn rejects_wrong_key_length() {
        assert!(Aes256::new(&[0u8; 16]).is_err());
    }

    /// The bitsliced portable backend, driven through the public API, agrees
    /// with the reference cipher for every batch length (remainder handling).
    #[test]
    fn portable_backend_all_batch_lengths() {
        let key: [u8; 32] = core::array::from_fn(|i| (i * 7 + 3) as u8);
        let rk = soft::expand_key_256(&key);
        let aes = Aes256 {
            round_keys: rk,
            sliced: soft::slice_keys(&rk),
            backend: Backend::Portable,
        };
        for n in 0..=19 {
            let mut blocks: alloc::vec::Vec<[u8; 16]> = (0..n)
                .map(|b| core::array::from_fn(|i| (b * 31 + i) as u8))
                .collect();
            let mut want = blocks.clone();
            for b in &mut want {
                soft::encrypt_block(&rk, b);
            }
            aes.encrypt_blocks(&mut blocks);
            assert_eq!(blocks, want, "n = {n}");
        }
        let mut one = [0x5au8; 16];
        let mut want = one;
        soft::encrypt_block(&rk, &mut want);
        aes.encrypt_block_into(&mut one);
        assert_eq!(one, want);
    }

    #[test]
    fn portable_matches_selected_backend() {
        let key = [0x42u8; 32];
        let rk = soft::expand_key_256(&key);
        let mut a = [0x11u8; 16];
        let mut b = a;
        soft::encrypt_block(&rk, &mut a);
        Aes256::new(&key).unwrap().encrypt_block_into(&mut b);
        assert_eq!(a, b, "hardware backend disagrees with portable");
    }
}
