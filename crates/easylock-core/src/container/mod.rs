//! Password-based container formats shared by every easylock front-end
//! (CLI, TUI, desktop GUI, web dashboard):
//!
//! * [`stream`] — streaming, multi-core **ELK2** `.elk` files with password and/or
//!   public-key ([`elk2::Recipient`]) key slots; also reads ELK1. **Use this.**
//! * [`archive`] — the folder archive stored inside encrypted folders.
//! * [`seal_file`] / [`open_file`] — the original in-memory **ELK1** format (kept for
//!   `no_std` users and for reading old files).
//! * [`seal_token`] / [`open_token`] — the compact **`elk1.`** text token.
//!
//! Both derive a 256-bit key from the password with Argon2id (the parameters
//! are stored in the output, so they can change without breaking old files) and
//! encrypt with AES-256-GCM or ChaCha20-Poly1305.
//!
//! ## `.elk` layout (all integers little-endian unless noted)
//!
//! ```text
//! 0   4   magic "ELK1"
//! 4   1   cipher: 0 = AES-256-GCM, 1 = ChaCha20-Poly1305
//! 5   12  Argon2id m_cost (KiB), t_cost, parallelism — u32 each
//! 17  16  salt
//! 33  12  base nonce (first 8 bytes random, last 4 zero)
//! 45  …   chunks: u32 length ‖ AEAD(chunk ≤ 256 KiB)
//! ```
//!
//! Chunk `i` uses nonce `base[0..8] ‖ be32(i)` and associated data
//! `be32(i) ‖ is_last`, so chunks cannot be reordered, dropped, or truncated
//! without detection.
//!
//! ## `elk1.` token
//!
//! `"elk1." ‖ base64url_nopad(cipher ‖ salt[16] ‖ nonce[12] ‖ AEAD(text))`,
//! Argon2id m = 19 MiB, t = 2, p = 1, associated data `"elk1"`.

#[cfg(feature = "std")]
pub mod archive;
pub mod elk2;
#[cfg(feature = "std")]
pub mod stream;

use crate::aead::{Aead, Aes256Gcm, ChaCha20Poly1305};
use crate::encode::base64;
use crate::kdf::argon2::{self, Params};
use crate::secure::Zeroize;
use crate::{Error, Result};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// `.elk` file magic.
pub const MAGIC: &[u8; 4] = b"ELK1";
/// Plaintext bytes per `.elk` chunk.
pub const CHUNK: usize = 256 * 1024;
/// Size of the `.elk` header.
pub const HEADER_LEN: usize = 45;

/// Default Argon2id cost for files (64 MiB, 3 passes, 4 lanes).
pub const FILE_PARAMS: Params = Params {
    m_cost: 64 * 1024,
    t_cost: 3,
    parallelism: 4,
    out_len: 32,
};

/// Argon2id cost for text tokens (OWASP minimum: 19 MiB, 2 passes, 1 lane).
pub const TOKEN_PARAMS: Params = Params {
    m_cost: 19 * 1024,
    t_cost: 2,
    parallelism: 1,
    out_len: 32,
};

/// Which AEAD a container uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Cipher {
    /// Byte stored in the container.
    #[must_use]
    pub fn id(self) -> u8 {
        match self {
            Cipher::Aes256Gcm => 0,
            Cipher::ChaCha20Poly1305 => 1,
        }
    }

    /// Inverse of [`Cipher::id`].
    pub fn from_id(id: u8) -> Result<Self> {
        match id {
            0 => Ok(Cipher::Aes256Gcm),
            1 => Ok(Cipher::ChaCha20Poly1305),
            _ => Err(Error::InvalidEncoding {
                scheme: "elk cipher id",
            }),
        }
    }

    /// Parse a user-facing name (`aes-256-gcm`, `chacha20-poly1305`, …).
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "aes-256-gcm" | "aes256-gcm" | "aes" | "gcm" => Some(Cipher::Aes256Gcm),
            "chacha20-poly1305" | "chacha" | "chacha20" => Some(Cipher::ChaCha20Poly1305),
            _ => None,
        }
    }

    /// Display name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Cipher::Aes256Gcm => "AES-256-GCM",
            Cipher::ChaCha20Poly1305 => "ChaCha20-Poly1305",
        }
    }

    fn seal(self, key: &[u8], nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        Ok(match self {
            Cipher::Aes256Gcm => Aes256Gcm::new(key)?.seal(nonce, aad, pt),
            Cipher::ChaCha20Poly1305 => ChaCha20Poly1305::new(key)?.seal(nonce, aad, pt),
        })
    }

    fn open(self, key: &[u8], nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        match self {
            Cipher::Aes256Gcm => Aes256Gcm::new(key)?.open(nonce, aad, ct),
            Cipher::ChaCha20Poly1305 => ChaCha20Poly1305::new(key)?.open(nonce, aad, ct),
        }
    }
}

/// Nonce for chunk `counter`: `base[0..8] ‖ be32(counter)`.
#[must_use]
pub fn chunk_nonce(base: &[u8; 12], counter: u32) -> [u8; 12] {
    let mut n = *base;
    n[8..12].copy_from_slice(&counter.to_be_bytes());
    n
}

/// Associated data for chunk `counter`: `be32(counter) ‖ is_last`.
#[must_use]
pub fn chunk_aad(counter: u32, is_last: bool) -> [u8; 5] {
    let c = counter.to_be_bytes();
    [c[0], c[1], c[2], c[3], u8::from(is_last)]
}

/// Build the 45-byte `.elk` header.
#[must_use]
pub fn header(
    cipher: Cipher,
    params: &Params,
    salt: &[u8; 16],
    base_nonce: &[u8; 12],
) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..4].copy_from_slice(MAGIC);
    h[4] = cipher.id();
    h[5..9].copy_from_slice(&params.m_cost.to_le_bytes());
    h[9..13].copy_from_slice(&params.t_cost.to_le_bytes());
    h[13..17].copy_from_slice(&params.parallelism.to_le_bytes());
    h[17..33].copy_from_slice(salt);
    h[33..45].copy_from_slice(base_nonce);
    h
}

/// Parsed `.elk` header.
#[derive(Debug, Clone)]
pub struct Header {
    pub cipher: Cipher,
    pub params: Params,
    pub salt: [u8; 16],
    pub base_nonce: [u8; 12],
}

/// Parse and validate a `.elk` header.
pub fn parse_header(bytes: &[u8]) -> Result<Header> {
    if bytes.len() < HEADER_LEN || &bytes[..4] != MAGIC {
        return Err(Error::InvalidEncoding {
            scheme: "elk (bad magic — not an easylock file)",
        });
    }
    let u32_at =
        |i: usize| u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
    let mut salt = [0u8; 16];
    let mut base_nonce = [0u8; 12];
    salt.copy_from_slice(&bytes[17..33]);
    base_nonce.copy_from_slice(&bytes[33..45]);
    let params = Params {
        m_cost: u32_at(5),
        t_cost: u32_at(9),
        parallelism: u32_at(13),
        out_len: 32,
    };
    elk2::check_params(&params)?;
    Ok(Header {
        cipher: Cipher::from_id(bytes[4])?,
        params,
        salt,
        base_nonce,
    })
}

/// Encrypt `plaintext` into a complete in-memory `.elk` file.
///
/// `rng` must fill buffers with cryptographically secure randomness.
pub fn seal_file(
    plaintext: &[u8],
    password: &[u8],
    cipher: Cipher,
    params: Params,
    rng: &mut impl FnMut(&mut [u8]),
) -> Result<Vec<u8>> {
    let mut salt = [0u8; 16];
    let mut base_nonce = [0u8; 12];
    rng(&mut salt);
    rng(&mut base_nonce[..8]);
    let mut key = argon2::hash(password, &salt, params)?;

    let mut out =
        Vec::with_capacity(HEADER_LEN + plaintext.len() + (plaintext.len() / CHUNK + 1) * 20);
    out.extend_from_slice(&header(cipher, &params, &salt, &base_nonce));

    let mut counter: u32 = 0;
    let mut offset = 0usize;
    loop {
        let end = (offset + CHUNK).min(plaintext.len());
        let chunk = &plaintext[offset..end];
        let is_last = chunk.len() < CHUNK;
        let sealed = cipher.seal(
            &key,
            &chunk_nonce(&base_nonce, counter),
            &chunk_aad(counter, is_last),
            chunk,
        )?;
        out.extend_from_slice(
            &u32::try_from(sealed.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        out.extend_from_slice(&sealed);
        counter = counter.wrapping_add(1);
        offset = end;
        if is_last {
            break;
        }
    }
    key.zeroize();
    Ok(out)
}

/// Decrypt an in-memory `.elk` file. Any tampering, truncation, reordering or a
/// wrong password yields [`Error::Authentication`].
pub fn open_file(data: &[u8], password: &[u8]) -> Result<Vec<u8>> {
    let h = parse_header(data)?;
    let mut key = argon2::hash(password, &h.salt, h.params)?;
    let mut out = Vec::with_capacity(data.len());
    let mut pos = HEADER_LEN;
    let mut counter: u32 = 0;
    let result = loop {
        if pos + 4 > data.len() {
            break Err(Error::Authentication); // truncated: final chunk missing
        }
        let len =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + len > data.len() {
            break Err(Error::Authentication);
        }
        let sealed = &data[pos..pos + len];
        pos += len;
        let is_last = pos == data.len();
        match h.cipher.open(
            &key,
            &chunk_nonce(&h.base_nonce, counter),
            &chunk_aad(counter, is_last),
            sealed,
        ) {
            Ok(pt) => out.extend_from_slice(&pt),
            Err(e) => break Err(e),
        }
        counter = counter.wrapping_add(1);
        if is_last {
            break Ok(());
        }
    };
    key.zeroize();
    match result {
        Ok(()) => Ok(out),
        Err(e) => {
            out.zeroize();
            Err(e)
        }
    }
}

/// Encrypt a short text into an `elk1.` token.
pub fn seal_token(
    plaintext: &[u8],
    password: &[u8],
    cipher: Cipher,
    rng: &mut impl FnMut(&mut [u8]),
) -> Result<String> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rng(&mut salt);
    rng(&mut nonce);
    let mut key = argon2::hash(password, &salt, TOKEN_PARAMS)?;
    let ct = cipher.seal(&key, &nonce, b"elk1", plaintext)?;
    key.zeroize();
    let mut blob = Vec::with_capacity(1 + 16 + 12 + ct.len());
    blob.push(cipher.id());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    Ok(format!(
        "elk1.{}",
        base64::encode(&blob, base64::Variant::UrlNoPad)
    ))
}

/// Decrypt an `elk1.` token.
pub fn open_token(token: &str, password: &[u8]) -> Result<Vec<u8>> {
    let bad = || Error::InvalidEncoding {
        scheme: "elk1 token",
    };
    let body = token.trim().strip_prefix("elk1.").ok_or_else(bad)?;
    let blob = base64::decode(body, base64::Variant::UrlNoPad).map_err(|_| bad())?;
    if blob.len() < 1 + 16 + 12 + 16 {
        return Err(bad());
    }
    let cipher = Cipher::from_id(blob[0])?;
    let salt = &blob[1..17];
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[17..29]);
    let mut key = argon2::hash(password, salt, TOKEN_PARAMS)?;
    let pt = cipher.open(&key, &nonce, b"elk1", &blob[29..]);
    key.zeroize();
    pt
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng() -> impl FnMut(&mut [u8]) {
        let mut s = 0x1234_5678_9abc_def0u64;
        move |b: &mut [u8]| {
            for x in b.iter_mut() {
                s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                *x = (s >> 33) as u8;
            }
        }
    }

    const FAST: Params = Params {
        m_cost: 64,
        t_cost: 1,
        parallelism: 1,
        out_len: 32,
    };

    #[test]
    fn file_roundtrip_multi_chunk_both_ciphers() {
        let data: Vec<u8> = (0..(CHUNK * 2 + 777)).map(|i| (i % 251) as u8).collect();
        for c in [Cipher::Aes256Gcm, Cipher::ChaCha20Poly1305] {
            let sealed = seal_file(&data, b"pw", c, FAST, &mut rng()).unwrap();
            assert_eq!(&sealed[..4], MAGIC);
            assert_eq!(open_file(&sealed, b"pw").unwrap(), data);
            assert!(open_file(&sealed, b"nope").is_err());
        }
    }

    #[test]
    fn exact_chunk_multiple_and_empty() {
        for len in [0, CHUNK, 2 * CHUNK] {
            let data = alloc::vec![7u8; len];
            let sealed =
                seal_file(&data, b"k", Cipher::ChaCha20Poly1305, FAST, &mut rng()).unwrap();
            assert_eq!(open_file(&sealed, b"k").unwrap(), data, "len {len}");
        }
    }

    #[test]
    fn truncation_and_tamper_detected() {
        let data = alloc::vec![1u8; CHUNK + 10];
        let sealed = seal_file(&data, b"k", Cipher::Aes256Gcm, FAST, &mut rng()).unwrap();
        // drop the final chunk entirely
        let first_len = u32::from_le_bytes(sealed[45..49].try_into().unwrap()) as usize;
        assert!(open_file(&sealed[..45 + 4 + first_len], b"k").is_err());
        // flip a ciphertext bit
        let mut bad = sealed.clone();
        bad[60] ^= 1;
        assert!(open_file(&bad, b"k").is_err());
        // not an elk file
        assert!(open_file(b"hello world, definitely not elk....................", b"k").is_err());
    }

    #[test]
    fn token_roundtrip() {
        let tok = seal_token(
            b"attack at dawn",
            b"hunter2",
            Cipher::ChaCha20Poly1305,
            &mut rng(),
        )
        .unwrap();
        assert!(tok.starts_with("elk1."));
        assert_eq!(open_token(&tok, b"hunter2").unwrap(), b"attack at dawn");
        assert!(open_token(&tok, b"hunter3").is_err());
        assert!(open_token("elk1.!!!", b"x").is_err());
    }
}
