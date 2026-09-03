//! The crypto worker functions behind the Tauri commands. Kept separate from the
//! IPC layer so they are plain, testable Rust.

#![allow(clippy::fn_params_excessive_bools)]

use easylock_core::aead::{Aead, Aes256Gcm, ChaCha20Poly1305};
use easylock_core::encode::{base64, hex, Transform};
use easylock_core::hash::Algorithm;
use easylock_core::kdf::argon2::{self, Params as ArgonParams};
use easylock_core::secure::{Secret, Zeroize};
use std::fs::File;
use std::io::{Read, Seek, Write};

const MAGIC: &[u8; 4] = b"ELK1";
const CHUNK: usize = 256 * 1024;
/// Argon2id parameters for file encryption (interactive: 64 MiB, t=3, p=4).
const FILE_ARGON: ArgonParams = ArgonParams {
    m_cost: 64 * 1024,
    t_cost: 3,
    parallelism: 4,
    out_len: 32,
};

/// Fill `buf` with OS randomness (`/dev/urandom`, a CSPRNG on macOS and Linux).
pub fn os_random(buf: &mut [u8]) -> Result<(), String> {
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(buf))
        .map_err(|e| format!("randomness unavailable: {e}"))
}

// --- hashing -------------------------------------------------------------

pub fn parse_algo(name: &str) -> Result<Algorithm, String> {
    Algorithm::parse(name).ok_or_else(|| format!("unknown hash algorithm: {name}"))
}

pub fn hash_bytes(data: &[u8], algo: &str) -> Result<String, String> {
    Ok(hex::encode(&parse_algo(algo)?.hash(data)))
}

pub fn hash_file_path(path: &str, algo: &str) -> Result<(String, u64), String> {
    let alg = parse_algo(algo)?;
    let mut f = File::open(path).map_err(|e| format!("open {path}: {e}"))?;
    // Streaming would need a Digest object per algo; files here are modest, read
    // fully but report the size.
    let mut data = Vec::new();
    let n = f
        .read_to_end(&mut data)
        .map_err(|e| format!("read {path}: {e}"))? as u64;
    let digest = hex::encode(&alg.hash(&data));
    data.zeroize();
    Ok((digest, n))
}

// --- transform pipeline -------------------------------------------------

pub fn run_transform(input: &str, steps: &[String], decode: bool) -> Result<String, String> {
    let parsed: Result<Vec<Transform>, String> = steps
        .iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| Transform::parse(s).ok_or_else(|| format!("unknown transform: {s}")))
        .collect();
    let parsed = parsed?;
    if parsed.is_empty() {
        return Ok(input.to_string());
    }
    if decode {
        let bytes = easylock_core::encode::chain_decode(input.trim(), &parsed)
            .map_err(|_| "invalid input for this pipeline".to_string())?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    } else {
        Ok(easylock_core::encode::chain_encode(
            input.as_bytes(),
            &parsed,
        ))
    }
}

// --- file encryption ----------------------------------------------------

#[derive(Clone, Copy)]
pub enum FileCipher {
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl FileCipher {
    fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().replace('_', "-").as_str() {
            "aes-256-gcm" | "aes256-gcm" | "gcm" => Ok(FileCipher::Aes256Gcm),
            "chacha20-poly1305" | "chacha" => Ok(FileCipher::ChaCha20Poly1305),
            other => Err(format!("unknown cipher: {other}")),
        }
    }
    fn tag(self) -> u8 {
        match self {
            FileCipher::Aes256Gcm => 0,
            FileCipher::ChaCha20Poly1305 => 1,
        }
    }
    fn from_tag(t: u8) -> Result<Self, String> {
        match t {
            0 => Ok(FileCipher::Aes256Gcm),
            1 => Ok(FileCipher::ChaCha20Poly1305),
            _ => Err("unrecognised cipher id in header".into()),
        }
    }
    fn name(self) -> &'static str {
        match self {
            FileCipher::Aes256Gcm => "AES-256-GCM",
            FileCipher::ChaCha20Poly1305 => "ChaCha20-Poly1305",
        }
    }
    fn seal(self, key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> Vec<u8> {
        match self {
            FileCipher::Aes256Gcm => Aes256Gcm::new(key).unwrap().seal(nonce, aad, pt),
            FileCipher::ChaCha20Poly1305 => {
                ChaCha20Poly1305::new(key).unwrap().seal(nonce, aad, pt)
            }
        }
    }
    fn open(
        self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Vec<u8>, String> {
        let r = match self {
            FileCipher::Aes256Gcm => Aes256Gcm::new(key).unwrap().open(nonce, aad, ct),
            FileCipher::ChaCha20Poly1305 => {
                ChaCha20Poly1305::new(key).unwrap().open(nonce, aad, ct)
            }
        };
        r.map_err(|_| "authentication failed — wrong password or corrupted file".to_string())
    }
}

fn chunk_nonce(base: &[u8; 12], counter: u32) -> [u8; 12] {
    let mut n = *base;
    n[8..12].copy_from_slice(&counter.to_be_bytes());
    n
}

/// Result of a file encrypt/decrypt.
pub struct FileOp {
    pub out_path: String,
    pub cipher: &'static str,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// Encrypt `in_path` to `in_path + ".elk"`. `progress(done, total)` is invoked as
/// chunks are processed.
pub fn encrypt_file(
    in_path: &str,
    cipher: &str,
    password: String,
    mut progress: impl FnMut(u64, u64),
) -> Result<FileOp, String> {
    let cipher = FileCipher::parse(cipher)?;
    let mut pw = password.into_bytes();

    let total = std::fs::metadata(in_path).map_err(|e| e.to_string())?.len();
    let mut salt = [0u8; 16];
    let mut base_nonce = [0u8; 12];
    os_random(&mut salt)?;
    os_random(&mut base_nonce[..8])?;

    let key_vec = argon2::hash(&pw, &salt, FILE_ARGON).map_err(|e| e.to_string())?;
    pw.zeroize();
    let key = Secret::<32>::from_slice(&key_vec).map_err(|e| e.to_string())?;

    let out_path = format!("{in_path}.elk");
    let mut fin = File::open(in_path).map_err(|e| e.to_string())?;
    let mut fout = File::create(&out_path).map_err(|e| e.to_string())?;

    let mut header = Vec::with_capacity(45);
    header.extend_from_slice(MAGIC);
    header.push(cipher.tag());
    header.extend_from_slice(&FILE_ARGON.m_cost.to_le_bytes());
    header.extend_from_slice(&FILE_ARGON.t_cost.to_le_bytes());
    header.extend_from_slice(&FILE_ARGON.parallelism.to_le_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&base_nonce);
    fout.write_all(&header).map_err(|e| e.to_string())?;

    let mut buf = vec![0u8; CHUNK];
    let mut counter: u32 = 0;
    let mut done: u64 = 0;
    let mut bytes_out = header.len() as u64;
    loop {
        let n = read_full(&mut fin, &mut buf).map_err(|e| e.to_string())?;
        let is_last = n < CHUNK;
        let aad = [&counter.to_be_bytes()[..], &[u8::from(is_last)]].concat();
        let sealed = cipher.seal(
            key.expose(),
            &chunk_nonce(&base_nonce, counter),
            &aad,
            &buf[..n],
        );
        fout.write_all(&(sealed.len() as u32).to_le_bytes())
            .map_err(|e| e.to_string())?;
        fout.write_all(&sealed).map_err(|e| e.to_string())?;
        bytes_out += 4 + sealed.len() as u64;
        done += n as u64;
        counter = counter.wrapping_add(1);
        progress(done, total);
        if is_last {
            break;
        }
    }
    buf.zeroize();

    Ok(FileOp {
        out_path,
        cipher: cipher.name(),
        bytes_in: total,
        bytes_out,
    })
}

/// Decrypt an `.elk` file, writing next to it with the extension stripped
/// (or `+ ".dec"` if it had none).
pub fn decrypt_file(
    in_path: &str,
    password: String,
    mut progress: impl FnMut(u64, u64),
) -> Result<FileOp, String> {
    let mut pw = password.into_bytes();
    let total = std::fs::metadata(in_path).map_err(|e| e.to_string())?.len();
    let mut fin = File::open(in_path).map_err(|e| e.to_string())?;

    let mut header = [0u8; 45];
    fin.read_exact(&mut header)
        .map_err(|_| "file too short / not an easylock file".to_string())?;
    if &header[..4] != MAGIC {
        return Err("not an easylock encrypted file (bad magic)".into());
    }
    let cipher = FileCipher::from_tag(header[4])?;
    let m_cost = u32::from_le_bytes(header[5..9].try_into().unwrap());
    let t_cost = u32::from_le_bytes(header[9..13].try_into().unwrap());
    let parallelism = u32::from_le_bytes(header[13..17].try_into().unwrap());
    let salt = &header[17..33];
    let mut base_nonce = [0u8; 12];
    base_nonce.copy_from_slice(&header[33..45]);

    let params = ArgonParams {
        m_cost,
        t_cost,
        parallelism,
        out_len: 32,
    };
    let key_vec = argon2::hash(&pw, salt, params).map_err(|e| e.to_string())?;
    pw.zeroize();
    let key = Secret::<32>::from_slice(&key_vec).map_err(|e| e.to_string())?;

    let out_path = match in_path.strip_suffix(".elk") {
        Some(base) if !base.is_empty() => base.to_string(),
        _ => format!("{in_path}.dec"),
    };
    let mut fout = File::create(&out_path).map_err(|e| e.to_string())?;

    let mut counter: u32 = 0;
    let mut done: u64 = header.len() as u64;
    let mut bytes_out: u64 = 0;
    loop {
        let mut len_bytes = [0u8; 4];
        match fin.read_exact(&mut len_bytes) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err("truncated ciphertext (missing final chunk)".into())
            }
            Err(e) => return Err(e.to_string()),
        }
        let clen = u32::from_le_bytes(len_bytes) as usize;
        let mut sealed = vec![0u8; clen];
        fin.read_exact(&mut sealed)
            .map_err(|_| "truncated chunk".to_string())?;

        // Peek whether more data follows to know the `is_last` flag.
        let mut probe = [0u8; 1];
        let has_more = matches!(fin.read(&mut probe), Ok(1));
        let is_last = !has_more;
        let aad = [&counter.to_be_bytes()[..], &[u8::from(is_last)]].concat();
        let pt = cipher.open(
            key.expose(),
            &chunk_nonce(&base_nonce, counter),
            &aad,
            &sealed,
        )?;
        fout.write_all(&pt).map_err(|e| e.to_string())?;
        bytes_out += pt.len() as u64;
        done += 4 + clen as u64;
        counter = counter.wrapping_add(1);
        progress(done.min(total), total);

        if is_last {
            break;
        }
        // put the probed byte back
        fin.seek(std::io::SeekFrom::Current(-1))
            .map_err(|e| e.to_string())?;
    }

    Ok(FileOp {
        out_path,
        cipher: cipher.name(),
        bytes_in: total,
        bytes_out,
    })
}

fn read_full(f: &mut File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = f.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

// --- generators -------------------------------------------------------

const PW_LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
const PW_UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
const PW_DIGIT: &[u8] = b"23456789";
const PW_SYMBOL: &[u8] = b"!@#$%^&*-_=+?";

pub fn gen_password(
    length: usize,
    lower: bool,
    upper: bool,
    digits: bool,
    symbols: bool,
) -> Result<String, String> {
    let mut pool = Vec::new();
    if lower {
        pool.extend_from_slice(PW_LOWER);
    }
    if upper {
        pool.extend_from_slice(PW_UPPER);
    }
    if digits {
        pool.extend_from_slice(PW_DIGIT);
    }
    if symbols {
        pool.extend_from_slice(PW_SYMBOL);
    }
    if pool.is_empty() || !(4..=256).contains(&length) {
        return Err("pick at least one character class and a length in 4..=256".into());
    }
    // Rejection sampling for an unbiased index into `pool`.
    let mut out = String::with_capacity(length);
    let bound = (256 / pool.len()) * pool.len();
    let mut rand = [0u8; 64];
    let mut ri = rand.len();
    while out.len() < length {
        if ri == rand.len() {
            os_random(&mut rand)?;
            ri = 0;
        }
        let b = rand[ri] as usize;
        ri += 1;
        if b < bound {
            out.push(pool[b % pool.len()] as char);
        }
    }
    Ok(out)
}

pub fn argon2_phc(
    password: String,
    m_cost: u32,
    t_cost: u32,
    parallelism: u32,
) -> Result<String, String> {
    let mut pw = password.into_bytes();
    let mut salt = [0u8; 16];
    os_random(&mut salt)?;
    let params = ArgonParams {
        m_cost,
        t_cost,
        parallelism,
        out_len: 32,
    };
    let tag = argon2::hash(&pw, &salt, params).map_err(|e| e.to_string())?;
    pw.zeroize();
    Ok(format!(
        "$argon2id$v=19$m={m_cost},t={t_cost},p={parallelism}${}${}",
        base64::encode(&salt, base64::Variant::UrlNoPad),
        base64::encode(&tag, base64::Variant::UrlNoPad),
    ))
}

/// A generated key pair, hex-encoded.
pub struct KeyPair {
    pub kind: String,
    pub public: String,
    pub secret: String,
    pub note: String,
}

pub fn gen_keypair(kind: &str) -> Result<KeyPair, String> {
    match kind {
        "ed25519" => {
            let mut seed = [0u8; 32];
            os_random(&mut seed)?;
            let sk = easylock_core::ec::SigningKey::from_seed(seed);
            let kp = KeyPair {
                kind: "Ed25519".into(),
                public: hex::encode(sk.verifying_key().as_bytes()),
                secret: hex::encode(&sk.to_seed()),
                note: "32-byte seed / 32-byte public key (RFC 8032).".into(),
            };
            seed.zeroize();
            Ok(kp)
        }
        "x25519" => {
            let mut sk_bytes = [0u8; 32];
            os_random(&mut sk_bytes)?;
            let sk = easylock_core::ec::StaticSecret::from_bytes(sk_bytes);
            let kp = KeyPair {
                kind: "X25519".into(),
                public: hex::encode(sk.public_key().as_bytes()),
                secret: hex::encode(&sk.to_bytes()),
                note: "Curve25519 ECDH key pair (RFC 7748).".into(),
            };
            sk_bytes.zeroize();
            Ok(kp)
        }
        "mlkem768" => {
            let mut rng = |b: &mut [u8]| {
                let _ = os_random(b);
            };
            let (ek, dk) =
                easylock_core::pqc::mlkem::keygen(&easylock_core::pqc::MlKem768, &mut rng);
            Ok(KeyPair {
                kind: "ML-KEM-768".into(),
                public: hex::encode(&ek),
                secret: hex::encode(&dk),
                note: "Post-quantum KEM (FIPS 203). ek 1184 B, dk 2400 B.".into(),
            })
        }
        "rsa2048" => {
            let mut rng = |b: &mut [u8]| {
                let _ = os_random(b);
            };
            let sk = easylock_core::rsa::keygen::generate_rsa2048(&mut rng)
                .map_err(|e| e.to_string())?;
            let c = sk.export_components();
            Ok(KeyPair {
                kind: "RSA-2048".into(),
                public: format!("n={}\ne={}", hex::encode(&c.n), c.e),
                secret: format!(
                    "p={}\nq={}\ndp={}\ndq={}\nqinv={}",
                    hex::encode(&c.p),
                    hex::encode(&c.q),
                    hex::encode(&c.dp),
                    hex::encode(&c.dq),
                    hex::encode(&c.qinv)
                ),
                note: "Fresh 2048-bit modulus, F4 exponent. Raw CRT components \
                       (no DER/PEM encoder in core yet)."
                    .into(),
            })
        }
        other => Err(format!("unknown key kind: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transform_pipeline_roundtrip() {
        let enc = run_transform("hello gui", &["base64".into(), "hex".into()], false).unwrap();
        let dec = run_transform(&enc, &["base64".into(), "hex".into()], true).unwrap();
        assert_eq!(dec, "hello gui");
    }

    #[test]
    fn password_respects_length_and_classes() {
        let p = gen_password(24, true, true, true, false).unwrap();
        assert_eq!(p.chars().count(), 24);
        assert!(p.chars().all(|c| c.is_ascii_alphanumeric()));
        assert!(gen_password(2, true, true, true, true).is_err());
        assert!(gen_password(16, false, false, false, false).is_err());
    }

    #[test]
    fn file_encrypt_decrypt_roundtrip() {
        let dir = std::env::temp_dir();
        let src = dir.join("easylock_gui_test_input.bin");
        let data: Vec<u8> = (0..(CHUNK * 2 + 1234)).map(|i| (i % 251) as u8).collect();
        std::fs::write(&src, &data).unwrap();

        let op = encrypt_file(
            src.to_str().unwrap(),
            "chacha20-poly1305",
            "correct horse".into(),
            |_, _| {},
        )
        .unwrap();
        let dec = decrypt_file(&op.out_path, "correct horse".into(), |_, _| {}).unwrap();
        assert_eq!(std::fs::read(&dec.out_path).unwrap(), data);

        // wrong password fails
        assert!(decrypt_file(&op.out_path, "wrong".into(), |_, _| {}).is_err());

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&op.out_path);
        let _ = std::fs::remove_file(&dec.out_path);
    }

    #[test]
    fn keypairs_generate() {
        assert_eq!(gen_keypair("ed25519").unwrap().public.len(), 64);
        assert_eq!(gen_keypair("x25519").unwrap().public.len(), 64);
        assert_eq!(gen_keypair("mlkem768").unwrap().public.len(), 1184 * 2);
    }

    #[test]
    fn argon2_phc_shape() {
        let s = argon2_phc("pw".into(), 8, 1, 1).unwrap();
        assert!(s.starts_with("$argon2id$v=19$m=8,t=1,p=1$"));
    }
}
