//! The crypto worker functions behind the Tauri commands. Kept separate from the
//! IPC layer so they are plain, testable Rust.

#![allow(clippy::fn_params_excessive_bools)]

use easylock_core::container::elk2::{Credential, SlotSpec, FLAG_ARCHIVE};
use easylock_core::container::stream::{self, EncryptOptions};
use easylock_core::container::{archive, Cipher, FILE_PARAMS};
use easylock_core::encode::{hex, Transform};
use easylock_core::hash::Algorithm;
use easylock_core::kdf::argon2::{self, Params as ArgonParams};
use easylock_core::secure::Zeroize;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

#[cfg(test)]
const CHUNK: usize = easylock_core::container::CHUNK;

/// Fill `buf` with OS randomness (`getrandom`).
pub fn os_random(buf: &mut [u8]) -> Result<(), String> {
    getrandom::getrandom(buf).map_err(|e| format!("randomness unavailable: {e}"))
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
//
// Uses the shared streaming ELK2 engine from `easylock_core::container`, so files
// and folders interoperate with the CLI, TUI and website.

/// Result of a file encrypt/decrypt.
pub struct FileOp {
    pub out_path: String,
    pub cipher: &'static str,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// Passes bytes through while reporting progress.
struct Counting<R, F: FnMut(u64)> {
    inner: R,
    done: u64,
    report: F,
}

impl<R: Read, F: FnMut(u64)> Read for Counting<R, F> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.done += n as u64;
        (self.report)(self.done);
        Ok(n)
    }
}

fn dir_size(p: &Path) -> u64 {
    std::fs::read_dir(p).map_or(0, |rd| {
        rd.flatten()
            .map(|e| match std::fs::symlink_metadata(e.path()) {
                Ok(m) if m.is_dir() => dir_size(&e.path()),
                Ok(m) if m.is_file() => m.len(),
                _ => 0,
            })
            .sum()
    })
}

fn auth_or(e: &std::io::Error) -> String {
    match stream::core_error(e) {
        Some(easylock_core::Error::Authentication) => {
            "authentication failed — wrong password or corrupted file".into()
        }
        Some(other) => other.to_string(),
        None => e.to_string(),
    }
}

/// Removes a temporary output unless it was renamed into place.
struct Temp(PathBuf, bool);
impl Drop for Temp {
    fn drop(&mut self) {
        if !self.1 {
            let _ = std::fs::remove_dir_all(&self.0);
            let _ = std::fs::remove_file(&self.0);
        }
    }
}

fn temp_for(out: &Path) -> Result<Temp, String> {
    if out.exists() {
        return Err(format!("{} already exists", out.display()));
    }
    let mut name = out.as_os_str().to_owned();
    name.push(format!(".part-{}", std::process::id()));
    Ok(Temp(PathBuf::from(name), false))
}

/// Encrypt a file or folder at `in_path` to `in_path + ".elk"` with a password.
/// `progress(done, total)` is invoked as data is processed.
pub fn encrypt_file(
    in_path: &str,
    cipher: &str,
    password: String,
    mut progress: impl FnMut(u64, u64),
) -> Result<FileOp, String> {
    let cipher = Cipher::parse(cipher).ok_or_else(|| format!("unknown cipher: {cipher}"))?;
    let src = Path::new(in_path.trim_end_matches('/'));
    let is_dir = src.is_dir();
    let total = if is_dir {
        dir_size(src)
    } else {
        std::fs::metadata(src).map_err(|e| e.to_string())?.len()
    };
    let out = PathBuf::from(format!("{}.elk", src.display()));
    let mut tmp = temp_for(&out)?;

    let mut pw = password.into_bytes();
    let opts = EncryptOptions {
        cipher,
        slots: vec![SlotSpec::Password {
            password: &pw,
            params: FILE_PARAMS,
        }],
        flags: if is_dir { FLAG_ARCHIVE } else { 0 },
    };
    let mut rng = |b: &mut [u8]| os_random(b).expect("OS randomness");
    let result = (|| -> std::io::Result<()> {
        let f = File::create(&tmp.0)?;
        let mut enc = stream::encrypt(f, &opts, &mut rng)?;
        if is_dir {
            archive::pack(src, &mut enc, &mut |d| progress(d, total))?;
        } else {
            let mut r = Counting {
                inner: File::open(src)?,
                done: 0,
                report: |d| progress(d, total),
            };
            std::io::copy(&mut r, &mut enc)?;
        }
        enc.finish()?.sync_all()
    })();
    drop(opts);
    pw.zeroize();
    result.map_err(|e| auth_or(&e))?;
    std::fs::rename(&tmp.0, &out).map_err(|e| e.to_string())?;
    tmp.1 = true;

    Ok(FileOp {
        bytes_out: std::fs::metadata(&out).map_or(0, |m| m.len()),
        out_path: out.display().to_string(),
        cipher: cipher.name(),
        bytes_in: total,
    })
}

/// Decrypt an `.elk` file (ELK1 or ELK2; file or folder), writing next to it with
/// the extension stripped (or `+ ".dec"` if it had none).
pub fn decrypt_file(
    in_path: &str,
    password: String,
    mut progress: impl FnMut(u64, u64),
) -> Result<FileOp, String> {
    let total = std::fs::metadata(in_path).map_err(|e| e.to_string())?.len();
    let out = PathBuf::from(match in_path.strip_suffix(".elk") {
        Some(base) if !base.is_empty() => base.to_string(),
        _ => format!("{in_path}.dec"),
    });
    let mut tmp = temp_for(&out)?;
    let mut pw = password.into_bytes();

    let input = Counting {
        inner: std::io::BufReader::with_capacity(
            1 << 20,
            File::open(in_path).map_err(|e| e.to_string())?,
        ),
        done: 0,
        report: |d| progress(d, total),
    };
    let opened = stream::decrypt(input, &[Credential::Password(&pw)]);
    pw.zeroize();
    let (mut dec, info) = opened.map_err(|e| auth_or(&e))?;
    let bytes_out = if info.archive {
        std::fs::create_dir(&tmp.0).map_err(|e| e.to_string())?;
        archive::unpack(&mut dec, &tmp.0, &mut |_| {})
            .map_err(|e| auth_or(&e))?
            .bytes
    } else {
        let mut f = File::create(&tmp.0).map_err(|e| e.to_string())?;
        let n = std::io::copy(&mut dec, &mut f).map_err(|e| auth_or(&e))?;
        f.sync_all().map_err(|e| e.to_string())?;
        n
    };
    std::fs::rename(&tmp.0, &out).map_err(|e| e.to_string())?;
    tmp.1 = true;

    Ok(FileOp {
        out_path: out.display().to_string(),
        cipher: info.cipher.name(),
        bytes_in: total,
        bytes_out,
    })
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
    Ok(argon2::phc_string(&params, &salt, &tag))
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
        let src = dir.join(format!(
            "easylock_gui_test_input_{}.bin",
            std::process::id()
        ));
        let data: Vec<u8> = (0..(CHUNK * 2 + 1234)).map(|i| (i % 251) as u8).collect();
        std::fs::write(&src, &data).unwrap();

        let op = encrypt_file(
            src.to_str().unwrap(),
            "chacha20-poly1305",
            "correct horse".into(),
            |_, _| {},
        )
        .unwrap();
        // wrong password fails and leaves nothing behind
        assert!(decrypt_file(&op.out_path, "wrong".into(), |_, _| {}).is_err());
        assert!(src.exists());
        // refuses to overwrite the (still present) original
        assert!(decrypt_file(&op.out_path, "correct horse".into(), |_, _| {}).is_err());
        std::fs::remove_file(&src).unwrap();
        let dec = decrypt_file(&op.out_path, "correct horse".into(), |_, _| {}).unwrap();
        assert_eq!(std::fs::read(&dec.out_path).unwrap(), data);

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&op.out_path);
        let _ = std::fs::remove_file(&dec.out_path);
    }

    /// Files written by the desktop app open with the core in-memory reader, and
    /// legacy ELK1 files (older versions) still decrypt.
    #[test]
    fn elk_format_interoperates_with_core_container() {
        use easylock_core::container;
        let dir = std::env::temp_dir();
        let src = dir.join(format!("easylock_gui_interop_{}.bin", std::process::id()));
        let data: Vec<u8> = (0..(CHUNK + 4321)).map(|i| (i % 253) as u8).collect();
        std::fs::write(&src, &data).unwrap();

        let op =
            encrypt_file(src.to_str().unwrap(), "aes-256-gcm", "pw".into(), |_, _| {}).unwrap();
        let sealed = std::fs::read(&op.out_path).unwrap();
        let (plain, _) = stream::open_bytes(&sealed, &[Credential::Password(b"pw")]).unwrap();
        assert_eq!(plain, data);

        let mut rng = |b: &mut [u8]| os_random(b).unwrap();
        let fast = easylock_core::kdf::argon2::Params {
            m_cost: 64,
            t_cost: 1,
            parallelism: 1,
            out_len: 32,
        };
        let legacy =
            container::seal_file(&data, b"pw", Cipher::ChaCha20Poly1305, fast, &mut rng).unwrap();
        let core_path = dir.join(format!(
            "easylock_gui_legacy_{}.bin.elk",
            std::process::id()
        ));
        std::fs::write(&core_path, &legacy).unwrap();
        let dec = decrypt_file(core_path.to_str().unwrap(), "pw".into(), |_, _| {}).unwrap();
        assert_eq!(std::fs::read(&dec.out_path).unwrap(), data);

        for p in [
            src.display().to_string(),
            op.out_path,
            core_path.display().to_string(),
            dec.out_path,
        ] {
            let _ = std::fs::remove_file(p);
        }
    }

    #[test]
    fn folders_roundtrip() {
        let dir = std::env::temp_dir().join(format!("easylock_gui_dir_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/a.txt"), b"folder test").unwrap();
        let op = encrypt_file(
            dir.to_str().unwrap(),
            "chacha20-poly1305",
            "pw".into(),
            |_, _| {},
        )
        .unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        let dec = decrypt_file(&op.out_path, "pw".into(), |_, _| {}).unwrap();
        assert_eq!(
            std::fs::read(dir.join("sub/a.txt")).unwrap(),
            b"folder test"
        );
        let _ = std::fs::remove_dir_all(&dec.out_path);
        let _ = std::fs::remove_file(&op.out_path);
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
