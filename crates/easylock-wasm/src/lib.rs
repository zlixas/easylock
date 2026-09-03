//! WebAssembly bindings for `easylock-core`.
//!
//! Every operation runs in the browser — no server, no network. Randomness comes
//! from `crypto.getRandomValues` via `getrandom`. Built with `wasm-pack build
//! --target web`; the dashboard imports the generated ESM glue directly.

// wasm-bindgen exports take owned, JS-marshalled values and flat parameter
// lists; several pedantic lints don't apply to `#[wasm_bindgen]` fns.
#![allow(
    clippy::unused_unit,
    clippy::needless_pass_by_value,
    clippy::fn_params_excessive_bools
)]

use easylock_core::{
    aead::{Aead, Aes256Gcm, ChaCha20Poly1305},
    ec::{Signature, SigningKey, StaticSecret, VerifyingKey},
    encode::{hex, Transform},
    hash::Algorithm,
    kdf::argon2::{self, Params as ArgonParams},
    pqc::{mlkem, MlKem1024, MlKem512, MlKem768},
    rsa::keygen as rsa_keygen,
};
use serde::Serialize;
use wasm_bindgen::prelude::*;

fn err(msg: impl core::fmt::Display) -> JsValue {
    JsValue::from_str(&msg.to_string())
}

fn rng() -> impl FnMut(&mut [u8]) {
    |buf: &mut [u8]| getrandom::getrandom(buf).expect("crypto.getRandomValues failed")
}

fn random_vec(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    getrandom::getrandom(&mut v).expect("crypto.getRandomValues failed");
    v
}

fn js<T: Serialize>(v: &T) -> JsValue {
    serde_wasm_bindgen::to_value(v).unwrap_or(JsValue::NULL)
}

/// Library version string.
#[wasm_bindgen]
pub fn version() -> String {
    easylock_core::VERSION.to_string()
}

/// One line describing the build + active AES/GHASH backend
/// (portable software under wasm32).
#[wasm_bindgen]
pub fn build_info() -> String {
    format!(
        "{} · aes:{} · ghash:{}",
        easylock_core::build_info(),
        easylock_core::cipher::aes::active_backend(),
        easylock_core::aead::ghash::active_backend(),
    )
}

// --- hashing -----------------------------------------------------

/// Hash `data` with `algo` (`sha256`, `sha512`, `keccak256`, `sha3-256`, `blake3`).
#[wasm_bindgen]
pub fn hash(algo: &str, data: &[u8]) -> Result<String, JsValue> {
    let alg = Algorithm::parse(algo).ok_or_else(|| err(format!("unknown algorithm `{algo}`")))?;
    Ok(hex::encode(&alg.hash(data)))
}

// --- AEAD --------------------------------------------------------

fn aead_seal_inner(
    alg: &str,
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    pt: &[u8],
) -> Result<Vec<u8>, JsValue> {
    match alg {
        "aes-256-gcm" => Aes256Gcm::new(key).map(|c| c.seal(nonce, aad, pt)),
        "chacha20-poly1305" => ChaCha20Poly1305::new(key).map(|c| c.seal(nonce, aad, pt)),
        other => return Err(err(format!("unknown aead `{other}`"))),
    }
    .map_err(err)
}

#[wasm_bindgen]
pub fn aead_seal(
    alg: &str,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let n: [u8; 12] = nonce
        .try_into()
        .map_err(|_| err("nonce must be 12 bytes"))?;
    aead_seal_inner(alg, key, &n, aad, plaintext)
}

#[wasm_bindgen]
pub fn aead_open(
    alg: &str,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let n: [u8; 12] = nonce
        .try_into()
        .map_err(|_| err("nonce must be 12 bytes"))?;
    let r = match alg {
        "aes-256-gcm" => Aes256Gcm::new(key)
            .ok()
            .and_then(|c| c.open(&n, aad, ciphertext).ok()),
        "chacha20-poly1305" => ChaCha20Poly1305::new(key)
            .ok()
            .and_then(|c| c.open(&n, aad, ciphertext).ok()),
        other => return Err(err(format!("unknown aead `{other}`"))),
    };
    r.ok_or_else(|| err("authentication failed — wrong key/nonce or modified data"))
}

// --- KDF --------------------------------------------------------

#[wasm_bindgen]
pub fn argon2id(
    password: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    parallelism: u32,
    out_len: usize,
) -> Result<Vec<u8>, JsValue> {
    let params = ArgonParams {
        m_cost,
        t_cost,
        parallelism,
        out_len,
    };
    argon2::hash(password, salt, params).map_err(err)
}

#[wasm_bindgen]
pub fn pbkdf2_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out_len: usize,
) -> Result<Vec<u8>, JsValue> {
    easylock_core::kdf::pbkdf2::<easylock_core::hash::Sha256>(password, salt, iterations, out_len)
        .map_err(err)
}

// --- encode pipeline -------------------------------------------

#[wasm_bindgen]
pub fn encode_pipeline(input: &str, steps: Vec<String>, decode: bool) -> Result<String, JsValue> {
    let parsed: Result<Vec<Transform>, JsValue> = steps
        .iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| Transform::parse(s).ok_or_else(|| err(format!("unknown transform `{s}`"))))
        .collect();
    let parsed = parsed?;
    if decode {
        let bytes = easylock_core::encode::chain_decode(input.trim(), &parsed)
            .map_err(|_| err("input is not valid for this pipeline"))?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    } else {
        Ok(easylock_core::encode::chain_encode(
            input.as_bytes(),
            &parsed,
        ))
    }
}

// --- password generator --------------------------------------

#[wasm_bindgen]
pub fn gen_password(
    length: usize,
    lower: bool,
    upper: bool,
    digits: bool,
    symbols: bool,
) -> Result<String, JsValue> {
    let mut pool: Vec<u8> = Vec::new();
    if lower {
        pool.extend_from_slice(b"abcdefghijkmnopqrstuvwxyz");
    }
    if upper {
        pool.extend_from_slice(b"ABCDEFGHJKLMNPQRSTUVWXYZ");
    }
    if digits {
        pool.extend_from_slice(b"23456789");
    }
    if symbols {
        pool.extend_from_slice(b"!@#$%^&*-_=+?");
    }
    if pool.is_empty() || !(4..=256).contains(&length) {
        return Err(err("choose a class and a length in 4..=256"));
    }
    let bound = (256 / pool.len()) * pool.len();
    let mut out = String::with_capacity(length);
    while out.len() < length {
        for &b in &random_vec(length + 16) {
            if out.len() == length {
                break;
            }
            if (b as usize) < bound {
                out.push(pool[b as usize % pool.len()] as char);
            }
        }
    }
    Ok(out)
}

// --- key generation -----------------------------------------

#[derive(Serialize)]
struct KeyPair {
    kind: String,
    public: String,
    secret: String,
    note: String,
}

#[wasm_bindgen]
pub fn keygen(kind: &str) -> Result<JsValue, JsValue> {
    let kp = match kind {
        "ed25519" => {
            let seed: [u8; 32] = random_vec(32).try_into().unwrap();
            let sk = SigningKey::from_seed(seed);
            KeyPair {
                kind: "Ed25519".into(),
                public: hex::encode(sk.verifying_key().as_bytes()),
                secret: hex::encode(&sk.to_seed()),
                note: "32-byte seed / 32-byte public key (RFC 8032).".into(),
            }
        }
        "x25519" => {
            let s: [u8; 32] = random_vec(32).try_into().unwrap();
            let sk = StaticSecret::from_bytes(s);
            KeyPair {
                kind: "X25519".into(),
                public: hex::encode(sk.public_key().as_bytes()),
                secret: hex::encode(&sk.to_bytes()),
                note: "Curve25519 ECDH key pair (RFC 7748).".into(),
            }
        }
        "mlkem512" | "mlkem768" | "mlkem1024" => {
            let params = match kind {
                "mlkem512" => &MlKem512,
                "mlkem1024" => &MlKem1024,
                _ => &MlKem768,
            };
            let (ek, dk) = mlkem::keygen(params, &mut rng());
            KeyPair {
                kind: params.name.to_string(),
                public: hex::encode(&ek),
                secret: hex::encode(&dk),
                note: format!("FIPS 203 KEM — ek {} B, dk {} B.", ek.len(), dk.len()),
            }
        }
        "rsa2048" => {
            let sk = rsa_keygen::generate_rsa2048(&mut rng()).map_err(err)?;
            let c = sk.export_components();
            KeyPair {
                kind: "RSA-2048".into(),
                public: format!("n={}\ne={}", hex::encode(&c.n), c.e),
                secret: format!(
                    "p={}\nq={}\ndp={}\ndq={}\nqinv={}",
                    hex::encode(&c.p),
                    hex::encode(&c.q),
                    hex::encode(&c.dp),
                    hex::encode(&c.dq),
                    hex::encode(&c.qinv),
                ),
                note: "Fresh 2048-bit modulus, F4 exponent. Raw CRT components.".into(),
            }
        }
        other => return Err(err(format!("unknown key kind `{other}`"))),
    };
    Ok(js(&kp))
}

// --- ML-KEM encaps / decaps --------------------------------

fn mlkem_params(name: &str) -> Result<&'static mlkem::Params, JsValue> {
    Ok(match name {
        "mlkem512" => &MlKem512,
        "mlkem1024" => &MlKem1024,
        "mlkem768" => &MlKem768,
        other => return Err(err(format!("unknown ML-KEM set `{other}`"))),
    })
}

#[derive(Serialize)]
struct Encaps {
    ciphertext_hex: String,
    shared_secret_hex: String,
}

#[wasm_bindgen]
pub fn mlkem_encaps(param: &str, ek_hex: &str) -> Result<JsValue, JsValue> {
    let p = mlkem_params(param)?;
    let ek = hex::decode(ek_hex).map_err(|_| err("invalid ek hex"))?;
    let (k, ct) = mlkem::encaps(p, &ek, &mut rng()).map_err(err)?;
    Ok(js(&Encaps {
        ciphertext_hex: hex::encode(&ct),
        shared_secret_hex: hex::encode(&k),
    }))
}

#[wasm_bindgen]
pub fn mlkem_decaps(param: &str, dk_hex: &str, ciphertext_hex: &str) -> Result<String, JsValue> {
    let p = mlkem_params(param)?;
    let dk = hex::decode(dk_hex).map_err(|_| err("invalid dk hex"))?;
    let ct = hex::decode(ciphertext_hex).map_err(|_| err("invalid ciphertext hex"))?;
    Ok(hex::encode(&mlkem::decaps(p, &dk, &ct).map_err(err)?))
}

// --- Ed25519 / X25519 -------------------------------------

#[derive(Serialize)]
struct EdSig {
    public_hex: String,
    sig_hex: String,
}

#[wasm_bindgen]
pub fn ed25519_sign(seed_hex: &str, message: &[u8]) -> Result<JsValue, JsValue> {
    let seed: [u8; 32] = hex::decode(seed_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| err("seed must be 32 hex bytes"))?;
    let sk = SigningKey::from_seed(seed);
    let sig = sk.sign(message);
    Ok(js(&EdSig {
        public_hex: hex::encode(sk.verifying_key().as_bytes()),
        sig_hex: hex::encode(&sig.to_bytes()),
    }))
}

#[wasm_bindgen]
pub fn ed25519_verify(public_hex: &str, message: &[u8], sig_hex: &str) -> Result<bool, JsValue> {
    let pk: [u8; 32] = hex::decode(public_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| err("public key must be 32 hex bytes"))?;
    let sig: [u8; 64] = hex::decode(sig_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| err("signature must be 64 hex bytes"))?;
    Ok(VerifyingKey::from_bytes(pk).verify(message, &Signature::from_bytes(sig)))
}

#[wasm_bindgen]
pub fn x25519(scalar_hex: &str, point_hex: &str) -> Result<String, JsValue> {
    let s: [u8; 32] = hex::decode(scalar_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| err("scalar must be 32 hex bytes"))?;
    let p: [u8; 32] = hex::decode(point_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| err("point must be 32 hex bytes"))?;
    Ok(hex::encode(&easylock_core::ec::x25519(&s, &p)))
}

/// Fill a fresh `Uint8Array` of `n` random bytes (browser CSPRNG).
#[wasm_bindgen]
pub fn random_bytes(n: usize) -> Vec<u8> {
    random_vec(n)
}
