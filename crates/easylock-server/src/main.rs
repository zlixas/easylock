//! `easylock-server` — an async REST facade over `easylock-core`, and the static
//! host for the `easylock-web` dashboard.
//!
//! All API endpoints live under `/v1`; binary fields are Base64 unless the key
//! is suffixed `_hex`. Anything else is served from the built web frontend
//! (`EASYLOCK_WEB_DIST`, default `crates/easylock-web/dist`) with an SPA
//! fallback to `index.html`.
//!
//! | Method | Path                    | Purpose                                   |
//! |--------|-------------------------|-------------------------------------------|
//! | GET    | `/health`               | version + active backends                 |
//! | POST   | `/v1/hash`              | SHA-2/3, Keccak, BLAKE3                    |
//! | POST   | `/v1/aead/seal` `/open` | AES-256-GCM / ChaCha20-Poly1305            |
//! | POST   | `/v1/kdf/argon2`        | Argon2id                                  |
//! | POST   | `/v1/kdf/pbkdf2`        | PBKDF2-HMAC                                |
//! | POST   | `/v1/encode`            | hex/base64/base58/rot13 pipeline           |
//! | POST   | `/v1/password`          | CSPRNG password generator                 |
//! | POST   | `/v1/keygen`            | ed25519 / x25519 / rsa2048 / mlkem768      |
//! | POST   | `/v1/mlkem/encaps` `/decaps` | ML-KEM encapsulate / decapsulate      |
//! | POST   | `/v1/x25519`            | raw X25519                                |
//! | POST   | `/v1/ed25519/sign` `/verify` | Ed25519                              |

mod random;

use axum::{
    extract::{DefaultBodyLimit, Json},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use easylock_core::{
    aead::{Aead, Aes256Gcm, ChaCha20Poly1305},
    ec::{Signature, SigningKey, StaticSecret, VerifyingKey},
    encode::{base64, hex, Transform},
    hash::{Algorithm, Sha256},
    kdf::argon2::{self, Params as ArgonParams},
    pqc::{mlkem, MlKem1024, MlKem512, MlKem768},
    rsa::keygen as rsa_keygen,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tower_http::{cors::CorsLayer, services::ServeDir};

#[tokio::main]
async fn main() {
    let addr: SocketAddr = std::env::var("EASYLOCK_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()
        .expect("EASYLOCK_LISTEN must be host:port");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind failed");
    eprintln!(
        "easylock-server {} listening on http://{addr}  (web: {})",
        easylock_core::VERSION,
        web_dist().display(),
    );

    axum::serve(listener, app())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");
}

fn web_dist() -> std::path::PathBuf {
    std::env::var("EASYLOCK_WEB_DIST").map_or_else(
        |_| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../easylock-web/dist"),
        std::path::PathBuf::from,
    )
}

/// Build the router. Exposed for integration tests.
fn app() -> Router {
    let api = Router::new()
        .route("/health", get(health))
        .route("/v1/hash", post(hash))
        .route("/v1/aead/seal", post(aead_seal))
        .route("/v1/aead/open", post(aead_open))
        .route("/v1/kdf/argon2", post(kdf_argon2))
        .route("/v1/kdf/pbkdf2", post(kdf_pbkdf2))
        .route("/v1/encode", post(encode_pipeline))
        .route("/v1/password", post(password))
        .route("/v1/keygen", post(keygen))
        .route("/v1/mlkem/encaps", post(mlkem_encaps))
        .route("/v1/mlkem/decaps", post(mlkem_decaps))
        .route("/v1/x25519", post(x25519))
        .route("/v1/ed25519/sign", post(ed_sign))
        .route("/v1/ed25519/verify", post(ed_verify))
        .layer(DefaultBodyLimit::max(16 * 1024 * 1024))
        .layer(CorsLayer::very_permissive());

    // Static frontend with SPA fallback; missing dist just yields 404s for `/`.
    let dist = web_dist();
    let serve = ServeDir::new(&dist).fallback(tower_http::services::ServeFile::new(
        dist.join("index.html"),
    ));
    api.fallback_service(serve)
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("shutting down");
}

// --- error plumbing -------------------------------------------------------

struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

type ApiResult<T> = Result<T, ApiError>;

fn de_hex(s: &str, what: &str) -> ApiResult<Vec<u8>> {
    hex::decode(s).map_err(|_| bad(format!("invalid hex in `{what}`")))
}

fn de_b64(s: &str, what: &str) -> ApiResult<Vec<u8>> {
    base64::decode(s, base64::Variant::Standard)
        .map_err(|_| bad(format!("invalid base64 in `{what}`")))
}

fn fixed<const N: usize>(v: &[u8], what: &str) -> ApiResult<[u8; N]> {
    v.try_into()
        .map_err(|_| bad(format!("`{what}` must be {N} bytes")))
}

fn b64(data: &[u8]) -> String {
    base64::encode(data, base64::Variant::Standard)
}

// --- health -----------------------------------------------------------

#[derive(Serialize)]
struct Health {
    status: &'static str,
    version: &'static str,
    aes_backend: String,
    ghash_backend: String,
}

async fn health() -> Json<Health> {
    Json(Health {
        status: "ok",
        version: easylock_core::VERSION,
        aes_backend: easylock_core::cipher::aes::active_backend().to_string(),
        ghash_backend: easylock_core::aead::ghash::active_backend().to_string(),
    })
}

// --- hashing --------------------------------------------------------

#[derive(Deserialize)]
struct HashReq {
    algo: String,
    /// Base64 data, or hex if `hex` is true.
    data: String,
    #[serde(default)]
    hex: bool,
}

#[derive(Serialize)]
struct HashResp {
    digest_hex: String,
}

async fn hash(Json(req): Json<HashReq>) -> ApiResult<Json<HashResp>> {
    let alg = Algorithm::parse(&req.algo)
        .ok_or_else(|| bad(format!("unknown algorithm `{}`", req.algo)))?;
    let data = if req.hex {
        de_hex(&req.data, "data")?
    } else {
        de_b64(&req.data, "data")?
    };
    Ok(Json(HashResp {
        digest_hex: hex::encode(&alg.hash(&data)),
    }))
}

// --- AEAD ----------------------------------------------------------

#[derive(Deserialize)]
struct AeadReq {
    alg: String,
    key_hex: String,
    nonce_hex: String,
    #[serde(default)]
    aad_hex: String,
    #[serde(default)]
    plaintext: String,
    #[serde(default)]
    ciphertext: String,
}

#[derive(Serialize)]
struct SealResp {
    ciphertext: String,
}
#[derive(Serialize)]
struct OpenResp {
    plaintext: String,
}

fn seal_with(alg: &str, key: &[u8], nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> ApiResult<Vec<u8>> {
    match alg {
        "aes-256-gcm" => Aes256Gcm::new(key).map(|c| c.seal(nonce, aad, pt)),
        "chacha20-poly1305" => ChaCha20Poly1305::new(key).map(|c| c.seal(nonce, aad, pt)),
        other => return Err(bad(format!("unknown aead `{other}`"))),
    }
    .map_err(|_| bad("bad key length (need 32 bytes)"))
}

async fn aead_seal(Json(req): Json<AeadReq>) -> ApiResult<Json<SealResp>> {
    let key = de_hex(&req.key_hex, "key_hex")?;
    let nonce = fixed::<12>(&de_hex(&req.nonce_hex, "nonce_hex")?, "nonce_hex")?;
    let aad = de_hex(&req.aad_hex, "aad_hex")?;
    let pt = de_b64(&req.plaintext, "plaintext")?;
    let ct = seal_with(&req.alg, &key, &nonce, &aad, &pt)?;
    Ok(Json(SealResp {
        ciphertext: b64(&ct),
    }))
}

async fn aead_open(Json(req): Json<AeadReq>) -> ApiResult<Json<OpenResp>> {
    let key = de_hex(&req.key_hex, "key_hex")?;
    let nonce = fixed::<12>(&de_hex(&req.nonce_hex, "nonce_hex")?, "nonce_hex")?;
    let aad = de_hex(&req.aad_hex, "aad_hex")?;
    let ct = de_b64(&req.ciphertext, "ciphertext")?;
    let opened = match req.alg.as_str() {
        "aes-256-gcm" => Aes256Gcm::new(&key)
            .ok()
            .and_then(|c| c.open(&nonce, &aad, &ct).ok()),
        "chacha20-poly1305" => ChaCha20Poly1305::new(&key)
            .ok()
            .and_then(|c| c.open(&nonce, &aad, &ct).ok()),
        other => return Err(bad(format!("unknown aead `{other}`"))),
    };
    match opened {
        Some(pt) => Ok(Json(OpenResp {
            plaintext: b64(&pt),
        })),
        None => Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "authentication failed".into(),
        )),
    }
}

// --- KDF ---------------------------------------------------------

#[derive(Deserialize)]
struct Argon2Req {
    /// UTF-8 password.
    password: String,
    /// Optional hex salt; a random 16-byte salt is generated when absent.
    #[serde(default)]
    salt_hex: String,
    #[serde(default = "d_m")]
    m_cost: u32,
    #[serde(default = "d_t")]
    t_cost: u32,
    #[serde(default = "d_p")]
    parallelism: u32,
    #[serde(default = "d_len")]
    out_len: usize,
}
fn d_m() -> u32 {
    65536
}
fn d_t() -> u32 {
    3
}
fn d_p() -> u32 {
    4
}
fn d_len() -> usize {
    32
}

#[derive(Serialize)]
struct Argon2Resp {
    tag_hex: String,
    salt_hex: String,
    phc: String,
}

async fn kdf_argon2(Json(req): Json<Argon2Req>) -> ApiResult<Json<Argon2Resp>> {
    let salt = if req.salt_hex.is_empty() {
        random::bytes(16).map_err(bad)?
    } else {
        de_hex(&req.salt_hex, "salt_hex")?
    };
    let params = ArgonParams {
        m_cost: req.m_cost,
        t_cost: req.t_cost,
        parallelism: req.parallelism,
        out_len: req.out_len,
    };
    let tag =
        argon2::hash(req.password.as_bytes(), &salt, params).map_err(|e| bad(e.to_string()))?;
    Ok(Json(Argon2Resp {
        tag_hex: hex::encode(&tag),
        salt_hex: hex::encode(&salt),
        phc: format!(
            "$argon2id$v=19$m={},t={},p={}${}${}",
            req.m_cost,
            req.t_cost,
            req.parallelism,
            base64::encode(&salt, base64::Variant::UrlNoPad),
            base64::encode(&tag, base64::Variant::UrlNoPad),
        ),
    }))
}

#[derive(Deserialize)]
struct Pbkdf2Req {
    password: String,
    salt_hex: String,
    iterations: u32,
    #[serde(default = "d_len")]
    out_len: usize,
    #[serde(default = "d_sha")]
    hash: String,
}
fn d_sha() -> String {
    "sha256".into()
}

async fn kdf_pbkdf2(Json(req): Json<Pbkdf2Req>) -> ApiResult<Json<HashResp>> {
    let salt = de_hex(&req.salt_hex, "salt_hex")?;
    let dk = match req.hash.as_str() {
        "sha256" => easylock_core::kdf::pbkdf2::<Sha256>(
            req.password.as_bytes(),
            &salt,
            req.iterations,
            req.out_len,
        ),
        "sha512" => easylock_core::kdf::pbkdf2::<easylock_core::hash::Sha512>(
            req.password.as_bytes(),
            &salt,
            req.iterations,
            req.out_len,
        ),
        other => return Err(bad(format!("unsupported prf `{other}`"))),
    }
    .map_err(|e| bad(e.to_string()))?;
    Ok(Json(HashResp {
        digest_hex: hex::encode(&dk),
    }))
}

// --- encode pipeline ---------------------------------------------

#[derive(Deserialize)]
struct EncodeReq {
    /// For encode: raw text. For decode: the encoded text.
    input: String,
    /// Ordered transform names, applied left→right for encode.
    steps: Vec<String>,
    #[serde(default)]
    decode: bool,
}

#[derive(Serialize)]
struct EncodeResp {
    output: String,
}

async fn encode_pipeline(Json(req): Json<EncodeReq>) -> ApiResult<Json<EncodeResp>> {
    let steps: Result<Vec<Transform>, _> = req
        .steps
        .iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| Transform::parse(s).ok_or_else(|| bad(format!("unknown transform `{s}`"))))
        .collect();
    let steps = steps?;
    let output = if req.decode {
        let bytes = easylock_core::encode::chain_decode(req.input.trim(), &steps)
            .map_err(|_| bad("input is not valid for this pipeline"))?;
        String::from_utf8_lossy(&bytes).into_owned()
    } else {
        easylock_core::encode::chain_encode(req.input.as_bytes(), &steps)
    };
    Ok(Json(EncodeResp { output }))
}

// --- password generator ----------------------------------------

#[derive(Deserialize)]
struct PasswordReq {
    #[serde(default = "d_pwlen")]
    length: usize,
    #[serde(default = "d_true")]
    lower: bool,
    #[serde(default = "d_true")]
    upper: bool,
    #[serde(default = "d_true")]
    digits: bool,
    #[serde(default)]
    symbols: bool,
}
fn d_pwlen() -> usize {
    20
}
fn d_true() -> bool {
    true
}

#[derive(Serialize)]
struct PasswordResp {
    password: String,
    bits_of_entropy: f64,
}

async fn password(Json(req): Json<PasswordReq>) -> ApiResult<Json<PasswordResp>> {
    let mut pool: Vec<u8> = Vec::new();
    if req.lower {
        pool.extend_from_slice(b"abcdefghijkmnopqrstuvwxyz");
    }
    if req.upper {
        pool.extend_from_slice(b"ABCDEFGHJKLMNPQRSTUVWXYZ");
    }
    if req.digits {
        pool.extend_from_slice(b"23456789");
    }
    if req.symbols {
        pool.extend_from_slice(b"!@#$%^&*-_=+?");
    }
    if pool.is_empty() || !(4..=256).contains(&req.length) {
        return Err(bad("choose a class and a length in 4..=256"));
    }
    let raw = random::bytes(req.length * 2 + 16).map_err(bad)?;
    let bound = (256 / pool.len()) * pool.len();
    let mut out = String::with_capacity(req.length);
    for &b in &raw {
        if out.len() == req.length {
            break;
        }
        if (b as usize) < bound {
            out.push(pool[b as usize % pool.len()] as char);
        }
    }
    while out.len() < req.length {
        // extremely unlikely; top up deterministically-unbiased
        let more = random::bytes(req.length).map_err(bad)?;
        for &b in &more {
            if out.len() == req.length {
                break;
            }
            if (b as usize) < bound {
                out.push(pool[b as usize % pool.len()] as char);
            }
        }
    }
    // length <= 256 and pool <= 70, so the f64 conversions are exact.
    let bits = f64::from(u16::try_from(req.length).unwrap_or(u16::MAX))
        * f64::from(u16::try_from(pool.len()).unwrap_or(1)).log2();
    Ok(Json(PasswordResp {
        password: out,
        bits_of_entropy: (bits * 10.0).round() / 10.0,
    }))
}

// --- key generation ---------------------------------------------

#[derive(Deserialize)]
struct KeygenReq {
    kind: String,
}

#[derive(Serialize)]
struct KeygenResp {
    kind: String,
    public: String,
    secret: String,
    note: String,
}

async fn keygen(Json(req): Json<KeygenReq>) -> ApiResult<Json<KeygenResp>> {
    // Heavy work (RSA) goes on a blocking thread.
    let resp = tokio::task::spawn_blocking(move || keygen_blocking(&req.kind))
        .await
        .map_err(|e| bad(e.to_string()))??;
    Ok(Json(resp))
}

fn keygen_blocking(kind: &str) -> ApiResult<KeygenResp> {
    match kind {
        "ed25519" => {
            let seed: [u8; 32] = fixed::<32>(&random::bytes(32).map_err(bad)?, "seed")?;
            let sk = SigningKey::from_seed(seed);
            Ok(KeygenResp {
                kind: "Ed25519".into(),
                public: hex::encode(sk.verifying_key().as_bytes()),
                secret: hex::encode(&sk.to_seed()),
                note: "32-byte seed / 32-byte public key (RFC 8032).".into(),
            })
        }
        "x25519" => {
            let s: [u8; 32] = fixed::<32>(&random::bytes(32).map_err(bad)?, "secret")?;
            let sk = StaticSecret::from_bytes(s);
            Ok(KeygenResp {
                kind: "X25519".into(),
                public: hex::encode(sk.public_key().as_bytes()),
                secret: hex::encode(&sk.to_bytes()),
                note: "Curve25519 ECDH key pair (RFC 7748).".into(),
            })
        }
        "mlkem512" | "mlkem768" | "mlkem1024" => {
            let params = match kind {
                "mlkem512" => &MlKem512,
                "mlkem1024" => &MlKem1024,
                _ => &MlKem768,
            };
            let mut rng = |b: &mut [u8]| {
                let r = random::bytes(b.len()).unwrap_or_else(|_| vec![0; b.len()]);
                b.copy_from_slice(&r);
            };
            let (ek, dk) = mlkem::keygen(params, &mut rng);
            Ok(KeygenResp {
                kind: params.name.to_string(),
                public: hex::encode(&ek),
                secret: hex::encode(&dk),
                note: format!("FIPS 203 KEM — ek {} B, dk {} B.", ek.len(), dk.len()),
            })
        }
        "rsa2048" => {
            let mut rng = |b: &mut [u8]| {
                let r = random::bytes(b.len()).unwrap_or_else(|_| vec![0; b.len()]);
                b.copy_from_slice(&r);
            };
            let sk = rsa_keygen::generate_rsa2048(&mut rng).map_err(|e| bad(e.to_string()))?;
            let c = sk.export_components();
            Ok(KeygenResp {
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
            })
        }
        other => Err(bad(format!("unknown key kind `{other}`"))),
    }
}

// --- ML-KEM encaps / decaps -----------------------------------

fn mlkem_params(name: &str) -> ApiResult<&'static mlkem::Params> {
    match name {
        "mlkem512" | "ml-kem-512" => Ok(&MlKem512),
        "mlkem768" | "ml-kem-768" => Ok(&MlKem768),
        "mlkem1024" | "ml-kem-1024" => Ok(&MlKem1024),
        other => Err(bad(format!("unknown ML-KEM parameter set `{other}`"))),
    }
}

#[derive(Deserialize)]
struct EncapsReq {
    param: String,
    ek_hex: String,
}
#[derive(Serialize)]
struct EncapsResp {
    ciphertext_hex: String,
    shared_secret_hex: String,
}

async fn mlkem_encaps(Json(req): Json<EncapsReq>) -> ApiResult<Json<EncapsResp>> {
    let params = mlkem_params(&req.param)?;
    let ek = de_hex(&req.ek_hex, "ek_hex")?;
    let mut rng = |b: &mut [u8]| {
        let r = random::bytes(b.len()).unwrap_or_else(|_| vec![0; b.len()]);
        b.copy_from_slice(&r);
    };
    let (k, ct) = mlkem::encaps(params, &ek, &mut rng).map_err(|e| bad(e.to_string()))?;
    Ok(Json(EncapsResp {
        ciphertext_hex: hex::encode(&ct),
        shared_secret_hex: hex::encode(&k),
    }))
}

#[derive(Deserialize)]
struct DecapsReq {
    param: String,
    dk_hex: String,
    ciphertext_hex: String,
}

async fn mlkem_decaps(Json(req): Json<DecapsReq>) -> ApiResult<Json<HashResp>> {
    let params = mlkem_params(&req.param)?;
    let dk = de_hex(&req.dk_hex, "dk_hex")?;
    let ct = de_hex(&req.ciphertext_hex, "ciphertext_hex")?;
    let k = mlkem::decaps(params, &dk, &ct).map_err(|e| bad(e.to_string()))?;
    Ok(Json(HashResp {
        digest_hex: hex::encode(&k),
    }))
}

// --- X25519 / Ed25519 -----------------------------------------

#[derive(Deserialize)]
struct X25519Req {
    scalar_hex: String,
    point_hex: String,
}
#[derive(Serialize)]
struct X25519Resp {
    shared_hex: String,
}

async fn x25519(Json(req): Json<X25519Req>) -> ApiResult<Json<X25519Resp>> {
    let scalar = fixed::<32>(&de_hex(&req.scalar_hex, "scalar_hex")?, "scalar_hex")?;
    let point = fixed::<32>(&de_hex(&req.point_hex, "point_hex")?, "point_hex")?;
    Ok(Json(X25519Resp {
        shared_hex: hex::encode(&easylock_core::ec::x25519(&scalar, &point)),
    }))
}

#[derive(Deserialize)]
struct EdSignReq {
    seed_hex: String,
    message: String,
}
#[derive(Serialize)]
struct EdSignResp {
    public_hex: String,
    sig_hex: String,
}

async fn ed_sign(Json(req): Json<EdSignReq>) -> ApiResult<Json<EdSignResp>> {
    let seed = fixed::<32>(&de_hex(&req.seed_hex, "seed_hex")?, "seed_hex")?;
    let msg = de_b64(&req.message, "message")?;
    let sk = SigningKey::from_seed(seed);
    let sig = sk.sign(&msg);
    Ok(Json(EdSignResp {
        public_hex: hex::encode(sk.verifying_key().as_bytes()),
        sig_hex: hex::encode(&sig.to_bytes()),
    }))
}

#[derive(Deserialize)]
struct EdVerifyReq {
    public_hex: String,
    message: String,
    sig_hex: String,
}
#[derive(Serialize)]
struct EdVerifyResp {
    valid: bool,
}

async fn ed_verify(Json(req): Json<EdVerifyReq>) -> ApiResult<Json<EdVerifyResp>> {
    let public = fixed::<32>(&de_hex(&req.public_hex, "public_hex")?, "public_hex")?;
    let sig = fixed::<64>(&de_hex(&req.sig_hex, "sig_hex")?, "sig_hex")?;
    let msg = de_b64(&req.message, "message")?;
    let vk = VerifyingKey::from_bytes(public);
    Ok(Json(EdVerifyResp {
        valid: vk.verify(&msg, &Signature::from_bytes(sig)),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn post_json(path: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    #[tokio::test]
    async fn health_ok() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["status"], "ok");
    }

    #[tokio::test]
    async fn hash_blake3_matches_reference() {
        let (status, body) = post_json(
            "/v1/hash",
            serde_json::json!({"algo":"blake3","data":"YWJj"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["digest_hex"],
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
    }

    #[tokio::test]
    async fn aead_roundtrip() {
        let key = "11".repeat(32);
        let nonce = "22".repeat(12);
        let (_, sealed) = post_json(
            "/v1/aead/seal",
            serde_json::json!({"alg":"chacha20-poly1305","key_hex":key,"nonce_hex":nonce,"plaintext":"c2VjcmV0"}),
        )
        .await;
        let ct = sealed["ciphertext"].as_str().unwrap().to_string();
        let (status, opened) = post_json(
            "/v1/aead/open",
            serde_json::json!({"alg":"chacha20-poly1305","key_hex":key,"nonce_hex":nonce,"ciphertext":ct}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(opened["plaintext"], "c2VjcmV0");
    }

    #[tokio::test]
    async fn argon2_endpoint() {
        let (status, body) = post_json(
            "/v1/kdf/argon2",
            serde_json::json!({"password":"pw","salt_hex":"3030303030303030","m_cost":8,"t_cost":1,"parallelism":1}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["phc"].as_str().unwrap().starts_with("$argon2id$"));
    }

    #[tokio::test]
    async fn encode_pipeline_roundtrip() {
        let (_, enc) = post_json(
            "/v1/encode",
            serde_json::json!({"input":"hello web","steps":["base64","hex"],"decode":false}),
        )
        .await;
        let s = enc["output"].as_str().unwrap().to_string();
        let (_, dec) = post_json(
            "/v1/encode",
            serde_json::json!({"input":s,"steps":["base64","hex"],"decode":true}),
        )
        .await;
        assert_eq!(dec["output"], "hello web");
    }

    #[tokio::test]
    async fn password_endpoint() {
        let (status, body) = post_json(
            "/v1/password",
            serde_json::json!({"length":24,"symbols":true}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["password"].as_str().unwrap().chars().count(), 24);
    }

    #[tokio::test]
    async fn keygen_and_mlkem_flow() {
        let (status, kp) = post_json("/v1/keygen", serde_json::json!({"kind":"mlkem768"})).await;
        assert_eq!(status, StatusCode::OK);
        let ek = kp["public"].as_str().unwrap().to_string();
        let dk = kp["secret"].as_str().unwrap().to_string();

        let (_, enc) = post_json(
            "/v1/mlkem/encaps",
            serde_json::json!({"param":"mlkem768","ek_hex":ek}),
        )
        .await;
        let ct = enc["ciphertext_hex"].as_str().unwrap().to_string();
        let k1 = enc["shared_secret_hex"].as_str().unwrap().to_string();

        let (_, dec) = post_json(
            "/v1/mlkem/decaps",
            serde_json::json!({"param":"mlkem768","dk_hex":dk,"ciphertext_hex":ct}),
        )
        .await;
        assert_eq!(dec["digest_hex"], k1);
    }

    #[tokio::test]
    async fn ed25519_sign_then_verify() {
        let (_, signed) = post_json(
            "/v1/ed25519/sign",
            serde_json::json!({"seed_hex":"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60","message":""}),
        )
        .await;
        assert_eq!(
            signed["public_hex"],
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let (status, verified) = post_json(
            "/v1/ed25519/verify",
            serde_json::json!({"public_hex":signed["public_hex"],"message":"","sig_hex":signed["sig_hex"]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(verified["valid"], true);
    }
}
