//! `easylock-server` — an async REST facade over `easylock-core`.
//!
//! Endpoints (all JSON; binary fields are Base64 unless suffixed `_hex`):
//!
//! | Method | Path              | Body                                            | Response                |
//! |--------|-------------------|-------------------------------------------------|-------------------------|
//! | GET    | `/health`         | —                                               | `{status,version,aes}`  |
//! | POST   | `/v1/hash`        | `{algo, data}`                                   | `{digest_hex}`          |
//! | POST   | `/v1/aead/seal`   | `{alg, key_hex, nonce_hex, aad?, plaintext}`     | `{ciphertext}`          |
//! | POST   | `/v1/aead/open`   | `{alg, key_hex, nonce_hex, aad?, ciphertext}`    | `{plaintext}` / 401     |
//! | POST   | `/v1/x25519`      | `{scalar_hex, point_hex}`                        | `{shared_hex}`          |
//! | POST   | `/v1/ed25519/sign`| `{seed_hex, message}`                            | `{public_hex, sig_hex}` |
//! | POST   | `/v1/ed25519/verify` | `{public_hex, message, sig_hex}`             | `{valid}`               |
//!
//! gRPC is planned; the routing layer is kept thin so a `tonic` service can be
//! mounted alongside.

use axum::{
    extract::Json,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use easylock_core::{
    aead::{Aead, Aes256Gcm, ChaCha20Poly1305},
    ec::{Signature, SigningKey, VerifyingKey},
    encode::{base64, hex},
    hash::Algorithm,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

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
        "easylock-server {} listening on http://{addr}",
        easylock_core::VERSION
    );

    axum::serve(listener, app())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");
}

/// Build the router. Exposed for integration tests.
fn app() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/hash", post(hash))
        .route("/v1/aead/seal", post(aead_seal))
        .route("/v1/aead/open", post(aead_open))
        .route("/v1/x25519", post(x25519))
        .route("/v1/ed25519/sign", post(ed_sign))
        .route("/v1/ed25519/verify", post(ed_verify))
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

// --- handlers -----------------------------------------------------------

#[derive(Serialize)]
struct Health {
    status: &'static str,
    version: &'static str,
    aes_backend: String,
}

async fn health() -> Json<Health> {
    Json(Health {
        status: "ok",
        version: easylock_core::VERSION,
        aes_backend: easylock_core::cipher::aes::active_backend().to_string(),
    })
}

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
        ciphertext: base64::encode(&ct, base64::Variant::Standard),
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
            plaintext: base64::encode(&pt, base64::Variant::Standard),
        })),
        None => Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "authentication failed".into(),
        )),
    }
}

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
        (status, serde_json::from_slice(&bytes).unwrap())
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
        assert_eq!(body["version"], easylock_core::VERSION);
    }

    #[tokio::test]
    async fn hash_endpoint_matches_nist() {
        let (status, body) = post_json(
            "/v1/hash",
            serde_json::json!({"algo":"sha256","data":"YWJj"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["digest_hex"],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[tokio::test]
    async fn aead_seal_open_roundtrip_and_reject() {
        let key = "11".repeat(32);
        let nonce = "22".repeat(12);
        let (_, sealed) = post_json(
            "/v1/aead/seal",
            serde_json::json!({
                "alg":"aes-256-gcm","key_hex":key,"nonce_hex":nonce,
                "plaintext":"c2VjcmV0"
            }),
        )
        .await;
        let ct = sealed["ciphertext"].as_str().unwrap().to_string();

        let (status, opened) = post_json(
            "/v1/aead/open",
            serde_json::json!({
                "alg":"aes-256-gcm","key_hex":key,"nonce_hex":nonce,"ciphertext":ct
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(opened["plaintext"], "c2VjcmV0");

        let (status, _) = post_json(
            "/v1/aead/open",
            serde_json::json!({
                "alg":"aes-256-gcm","key_hex":key,"nonce_hex":nonce,
                "ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn ed25519_sign_then_verify() {
        let (_, signed) = post_json(
            "/v1/ed25519/sign",
            serde_json::json!({
                "seed_hex":"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "message":""
            }),
        )
        .await;
        assert_eq!(
            signed["public_hex"],
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let (status, verified) = post_json(
            "/v1/ed25519/verify",
            serde_json::json!({
                "public_hex": signed["public_hex"],
                "message":"",
                "sig_hex": signed["sig_hex"],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(verified["valid"], true);
    }
}
