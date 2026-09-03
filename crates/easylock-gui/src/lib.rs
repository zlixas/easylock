//! Tauri v2 IPC layer for the easylock desktop app.
//!
//! Every command is a thin wrapper over [`crypto`]; no HTTP server is involved —
//! the frontend talks to `easylock-core` directly over Tauri's IPC bridge.
//! Password/key `String`s are converted to byte buffers and
//! [`Zeroize`](easylock_core::secure::Zeroize)d as soon as they are consumed.

// Tauri commands must take owned, IPC-deserialized values and flat parameter
// lists — both trip these pedantic lints.
#![allow(clippy::needless_pass_by_value, clippy::fn_params_excessive_bools)]

mod crypto;

use serde::Serialize;
use tauri::{Emitter, Window};

#[derive(Serialize, Debug)]
pub struct SysInfo {
    version: String,
    build: String,
    aes_backend: String,
    ghash_backend: String,
}

#[tauri::command]
fn sys_info() -> SysInfo {
    SysInfo {
        version: easylock_core::VERSION.to_string(),
        build: easylock_core::build_info(),
        aes_backend: easylock_core::cipher::aes::active_backend().to_string(),
        ghash_backend: easylock_core::aead::ghash::active_backend().to_string(),
    }
}

#[tauri::command]
fn hash_text(input: String, is_base64: bool, algo: String) -> Result<String, String> {
    let data = if is_base64 {
        easylock_core::encode::base64::decode(
            input.trim(),
            easylock_core::encode::base64::Variant::Standard,
        )
        .map_err(|_| "invalid base64 input".to_string())?
    } else {
        input.into_bytes()
    };
    crypto::hash_bytes(&data, &algo)
}

#[derive(Serialize, Debug)]
pub struct HashFileResult {
    digest: String,
    size: u64,
}

#[tauri::command]
fn hash_file(path: String, algo: String) -> Result<HashFileResult, String> {
    let (digest, size) = crypto::hash_file_path(&path, &algo)?;
    Ok(HashFileResult { digest, size })
}

#[tauri::command]
fn transform(input: String, steps: Vec<String>, decode: bool) -> Result<String, String> {
    crypto::run_transform(&input, &steps, decode)
}

#[derive(Serialize, Debug)]
pub struct FileOpResult {
    out_path: String,
    cipher: String,
    bytes_in: u64,
    bytes_out: u64,
}

#[derive(Serialize, Clone, Debug)]
struct Progress {
    op: &'static str,
    done: u64,
    total: u64,
}

#[tauri::command]
fn encrypt_file(
    window: Window,
    path: String,
    cipher: String,
    password: String,
) -> Result<FileOpResult, String> {
    let w = window.clone();
    let op = crypto::encrypt_file(&path, &cipher, password, move |done, total| {
        let _ = w.emit(
            "file-progress",
            Progress {
                op: "encrypt",
                done,
                total,
            },
        );
    })?;
    Ok(FileOpResult {
        out_path: op.out_path,
        cipher: op.cipher.to_string(),
        bytes_in: op.bytes_in,
        bytes_out: op.bytes_out,
    })
}

#[tauri::command]
fn decrypt_file(window: Window, path: String, password: String) -> Result<FileOpResult, String> {
    let w = window.clone();
    let op = crypto::decrypt_file(&path, password, move |done, total| {
        let _ = w.emit(
            "file-progress",
            Progress {
                op: "decrypt",
                done,
                total,
            },
        );
    })?;
    Ok(FileOpResult {
        out_path: op.out_path,
        cipher: op.cipher.to_string(),
        bytes_in: op.bytes_in,
        bytes_out: op.bytes_out,
    })
}

#[tauri::command]
fn gen_password(
    length: usize,
    lower: bool,
    upper: bool,
    digits: bool,
    symbols: bool,
) -> Result<String, String> {
    crypto::gen_password(length, lower, upper, digits, symbols)
}

#[tauri::command]
fn gen_argon2(
    password: String,
    m_cost: u32,
    t_cost: u32,
    parallelism: u32,
) -> Result<String, String> {
    crypto::argon2_phc(password, m_cost, t_cost, parallelism)
}

#[derive(Serialize, Debug)]
pub struct KeyPairResult {
    kind: String,
    public: String,
    secret: String,
    note: String,
}

#[tauri::command]
async fn gen_keypair(kind: String) -> Result<KeyPairResult, String> {
    // RSA keygen is CPU-heavy; run it off the UI thread.
    let kp = tauri::async_runtime::spawn_blocking(move || crypto::gen_keypair(&kind))
        .await
        .map_err(|e| e.to_string())??;
    Ok(KeyPairResult {
        kind: kp.kind,
        public: kp.public,
        secret: kp.secret,
        note: kp.note,
    })
}

/// Tauri entry point (shared by `main.rs` and the mobile shims).
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            sys_info,
            hash_text,
            hash_file,
            transform,
            encrypt_file,
            decrypt_file,
            gen_password,
            gen_argon2,
            gen_keypair,
        ])
        .run(tauri::generate_context!())
        .expect("error while running easylock desktop");
}
