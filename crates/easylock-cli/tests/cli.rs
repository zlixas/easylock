//! Black-box tests that drive the built `easylock` binary over stdin/stdout.

use std::io::Write;
use std::process::{Command, Stdio};

fn run(args: &[&str], stdin: &[u8]) -> (String, String, bool) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_easylock"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let out = child.wait_with_output().unwrap();
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.success(),
    )
}

#[test]
fn hash_sha256_matches_nist() {
    let (stdout, _, ok) = run(&["hash", "--algo", "sha256"], b"abc");
    assert!(ok);
    assert_eq!(
        stdout.trim(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn encode_decode_chain_roundtrips() {
    let (encoded, _, ok) = run(&["encode", "-t", "base64,hex"], b"hello pipeline");
    assert!(ok);
    let (decoded, _, ok) = run(&["decode", "-t", "base64,hex"], encoded.trim().as_bytes());
    assert!(ok);
    assert_eq!(decoded, "hello pipeline");
}

#[test]
fn aead_roundtrip_via_armor() {
    let key = "11".repeat(32);
    let nonce = "22".repeat(12);
    let (ct, stderr, ok) = run(
        &[
            "encrypt",
            "-c",
            "chacha20-poly1305",
            "--key",
            &key,
            "--nonce",
            &nonce,
            "--armor",
        ],
        b"top secret",
    );
    assert!(ok, "{stderr}");
    let (pt, stderr, ok) = run(
        &[
            "decrypt",
            "-c",
            "chacha20-poly1305",
            "--key",
            &key,
            "--nonce",
            &nonce,
            "--armor",
        ],
        ct.trim().as_bytes(),
    );
    assert!(ok, "{stderr}");
    assert_eq!(pt, "top secret");
}

#[test]
fn decrypt_rejects_tampered_ciphertext() {
    let key = "33".repeat(32);
    let nonce = "44".repeat(12);
    let (ct, _, ok) = run(
        &[
            "encrypt",
            "-c",
            "aes-256-gcm",
            "--key",
            &key,
            "--nonce",
            &nonce,
            "--armor",
        ],
        b"authentic",
    );
    assert!(ok);
    // Flip a character in the Base64 body.
    let mut bad: Vec<u8> = ct.trim().bytes().collect();
    bad[0] ^= 0b0000_0100;
    let (_, _, ok) = run(
        &[
            "decrypt",
            "-c",
            "aes-256-gcm",
            "--key",
            &key,
            "--nonce",
            &nonce,
            "--armor",
        ],
        &bad,
    );
    assert!(!ok, "tampered ciphertext must fail");
}

#[test]
fn turkish_locale_changes_error_text() {
    let (_, stderr_en, _) = run(&["--lang", "en", "hash", "--algo", "nope"], b"");
    let (_, stderr_tr, _) = run(&["--lang", "tr", "hash", "--algo", "nope"], b"");
    assert!(stderr_en.contains("unknown hash algorithm"));
    assert!(stderr_tr.contains("bilinmeyen özet algoritması"));
}

#[test]
fn unknown_cipher_is_reported() {
    let (_, stderr, ok) = run(&["encrypt", "-c", "rot13", "--key", "00"], b"x");
    assert!(!ok);
    assert!(stderr.contains("unknown cipher"));
}

#[test]
fn help_is_localized_including_clap_labels() {
    let (out_en, _, ok) = run(&["--help"], b"");
    assert!(ok);
    assert!(out_en.contains("Usage:") && out_en.contains("Commands:"));
    assert!(out_en.contains("from-scratch cryptography toolkit"));

    let (out_tr, _, ok) = run(&["--lang", "tr", "--help"], b"");
    assert!(ok);
    assert!(out_tr.contains("Kullanım:"), "{out_tr}");
    assert!(out_tr.contains("Komutlar:"));
    assert!(out_tr.contains("Seçenekler:"));
    assert!(out_tr.contains("kriptografi araç seti"));
}

#[test]
fn subcommand_help_is_localized() {
    let (out, _, ok) = run(&["--lang", "tr", "encrypt", "--help"], b"");
    assert!(ok);
    assert!(out.contains("Kullanım: easylock encrypt"), "{out}");
    assert!(out.contains("Veriyi şifrele"));
    assert!(out.contains("Onaltılık anahtar"));
}

#[test]
fn system_locale_selects_turkish() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_easylock"))
        .args(["hash", "--algo", "nope"])
        .env("LC_ALL", "tr_TR.UTF-8")
        .env_remove("LANG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"").unwrap();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("bilinmeyen özet algoritması"), "{stderr}");
}

#[test]
fn encrypt_emits_turkish_status_log() {
    let key = "11".repeat(32);
    let nonce = "22".repeat(12);
    let (_, stderr, ok) = run(
        &[
            "--lang",
            "tr",
            "encrypt",
            "-c",
            "aes-256-gcm",
            "--key",
            &key,
            "--nonce",
            &nonce,
        ],
        b"veri",
    );
    assert!(ok);
    assert!(
        stderr.contains("şifrelendi:") && stderr.contains("AES-256-GCM kullanıldı"),
        "{stderr}"
    );
}

#[test]
fn version_flag_prints_name_and_version() {
    let (out, _, ok) = run(&["--version"], b"");
    assert!(ok);
    assert!(out.starts_with("easylock "));
}
