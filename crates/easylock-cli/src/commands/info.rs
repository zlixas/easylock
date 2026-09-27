//! `easylock info` — build, hardware backends and the algorithm catalogue.

use crate::i18n::{CliError, Lang};

/// `(family, [algorithms…])` for the catalogue listing.
pub const CATALOGUE: &[(&str, &[&str])] = &[
    (
        "hash",
        &[
            "SHA-256",
            "SHA-512",
            "SHA3-256",
            "SHA3-512",
            "Keccak-256",
            "BLAKE3",
            "BLAKE2b",
            "SHAKE128/256",
        ],
    ),
    ("mac", &["HMAC (any hash)", "Poly1305"]),
    ("kdf", &["Argon2id/i/d", "PBKDF2", "HKDF"]),
    ("aead", &["AES-256-GCM", "ChaCha20-Poly1305"]),
    ("cipher", &["AES-256-CTR", "ChaCha20", "XOR"]),
    ("sig", &["Ed25519", "RSA PKCS#1 v1.5"]),
    ("kex", &["X25519", "ML-KEM-512/768/1024", "RSA-OAEP"]),
    ("encode", &["Hex", "Base64", "Base64URL", "Base58", "ROT13"]),
];

fn family_label(lang: Lang, f: &str) -> &'static str {
    match f {
        "hash" => lang.pick(["Hashing", "Özet", "Hash"]),
        "mac" => lang.pick([
            "Message authentication",
            "Mesaj doğrulama",
            "Autenticación de mensajes",
        ]),
        "kdf" => lang.pick(["Key derivation", "Anahtar türetme", "Derivación de claves"]),
        "aead" => lang.pick([
            "Authenticated encryption",
            "Doğrulamalı şifreleme",
            "Cifrado autenticado",
        ]),
        "cipher" => lang.pick([
            "Stream / block ciphers",
            "Akış / blok şifreleri",
            "Cifrados de flujo / bloque",
        ]),
        "sig" => lang.pick(["Signatures", "İmzalar", "Firmas"]),
        "kex" => lang.pick([
            "Key exchange & KEM",
            "Anahtar değişimi & KEM",
            "Intercambio de claves y KEM",
        ]),
        "encode" => lang.pick(["Encodings", "Kodlamalar", "Codificaciones"]),
        _ => "",
    }
}

// Uniform `Result` signature with the other subcommands.
#[allow(clippy::unnecessary_wraps)]
pub fn run(lang: Lang) -> Result<(), CliError> {
    println!("easylock {}", env!("CARGO_PKG_VERSION"));
    println!("  {}", easylock_core::build_info());
    println!(
        "  {}: aes={}  ghash={}",
        lang.pick(["backends", "arka uçlar", "backends"]),
        easylock_core::cipher::aes::active_backend(),
        easylock_core::aead::ghash::active_backend()
    );
    println!(
        "  {}: {} ({})",
        lang.pick(["language", "dil", "idioma"]),
        lang.endonym(),
        lang.code()
    );
    println!();
    for (family, algos) in CATALOGUE {
        println!("{:<28} {}", family_label(lang, family), algos.join(" · "));
    }
    println!();
    println!(
        "{}",
        lang.pick([
            "⚠ From-scratch and unaudited — for learning and experiments, not for protecting real secrets.",
            "⚠ Sıfırdan yazıldı ve denetlenmedi — öğrenme ve deneme içindir, gerçek sırları korumak için değil.",
            "⚠ Escrito desde cero y sin auditar — para aprender y experimentar, no para proteger secretos reales.",
        ])
    );
    Ok(())
}
