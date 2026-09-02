//! `easylock encrypt` / `decrypt`.
//!
//! Ciphers: `aes-256-gcm`, `chacha20-poly1305` (AEAD, `ciphertext||tag` output);
//! `aes-256-ctr` (raw stream); `xor` (repeating-key, toy). `--armor` wraps the
//! output in Base64 (and expects Base64 on decrypt).

use crate::i18n::{CliError, Lang, Msg};
use crate::io::{os_random, read_input, write_output};
use crate::FileArgs;
use easylock_core::aead::{Aead, Aes256Gcm, ChaCha20Poly1305};
use easylock_core::cipher::{aes::Aes256, ctr::Ctr, xor::XorStream};
use easylock_core::encode::{base64, hex};
use std::path::PathBuf;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Direction {
    Encrypt,
    Decrypt,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Cipher {
    Aes256Gcm,
    ChaCha20Poly1305,
    Aes256Ctr,
    Xor,
}

impl Cipher {
    fn parse(s: &str) -> Option<Self> {
        match s
            .trim()
            .to_ascii_lowercase()
            .replace(['_', ' '], "-")
            .as_str()
        {
            "aes-256-gcm" | "aes256-gcm" | "gcm" => Some(Cipher::Aes256Gcm),
            "chacha20-poly1305" | "chacha" | "chachapoly" => Some(Cipher::ChaCha20Poly1305),
            "aes-256-ctr" | "aes256-ctr" | "ctr" => Some(Cipher::Aes256Ctr),
            "xor" => Some(Cipher::Xor),
            _ => None,
        }
    }

    fn nonce_len(self) -> usize {
        match self {
            Cipher::Aes256Gcm | Cipher::ChaCha20Poly1305 => 12,
            Cipher::Aes256Ctr => 16,
            Cipher::Xor => 0,
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Cipher::Aes256Gcm => "AES-256-GCM",
            Cipher::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            Cipher::Aes256Ctr => "AES-256-CTR",
            Cipher::Xor => "XOR",
        }
    }
}

/// Human label for the output destination, used in status logs.
fn target_label(output: &Option<PathBuf>, lang: Lang) -> String {
    match output {
        Some(p) if p.as_os_str() != "-" => p.display().to_string(),
        _ => match lang {
            Lang::En => "stdout".to_string(),
            Lang::Tr => "standart çıktı".to_string(),
        },
    }
}

#[derive(clap::Args, Debug, Clone)]
pub struct Args {
    /// Cipher: aes-256-gcm, chacha20-poly1305, aes-256-ctr, xor.
    #[arg(short, long, default_value = "aes-256-gcm")]
    pub cipher: String,

    /// Key as hex (32 bytes for AES/ChaCha; any length for xor).
    #[arg(long, value_name = "HEX", conflicts_with = "key_file")]
    pub key: Option<String>,

    /// Read the raw key bytes from a file.
    #[arg(long, value_name = "PATH")]
    pub key_file: Option<PathBuf>,

    /// Nonce/IV as hex. Required for decrypt; auto-generated for encrypt if absent.
    #[arg(long, value_name = "HEX")]
    pub nonce: Option<String>,

    /// Additional authenticated data as hex (AEAD ciphers only).
    #[arg(long, value_name = "HEX")]
    pub aad: Option<String>,

    /// Base64-armor the output (encrypt) / input (decrypt).
    #[arg(long)]
    pub armor: bool,

    #[command(flatten)]
    pub files: FileArgs,
}

fn load_key(args: &Args) -> Result<Vec<u8>, CliError> {
    if let Some(hexk) = &args.key {
        hex::decode(hexk).map_err(|_| CliError::new(Msg::InvalidInputEncoding("hex".into())))
    } else if let Some(path) = &args.key_file {
        crate::io::read_input(&Some(path.clone()))
    } else {
        Err(CliError::new(Msg::KeyRequired))
    }
}

fn parse_hex_opt(s: &Option<String>) -> Result<Vec<u8>, CliError> {
    match s {
        Some(h) => {
            hex::decode(h).map_err(|_| CliError::new(Msg::InvalidInputEncoding("hex".into())))
        }
        None => Ok(Vec::new()),
    }
}

/// Run the chosen cipher over `input` in the requested direction. `nonce` is
/// already length-validated for the cipher.
fn apply_cipher(
    cipher: Cipher,
    dir: Direction,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    input: Vec<u8>,
) -> Result<Vec<u8>, CliError> {
    let auth_err = || CliError::new(Msg::AuthenticationFailed);
    Ok(match (cipher, dir) {
        (Cipher::Aes256Gcm, Direction::Encrypt) => {
            let n: [u8; 12] = nonce.try_into().unwrap();
            Aes256Gcm::new(key).unwrap().seal(&n, aad, &input)
        }
        (Cipher::Aes256Gcm, Direction::Decrypt) => {
            let n: [u8; 12] = nonce.try_into().unwrap();
            Aes256Gcm::new(key)
                .unwrap()
                .open(&n, aad, &input)
                .map_err(|_| auth_err())?
        }
        (Cipher::ChaCha20Poly1305, Direction::Encrypt) => {
            let n: [u8; 12] = nonce.try_into().unwrap();
            ChaCha20Poly1305::new(key).unwrap().seal(&n, aad, &input)
        }
        (Cipher::ChaCha20Poly1305, Direction::Decrypt) => {
            let n: [u8; 12] = nonce.try_into().unwrap();
            ChaCha20Poly1305::new(key)
                .unwrap()
                .open(&n, aad, &input)
                .map_err(|_| auth_err())?
        }
        (Cipher::Aes256Ctr, _) => {
            let n: [u8; 16] = nonce.try_into().unwrap();
            let aes = Aes256::new(key).unwrap();
            let mut buf = input;
            Ctr::with_counter(&aes, n).apply(&mut buf);
            buf
        }
        (Cipher::Xor, _) => {
            let mut s = XorStream::new(key).map_err(|_| CliError::new(Msg::KeyRequired))?;
            let mut buf = input;
            s.apply(&mut buf);
            buf
        }
    })
}

pub fn run(args: &Args, lang: Lang, dir: Direction) -> Result<(), CliError> {
    let cipher = Cipher::parse(&args.cipher)
        .ok_or_else(|| CliError::new(Msg::UnknownCipher(args.cipher.clone())))?;
    let key = load_key(args)?;

    if matches!(
        cipher,
        Cipher::Aes256Gcm | Cipher::ChaCha20Poly1305 | Cipher::Aes256Ctr
    ) && key.len() != 32
    {
        return Err(CliError::new(Msg::BadKeyLength {
            expected: 32,
            got: key.len(),
        }));
    }

    let aad = parse_hex_opt(&args.aad)?;
    let nlen = cipher.nonce_len();

    // Resolve the nonce.
    let nonce = if nlen == 0 {
        Vec::new()
    } else if let Some(nhex) = &args.nonce {
        let n = hex::decode(nhex)
            .map_err(|_| CliError::new(Msg::InvalidInputEncoding("hex".into())))?;
        if n.len() != nlen {
            return Err(CliError::new(Msg::BadNonceLength {
                expected: nlen,
                got: n.len(),
            }));
        }
        n
    } else if dir == Direction::Encrypt {
        let mut n = vec![0u8; nlen];
        os_random(&mut n)?;
        eprintln!(
            "easylock: {}",
            Msg::GeneratedNonce(hex::encode(&n)).text(lang)
        );
        n
    } else {
        return Err(CliError::new(Msg::NonceRequired { bytes: nlen }));
    };

    let mut input = read_input(&args.files.input)?;
    if dir == Direction::Decrypt && args.armor {
        let text = String::from_utf8(input)
            .map_err(|_| CliError::new(Msg::InvalidInputEncoding("base64".into())))?;
        input = base64::decode(text.trim(), base64::Variant::Standard)
            .map_err(|_| CliError::new(Msg::InvalidInputEncoding("base64".into())))?;
    }

    let output = apply_cipher(cipher, dir, &key, &nonce, &aad, input)?;

    let final_bytes = if dir == Direction::Encrypt && args.armor {
        base64::encode(&output, base64::Variant::Standard).into_bytes()
    } else {
        output
    };
    write_output(&args.files.output, &final_bytes)?;

    // Status log to stderr (keeps stdout pipe-clean).
    let target = target_label(&args.files.output, lang);
    let cipher_name = cipher.display_name().to_string();
    let msg = match dir {
        Direction::Encrypt => Msg::Encrypted {
            target,
            cipher: cipher_name,
        },
        Direction::Decrypt => Msg::Decrypted {
            target,
            cipher: cipher_name,
        },
    };
    eprintln!("easylock {}", msg.text(lang));
    Ok(())
}
