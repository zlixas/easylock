//! `easylock hmac` — keyed message authentication (HMAC-SHA-2/3, Keccak).

use crate::i18n::{CliError, Lang, Msg};
use crate::io::{read_input, write_output};
use crate::FileArgs;
use easylock_core::encode::hex;
use easylock_core::hash::{Keccak256, Sha256, Sha3_256, Sha512};
use easylock_core::mac::Hmac;

#[derive(clap::Args, Debug, Clone)]
pub struct Args {
    /// Hash: sha256, sha512, sha3-256, keccak256.
    #[arg(short, long, default_value = "sha256")]
    pub algo: String,

    /// Key as hex.
    #[arg(short, long, value_name = "HEX", conflicts_with = "key_text")]
    pub key: Option<String>,

    /// Key as UTF-8 text.
    #[arg(long, value_name = "TEXT")]
    pub key_text: Option<String>,

    #[command(flatten)]
    pub files: FileArgs,
}

/// Compute an HMAC tag (hex) of `data` under `key` with the named hash.
pub fn compute(algo: &str, key: &[u8], data: &[u8]) -> Result<String, CliError> {
    let tag = match algo.to_ascii_lowercase().replace(['-', '_'], "").as_str() {
        "sha256" => Hmac::<Sha256>::mac(key, data),
        "sha512" => Hmac::<Sha512>::mac(key, data),
        "sha3256" | "sha3" => Hmac::<Sha3_256>::mac(key, data),
        "keccak256" => Hmac::<Keccak256>::mac(key, data),
        _ => return Err(CliError::new(Msg::UnknownAlgorithm(algo.to_string()))),
    };
    Ok(hex::encode(&tag))
}

pub fn run(args: &Args, _lang: Lang) -> Result<(), CliError> {
    let key = match (&args.key, &args.key_text) {
        (Some(h), _) => {
            hex::decode(h).map_err(|_| CliError::new(Msg::InvalidInputEncoding("hex".into())))?
        }
        (None, Some(t)) => t.clone().into_bytes(),
        (None, None) => return Err(CliError::new(Msg::KeyRequired)),
    };
    let data = read_input(&args.files.input)?;
    let mut out = compute(&args.algo, &key, &data)?.into_bytes();
    if args.files.output.is_none() {
        out.push(b'\n');
    }
    write_output(&args.files.output, &out)
}
