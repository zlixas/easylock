//! `easylock sign` / `easylock verify` — Ed25519 detached signatures.

use crate::i18n::{CliError, Lang, Msg};
use crate::io::read_input;
use crate::FileArgs;
use easylock_core::ec::{Signature, SigningKey, VerifyingKey};
use easylock_core::encode::hex;

#[derive(clap::Args, Debug, Clone)]
pub struct SignArgs {
    /// 32-byte Ed25519 seed as hex (from `easylock keygen ed25519`).
    #[arg(short, long, value_name = "HEX")]
    pub seed: String,

    #[command(flatten)]
    pub files: FileArgs,
}

#[derive(clap::Args, Debug, Clone)]
pub struct VerifyArgs {
    /// 32-byte Ed25519 public key as hex.
    #[arg(short, long, value_name = "HEX")]
    pub public: String,

    /// 64-byte signature as hex.
    #[arg(short = 'S', long, value_name = "HEX")]
    pub signature: String,

    #[command(flatten)]
    pub files: FileArgs,
}

fn fixed<const N: usize>(hex_str: &str) -> Result<[u8; N], CliError> {
    hex::decode(hex_str)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| {
            CliError::new(Msg::BadKeyLength {
                expected: N,
                got: hex_str.trim().len() / 2,
            })
        })
}

pub fn run_sign(args: &SignArgs, lang: Lang) -> Result<(), CliError> {
    let sk = SigningKey::from_seed(fixed::<32>(&args.seed)?);
    let msg = read_input(&args.files.input)?;
    let sig = sk.sign(&msg);
    println!("{}", hex::encode(&sig.to_bytes()));
    eprintln!(
        "easylock: {}: {}",
        lang.pick(["public key", "açık anahtar", "clave pública"]),
        hex::encode(sk.verifying_key().as_bytes())
    );
    Ok(())
}

pub fn run_verify(args: &VerifyArgs, lang: Lang) -> Result<(), CliError> {
    let vk = VerifyingKey::from_bytes(fixed::<32>(&args.public)?);
    let sig = Signature::from_bytes(fixed::<64>(&args.signature)?);
    let msg = read_input(&args.files.input)?;
    if vk.verify(&msg, &sig) {
        println!("{}", Msg::SignatureValid.text(lang));
        Ok(())
    } else {
        Err(CliError::new(Msg::SignatureInvalid))
    }
}
