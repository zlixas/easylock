//! `easylock hash`

use crate::i18n::{CliError, Lang, Msg};
use crate::io::{read_input, write_output};
use crate::FileArgs;
use easylock_core::encode::{base64, hex};
use easylock_core::hash::Algorithm;

#[derive(clap::Args, Debug, Clone)]
pub struct Args {
    /// Hash algorithm: sha256, sha512, keccak256, sha3-256.
    #[arg(short, long, default_value = "sha256")]
    pub algo: String,

    /// Digest output encoding.
    #[arg(long, value_name = "hex|base64|raw", default_value = "hex")]
    pub encoding: String,

    #[command(flatten)]
    pub files: FileArgs,
}

pub fn run(args: &Args, lang: Lang) -> Result<(), CliError> {
    let alg = Algorithm::parse(&args.algo)
        .filter(|a| !matches!(a, Algorithm::Blake3))
        .ok_or_else(|| CliError::new(Msg::UnknownAlgorithm(args.algo.clone())))?;

    let data = read_input(&args.files.input)?;
    let digest = alg.hash(&data);

    let rendered = match args.encoding.as_str() {
        "raw" => digest.clone(),
        "base64" => base64::encode(&digest, base64::Variant::Standard).into_bytes(),
        _ => {
            let mut s = hex::encode(&digest).into_bytes();
            if args.files.output.is_none() {
                s.push(b'\n');
            }
            s
        }
    };
    write_output(&args.files.output, &rendered)?;
    let _ = lang;
    Ok(())
}
