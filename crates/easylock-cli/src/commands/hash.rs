//! `easylock hash`

use crate::i18n::{CliError, Lang, Msg};
use crate::io::write_output;
use crate::FileArgs;
use easylock_core::encode::{base64, hex};
use easylock_core::hash::Algorithm;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

#[derive(clap::Args, Debug, Clone)]
pub struct Args {
    /// Hash algorithm: sha256, sha512, keccak256, sha3-256, blake3.
    #[arg(short, long, default_value = "sha256")]
    pub algo: String,

    /// Digest output encoding.
    #[arg(long, value_name = "hex|base64|raw", default_value = "hex")]
    pub encoding: String,

    #[command(flatten)]
    pub files: FileArgs,
}

/// Hash a file (or stdin) in constant memory, 1 MiB at a time.
fn hash_stream(alg: Algorithm, input: &Option<PathBuf>) -> Result<Vec<u8>, CliError> {
    let mut reader: Box<dyn Read> = match input {
        Some(p) if p.as_os_str() != "-" => {
            Box::new(File::open(p).map_err(|e| CliError::new(Msg::ReadError(e.to_string())))?)
        }
        _ => Box::new(std::io::stdin().lock()),
    };
    let mut h = alg.hasher();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => return Ok(h.finalize()),
            Ok(n) => h.update(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(CliError::new(Msg::ReadError(e.to_string()))),
        }
    }
}

pub fn run(args: &Args, lang: Lang) -> Result<(), CliError> {
    let alg = Algorithm::parse(&args.algo)
        .ok_or_else(|| CliError::new(Msg::UnknownAlgorithm(args.algo.clone())))?;

    let digest = hash_stream(alg, &args.files.input)?;

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
