//! `easylock encode` / `decode`, including transform chaining.

use crate::i18n::{CliError, Lang, Msg};
use crate::io::{read_input, write_output};
use crate::FileArgs;
use easylock_core::encode::{chain_decode, chain_encode, Transform};

#[derive(clap::Args, Debug, Clone)]
pub struct EncodeArgs {
    /// Transform(s), comma-separated for a pipeline applied left to right
    /// (e.g. `base64,hex` = hex(base64(data))).
    #[arg(short, long, value_name = "hex|base64|base64url|base58|rot13[,...]")]
    pub transform: String,

    /// Append a trailing newline to stdout text output.
    #[arg(long)]
    pub newline: bool,

    #[command(flatten)]
    pub files: FileArgs,
}

#[derive(clap::Args, Debug, Clone)]
pub struct DecodeArgs {
    /// Same transform spec used to encode; it is reversed automatically.
    #[arg(short, long, value_name = "hex|base64|base64url|base58|rot13[,...]")]
    pub transform: String,

    #[command(flatten)]
    pub files: FileArgs,
}

fn parse_pipeline(spec: &str) -> Result<Vec<Transform>, CliError> {
    spec.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            Transform::parse(s).ok_or_else(|| CliError::new(Msg::UnknownTransform(s.to_string())))
        })
        .collect()
}

pub fn run_encode(args: &EncodeArgs, _lang: Lang) -> Result<(), CliError> {
    let steps = parse_pipeline(&args.transform)?;
    let data = read_input(&args.files.input)?;
    let mut out = chain_encode(&data, &steps).into_bytes();
    if args.newline && args.files.output.is_none() {
        out.push(b'\n');
    }
    write_output(&args.files.output, &out)
}

pub fn run_decode(args: &DecodeArgs, _lang: Lang) -> Result<(), CliError> {
    let steps = parse_pipeline(&args.transform)?;
    let raw = read_input(&args.files.input)?;
    let text = String::from_utf8(raw)
        .map_err(|_| CliError::new(Msg::InvalidInputEncoding(args.transform.clone())))?;
    let out = chain_decode(text.trim(), &steps)
        .map_err(|_| CliError::new(Msg::InvalidInputEncoding(args.transform.clone())))?;
    write_output(&args.files.output, &out)
}
