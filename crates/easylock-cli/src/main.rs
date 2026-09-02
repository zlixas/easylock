//! `easylock` command-line interface.
//!
//! Subcommands: `hash`, `encode`, `decode`, `encrypt`, `decrypt`.
//! Help text, command descriptions, error messages and status logs are available
//! in English (`en`) and Turkish (`tr`). The language comes from `--lang` or the
//! system locale (`tr_TR` → Turkish, otherwise English).

mod commands;
mod help;
mod i18n;
mod io;

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use i18n::Lang;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(name = "easylock", version)]
pub struct Cli {
    /// Interface language: `tr` or `en` (default: system locale).
    #[arg(long, global = true, value_name = "tr|en")]
    lang: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Hash data with SHA-256/512, Keccak-256 or SHA3-256.
    Hash(commands::hash::Args),
    /// Encode bytes to text (hex/base64/base64url/base58/rot13), with chaining.
    Encode(commands::encode::EncodeArgs),
    /// Decode text back to bytes.
    Decode(commands::encode::DecodeArgs),
    /// Authenticated (or raw) encryption. Output is `ciphertext||tag`.
    Encrypt(commands::crypt::Args),
    /// Decrypt data produced by `encrypt`.
    Decrypt(commands::crypt::Args),
}

fn main() -> ExitCode {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();

    // Resolve the language before clap runs so `--help` is localized too.
    let lang = i18n::prescan_lang(&args);

    let matches = help::localized_command(Cli::command(), lang).get_matches_from(args);

    if help::wants_version(&matches) {
        println!("easylock {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if help::wants_help(&matches) || matches.subcommand().is_none() {
        let mut cmd = help::localized_command(Cli::command(), lang);
        print!("{}", help::render_localized_help(&mut cmd, &matches, lang));
        return ExitCode::SUCCESS;
    }

    let cli = match Cli::from_arg_matches(&matches) {
        Ok(c) => c,
        Err(e) => e.exit(),
    };

    // A valid `--lang` value overrides the prescan (they normally agree).
    let lang = Lang::resolve(cli.lang.as_deref());

    let result = match cli.command {
        Command::Hash(a) => commands::hash::run(&a, lang),
        Command::Encode(a) => commands::encode::run_encode(&a, lang),
        Command::Decode(a) => commands::encode::run_decode(&a, lang),
        Command::Encrypt(a) => commands::crypt::run(&a, lang, commands::crypt::Direction::Encrypt),
        Command::Decrypt(a) => commands::crypt::run(&a, lang, commands::crypt::Direction::Decrypt),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("easylock: {}", e.msg.text(lang));
            ExitCode::FAILURE
        }
    }
}

/// Shared positional/optional file arguments.
#[derive(clap::Args, Debug, Clone)]
pub struct FileArgs {
    /// Input file (`-` or omitted = stdin).
    #[arg(value_name = "FILE")]
    pub input: Option<PathBuf>,

    /// Output file (`-` or omitted = stdout).
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    pub output: Option<PathBuf>,
}
