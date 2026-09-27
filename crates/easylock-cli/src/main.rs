//! `easylock` — command-line interface and terminal UI.
//!
//! Subcommands: `lock`, `unlock`, `hash`, `encode`, `decode`, `encrypt`, `decrypt`, `hmac`, `kdf`,
//! `password`, `keygen`, `sign`, `verify`, `info`, and `tui` (full-screen UI).
//! Help, messages and the TUI are available in English, Turkish and Spanish,
//! chosen with `--lang en|tr|es` or the system locale.

mod commands;
mod help;
mod i18n;
mod io;
mod tui;

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use commands::crypt::Direction;
use i18n::Lang;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(name = "easylock", version)]
pub struct Cli {
    /// Interface language: `en`, `tr` or `es` (default: system locale).
    #[arg(long, global = true, value_name = "en|tr|es")]
    lang: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Hash data with SHA-256/512, SHA3-256, Keccak-256 or BLAKE3.
    Hash(commands::hash::Args),
    /// Encode bytes to text (hex/base64/base64url/base58/rot13), with chaining.
    Encode(commands::encode::EncodeArgs),
    /// Decode text back to bytes.
    Decode(commands::encode::DecodeArgs),
    /// Authenticated (or raw) encryption. Output is `ciphertext||tag`.
    Encrypt(commands::crypt::Args),
    /// Decrypt data produced by `encrypt`.
    Decrypt(commands::crypt::Args),
    /// Encrypt a file with a password (`.elk`, works with the app and website).
    Lock(commands::lock::LockArgs),
    /// Decrypt a `.elk` file.
    Unlock(commands::lock::UnlockArgs),
    /// Keyed message authentication code.
    Hmac(commands::hmac::Args),
    /// Password hashing / key derivation (Argon2id, PBKDF2).
    Kdf(commands::kdf::Args),
    /// Generate strong random passwords.
    Password(commands::password::Args),
    /// Generate a key pair (Ed25519, X25519, ML-KEM, RSA).
    Keygen(commands::keygen::Args),
    /// Sign data with an Ed25519 seed.
    Sign(commands::sign::SignArgs),
    /// Verify an Ed25519 signature.
    Verify(commands::sign::VerifyArgs),
    /// Show version, hardware backends and supported algorithms.
    Info,
    /// Open the full-screen terminal UI.
    Tui,
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
        Command::Encrypt(a) => commands::crypt::run(&a, lang, Direction::Encrypt),
        Command::Decrypt(a) => commands::crypt::run(&a, lang, Direction::Decrypt),
        Command::Lock(a) => commands::lock::run_lock(&a, lang),
        Command::Unlock(a) => commands::lock::run_unlock(&a, lang),
        Command::Hmac(a) => commands::hmac::run(&a, lang),
        Command::Kdf(a) => commands::kdf::run(&a, lang),
        Command::Password(a) => commands::password::run(&a, lang),
        Command::Keygen(a) => commands::keygen::run(&a, lang),
        Command::Sign(a) => commands::sign::run_sign(&a, lang),
        Command::Verify(a) => commands::sign::run_verify(&a, lang),
        Command::Info => commands::info::run(lang),
        Command::Tui => tui::run(lang),
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
