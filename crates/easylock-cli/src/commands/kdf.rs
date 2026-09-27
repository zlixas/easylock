//! `easylock kdf` — password hashing / key derivation (Argon2id, PBKDF2).

use crate::i18n::{CliError, Lang, Msg};
use crate::io::{os_random, read_input};
use crate::FileArgs;
use easylock_core::encode::hex;
use easylock_core::hash::{Sha256, Sha512};
use easylock_core::kdf::argon2::{self, Params};

#[derive(clap::Args, Debug, Clone)]
pub struct Args {
    /// Algorithm: argon2id (default) or pbkdf2.
    #[arg(short, long, default_value = "argon2id")]
    pub algo: String,

    /// Password (omit to read it from stdin / FILE).
    #[arg(short, long)]
    pub password: Option<String>,

    /// Salt as hex (random 16 bytes when omitted).
    #[arg(long, value_name = "HEX")]
    pub salt: Option<String>,

    /// Argon2 memory in KiB.
    #[arg(short, long, default_value_t = 65536)]
    pub memory: u32,

    /// Argon2 passes / PBKDF2 iterations (PBKDF2 default: 600000).
    #[arg(short, long)]
    pub iterations: Option<u32>,

    /// Argon2 parallelism (lanes).
    #[arg(long, default_value_t = 4)]
    pub parallelism: u32,

    /// Verify the password against this PHC string instead of hashing.
    #[arg(long, value_name = "PHC")]
    pub verify: Option<String>,

    /// Output key length in bytes.
    #[arg(short = 'L', long, default_value_t = 32)]
    pub length: usize,

    #[command(flatten)]
    pub files: FileArgs,
}

pub fn run(args: &Args, lang: Lang) -> Result<(), CliError> {
    let mut password: Vec<u8> = if let Some(p) = &args.password {
        p.clone().into_bytes()
    } else {
        let mut raw = read_input(&args.files.input)?;
        while raw.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
            raw.pop();
        }
        raw
    };

    if let Some(phc) = &args.verify {
        let ok = argon2::verify_phc(&password, phc).map_err(CliError::crypto)?;
        easylock_core::secure::Zeroize::zeroize(password.as_mut_slice());
        return if ok {
            println!("{}", Msg::PasswordMatches.text(lang));
            Ok(())
        } else {
            Err(CliError::new(Msg::PasswordMismatch))
        };
    }

    let salt = if let Some(h) = &args.salt {
        hex::decode(h).map_err(|_| CliError::new(Msg::InvalidInputEncoding("hex".into())))?
    } else {
        let mut s = vec![0u8; 16];
        os_random(&mut s)?;
        s
    };

    let algo = args.algo.to_ascii_lowercase();
    let out = if algo.starts_with("argon") {
        let t = args.iterations.unwrap_or(3);
        let params = Params {
            m_cost: args.memory,
            t_cost: t,
            parallelism: args.parallelism,
            out_len: args.length,
        };
        argon2::hash_phc(&password, &salt, params).map_err(CliError::crypto)?
    } else if algo.starts_with("pbkdf2") {
        let iters = args.iterations.unwrap_or(600_000);
        let dk = if algo.contains("512") {
            easylock_core::kdf::pbkdf2::<Sha512>(&password, &salt, iters, args.length)
        } else {
            easylock_core::kdf::pbkdf2::<Sha256>(&password, &salt, iters, args.length)
        }
        .map_err(CliError::crypto)?;
        format!(
            "pbkdf2-sha256$i={iters}${}${}",
            hex::encode(&salt),
            hex::encode(&dk)
        )
    } else {
        return Err(CliError::new(Msg::UnknownAlgorithm(args.algo.clone())));
    };

    easylock_core::secure::Zeroize::zeroize(password.as_mut_slice());
    println!("{out}");
    Ok(())
}
