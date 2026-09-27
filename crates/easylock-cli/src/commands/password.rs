//! `easylock password` — CSPRNG password generator with an entropy estimate.

use crate::i18n::{CliError, Lang, Msg};
use crate::io::os_random;

#[derive(clap::Args, Debug, Clone)]
pub struct Args {
    /// Password length (4..=256).
    #[arg(short, long, default_value_t = 20)]
    pub length: usize,

    /// How many passwords to print.
    #[arg(short = 'n', long, default_value_t = 1)]
    pub count: usize,

    /// Include symbols (!@#$…).
    #[arg(short, long)]
    pub symbols: bool,

    /// Exclude lowercase letters.
    #[arg(long)]
    pub no_lower: bool,

    /// Exclude uppercase letters.
    #[arg(long)]
    pub no_upper: bool,

    /// Exclude digits.
    #[arg(long)]
    pub no_digits: bool,
}

/// Look-alike characters (0/O, 1/l/I) are removed from every class.
const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS: &[u8] = b"23456789";
const SYMBOLS: &[u8] = b"!@#$%^&*-_=+?";

/// Build the character pool for the given class switches.
#[allow(clippy::fn_params_excessive_bools)] // mirrors the CLI flags
pub fn pool(lower: bool, upper: bool, digits: bool, symbols: bool) -> Vec<u8> {
    let mut p = Vec::new();
    if lower {
        p.extend_from_slice(LOWER);
    }
    if upper {
        p.extend_from_slice(UPPER);
    }
    if digits {
        p.extend_from_slice(DIGITS);
    }
    if symbols {
        p.extend_from_slice(SYMBOLS);
    }
    p
}

/// Generate one unbiased password (rejection sampling over the OS CSPRNG).
pub fn generate(length: usize, pool: &[u8]) -> Result<String, CliError> {
    if pool.is_empty() || !(4..=256).contains(&length) {
        return Err(CliError::new(Msg::BadPasswordSpec));
    }
    let bound = (256 / pool.len()) * pool.len();
    let mut out = String::with_capacity(length);
    let mut buf = [0u8; 64];
    while out.len() < length {
        os_random(&mut buf)?;
        for &b in &buf {
            if out.len() == length {
                break;
            }
            if usize::from(b) < bound {
                out.push(char::from(pool[usize::from(b) % pool.len()]));
            }
        }
    }
    Ok(out)
}

/// Shannon entropy of a uniformly random password in bits.
pub fn entropy_bits(length: usize, pool_len: usize) -> f64 {
    let len = f64::from(u16::try_from(length).unwrap_or(u16::MAX));
    let pl = f64::from(u16::try_from(pool_len).unwrap_or(1));
    len * pl.log2()
}

pub fn run(args: &Args, lang: Lang) -> Result<(), CliError> {
    let pool = pool(
        !args.no_lower,
        !args.no_upper,
        !args.no_digits,
        args.symbols,
    );
    for _ in 0..args.count.clamp(1, 1000) {
        println!("{}", generate(args.length, &pool)?);
    }
    let bits = entropy_bits(args.length, pool.len());
    let label = lang.pick(["entropy", "entropi", "entropía"]);
    eprintln!("easylock: {label} ≈ {bits:.1} bits");
    Ok(())
}
