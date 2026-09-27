//! `easylock identity`: create or show your public-key identity.
//!
//! The identity file holds an `ELK-SECRET-KEY-1…` secret (X25519 + ML-KEM-768), by
//! default protected with a password as an `elk1.` token. Its first comment line
//! carries the public key, so `--show` works without the password.

use crate::i18n::{CliError, Lang, Msg};
use crate::io::{prompt_secret, rng};
use easylock_core::container::elk2::{Identity, Recipient};
use easylock_core::container::{open_token, seal_token, Cipher};
use easylock_core::secure::Zeroize;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(clap::Args, Debug, Clone)]
pub struct Args {
    /// Where to write the identity (default: ~/.config/easylock/identity.key).
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Print the public key of an existing identity instead of creating one.
    #[arg(long)]
    pub show: bool,

    /// Identity file for --show (default: ~/.config/easylock/identity.key).
    #[arg(short, long, value_name = "FILE")]
    pub identity: Option<PathBuf>,

    /// Store the secret key without password protection.
    #[arg(long)]
    pub plain: bool,

    /// Replace an existing identity file.
    #[arg(short, long)]
    pub force: bool,
}

/// Default identity location: `$EASYLOCK_IDENTITY`, else
/// `$XDG_CONFIG_HOME/easylock/identity.key`, `~/.config/easylock/identity.key`
/// or `%APPDATA%\easylock\identity.key`.
pub fn default_path() -> PathBuf {
    if let Some(p) = std::env::var_os("EASYLOCK_IDENTITY") {
        return PathBuf::from(p);
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("easylock").join("identity.key")
}

fn secret_password(lang: Lang, confirm: bool) -> Result<String, CliError> {
    if let Ok(p) = std::env::var("EASYLOCK_IDENTITY_PASSWORD") {
        return Ok(p);
    }
    let first = prompt_secret(lang.pick([
        "Identity password",
        "Kimlik parolası",
        "Contraseña de la identidad",
    ]))?;
    if confirm {
        let again = prompt_secret(lang.pick([
            "Repeat password",
            "Parolayı tekrarlayın",
            "Repita la contraseña",
        ]))?;
        if first != again {
            return Err(CliError::new(Msg::PasswordsDiffer));
        }
    }
    if first.is_empty() {
        return Err(CliError::new(Msg::PasswordEmpty));
    }
    Ok(first)
}

/// Load an identity file, asking for its password if it is protected.
pub fn load(path: &Path, lang: Lang) -> Result<Identity, CliError> {
    let text = fs::read_to_string(path)
        .map_err(|_| CliError::new(Msg::IdentityMissing(path.display().to_string())))?;
    for line in text.lines().map(str::trim) {
        if line.starts_with("ELK-SECRET-KEY-1") {
            return Identity::parse(line).map_err(CliError::crypto);
        }
        if line.starts_with("elk1.") {
            let mut pw = secret_password(lang, false)?;
            let opened = open_token(line, pw.as_bytes());
            crate::io::wipe(&mut pw);
            let mut secret = opened.map_err(|_| CliError::new(Msg::AuthenticationFailed))?;
            let id = std::str::from_utf8(&secret)
                .map_err(CliError::crypto)
                .and_then(|s| Identity::parse(s).map_err(CliError::crypto));
            secret.zeroize();
            return id;
        }
    }
    Err(CliError::new(Msg::IdentityMissing(
        path.display().to_string(),
    )))
}

/// The public key recorded in an identity file's comment (no password needed).
fn recorded_public(path: &Path) -> Option<Recipient> {
    let text = fs::read_to_string(path).ok()?;
    text.split_whitespace()
        .find(|t| t.starts_with("elkpub1"))
        .and_then(|t| Recipient::parse(t).ok())
}

fn print_public(r: &Recipient, lang: Lang) {
    println!("{}", r.encode());
    eprintln!(
        "{} {}",
        lang.pick(["fingerprint:", "parmak izi:", "huella:"]),
        r.fingerprint()
    );
}

pub fn run(args: &Args, lang: Lang) -> Result<(), CliError> {
    if args.show {
        let path = args.identity.clone().unwrap_or_else(default_path);
        let r = match recorded_public(&path) {
            Some(r) => r,
            None => load(&path, lang)?.recipient(),
        };
        print_public(&r, lang);
        return Ok(());
    }

    let path = args.output.clone().unwrap_or_else(default_path);
    if path.exists() && !args.force {
        return Err(CliError::new(Msg::IdentityExists(
            path.display().to_string(),
        )));
    }
    let id = Identity::generate(&mut rng());
    let public = id.recipient();
    let mut secret = id.encode_secret();
    let body = if args.plain {
        secret.clone()
    } else {
        let mut pw = secret_password(lang, true)?;
        let t = seal_token(
            secret.as_bytes(),
            pw.as_bytes(),
            Cipher::ChaCha20Poly1305,
            &mut rng(),
        )
        .map_err(CliError::crypto);
        crate::io::wipe(&mut pw);
        t?
    };
    crate::io::wipe(&mut secret);
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let contents = format!(
        "# easylock identity: KEEP THIS FILE SECRET and back it up.\n\
         # created: {created} (unix time)\n\
         # public key: {}\n{body}\n",
        public.encode()
    );
    write_private(&path, contents.as_bytes())
        .map_err(|e| CliError::new(Msg::WriteError(format!("{}: {e}", path.display()))))?;

    eprintln!(
        "{} {}",
        lang.pick([
            "identity written to",
            "kimlik şuraya yazıldı:",
            "identidad guardada en"
        ]),
        path.display()
    );
    eprintln!(
        "{}",
        lang.pick([
            "Share this public key; others encrypt to it with `easylock lock -r KEY FILE`:",
            "Bu açık anahtarı paylaşın; başkaları `easylock lock -r ANAHTAR DOSYA` ile size şifreler:",
            "Comparta esta clave pública; otros cifran para usted con `easylock lock -r CLAVE ARCHIVO`:",
        ])
    );
    print_public(&public, lang);
    Ok(())
}

/// Write a file readable only by the owner (0600, parent directory 0700 on Unix).
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        }
    }
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(data)?;
    f.sync_all()
}
