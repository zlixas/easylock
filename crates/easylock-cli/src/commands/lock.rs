//! `easylock lock` / `easylock unlock` — encrypt a file with a password into the
//! shared `.elk` format (readable by the CLI, desktop app and web dashboard).

use crate::i18n::{CliError, Lang, Msg};
use crate::io::os_random;
use easylock_core::container::{self, Cipher};
use easylock_core::secure::Zeroize;
use std::path::{Path, PathBuf};

#[derive(clap::Args, Debug, Clone)]
pub struct LockArgs {
    /// File to encrypt.
    #[arg(value_name = "FILE")]
    pub input: PathBuf,

    /// Output file (default: FILE.elk).
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// aes-256-gcm or chacha20-poly1305.
    #[arg(short, long, default_value = "chacha20-poly1305")]
    pub cipher: String,

    /// Password (prefer the prompt or `EASYLOCK_PASSWORD`; flags leak into shell history).
    #[arg(short, long)]
    pub password: Option<String>,
}

#[derive(clap::Args, Debug, Clone)]
pub struct UnlockArgs {
    /// `.elk` file to decrypt.
    #[arg(value_name = "FILE")]
    pub input: PathBuf,

    /// Output file (default: FILE without `.elk`).
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Password (prefer the prompt or `EASYLOCK_PASSWORD`).
    #[arg(short, long)]
    pub password: Option<String>,
}

/// Read a password without echo from the terminal.
fn prompt(label: &str) -> Result<String, CliError> {
    use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    use ratatui::crossterm::terminal;
    use std::io::Write;

    eprint!("{label}: ");
    let _ = std::io::stderr().flush();
    terminal::enable_raw_mode().map_err(|e| CliError::new(Msg::TerminalError(e.to_string())))?;
    let mut pw = String::new();
    let res = loop {
        match event::read() {
            Ok(Event::Key(k)) if k.kind == KeyEventKind::Press => match k.code {
                KeyCode::Enter => break Ok(()),
                KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                    break Err(CliError::new(Msg::TerminalError("cancelled".into())))
                }
                KeyCode::Char(c) => pw.push(c),
                KeyCode::Backspace => {
                    pw.pop();
                }
                _ => {}
            },
            Ok(_) => {}
            Err(e) => break Err(CliError::new(Msg::TerminalError(e.to_string()))),
        }
    };
    let _ = terminal::disable_raw_mode();
    eprintln!();
    res.map(|()| pw)
}

fn get_password(flag: Option<&String>, lang: Lang, confirm: bool) -> Result<String, CliError> {
    if let Some(p) = flag {
        return Ok(p.clone());
    }
    if let Ok(p) = std::env::var("EASYLOCK_PASSWORD") {
        return Ok(p);
    }
    let first = prompt(lang.pick(["Password", "Parola", "Contraseña"]))?;
    if confirm {
        let second = prompt(lang.pick([
            "Repeat password",
            "Parolayı tekrarlayın",
            "Repita la contraseña",
        ]))?;
        if first != second {
            return Err(CliError::new(Msg::PasswordsDiffer));
        }
    }
    if first.is_empty() {
        return Err(CliError::new(Msg::PasswordEmpty));
    }
    Ok(first)
}

fn read(path: &Path) -> Result<Vec<u8>, CliError> {
    std::fs::read(path)
        .map_err(|e| CliError::new(Msg::ReadError(format!("{}: {e}", path.display()))))
}

fn write(path: &Path, data: &[u8]) -> Result<(), CliError> {
    std::fs::write(path, data)
        .map_err(|e| CliError::new(Msg::WriteError(format!("{}: {e}", path.display()))))
}

pub fn run_lock(args: &LockArgs, lang: Lang) -> Result<(), CliError> {
    let cipher = Cipher::parse(&args.cipher)
        .ok_or_else(|| CliError::new(Msg::UnknownCipher(args.cipher.clone())))?;
    let mut data = read(&args.input)?;
    let mut pw = get_password(args.password.as_ref(), lang, true)?;
    eprintln!(
        "easylock: {}",
        lang.pick([
            "deriving key (Argon2id, 64 MiB)…",
            "anahtar türetiliyor (Argon2id, 64 MiB)…",
            "derivando la clave (Argon2id, 64 MiB)…"
        ])
    );
    let mut rng = |b: &mut [u8]| os_random(b).expect("OS randomness");
    let sealed = container::seal_file(
        &data,
        pw.as_bytes(),
        cipher,
        container::FILE_PARAMS,
        &mut rng,
    )
    .map_err(CliError::crypto)?;
    data.zeroize();
    // SAFETY-free scrub of the password's heap buffer.
    let mut bytes = std::mem::take(&mut pw).into_bytes();
    bytes.zeroize();

    let out = args.output.clone().unwrap_or_else(|| {
        let mut p = args.input.clone().into_os_string();
        p.push(".elk");
        PathBuf::from(p)
    });
    write(&out, &sealed)?;
    eprintln!(
        "easylock {}",
        Msg::Encrypted {
            target: out.display().to_string(),
            cipher: cipher.name().into()
        }
        .text(lang)
    );
    Ok(())
}

pub fn run_unlock(args: &UnlockArgs, lang: Lang) -> Result<(), CliError> {
    let data = read(&args.input)?;
    let cipher = container::parse_header(&data)
        .map_err(CliError::crypto)?
        .cipher;
    let mut pw = get_password(args.password.as_ref(), lang, false)?;
    let plain = container::open_file(&data, pw.as_bytes())
        .map_err(|_| CliError::new(Msg::AuthenticationFailed))?;
    let mut bytes = std::mem::take(&mut pw).into_bytes();
    bytes.zeroize();

    let out = args.output.clone().unwrap_or_else(|| {
        let s = args.input.to_string_lossy();
        match s.strip_suffix(".elk") {
            Some(base) if !base.is_empty() => PathBuf::from(base),
            _ => PathBuf::from(format!("{s}.dec")),
        }
    });
    write(&out, &plain)?;
    eprintln!(
        "easylock {}",
        Msg::Decrypted {
            target: out.display().to_string(),
            cipher: cipher.name().into()
        }
        .text(lang)
    );
    Ok(())
}
