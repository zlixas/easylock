//! stdin/stdout/file plumbing and OS randomness.

use crate::i18n::{CliError, Msg};
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;

/// Read all bytes from `path`, or from stdin when `path` is `None` or `"-"`.
pub fn read_input(path: &Option<PathBuf>) -> Result<Vec<u8>, CliError> {
    let mut buf = Vec::new();
    match path {
        Some(p) if p.as_os_str() != "-" => {
            File::open(p)
                .and_then(|mut f| f.read_to_end(&mut buf))
                .map_err(|e| CliError::new(Msg::ReadError(e.to_string())))?;
        }
        _ => {
            std::io::stdin()
                .lock()
                .read_to_end(&mut buf)
                .map_err(|e| CliError::new(Msg::ReadError(e.to_string())))?;
        }
    }
    Ok(buf)
}

/// Write bytes to `path`, or to stdout when `path` is `None` or `"-"`.
pub fn write_output(path: &Option<PathBuf>, data: &[u8]) -> Result<(), CliError> {
    match path {
        Some(p) if p.as_os_str() != "-" => File::create(p)
            .and_then(|mut f| f.write_all(data))
            .map_err(|e| CliError::new(Msg::WriteError(e.to_string()))),
        _ => {
            let mut out = std::io::stdout().lock();
            out.write_all(data)
                .and_then(|()| out.flush())
                .map_err(|e| CliError::new(Msg::WriteError(e.to_string())))
        }
    }
}

/// Fill `buf` with cryptographically secure random bytes from the OS
/// (`getrandom(2)` / `SecRandomCopyBytes` / `BCryptGenRandom`).
pub fn os_random(buf: &mut [u8]) -> Result<(), CliError> {
    getrandom::getrandom(buf).map_err(|e| CliError::new(Msg::RandomError(e.to_string())))
}

/// Infallible RNG closure for core APIs; aborts if the OS RNG is unavailable,
/// which is the only safe reaction for a crypto tool.
pub fn rng() -> impl FnMut(&mut [u8]) {
    |b: &mut [u8]| os_random(b).expect("the operating system's random number generator failed")
}

/// Read a secret from the terminal without echo. Works even when stdin is a pipe
/// (the terminal is opened directly).
pub fn prompt_secret(label: &str) -> Result<String, CliError> {
    use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    use ratatui::crossterm::terminal;

    eprint!("{label}: ");
    let _ = std::io::stderr().flush();
    terminal::enable_raw_mode().map_err(|e| CliError::new(Msg::TerminalError(e.to_string())))?;
    let mut secret = String::new();
    let res = loop {
        match event::read() {
            Ok(Event::Key(k)) if k.kind == KeyEventKind::Press => match k.code {
                KeyCode::Enter => break Ok(()),
                KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                    break Err(CliError::new(Msg::TerminalError("cancelled".into())));
                }
                KeyCode::Char(c) => secret.push(c),
                KeyCode::Backspace => {
                    secret.pop();
                }
                _ => {}
            },
            Ok(_) => {}
            Err(e) => break Err(CliError::new(Msg::TerminalError(e.to_string()))),
        }
    };
    let _ = terminal::disable_raw_mode();
    eprintln!();
    res.map(|()| secret)
}

/// Best-effort wipe of a `String`'s heap buffer.
pub fn wipe(s: &mut String) {
    use easylock_core::secure::Zeroize;
    let mut bytes = std::mem::take(s).into_bytes();
    bytes.zeroize();
}
