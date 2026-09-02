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

/// Fill `buf` with cryptographically secure random bytes from the OS.
pub fn os_random(buf: &mut [u8]) -> Result<(), CliError> {
    // `/dev/urandom` is the portable choice on macOS and Linux; it never blocks
    // after early boot and is a CSPRNG on both.
    let mut f =
        File::open("/dev/urandom").map_err(|e| CliError::new(Msg::RandomError(e.to_string())))?;
    f.read_exact(buf)
        .map_err(|e| CliError::new(Msg::RandomError(e.to_string())))
}
