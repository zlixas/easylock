//! OS randomness for the server's key-generation and salt endpoints.

use std::fs::File;
use std::io::Read;

/// Read `n` cryptographically-secure random bytes from the OS.
///
/// `/dev/urandom` is a CSPRNG on macOS and Linux and never blocks after early
/// boot.
pub fn bytes(n: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; n];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|e| format!("system randomness unavailable: {e}"))?;
    Ok(buf)
}
