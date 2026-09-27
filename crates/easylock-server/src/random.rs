//! OS randomness for the server's key-generation and salt endpoints.

/// Read `n` cryptographically secure random bytes from the OS
/// (`getrandom(2)`, `SecRandomCopyBytes`, `BCryptGenRandom`, …).
pub fn bytes(n: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).map_err(|e| format!("system randomness unavailable: {e}"))?;
    Ok(buf)
}
