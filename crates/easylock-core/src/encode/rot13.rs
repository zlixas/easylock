//! ROT13 — a Caesar cipher, included for the transform pipeline. Not cryptography.

use alloc::string::String;
use alloc::vec::Vec;

/// Apply ROT13 to a byte buffer. Bytes outside `A-Za-z` are copied unchanged.
#[must_use]
pub fn apply(data: &[u8]) -> Vec<u8> {
    data.iter()
        .map(|&b| match b {
            b'A'..=b'Z' => (b - b'A' + 13) % 26 + b'A',
            b'a'..=b'z' => (b - b'a' + 13) % 26 + b'a',
            other => other,
        })
        .collect()
}

/// Apply ROT13 and return a `String` (input is treated as Latin-1/ASCII text).
#[must_use]
pub fn apply_str(data: &[u8]) -> String {
    String::from_utf8_lossy(&apply(data)).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn involution() {
        let s = b"Why did the chicken cross the road? 42!";
        assert_eq!(apply(&apply(s)), s);
    }

    #[test]
    fn known_vector() {
        assert_eq!(apply_str(b"Hello, World!"), "Uryyb, Jbeyq!");
    }
}
