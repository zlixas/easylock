//! Lowercase hexadecimal (Base16).

use crate::{Error, Result};
use alloc::string::String;
use alloc::vec::Vec;

const LUT: &[u8; 16] = b"0123456789abcdef";

/// Encode to lowercase hex. Output length is `2 * data.len()`.
#[must_use]
pub fn encode(data: &[u8]) -> String {
    let mut out = Vec::with_capacity(data.len() * 2);
    for &b in data {
        out.push(LUT[usize::from(b >> 4)]);
        out.push(LUT[usize::from(b & 0x0f)]);
    }
    // SAFETY: every pushed byte is an ASCII hex digit.
    unsafe { String::from_utf8_unchecked(out) }
}

/// Decode hex. Accepts upper/lowercase; ignores ASCII whitespace between bytes.
/// Rejects odd length and non-hex characters.
pub fn decode(text: &str) -> Result<Vec<u8>> {
    let filtered: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if filtered.len() % 2 != 0 {
        return Err(Error::InvalidEncoding { scheme: "hex" });
    }
    let mut out = Vec::with_capacity(filtered.len() / 2);
    for pair in filtered.chunks_exact(2) {
        let hi = nibble(pair[0])?;
        let lo = nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

#[inline]
fn nibble(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(Error::InvalidEncoding { scheme: "hex" }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "66");
        assert_eq!(encode(b"foobar"), "666f6f626172");
        assert_eq!(encode(&[0x00, 0xde, 0xad, 0xbe, 0xef]), "00deadbeef");
    }

    #[test]
    fn decode_roundtrip_and_case() {
        assert_eq!(decode("666F6F626172").unwrap(), b"foobar");
        assert_eq!(decode("de ad be ef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn decode_rejects_bad_input() {
        assert!(decode("abc").is_err());
        assert!(decode("zz").is_err());
    }
}
