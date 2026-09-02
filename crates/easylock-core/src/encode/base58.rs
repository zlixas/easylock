//! Base58 with the Bitcoin alphabet (omits `0`, `O`, `I`, `l`).
//!
//! This is a big-integer base conversion, so it is `O(n^2)` in the input length —
//! fine for keys and hashes, not for bulk data.

use crate::{Error, Result};
use alloc::string::String;
use alloc::vec::Vec;

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode bytes as a Base58 string. Leading zero bytes become leading `1`s.
#[must_use]
pub fn encode(data: &[u8]) -> String {
    let zeros = data.iter().take_while(|&&b| b == 0).count();

    // Convert base-256 -> base-58 by repeated division.
    let mut digits: Vec<u8> = Vec::with_capacity(data.len() * 138 / 100 + 1);
    for &byte in &data[zeros..] {
        let mut carry = u32::from(byte);
        for d in &mut digits {
            carry += u32::from(*d) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut out = Vec::with_capacity(zeros + digits.len());
    out.resize(zeros, b'1');
    for &d in digits.iter().rev() {
        out.push(ALPHABET[usize::from(d)]);
    }
    // SAFETY: bytes are either b'1' or entries of an ASCII alphabet.
    unsafe { String::from_utf8_unchecked(out) }
}

/// Decode a Base58 string back to bytes.
pub fn decode(text: &str) -> Result<Vec<u8>> {
    let err = || Error::InvalidEncoding { scheme: "base58" };
    let text = text.trim();
    let zeros = text.bytes().take_while(|&b| b == b'1').count();

    let mut bytes: Vec<u8> = Vec::with_capacity(text.len());
    for ch in text.bytes().skip(zeros) {
        let mut carry = u32::from(digit_value(ch).ok_or_else(err)?);
        for b in &mut bytes {
            carry += u32::from(*b) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    let mut out = Vec::with_capacity(zeros + bytes.len());
    out.resize(zeros, 0);
    out.extend(bytes.iter().rev());
    Ok(out)
}

#[inline]
fn digit_value(c: u8) -> Option<u8> {
    ALPHABET.iter().position(|&a| a == c).map(|p| p as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"Hello World!"), "2NEpo7TZRRrLZSi2U");
        assert_eq!(encode(&[0x00, 0x00, 0x28, 0x7f, 0xb4, 0xcd]), "11233QC4");
    }

    #[test]
    fn roundtrip() {
        for data in [
            &b"\x00\x00\x01"[..],
            &b"the quick brown fox"[..],
            &[0xff; 32][..],
        ] {
            assert_eq!(decode(&encode(data)).unwrap(), data);
        }
    }

    #[test]
    fn rejects_ambiguous_chars() {
        assert!(decode("0OIl").is_err());
    }
}
