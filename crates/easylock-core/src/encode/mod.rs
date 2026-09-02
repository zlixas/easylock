//! Reversible byte<->text transforms: Hex, Base64, Base64URL, Base58, ROT13.
//!
//! Every decoder validates its alphabet and returns [`crate::Error::InvalidEncoding`]
//! on the first stray byte. Encoders never allocate more than the exact output
//! size. These transforms are *not* secret-dependent-constant-time — encoding is
//! not a place where timing leaks matter — with the exception of nothing here;
//! callers that need to hide the length of a secret should pad before encoding.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub mod base58;
pub mod base64;
pub mod hex;
pub mod rot13;

/// Transform identifiers accepted by the CLI's `encode`/`decode` and the FFI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transform {
    /// Lowercase hexadecimal.
    Hex,
    /// Standard RFC 4648 Base64 with `+/` and `=` padding.
    Base64,
    /// URL-safe RFC 4648 Base64 with `-_` and no padding.
    Base64Url,
    /// Bitcoin-style Base58 (no `0OIl`).
    Base58,
    /// ROT13 (letters only; bytes outside `A-Za-z` pass through).
    Rot13,
}

impl Transform {
    /// Parse a transform name (case-insensitive; accepts a few aliases).
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        let n = name.trim().to_ascii_lowercase();
        Some(match n.as_str() {
            "hex" | "base16" => Transform::Hex,
            "base64" | "b64" => Transform::Base64,
            "base64url" | "base64-url" | "b64url" => Transform::Base64Url,
            "base58" | "b58" => Transform::Base58,
            "rot13" => Transform::Rot13,
            _ => return None,
        })
    }

    /// Canonical lowercase name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Transform::Hex => "hex",
            Transform::Base64 => "base64",
            Transform::Base64Url => "base64url",
            Transform::Base58 => "base58",
            Transform::Rot13 => "rot13",
        }
    }

    /// Encode bytes to text.
    #[must_use]
    pub fn encode(self, data: &[u8]) -> String {
        match self {
            Transform::Hex => hex::encode(data),
            Transform::Base64 => base64::encode(data, base64::Variant::Standard),
            Transform::Base64Url => base64::encode(data, base64::Variant::UrlNoPad),
            Transform::Base58 => base58::encode(data),
            Transform::Rot13 => rot13::apply_str(data),
        }
    }

    /// Decode text back to bytes.
    pub fn decode(self, text: &str) -> crate::Result<Vec<u8>> {
        match self {
            Transform::Hex => hex::decode(text),
            Transform::Base64 => base64::decode(text, base64::Variant::Standard),
            Transform::Base64Url => base64::decode(text, base64::Variant::UrlNoPad),
            Transform::Base58 => base58::decode(text),
            Transform::Rot13 => Ok(rot13::apply(text.as_bytes())),
        }
    }
}

/// Apply a pipeline of transforms left to right (encoding direction).
///
/// `chain_encode(data, [Base64, Hex])` = hex(base64(data)).
pub fn chain_encode(data: &[u8], steps: &[Transform]) -> String {
    if steps.is_empty() {
        return hex::encode(data);
    }
    let mut buf: Vec<u8> = data.to_vec();
    let mut out = String::new();
    for (i, step) in steps.iter().enumerate() {
        out = step.encode(&buf);
        if i + 1 < steps.len() {
            buf = out.clone().into_bytes();
        }
    }
    out
}

/// Reverse a pipeline (decoding direction): pass the *encoding* order and it is
/// undone right to left.
pub fn chain_decode(text: &str, steps: &[Transform]) -> crate::Result<Vec<u8>> {
    let mut current = text.to_string();
    for step in steps.iter().rev() {
        let bytes = step.decode(&current)?;
        current = match core::str::from_utf8(&bytes) {
            Ok(s) => s.to_string(),
            Err(_) => {
                // Final stage produced raw bytes; only valid as the last decode.
                return Ok(bytes);
            }
        };
    }
    Ok(current.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transform_roundtrips() {
        let data = b"The quick brown fox \x00\xff\x80";
        for t in [
            Transform::Hex,
            Transform::Base64,
            Transform::Base64Url,
            Transform::Base58,
        ] {
            let enc = t.encode(data);
            let dec = t.decode(&enc).unwrap();
            assert_eq!(dec, data, "roundtrip failed for {}", t.name());
        }
    }

    #[test]
    fn chain_encode_then_decode() {
        let data = b"chained!";
        let steps = [Transform::Base64, Transform::Hex];
        let enc = chain_encode(data, &steps);
        let dec = chain_decode(&enc, &steps).unwrap();
        assert_eq!(dec, data);
    }
}
