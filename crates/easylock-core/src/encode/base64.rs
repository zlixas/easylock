//! RFC 4648 Base64, standard and URL-safe variants.

use crate::{Error, Result};
use alloc::string::String;
use alloc::vec::Vec;

/// Which alphabet / padding rules to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// `A-Za-z0-9+/`, `=` padding required on encode, accepted on decode.
    Standard,
    /// `A-Za-z0-9-_`, no padding emitted; padding tolerated on decode.
    UrlNoPad,
}

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn alphabet(v: Variant) -> &'static [u8; 64] {
    match v {
        Variant::Standard => STD,
        Variant::UrlNoPad => URL,
    }
}

/// Encode `data` with the given variant.
#[must_use]
pub fn encode(data: &[u8], variant: Variant) -> String {
    let alpha = alphabet(variant);
    let pad = variant == Variant::Standard;
    let mut out = Vec::with_capacity(data.len().div_ceil(3) * 4);

    let mut chunks = data.chunks_exact(3);
    for c in &mut chunks {
        let n = (u32::from(c[0]) << 16) | (u32::from(c[1]) << 8) | u32::from(c[2]);
        out.push(alpha[(n >> 18) as usize & 0x3f]);
        out.push(alpha[(n >> 12) as usize & 0x3f]);
        out.push(alpha[(n >> 6) as usize & 0x3f]);
        out.push(alpha[n as usize & 0x3f]);
    }
    let rem = chunks.remainder();
    match rem.len() {
        1 => {
            let n = u32::from(rem[0]) << 16;
            out.push(alpha[(n >> 18) as usize & 0x3f]);
            out.push(alpha[(n >> 12) as usize & 0x3f]);
            if pad {
                out.push(b'=');
                out.push(b'=');
            }
        }
        2 => {
            let n = (u32::from(rem[0]) << 16) | (u32::from(rem[1]) << 8);
            out.push(alpha[(n >> 18) as usize & 0x3f]);
            out.push(alpha[(n >> 12) as usize & 0x3f]);
            out.push(alpha[(n >> 6) as usize & 0x3f]);
            if pad {
                out.push(b'=');
            }
        }
        _ => {}
    }
    // SAFETY: all pushed bytes come from an ASCII alphabet or are '='.
    unsafe { String::from_utf8_unchecked(out) }
}

/// Decode a Base64 string. Whitespace is ignored. `=` padding is optional for
/// both variants; where present it must be consistent with the data length.
pub fn decode(text: &str, variant: Variant) -> Result<Vec<u8>> {
    let err = || Error::InvalidEncoding { scheme: "base64" };
    let mut vals: Vec<u8> = Vec::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_whitespace() || b == b'=' {
            continue;
        }
        vals.push(decode_byte(b, variant).ok_or_else(err)?);
    }
    if vals.len() % 4 == 1 {
        return Err(err());
    }

    let mut out = Vec::with_capacity(vals.len() / 4 * 3 + 2);
    let mut chunks = vals.chunks_exact(4);
    for c in &mut chunks {
        let n = (u32::from(c[0]) << 18)
            | (u32::from(c[1]) << 12)
            | (u32::from(c[2]) << 6)
            | u32::from(c[3]);
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
        out.push(n as u8);
    }
    match chunks.remainder() {
        [a, b] => {
            let n = (u32::from(*a) << 18) | (u32::from(*b) << 12);
            out.push((n >> 16) as u8);
        }
        [a, b, c] => {
            let n = (u32::from(*a) << 18) | (u32::from(*b) << 12) | (u32::from(*c) << 6);
            out.push((n >> 16) as u8);
            out.push((n >> 8) as u8);
        }
        _ => {}
    }
    Ok(out)
}

#[inline]
fn decode_byte(b: u8, variant: Variant) -> Option<u8> {
    Some(match b {
        b'A'..=b'Z' => b - b'A',
        b'a'..=b'z' => b - b'a' + 26,
        b'0'..=b'9' => b - b'0' + 52,
        b'+' if variant == Variant::Standard => 62,
        b'/' if variant == Variant::Standard => 63,
        b'-' if variant == Variant::UrlNoPad => 62,
        b'_' if variant == Variant::UrlNoPad => 63,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4648 section 10 test vectors.
    #[test]
    fn rfc4648_vectors() {
        let cases = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, b64) in cases {
            assert_eq!(encode(plain.as_bytes(), Variant::Standard), b64);
            assert_eq!(decode(b64, Variant::Standard).unwrap(), plain.as_bytes());
        }
    }

    #[test]
    fn url_safe_no_padding() {
        let data = &[0xfb, 0xff, 0xbf];
        let e = encode(data, Variant::UrlNoPad);
        assert!(!e.contains('='));
        assert!(!e.contains('+') && !e.contains('/'));
        assert_eq!(decode(&e, Variant::UrlNoPad).unwrap(), data);
    }

    #[test]
    fn rejects_foreign_alphabet() {
        assert!(decode("Zm9v-w", Variant::Standard).is_err());
        assert!(decode("Zm9v/w", Variant::UrlNoPad).is_err());
    }
}
