//! PBKDF2 (RFC 8018 §5.2) over HMAC.

use crate::hash::Hash;
use crate::mac::Hmac;
use crate::secure::Zeroize;
use crate::{Error, Result};
use alloc::vec;
use alloc::vec::Vec;

/// Derive `out.len()` bytes from `password` and `salt` using `iterations` rounds
/// of `HMAC-<H>`.
///
/// # Errors
/// Returns [`Error::InvalidParameter`] if `iterations == 0` or `out` is empty.
pub fn pbkdf2_into<H: Hash>(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out: &mut [u8],
) -> Result<()> {
    if iterations == 0 {
        return Err(Error::InvalidParameter { what: "iterations" });
    }
    if out.is_empty() {
        return Err(Error::InvalidParameter {
            what: "output length",
        });
    }
    let h_len = H::OUTPUT_LEN;

    for (block_index, chunk) in out.chunks_mut(h_len).enumerate() {
        let i = (block_index as u32) + 1;

        // U1 = PRF(password, salt || INT_32_BE(i))
        let mut mac = Hmac::<H>::new(password);
        mac.update(salt);
        mac.update(&i.to_be_bytes());
        let mut u = mac.finalize();
        let mut acc = u.clone();

        for _ in 1..iterations {
            let next = Hmac::<H>::mac(password, &u);
            for (a, n) in acc.iter_mut().zip(next.iter()) {
                *a ^= *n;
            }
            u.zeroize();
            u = next;
        }
        chunk.copy_from_slice(&acc[..chunk.len()]);
        u.zeroize();
        acc.zeroize();
    }
    Ok(())
}

/// Convenience wrapper returning a freshly allocated `Vec`.
pub fn pbkdf2<H: Hash>(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out_len: usize,
) -> Result<Vec<u8>> {
    let mut out = vec![0u8; out_len];
    pbkdf2_into::<H>(password, salt, iterations, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::hex::encode;
    use crate::hash::Sha256;

    // RFC 7914 / draft-josefsson PBKDF2-HMAC-SHA-256 test vectors.
    #[test]
    fn pbkdf2_hmac_sha256_vectors() {
        assert_eq!(
            encode(&pbkdf2::<Sha256>(b"passwd", b"salt", 1, 64).unwrap()),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc\
             49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
        );
        assert_eq!(
            encode(&pbkdf2::<Sha256>(b"Password", b"NaCl", 80000, 64).unwrap()),
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56\
             a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"
        );
    }

    #[test]
    fn rejects_zero_iterations() {
        assert!(pbkdf2::<Sha256>(b"p", b"s", 0, 16).is_err());
    }
}
