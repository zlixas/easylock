//! RSA for 2048- and 4096-bit keys: PKCS#1 v1.5 sign/verify and encrypt/decrypt
//! (this module), and RSAES-OAEP / PKCS#1 v2.2 in [`oaep`].
//!
//! Keys are loaded from raw big-endian components (this build does not parse
//! DER/PEM — that belongs in a higher layer). Private-key operations use the CRT
//! with a constant-time Montgomery ladder per prime. Padding checks in
//! `decrypt`/`verify` are written to avoid revealing *where* a check failed
//! (Bleichenbacher / Manger hygiene), though a from-scratch RSA should not be a
//! padding oracle in the first place.
//!
//! `N` is the modulus size in 64-bit limbs: 32 for RSA-2048, 64 for RSA-4096.
//! `H` is `N / 2` (prime size).

pub mod oaep;

use crate::bigint::montgomery::{reduce_wide, Montgomery};
use crate::bigint::BigUint;
use crate::ct::{ct_eq, Choice};
use crate::hash::Algorithm;
use crate::secure::Zeroize;
use crate::{Error, Result};
use alloc::vec;
use alloc::vec::Vec;

/// RSA-2048 modulus limb count.
pub const RSA2048_LIMBS: usize = 32;
/// RSA-4096 modulus limb count.
pub const RSA4096_LIMBS: usize = 64;

/// An RSA public key: modulus `n` and public exponent `e`.
#[derive(Clone, Debug)]
pub struct RsaPublicKey<const N: usize> {
    n: BigUint<N>,
    e: u64,
    mont: Montgomery<N>,
    modulus_bytes: usize,
}

/// An RSA private key with CRT parameters. Secret components scrub on drop.
pub struct RsaPrivateKey<const N: usize, const H: usize> {
    public: RsaPublicKey<N>,
    p: BigUint<H>,
    q: BigUint<H>,
    dp: BigUint<H>,
    dq: BigUint<H>,
    qinv: BigUint<H>,
    mont_p: Montgomery<H>,
    mont_q: Montgomery<H>,
}

impl<const N: usize> RsaPublicKey<N> {
    /// Load from a big-endian modulus and a small public exponent.
    ///
    /// # Errors
    /// Fails if `n` is even/zero or does not use its top limb (i.e. is not a
    /// full `N`-limb modulus).
    pub fn from_components(n_be: &[u8], e: u64) -> Result<Self> {
        let n = BigUint::<N>::from_be_bytes(n_be);
        if !n.is_odd() || n.limbs[N - 1] == 0 {
            return Err(Error::InvalidParameter {
                what: "rsa modulus",
            });
        }
        let mont = Montgomery::new(n).ok_or(Error::InvalidParameter {
            what: "rsa modulus",
        })?;
        Ok(Self {
            n,
            e,
            mont,
            modulus_bytes: modulus_byte_len(&n),
        })
    }

    /// Modulus size in bytes (`k` in PKCS#1).
    #[must_use]
    pub fn size(&self) -> usize {
        self.modulus_bytes
    }

    pub(super) fn modulus(&self) -> &BigUint<N> {
        &self.n
    }

    pub(super) fn raw(&self, m: &BigUint<N>) -> BigUint<N> {
        let e = BigUint::<N>::from_limbs({
            let mut l = [0u64; N];
            l[0] = self.e;
            l
        });
        self.mont.pow(m, &e)
    }

    /// PKCS#1 v1.5 signature verification. Returns `Ok(())` iff the signature is
    /// valid for `message` under `hash`.
    pub fn verify_pkcs1v15(&self, hash: Algorithm, message: &[u8], sig: &[u8]) -> Result<()> {
        if sig.len() != self.modulus_bytes {
            return Err(Error::InvalidLength {
                what: "rsa signature",
                expected: self.modulus_bytes,
                got: sig.len(),
            });
        }
        let s = BigUint::<N>::from_be_bytes(sig);
        if bool::from(s.ct_gte(&self.n)) {
            return Err(Error::Authentication);
        }
        let m = self.raw(&s);
        let em = to_fixed_be(&m, self.modulus_bytes);
        let expected = pkcs1v15_sig_encode(hash, message, self.modulus_bytes)?;
        if bool::from(ct_eq(&em, &expected)) {
            Ok(())
        } else {
            Err(Error::Authentication)
        }
    }

    /// PKCS#1 v1.5 encryption (RSAES-PKCS1-v1_5). `rand` supplies the non-zero
    /// padding bytes (`k - 3 - msg.len()` of them).
    pub fn encrypt_pkcs1v15(&self, message: &[u8], rand: &[u8]) -> Result<Vec<u8>> {
        let k = self.modulus_bytes;
        if message.len() + 11 > k {
            return Err(Error::InvalidParameter {
                what: "rsa plaintext too long",
            });
        }
        let ps_len = k - message.len() - 3;
        if rand.len() < ps_len {
            return Err(Error::InvalidParameter {
                what: "insufficient padding randomness",
            });
        }
        let mut em = vec![0u8; k];
        em[0] = 0x00;
        em[1] = 0x02;
        // Non-zero padding string.
        let mut ri = 0;
        for slot in &mut em[2..2 + ps_len] {
            let mut b = 0u8;
            while b == 0 {
                b = rand[ri % rand.len()];
                ri += 1;
                if ri > rand.len() * 4 {
                    b = 0x01; // fallback, extremely unlikely
                }
            }
            *slot = b;
        }
        em[2 + ps_len] = 0x00;
        em[3 + ps_len..].copy_from_slice(message);

        let m = BigUint::<N>::from_be_bytes(&em);
        let c = self.raw(&m);
        em.zeroize();
        Ok(to_fixed_be(&c, k))
    }
}

impl<const N: usize, const H: usize> RsaPrivateKey<N, H> {
    /// Load from big-endian CRT components. `H` must be `N / 2`.
    pub fn from_components(
        n_be: &[u8],
        e: u64,
        p_be: &[u8],
        q_be: &[u8],
        dp_be: &[u8],
        dq_be: &[u8],
        qinv_be: &[u8],
    ) -> Result<Self> {
        assert_eq!(H * 2, N, "H must equal N/2");
        let public = RsaPublicKey::<N>::from_components(n_be, e)?;
        let p = BigUint::<H>::from_be_bytes(p_be);
        let q = BigUint::<H>::from_be_bytes(q_be);
        let mont_p = Montgomery::new(p).ok_or(Error::InvalidParameter {
            what: "rsa prime p",
        })?;
        let mont_q = Montgomery::new(q).ok_or(Error::InvalidParameter {
            what: "rsa prime q",
        })?;
        Ok(Self {
            public,
            p,
            q,
            dp: BigUint::<H>::from_be_bytes(dp_be),
            dq: BigUint::<H>::from_be_bytes(dq_be),
            qinv: BigUint::<H>::from_be_bytes(qinv_be),
            mont_p,
            mont_q,
        })
    }

    /// The matching public key.
    #[must_use]
    pub fn public_key(&self) -> &RsaPublicKey<N> {
        &self.public
    }

    /// CRT private-key primitive: `c -> c^d mod n`.
    pub(super) fn raw(&self, c: &BigUint<N>) -> BigUint<N> {
        // m1 = (c mod p)^dp mod p ; m2 = (c mod q)^dq mod q
        let cp = reduce_wide::<H>(&c.limbs, &self.p);
        let cq = reduce_wide::<H>(&c.limbs, &self.q);
        let m1 = self.mont_p.pow(&cp, &self.dp);
        let m2 = self.mont_q.pow(&cq, &self.dq);

        // h = qinv * (m1 - m2) mod p
        let mut diff = m1;
        let borrow = diff.sub_assign(&m2);
        diff.ct_add_assign(&self.p, ct_choice(borrow));
        let h = self.mont_p.mul_mod(&diff, &self.qinv);

        // m = m2 + h * q
        let hq = h.mul_wide(&self.q); // 2H = N limbs
        let mut m = BigUint::<N>::ZERO;
        m.limbs.copy_from_slice(&hq[..N]);
        let mut m2_ext = BigUint::<N>::ZERO;
        m2_ext.limbs[..H].copy_from_slice(&m2.limbs);
        m.add_assign(&m2_ext);
        m
    }

    /// PKCS#1 v1.5 signature over `message` using `hash`.
    pub fn sign_pkcs1v15(&self, hash: Algorithm, message: &[u8]) -> Result<Vec<u8>> {
        let k = self.public.modulus_bytes;
        let em = pkcs1v15_sig_encode(hash, message, k)?;
        let m = BigUint::<N>::from_be_bytes(&em);
        let s = self.raw(&m);
        Ok(to_fixed_be(&s, k))
    }

    /// PKCS#1 v1.5 decryption. Returns the recovered message.
    pub fn decrypt_pkcs1v15(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let k = self.public.modulus_bytes;
        if ciphertext.len() != k {
            return Err(Error::InvalidLength {
                what: "rsa ciphertext",
                expected: k,
                got: ciphertext.len(),
            });
        }
        let c = BigUint::<N>::from_be_bytes(ciphertext);
        let m = self.raw(&c);
        let mut em = to_fixed_be(&m, k);

        // Constant-ish-time PKCS#1 unpad: accumulate validity, then locate the
        // 0x00 separator.
        let mut valid = u8::from(em[0] == 0x00) & u8::from(em[1] == 0x02);
        let mut sep = 0usize;
        let mut seen = 0u8;
        for i in 2..k {
            let is_zero = u8::from(em[i] == 0x00);
            let first = is_zero & (seen ^ 1);
            sep += usize::from(first) * i;
            seen |= is_zero;
        }
        valid &= seen; // there was a separator
        valid &= u8::from(sep >= 10); // >= 8 padding bytes + 2 header
        if valid != 1 {
            em.zeroize();
            return Err(Error::Authentication);
        }
        let msg = em[sep + 1..].to_vec();
        em.zeroize();
        Ok(msg)
    }
}

impl<const N: usize, const H: usize> Drop for RsaPrivateKey<N, H> {
    fn drop(&mut self) {
        self.p.zeroize();
        self.q.zeroize();
        self.dp.zeroize();
        self.dq.zeroize();
        self.qinv.zeroize();
        self.mont_p.zeroize();
        self.mont_q.zeroize();
    }
}

impl<const N: usize, const H: usize> core::fmt::Debug for RsaPrivateKey<N, H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RsaPrivateKey").finish_non_exhaustive()
    }
}

fn ct_choice(v: u64) -> Choice {
    Choice::from_u8((v & 1) as u8)
}

pub(super) fn modulus_byte_len<const N: usize>(n: &BigUint<N>) -> usize {
    // Highest non-zero byte position + 1.
    let be = n.to_be_bytes();
    let lead = be.iter().take_while(|&&b| b == 0).count();
    be.len() - lead
}

pub(super) fn to_fixed_be<const N: usize>(v: &BigUint<N>, len: usize) -> Vec<u8> {
    let full = v.to_be_bytes();
    debug_assert!(full.len() >= len);
    full[full.len() - len..].to_vec()
}

/// ASN.1 DigestInfo DER prefixes for PKCS#1 v1.5 signatures.
fn digest_info_prefix(hash: Algorithm) -> Result<&'static [u8]> {
    Ok(match hash {
        Algorithm::Sha256 => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ],
        Algorithm::Sha512 => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ],
        _ => {
            return Err(Error::Unsupported {
                what: "rsa-pkcs1v15 with this hash",
            })
        }
    })
}

fn pkcs1v15_sig_encode(hash: Algorithm, message: &[u8], k: usize) -> Result<Vec<u8>> {
    let prefix = digest_info_prefix(hash)?;
    let digest = match hash {
        Algorithm::Sha256 => crate::hash::digest::<crate::hash::Sha256>(message),
        Algorithm::Sha512 => crate::hash::digest::<crate::hash::Sha512>(message),
        _ => return Err(Error::Unsupported { what: "hash" }),
    };
    let t_len = prefix.len() + digest.len();
    if k < t_len + 11 {
        return Err(Error::InvalidParameter {
            what: "rsa modulus too small for hash",
        });
    }
    let mut em = vec![0xffu8; k];
    em[0] = 0x00;
    em[1] = 0x01;
    em[k - t_len - 1] = 0x00;
    em[k - t_len..k - digest.len()].copy_from_slice(prefix);
    em[k - digest.len()..].copy_from_slice(&digest);
    Ok(em)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::hex::decode;

    // A real RSA-2048 key (generated with OpenSSL for testing only).
    const N_HEX: &str = "a2023697b79a4ec1b9920a045fdc1cf281c35bac0eb88cb73ba73780605cd1b8961127d50402ae87f22c053b9fd9fee78d7600f0b138dd7146229be9e6498e6063650421492340557780b03b824b9fc4751890ac61875b7b5fe1d6cc35fa3ce6d12c26cc6c965acf209378f8068615016eafe1fd1b3993945b2bca390eb9ce2f9c29f84e2d22a40629c958e999d0cdc4a0ab0cae62a3a616364bcf139c09d6b3644ebf2be82cd2c645491790cfaf4c27d3e4af95e0f562751368067eae84f0a9359b9482d171d8165508526bc925880a9b621fa71c57bb637276cc5c377daec4704094e1155ae085e3ba285626bb2df8c6840cf4217e29f77f6d4b7c631b74a5";
    const P_HEX: &str = "df709ca17ba698d6ee504a734773aea6e8a29f143f775f40f10f344ab69e706f78819a83023195afa929fdd92f19cb4287fa3525ad1f3eba3e5f1d6ed189f1ea27a3873cb62f107d205c937b18c1d818d285f0a04fb1fbd35142a9b9d01012384d9dc0250a8c76bdf1a56c29eacbcc4a751d40ba0e066b02cf6f9164ef56f42b";
    const Q_HEX: &str = "b99deb432007c39517f543ea57b09d17c3682dd1bec3f0ef7b59016fadc76a617c43011ade5821d0abf951108b2b435f1e800a78e624ff2d6089fb6f4c02ca78bc5fc3066ab418648319656125968d6486d3a572326fc84e9732f900e71463877e9096dd33e1951f5e9bb3a55652dac937c3d9a242cdea5efdd3ea656b9dc26f";
    const DP_HEX: &str = "55a05735ff27d1ec93f94afeb084218b2f1d9aeeec7f778e7092ce0c4fbd9a02ede064f10db728d0df780b22deccf8baef573064d6da61748810753c11aad67d506177a3098231c471d16867450e8c1cbf18bb25044585e6ee7e2882dfbc38ef40b7527a1f77c2cd79bc561e1e2fa983632c29b0e34d0c57505d460fb334d46f";
    const DQ_HEX: &str = "83eae1160ec095d6f37503749c27d02de059bd1eb1366e98b51057bdf8429eaf73f1e6ea22957e4ae0be4b47b7b0e2abca707380e307ee3760c20fe9549b332cc5ac455ddd1debac1ba443f1dc15f89d36595adf234b608fc2539eb66e84860bf8fe67ca042251aa3ec1e7d61cd8bbd78003783c22c057ce751554240a6ccf8f";
    const QINV_HEX: &str = "adbda50a8b5616b5d53ce294a35e782e9caf06709721886e2bf6dde4db7a00a9cab4d182cec3dbced28f43137d40758824fffb9a3febff88bf3841d4f26277ecac1677702a6ecee680dbd947223fcf0634ea9a966954348612f5d708aa0f4326d8dc28321a285d25cfa515b9c4db13c6ad7335b3061fc65d774a93dfca838961";

    fn priv_key() -> RsaPrivateKey<32, 16> {
        RsaPrivateKey::<32, 16>::from_components(
            &decode(N_HEX).unwrap(),
            65537,
            &decode(P_HEX).unwrap(),
            &decode(Q_HEX).unwrap(),
            &decode(DP_HEX).unwrap(),
            &decode(DQ_HEX).unwrap(),
            &decode(QINV_HEX).unwrap(),
        )
        .unwrap()
    }

    // 2^65537 mod n, cross-checked against Python `pow(2, 65537, n)`.
    #[test]
    fn public_raw_matches_reference() {
        use crate::bigint::{BigUint, Montgomery};
        use crate::encode::hex::encode;
        let n = BigUint::<32>::from_be_bytes(&decode(N_HEX).unwrap());
        let m = Montgomery::new(n).unwrap();
        let mut two = BigUint::<32>::ZERO;
        two.limbs[0] = 2;
        let mut e = BigUint::<32>::ZERO;
        e.limbs[0] = 65537;
        let r = m.pow(&two, &e);
        assert_eq!(
            encode(&r.to_be_bytes()),
            "4e300fce4f855b9ee22127ed692f4978db6a454b2eabe96023f382b18aed52a0fc2b99ea5117a39c619d1c70679359236f63d4796df5c13c12afbd4090bd14d74c541a7a105fade86ca57699bd596b12742f89c89693892dc97a3b05c3475a35ea649269c022370071ed80f2ad2c6365fa30ba081dc3ee4ec4d827b5b7c86cb4f158b1b29097f4b04f6cab3feaf5ec47de52ac1972cfb028ccaf372cc6f0472f3f99f9ecb46e752f8606f40269133e2a46720ea8bc9775ad4d516268bfff9ee252fe7b807b33eeb32a8af6e0c7476dfa0dfb55828dda63b687e0b43d86d208f0ce29a723cc346808018a8a618858451531d717b1de2033cb8ac1f545047eebc0"
        );
    }

    #[test]
    fn sign_then_verify_sha256() {
        let sk = priv_key();
        let msg = b"easylock RSA PKCS#1 v1.5 self-test";
        let sig = sk.sign_pkcs1v15(Algorithm::Sha256, msg).unwrap();
        assert_eq!(sig.len(), 256);
        sk.public_key()
            .verify_pkcs1v15(Algorithm::Sha256, msg, &sig)
            .unwrap();
        assert!(sk
            .public_key()
            .verify_pkcs1v15(Algorithm::Sha256, b"tampered", &sig)
            .is_err());
    }

    #[test]
    fn encrypt_then_decrypt() {
        let sk = priv_key();
        let msg = b"a short secret";
        let rand = [0x5au8; 256];
        let ct = sk.public_key().encrypt_pkcs1v15(msg, &rand).unwrap();
        assert_eq!(ct.len(), 256);
        let pt = sk.decrypt_pkcs1v15(&ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn rejects_garbage_ciphertext() {
        let sk = priv_key();
        assert!(sk.decrypt_pkcs1v15(&[0x01u8; 256]).is_err());
    }
}
