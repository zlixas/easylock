//! RSAES-OAEP (PKCS#1 v2.2 / RFC 8017 §7.1) with MGF1.
//!
//! `hash` selects both the label hash and the MGF1 hash (SHA-256 / SHA-512, or
//! any 32-byte digest in this crate). The decryption path folds every structural
//! check into a single accumulator so a failure does not reveal *which* check
//! failed (Manger's attack hygiene) — though a from-scratch RSA should not be a
//! padding oracle in the first place.

use super::{modulus_byte_len, to_fixed_be, RsaPrivateKey, RsaPublicKey};
use crate::bigint::BigUint;
use crate::ct::ct_eq;
use crate::hash::Algorithm;
use crate::secure::Zeroize;
use crate::{Error, Result};
use alloc::vec;
use alloc::vec::Vec;

/// MGF1 mask generation function (RFC 8017 §B.2.1).
fn mgf1(hash: Algorithm, seed: &[u8], mask_len: usize) -> Vec<u8> {
    let h_len = hash.output_len();
    let mut mask = Vec::with_capacity(mask_len);
    let mut counter: u32 = 0;
    while mask.len() < mask_len {
        let mut block_input = Vec::with_capacity(seed.len() + 4);
        block_input.extend_from_slice(seed);
        block_input.extend_from_slice(&counter.to_be_bytes());
        mask.extend_from_slice(&hash.hash(&block_input));
        counter += 1;
        let _ = h_len;
    }
    mask.truncate(mask_len);
    mask
}

impl<const N: usize> RsaPublicKey<N> {
    /// RSAES-OAEP encryption. `label` is usually empty. `seed` must be exactly
    /// `hash.output_len()` bytes of fresh randomness.
    ///
    /// # Errors
    /// Fails if the message is too long for the modulus / hash, or the seed
    /// length is wrong.
    pub fn encrypt_oaep(
        &self,
        hash: Algorithm,
        label: &[u8],
        message: &[u8],
        seed: &[u8],
    ) -> Result<Vec<u8>> {
        let k = self.size();
        let h_len = hash.output_len();

        if seed.len() != h_len {
            return Err(Error::InvalidLength {
                what: "oaep seed",
                expected: h_len,
                got: seed.len(),
            });
        }
        if message.len() > k.saturating_sub(2 * h_len + 2) {
            return Err(Error::InvalidParameter {
                what: "oaep message too long",
            });
        }

        let l_hash = hash.hash(label);
        let db_len = k - h_len - 1;

        // DB = lHash || PS(0x00..) || 0x01 || M
        let mut db = vec![0u8; db_len];
        db[..h_len].copy_from_slice(&l_hash);
        db[db_len - message.len() - 1] = 0x01;
        db[db_len - message.len()..].copy_from_slice(message);

        let db_mask = mgf1(hash, seed, db_len);
        for (b, m) in db.iter_mut().zip(&db_mask) {
            *b ^= *m;
        }
        let seed_mask = mgf1(hash, &db, h_len);
        let mut masked_seed = seed.to_vec();
        for (b, m) in masked_seed.iter_mut().zip(&seed_mask) {
            *b ^= *m;
        }

        // EM = 0x00 || maskedSeed || maskedDB
        let mut em = vec![0u8; k];
        em[1..=h_len].copy_from_slice(&masked_seed);
        em[h_len + 1..].copy_from_slice(&db);

        let c = self.raw(&BigUint::<N>::from_be_bytes(&em));
        db.zeroize();
        masked_seed.zeroize();
        em.zeroize();
        Ok(to_fixed_be(&c, k))
    }
}

impl<const N: usize, const H: usize> RsaPrivateKey<N, H> {
    /// RSAES-OAEP decryption.
    ///
    /// # Errors
    /// Returns [`Error::Authentication`] on any padding failure, with no detail.
    pub fn decrypt_oaep(
        &self,
        hash: Algorithm,
        label: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let k = modulus_byte_len(self.public_key().modulus());
        let h_len = hash.output_len();
        if ciphertext.len() != k || k < 2 * h_len + 2 {
            return Err(Error::Authentication);
        }

        let c = BigUint::<N>::from_be_bytes(ciphertext);
        let m = self.raw(&c);
        let mut em = to_fixed_be(&m, k);

        let l_hash = hash.hash(label);
        let db_len = k - h_len - 1;

        let (y, rest) = em.split_at(1);
        let (masked_seed, masked_db) = rest.split_at(h_len);

        let seed_mask = mgf1(hash, masked_db, h_len);
        let mut seed = masked_seed.to_vec();
        for (b, m) in seed.iter_mut().zip(&seed_mask) {
            *b ^= *m;
        }
        let db_mask = mgf1(hash, &seed, db_len);
        let mut db = masked_db.to_vec();
        for (b, m) in db.iter_mut().zip(&db_mask) {
            *b ^= *m;
        }

        // Validate: Y == 0, db[..hLen] == lHash, then a run of 0x00 followed by a
        // single 0x01 separator. Accumulate into one flag.
        let mut valid: u8 = u8::from(y[0] == 0x00);
        valid &= u8::from(bool::from(ct_eq(&db[..h_len], &l_hash)));

        let mut seen_one: u8 = 0;
        let mut msg_start = 0usize;
        for i in h_len..db_len {
            let is_one = u8::from(db[i] == 0x01);
            let is_zero = u8::from(db[i] == 0x00);
            let first_one = is_one & (seen_one ^ 1);
            msg_start += usize::from(first_one) * (i + 1);
            // before the separator every byte must be 0x00
            valid &= (seen_one) | is_one | is_zero;
            seen_one |= is_one;
        }
        valid &= seen_one;

        let ok = valid == 1;
        let message = if ok {
            db[msg_start..].to_vec()
        } else {
            Vec::new()
        };

        seed.zeroize();
        db.zeroize();
        em.zeroize();

        if ok {
            Ok(message)
        } else {
            Err(Error::Authentication)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::hex::decode;
    use crate::rsa::RsaPrivateKey;

    // Same RSA-2048 test key used by the pkcs1v15 tests.
    const N_HEX: &str = "a2023697b79a4ec1b9920a045fdc1cf281c35bac0eb88cb73ba73780605cd1b8961127d50402ae87f22c053b9fd9fee78d7600f0b138dd7146229be9e6498e6063650421492340557780b03b824b9fc4751890ac61875b7b5fe1d6cc35fa3ce6d12c26cc6c965acf209378f8068615016eafe1fd1b3993945b2bca390eb9ce2f9c29f84e2d22a40629c958e999d0cdc4a0ab0cae62a3a616364bcf139c09d6b3644ebf2be82cd2c645491790cfaf4c27d3e4af95e0f562751368067eae84f0a9359b9482d171d8165508526bc925880a9b621fa71c57bb637276cc5c377daec4704094e1155ae085e3ba285626bb2df8c6840cf4217e29f77f6d4b7c631b74a5";
    const P_HEX: &str = "df709ca17ba698d6ee504a734773aea6e8a29f143f775f40f10f344ab69e706f78819a83023195afa929fdd92f19cb4287fa3525ad1f3eba3e5f1d6ed189f1ea27a3873cb62f107d205c937b18c1d818d285f0a04fb1fbd35142a9b9d01012384d9dc0250a8c76bdf1a56c29eacbcc4a751d40ba0e066b02cf6f9164ef56f42b";
    const Q_HEX: &str = "b99deb432007c39517f543ea57b09d17c3682dd1bec3f0ef7b59016fadc76a617c43011ade5821d0abf951108b2b435f1e800a78e624ff2d6089fb6f4c02ca78bc5fc3066ab418648319656125968d6486d3a572326fc84e9732f900e71463877e9096dd33e1951f5e9bb3a55652dac937c3d9a242cdea5efdd3ea656b9dc26f";
    const DP_HEX: &str = "55a05735ff27d1ec93f94afeb084218b2f1d9aeeec7f778e7092ce0c4fbd9a02ede064f10db728d0df780b22deccf8baef573064d6da61748810753c11aad67d506177a3098231c471d16867450e8c1cbf18bb25044585e6ee7e2882dfbc38ef40b7527a1f77c2cd79bc561e1e2fa983632c29b0e34d0c57505d460fb334d46f";
    const DQ_HEX: &str = "83eae1160ec095d6f37503749c27d02de059bd1eb1366e98b51057bdf8429eaf73f1e6ea22957e4ae0be4b47b7b0e2abca707380e307ee3760c20fe9549b332cc5ac455ddd1debac1ba443f1dc15f89d36595adf234b608fc2539eb66e84860bf8fe67ca042251aa3ec1e7d61cd8bbd78003783c22c057ce751554240a6ccf8f";
    const QINV_HEX: &str = "adbda50a8b5616b5d53ce294a35e782e9caf06709721886e2bf6dde4db7a00a9cab4d182cec3dbced28f43137d40758824fffb9a3febff88bf3841d4f26277ecac1677702a6ecee680dbd947223fcf0634ea9a966954348612f5d708aa0f4326d8dc28321a285d25cfa515b9c4db13c6ad7335b3061fc65d774a93dfca838961";

    fn key() -> RsaPrivateKey<32, 16> {
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

    #[test]
    fn oaep_sha256_roundtrip() {
        let sk = key();
        let seed = [0xA5u8; 32];
        let msg = b"OAEP with SHA-256 label test";
        let ct = sk
            .public_key()
            .encrypt_oaep(Algorithm::Sha256, b"context", msg, &seed)
            .unwrap();
        assert_eq!(ct.len(), 256);
        let pt = sk.decrypt_oaep(Algorithm::Sha256, b"context", &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn oaep_sha512_roundtrip_empty_label() {
        let sk = key();
        let seed = [0x11u8; 64];
        let msg = b"short";
        let ct = sk
            .public_key()
            .encrypt_oaep(Algorithm::Sha512, b"", msg, &seed)
            .unwrap();
        let pt = sk.decrypt_oaep(Algorithm::Sha512, b"", &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn oaep_wrong_label_rejected() {
        let sk = key();
        let ct = sk
            .public_key()
            .encrypt_oaep(Algorithm::Sha256, b"label-a", b"secret", &[7u8; 32])
            .unwrap();
        assert_eq!(
            sk.decrypt_oaep(Algorithm::Sha256, b"label-b", &ct),
            Err(Error::Authentication)
        );
    }

    #[test]
    fn oaep_tampered_ciphertext_rejected() {
        let sk = key();
        let mut ct = sk
            .public_key()
            .encrypt_oaep(Algorithm::Sha256, b"", b"secret", &[7u8; 32])
            .unwrap();
        ct[200] ^= 0x01;
        assert!(sk.decrypt_oaep(Algorithm::Sha256, b"", &ct).is_err());
    }

    // Decrypt a ciphertext produced by OpenSSL 3
    // (`pkeyutl -encrypt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256`).
    #[test]
    fn decrypts_openssl_oaep_sha256_ciphertext() {
        let sk = key();
        let ct = decode(
            "2b902a1317b3947558d7e5a9e632375c581a4087804e4655c132f7bc10eb6da3c\
             0974fc36ef54c2c2eb9ab30eb35c05da1612a39323826113aed4ce825ae524d0\
             50d99f26522f0bb718cb53049325cf08b1c71aeb4b701081a7577d853aca22b84\
             09169bdad240d8ca60a5fab8d276000bf5f27725cea990343626e2c005cca4024\
             8732054037ceadd145585f6df3113e9be322026ca8fb13e19f453a526c2eaf904\
             6041e76b63fbbf3bf1785f392cf57a65f1741c0f92a6c382e6136727a5482b9c2\
             5d10ba483377824729f375d1c5fda5bd7752c26ffc2a50091852f250f8f6f45be\
             b4dceb736c8c178fae2342667764140268664f1481cd425959940c4956",
        )
        .unwrap();
        let pt = sk.decrypt_oaep(Algorithm::Sha256, b"", &ct).unwrap();
        assert_eq!(pt, b"cross-impl OAEP check");
    }

    #[test]
    fn oaep_message_too_long_rejected() {
        let sk = key();
        // k=256, hLen=32 -> max message = 256 - 2*32 - 2 = 190
        let too_long = vec![0u8; 191];
        assert!(sk
            .public_key()
            .encrypt_oaep(Algorithm::Sha256, b"", &too_long, &[0u8; 32])
            .is_err());
    }
}
