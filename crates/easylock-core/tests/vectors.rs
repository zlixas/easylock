//! End-to-end tests over the public API: extra published test vectors plus
//! cross-primitive pipelines (e.g. "encrypt then Base64").

use easylock_core::aead::{Aead, Aes256Gcm, ChaCha20Poly1305};
use easylock_core::ec::{Signature, SigningKey, StaticSecret, VerifyingKey};
use easylock_core::encode::{base64, hex, Transform};
use easylock_core::hash::Algorithm;
use easylock_core::hash::Sha256;
use easylock_core::kdf::{pbkdf2, Hkdf};

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

#[test]
fn sha_family_extra_vectors() {
    // NIST SHA-256 two-block message.
    assert_eq!(
        hex::encode(
            &Algorithm::Sha256.hash(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        ),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    // Keccak-256 of "testing"
    assert_eq!(
        hex::encode(&Algorithm::Keccak256.hash(b"testing")),
        "5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02"
    );
}

#[test]
fn aead_pipeline_encrypt_then_base64() {
    // "AES-256-GCM -> Base64" chaining from the spec.
    let key = [0x11u8; 32];
    let nonce = [0x22u8; 12];
    let aead = Aes256Gcm::new(&key).unwrap();

    let sealed = aead.seal(&nonce, b"context", b"pipeline plaintext");
    let armored = Transform::Base64.encode(&sealed);

    // Reverse the pipeline.
    let back = Transform::Base64.decode(&armored).unwrap();
    let opened = aead.open(&nonce, b"context", &back).unwrap();
    assert_eq!(opened, b"pipeline plaintext");
}

#[test]
fn chacha_and_aes_gcm_interoperate_with_wrappers() {
    for (name, sealed) in [
        (
            "chacha",
            ChaCha20Poly1305::new(&[7u8; 32])
                .unwrap()
                .seal(&[1u8; 12], b"", b"hello aead"),
        ),
        (
            "gcm",
            Aes256Gcm::new(&[7u8; 32])
                .unwrap()
                .seal(&[1u8; 12], b"", b"hello aead"),
        ),
    ] {
        let opened = match name {
            "chacha" => ChaCha20Poly1305::new(&[7u8; 32])
                .unwrap()
                .open(&[1u8; 12], b"", &sealed),
            _ => Aes256Gcm::new(&[7u8; 32])
                .unwrap()
                .open(&[1u8; 12], b"", &sealed),
        }
        .unwrap();
        assert_eq!(opened, b"hello aead");
    }
}

#[test]
fn x25519_then_hkdf_then_aead_handshake() {
    // A miniature Noise-like flow: DH -> HKDF -> AEAD.
    let alice = StaticSecret::from_bytes(
        hx("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
            .try_into()
            .unwrap(),
    );
    let bob = StaticSecret::from_bytes(
        hx("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
            .try_into()
            .unwrap(),
    );

    let s1 = alice.diffie_hellman(&bob.public_key());
    let s2 = bob.diffie_hellman(&alice.public_key());
    assert_eq!(s1.as_bytes(), s2.as_bytes());
    assert!(s1.was_contributory());

    let key = Hkdf::<Sha256>::derive(b"salt", s1.as_bytes(), b"zc handshake v1", 32).unwrap();
    let aead = ChaCha20Poly1305::new(&key).unwrap();
    let sealed = aead.seal(&[0u8; 12], b"", b"handshake complete");
    assert_eq!(
        aead.open(&[0u8; 12], b"", &sealed).unwrap(),
        b"handshake complete"
    );
}

#[test]
fn ed25519_detached_roundtrip_and_rejection() {
    let sk = SigningKey::from_seed([42u8; 32]);
    let vk = sk.verifying_key();
    let msg = b"transfer 10 coins to bob";
    let sig = sk.sign(msg);
    assert!(vk.verify(msg, &sig));

    // Wrong message, wrong signer, flipped bit.
    assert!(!vk.verify(b"transfer 20 coins to bob", &sig));
    assert!(!VerifyingKey::from_bytes([0u8; 32]).verify(msg, &sig));
    let mut bad = sig.to_bytes();
    bad[0] ^= 1;
    assert!(!vk.verify(msg, &Signature::from_bytes(bad)));
}

#[test]
fn pbkdf2_and_base64url_roundtrip() {
    let dk = pbkdf2::<Sha256>(b"password", b"salt", 4096, 32).unwrap();
    let encoded = base64::encode(&dk, base64::Variant::UrlNoPad);
    assert!(!encoded.contains('=') && !encoded.contains('+') && !encoded.contains('/'));
    let decoded = base64::decode(&encoded, base64::Variant::UrlNoPad).unwrap();
    assert_eq!(decoded, dk);
}

#[test]
fn base58_handles_leading_zeros() {
    let data = hx("000000deadbeef");
    let s = Transform::Base58.encode(&data);
    assert!(s.starts_with("111"));
    assert_eq!(Transform::Base58.decode(&s).unwrap(), data);
}
