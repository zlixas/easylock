//! Project Wycheproof test vectors (<https://github.com/C2SP/wycheproof>, Apache-2.0).
//!
//! Wycheproof targets known implementation pitfalls: edge-case lengths, invalid
//! tags, low-order points, non-canonical encodings and signature malleability.
//! Every applicable vector must behave exactly as specified.

use easylock_core::aead::{Aead, Aes256Gcm, ChaCha20Poly1305};
use easylock_core::ec::ed25519::{Signature, VerifyingKey};
use easylock_core::ec::x25519;
use easylock_core::encode::hex;
use easylock_core::hash::{Sha256, Sha512};
use easylock_core::kdf::Hkdf;
use easylock_core::mac::Hmac;
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = format!(
        "{}/tests/wycheproof/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn h(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

/// Iterate `(group, test)` pairs.
fn tests(doc: &Value) -> impl Iterator<Item = (&Value, &Value)> {
    doc["testGroups"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|g| g["tests"].as_array().unwrap().iter().map(move |t| (g, t)))
}

fn result(t: &Value) -> &str {
    t["result"].as_str().unwrap()
}

fn aead_suite(
    name: &str,
    make: impl Fn(&[u8]) -> Box<dyn Fn(&[u8; 12], &[u8], &[u8], bool) -> Option<Vec<u8>>>,
) {
    let doc = load(name);
    let mut checked = 0;
    for (g, t) in tests(&doc) {
        // easylock supports 256-bit keys, 96-bit nonces and 128-bit tags.
        if g["keySize"] != 256 || g["ivSize"] != 96 || g["tagSize"] != 128 {
            continue;
        }
        let id = &t["tcId"];
        let (key, iv, aad, msg, ct, tag) = (
            h(&t["key"]),
            h(&t["iv"]),
            h(&t["aad"]),
            h(&t["msg"]),
            h(&t["ct"]),
            h(&t["tag"]),
        );
        let iv: [u8; 12] = iv.try_into().unwrap();
        let aead = make(&key);
        let mut sealed_expected = ct.clone();
        sealed_expected.extend_from_slice(&tag);
        let opened = aead(&iv, &aad, &sealed_expected, false);
        if result(t) == "invalid" {
            assert!(
                opened.is_none(),
                "{name} #{id}: invalid vector was accepted"
            );
        } else {
            assert_eq!(opened.as_deref(), Some(&msg[..]), "{name} #{id}: decrypt");
            assert_eq!(
                aead(&iv, &aad, &msg, true).unwrap(),
                sealed_expected,
                "{name} #{id}: encrypt"
            );
        }
        checked += 1;
    }
    assert!(checked > 50, "{name}: only {checked} vectors applied");
    eprintln!("{name}: {checked} vectors");
}

#[test]
fn aes_256_gcm() {
    aead_suite("aes_gcm_test", |k| {
        let c = Aes256Gcm::new(k).unwrap();
        Box::new(move |n, a, d, seal| {
            if seal {
                Some(c.seal(n, a, d))
            } else {
                c.open(n, a, d).ok()
            }
        })
    });
}

#[test]
fn chacha20_poly1305() {
    aead_suite("chacha20_poly1305_test", |k| {
        let c = ChaCha20Poly1305::new(k).unwrap();
        Box::new(move |n, a, d, seal| {
            if seal {
                Some(c.seal(n, a, d))
            } else {
                c.open(n, a, d).ok()
            }
        })
    });
}

#[test]
fn x25519_ecdh() {
    let doc = load("x25519_test");
    let mut n = 0;
    for (_, t) in tests(&doc) {
        let (public, private) = (h(&t["public"]), h(&t["private"]));
        if public.len() != 32 || private.len() != 32 {
            assert_eq!(result(t), "invalid");
            continue;
        }
        let shared = x25519(&private.try_into().unwrap(), &public.try_into().unwrap());
        if result(t) != "invalid" {
            // "acceptable" covers low-order / non-canonical points: RFC 7748 still
            // defines the output, and Wycheproof gives it.
            assert_eq!(shared.to_vec(), h(&t["shared"]), "x25519 #{}", t["tcId"]);
        }
        n += 1;
    }
    eprintln!("x25519: {n} vectors");
}

#[test]
fn ed25519_verify() {
    let doc = load("ed25519_test");
    let mut n = 0;
    for (g, t) in tests(&doc) {
        let pk: [u8; 32] = h(&g["publicKey"]["pk"]).try_into().unwrap();
        let sig = h(&t["sig"]);
        let ok = sig.len() == 64
            && VerifyingKey::from_bytes(pk).verify(
                &h(&t["msg"]),
                &Signature::from_bytes(sig.clone().try_into().unwrap()),
            );
        assert_eq!(
            ok,
            result(t) == "valid",
            "ed25519 #{} ({})",
            t["tcId"],
            t["comment"]
        );
        n += 1;
    }
    eprintln!("ed25519: {n} vectors");
}

#[test]
fn hkdf_sha256() {
    let doc = load("hkdf_sha256_test");
    let mut n = 0;
    for (_, t) in tests(&doc) {
        let size = t["size"].as_u64().unwrap() as usize;
        let out = Hkdf::<Sha256>::derive(&h(&t["salt"]), &h(&t["ikm"]), &h(&t["info"]), size);
        if result(t) == "invalid" {
            assert!(out.is_err(), "hkdf #{} should fail", t["tcId"]);
        } else {
            assert_eq!(out.unwrap(), h(&t["okm"]), "hkdf #{}", t["tcId"]);
        }
        n += 1;
    }
    eprintln!("hkdf: {n} vectors");
}

fn hmac_suite(name: &str, mac: fn(&[u8], &[u8]) -> Vec<u8>) {
    let doc = load(name);
    let mut n = 0;
    for (g, t) in tests(&doc) {
        let bytes = g["tagSize"].as_u64().unwrap() as usize / 8;
        let full = mac(&h(&t["key"]), &h(&t["msg"]));
        let matches = full[..bytes] == h(&t["tag"])[..];
        assert_eq!(matches, result(t) == "valid", "{name} #{}", t["tcId"]);
        n += 1;
    }
    eprintln!("{name}: {n} vectors");
}

#[test]
fn hmac_sha256() {
    hmac_suite("hmac_sha256_test", Hmac::<Sha256>::mac);
}

#[test]
fn hmac_sha512() {
    hmac_suite("hmac_sha512_test", Hmac::<Sha512>::mac);
}
