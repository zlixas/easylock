//! seal → open round-trips, and any single-bit change is rejected.
#![no_main]
use easylock_core::aead::{Aead, Aes256Gcm, ChaCha20Poly1305};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (Vec<u8>, Vec<u8>, u16)| {
    let (msg, aad, flip) = input;
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let ciphers: [&dyn Fn(&[u8], bool) -> Option<Vec<u8>>; 2] = [
        &|d, seal| {
            let c = Aes256Gcm::new(&key).unwrap();
            if seal { Some(c.seal(&nonce, &aad, d)) } else { c.open(&nonce, &aad, d).ok() }
        },
        &|d, seal| {
            let c = ChaCha20Poly1305::new(&key).unwrap();
            if seal { Some(c.seal(&nonce, &aad, d)) } else { c.open(&nonce, &aad, d).ok() }
        },
    ];
    for c in ciphers {
        let sealed = c(&msg, true).unwrap();
        assert_eq!(c(&sealed, false).unwrap(), msg);
        let mut bad = sealed.clone();
        let bit = usize::from(flip) % (bad.len() * 8);
        bad[bit / 8] ^= 1 << (bit % 8);
        assert!(c(&bad, false).is_none(), "bit flip accepted");
    }
});
