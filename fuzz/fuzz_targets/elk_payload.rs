//! The chunk-stream decryptor must reject (never panic on, never accept) garbage.
#![no_main]
use easylock_core::container::stream::Decryptor;
use easylock_core::container::Cipher;
use libfuzzer_sys::fuzz_target;
use std::io::Read;

fuzz_target!(|data: &[u8]| {
    let cipher = if data.first().copied().unwrap_or(0) & 1 == 0 { Cipher::Aes256Gcm } else { Cipher::ChaCha20Poly1305 };
    let mut d = Decryptor::with_key(data, cipher, &[7u8; 32], [0u8; 12]).unwrap();
    let mut out = Vec::new();
    // Random bytes can't carry a valid tag under this key, so any Ok result must be empty-input-free garbage-free.
    if d.read_to_end(&mut out).is_ok() {
        panic!("forged ciphertext accepted ({} bytes)", data.len());
    }
});
