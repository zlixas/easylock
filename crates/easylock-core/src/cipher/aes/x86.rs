//! x86-64 AES-NI backend. Reachable only after `is_x86_feature_detected!("aes")`.

#![cfg(target_arch = "x86_64")]

use core::arch::x86_64::{
    __m128i, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_loadu_si128, _mm_storeu_si128,
    _mm_xor_si128,
};

/// Encrypt one block using AES-NI.
///
/// # Safety
/// The CPU must support the `aes` target feature. Callers ensure this via
/// [`crate::cpu::features`] before dispatching here.
// `loadu`/`storeu` are the explicitly-unaligned SSE2 load/store intrinsics, so
// the "more-strictly-aligned pointer" cast lint is a false positive here.
#[allow(clippy::cast_ptr_alignment)]
#[target_feature(enable = "aes")]
pub unsafe fn encrypt_block(round_keys: &[[u8; 16]; 15], block: &mut [u8; 16]) {
    // SAFETY: pointers are 16-byte buffers; `loadu`/`storeu` are unaligned.
    unsafe {
        let load = |rk: &[u8; 16]| _mm_loadu_si128(rk.as_ptr().cast::<__m128i>());
        let mut state = _mm_loadu_si128(block.as_ptr().cast::<__m128i>());

        state = _mm_xor_si128(state, load(&round_keys[0]));
        for rk in &round_keys[1..14] {
            state = _mm_aesenc_si128(state, load(rk));
        }
        state = _mm_aesenclast_si128(state, load(&round_keys[14]));

        _mm_storeu_si128(block.as_mut_ptr().cast::<__m128i>(), state);
    }
}

/// Encrypt 8 independent blocks with the rounds interleaved (fills the AES-NI
/// pipeline).
///
/// # Safety
/// The CPU must support the `aes` target feature.
#[allow(clippy::cast_ptr_alignment)] // unaligned loadu/storeu only
#[target_feature(enable = "aes")]
pub unsafe fn encrypt_blocks8(round_keys: &[[u8; 16]; 15], blocks: &mut [[u8; 16]; 8]) {
    // SAFETY: every pointer references a 16-byte array; loadu/storeu are unaligned.
    unsafe {
        let load = |b: &[u8; 16]| _mm_loadu_si128(b.as_ptr().cast::<__m128i>());
        let mut rk = [load(&round_keys[0]); 15];
        for (i, k) in rk.iter_mut().enumerate() {
            *k = load(&round_keys[i]);
        }
        let mut s = [load(&blocks[0]); 8];
        for (i, st) in s.iter_mut().enumerate() {
            *st = _mm_xor_si128(load(&blocks[i]), rk[0]);
        }
        for k in &rk[1..14] {
            for st in &mut s {
                *st = _mm_aesenc_si128(*st, *k);
            }
        }
        for (i, st) in s.iter().enumerate() {
            _mm_storeu_si128(
                blocks[i].as_mut_ptr().cast::<__m128i>(),
                _mm_aesenclast_si128(*st, rk[14]),
            );
        }
    }
}
