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
