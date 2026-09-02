//! aarch64 ARMv8 AES-extension backend. Reachable only after
//! `is_aarch64_feature_detected!("aes")`.

#![cfg(target_arch = "aarch64")]

use core::arch::aarch64::{vaeseq_u8, vaesmcq_u8, veorq_u8, vld1q_u8, vst1q_u8};

/// Encrypt one block using the ARMv8 AES instructions.
///
/// `vaeseq_u8(state, key)` computes `AddRoundKey` then `SubBytes` + `ShiftRows`;
/// `vaesmcq_u8` computes `MixColumns`. So a full round is
/// `MixColumns(SubBytes(ShiftRows(state ^ rk)))`, which means we feed round key
/// `i` into the AES instruction of round `i` and finish with a bare
/// `state ^ rk[14]`.
///
/// # Safety
/// The CPU must support the `aes` target feature.
#[target_feature(enable = "aes")]
pub unsafe fn encrypt_block(round_keys: &[[u8; 16]; 15], block: &mut [u8; 16]) {
    // SAFETY: all pointers reference 16-byte buffers; NEON loads/stores are
    // unaligned-safe.
    unsafe {
        let mut state = vld1q_u8(block.as_ptr());

        // Rounds 0..=12: AES round instruction consumes round key r.
        for rk in &round_keys[..13] {
            let k = vld1q_u8(rk.as_ptr());
            state = vaesmcq_u8(vaeseq_u8(state, k));
        }
        // Round 13: AES-E with rk[13], no MixColumns.
        let k13 = vld1q_u8(round_keys[13].as_ptr());
        state = vaeseq_u8(state, k13);
        // Final AddRoundKey with rk[14].
        let k14 = vld1q_u8(round_keys[14].as_ptr());
        state = veorq_u8(state, k14);

        vst1q_u8(block.as_mut_ptr(), state);
    }
}
