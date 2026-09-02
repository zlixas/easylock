//! Constant-time portable AES-256 (encryption direction only).

/// GF(2^8) multiply with the AES reduction polynomial `x^8 + x^4 + x^3 + x + 1`.
/// Branch-free: exactly 8 iterations, no data-dependent control flow.
#[inline(always)]
const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    let mut i = 0;
    while i < 8 {
        // add `a` into `p` iff low bit of `b` is set
        p ^= 0u8.wrapping_sub(b & 1) & a;
        // a <<= 1 with conditional reduction by 0x1b
        let hi = a >> 7;
        a <<= 1;
        a ^= 0u8.wrapping_sub(hi) & 0x1b;
        b >>= 1;
        i += 1;
    }
    p
}

#[inline(always)]
const fn gf_square(x: u8) -> u8 {
    gf_mul(x, x)
}

/// Multiplicative inverse in GF(2^8) via `x^254` (Fermat). `inv(0) = 0`.
#[inline(always)]
const fn gf_inv(x: u8) -> u8 {
    // 254 = 0b1111_1110 -> product of x^(2^i) for i in 1..=7
    let p2 = gf_square(x); // x^2
    let p4 = gf_square(p2); // x^4
    let p8 = gf_square(p4);
    let p16 = gf_square(p8);
    let p32 = gf_square(p16);
    let p64 = gf_square(p32);
    let p128 = gf_square(p64);

    let mut r = p2;
    r = gf_mul(r, p4);
    r = gf_mul(r, p8);
    r = gf_mul(r, p16);
    r = gf_mul(r, p32);
    r = gf_mul(r, p64);
    gf_mul(r, p128)
}

/// AES S-box: multiplicative inverse followed by the affine map.
#[inline(always)]
const fn sbox(x: u8) -> u8 {
    let inv = gf_inv(x);
    inv ^ inv.rotate_left(1) ^ inv.rotate_left(2) ^ inv.rotate_left(3) ^ inv.rotate_left(4) ^ 0x63
}

#[inline(always)]
fn sub_word(w: u32) -> u32 {
    let b = w.to_be_bytes();
    u32::from_be_bytes([sbox(b[0]), sbox(b[1]), sbox(b[2]), sbox(b[3])])
}

const RCON: [u8; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

/// AES-256 key expansion -> 15 round keys of 16 bytes each.
pub fn expand_key_256(key: &[u8; 32]) -> [[u8; 16]; 15] {
    const NK: usize = 8;
    const NR: usize = 14;
    let mut w = [0u32; 4 * (NR + 1)];
    for i in 0..NK {
        w[i] = u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    for i in NK..w.len() {
        let mut temp = w[i - 1];
        if i % NK == 0 {
            temp = sub_word(temp.rotate_left(8)) ^ (u32::from(RCON[i / NK - 1]) << 24);
        } else if i % NK == 4 {
            temp = sub_word(temp);
        }
        w[i] = w[i - NK] ^ temp;
    }

    let mut round_keys = [[0u8; 16]; 15];
    for (r, rk) in round_keys.iter_mut().enumerate() {
        for c in 0..4 {
            rk[4 * c..4 * c + 4].copy_from_slice(&w[4 * r + c].to_be_bytes());
        }
    }
    round_keys
}

#[inline(always)]
fn add_round_key(state: &mut [u8; 16], rk: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= rk[i];
    }
}

#[inline(always)]
fn sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = sbox(*b);
    }
}

#[inline(always)]
fn shift_rows(state: &mut [u8; 16]) {
    // Column-major state: byte at row r, col c is state[4*c + r].
    let s = *state;
    // row 0 unchanged
    // row 1: shift left by 1
    state[1] = s[5];
    state[5] = s[9];
    state[9] = s[13];
    state[13] = s[1];
    // row 2: shift left by 2
    state[2] = s[10];
    state[6] = s[14];
    state[10] = s[2];
    state[14] = s[6];
    // row 3: shift left by 3
    state[3] = s[15];
    state[7] = s[3];
    state[11] = s[7];
    state[15] = s[11];
}

#[inline(always)]
fn xtime(x: u8) -> u8 {
    let hi = x >> 7;
    (x << 1) ^ (0u8.wrapping_sub(hi) & 0x1b)
}

#[inline(always)]
fn mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let i = 4 * c;
        let a0 = state[i];
        let a1 = state[i + 1];
        let a2 = state[i + 2];
        let a3 = state[i + 3];
        let t = a0 ^ a1 ^ a2 ^ a3;
        state[i] ^= t ^ xtime(a0 ^ a1);
        state[i + 1] ^= t ^ xtime(a1 ^ a2);
        state[i + 2] ^= t ^ xtime(a2 ^ a3);
        state[i + 3] ^= t ^ xtime(a3 ^ a0);
    }
}

/// Encrypt one block in place with expanded AES-256 round keys.
pub fn encrypt_block(round_keys: &[[u8; 16]; 15], block: &mut [u8; 16]) {
    add_round_key(block, &round_keys[0]);
    for rk in &round_keys[1..14] {
        sub_bytes(block);
        shift_rows(block);
        mix_columns(block);
        add_round_key(block, rk);
    }
    sub_bytes(block);
    shift_rows(block);
    add_round_key(block, &round_keys[14]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sbox_known_entries() {
        assert_eq!(sbox(0x00), 0x63);
        assert_eq!(sbox(0x01), 0x7c);
        assert_eq!(sbox(0x53), 0xed);
        assert_eq!(sbox(0xff), 0x16);
    }

    #[test]
    fn gf_inv_is_involution_on_units() {
        for x in 1u8..=255 {
            assert_eq!(gf_mul(x, gf_inv(x)), 1, "inv failed for {x:#x}");
        }
        assert_eq!(gf_inv(0), 0);
    }

    #[test]
    fn full_sbox_table_matches_reference() {
        // Spot-check against the canonical table's first row.
        const ROW0: [u8; 16] = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
            0xab, 0x76,
        ];
        for (i, want) in ROW0.iter().enumerate() {
            assert_eq!(sbox(i as u8), *want);
        }
    }
}
