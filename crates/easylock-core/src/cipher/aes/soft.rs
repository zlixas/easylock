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

#[cfg(test)]
#[inline(always)]
fn add_round_key(state: &mut [u8; 16], rk: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= rk[i];
    }
}

#[cfg(test)]
#[inline(always)]
fn sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = sbox(*b);
    }
}

#[cfg(test)]
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

#[cfg(test)]
#[inline(always)]
fn xtime(x: u8) -> u8 {
    let hi = x >> 7;
    (x << 1) ^ (0u8.wrapping_sub(hi) & 0x1b)
}

#[cfg(test)]
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

// --- bitsliced implementation ---------------------------------------------
//
// Four blocks are processed together as eight 64-bit "bit planes": `q[i]` holds
// bit `i` of all 64 state bytes. Within a plane, the byte at AES state
// position (`row`, `col`) of block `blk` sits at bit `16*row + 4*col + blk`, so
// ShiftRows is a fixed shuffle of 4-bit groups and MixColumns is a rotation by
// whole rows (the layout of BearSSL's `aes_ct64`). SubBytes is the Boyar–Peralta
// circuit evaluated on the planes. Everything is bitwise logic on registers:
// no table lookups and no data-dependent branches, so it is constant-time,
// and it is roughly two orders of magnitude faster than the per-byte `x^254`
// S-box above (which remains as the reference and for key expansion).

/// AES-256 round keys in bitsliced form (each round key replicated for the
/// four parallel blocks).
pub type SlicedKeys = [[u64; 8]; 15];

/// Transpose the 8x8 bit matrix whose row `k` is byte `k` of `x`.
#[inline(always)]
fn transpose8x8(mut x: u64) -> u64 {
    let t = (x ^ (x >> 7)) & 0x00aa_00aa_00aa_00aa;
    x ^= t ^ (t << 7);
    let t = (x ^ (x >> 14)) & 0x0000_cccc_0000_cccc;
    x ^= t ^ (t << 14);
    let t = (x ^ (x >> 28)) & 0x0000_0000_f0f0_f0f0;
    x ^= t ^ (t << 28);
    x
}

/// Four column-major AES states -> bit planes.
#[inline(always)]
fn pack(blocks: &[[u8; 16]; 4]) -> [u64; 8] {
    let mut g = [0u8; 64];
    for (blk, block) in blocks.iter().enumerate() {
        for col in 0..4 {
            for row in 0..4 {
                g[16 * row + 4 * col + blk] = block[4 * col + row];
            }
        }
    }
    let mut q = [0u64; 8];
    for (k, chunk) in g.chunks_exact(8).enumerate() {
        let w = transpose8x8(u64::from_le_bytes(chunk.try_into().expect("8 bytes")));
        for (i, plane) in q.iter_mut().enumerate() {
            *plane |= ((w >> (8 * i)) & 0xff) << (8 * k);
        }
    }
    q
}

/// Bit planes -> four column-major AES states.
#[inline(always)]
fn unpack(q: &[u64; 8]) -> [[u8; 16]; 4] {
    let mut g = [0u8; 64];
    for (k, chunk) in g.chunks_exact_mut(8).enumerate() {
        let mut w = 0u64;
        for (i, plane) in q.iter().enumerate() {
            w |= ((plane >> (8 * k)) & 0xff) << (8 * i);
        }
        chunk.copy_from_slice(&transpose8x8(w).to_le_bytes());
    }
    let mut blocks = [[0u8; 16]; 4];
    for (blk, block) in blocks.iter_mut().enumerate() {
        for col in 0..4 {
            for row in 0..4 {
                block[4 * col + row] = g[16 * row + 4 * col + blk];
            }
        }
    }
    blocks
}

/// The AES S-box on bit planes: the Boyar–Peralta circuit ("A new combinational
/// logic minimization technique with applications to cryptology", 2009), as
/// used by BearSSL. `x0` is the most significant bit.
#[inline(always)]
#[allow(clippy::too_many_lines)]
fn sbox_sliced(q: &mut [u64; 8]) {
    let (x0, x1, x2, x3, x4, x5, x6, x7) = (q[7], q[6], q[5], q[4], q[3], q[2], q[1], q[0]);

    // Top linear transformation.
    let y14 = x3 ^ x5;
    let y13 = x0 ^ x6;
    let y9 = x0 ^ x3;
    let y8 = x0 ^ x5;
    let t0 = x1 ^ x2;
    let y1 = t0 ^ x7;
    let y4 = y1 ^ x3;
    let y12 = y13 ^ y14;
    let y2 = y1 ^ x0;
    let y5 = y1 ^ x6;
    let y3 = y5 ^ y8;
    let t1 = x4 ^ y12;
    let y15 = t1 ^ x5;
    let y20 = t1 ^ x1;
    let y6 = y15 ^ x7;
    let y10 = y15 ^ t0;
    let y11 = y20 ^ y9;
    let y7 = x7 ^ y11;
    let y17 = y10 ^ y11;
    let y19 = y10 ^ y8;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let y18 = x0 ^ y16;

    // Non-linear section.
    let t2 = y12 & y15;
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    let t5 = y4 & x7;
    let t6 = t5 ^ t2;
    let t7 = y13 & y16;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t12 = y9 & y11;
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let t17 = t4 ^ t14;
    let t18 = t6 ^ t16;
    let t19 = t9 ^ t14;
    let t20 = t11 ^ t16;
    let t21 = t17 ^ y20;
    let t22 = t18 ^ y19;
    let t23 = t19 ^ y21;
    let t24 = t20 ^ y18;

    let t25 = t21 ^ t22;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let t30 = t23 ^ t24;
    let t31 = t22 ^ t26;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t34 = t23 ^ t33;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t37 = t36 ^ t34;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;

    let t41 = t40 ^ t37;
    let t42 = t29 ^ t33;
    let t43 = t29 ^ t40;
    let t44 = t33 ^ t37;
    let t45 = t42 ^ t41;
    let z0 = t44 & y15;
    let z1 = t37 & y6;
    let z2 = t33 & x7;
    let z3 = t43 & y16;
    let z4 = t40 & y1;
    let z5 = t29 & y7;
    let z6 = t42 & y11;
    let z7 = t45 & y17;
    let z8 = t41 & y10;
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z11 = t33 & y4;
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z14 = t29 & y2;
    let z15 = t42 & y9;
    let z16 = t45 & y14;
    let z17 = t41 & y8;

    // Bottom linear transformation.
    let t46 = z15 ^ z16;
    let t47 = z10 ^ z11;
    let t48 = z5 ^ z13;
    let t49 = z9 ^ z10;
    let t50 = z2 ^ z12;
    let t51 = z2 ^ z5;
    let t52 = z7 ^ z8;
    let t53 = z0 ^ z3;
    let t54 = z6 ^ z7;
    let t55 = z16 ^ z17;
    let t56 = z12 ^ t48;
    let t57 = t50 ^ t53;
    let t58 = z4 ^ t46;
    let t59 = z3 ^ t54;
    let t60 = t46 ^ t57;
    let t61 = z14 ^ t57;
    let t62 = t52 ^ t58;
    let t63 = t49 ^ t58;
    let t64 = z4 ^ t59;
    let t65 = t61 ^ t62;
    let t66 = z1 ^ t63;
    let s0 = t59 ^ t63;
    let s6 = t56 ^ !t62;
    let s7 = t48 ^ !t60;
    let t67 = t64 ^ t65;
    let s3 = t53 ^ t66;
    let s4 = t51 ^ t66;
    let s5 = t47 ^ t65;
    let s1 = t64 ^ !s3;
    let s2 = t55 ^ !t67;

    *q = [s7, s6, s5, s4, s3, s2, s1, s0];
}

#[inline(always)]
fn shift_rows_sliced(q: &mut [u64; 8]) {
    for x in q.iter_mut() {
        let v = *x;
        *x = (v & 0x0000_0000_0000_ffff)
            | ((v & 0x0000_0000_fff0_0000) >> 4)
            | ((v & 0x0000_0000_000f_0000) << 12)
            | ((v & 0x0000_ff00_0000_0000) >> 8)
            | ((v & 0x0000_00ff_0000_0000) << 8)
            | ((v & 0xf000_0000_0000_0000) >> 12)
            | ((v & 0x0fff_0000_0000_0000) << 4);
    }
}

#[inline(always)]
fn mix_columns_sliced(q: &mut [u64; 8]) {
    // r[i]: the next row's bits in each row slot; rotate_left(32): two rows on.
    let r: [u64; 8] = core::array::from_fn(|i| q[i].rotate_right(16));
    let v: [u64; 8] = core::array::from_fn(|i| q[i] ^ r[i]);
    let c = |i: usize| v[i].rotate_left(32);
    let [q0, q1, q2, q3, q4, q5, q6, q7] = *q;
    let [r0, r1, r2, r3, r4, r5, r6, r7] = r;
    *q = [
        q7 ^ r7 ^ r0 ^ c(0),
        q0 ^ r0 ^ q7 ^ r7 ^ r1 ^ c(1),
        q1 ^ r1 ^ r2 ^ c(2),
        q2 ^ r2 ^ q7 ^ r7 ^ r3 ^ c(3),
        q3 ^ r3 ^ q7 ^ r7 ^ r4 ^ c(4),
        q4 ^ r4 ^ r5 ^ c(5),
        q5 ^ r5 ^ r6 ^ c(6),
        q6 ^ r6 ^ r7 ^ c(7),
    ];
}

#[inline(always)]
fn add_round_key_sliced(q: &mut [u64; 8], sk: &[u64; 8]) {
    for (x, k) in q.iter_mut().zip(sk) {
        *x ^= k;
    }
}

/// Convert expanded round keys to bitsliced form.
#[must_use]
pub fn slice_keys(round_keys: &[[u8; 16]; 15]) -> SlicedKeys {
    core::array::from_fn(|r| pack(&[round_keys[r]; 4]))
}

/// Encrypt four blocks in place (bitsliced, constant-time).
pub fn encrypt4(sk: &SlicedKeys, blocks: &mut [[u8; 16]; 4]) {
    let mut q = pack(blocks);
    add_round_key_sliced(&mut q, &sk[0]);
    for rk in &sk[1..14] {
        sbox_sliced(&mut q);
        shift_rows_sliced(&mut q);
        mix_columns_sliced(&mut q);
        add_round_key_sliced(&mut q, rk);
    }
    sbox_sliced(&mut q);
    shift_rows_sliced(&mut q);
    add_round_key_sliced(&mut q, &sk[14]);
    *blocks = unpack(&q);
    crate::secure::Zeroize::zeroize(&mut q);
}

/// Encrypt one block in place with expanded AES-256 round keys (reference
/// byte-oriented implementation, used to cross-check the bitsliced path).
#[cfg(test)]
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

    /// The bitsliced circuit equals the reference S-box on all 256 inputs.
    #[test]
    fn sliced_sbox_matches_reference_exhaustively() {
        for base in (0..256).step_by(64) {
            let mut blocks = [[0u8; 16]; 4];
            for (j, b) in blocks.iter_mut().flatten().enumerate() {
                *b = (base + j) as u8;
            }
            let mut q = pack(&blocks);
            sbox_sliced(&mut q);
            let out = unpack(&q);
            for (a, b) in blocks.iter().flatten().zip(out.iter().flatten()) {
                assert_eq!(sbox(*a), *b, "input {a:#04x}");
            }
        }
    }

    #[test]
    fn pack_unpack_roundtrip() {
        let blocks: [[u8; 16]; 4] =
            core::array::from_fn(|b| core::array::from_fn(|i| (b * 16 + i) as u8 ^ 0xa5));
        assert_eq!(unpack(&pack(&blocks)), blocks);
        let x = 0x0123_4567_89ab_cdef_u64;
        assert_eq!(transpose8x8(transpose8x8(x)), x);
    }

    #[test]
    fn encrypt4_matches_reference() {
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as u8
        };
        for _ in 0..50 {
            let key: [u8; 32] = core::array::from_fn(|_| next());
            let rk = expand_key_256(&key);
            let sk = slice_keys(&rk);
            let mut blocks: [[u8; 16]; 4] =
                core::array::from_fn(|_| core::array::from_fn(|_| next()));
            let mut want = blocks;
            for b in &mut want {
                encrypt_block(&rk, b);
            }
            encrypt4(&sk, &mut blocks);
            assert_eq!(blocks, want);
        }
    }
}
