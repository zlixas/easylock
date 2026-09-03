//! Argon2 (RFC 9106) — memory-hard password hashing, version 0x13.
//!
//! Port of the reference `phc-winner-argon2` construction over this crate's
//! BLAKE2b. Supports Argon2d / Argon2i / Argon2id; [`hash`] defaults to Argon2id
//! as recommended by the RFC. Single-threaded (lanes are filled sequentially);
//! the output is identical to a parallel implementation.

use crate::hash::blake2b;
use crate::secure::{zeroize_u64s, Zeroize};
use crate::{Error, Result};
use alloc::vec;
use alloc::vec::Vec;

const VERSION: u32 = 0x13;
const BLOCK_WORDS: usize = 128; // 1024 bytes
const SYNC_POINTS: u32 = 4;
const ADDRESSES_PER_BLOCK: usize = 128;

/// Argon2 variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// Data-dependent (fastest, side-channel sensitive).
    D,
    /// Data-independent (side-channel resistant).
    I,
    /// Hybrid — data-independent first half of the first pass, then
    /// data-dependent. **The recommended default.**
    Id,
}

impl Variant {
    fn type_id(self) -> u32 {
        match self {
            Variant::D => 0,
            Variant::I => 1,
            Variant::Id => 2,
        }
    }
}

/// Cost parameters.
#[derive(Debug, Clone, Copy)]
pub struct Params {
    /// Memory size in KiB (`m`). Must be >= `8 * parallelism`.
    pub m_cost: u32,
    /// Number of passes (`t`). Must be >= 1.
    pub t_cost: u32,
    /// Degree of parallelism / lanes (`p`). Must be 1..=2^24.
    pub parallelism: u32,
    /// Output tag length in bytes. Must be >= 4.
    pub out_len: usize,
}

impl Params {
    /// RFC 9106 "first recommended" option: 2 GiB is impractical for a library
    /// default, so this is the "second recommended" option (64 MiB, t=3, p=4).
    pub const RECOMMENDED: Params = Params {
        m_cost: 64 * 1024,
        t_cost: 3,
        parallelism: 4,
        out_len: 32,
    };

    fn validate(&self, salt_len: usize) -> Result<()> {
        if self.parallelism == 0 || self.parallelism > 0x00ff_ffff {
            return Err(Error::InvalidParameter {
                what: "argon2 parallelism",
            });
        }
        if self.t_cost == 0 {
            return Err(Error::InvalidParameter {
                what: "argon2 t_cost",
            });
        }
        if self.m_cost < 8 * self.parallelism {
            return Err(Error::InvalidParameter {
                what: "argon2 m_cost (need >= 8*p)",
            });
        }
        if self.out_len < 4 {
            return Err(Error::InvalidParameter {
                what: "argon2 out_len",
            });
        }
        if salt_len < 8 {
            return Err(Error::InvalidParameter {
                what: "argon2 salt (need >= 8 bytes)",
            });
        }
        Ok(())
    }
}

/// Argon2id with default context (no secret / associated data).
pub fn hash(password: &[u8], salt: &[u8], params: Params) -> Result<Vec<u8>> {
    derive(Variant::Id, password, salt, &[], &[], params)
}

/// Full Argon2 with an optional secret key `k` and associated data `x`.
pub fn derive(
    variant: Variant,
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    ad: &[u8],
    params: Params,
) -> Result<Vec<u8>> {
    params.validate(salt.len())?;

    let lanes = params.parallelism;
    let m_prime = 4 * lanes * (params.m_cost / (4 * lanes));
    let lane_length = m_prime / lanes;
    let segment_length = lane_length / SYNC_POINTS;

    // H_0
    let mut h0_input: Vec<u8> = Vec::new();
    for v in [
        lanes,
        params.out_len as u32,
        params.m_cost,
        params.t_cost,
        VERSION,
        variant.type_id(),
    ] {
        h0_input.extend_from_slice(&v.to_le_bytes());
    }
    for part in [password, salt, secret, ad] {
        h0_input.extend_from_slice(&(part.len() as u32).to_le_bytes());
        h0_input.extend_from_slice(part);
    }
    let mut h0 = [0u8; 64];
    let d = blake2b::hash(64, &[], &h0_input);
    h0.copy_from_slice(&d);
    h0_input.zeroize();

    // Memory matrix, laid out lane-major: block (lane, col) at index
    // `lane * lane_length + col`.
    let mut memory: Vec<[u64; BLOCK_WORDS]> = vec![[0u64; BLOCK_WORDS]; m_prime as usize];

    // First two blocks of every lane.
    let mut seed = [0u8; 72];
    seed[..64].copy_from_slice(&h0);
    for lane in 0..lanes {
        seed[68..72].copy_from_slice(&lane.to_le_bytes());
        for col in 0u32..2 {
            seed[64..68].copy_from_slice(&col.to_le_bytes());
            let block_bytes = h_prime(1024, &seed);
            let dst = &mut memory[(lane * lane_length + col) as usize];
            load_block(dst, &block_bytes);
        }
    }
    h0.zeroize();
    seed.zeroize();

    // Passes.
    for pass in 0..params.t_cost {
        for slice in 0..SYNC_POINTS {
            for lane in 0..lanes {
                fill_segment(
                    &mut memory,
                    variant,
                    pass,
                    slice,
                    lane,
                    lanes,
                    lane_length,
                    segment_length,
                    m_prime,
                    params.t_cost,
                );
            }
        }
    }

    // XOR the final column of every lane, then H'.
    let mut final_block = [0u64; BLOCK_WORDS];
    for lane in 0..lanes {
        let last = &memory[(lane * lane_length + (lane_length - 1)) as usize];
        for i in 0..BLOCK_WORDS {
            final_block[i] ^= last[i];
        }
    }
    let mut final_bytes = [0u8; 1024];
    store_block(&mut final_bytes, &final_block);

    let tag = h_prime(params.out_len, &final_bytes);

    // Scrub everything sensitive.
    for block in &mut memory {
        zeroize_u64s(block);
    }
    final_block.zeroize();
    final_bytes.zeroize();

    Ok(tag)
}

// `curr_offset` / `prev_offset` track memory positions with lane-length
// wraparound that a plain counted loop cannot express.
#[allow(clippy::too_many_arguments, clippy::explicit_counter_loop)]
fn fill_segment(
    memory: &mut [[u64; BLOCK_WORDS]],
    variant: Variant,
    pass: u32,
    slice: u32,
    lane: u32,
    lanes: u32,
    lane_length: u32,
    segment_length: u32,
    m_prime: u32,
    passes: u32,
) {
    let data_independent = matches!(variant, Variant::I)
        || (matches!(variant, Variant::Id) && pass == 0 && slice < SYNC_POINTS / 2);

    let mut input_block = [0u64; BLOCK_WORDS];
    let mut address_block = [0u64; BLOCK_WORDS];
    if data_independent {
        input_block[0] = u64::from(pass);
        input_block[1] = u64::from(lane);
        input_block[2] = u64::from(slice);
        input_block[3] = u64::from(m_prime);
        input_block[4] = u64::from(passes);
        input_block[5] = variant.type_id().into();
    }

    let starting_index: u32 = if pass == 0 && slice == 0 { 2 } else { 0 };
    if pass == 0 && slice == 0 && data_independent {
        next_addresses(&mut address_block, &mut input_block);
    }

    let mut curr_offset = lane * lane_length + slice * segment_length + starting_index;
    let mut prev_offset = if curr_offset % lane_length == 0 {
        curr_offset + lane_length - 1
    } else {
        curr_offset - 1
    };

    for i in starting_index..segment_length {
        if curr_offset % lane_length == 1 {
            prev_offset = curr_offset - 1;
        }

        let pseudo_rand = if data_independent {
            if (i as usize) % ADDRESSES_PER_BLOCK == 0 {
                next_addresses(&mut address_block, &mut input_block);
            }
            address_block[(i as usize) % ADDRESSES_PER_BLOCK]
        } else {
            memory[prev_offset as usize][0]
        };

        let mut ref_lane = (pseudo_rand >> 32) % u64::from(lanes);
        if pass == 0 && slice == 0 {
            ref_lane = u64::from(lane);
        }

        let ref_index = index_alpha(
            pass,
            slice,
            i,
            segment_length,
            lane_length,
            (pseudo_rand & 0xffff_ffff) as u32,
            ref_lane == u64::from(lane),
        );

        let ref_block_idx = (ref_lane as u32 * lane_length + ref_index) as usize;
        let with_xor = pass != 0;

        // fill_block(prev, ref, curr): need three disjoint borrows.
        let prev = memory[prev_offset as usize];
        let refb = memory[ref_block_idx];
        let curr = &mut memory[curr_offset as usize];
        fill_block(&prev, &refb, curr, with_xor);

        curr_offset += 1;
        prev_offset += 1;
    }
}

fn next_addresses(address_block: &mut [u64; BLOCK_WORDS], input_block: &mut [u64; BLOCK_WORDS]) {
    input_block[6] += 1;
    let zero = [0u64; BLOCK_WORDS];
    let mut tmp = *address_block;
    fill_block(&zero, input_block, &mut tmp, false);
    let first = tmp;
    fill_block(&zero, &first, &mut tmp, false);
    *address_block = tmp;
}

#[allow(clippy::too_many_arguments)]
fn index_alpha(
    pass: u32,
    slice: u32,
    index: u32,
    segment_length: u32,
    lane_length: u32,
    pseudo_rand: u32,
    same_lane: bool,
) -> u32 {
    // Unsigned wraparound matches the reference C (`(uint32_t)(-1)` for the
    // `index == 0` corner).
    let minus_one_if_zero = if index == 0 { u32::MAX } else { 0 };
    let reference_area_size: u32 = if pass == 0 {
        if slice == 0 {
            index - 1
        } else if same_lane {
            slice * segment_length + index - 1
        } else {
            (slice * segment_length).wrapping_add(minus_one_if_zero)
        }
    } else if same_lane {
        lane_length - segment_length + index - 1
    } else {
        (lane_length - segment_length).wrapping_add(minus_one_if_zero)
    };

    let mut relative_position = u64::from(pseudo_rand);
    relative_position = (relative_position * relative_position) >> 32;
    relative_position = u64::from(reference_area_size.wrapping_sub(1))
        .wrapping_sub((u64::from(reference_area_size) * relative_position) >> 32);

    let start_position: u32 = if pass != 0 {
        if slice == SYNC_POINTS - 1 {
            0
        } else {
            (slice + 1) * segment_length
        }
    } else {
        0
    };

    ((u64::from(start_position) + relative_position) % u64::from(lane_length)) as u32
}

// --- the Argon2 compression function -----------------------------------------

#[inline(always)]
fn f_blamka(x: u64, y: u64) -> u64 {
    let m = (x & 0xffff_ffff).wrapping_mul(y & 0xffff_ffff);
    x.wrapping_add(y).wrapping_add(m.wrapping_mul(2))
}

#[inline(always)]
fn g(v: &mut [u64; BLOCK_WORDS], a: usize, b: usize, c: usize, d: usize) {
    v[a] = f_blamka(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = f_blamka(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = f_blamka(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = f_blamka(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// The BLAKE2 round with no message input, over 16 indices of `v`.
fn round_nomsg(v: &mut [u64; BLOCK_WORDS], p: [usize; 16]) {
    g(v, p[0], p[4], p[8], p[12]);
    g(v, p[1], p[5], p[9], p[13]);
    g(v, p[2], p[6], p[10], p[14]);
    g(v, p[3], p[7], p[11], p[15]);
    g(v, p[0], p[5], p[10], p[15]);
    g(v, p[1], p[6], p[11], p[12]);
    g(v, p[2], p[7], p[8], p[13]);
    g(v, p[3], p[4], p[9], p[14]);
}

fn fill_block(
    prev: &[u64; BLOCK_WORDS],
    refb: &[u64; BLOCK_WORDS],
    next: &mut [u64; BLOCK_WORDS],
    with_xor: bool,
) {
    let mut block_r = [0u64; BLOCK_WORDS];
    for i in 0..BLOCK_WORDS {
        block_r[i] = refb[i] ^ prev[i];
    }
    let mut block_tmp = block_r;
    if with_xor {
        for i in 0..BLOCK_WORDS {
            block_tmp[i] ^= next[i];
        }
    }

    // Blake2 over contiguous groups of 16 words.
    for i in 0..8 {
        let base = 16 * i;
        let idx = core::array::from_fn(|k| base + k);
        round_nomsg(&mut block_r, idx);
    }
    // Blake2 over the strided groups (columns).
    for i in 0..8 {
        let idx: [usize; 16] = [
            2 * i,
            2 * i + 1,
            2 * i + 16,
            2 * i + 17,
            2 * i + 32,
            2 * i + 33,
            2 * i + 48,
            2 * i + 49,
            2 * i + 64,
            2 * i + 65,
            2 * i + 80,
            2 * i + 81,
            2 * i + 96,
            2 * i + 97,
            2 * i + 112,
            2 * i + 113,
        ];
        round_nomsg(&mut block_r, idx);
    }

    for i in 0..BLOCK_WORDS {
        next[i] = block_tmp[i] ^ block_r[i];
    }
    block_r.zeroize();
    block_tmp.zeroize();
}

// --- helpers ---------------------------------------------------------------

fn load_block(dst: &mut [u64; BLOCK_WORDS], bytes: &[u8]) {
    for (word, chunk) in dst.iter_mut().zip(bytes.chunks_exact(8)) {
        *word = u64::from_le_bytes(chunk.try_into().unwrap());
    }
}

fn store_block(dst: &mut [u8; 1024], block: &[u64; BLOCK_WORDS]) {
    for (chunk, word) in dst.chunks_exact_mut(8).zip(block.iter()) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
}

/// Argon2's variable-length hash `H'` built on BLAKE2b-512.
fn h_prime(out_len: usize, input: &[u8]) -> Vec<u8> {
    let mut prefixed = Vec::with_capacity(4 + input.len());
    prefixed.extend_from_slice(&(out_len as u32).to_le_bytes());
    prefixed.extend_from_slice(input);

    if out_len <= 64 {
        let out = blake2b::hash(out_len, &[], &prefixed);
        prefixed.zeroize();
        return out;
    }

    let mut out = vec![0u8; out_len];
    let mut v = blake2b::hash(64, &[], &prefixed);
    prefixed.zeroize();
    out[..32].copy_from_slice(&v[..32]);

    let mut written = 32usize;
    let mut remaining = out_len - 32;
    while remaining > 64 {
        v = blake2b::hash(64, &[], &v);
        out[written..written + 32].copy_from_slice(&v[..32]);
        written += 32;
        remaining -= 32;
    }
    let last = blake2b::hash(remaining, &[], &v);
    out[written..].copy_from_slice(&last);
    v.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::hex::{decode, encode};

    fn p(m: u32, t: u32, par: u32, l: usize) -> Params {
        Params {
            m_cost: m,
            t_cost: t,
            parallelism: par,
            out_len: l,
        }
    }

    // Cross-checked against the reference `argon2` CLI (phc-winner-argon2).
    #[test]
    fn reference_cli_vectors_id() {
        let cases: &[(&[u8], &[u8], Params, &str)] = &[
            (
                b"password",
                b"somesalt",
                p(8, 1, 1, 32),
                "f137f8e186a403a679ccd0606e5ab5dcdafe43c1640855ac8c6e33e9bd63eeb3",
            ),
            (
                b"password",
                b"somesalt",
                p(8, 2, 1, 32),
                "fdb4ddb6d5887131b66f0b2a3740c077dd05b755845861f6b5a1dde8b1071646",
            ),
            (
                b"password",
                b"somesalt",
                p(16, 3, 2, 32),
                "b6bc0f5b8ee239d77d7bcde9ead09144a2e01093367b8600b99c617921e2e3f5",
            ),
            (
                b"hello",
                b"abcdefgh",
                p(64, 2, 1, 32),
                "fb11c67bd04720df6fd75c5456d8792aeb8eb626d964963b88bf96117b75c7ca",
            ),
        ];
        for &(pw, salt, params, want) in cases {
            assert_eq!(encode(&hash(pw, salt, params).unwrap()), want);
        }
    }

    #[test]
    fn reference_cli_vector_long_output() {
        let got = hash(b"password", b"somesalt", p(32, 1, 4, 64)).unwrap();
        assert_eq!(
            encode(&got),
            "2b32c78bb3ad111f15c38c598e9e032a7619074456e7477c2115160055cdb906\
             00672005ce4f7c22864e3b89b693e2216beb31d2ad64c6a9cb980af1d1cc9d38"
        );
    }

    // RFC 9106 §5.3 Argon2id test vector (with secret + associated data).
    #[test]
    fn rfc9106_argon2id() {
        let password = [0x01u8; 32];
        let salt = [0x02u8; 16];
        let secret = [0x03u8; 8];
        let ad = [0x04u8; 12];
        let out = derive(Variant::Id, &password, &salt, &secret, &ad, p(32, 3, 4, 32)).unwrap();
        assert_eq!(
            encode(&out),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }

    // RFC 9106 §5.1 Argon2d and §5.2 Argon2i.
    #[test]
    fn rfc9106_argon2d_and_i() {
        let password = [0x01u8; 32];
        let salt = [0x02u8; 16];
        let secret = [0x03u8; 8];
        let ad = [0x04u8; 12];
        assert_eq!(
            encode(&derive(Variant::D, &password, &salt, &secret, &ad, p(32, 3, 4, 32)).unwrap()),
            "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb"
        );
        assert_eq!(
            encode(&derive(Variant::I, &password, &salt, &secret, &ad, p(32, 3, 4, 32)).unwrap()),
            "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8"
        );
    }

    #[test]
    fn rejects_bad_params() {
        assert!(hash(b"pw", b"somesalt", p(4, 1, 1, 32)).is_err()); // m < 8p
        assert!(hash(b"pw", b"short", p(8, 1, 1, 32)).is_err()); // salt < 8
        assert!(hash(b"pw", b"somesalt", p(8, 0, 1, 32)).is_err()); // t == 0
    }

    #[test]
    fn deterministic_and_salt_sensitive() {
        let a = hash(b"same", b"samesalt", p(64, 2, 2, 32)).unwrap();
        let b = hash(b"same", b"samesalt", p(64, 2, 2, 32)).unwrap();
        assert_eq!(a, b);
        let c = hash(b"same", b"othersalt", p(64, 2, 2, 32)).unwrap();
        assert_ne!(a, c);
        let _ = decode("00");
    }

    #[test]
    fn recommended_params_are_valid() {
        assert!(Params::RECOMMENDED.validate(16).is_ok());
    }
}
