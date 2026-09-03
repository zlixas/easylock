//! BLAKE3 (the reference tree-hash construction).
//!
//! This is a port of the official BLAKE3 reference implementation (public
//! domain): 32-bit words, 7 rounds, 1024-byte chunks combined as a binary tree.
//! It is not SIMD-accelerated — one chunk / one parent node at a time — but it
//! matches the official test vectors bit for bit, including the extendable
//! output and the `keyed_hash` / `derive_key` modes.

use super::Hash;
use crate::secure::Zeroize;

const OUT_LEN: usize = 32;
const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;
const KEYED_HASH: u32 = 1 << 4;
const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

#[inline(always)]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

fn round(state: &mut [u32; 16], m: &[u32; 16]) {
    // Columns.
    g(state, 0, 4, 8, 12, m[0], m[1]);
    g(state, 1, 5, 9, 13, m[2], m[3]);
    g(state, 2, 6, 10, 14, m[4], m[5]);
    g(state, 3, 7, 11, 15, m[6], m[7]);
    // Diagonals.
    g(state, 0, 5, 10, 15, m[8], m[9]);
    g(state, 1, 6, 11, 12, m[10], m[11]);
    g(state, 2, 7, 8, 13, m[12], m[13]);
    g(state, 3, 4, 9, 14, m[14], m[15]);
}

fn permute(m: &mut [u32; 16]) {
    let orig = *m;
    for i in 0..16 {
        m[i] = orig[MSG_PERMUTATION[i]];
    }
}

/// The BLAKE3 compression function. Returns the full 16-word state (callers that
/// only need a chaining value take the first 8 words).
fn compress(
    chaining_value: &[u32; 8],
    block_words: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let counter_low = counter as u32;
    let counter_high = (counter >> 32) as u32;
    let mut state: [u32; 16] = [
        chaining_value[0],
        chaining_value[1],
        chaining_value[2],
        chaining_value[3],
        chaining_value[4],
        chaining_value[5],
        chaining_value[6],
        chaining_value[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter_low,
        counter_high,
        block_len,
        flags,
    ];
    let mut block = *block_words;

    round(&mut state, &block); // round 1
    permute(&mut block);
    round(&mut state, &block); // 2
    permute(&mut block);
    round(&mut state, &block); // 3
    permute(&mut block);
    round(&mut state, &block); // 4
    permute(&mut block);
    round(&mut state, &block); // 5
    permute(&mut block);
    round(&mut state, &block); // 6
    permute(&mut block);
    round(&mut state, &block); // 7

    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= chaining_value[i];
    }
    state
}

fn words_from_le_bytes(bytes: &[u8], words: &mut [u32]) {
    for (word, chunk) in words.iter_mut().zip(bytes.chunks_exact(4)) {
        *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
}

/// Output of a chunk or parent node; can be finalized to a chaining value or
/// squeezed as extendable output.
#[derive(Clone)]
struct Output {
    input_chaining_value: [u32; 8],
    block_words: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        let full = compress(
            &self.input_chaining_value,
            &self.block_words,
            self.counter,
            self.block_len,
            self.flags,
        );
        let mut cv = [0u32; 8];
        cv.copy_from_slice(&full[..8]);
        cv
    }

    fn root_output_bytes(&self, out: &mut [u8]) {
        for (output_block_counter, out_block) in out.chunks_mut(2 * OUT_LEN).enumerate() {
            let words = compress(
                &self.input_chaining_value,
                &self.block_words,
                output_block_counter as u64,
                self.block_len,
                self.flags | ROOT,
            );
            for (word, out_word) in words.iter().zip(out_block.chunks_mut(4)) {
                out_word.copy_from_slice(&word.to_le_bytes()[..out_word.len()]);
            }
        }
    }
}

#[derive(Clone)]
struct ChunkState {
    chaining_value: [u32; 8],
    chunk_counter: u64,
    block: [u8; BLOCK_LEN],
    block_len: u8,
    blocks_compressed: u8,
    flags: u32,
}

impl ChunkState {
    fn new(key_words: &[u32; 8], chunk_counter: u64, flags: u32) -> Self {
        Self {
            chaining_value: *key_words,
            chunk_counter,
            block: [0u8; BLOCK_LEN],
            block_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    fn len(&self) -> usize {
        BLOCK_LEN * self.blocks_compressed as usize + self.block_len as usize
    }

    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.block_len as usize == BLOCK_LEN {
                let mut block_words = [0u32; 16];
                words_from_le_bytes(&self.block, &mut block_words);
                let full = compress(
                    &self.chaining_value,
                    &block_words,
                    self.chunk_counter,
                    BLOCK_LEN as u32,
                    self.flags | self.start_flag(),
                );
                self.chaining_value.copy_from_slice(&full[..8]);
                self.blocks_compressed += 1;
                self.block = [0u8; BLOCK_LEN];
                self.block_len = 0;
            }

            let want = BLOCK_LEN - self.block_len as usize;
            let take = want.min(input.len());
            self.block[self.block_len as usize..self.block_len as usize + take]
                .copy_from_slice(&input[..take]);
            self.block_len += take as u8;
            input = &input[take..];
        }
    }

    fn output(&self) -> Output {
        let mut block_words = [0u32; 16];
        words_from_le_bytes(&self.block, &mut block_words);
        Output {
            input_chaining_value: self.chaining_value,
            block_words,
            counter: self.chunk_counter,
            block_len: u32::from(self.block_len),
            flags: self.flags | self.start_flag() | CHUNK_END,
        }
    }
}

fn parent_output(
    left_child_cv: &[u32; 8],
    right_child_cv: &[u32; 8],
    key_words: &[u32; 8],
    flags: u32,
) -> Output {
    let mut block_words = [0u32; 16];
    block_words[..8].copy_from_slice(left_child_cv);
    block_words[8..].copy_from_slice(right_child_cv);
    Output {
        input_chaining_value: *key_words,
        block_words,
        counter: 0,
        block_len: BLOCK_LEN as u32,
        flags: PARENT | flags,
    }
}

/// Streaming BLAKE3 hasher supporting default hashing, keyed hashing, key
/// derivation, and extendable output.
#[derive(Clone)]
pub struct Blake3 {
    chunk_state: ChunkState,
    key_words: [u32; 8],
    cv_stack: [[u32; 8]; 54],
    cv_stack_len: u8,
    flags: u32,
}

impl Blake3 {
    fn new_internal(key_words: [u32; 8], flags: u32) -> Self {
        Self {
            chunk_state: ChunkState::new(&key_words, 0, flags),
            key_words,
            cv_stack: [[0u32; 8]; 54],
            cv_stack_len: 0,
            flags,
        }
    }

    /// Standard unkeyed hasher.
    #[must_use]
    pub fn new() -> Self {
        Self::new_internal(IV, 0)
    }

    /// Keyed hasher (MAC / PRF) with a 32-byte key.
    #[must_use]
    pub fn new_keyed(key: &[u8; 32]) -> Self {
        let mut key_words = [0u32; 8];
        words_from_le_bytes(key, &mut key_words);
        Self::new_internal(key_words, KEYED_HASH)
    }

    /// Key-derivation hasher bound to a context string.
    #[must_use]
    pub fn new_derive_key(context: &str) -> Self {
        let mut ctx = Self::new_internal(IV, DERIVE_KEY_CONTEXT);
        ctx.update(context.as_bytes());
        let mut context_key = [0u8; 32];
        ctx.finalize_into(&mut context_key);
        let mut context_key_words = [0u32; 8];
        words_from_le_bytes(&context_key, &mut context_key_words);
        context_key.zeroize();
        Self::new_internal(context_key_words, DERIVE_KEY_MATERIAL)
    }

    fn push_stack(&mut self, cv: [u32; 8]) {
        self.cv_stack[self.cv_stack_len as usize] = cv;
        self.cv_stack_len += 1;
    }

    fn pop_stack(&mut self) -> [u32; 8] {
        self.cv_stack_len -= 1;
        self.cv_stack[self.cv_stack_len as usize]
    }

    fn add_chunk_chaining_value(&mut self, mut new_cv: [u32; 8], mut total_chunks: u64) {
        while total_chunks & 1 == 0 {
            let left = self.pop_stack();
            new_cv = parent_output(&left, &new_cv, &self.key_words, self.flags).chaining_value();
            total_chunks >>= 1;
        }
        self.push_stack(new_cv);
    }

    /// Absorb input.
    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.chunk_state.len() == CHUNK_LEN {
                let chunk_cv = self.chunk_state.output().chaining_value();
                let total_chunks = self.chunk_state.chunk_counter + 1;
                self.add_chunk_chaining_value(chunk_cv, total_chunks);
                self.chunk_state = ChunkState::new(&self.key_words, total_chunks, self.flags);
            }

            let want = CHUNK_LEN - self.chunk_state.len();
            let take = want.min(input.len());
            self.chunk_state.update(&input[..take]);
            input = &input[take..];
        }
    }

    /// Squeeze `out.len()` bytes of output (XOF). May be called once.
    pub fn finalize_xof(&self, out: &mut [u8]) {
        let mut output = self.chunk_state.output();
        let mut parent_nodes_remaining = self.cv_stack_len as usize;
        while parent_nodes_remaining > 0 {
            parent_nodes_remaining -= 1;
            output = parent_output(
                &self.cv_stack[parent_nodes_remaining],
                &output.chaining_value(),
                &self.key_words,
                self.flags,
            );
        }
        output.root_output_bytes(out);
    }
}

impl Default for Blake3 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Blake3 {
    fn drop(&mut self) {
        self.chunk_state.chaining_value.zeroize();
        self.chunk_state.block.zeroize();
        self.key_words.zeroize();
        for cv in &mut self.cv_stack {
            cv.zeroize();
        }
    }
}

impl core::fmt::Debug for Blake3 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Blake3").finish_non_exhaustive()
    }
}

impl Hash for Blake3 {
    const OUTPUT_LEN: usize = OUT_LEN;
    const BLOCK_LEN: usize = BLOCK_LEN;
    const NAME: &'static str = "blake3";

    fn init() -> Self {
        Self::new()
    }
    fn update(&mut self, data: &[u8]) {
        Blake3::update(self, data);
    }
    fn finalize_into(self, out: &mut [u8]) {
        assert_eq!(out.len(), OUT_LEN, "blake3 default output is 32 bytes");
        self.finalize_xof(out);
    }
}

/// One-shot BLAKE3-256.
#[must_use]
pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut h = Blake3::new();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize_xof(&mut out);
    out
}

/// One-shot keyed BLAKE3 (32-byte tag).
#[must_use]
pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut h = Blake3::new_keyed(key);
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize_xof(&mut out);
    out
}

/// One-shot BLAKE3 key derivation, writing `out.len()` bytes.
pub fn derive_key(context: &str, key_material: &[u8], out: &mut [u8]) {
    let mut h = Blake3::new_derive_key(context);
    h.update(key_material);
    h.finalize_xof(out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::hex::encode;

    /// Official BLAKE3 test-vector input: byte i is `i % 251`.
    fn test_input(len: usize) -> alloc::vec::Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    // Values cross-checked against the official `b3sum` 1.8.7 reference tool.
    #[test]
    fn reference_vectors_default_hash() {
        let cases: &[(usize, &str)] = &[
            (
                0,
                "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
            ),
            (
                1,
                "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
            ),
            (
                2,
                "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63",
            ),
            (
                3,
                "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f",
            ),
            (
                7,
                "3f8770f387faad08faa9d8414e9f449ac68e6ff0417f673f602a646a891419fe",
            ),
            (
                8,
                "2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb",
            ),
            (
                63,
                "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b",
            ),
            (
                64,
                "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
            ),
            (
                65,
                "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee",
            ),
            (
                127,
                "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d",
            ),
            (
                128,
                "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef",
            ),
            (
                129,
                "683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12",
            ),
            (
                1023,
                "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
            ),
            (
                1024,
                "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
            ),
            (
                1025,
                "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
            ),
            (
                2048,
                "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
            ),
            (
                3072,
                "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2",
            ),
            (
                4096,
                "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969",
            ),
            (
                5120,
                "9cadc15fed8b5d854562b26a9536d9707cadeda9b143978f319ab34230535833",
            ),
            (
                6144,
                "3e2e5b74e048f3add6d21faab3f83aa44d3b2278afb83b80b3c35164ebeca205",
            ),
            (
                8192,
                "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63",
            ),
            (
                102_400,
                "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085",
            ),
        ];
        for &(len, want) in cases {
            assert_eq!(encode(&hash(&test_input(len))), want, "len {len}");
        }
    }

    #[test]
    fn reference_keyed_and_derive_vectors() {
        const KEY: &[u8; 32] = b"whats the Elvish word for friend";
        const CTX: &str = "BLAKE3 2019-12-27 16:29:52 test vectors context";
        assert_eq!(
            encode(&keyed_hash(KEY, &test_input(0))),
            "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26"
        );
        assert_eq!(
            encode(&keyed_hash(KEY, &test_input(1024))),
            "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4"
        );

        let mut dk = [0u8; 32];
        derive_key(CTX, &test_input(0), &mut dk);
        assert_eq!(
            encode(&dk),
            "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d"
        );
        derive_key(CTX, &test_input(1024), &mut dk);
        assert_eq!(
            encode(&dk),
            "7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a689684302706"
        );
    }

    #[test]
    fn xof_prefix_matches_short_hash() {
        let mut long = [0u8; 128];
        let mut h = Blake3::new();
        h.update(b"extendable output");
        h.finalize_xof(&mut long);
        let short = hash(b"extendable output");
        assert_eq!(&long[..32], &short[..]);
    }

    #[test]
    fn streaming_matches_oneshot_across_chunk_boundary() {
        let data = test_input(CHUNK_LEN * 3 + 100);
        let one = hash(&data);
        let mut h = Blake3::new();
        for c in data.chunks(37) {
            h.update(c);
        }
        let mut got = [0u8; 32];
        h.finalize_xof(&mut got);
        assert_eq!(got, one);
    }
}
