# Architecture

This document explains how easylock is organised, the ideas behind its design, and where to start reading the code.

## 1. Design goals

1. **Readable from scratch.** Every primitive lives in this repository and has no hidden dependencies. The code should
   read like an annotated textbook while still being fast enough for real use.
2. **Verified.** Every algorithm is checked against official known-answer tests (KATs) before anything is built on it.
3. **Side-channel aware.** Code that handles secrets avoids branches, table lookups and divisions that depend on secret values.
4. **One core, many front-ends.** The CLI, TUI, desktop app, REST server and website are thin layers over
   `easylock-core`, and they share file formats.

## 2. Workspace map

```
crates/
├── easylock-core/     zero-dependency library (rlib + cdylib + staticlib)
│   ├── src/secure.rs      volatile zeroization, Zeroizing<T>, Secret<N>
│   ├── src/ct.rs          constant-time eq / select / swap
│   ├── src/cpu.rs         runtime CPU feature detection
│   ├── src/hash/          SHA-256, SHA-512, Keccak/SHA-3/SHAKE, BLAKE2b, BLAKE3
│   ├── src/mac/           HMAC<H>, Poly1305
│   ├── src/kdf/           PBKDF2, HKDF, Argon2 (+ PHC strings)
│   ├── src/cipher/        AES-256 (portable / AES-NI / ARMv8), CTR, XOR
│   ├── src/aead/          ChaCha20, ChaCha20-Poly1305, GHASH (CLMUL/PMULL), AES-GCM
│   ├── src/bigint/        BigUint<N>, Karatsuba, Montgomery
│   ├── src/ec/            GF(2²⁵⁵−19), X25519, Ed25519
│   ├── src/rsa/           keygen (Miller–Rabin), PKCS#1 v1.5, OAEP, CRT
│   ├── src/pqc/           ML-KEM (FIPS 203): NTT, CBD sampling, FO transform
│   ├── src/encode/        hex, Base64(URL), Base58, ROT13, pipelines
│   ├── src/container.rs   .elk files and elk1. tokens
│   ├── src/ffi.rs         extern "C" API  → include/easylock.h
│   ├── tests/vectors.rs   cross-module KATs
│   └── benches/           criterion benchmarks
├── easylock-cli/      `easylock` binary: clap CLI + ratatui TUI + EN/TR/ES i18n
├── easylock-gui/      Tauri v2 desktop app (ui/ is plain HTML/JS)
├── easylock-server/   axum REST API, optional static hosting of the web app
├── easylock-wasm/     wasm-bindgen façade over easylock-core
└── easylock-web/      Vite + Tailwind front-end (vanilla JS, no framework)
```

## 3. Suggested reading order

If you are here to learn, read the files in this order:

1. `ct.rs` and `secure.rs`: the two ideas every other file depends on.
2. `hash/sha256.rs`: a short, complete Merkle–Damgård hash.
3. `aead/chacha20.rs` → `mac/poly1305.rs` → `aead/chacha20poly1305.rs`: how an AEAD is put together.
4. `cipher/aes.rs` and `aead/ghash.rs`: table-free AES, plus carry-less multiplication in hardware and in software.
5. `ec/field25519.rs` → `ec/x25519.rs` → `ec/ed25519.rs`: finite-field arithmetic up to signatures.
6. `bigint/` → `rsa/`: multi-precision arithmetic and Montgomery reduction.
7. `pqc/mlkem.rs`: lattice cryptography and the Number-Theoretic Transform.
8. `kdf/argon2.rs` and `container.rs`: how a password turns into an encrypted file.

## 4. Constant-time techniques

| Technique | Where |
|---|---|
| Branch-free masks: `mask = 0u32.wrapping_sub(bit)` then `(a & mask) \| (b & !mask)` | `ct.rs`, field arithmetic, Montgomery ladder |
| XOR-accumulated comparison instead of an early-exit `==` | tag checks in every AEAD/MAC, `argon2::verify_phc` |
| Conditional swap for scalar multiplication | `ec/x25519.rs` (Montgomery ladder) |
| No secret-indexed tables | software AES computes the S-box as `x²⁵⁴` in GF(2⁸) plus the affine map; the software GHASH is a bit-at-a-time multiply |
| Montgomery multiplication instead of division | `bigint/montgomery.rs` (RSA private-key operations) |
| `core::hint::black_box` and `compiler_fence` | stop the optimizer from removing masks (`ct.rs`) or zeroization (`secure.rs`) |

**Known gaps.** ML-KEM reduces modulo q = 3329 with `%` by a constant and uses a conditional subtraction.
Compilers usually turn both into branch-free code, but they are not required to. `bigint::montgomery::reduce_wide` is
long division and is **not** constant time. It is only used on RSA values that are not secret. Porting ML-KEM to
Barrett/Montgomery reduction is an open task.

Rust does not formally guarantee constant-time execution. These techniques follow what audited libraries do, but they
have not been checked with tools such as `dudect` or `ctgrind`. See [SECURITY.md](../SECURITY.md).

## 5. Hardware acceleration

`cpu.rs` detects features once at runtime (with `std`) or at compile time (`no_std`). Then:

| Primitive | x86-64 | aarch64 | Fallback |
|---|---|---|---|
| AES-256 | AES-NI (`aesenc`) | ARMv8 Crypto (`aese`/`aesmc`) | constant-time software |
| GHASH | `PCLMULQDQ` | `PMULL` | constant-time software |

`easylock info` shows which backends are active, and so do `GET /health` and the GUI status bar.

## 6. Error handling and memory hygiene

- The core returns `easylock_core::Error`, which is a small enum and never includes secret material in messages.
- Every keyed type implements `Drop` so it zeroizes its state. Temporary keys are wrapped in `Zeroizing<T>`.
- The CLI wraps errors as `CliError(Msg)`. Each message variant has a translation in English, Turkish and Spanish.

## 7. Internationalisation

| Front-end | Mechanism |
|---|---|
| CLI / TUI | `i18n.rs`: `Lang::{En,Tr,Es}` and `lang.pick([en, tr, es])`. `help.rs` rewrites clap's help in place |
| Website | `src/i18n.js` for UI strings and `src/content.js` for the tool catalogue and the *Learn* panels |
| Desktop | `ui/app.js` `I18N` dictionary |

To add a language, add a variant or dictionary in each of these places. See [CONTRIBUTING.md](../CONTRIBUTING.md).

## 8. The web build

`easylock-wasm` exposes a flat `wasm-bindgen` API. It takes bytes and hex strings and returns hex strings, byte arrays or JSON objects. `npm run wasm`
compiles it with `wasm-pack --target web` into `easylock-web/src/pkg`, and Vite bundles the result. The randomness comes from
`crypto.getRandomValues` through `getrandom`'s `js` feature. GitHub Actions ([`pages.yml`](../.github/workflows/pages.yml)) rebuilds and
deploys the site on every push to `main`.
