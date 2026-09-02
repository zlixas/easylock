# easylock

A from-scratch cryptography library, CLI, and HTTP engine written in Rust — an
exploration of what a small OpenSSL alternative looks like when every primitive
is implemented in-tree.

> [!WARNING]
> **Not audited. Not for protecting real secrets.**
> The primitives are implemented from first principles and checked against
> published test vectors (NIST CAVP, RFC 8439 / 7748 / 8032, RFC 4231 / 5869 /
> 7914, FIPS 197 / 180-4 / 202). That is necessary but *not sufficient* for
> production use. Constant-time routines are written to avoid secret-dependent
> branches, indexing, and division and use volatile/optimization-barrier
> techniques, but the language provides no formal guarantee. Use a reviewed
> library (`ring`, `RustCrypto`, `libsodium`, `aws-lc`) for anything that matters.

## Workspace

| Crate | Contents |
|-------|----------|
| [`easylock-core`](crates/easylock-core) | Zero-dependency primitives, constant-time `BigUint<N>` + Montgomery engine, Curve25519, RSA, and the `extern "C"` FFI. |
| [`easylock-cli`](crates/easylock-cli) | `easylock` command — `hash` / `encode` / `decode` / `encrypt` / `decrypt`, English & Turkish output, full stdin/stdout streaming. |
| [`easylock-server`](crates/easylock-server) | Async REST API over `tokio` + `axum`. |

`easylock-core` has **no runtime dependencies**. The CLI adds only `clap`; the
server adds `tokio`, `axum`, `serde`.

## Platform support

Builds and runs natively, with no system libraries, on:

- macOS: `aarch64-apple-darwin` (Apple silicon), `x86_64-apple-darwin`
- Linux: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`

AES dispatches at runtime:

| Target | Fast path | Fallback |
|--------|-----------|----------|
| x86-64 | AES-NI (`aesenc`/`aesenclast`) | constant-time `x^254` S-box |
| aarch64 | ARMv8 crypto extension (`aese`/`aesmc`) | constant-time `x^254` S-box |

GHASH currently uses the branch-free portable multiply on all targets
(`build_info()` / `GET /health` report the active AES backend).

## Feature status

**Implemented and vector-tested**

- Hashing: SHA-256, SHA-512, Keccak-256, SHA3-256
- MAC: HMAC (any hash), Poly1305
- KDF: PBKDF2, HKDF
- AEAD: ChaCha20-Poly1305 (RFC 8439), AES-256-GCM (SP 800-38D)
- Stream/block: ChaCha20, AES-256 (HW + portable), AES-256-CTR, multi-byte XOR
- Big integers: `BigUint<N>` — constant-time add/sub/compare, schoolbook &
  Karatsuba multiply, Montgomery multiplication + constant-time powering ladder
- Curve25519: X25519 ECDH (RFC 7748), Ed25519 sign/verify (RFC 8032)
- RSA-2048 / 4096: PKCS#1 v1.5 sign/verify and encrypt/decrypt, CRT private ops
- Encodings: Hex, Base64, Base64URL, Base58, ROT13 — with pipeline chaining
- Memory hygiene: `write_volatile` zeroization, `Zeroizing<T>`, `Secret<N>`,
  zeroize-on-drop for every keyed/stateful type
- Side channels: XOR-accumulated constant-time tag/hash comparison everywhere
- C ABI: `el_hash`, `el_aead_seal`/`open`, `el_x25519`, `el_ed25519_sign`/`verify`
- `criterion` benchmarks for the hot primitives

**Deferred to a later milestone**

- BLAKE3, Argon2id (hashing/KDF)
- Hardware GHASH (PCLMULQDQ / PMULL) — AES block already uses hardware
- RSA key generation (needs a vetted prime search) and OAEP/PSS padding
- DER/PEM key parsing
- gRPC (`tonic`) — the REST router is kept thin so a gRPC service can mount beside it

## Build & test

```sh
cargo build --workspace --release
cargo test  --workspace              # ~120 tests, all vector-backed
cargo clippy --workspace --all-targets   # clean under clippy::pedantic
cargo bench -p easylock-core

# cross-compile checks
rustup target add x86_64-apple-darwin aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu
for t in x86_64-apple-darwin aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu; do
  cargo check --workspace --target "$t"
done
```

## Install the CLI

```sh
cargo install --path crates/easylock-cli     # -> ~/.cargo/bin/easylock
easylock --help
easylock --lang tr --help
```

The `easylock-cli` crate's only binary is named `easylock`, so `cargo install`
drops a single `easylock` executable on `PATH`.

## CLI

```sh
# hashing (reads stdin or a file; hex/base64/raw output)
printf 'abc' | easylock hash --algo sha256
easylock hash -a keccak256 --encoding base64 ./file.bin

# encoding pipelines: "base64,hex" means hex(base64(data)); decode reverses it
printf 'data' | easylock encode -t base64,hex
echo 5a5852695a773d3d | easylock decode -t base64,hex

# authenticated encryption (nonce auto-generated + printed if omitted)
KEY=$(printf '%064d' 0)
printf 'secret' | easylock encrypt -c aes-256-gcm --key "$KEY" --armor
cat sealed.b64 | easylock decrypt -c chacha20-poly1305 --key "$KEY" --nonce "$N" --armor
```

Ciphers: `aes-256-gcm`, `chacha20-poly1305`, `aes-256-ctr`, `xor`.

### Language support (English / Turkish)

The interface language is resolved as: **`--lang tr|en` flag** → **system locale**
(`LC_ALL` / `LC_MESSAGES` / `LANG` / `LANGUAGE`; a value beginning `tr` → Turkish)
→ **English**. `--lang` is global, so it works before or after the subcommand.

When Turkish is active, `easylock` translates command descriptions, every
`--help` body (including clap's `Usage:` / `Options:` / `Commands:` headings),
argument help, error messages, and status logs:

```console
$ easylock --lang tr encrypt --key … --nonce … -o dosya.enc
easylock şifrelendi: dosya.enc (AES-256-GCM kullanıldı)

$ LANG=tr_TR.UTF-8 easylock hash --algo yok
easylock: bilinmeyen özet algoritması: yok
```

Cryptographic identifiers (`sha256`, `aes-256-gcm`, …), hex/Base64 payloads, and
the crate's Rust API stay in English by design.

## Server

```sh
EASYLOCK_LISTEN=127.0.0.1:8080 easylock-server

curl localhost:8080/health
curl -XPOST localhost:8080/v1/hash \
  -d '{"algo":"sha256","data":"YWJj"}'         # data is Base64 (or set "hex":true)
curl -XPOST localhost:8080/v1/ed25519/sign \
  -d '{"seed_hex":"00..","message":"aGk="}'
```

Endpoints: `/health`, `/v1/hash`, `/v1/aead/seal`, `/v1/aead/open`, `/v1/x25519`,
`/v1/ed25519/sign`, `/v1/ed25519/verify`. Binary fields are Base64 unless the key
ends in `_hex`.

## FFI

`easylock-core` builds as `rlib` + `cdylib` + `staticlib`. The C header is
[`crates/easylock-core/include/easylock.h`](crates/easylock-core/include/easylock.h).

```c
#include "easylock.h"
uint8_t digest[32]; size_t n;
el_hash("sha256", (const uint8_t*)"abc", 3, digest, sizeof digest, &n);
```

```sh
cargo build -p easylock-core --release
cc app.c target/release/libeasylock_core.a -framework Security -framework CoreFoundation -o app   # macOS
cc app.c target/release/libeasylock_core.a -o app                                                # Linux
```

The same static/dynamic library links into Tauri, .NET (`DllImport`), or Python
(`ctypes`/`cffi`) front-ends.

## License

Dual-licensed under Apache-2.0 OR MIT.
