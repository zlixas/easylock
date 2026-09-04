# easylock

A from-scratch cryptography library, CLI, and HTTP engine written in Rust — an
exploration of what a small OpenSSL alternative looks like when every primitive
is implemented in-tree. Site : https://zlixas.github.io/easylock/

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
| [`easylock-server`](crates/easylock-server) | Async REST API (`tokio` + `axum`) — also static-hosts the web dashboard. |
| [`easylock-gui`](crates/easylock-gui) | Tauri v2 **desktop** app — file encrypt/decrypt, hashing, pipelines, key generation. Talks to `easylock-core` over Tauri IPC (no HTTP). |
| [`easylock-web`](crates/easylock-web) | Vite + Tailwind v4 **web** dashboard — tree navigation, floating multi-clipboard, EN/TR. Talks to `easylock-server`. |

`easylock-core` has **no runtime dependencies**. The CLI adds only `clap`; the
server adds `tokio` / `axum` / `tower-http`; the desktop GUI adds `tauri`; the
web dashboard is a static Node/Vite build.

## Platform support

Builds and runs natively, with no system libraries, on:

- macOS: `aarch64-apple-darwin` (Apple silicon), `x86_64-apple-darwin`
- Linux: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`

AES **and** GHASH dispatch at runtime:

| Target | AES fast path | GHASH fast path | Fallback (both) |
|--------|---------------|-----------------|-----------------|
| x86-64 | AES-NI (`aesenc`) | `PCLMULQDQ` | constant-time software |
| aarch64 | ARMv8 crypto (`aese`) | `PMULL` | constant-time software |

`build_info()` / `GET /health` / the GUI status bar report both active backends.

## Feature status

**Implemented and vector-tested**

- Hashing: SHA-256, SHA-512, Keccak-256, SHA3-256, **SHA3-512**, **BLAKE3**
  (+ keyed / derive-key / XOF), **BLAKE2b**, **SHAKE128/256**
- MAC: HMAC (any hash), Poly1305
- KDF / password hashing: PBKDF2, HKDF, **Argon2id / Argon2i / Argon2d** (RFC 9106)
- AEAD: ChaCha20-Poly1305 (RFC 8439), AES-256-GCM (SP 800-38D) with a
  **hardware carry-less GHASH** backend
- Stream/block: ChaCha20, AES-256 (HW + portable), AES-256-CTR, multi-byte XOR
- Big integers: `BigUint<N>` — constant-time add/sub/compare, schoolbook &
  Karatsuba multiply, Montgomery multiplication + constant-time powering ladder
- Curve25519: X25519 ECDH (RFC 7748), Ed25519 sign/verify (RFC 8032)
- RSA-2048 / 4096: PKCS#1 v1.5 sign/verify + encrypt/decrypt, **RSAES-OAEP /
  PKCS#1 v2.2** (MGF1), CRT private ops, and **key generation** (Miller-Rabin
  prime search)
- **Post-quantum: ML-KEM-512 / 768 / 1024** (FIPS 203) — KATs match `kyber-py`
- Encodings: Hex, Base64, Base64URL, Base58, ROT13 — with pipeline chaining
- Memory hygiene: `write_volatile` zeroization, `Zeroizing<T>`, `Secret<N>`,
  zeroize-on-drop for every keyed/stateful type
- Side channels: XOR-accumulated constant-time tag/hash comparison everywhere
- C ABI: `el_hash`, `el_aead_seal`/`open`, `el_x25519`, `el_ed25519_sign`/`verify`
- `criterion` benchmarks for the hot primitives

**Deferred to a later milestone**

- ML-DSA / SLH-DSA (post-quantum signatures)
- RSA-PSS padding; DER/PEM key parsing and export
- gRPC (`tonic`) — the REST router is kept thin so a gRPC service can mount beside it

## Desktop GUI

```sh
cargo tauri dev  --config crates/easylock-gui/tauri.conf.json   # or:
cd crates/easylock-gui && cargo tauri build
```

A dark-themed Tauri v2 app with four tabs — **Files** (drag-and-drop
encrypt/decrypt, Argon2id-derived keys, chunked AEAD with a progress bar),
**Hash** (text or file → SHA-256 / BLAKE3 / Keccak-256 / … with a compare box),
**Convert** (real-time Base64/Hex/Base58/ROT13 pipeline), and **Keys**
(secure passwords, Argon2id PHC strings, Ed25519 / X25519 / **ML-KEM-768** /
RSA-2048 key pairs). A live **EN / TR** switch localises the whole UI. IPC
commands call `easylock-core` directly; secret buffers are `Zeroize`d after use.

## Build & test

```sh
cargo build --workspace --release
cargo test  --workspace              # ~165 tests, all vector-backed
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

## Server + web dashboard

`easylock-server` is both the REST API **and** the static host for the
`easylock-web` dashboard.

```sh
# 1. build the frontend
cd crates/easylock-web && npm install && npm run build && cd -
# 2. run the server (serves ../easylock-web/dist + the API on one origin)
EASYLOCK_LISTEN=127.0.0.1:8080 easylock-server
open http://localhost:8080
```

For frontend development with hot-reload, `npm run dev` starts Vite on `:5173`
and proxies `/v1` + `/health` to the server on `:8080`.

**API** (JSON; binary fields are Base64 unless the key ends `_hex`):

| Path | Purpose |
|---|---|
| `GET /health` | version + active AES / GHASH backends |
| `POST /v1/hash` | SHA-2/3, Keccak, BLAKE3 |
| `POST /v1/aead/seal` · `/open` | AES-256-GCM / ChaCha20-Poly1305 |
| `POST /v1/kdf/argon2` · `/kdf/pbkdf2` | password hashing / KDF |
| `POST /v1/encode` | `{input, steps[], decode}` transform pipeline |
| `POST /v1/password` | CSPRNG password generator |
| `POST /v1/keygen` | `{kind}` → ed25519 / x25519 / rsa2048 / mlkem512-1024 |
| `POST /v1/mlkem/encaps` · `/decaps` | ML-KEM encapsulate / decapsulate |
| `POST /v1/x25519`, `/v1/ed25519/sign` · `/verify` | Curve25519 |

### Dashboard

A dark "obsidian" single-page app (Vite + Tailwind v4, no framework) with a
**vertical tree sidebar** (🔒 Symmetric · 🔑 Asymmetric & Keys · ⚡ Hashing & KDF ·
🔄 Pipeline · 🛡️ Utilities), drag-and-drop file zones, a live **EN / TR** toggle,
and a **floating multi-clipboard dock** (bottom-right, 5-item stack, one-click
copy, clear-all, best-effort zeroize on tab close / 5-min idle). Every
hash/encrypt/keygen result is auto-pushed to the dock.

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
