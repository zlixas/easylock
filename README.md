<div align="center">

# 🔒 easylock

**Cryptography written from scratch in Rust, which you can see, learn from and experiment with.**

One dependency-free core, four ways to use it: a **command line**, a **terminal UI**,
a **desktop app** and a **website that runs entirely in your browser**.

[![CI](https://github.com/zlixas/easylock/actions/workflows/ci.yml/badge.svg)](https://github.com/zlixas/easylock/actions/workflows/ci.yml)
[![Pages](https://github.com/zlixas/easylock/actions/workflows/pages.yml/badge.svg)](https://zlixas.github.io/easylock/)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust 1.98+](https://img.shields.io/badge/rust-1.98%2B-orange.svg)](rust-toolchain.toml)
![clippy::pedantic](https://img.shields.io/badge/clippy-pedantic%20clean-success)
![languages](https://img.shields.io/badge/i18n-EN%20·%20TR%20·%20ES-8a2be2)

**[🌐 Try it in your browser →](https://zlixas.github.io/easylock/)**

English · [Türkçe](README.tr.md) · [Español](README.es.md)

<img src="docs/images/web-home.png" alt="The easylock web app" width="860">

</div>

> [!WARNING]
> **Educational and unaudited.** Every primitive is implemented from first principles and
> checked against official test vectors (NIST CAVP, FIPS 197/180-4/202/203, RFC 7748/8032/8439/9106 …).
> That is necessary, but it is **not enough** to make the code safe for production. Nobody has
> independently audited it. To protect real secrets, use a reviewed library such as
> `ring`, RustCrypto, libsodium or aws-lc. See [SECURITY.md](SECURITY.md).

---

## Contents

- [Why easylock?](#why-easylock)
- [Quick start](#quick-start)
- [What's inside](#whats-inside)
- [The four front-ends](#the-four-front-ends)
- [Architecture](#architecture)
- [Building & testing](#building--testing)
- [Documentation](#documentation)
- [Contributing](#contributing) · [Citing](#citing) · [License](#license)

## Why easylock?

Most people use cryptography as a black box. easylock opens the box:

- **From scratch.** `easylock-core` has *zero* runtime dependencies. It implements SHA-2, SHA-3, BLAKE3, AES and
  its GHASH, ChaCha20-Poly1305, Argon2id, Curve25519, RSA with a constant-time big-integer engine, and the
  post-quantum ML-KEM, all in readable Rust.
- **Verified.** More than 170 tests check the code against published vectors, and it builds with no warnings under `clippy::pedantic`.
- **Explained.** Each tool on the website has a **Learn** panel with four parts: *what it is*, *how it works*,
  *when to use it* and *what to be careful about*. All of it is available in English, Turkish and Spanish.
- **Interoperable.** The CLI, the TUI, the desktop app and the website share one `.elk` file format. A file you lock in the terminal
  opens on the website, and a file you lock on the website opens in the terminal.
- **Private.** The website compiles the same Rust core to WebAssembly, so it never sends a byte to a server.

## Quick start

**In the browser, with nothing to install:** <https://zlixas.github.io/easylock/>

**On the command line** (macOS / Linux, Rust 1.98+):

```sh
cargo install --git https://github.com/zlixas/easylock easylock-cli   # installs `easylock`

easylock tui                               # full-screen interactive UI
easylock lock taxes.pdf                    # → taxes.pdf.elk  (asks for a password)
easylock unlock taxes.pdf.elk              # → taxes.pdf
easylock lock ~/Photos --shred             # whole folder → Photos.elk, originals wiped

easylock identity                          # your key pair (X25519 + ML-KEM-768)
easylock lock report.pdf -r elkpub1…       # encrypt for someone, no shared password
easylock unlock report.pdf.elk             # opens with your identity
echo -n abc | easylock hash -a blake3
easylock password -n 3 -l 24 --symbols
easylock --lang es --help                  # English · Türkçe · Español
```

## What's inside

| Family | Algorithms | Specification |
|---|---|---|
| Hashing | SHA-256, SHA-512, SHA3-256/512, SHAKE128/256, Keccak-256, BLAKE2b, BLAKE3 | FIPS 180-4, FIPS 202, RFC 7693 |
| MAC | HMAC (any hash), Poly1305 | RFC 2104, RFC 8439 |
| KDF / passwords | Argon2id/i/d (PHC strings), PBKDF2, HKDF | RFC 9106, RFC 8018, RFC 5869 |
| AEAD | AES-256-GCM (AES-NI / ARMv8 and PCLMUL / PMULL), ChaCha20-Poly1305 | SP 800-38D, RFC 8439 |
| Ciphers | AES-256, AES-256-CTR, ChaCha20 | FIPS 197 |
| Elliptic curves | X25519, Ed25519 | RFC 7748, RFC 8032 |
| RSA | key generation, PKCS#1 v1.5, OAEP, CRT | RFC 8017 |
| Post-quantum | ML-KEM-512 / 768 / 1024 (Kyber) | FIPS 203 |
| Encodings | Hex, Base64, Base64URL, Base58, ROT13, chainable pipelines | RFC 4648 |
| Containers | `.elk` files and `elk1.` text tokens (Argon2id + chunked AEAD) | [docs/FILE_FORMAT.md](docs/FILE_FORMAT.md) |

Supporting pieces include `write_volatile` zeroization, `Zeroizing<T>` / `Secret<N>`, constant-time comparison and
selection, runtime CPU feature dispatch, a C ABI ([`easylock.h`](crates/easylock-core/include/easylock.h)) and
`criterion` benchmarks.

## The four front-ends

### 🌐 Website (WebAssembly)

<img src="docs/images/web-x25519.png" alt="X25519 key exchange demo" width="720">

The website has 20 tools in five categories. Each one includes a *Learn* panel and runs entirely on your device.

| | Tools |
|---|---|
| 🔒 Symmetric | Encrypt a file (`.elk`, password and/or public keys) · Encrypt a message (`elk1.` token) · AES-256-GCM · ChaCha20-Poly1305 |
| 🔑 Asymmetric | Key pair for file sharing · Ed25519 sign & verify · X25519 key-exchange walkthrough (Alice ⇄ Bob) · ML-KEM · RSA-2048 |
| ⚡ Hashing & KDF | Live multi-hash · Checksum verifier (detects the algorithm) · HMAC · Argon2id hash & verify · PBKDF2 · HKDF |
| 🔄 Encoding | Encoding pipeline · JWT inspector (checks HS256/HS512/EdDSA signatures) |
| 🛡️ Utilities | Password generator · Password strength estimator · Random bytes / tokens / UUIDs / PINs / passphrases |

The site also has a command palette (<kbd>⌘/Ctrl</kbd>+<kbd>K</kbd> or <kbd>/</kbd>), keyboard shortcuts (<kbd>?</kbd>), a layout
that works on phones, an EN/TR/ES switch (<kbd>Alt</kbd>+<kbd>L</kbd>) and a floating clipboard that holds up to five recent results.
The clipboard is wiped when you close the tab or after 5 minutes idle.

### 🗄️ File encryption in depth

`easylock lock` is built for real-world use:

- **Streaming and multi-core.** Memory use is constant (≈120 MB, mostly Argon2) at any file size. Chunks are encrypted on all
  cores in a pipeline. A 500 MB file takes about 0.3 s before the final `fsync`.
- **Folders.** Whole folder trees go into a single `.elk` file. Extraction is hardened against path traversal.
- **Public keys.** `-r` encrypts to one or more people using an X25519 + ML-KEM-768 hybrid, so the files are post-quantum
  secure. You can combine `-r` with `--with-password`.
- **Safe by default.** Output goes to a temporary file and is renamed only after it has succeeded and been `fsync`ed.
  Existing files are never overwritten without `--force`. A wrong key leaves nothing behind.
- **`--shred`.** After a successful encryption, the originals are overwritten and removed.
- **Pipes.** Example: `tar c dir | easylock lock - -r KEY > backup.elk`.
- **Compatible.** The same files open on the website and in the desktop app, and old ELK1 files still decrypt.

The byte-level format is documented in [docs/FILE_FORMAT.md](docs/FILE_FORMAT.md).

### 🔐 Encrypted vault

A vault is a folder where files **stay encrypted**. File names, sizes and dates are hidden in an encrypted index,
and plaintext is never written into the vault.

```sh
easylock vault init ~/Private.vault                 # password and/or -r public keys
easylock vault add  ~/Private.vault taxes/ id.pdf --shred
easylock vault ls   ~/Private.vault
easylock vault cat  ~/Private.vault taxes/2025.pdf | open -f
easylock vault get  ~/Private.vault taxes -o ~/Desktop
easylock vault rm   ~/Private.vault id.pdf
easylock vault passwd ~/Private.vault -r elkpub1…   # re-key without re-encrypting any files
```

Vaults sync safely through Dropbox, iCloud or Git because every file is a separate, randomly named object.

### ⌨️ Terminal UI

```sh
easylock tui
```

The terminal UI is a keyboard-driven ratatui app with nine tools: live hashing, encode/decode, password generation, key pairs,
password-based text encryption, HMAC, Ed25519 sign/verify, an X25519 exchange demo and an about screen. Keys:
<kbd>↑↓</kbd>/<kbd>1–9</kbd> choose a tool, <kbd>Tab</kbd> moves between fields, <kbd>F5</kbd> copies,
<kbd>F2</kbd> switches the language (EN → TR → ES) and <kbd>F1</kbd> opens help.

### 💻 Command line

| Command | Purpose |
|---|---|
| `hash` | SHA-2/3, Keccak, BLAKE3 over stdin or files |
| `encode` / `decode` | chainable Hex/Base64/Base58/ROT13 pipelines |
| `encrypt` / `decrypt` | raw-key AEAD / CTR / XOR |
| `lock` / `unlock` | encrypt files **and folders** to a password and/or public keys (`.elk`) |
| `inspect` | show how an `.elk` file can be unlocked, no password needed |
| `identity` | create or show your public-key identity |
| `vault` | `init` · `add` · `ls` · `get` · `cat` · `rm` · `passwd` · `info` for an encrypted vault |
| `hmac` | keyed MACs |
| `kdf` | Argon2id / PBKDF2, with `--verify <PHC>` to check a stored hash |
| `password` | unbiased random passwords, with their entropy |
| `keygen` | Ed25519, X25519, ML-KEM-512/768/1024, RSA-2048 (`--json`) |
| `sign` / `verify` | Ed25519 signatures |
| `info` | version, active hardware backends, algorithm catalogue |
| `tui` | the terminal UI |

The CLI localizes everything: help text, clap's headings, errors and status messages. It picks the language from
`--lang en|tr|es`, then `LC_ALL`/`LANG`, and falls back to English.

```console
$ easylock --lang tr kdf -p hunter2
$argon2id$v=19$m=65536,t=3,p=4$…
$ easylock --lang es unlock secreto.elk -p mala
easylock: autenticación fallida: clave/nonce incorrectos o los datos fueron modificados
```

### 🖥️ Desktop app (Tauri v2)

```sh
cd crates/easylock-gui && cargo tauri build
```

The desktop app has four tabs: **Files** (drag-and-drop `.elk` encryption with streaming progress), **Hash**, **Convert** and
**Keys**. It calls `easylock-core` directly over Tauri IPC without going through HTTP, and it is available in EN, TR and ES.

There is also **`easylock-server`**, an `axum` REST API (`/v1/hash`, `/v1/aead/*`, `/v1/kdf/*`, `/v1/keygen`, …) that can
also serve the web dashboard.

## Performance

These are single-process numbers on an Apple M4, measured with `cargo bench -p easylock-core` and `time`. All of it is still from-scratch code with
no dependencies. The hardware paths use each CPU's own instructions, selected at runtime, and fall back to constant-time software.

| Operation | Before | Now | Technique |
|---|---:|---:|---|
| AES-256-GCM (256 KiB) | 1.0 GB/s | **4.3 GB/s** | 8-block interleaved AES-NI / ARMv8 AES, aggregated PCLMUL/PMULL GHASH (H¹…H⁸) |
| ChaCha20-Poly1305 (256 KiB) | 0.49 GB/s | **1.05 GB/s** | 4-block NEON / SSE2 ChaCha20, 64-bit-limb Poly1305 |
| SHA-256 (256 KiB) | 0.37 GB/s | **2.4 GB/s** | ARMv8 SHA2 / Intel SHA-NI instructions |
| Argon2id 64 MiB, t=3, p=4 | 121 ms | **32 ms** | lanes filled on multiple cores, no block copies |
| `lock` 500 MB file → /dev/null | 1.41 s, 1 GB RAM | **0.10–0.15 s, ~120 MB** | streaming, multi-core pipeline |
| `unlock` 500 MB file → /dev/null | 1.31 s | **0.18 s** | pipelined read-ahead, bulk zeroization |

Every fast path is checked against the portable implementation in a differential test, on ARM natively and on x86-64 under Rosetta and in CI.

## Architecture

```mermaid
flowchart LR
  subgraph core["easylock-core (zero dependencies)"]
    H[hash] --- M[mac] --- K[kdf]
    C[cipher / aead] --- E[ec: X25519 · Ed25519]
    B[bigint + Montgomery] --- R[rsa] --- P[pqc: ML-KEM]
    X[container: .elk / elk1.]
  end
  core --> CLI[easylock-cli<br/>CLI + TUI]
  core --> GUI[easylock-gui<br/>Tauri desktop]
  core --> SRV[easylock-server<br/>axum REST]
  core --> WASM[easylock-wasm<br/>wasm-bindgen] --> WEB[easylock-web<br/>Vite + Tailwind]
  core --> FFI[C ABI<br/>easylock.h]
```

For a guided tour of the source, see **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**. It covers constant-time techniques, CPU
dispatch, how the big-integer engine works and where to start reading.

| Crate | Role |
|---|---|
| [`easylock-core`](crates/easylock-core) | All primitives, constant-time `BigUint<N>`, containers, FFI |
| [`easylock-cli`](crates/easylock-cli) | `easylock` binary: CLI + ratatui TUI, EN/TR/ES |
| [`easylock-gui`](crates/easylock-gui) | Tauri v2 desktop app |
| [`easylock-server`](crates/easylock-server) | REST API + static hosting |
| [`easylock-wasm`](crates/easylock-wasm) | WebAssembly bindings |
| [`easylock-web`](crates/easylock-web) | Browser front-end (vanilla JS, no framework) |

## Building & testing

```sh
cargo test   --workspace                  # 170+ tests, vector-backed
cargo clippy --workspace --all-targets    # clean under clippy::pedantic
cargo bench  -p easylock-core             # criterion benchmarks

# the website
cd crates/easylock-web
npm install
npm run wasm     # wasm-pack build of easylock-wasm
npm run dev      # http://localhost:5173
```

Supported native targets are `aarch64`/`x86_64` on macOS and Linux. CI runs fmt, clippy and tests on both Ubuntu and macOS.

## Documentation

| Document | |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Design, module map, constant-time techniques |
| [docs/FILE_FORMAT.md](docs/FILE_FORMAT.md) | Byte-level spec of `.elk` files and `elk1.` tokens |
| [SECURITY.md](SECURITY.md) | Threat model, known limitations, how to report issues |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Dev setup, coding standards, adding a primitive or a language |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## Contributing

Contributions are welcome: new primitives, more test vectors, translations, documentation and bug reports.
Please read [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).

## Citing

If easylock helps your teaching or research, you can cite it through [CITATION.cff](CITATION.cff). GitHub's
"Cite this repository" button uses that file.

## License

easylock is dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
