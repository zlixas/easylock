# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Performance
- AES-256-GCM is 4.3× faster: 8-block interleaved hardware AES and aggregated GHASH with precomputed H¹…H⁸.
- ChaCha20-Poly1305 is 2.1× faster: 4-way NEON/SSE2 ChaCha20 and 44-bit-limb Poly1305.
- SHA-256 is 6.5× faster using ARMv8 SHA2 / Intel SHA-NI (HMAC, HKDF and PBKDF2 benefit too).
- Argon2id is 3.8× faster at p=4 because lanes run in parallel, and block copies were removed.
- Bulk zeroization runs at memory speed (memset plus an optimization barrier instead of per-byte volatile writes).
- End to end, `lock` on 500 MB now takes 0.10–0.15 s (was 1.41 s) and `unlock` 0.18 s (was 1.31 s).

### Added
- **Encrypted vaults** (`easylock vault init/add/ls/get/cat/rm/passwd/info`): files stay encrypted at rest, names and
  sizes live in an encrypted index, updates are atomic with a process lock, `vault passwd` re-keys instantly, and
  adding files can `--shred` the originals.
- **ELK2 file format**: a random file key held in key slots (a password and/or public keys), with an HMAC over the header.
  See [docs/FILE_FORMAT.md](docs/FILE_FORMAT.md).
- **Public-key file encryption** with a post-quantum X25519 + ML-KEM-768 hybrid: `easylock identity`, `lock -r KEY`
  (multiple recipients allowed), and `unlock` finds your identity automatically. The website has the same features plus a new
  "Key pair" tool. Browser and CLI can open each other's files.
- **Streaming, multi-core engine** (`container::stream`) with a read → encrypt → write pipeline. Memory use is constant
  (1 GB → ~120 MB for a 500 MB file). Encryption is ~4× faster: 0.34 s instead of 1.41 s for 500 MB, excluding the final `fsync`.
- **Folder encryption** with a hardened archive format that rejects path traversal and never overwrites or follows symlinks.
- `lock` accepts several inputs, stdin/stdout pipes and `--shred`. The new `inspect` command shows how a file can be unlocked.
  Outputs are atomic (written to a temp file, `fsync`ed, then renamed) and nothing is overwritten without `--force`.
- Argon2 parameter limits when reading files, so a hostile header can't exhaust memory.
- The desktop app uses the shared engine and can encrypt folders.
- **Terminal UI** (`easylock tui`): nine interactive tools, live hashing and HMAC, clipboard copy, and in-app language switching.
- **Spanish** in every front-end: CLI, TUI, website and desktop app. The CLI accepts `--lang en|tr|es`.
- New CLI commands: `lock` / `unlock` (password-based `.elk` files), `hmac`, `kdf` (with `--verify`), `password`,
  `keygen`, `sign` / `verify`, `info`, `tui`.
- `easylock-core::container`: the shared `.elk` file format and `elk1.` text tokens ([spec](docs/FILE_FORMAT.md)).
- Argon2 **PHC string** helpers `phc_string`, `hash_phc` and `verify_phc`, which interoperate with the reference `argon2` CLI.
- Redesigned website with a home page, a command palette (⌘/Ctrl-K), keyboard shortcuts, a phone layout, *Learn* panels for
  every tool, and new tools: file and message encryption, checksum verifier, HMAC, HKDF, Argon2 verify, X25519 exchange
  demo, JWT inspector, password strength estimator, and a random generator for UUIDs, PINs and passphrases.
- Project docs: architecture guide, file-format spec, security policy, contributing guide, code of conduct, citation file,
  CI workflow, and issue and PR templates. The README is available in EN, TR and ES.

### Changed
- Writers now produce ELK2. ELK1 files still decrypt everywhere.
- The CLI and desktop app get randomness from `getrandom` instead of `/dev/urandom`, in preparation for Windows builds.
- The Argon2 output of the web app, server and desktop app now uses standard PHC Base64 instead of URL-safe Base64.
- The desktop app's `.elk` streaming implementation has been checked against the core implementation.

### Removed
- A test RSA private key (`rsa2048.pem`) that had been committed by mistake. It was a throwaway key and was never used for anything.

## [0.1.0]

### Added
- `easylock-core`: SHA-2, SHA-3/SHAKE/Keccak, BLAKE2b, BLAKE3, HMAC, Poly1305, PBKDF2, HKDF, Argon2id/i/d, AES-256 (with HW
  acceleration), AES-GCM (with HW GHASH), ChaCha20-Poly1305, X25519, Ed25519, RSA (PKCS#1 v1.5, OAEP, keygen), ML-KEM,
  encodings, a constant-time big-integer engine, and a C FFI.
- `easylock-cli` in English and Turkish, `easylock-server` (axum), `easylock-gui` (Tauri v2), `easylock-wasm`, and the
  `easylock-web` dashboard deployed to GitHub Pages.
