# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
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
