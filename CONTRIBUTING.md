# Contributing to easylock

Thank you for your interest in contributing. easylock is an educational project, so clear code and clear explanations
count as much as speed.

## Getting started

```sh
git clone https://github.com/zlixas/easylock && cd easylock
cargo test --workspace                     # everything must pass
cargo clippy --workspace --all-targets     # must stay warning-free (clippy::pedantic)
cargo fmt --all
```

For the website you also need Node 20+ and [`wasm-pack`](https://rustwasm.github.io/wasm-pack/):

```sh
cd crates/easylock-web
npm install
npm run wasm && npm run dev
```

## Ground rules for cryptographic code

1. **Test vectors first.** Every new primitive needs known-answer tests from an authoritative source, such as NIST CAVP, an RFC
   appendix or the reference implementation. Put a comment next to each vector that says where it comes from.
2. **No new runtime dependencies in `easylock-core`.** Dev-dependencies such as `criterion` are fine.
3. **Constant time for secrets.** Do not branch on secrets, index memory with secrets or divide by secrets. Use the helpers in `ct.rs`.
4. **Zeroize.** Types that hold keys implement `Drop`, and temporary key material goes in `Zeroizing<T>`.
5. **Document the math.** A short doc comment that explains *why* the code works is worth more than a clever trick.
6. **`unsafe`** is allowed only for intrinsics and FFI, and every block needs a `// SAFETY:` comment (enforced by
   `clippy::undocumented_unsafe_blocks`).

## Adding a translation

easylock ships in English, Turkish and Spanish. To add another language:

| Place | What to add |
|---|---|
| `crates/easylock-cli/src/i18n.rs` | a `Lang` variant, and extend every `pick([...])` array |
| `crates/easylock-cli/src/help.rs` | the help strings and the clap heading map |
| `crates/easylock-web/src/i18n.js` | a dictionary and a `LANGS` entry |
| `crates/easylock-web/src/content.js` | the tool names, summaries and *Learn* texts |
| `crates/easylock-gui/ui/app.js` + `index.html` | a dictionary and a language button |

Fixes to existing translations are very welcome, especially from native speakers.

## Commit and PR checklist

- [ ] `cargo fmt --all`, `cargo clippy --workspace --all-targets`, and `cargo test --workspace` all pass
- [ ] `npm run build` still works if you touched the web front-end or `easylock-wasm`
- [ ] New behaviour has tests, and new crypto has KATs
- [ ] `CHANGELOG.md` has an entry under *Unreleased*
- [ ] Commit messages use the imperative mood ("Add BLAKE2s", not "Added BLAKE2s")

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Please be kind.
