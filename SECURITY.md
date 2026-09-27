# Security policy

## Status: educational and unaudited

easylock is a **learning and research project**. The primitives are written from scratch and validated against
official test vectors, but:

- **no independent security audit** has been performed;
- constant-time behaviour follows established techniques, but no tool such as `dudect` or `ctgrind` has verified it;
- the Rust compiler does not guarantee constant-time code generation;
- ML-KEM modular reduction uses `%` by a constant, which is not guaranteed to be constant time (see
  [ARCHITECTURE.md](docs/ARCHITECTURE.md#4-constant-time-techniques));
- memory zeroization is best-effort (`write_volatile`), and copies made by the OS, the allocator or JavaScript engines are outside our
  control.

**Do not rely on easylock to protect real secrets.** Use an audited library instead, such as `ring`, RustCrypto, libsodium or aws-lc.

## Threat model (what we *try* to get right)

| In scope | Out of scope |
|---|---|
| Correctness against published KATs | Physical attacks (power, EM, fault injection) |
| Timing leaks from secret-dependent branches, indexing and division | Microarchitectural attacks (Spectre-class, cache attacks on shared hosts) |
| Authenticated encryption: tampering, truncation and reordering are detected | A compromised machine, browser or browser extension |
| Password-based keys use a memory-hard KDF (Argon2id) | Weak passwords chosen by the user |
| The website never sends user data over the network | Supply-chain compromise of the build toolchain |

## Reporting a vulnerability

Please report security issues **privately** through GitHub's
[private vulnerability reporting](https://github.com/zlixas/easylock/security/advisories/new).
Do not open a public issue.

Include:

- the affected crate, version or commit, and platform;
- a description of the problem and why it matters;
- a proof of concept or failing test vector, if you have one.

We aim to acknowledge reports within 7 days. We credit reporters in the advisory and the changelog unless they ask us not to.

## Past advisories

| Date | Issue | Severity | Fixed in |
|---|---|---|---|
| 2026-09-27 | Ed25519 accepted forged signatures under small-order public keys (non-strict verification) | High | `main` after 0.1.0 |
| 2026-09-27 | Server API: unbounded KDF costs, permissive CORS, zero-randomness fallback | Medium | `main` after 0.1.0 |
| 2026-09-27 | A throwaway test RSA key (`rsa2048.pem`, never used by any code) was present in early commits | Informational | removed from the tree |

## Supported versions

Only the latest commit on `main` receives fixes.
