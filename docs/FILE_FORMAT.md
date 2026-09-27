# easylock container formats

easylock has two password-based container formats. Every front-end reads and writes both of them: the CLI (`lock` / `unlock`), the
TUI, the desktop app and the website. The reference implementation is
[`crates/easylock-core/src/container.rs`](../crates/easylock-core/src/container.rs).

Both formats derive a 256-bit key from the password with **Argon2id** (RFC 9106, version 0x13) and encrypt with either
**AES-256-GCM** or **ChaCha20-Poly1305**. Each AEAD adds a 16-byte tag.

## 1. `.elk` files

### Header (45 bytes)

All integers in the header are **little-endian**.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | magic `"ELK1"` (`45 4C 4B 31`) |
| 4 | 1 | cipher id: `0` = AES-256-GCM, `1` = ChaCha20-Poly1305 |
| 5 | 4 | Argon2id memory cost `m` in KiB (u32) |
| 9 | 4 | Argon2id time cost `t` (u32) |
| 13 | 4 | Argon2id parallelism `p` (u32) |
| 17 | 16 | salt (random) |
| 33 | 12 | base nonce: 8 random bytes followed by 4 zero bytes |

The header stores the KDF parameters, so a future version can raise the defaults without breaking old files. Writers
currently use `m = 65536` (64 MiB), `t = 3` and `p = 4`.

### Key derivation

```
key = Argon2id(password, salt, m, t, p, out_len = 32)
```

### Chunks

After the header, the plaintext is split into chunks of **256 KiB** (262 144 bytes). Every chunk is full-size except
the last one, which is shorter. If the plaintext length is an exact multiple of 256 KiB, including 0, the file ends with
an extra **empty** final chunk.

Chunk number `i` (starting at 0) is stored as:

| Size | Field |
|---:|---|
| 4 | `len` = length of the sealed chunk in bytes (u32, little-endian) |
| `len` | `AEAD.seal(key, nonce_i, aad_i, chunk_i)` = ciphertext ‖ 16-byte tag |

The nonce and associated data use **big-endian** counters:

```
nonce_i = base_nonce[0..8] ‖ be32(i)
aad_i   = be32(i) ‖ is_last            (is_last = 0x01 for the final chunk, else 0x00)
```

### Security properties

- **Confidentiality and integrity** of every chunk come from the AEAD.
- **Order and completeness.** The chunk index is part of both the nonce and the AAD, so an attacker cannot reorder or
  duplicate chunks. The `is_last` flag makes truncation at a chunk boundary detectable, and so does appending data after
  the final chunk.
- **Header binding.** Changing the cipher id, KDF parameters or salt produces a different key. Changing the base nonce
  changes every chunk nonce. In both cases authentication fails.
- **Nonce uniqueness.** Each file gets a new random salt, which gives it a new key. The per-file key is used for at most 2³² chunks,
  and each of those chunks has a distinct nonce.

A reader **must** reject a file if any chunk fails authentication, if the input ends before a chunk marked `is_last`,
or if any bytes follow that chunk.

## 2. `elk1.` text tokens

The token format is a compact form for short messages that you copy and paste:

```
token = "elk1." ‖ base64url_nopad( cipher_id[1] ‖ salt[16] ‖ nonce[12] ‖ AEAD(key, nonce, "elk1", text) )
key   = Argon2id(password, salt, m = 19456 KiB, t = 2, p = 1, out_len = 32)
```

The token uses the OWASP "interactive" Argon2id profile (19 MiB, 2 passes, 1 lane), so it decrypts quickly in a browser. The
associated data is the four ASCII bytes `elk1`. Whitespace around the token is ignored when it is read.

## 3. Test vectors

The unit tests in `container.rs` check round-trips, tampering, truncation and wrong-password rejection. The
desktop GUI's test `elk_format_interoperates_with_core_container` checks that its streaming implementation and
the in-memory core implementation produce files that each can read.

## 4. Versioning

A future incompatible change will use a new magic (`ELK2`) and a new token prefix (`elk2.`). Readers should reject unknown
magics and cipher ids.
