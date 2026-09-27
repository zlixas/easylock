# easylock container formats

easylock has two password-based container formats. Every front-end reads and writes both of them: the CLI (`lock` / `unlock`), the
TUI, the desktop app and the website. The reference implementation is
[`crates/easylock-core/src/container.rs`](../crates/easylock-core/src/container.rs).

Both formats encrypt with **AES-256-GCM** or **ChaCha20-Poly1305**. Each AEAD adds a 16-byte tag. Passwords are
stretched with **Argon2id** (RFC 9106, version 0x13). `.elk` files can also be encrypted to public keys (§1, §5).

## 1. `.elk` files: ELK2 (current)

Every writer produces ELK2 files. Readers also accept the older ELK1 format described in §3.

### Overview

```
header  = "ELK2" ‖ cipher u8 ‖ flags u8 ‖ base_nonce[12] ‖ slot_count u8 ‖ slot* ‖ mac[32]
slot    = type u8 ‖ len u16 LE ‖ body[len]
payload = chunk*   (identical chunk layout to ELK1, see below)
```

| Field | Meaning |
|---|---|
| `cipher` | `0` = AES-256-GCM, `1` = ChaCha20-Poly1305 |
| `flags` | bit 0 = the payload is a folder archive (§4); other bits must be zero |
| `base_nonce` | 8 random bytes followed by 4 zero bytes |
| `slot_count` | 1–64 |
| `mac` | `HMAC-SHA-256(HKDF(file_key, info="elk2 header mac"), header bytes before the MAC)` |

A random 32-byte **file key** is generated for each file. Every slot wraps that same key:

```
wrapped = ChaCha20-Poly1305(KEK, nonce = 0¹², aad = "elk2" ‖ slot_type, file_key)   (48 bytes)
```

Every KEK is unique, because it comes from a fresh salt or a fresh ephemeral key, so a fixed nonce is safe here.

#### Slot type 1: password (body 76 bytes)

`m u32 ‖ t u32 ‖ p u32 ‖ salt[16] ‖ wrapped[48]`, with `KEK = Argon2id(password, salt, m, t, p, 32)`.
Writers currently use m = 64 MiB, t = 3 and p = 4.

#### Slot type 2: X25519 + ML-KEM-768 recipient (body 1168 bytes)

`eph_pub[32] ‖ mlkem_ct[1088] ‖ wrapped[48]`

```
ss_x  = X25519(eph_secret, recipient_x25519)        (rejected if all-zero)
ss_k, mlkem_ct = ML-KEM-768.Encaps(recipient_ek)
KEK   = HKDF-SHA-256(salt = eph_pub ‖ recipient_x25519,
                     ikm  = ss_x ‖ ss_k,
                     info = "elk2 x25519+mlkem768" ‖ SHA-256(mlkem_ct))
```

The file stays confidential as long as **either** X25519 or ML-KEM-768 remains unbroken.

Slots of an unknown type are skipped. They are still covered by the MAC.

### Payload key and chunks

```
payload_key = HKDF-SHA-256(salt = base_nonce, ikm = file_key, info = "elk2 payload")
```

The payload is split into 256 KiB chunks. Each chunk is stored as `len u32 LE ‖ AEAD(payload_key, nonce_i, aad_i, chunk_i)`, where

```
nonce_i = base_nonce[0..8] ‖ be32(i)
aad_i   = be32(i) ‖ is_last            (0x01 for the final chunk)
```

Every chunk is full-size except the last one. If the plaintext length is an exact multiple of 256 KiB, including 0,
the file ends with an extra empty final chunk.

### Reader requirements

A reader **must**:

- reject Argon2 parameters above m = 4 GiB, t = 64 or p = 64 before running the KDF, so a hostile header can't
  exhaust memory;
- verify the header MAC as soon as a slot opens, and fail if it doesn't match;
- reject any chunk whose length is outside `16 ..= 262 160` bytes;
- fail if a chunk fails authentication, if the input ends before the chunk marked `is_last`, or if any bytes
  follow that chunk.

### Security properties

- **Confidentiality and integrity** of every chunk come from the AEAD.
- **Order and completeness.** An attacker can't reorder, duplicate, truncate or extend chunks.
- **Header integrity.** Only a holder of the file key can produce a valid MAC. That rules out stripping or adding slots,
  flipping flags, and changing the cipher or nonce.
- **Independent keys.** Each file uses a fresh random file key, so ciphertexts from different files are unrelated.

### Implementation notes

The reference implementation (`container::stream`) encrypts and decrypts in a streaming, multi-threaded pipeline:
batches of chunks are processed on all cores while the next batch is read and the previous one is written.
Memory use stays bounded whatever the file size.

## 2. `elk1.` text tokens

The token format is a compact form for short messages that you copy and paste:

```
token = "elk1." ‖ base64url_nopad( cipher_id[1] ‖ salt[16] ‖ nonce[12] ‖ AEAD(key, nonce, "elk1", text) )
key   = Argon2id(password, salt, m = 19456 KiB, t = 2, p = 1, out_len = 32)
```

The token uses the OWASP "interactive" Argon2id profile (19 MiB, 2 passes, 1 lane), so it decrypts quickly in a browser. The
associated data is the four ASCII bytes `elk1`. Whitespace around the token is ignored when it is read.

## 3. Legacy ELK1 files

ELK1 is the original password-only format. Its 45-byte header is `"ELK1" ‖ cipher u8 ‖ m u32 ‖ t u32 ‖ p u32 ‖ salt[16] ‖ base_nonce[12]` (all little-endian).
The Argon2id output is used directly as the payload key. The chunks are identical to ELK2. Readers still accept ELK1, but writers no longer produce it.

## 4. Folder archives (`ELKA`)

When flag bit 0 is set, the plaintext is an archive:

```
"ELKA" ‖ version u8 (=1) ‖ entry* ‖ 0x00
entry = kind u8 (1 dir, 2 file) ‖ path_len u16 ‖ path (UTF-8, '/'-separated) ‖ mode u32 ‖ mtime i64 ‖ [size u64 ‖ data]
```

Extractors **must** reject absolute paths, `..`, `.`, empty components, backslashes, `:` and NUL. They must create files
with exclusive-create semantics and never create symlinks. The reference extractor does all of this. Symlinks and
special files are not archived.

## 5. Keys

| String | Contents |
|---|---|
| `elkpub1` + Base64URL | X25519 public key (32) ‖ ML-KEM-768 encapsulation key (1184) ‖ checksum (4) |
| `ELK-SECRET-KEY-1` + Base64URL | X25519 secret (32) ‖ ML-KEM seed d ‖ z (64) ‖ checksum (4) |

The checksum is the first 4 bytes of `SHA-256(prefix ‖ body)`, which catches copy-paste errors.
An identity file consists of comment lines (`# public key: elkpub1…`) followed by either the secret string or an `elk1.` token that
encrypts the secret string with a password.

## 6. Test vectors

The unit tests in `container.rs` check round-trips, tampering, truncation and wrong-password rejection. The
desktop GUI's test `elk_format_interoperates_with_core_container` checks that its streaming implementation and
the in-memory core implementation produce files that each can read.

## 7. Versioning

A future incompatible change will use a new magic (`ELK3`) and a new token prefix (`elk2.`). Readers should reject unknown
magics and cipher ids.
