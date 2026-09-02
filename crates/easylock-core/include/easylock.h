/*
 * easylock.h — C ABI for easylock-core.
 *
 * Link against libeasylock_core.{a,dylib,so}. All functions are thread-safe
 * (no shared mutable state) and never unwind across the boundary.
 *
 * Buffer convention: outputs are caller-allocated. Pass the capacity; the
 * function writes the true length back through `*out_len`. If the buffer is too
 * small the function returns EL_BUFFER_TOO_SMALL and still sets `*out_len` to the
 * required size.
 *
 * This is an unaudited from-scratch implementation. Do not use it to protect
 * production secrets without a review.
 */
#ifndef EASYLOCK_H
#define EASYLOCK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status codes. 0 = success, negative = failure. */
typedef enum {
    EL_OK = 0,
    EL_NULL_POINTER = -1,
    EL_BUFFER_TOO_SMALL = -2,
    EL_BAD_ARGUMENT = -3,
    EL_AUTH_FAILED = -4,
    EL_PANIC = -5
} el_status;

/* AEAD selector for el_aead_seal / el_aead_open. */
#define EL_AEAD_AES256_GCM        0
#define EL_AEAD_CHACHA20_POLY1305 1

/* Returns a static NUL-terminated version string, e.g. "0.1.0". */
const char *el_version(void);

/*
 * Hash `input` (`input_len` bytes) with `algo` (one of "sha256", "sha512",
 * "keccak256", "sha3-256"). Writes the digest into `out` (32 bytes for all but
 * sha512, which is 64). `*out_len` receives the digest length.
 */
int32_t el_hash(const char *algo,
                const uint8_t *input, size_t input_len,
                uint8_t *out, size_t out_cap, size_t *out_len);

/*
 * AEAD seal. `key` is 32 bytes, `nonce` is 12 bytes. Output is
 * `ciphertext || tag` (tag is 16 bytes), so out_cap must be >= plaintext_len+16.
 */
int32_t el_aead_seal(int32_t alg,
                     const uint8_t *key, const uint8_t *nonce,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *plaintext, size_t plaintext_len,
                     uint8_t *out, size_t out_cap, size_t *out_len);

/* AEAD open. Input is `ciphertext || tag`. Returns EL_AUTH_FAILED on mismatch. */
int32_t el_aead_open(int32_t alg,
                     const uint8_t *key, const uint8_t *nonce,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *ciphertext, size_t ciphertext_len,
                     uint8_t *out, size_t out_cap, size_t *out_len);

/* X25519: out(32) = X25519(scalar(32), point(32)). */
int32_t el_x25519(const uint8_t *scalar, const uint8_t *point, uint8_t *out);

/* Ed25519 detached signature. seed is 32 bytes, sig_out is 64 bytes. */
int32_t el_ed25519_sign(const uint8_t *seed,
                        const uint8_t *msg, size_t msg_len,
                        uint8_t *sig_out);

/* Ed25519 verify. Returns EL_OK if valid, EL_AUTH_FAILED otherwise. */
int32_t el_ed25519_verify(const uint8_t *public_key,
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t *sig);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* EASYLOCK_H */
