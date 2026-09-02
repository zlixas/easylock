//! C-ABI surface for Tauri / .NET / C / Python front-ends.
//!
//! Conventions:
//! * Every function is `extern "C"` and `#[no_mangle]` with a `el_` prefix.
//! * Buffers are `(ptr, len)` pairs. Output buffers are caller-allocated; the
//!   caller passes the capacity and the function writes the required length back
//!   through an out-param.
//! * Return code `0` = success, negative = error (see [`ElStatus`]).
//! * `el_*` functions never unwind across the boundary (panics are trapped).
//!
//! The canonical header lives at `include/easylock.h`.

// Every function here is `unsafe extern "C"` with a single documented pointer
// contract in its `# Safety` section; the per-block SAFETY lint would just repeat
// "caller upholds the function contract" on every line.
#![allow(clippy::missing_safety_doc, clippy::undocumented_unsafe_blocks)]

use crate::aead::{Aead, Aes256Gcm, ChaCha20Poly1305};
use crate::hash::Algorithm;
use core::slice;

/// Status codes returned across the FFI boundary.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElStatus {
    Ok = 0,
    NullPointer = -1,
    BufferTooSmall = -2,
    BadArgument = -3,
    AuthFailed = -4,
    Panic = -5,
}

#[inline]
fn guard<F: FnOnce() -> i32 + core::panic::UnwindSafe>(f: F) -> i32 {
    match std::panic::catch_unwind(f) {
        Ok(code) => code,
        Err(_) => ElStatus::Panic as i32,
    }
}

/// Write `src` into the `(out, out_cap)` buffer, storing the true length in
/// `*out_len`. Returns an `ElStatus` code.
unsafe fn emit(src: &[u8], out: *mut u8, out_cap: usize, out_len: *mut usize) -> i32 {
    if out_len.is_null() {
        return ElStatus::NullPointer as i32;
    }
    // SAFETY: caller guarantees `out_len` points to a writable `usize`.
    unsafe { *out_len = src.len() };
    if src.len() > out_cap {
        return ElStatus::BufferTooSmall as i32;
    }
    if out.is_null() {
        return ElStatus::NullPointer as i32;
    }
    // SAFETY: `out` has `out_cap >= src.len()` writable bytes.
    unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), out, src.len()) };
    ElStatus::Ok as i32
}

/// Library version as a static NUL-terminated C string.
#[no_mangle]
pub extern "C" fn el_version() -> *const core::ffi::c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// Hash `input` with the named algorithm (`"sha256"`, `"sha512"`, `"keccak256"`,
/// `"sha3-256"`). Writes the digest to `out`.
///
/// # Safety
/// `algo` must be a valid NUL-terminated C string; `input`/`out` valid for their
/// lengths.
#[no_mangle]
pub unsafe extern "C" fn el_hash(
    algo: *const core::ffi::c_char,
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    guard(|| {
        if algo.is_null() || (input.is_null() && input_len != 0) {
            return ElStatus::NullPointer as i32;
        }
        // SAFETY: caller contract on `algo`.
        let name = unsafe { core::ffi::CStr::from_ptr(algo) };
        let Ok(name) = name.to_str() else {
            return ElStatus::BadArgument as i32;
        };
        let Some(alg) = Algorithm::parse(name) else {
            return ElStatus::BadArgument as i32;
        };
        if matches!(alg, Algorithm::Blake3) {
            return ElStatus::BadArgument as i32;
        }
        // SAFETY: caller contract on `input`.
        let data = unsafe { slice_or_empty(input, input_len) };
        let digest = alg.hash(data);
        // SAFETY: caller contract on `out` / `out_len`.
        unsafe { emit(&digest, out, out_cap, out_len) }
    })
}

/// AEAD seal. `alg` = 0 for AES-256-GCM, 1 for ChaCha20-Poly1305.
/// Requires a 32-byte `key` and 12-byte `nonce`. Output is `ciphertext || tag`.
#[no_mangle]
pub unsafe extern "C" fn el_aead_seal(
    alg: i32,
    key: *const u8,
    nonce: *const u8,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    guard(|| {
        if key.is_null() || nonce.is_null() {
            return ElStatus::NullPointer as i32;
        }
        // SAFETY: caller guarantees 32 key bytes and 12 nonce bytes.
        let key = unsafe { slice::from_raw_parts(key, 32) };
        let nonce = unsafe { read_array::<12>(nonce) };
        let nonce = &nonce;
        let aad = unsafe { slice_or_empty(aad, aad_len) };
        let pt = unsafe { slice_or_empty(plaintext, plaintext_len) };

        let sealed = match alg {
            0 => match Aes256Gcm::new(key) {
                Ok(c) => c.seal(nonce, aad, pt),
                Err(_) => return ElStatus::BadArgument as i32,
            },
            1 => match ChaCha20Poly1305::new(key) {
                Ok(c) => c.seal(nonce, aad, pt),
                Err(_) => return ElStatus::BadArgument as i32,
            },
            _ => return ElStatus::BadArgument as i32,
        };
        unsafe { emit(&sealed, out, out_cap, out_len) }
    })
}

/// AEAD open. Mirrors [`el_aead_seal`]; input is `ciphertext || tag`.
/// Returns [`ElStatus::AuthFailed`] on tag mismatch.
#[no_mangle]
pub unsafe extern "C" fn el_aead_open(
    alg: i32,
    key: *const u8,
    nonce: *const u8,
    aad: *const u8,
    aad_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    guard(|| {
        if key.is_null() || nonce.is_null() {
            return ElStatus::NullPointer as i32;
        }
        // SAFETY: caller guarantees 32 key bytes and 12 nonce bytes.
        let key = unsafe { slice::from_raw_parts(key, 32) };
        let nonce = unsafe { read_array::<12>(nonce) };
        let nonce = &nonce;
        let aad = unsafe { slice_or_empty(aad, aad_len) };
        let ct = unsafe { slice_or_empty(ciphertext, ciphertext_len) };

        let opened = match alg {
            0 => Aes256Gcm::new(key)
                .ok()
                .and_then(|c| c.open(nonce, aad, ct).ok()),
            1 => ChaCha20Poly1305::new(key)
                .ok()
                .and_then(|c| c.open(nonce, aad, ct).ok()),
            _ => return ElStatus::BadArgument as i32,
        };
        match opened {
            Some(pt) => unsafe { emit(&pt, out, out_cap, out_len) },
            None => ElStatus::AuthFailed as i32,
        }
    })
}

/// X25519: `out = X25519(scalar, point)` (all 32 bytes).
#[no_mangle]
pub unsafe extern "C" fn el_x25519(scalar: *const u8, point: *const u8, out: *mut u8) -> i32 {
    guard(|| {
        if scalar.is_null() || point.is_null() || out.is_null() {
            return ElStatus::NullPointer as i32;
        }
        // SAFETY: caller guarantees 32-byte buffers.
        let s = unsafe { read_array::<32>(scalar) };
        let p = unsafe { read_array::<32>(point) };
        let r = crate::ec::x25519(&s, &p);
        unsafe { write_array(&r, out) };
        ElStatus::Ok as i32
    })
}

/// Ed25519 detached sign. `seed` is 32 bytes, `sig_out` is 64 bytes.
#[no_mangle]
pub unsafe extern "C" fn el_ed25519_sign(
    seed: *const u8,
    msg: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
) -> i32 {
    guard(|| {
        if seed.is_null() || sig_out.is_null() {
            return ElStatus::NullPointer as i32;
        }
        // SAFETY: caller guarantees a 32-byte seed and 64-byte output.
        let seed = unsafe { read_array::<32>(seed) };
        let msg = unsafe { slice_or_empty(msg, msg_len) };
        let sk = crate::ec::SigningKey::from_seed(seed);
        let sig = sk.sign(msg);
        unsafe { write_array(&sig.to_bytes(), sig_out) };
        ElStatus::Ok as i32
    })
}

/// Ed25519 verify. Returns [`ElStatus::Ok`] if valid, [`ElStatus::AuthFailed`]
/// otherwise.
#[no_mangle]
pub unsafe extern "C" fn el_ed25519_verify(
    public_key: *const u8,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
) -> i32 {
    guard(|| {
        if public_key.is_null() || sig.is_null() {
            return ElStatus::NullPointer as i32;
        }
        // SAFETY: caller guarantees 32-byte key and 64-byte signature.
        let pk = unsafe { read_array::<32>(public_key) };
        let sig = unsafe { read_array::<64>(sig) };
        let msg = unsafe { slice_or_empty(msg, msg_len) };
        let vk = crate::ec::VerifyingKey::from_bytes(pk);
        if vk.verify(msg, &crate::ec::Signature::from_bytes(sig)) {
            ElStatus::Ok as i32
        } else {
            ElStatus::AuthFailed as i32
        }
    })
}

unsafe fn slice_or_empty<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 || ptr.is_null() {
        &[]
    } else {
        // SAFETY: caller guarantees `ptr` is valid for `len` bytes.
        unsafe { slice::from_raw_parts(ptr, len) }
    }
}

/// Copy `N` bytes out of a caller-supplied pointer into an owned array.
unsafe fn read_array<const N: usize>(ptr: *const u8) -> [u8; N] {
    let mut out = [0u8; N];
    // SAFETY: caller guarantees `ptr` is valid for `N` bytes.
    unsafe { core::ptr::copy_nonoverlapping(ptr, out.as_mut_ptr(), N) };
    out
}

/// Write `N` bytes into a caller-supplied output pointer.
unsafe fn write_array<const N: usize>(src: &[u8; N], ptr: *mut u8) {
    // SAFETY: caller guarantees `ptr` is valid for `N` writable bytes.
    unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), ptr, N) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_hash_roundtrip() {
        let input = b"abc";
        let mut out = [0u8; 32];
        let mut out_len = 0usize;
        let code = unsafe {
            el_hash(
                c"sha256".as_ptr(),
                input.as_ptr(),
                input.len(),
                out.as_mut_ptr(),
                out.len(),
                core::ptr::addr_of_mut!(out_len),
            )
        };
        assert_eq!(code, 0);
        assert_eq!(out_len, 32);
        assert_eq!(
            crate::encode::hex::encode(&out),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn ffi_buffer_too_small_reports_len() {
        let mut out = [0u8; 8];
        let mut out_len = 0usize;
        let code = unsafe {
            el_hash(
                c"sha256".as_ptr(),
                b"x".as_ptr(),
                1,
                out.as_mut_ptr(),
                out.len(),
                core::ptr::addr_of_mut!(out_len),
            )
        };
        assert_eq!(code, ElStatus::BufferTooSmall as i32);
        assert_eq!(out_len, 32);
    }

    #[test]
    fn ffi_aead_roundtrip() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let pt = b"ffi aead payload";
        let mut sealed = [0u8; 64];
        let mut sealed_len = 0usize;
        let rc = unsafe {
            el_aead_seal(
                1,
                key.as_ptr(),
                nonce.as_ptr(),
                core::ptr::null(),
                0,
                pt.as_ptr(),
                pt.len(),
                sealed.as_mut_ptr(),
                sealed.len(),
                core::ptr::addr_of_mut!(sealed_len),
            )
        };
        assert_eq!(rc, 0);
        let mut opened = [0u8; 64];
        let mut opened_len = 0usize;
        let rc = unsafe {
            el_aead_open(
                1,
                key.as_ptr(),
                nonce.as_ptr(),
                core::ptr::null(),
                0,
                sealed.as_ptr(),
                sealed_len,
                opened.as_mut_ptr(),
                opened.len(),
                core::ptr::addr_of_mut!(opened_len),
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(&opened[..opened_len], pt);
    }
}
