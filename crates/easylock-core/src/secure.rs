//! Memory hygiene: volatile zeroization and self-wiping containers.
//!
//! The compiler is free to elide a "dead" `memset` that overwrites memory which is
//! never read again. To stop that we write each byte through
//! [`core::ptr::write_volatile`] and follow it with a
//! [`core::sync::atomic::compiler_fence`] so the writes are ordered before the
//! deallocation / stack pop that follows.
//!
//! This does not defend against secrets that were already copied elsewhere
//! (a `memcpy` the optimizer made, register spills, swap). It is a mitigation,
//! not a guarantee.

use core::sync::atomic::{compiler_fence, Ordering};

/// Overwrite `buf` with zeros in a way the optimizer may not remove.
#[inline(never)]
pub fn zeroize_bytes(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        // SAFETY: `byte` is a valid, aligned, uniquely-borrowed `u8`.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Overwrite a slice of `u64` limbs with zeros (used by the big-integer engine).
#[inline(never)]
pub fn zeroize_u64s(buf: &mut [u64]) {
    for limb in buf.iter_mut() {
        // SAFETY: `limb` is a valid, aligned, uniquely-borrowed `u64`.
        unsafe { core::ptr::write_volatile(limb, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Generic volatile scrub for a slice of any `Copy` word type.
#[inline(never)]
pub fn zeroize_words<T: Copy>(buf: &mut [T], zero: T) {
    for word in buf.iter_mut() {
        // SAFETY: `word` is a valid, aligned, uniquely-borrowed `T`.
        unsafe { core::ptr::write_volatile(word, zero) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Types that can scrub their own sensitive contents.
///
/// Implementors must overwrite *every* byte that could carry key material or
/// plaintext. It is called automatically by [`Zeroizing`] and by `Drop` impls in
/// this crate.
pub trait Zeroize {
    /// Overwrite all sensitive state with zeros.
    fn zeroize(&mut self);
}

impl Zeroize for [u8] {
    fn zeroize(&mut self) {
        zeroize_bytes(self);
    }
}

impl<const N: usize> Zeroize for [u8; N] {
    fn zeroize(&mut self) {
        zeroize_bytes(self);
    }
}

impl Zeroize for [u64] {
    fn zeroize(&mut self) {
        zeroize_u64s(self);
    }
}

impl<const N: usize> Zeroize for [u64; N] {
    fn zeroize(&mut self) {
        zeroize_u64s(self);
    }
}

impl Zeroize for [u32] {
    fn zeroize(&mut self) {
        zeroize_words(self, 0);
    }
}

impl<const N: usize> Zeroize for [u32; N] {
    fn zeroize(&mut self) {
        zeroize_words(self, 0);
    }
}

impl Zeroize for [i64] {
    fn zeroize(&mut self) {
        zeroize_words(self, 0);
    }
}

impl<const N: usize> Zeroize for [i64; N] {
    fn zeroize(&mut self) {
        zeroize_words(self, 0);
    }
}

impl Zeroize for [u16] {
    fn zeroize(&mut self) {
        zeroize_words(self, 0);
    }
}

impl<const N: usize> Zeroize for [u16; N] {
    fn zeroize(&mut self) {
        zeroize_words(self, 0);
    }
}

impl Zeroize for u32 {
    fn zeroize(&mut self) {
        // SAFETY: `self` is a valid, uniquely-borrowed `u32`.
        unsafe { core::ptr::write_volatile(self, 0) };
        compiler_fence(Ordering::SeqCst);
    }
}

impl Zeroize for u64 {
    fn zeroize(&mut self) {
        // SAFETY: `self` is a valid, uniquely-borrowed `u64`.
        unsafe { core::ptr::write_volatile(self, 0) };
        compiler_fence(Ordering::SeqCst);
    }
}

impl Zeroize for u128 {
    fn zeroize(&mut self) {
        // SAFETY: `self` is a valid, uniquely-borrowed `u128`.
        unsafe { core::ptr::write_volatile(self, 0) };
        compiler_fence(Ordering::SeqCst);
    }
}

#[cfg(feature = "std")]
impl Zeroize for alloc::vec::Vec<u8> {
    fn zeroize(&mut self) {
        // Wipe the full backing allocation, not just the current length.
        let cap = self.capacity();
        self.clear();
        self.resize(cap, 0);
        zeroize_bytes(self.as_mut_slice());
        self.clear();
    }
}

/// A wrapper that runs [`Zeroize::zeroize`] on its contents when dropped.
///
/// ```
/// use easylock_core::secure::Zeroizing;
/// let mut k = Zeroizing::new([0u8; 32]);
/// k[0] = 0xAB;
/// // `k` is scrubbed here.
/// ```
pub struct Zeroizing<T: Zeroize>(T);

impl<T: Zeroize> Zeroizing<T> {
    /// Wrap a value so it is scrubbed on drop.
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Consume the wrapper and return the inner value *without* scrubbing it.
    /// The caller becomes responsible for the secret.
    pub fn into_inner(self) -> T {
        let me = core::mem::ManuallyDrop::new(self);
        // SAFETY: `me` is not dropped (ManuallyDrop), so `me.0` is read out
        // exactly once and its destructor never runs.
        unsafe { core::ptr::read(core::ptr::addr_of!(me.0)) }
    }
}

impl<T: Zeroize> Drop for Zeroizing<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> core::ops::Deref for Zeroizing<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> core::ops::DerefMut for Zeroizing<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Zeroize + core::fmt::Debug> core::fmt::Debug for Zeroizing<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Zeroizing(<redacted>)")
    }
}

/// A fixed-size secret byte array (keys, seeds, expanded states).
///
/// * Scrubbed on drop via `write_volatile`.
/// * `Debug` never prints the bytes.
/// * Equality is constant-time (see [`crate::ct`]).
#[derive(Clone)]
pub struct Secret<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> Secret<N> {
    /// Create a secret from raw bytes (takes ownership of the material).
    pub const fn from_bytes(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// A zero-filled secret, typically filled in place afterwards.
    pub const fn zeroed() -> Self {
        Self { bytes: [0u8; N] }
    }

    /// Copy from a slice, checking the length.
    pub fn from_slice(slice: &[u8]) -> crate::Result<Self> {
        if slice.len() != N {
            return Err(crate::Error::len("Secret", N, slice.len()));
        }
        let mut bytes = [0u8; N];
        bytes.copy_from_slice(slice);
        Ok(Self { bytes })
    }

    /// Borrow the raw bytes. Handle with care.
    #[must_use]
    pub fn expose(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Mutably borrow the raw bytes (e.g. to fill from an RNG).
    pub fn expose_mut(&mut self) -> &mut [u8; N] {
        &mut self.bytes
    }
}

impl<const N: usize> Zeroize for Secret<N> {
    fn zeroize(&mut self) {
        zeroize_bytes(&mut self.bytes);
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.bytes);
    }
}

impl<const N: usize> core::fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Secret<{N}>(<redacted>)")
    }
}

impl<const N: usize> PartialEq for Secret<N> {
    fn eq(&self, other: &Self) -> bool {
        crate::ct::ct_eq(&self.bytes, &other.bytes).into()
    }
}

impl<const N: usize> Eq for Secret<N> {}

impl<const N: usize> From<[u8; N]> for Secret<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self::from_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroize_wipes_all_bytes() {
        let mut buf = [0xFFu8; 64];
        zeroize_bytes(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn zeroizing_drop_runs() {
        // We can't observe freed memory portably, but we can confirm the Drop
        // path compiles and `into_inner` bypasses it.
        let z = Zeroizing::new([1u8, 2, 3, 4]);
        let inner = z.into_inner();
        assert_eq!(inner, [1, 2, 3, 4]);
    }

    #[test]
    fn secret_debug_is_redacted() {
        let s = Secret::from_bytes([7u8; 16]);
        assert_eq!(alloc::format!("{s:?}"), "Secret<16>(<redacted>)");
    }

    #[test]
    fn secret_eq_is_value_based() {
        assert_eq!(Secret::from_bytes([9u8; 32]), Secret::from_bytes([9u8; 32]));
        assert_ne!(Secret::from_bytes([9u8; 32]), Secret::from_bytes([8u8; 32]));
    }
}
