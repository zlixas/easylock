//! Runtime CPU-feature detection used to dispatch hardware-accelerated backends.
//!
//! Detection is done once and cached. On x86/x86-64 we look for AES-NI, PCLMULQDQ
//! (for GHASH), SSE2, and AVX2. On aarch64 we look for the `aes`, `pmull`, and
//! `sha2` extensions. Everything else falls back to portable software.
//!
//! The `force-portable` cargo feature disables all of this and always reports
//! "no acceleration", which is useful for differential testing.

/// Compile-time target architecture name.
pub const TARGET_ARCH: &str = {
    #[cfg(target_arch = "x86_64")]
    {
        "x86_64"
    }
    #[cfg(target_arch = "x86")]
    {
        "x86"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "aarch64"
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
    {
        "portable"
    }
};

/// Hardware features relevant to this library, resolved at runtime.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Features {
    /// AES round instructions (`AES-NI` on x86, `aes` on aarch64).
    pub aes: bool,
    /// Carry-less multiply (`PCLMULQDQ` / `PMULL`), needed for fast GHASH.
    pub clmul: bool,
    /// 256-bit vector integer ops (AVX2). Always `false` on non-x86.
    pub avx2: bool,
    /// SHA-2 message-schedule instructions.
    pub sha2: bool,
}

impl Features {
    /// `true` when an AES-GCM hardware path (round keys + GHASH) is available.
    #[must_use]
    pub const fn has_aes_gcm(self) -> bool {
        self.aes && self.clmul
    }
}

#[cfg(all(feature = "std", not(feature = "force-portable")))]
mod detect {
    use super::Features;
    use std::sync::OnceLock;

    static CACHE: OnceLock<Features> = OnceLock::new();

    pub fn features() -> Features {
        *CACHE.get_or_init(probe)
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn probe() -> Features {
        Features {
            aes: std::arch::is_x86_feature_detected!("aes"),
            clmul: std::arch::is_x86_feature_detected!("pclmulqdq"),
            avx2: std::arch::is_x86_feature_detected!("avx2"),
            sha2: std::arch::is_x86_feature_detected!("sha"),
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn probe() -> Features {
        Features {
            aes: std::arch::is_aarch64_feature_detected!("aes"),
            clmul: std::arch::is_aarch64_feature_detected!("pmull"),
            avx2: false,
            sha2: std::arch::is_aarch64_feature_detected!("sha2"),
        }
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    fn probe() -> Features {
        Features::default()
    }
}

#[cfg(not(all(feature = "std", not(feature = "force-portable"))))]
mod detect {
    use super::Features;

    /// Without `std` (or with `force-portable`) we can only trust
    /// statically-enabled target features.
    pub fn features() -> Features {
        Features {
            aes: cfg!(any(target_feature = "aes")),
            clmul: cfg!(any(target_feature = "pclmulqdq", target_feature = "aes")),
            avx2: cfg!(target_feature = "avx2"),
            sha2: cfg!(any(target_feature = "sha", target_feature = "sha2")),
        }
    }
}

/// Detected (and cached) hardware features for the running CPU.
#[must_use]
pub fn features() -> Features {
    detect::features()
}
