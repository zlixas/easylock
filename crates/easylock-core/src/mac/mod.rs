//! Message authentication codes: HMAC (FIPS 198-1) and Poly1305 (RFC 8439).

pub mod hmac;
pub mod poly1305;

pub use hmac::Hmac;
pub use poly1305::Poly1305;
