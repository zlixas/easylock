//! ELK1/ELK2 header parsing and `inspect` must never panic on arbitrary input.
#![no_main]
use easylock_core::container::{elk2, stream};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = stream::inspect(data);
    if let Ok((h, len)) = elk2::Header::parse(data) {
        assert!(len <= data.len());
        let _ = (h.is_archive(), h.password_slots(), h.recipient_slots());
    }
});
