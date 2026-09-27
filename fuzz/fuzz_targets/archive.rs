//! Folder-archive listing must never panic, and never accept an unsafe path.
#![no_main]
use easylock_core::container::archive;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(entries) = archive::list(&mut &data[..]) {
        for e in entries {
            assert!(!e.path.is_empty());
            assert!(!e.path.starts_with('/'));
            assert!(!e.path.split('/').any(|p| p.is_empty() || p == ".." || p == "."));
            assert!(!e.path.contains(['\\', ':', '\0']));
        }
    }
});
