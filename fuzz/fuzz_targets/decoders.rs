//! Text decoders and key parsers must never panic; valid decodes must round-trip.
#![no_main]
use easylock_core::container::elk2::{Identity, Recipient};
use easylock_core::encode::{base58, base64, hex};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Ok(b) = hex::decode(s) {
        assert_eq!(hex::decode(&hex::encode(&b)).unwrap(), b);
    }
    for v in [base64::Variant::Standard, base64::Variant::UrlNoPad] {
        if let Ok(b) = base64::decode(s, v) {
            assert_eq!(base64::decode(&base64::encode(&b, v), v).unwrap(), b);
        }
    }
    if let Ok(b) = base58::decode(s) {
        assert_eq!(base58::decode(&base58::encode(&b)).unwrap(), b);
    }
    if let Ok(r) = Recipient::parse(s) {
        assert_eq!(Recipient::parse(&r.encode()).unwrap(), r);
    }
    let _ = Identity::parse(s);
});
