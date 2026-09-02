//! Minimal internationalization: an enum of message keys resolved to English or
//! Turkish. No runtime dependency; the table is a `match`.

use std::fmt;

/// Supported UI languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Tr,
}

impl Lang {
    /// Parse a `--lang` value.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "en" | "english" | "en-us" | "en_us" => Some(Lang::En),
            "tr" | "turkish" | "türkçe" | "turkce" | "tr-tr" | "tr_tr" => Some(Lang::Tr),
            _ => None,
        }
    }

    /// Detect from the POSIX locale environment, defaulting to English.
    ///
    /// Checks `LC_ALL`, `LC_MESSAGES`, `LANG`, then `LANGUAGE` in that order; a
    /// value like `tr_TR.UTF-8` (or `tr`) selects Turkish.
    pub fn detect() -> Self {
        for var in ["LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"] {
            if let Ok(v) = std::env::var(var) {
                let lower = v.to_ascii_lowercase();
                if lower.starts_with("tr") {
                    return Lang::Tr;
                }
                if lower.starts_with("en") {
                    return Lang::En;
                }
            }
        }
        Lang::En
    }

    /// Resolve the UI language: an explicit `--lang` value wins, otherwise the
    /// system locale, otherwise English. An unrecognized `--lang` value falls
    /// back to detection (clap validates the flag separately and will report it).
    pub fn resolve(lang_flag: Option<&str>) -> Self {
        lang_flag.and_then(Lang::parse).unwrap_or_else(Lang::detect)
    }

    /// The locale's own name, for `--help` footers.
    pub fn endonym(self) -> &'static str {
        match self {
            Lang::En => "English",
            Lang::Tr => "Türkçe",
        }
    }
}

/// Scan a raw argument vector for `--lang <v>` / `--lang=<v>` before clap runs,
/// so `--help` can be rendered in the requested language.
pub fn prescan_lang<S: AsRef<std::ffi::OsStr>>(args: &[S]) -> Lang {
    let mut it = args.iter().map(|s| s.as_ref().to_string_lossy());
    while let Some(a) = it.next() {
        if let Some(v) = a.strip_prefix("--lang=") {
            return Lang::resolve(Some(v));
        }
        if a == "--lang" {
            if let Some(v) = it.next() {
                return Lang::resolve(Some(&v));
            }
        }
    }
    Lang::detect()
}

/// A translatable message.
#[derive(Debug, Clone)]
pub enum Msg {
    UnknownAlgorithm(String),
    UnknownTransform(String),
    UnknownCipher(String),
    KeyRequired,
    BadKeyLength { expected: usize, got: usize },
    NonceRequired { bytes: usize },
    BadNonceLength { expected: usize, got: usize },
    AuthenticationFailed,
    InvalidInputEncoding(String),
    ReadError(String),
    WriteError(String),
    RandomError(String),
    GeneratedNonce(String),
    Encrypted { target: String, cipher: String },
    Decrypted { target: String, cipher: String },
}

impl Msg {
    pub fn text(&self, lang: Lang) -> String {
        match (lang, self) {
            (Lang::En, Msg::UnknownAlgorithm(a)) => format!("unknown hash algorithm: {a}"),
            (Lang::Tr, Msg::UnknownAlgorithm(a)) => format!("bilinmeyen özet algoritması: {a}"),

            (Lang::En, Msg::UnknownTransform(t)) => format!("unknown transform: {t}"),
            (Lang::Tr, Msg::UnknownTransform(t)) => format!("bilinmeyen dönüşüm: {t}"),

            (Lang::En, Msg::UnknownCipher(c)) => format!("unknown cipher: {c}"),
            (Lang::Tr, Msg::UnknownCipher(c)) => format!("bilinmeyen şifre: {c}"),

            (Lang::En, Msg::KeyRequired) => {
                "a key is required (--key <hex> or --key-file <path>)".into()
            }
            (Lang::Tr, Msg::KeyRequired) => {
                "bir anahtar gerekli (--key <hex> veya --key-file <yol>)".into()
            }

            (Lang::En, Msg::BadKeyLength { expected, got }) => {
                format!("key must be {expected} bytes, got {got}")
            }
            (Lang::Tr, Msg::BadKeyLength { expected, got }) => {
                format!("anahtar {expected} bayt olmalı, {got} alındı")
            }

            (Lang::En, Msg::NonceRequired { bytes }) => {
                format!("a {bytes}-byte nonce is required for decryption (--nonce <hex>)")
            }
            (Lang::Tr, Msg::NonceRequired { bytes }) => {
                format!("şifre çözme için {bytes} baytlık bir nonce gerekli (--nonce <hex>)")
            }

            (Lang::En, Msg::BadNonceLength { expected, got }) => {
                format!("nonce must be {expected} bytes, got {got}")
            }
            (Lang::Tr, Msg::BadNonceLength { expected, got }) => {
                format!("nonce {expected} bayt olmalı, {got} alındı")
            }

            (Lang::En, Msg::AuthenticationFailed) => {
                "authentication failed: wrong key/nonce or the data was modified".into()
            }
            (Lang::Tr, Msg::AuthenticationFailed) => {
                "kimlik doğrulama başarısız: yanlış anahtar/nonce ya da veri değiştirilmiş".into()
            }

            (Lang::En, Msg::InvalidInputEncoding(s)) => format!("invalid {s} input"),
            (Lang::Tr, Msg::InvalidInputEncoding(s)) => format!("geçersiz {s} girdisi"),

            (Lang::En, Msg::ReadError(e)) => format!("read error: {e}"),
            (Lang::Tr, Msg::ReadError(e)) => format!("okuma hatası: {e}"),

            (Lang::En, Msg::WriteError(e)) => format!("write error: {e}"),
            (Lang::Tr, Msg::WriteError(e)) => format!("yazma hatası: {e}"),

            (Lang::En, Msg::RandomError(e)) => format!("could not read system randomness: {e}"),
            (Lang::Tr, Msg::RandomError(e)) => format!("sistem rastgeleliği okunamadı: {e}"),

            (Lang::En, Msg::GeneratedNonce(n)) => format!("generated nonce (hex): {n}"),
            (Lang::Tr, Msg::GeneratedNonce(n)) => format!("üretilen nonce (hex): {n}"),

            (Lang::En, Msg::Encrypted { target, cipher }) => {
                format!("encrypted: {target} (used {cipher})")
            }
            (Lang::Tr, Msg::Encrypted { target, cipher }) => {
                format!("şifrelendi: {target} ({cipher} kullanıldı)")
            }

            (Lang::En, Msg::Decrypted { target, cipher }) => {
                format!("decrypted: {target} (used {cipher})")
            }
            (Lang::Tr, Msg::Decrypted { target, cipher }) => {
                format!("şifre çözüldü: {target} ({cipher} kullanıldı)")
            }
        }
    }
}

/// A CLI error carrying a translatable message.
#[derive(Debug)]
pub struct CliError {
    pub msg: Msg,
}

impl CliError {
    pub fn new(msg: Msg) -> Self {
        Self { msg }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display uses English; `main` re-renders in the selected language.
        write!(f, "{}", self.msg.text(Lang::En))
    }
}

impl std::error::Error for CliError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_detect() {
        assert_eq!(Lang::parse("TR"), Some(Lang::Tr));
        assert_eq!(Lang::parse("en-US"), Some(Lang::En));
        assert_eq!(Lang::parse("de"), None);
    }

    #[test]
    fn turkish_differs_from_english() {
        let m = Msg::AuthenticationFailed;
        assert_ne!(m.text(Lang::En), m.text(Lang::Tr));
    }
}
