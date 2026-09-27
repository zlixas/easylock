//! Internationalization for the CLI and TUI: English, Turkish, Spanish.
//!
//! No runtime dependency — every string is a `[en, tr, es]` triple resolved by
//! [`Lang::pick`].

use std::fmt;

/// Supported UI languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Tr,
    Es,
}

impl Lang {
    /// All languages, in toggle order.
    pub const ALL: [Lang; 3] = [Lang::En, Lang::Tr, Lang::Es];

    /// Parse a `--lang` value.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "en" | "english" | "en-us" | "en-gb" => Some(Lang::En),
            "tr" | "turkish" | "türkçe" | "turkce" | "tr-tr" => Some(Lang::Tr),
            "es" | "spanish" | "español" | "espanol" | "es-es" | "es-mx" => Some(Lang::Es),
            _ => None,
        }
    }

    /// Detect from the POSIX locale environment, defaulting to English.
    ///
    /// Checks `LC_ALL`, `LC_MESSAGES`, `LANG`, then `LANGUAGE`; a value like
    /// `tr_TR.UTF-8` selects Turkish, `es_ES.UTF-8` Spanish.
    pub fn detect() -> Self {
        for var in ["LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"] {
            if let Ok(v) = std::env::var(var) {
                let lower = v.to_ascii_lowercase();
                if lower.starts_with("tr") {
                    return Lang::Tr;
                }
                if lower.starts_with("es") {
                    return Lang::Es;
                }
                if lower.starts_with("en") {
                    return Lang::En;
                }
            }
        }
        Lang::En
    }

    /// Explicit `--lang` wins, then the system locale, then English.
    pub fn resolve(lang_flag: Option<&str>) -> Self {
        lang_flag.and_then(Lang::parse).unwrap_or_else(Lang::detect)
    }

    /// The language's own name.
    pub fn endonym(self) -> &'static str {
        match self {
            Lang::En => "English",
            Lang::Tr => "Türkçe",
            Lang::Es => "Español",
        }
    }

    /// Short code (`en` / `tr` / `es`).
    pub fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Tr => "tr",
            Lang::Es => "es",
        }
    }

    /// Next language in toggle order (used by the TUI).
    pub fn next(self) -> Self {
        match self {
            Lang::En => Lang::Tr,
            Lang::Tr => Lang::Es,
            Lang::Es => Lang::En,
        }
    }

    /// Select the string for this language from an `[en, tr, es]` triple.
    pub fn pick<T: Copy>(self, [en, tr, es]: [T; 3]) -> T {
        match self {
            Lang::En => en,
            Lang::Tr => tr,
            Lang::Es => es,
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
    UnknownKeyKind(String),
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
    Crypto(String),
    BadPasswordSpec,
    SignatureValid,
    SignatureInvalid,
    TerminalError(String),
    PasswordMatches,
    PasswordMismatch,
    PasswordsDiffer,
    PasswordEmpty,
}

impl Msg {
    #[allow(clippy::too_many_lines)] // a flat three-language table
    pub fn text(&self, lang: Lang) -> String {
        let p = |t: [&str; 3]| lang.pick(t).to_string();
        match self {
            Msg::UnknownAlgorithm(a) => format!(
                "{}: {a}",
                lang.pick([
                    "unknown hash algorithm",
                    "bilinmeyen özet algoritması",
                    "algoritmo de hash desconocido"
                ])
            ),
            Msg::UnknownTransform(t) => format!(
                "{}: {t}",
                lang.pick([
                    "unknown transform",
                    "bilinmeyen dönüşüm",
                    "transformación desconocida"
                ])
            ),
            Msg::UnknownCipher(c) => format!(
                "{}: {c}",
                lang.pick(["unknown cipher", "bilinmeyen şifre", "cifrado desconocido"])
            ),
            Msg::UnknownKeyKind(k) => format!(
                "{}: {k} (ed25519, x25519, mlkem512, mlkem768, mlkem1024, rsa2048)",
                lang.pick([
                    "unknown key type",
                    "bilinmeyen anahtar türü",
                    "tipo de clave desconocido"
                ])
            ),
            Msg::KeyRequired => p([
                "a key is required (--key <hex> or --key-file <path>)",
                "bir anahtar gerekli (--key <hex> veya --key-file <yol>)",
                "se requiere una clave (--key <hex> o --key-file <ruta>)",
            ]),
            Msg::BadKeyLength { expected, got } => match lang {
                Lang::En => format!("key must be {expected} bytes, got {got}"),
                Lang::Tr => format!("anahtar {expected} bayt olmalı, {got} alındı"),
                Lang::Es => format!("la clave debe tener {expected} bytes, se recibieron {got}"),
            },
            Msg::NonceRequired { bytes } => match lang {
                Lang::En => {
                    format!("a {bytes}-byte nonce is required for decryption (--nonce <hex>)")
                }
                Lang::Tr => {
                    format!("şifre çözme için {bytes} baytlık bir nonce gerekli (--nonce <hex>)")
                }
                Lang::Es => {
                    format!("se requiere un nonce de {bytes} bytes para descifrar (--nonce <hex>)")
                }
            },
            Msg::BadNonceLength { expected, got } => match lang {
                Lang::En => format!("nonce must be {expected} bytes, got {got}"),
                Lang::Tr => format!("nonce {expected} bayt olmalı, {got} alındı"),
                Lang::Es => format!("el nonce debe tener {expected} bytes, se recibieron {got}"),
            },
            Msg::AuthenticationFailed => p([
                "authentication failed: wrong key/nonce or the data was modified",
                "kimlik doğrulama başarısız: yanlış anahtar/nonce ya da veri değiştirilmiş",
                "autenticación fallida: clave/nonce incorrectos o los datos fueron modificados",
            ]),
            Msg::InvalidInputEncoding(s) => match lang {
                Lang::En => format!("invalid {s} input"),
                Lang::Tr => format!("geçersiz {s} girdisi"),
                Lang::Es => format!("entrada {s} no válida"),
            },
            Msg::ReadError(e) => format!(
                "{}: {e}",
                lang.pick(["read error", "okuma hatası", "error de lectura"])
            ),
            Msg::WriteError(e) => format!(
                "{}: {e}",
                lang.pick(["write error", "yazma hatası", "error de escritura"])
            ),
            Msg::RandomError(e) => format!(
                "{}: {e}",
                lang.pick([
                    "could not read system randomness",
                    "sistem rastgeleliği okunamadı",
                    "no se pudo leer la aleatoriedad del sistema",
                ])
            ),
            Msg::GeneratedNonce(n) => format!(
                "{}: {n}",
                lang.pick([
                    "generated nonce (hex)",
                    "üretilen nonce (hex)",
                    "nonce generado (hex)"
                ])
            ),
            Msg::Encrypted { target, cipher } => match lang {
                Lang::En => format!("encrypted: {target} (used {cipher})"),
                Lang::Tr => format!("şifrelendi: {target} ({cipher} kullanıldı)"),
                Lang::Es => format!("cifrado: {target} (se usó {cipher})"),
            },
            Msg::Decrypted { target, cipher } => match lang {
                Lang::En => format!("decrypted: {target} (used {cipher})"),
                Lang::Tr => format!("şifre çözüldü: {target} ({cipher} kullanıldı)"),
                Lang::Es => format!("descifrado: {target} (se usó {cipher})"),
            },
            Msg::Crypto(e) => format!(
                "{}: {e}",
                lang.pick(["crypto error", "kripto hatası", "error criptográfico"])
            ),
            Msg::BadPasswordSpec => p([
                "choose at least one character class and a length between 4 and 256",
                "en az bir karakter sınıfı ve 4–256 arası bir uzunluk seçin",
                "elija al menos una clase de caracteres y una longitud entre 4 y 256",
            ]),
            Msg::SignatureValid => p(["signature VALID", "imza GEÇERLİ", "firma VÁLIDA"]),
            Msg::SignatureInvalid => p(["signature INVALID", "imza GEÇERSİZ", "firma NO VÁLIDA"]),
            Msg::PasswordMatches => p([
                "password MATCHES",
                "parola EŞLEŞİYOR",
                "la contraseña COINCIDE",
            ]),
            Msg::PasswordMismatch => p([
                "password does NOT match",
                "parola EŞLEŞMİYOR",
                "la contraseña NO coincide",
            ]),
            Msg::PasswordsDiffer => p([
                "the passwords do not match",
                "parolalar eşleşmiyor",
                "las contraseñas no coinciden",
            ]),
            Msg::PasswordEmpty => p([
                "the password is empty",
                "parola boş",
                "la contraseña está vacía",
            ]),
            Msg::TerminalError(e) => format!(
                "{}: {e}",
                lang.pick(["terminal error", "terminal hatası", "error de terminal"])
            ),
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
    pub fn crypto(e: impl fmt::Display) -> Self {
        Self::new(Msg::Crypto(e.to_string()))
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
        assert_eq!(Lang::parse("es_ES"), Some(Lang::Es));
        assert_eq!(Lang::parse("de"), None);
    }

    #[test]
    fn all_languages_differ() {
        let m = Msg::AuthenticationFailed;
        let [en, tr, es] = Lang::ALL.map(|l| m.text(l));
        assert_ne!(en, tr);
        assert_ne!(en, es);
        assert_ne!(tr, es);
    }

    #[test]
    fn toggle_cycles_through_all() {
        assert_eq!(Lang::En.next().next().next(), Lang::En);
    }
}
