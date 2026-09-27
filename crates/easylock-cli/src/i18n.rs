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
    OutputExists(String),
    NeedIdentity,
    IdentityExists(String),
    IdentityMissing(String),
    BadRecipient(String),
    OneOutputOnly,
    StdinNeedsKey,
    FolderToStdout,
    Shredded(String),
    ShredSkipped(String),
    ArchiveSummary { files: u64, dirs: u64, size: String },
    SlotsSummary { recipients: usize, password: bool },
    SomeFailed(usize),
    SkippedSpecial(u64),
    Vault(String),
    VaultCreated(String),
    VaultAdded { files: u64, size: String },
    VaultRemoved(usize),
    VaultMissing(String),
    VaultRekeyed,
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
            Msg::OutputExists(path) => match lang {
                Lang::En => format!("{path} already exists (use --force to replace it)"),
                Lang::Tr => format!("{path} zaten var (değiştirmek için --force kullanın)"),
                Lang::Es => format!("{path} ya existe (use --force para reemplazarlo)"),
            },
            Msg::NeedIdentity => p([
                "this file is encrypted to a public key: pass your identity with -i FILE (create one with `easylock identity`)",
                "bu dosya bir açık anahtara şifrelenmiş: kimliğinizi -i DOSYA ile verin (`easylock identity` ile oluşturabilirsiniz)",
                "este archivo está cifrado para una clave pública: indique su identidad con -i ARCHIVO (créela con `easylock identity`)",
            ]),
            Msg::IdentityExists(path) => match lang {
                Lang::En => format!("an identity already exists at {path} (use --force to replace it — the old key will be lost)"),
                Lang::Tr => format!("{path} konumunda zaten bir kimlik var (değiştirmek için --force; eski anahtar kaybolur)"),
                Lang::Es => format!("ya existe una identidad en {path} (use --force para reemplazarla; la clave anterior se perderá)"),
            },
            Msg::IdentityMissing(path) => match lang {
                Lang::En => format!("no identity found at {path} — create one with `easylock identity`"),
                Lang::Tr => format!("{path} konumunda kimlik yok — `easylock identity` ile oluşturun"),
                Lang::Es => format!("no hay identidad en {path}: créela con `easylock identity`"),
            },
            Msg::BadRecipient(r) => format!(
                "{}: {r}",
                lang.pick([
                    "not a valid recipient (expected an elkpub1… key or a file containing one)",
                    "geçerli bir alıcı değil (elkpub1… anahtarı veya onu içeren bir dosya bekleniyor)",
                    "destinatario no válido (se espera una clave elkpub1… o un archivo que la contenga)",
                ])
            ),
            Msg::OneOutputOnly => p([
                "-o/--output can only be used with a single input",
                "-o/--output yalnızca tek bir girdiyle kullanılabilir",
                "-o/--output solo se puede usar con una única entrada",
            ]),
            Msg::StdinNeedsKey => p([
                "when reading from stdin, pass -r/--recipient, --password or EASYLOCK_PASSWORD",
                "stdin'den okurken -r/--recipient, --password veya EASYLOCK_PASSWORD verin",
                "al leer de stdin, indique -r/--recipient, --password o EASYLOCK_PASSWORD",
            ]),
            Msg::FolderToStdout => p([
                "an encrypted folder can't be written to stdout; use -o DIR or --list",
                "şifreli bir klasör stdout'a yazılamaz; -o KLASÖR veya --list kullanın",
                "una carpeta cifrada no se puede escribir en stdout; use -o DIR o --list",
            ]),
            Msg::Shredded(path) => match lang {
                Lang::En => format!("original overwritten and removed: {path} (on SSDs and copy-on-write filesystems old blocks may survive)"),
                Lang::Tr => format!("orijinalin üzerine yazıldı ve silindi: {path} (SSD'lerde ve yazarken-kopyala dosya sistemlerinde eski bloklar kalabilir)"),
                Lang::Es => format!("original sobrescrito y eliminado: {path} (en SSD y sistemas copy-on-write pueden quedar bloques antiguos)"),
            },
            Msg::ShredSkipped(path) => match lang {
                Lang::En => format!("{path} contains symlinks or special files that were not archived — the original was kept"),
                Lang::Tr => format!("{path} arşivlenmeyen sembolik bağlar veya özel dosyalar içeriyor — orijinal korundu"),
                Lang::Es => format!("{path} contiene enlaces simbólicos o archivos especiales no archivados; se conservó el original"),
            },
            Msg::ArchiveSummary { files, dirs, size } => match lang {
                Lang::En => format!("{files} files, {dirs} folders, {size}"),
                Lang::Tr => format!("{files} dosya, {dirs} klasör, {size}"),
                Lang::Es => format!("{files} archivos, {dirs} carpetas, {size}"),
            },
            Msg::SlotsSummary { recipients, password } => {
                let mut parts = Vec::new();
                if *recipients > 0 {
                    parts.push(match lang {
                        Lang::En => format!("{recipients} recipient(s)"),
                        Lang::Tr => format!("{recipients} alıcı"),
                        Lang::Es => format!("{recipients} destinatario(s)"),
                    });
                }
                if *password {
                    parts.push(p(["password", "parola", "contraseña"]));
                }
                format!("{} {}", p(["unlockable by:", "açabilen:", "se abre con:"]), parts.join(" + "))
            }
            Msg::Vault(e) => format!("{}: {e}", p(["vault error", "kasa hatası", "error del almacén"])),
            Msg::VaultCreated(path) => match lang {
                Lang::En => format!("vault created: {path} (add files with `easylock vault add {path} FILE…`)"),
                Lang::Tr => format!("kasa oluşturuldu: {path} (`easylock vault add {path} DOSYA…` ile dosya ekleyin)"),
                Lang::Es => format!("almacén creado: {path} (añada archivos con `easylock vault add {path} ARCHIVO…`)"),
            },
            Msg::VaultAdded { files, size } => match lang {
                Lang::En => format!("added {files} file(s), {size}: stored encrypted"),
                Lang::Tr => format!("{files} dosya eklendi, {size}: şifreli olarak saklanıyor"),
                Lang::Es => format!("{files} archivo(s) añadido(s), {size}: guardados cifrados"),
            },
            Msg::VaultRemoved(n) => match lang {
                Lang::En => format!("removed {n} file(s) from the vault"),
                Lang::Tr => format!("kasadan {n} dosya silindi"),
                Lang::Es => format!("{n} archivo(s) eliminado(s) del almacén"),
            },
            Msg::VaultMissing(name) => match lang {
                Lang::En => format!("not in the vault: {name}"),
                Lang::Tr => format!("kasada yok: {name}"),
                Lang::Es => format!("no está en el almacén: {name}"),
            },
            Msg::VaultRekeyed => p([
                "vault unlock keys changed (stored files are untouched)",
                "kasa açma anahtarları değişti (saklanan dosyalara dokunulmadı)",
                "claves de apertura cambiadas (los archivos guardados no se tocan)",
            ]),
            Msg::SkippedSpecial(n) => match lang {
                Lang::En => format!("warning: {n} symlink(s) or special file(s) were not included"),
                Lang::Tr => format!("uyarı: {n} sembolik bağ veya özel dosya dahil edilmedi"),
                Lang::Es => format!("aviso: no se incluyeron {n} enlace(s) simbólico(s) o archivo(s) especial(es)"),
            },
            Msg::SomeFailed(n) => match lang {
                Lang::En => format!("{n} item(s) failed"),
                Lang::Tr => format!("{n} öğe başarısız oldu"),
                Lang::Es => format!("{n} elemento(s) fallaron"),
            },
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
