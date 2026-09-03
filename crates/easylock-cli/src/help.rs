//! Runtime localization of clap's generated `--help` / `--version` output.
//!
//! The command *structure* still comes from the `#[derive(Parser)]` types in
//! `main.rs`. Here we:
//!
//! 1. replace every `about` / argument `help` string with the English or Turkish
//!    version,
//! 2. disable clap's built-in `--help` / `--version` handling and add our own
//!    global flags, so `main` can render help itself and translate the few
//!    structural labels clap hard-codes (`Usage:`, `Options:`, ...).

use crate::i18n::Lang;
use clap::{Arg, ArgAction, ArgMatches, Command};

/// Pick the string for the active language.
fn t(lang: Lang, en: &'static str, tr: &'static str) -> &'static str {
    match lang {
        Lang::En => en,
        Lang::Tr => tr,
    }
}

fn localize_file_args(sc: Command, lang: Lang) -> Command {
    sc.mut_arg("input", |a| {
        a.help(t(
            lang,
            "Input file (omitted or `-` = stdin)",
            "Girdi dosyası (belirtilmezse veya `-` ise stdin)",
        ))
    })
    .mut_arg("output", |a| {
        a.help(t(
            lang,
            "Output file (omitted or `-` = stdout)",
            "Çıktı dosyası (belirtilmezse veya `-` ise stdout)",
        ))
    })
}

fn localize_crypt(sc: Command, lang: Lang, encrypt: bool) -> Command {
    let about = if encrypt {
        t(
            lang,
            "Encrypt data (AEAD output is `ciphertext||tag`)",
            "Veriyi şifrele (AEAD çıktısı `şifreli metin||etiket` biçimindedir)",
        )
    } else {
        t(
            lang,
            "Decrypt data produced by `easylock encrypt`",
            "`easylock encrypt` ile üretilmiş veriyi çöz",
        )
    };
    localize_file_args(sc, lang)
        .about(about)
        .mut_arg("cipher", |a| {
            a.help(t(
                lang,
                "Cipher: aes-256-gcm, chacha20-poly1305, aes-256-ctr, xor",
                "Şifre: aes-256-gcm, chacha20-poly1305, aes-256-ctr, xor",
            ))
        })
        .mut_arg("key", |a| {
            a.help(t(
                lang,
                "Key as hex (32 bytes for AES/ChaCha; any length for xor)",
                "Onaltılık anahtar (AES/ChaCha için 32 bayt; xor için herhangi bir uzunluk)",
            ))
        })
        .mut_arg("key_file", |a| {
            a.help(t(
                lang,
                "Read the raw key bytes from a file",
                "Ham anahtar baytlarını bir dosyadan oku",
            ))
        })
        .mut_arg("nonce", |a| {
            a.help(t(
                lang,
                "Nonce/IV as hex. Required to decrypt; auto-generated when encrypting",
                "Onaltılık nonce/IV. Şifre çözmek için gerekli; şifrelerken otomatik üretilir",
            ))
        })
        .mut_arg("aad", |a| {
            a.help(t(
                lang,
                "Additional authenticated data as hex (AEAD ciphers only)",
                "Onaltılık ek kimlik doğrulama verisi (yalnızca AEAD şifreleri)",
            ))
        })
        .mut_arg("armor", |a| {
            a.help(t(
                lang,
                "Base64-armor the output (encrypt) / expect Base64 input (decrypt)",
                "Çıktıyı Base64 ile sarmala (şifrele) / Base64 girdisi bekle (çöz)",
            ))
        })
}

/// Recursively drop clap's built-in help flag / help subcommand so we can supply
/// our own translated versions.
fn disable_builtin_help(cmd: Command) -> Command {
    let names: Vec<String> = cmd
        .get_subcommands()
        .map(|c| c.get_name().to_string())
        .collect();
    let mut cmd = cmd
        .disable_help_flag(true)
        .disable_version_flag(true)
        .disable_help_subcommand(true);
    for n in names {
        cmd = cmd.mut_subcommand(n, disable_builtin_help);
    }
    cmd
}

/// Build the fully-localized top-level command.
// This is a flat translation table; splitting it up only scatters the strings.
#[allow(clippy::too_many_lines)]
pub fn localized_command(base: Command, lang: Lang) -> Command {
    let base = disable_builtin_help(base)
        // `main` renders help itself (localized) when no subcommand is given.
        .subcommand_required(false)
        .arg(
            Arg::new("help")
                .short('h')
                .long("help")
                .global(true)
                .action(ArgAction::SetTrue)
                .help(t(lang, "Print help", "Yardımı göster")),
        )
        .arg(
            Arg::new("version")
                .short('V')
                .long("version")
                .global(true)
                .action(ArgAction::SetTrue)
                .help(t(lang, "Print version", "Sürümü göster")),
        );

    let cmd = base
        .about(t(
            lang,
            "easylock — a from-scratch cryptography toolkit",
            "easylock — sıfırdan yazılmış bir kriptografi araç seti",
        ))
        .after_help(match lang {
            Lang::En => format!(
                "Active language: {} · switch with --lang tr|en or the LANG / LC_ALL locale.\n\
                 All commands stream stdin -> stdout and accept files with -o.",
                lang.endonym()
            ),
            Lang::Tr => format!(
                "Etkin dil: {} · --lang tr|en ile ya da LANG / LC_ALL yerel ayarıyla değiştirin.\n\
                 Tüm komutlar stdin -> stdout akışını destekler; dosyalar için -o kullanın.",
                lang.endonym()
            ),
        })
        .mut_arg("lang", |a| {
            a.help(t(
                lang,
                "Interface language for messages and help: `tr` or `en`",
                "Mesajlar ve yardım için arayüz dili: `tr` veya `en`",
            ))
        });

    cmd.mut_subcommand("hash", |sc| {
        localize_file_args(sc, lang)
            .about(t(
                lang,
                "Hash data with SHA-256/512, Keccak-256 or SHA3-256",
                "Veriyi SHA-256/512, Keccak-256 veya SHA3-256 ile özetle",
            ))
            .mut_arg("algo", |a| {
                a.help(t(
                    lang,
                    "Hash algorithm: sha256, sha512, keccak256, sha3-256, blake3",
                    "Özet algoritması: sha256, sha512, keccak256, sha3-256, blake3",
                ))
            })
            .mut_arg("encoding", |a| {
                a.help(t(
                    lang,
                    "Digest output encoding: hex, base64 or raw",
                    "Özet çıktı kodlaması: hex, base64 veya raw",
                ))
            })
    })
    .mut_subcommand("encode", |sc| {
        localize_file_args(sc, lang)
            .about(t(
                lang,
                "Encode bytes to text (hex/base64/base64url/base58/rot13), chainable",
                "Baytları metne kodla (hex/base64/base64url/base58/rot13), zincirlenebilir",
            ))
            .mut_arg("transform", |a| {
                a.help(t(
                    lang,
                    "Transform(s), comma-separated; applied left to right (e.g. base64,hex)",
                    "Dönüşüm(ler), virgülle ayrılır; soldan sağa uygulanır (örn. base64,hex)",
                ))
            })
            .mut_arg("newline", |a| {
                a.help(t(
                    lang,
                    "Append a trailing newline when writing text to stdout",
                    "stdout'a metin yazarken sona satır sonu ekle",
                ))
            })
    })
    .mut_subcommand("decode", |sc| {
        localize_file_args(sc, lang)
            .about(t(
                lang,
                "Decode text back to bytes (reverses an `encode` pipeline)",
                "Metni baytlara geri çöz (`encode` işlem hattını tersine çevirir)",
            ))
            .mut_arg("transform", |a| {
                a.help(t(
                    lang,
                    "The same transform spec used to encode; it is reversed automatically",
                    "Kodlarken kullanılan dönüşüm dizisi; otomatik olarak tersine çevrilir",
                ))
            })
    })
    .mut_subcommand("encrypt", |sc| localize_crypt(sc, lang, true))
    .mut_subcommand("decrypt", |sc| localize_crypt(sc, lang, false))
}

/// `true` if `-h/--help` (or `-V/--version`) was passed at any nesting level.
pub fn wants_help(m: &ArgMatches) -> bool {
    flag_set(m, "help")
}

pub fn wants_version(m: &ArgMatches) -> bool {
    flag_set(m, "version")
}

fn flag_set(m: &ArgMatches, name: &str) -> bool {
    if m.try_get_one::<bool>(name)
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false)
    {
        return true;
    }
    m.subcommand().is_some_and(|(_, s)| flag_set(s, name))
}

/// Render the help text for whichever (sub)command `-h` was attached to,
/// translating clap's hard-coded section labels.
pub fn render_localized_help(root: &mut Command, m: &ArgMatches, lang: Lang) -> String {
    let mut path = vec![root.get_name().to_string()];
    collect_path(m, &mut path);
    let target = locate(root, m);
    target.set_bin_name(path.join(" "));
    let raw = target.render_long_help().to_string();
    localize_labels(&raw, lang)
}

fn collect_path(m: &ArgMatches, path: &mut Vec<String>) {
    if let Some((name, sub_m)) = m.subcommand() {
        path.push(name.to_string());
        collect_path(sub_m, path);
    }
}

/// Descend to the deepest named (sub)command in `m`; `-h` there means "help for
/// this context".
fn locate<'a>(cmd: &'a mut Command, m: &ArgMatches) -> &'a mut Command {
    if let Some((name, sub_m)) = m.subcommand() {
        if cmd.find_subcommand(name).is_some() {
            return locate(cmd.find_subcommand_mut(name).unwrap(), sub_m);
        }
    }
    cmd
}

fn localize_labels(s: &str, lang: Lang) -> String {
    match lang {
        Lang::En => s.to_string(),
        Lang::Tr => s
            .replace("Usage:", "Kullanım:")
            .replace("Commands:", "Komutlar:")
            .replace("Arguments:", "Bağımsız değişkenler:")
            .replace("Options:", "Seçenekler:")
            .replace("[default:", "[varsayılan:")
            .replace("[possible values:", "[olası değerler:")
            .replace("[aliases:", "[takma adlar:")
            .replace(
                "Print this message or the help of the given subcommand(s)",
                "Bu iletiyi veya verilen alt komutların yardımını göster",
            ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn turkish_help_renders_turkish_about_and_labels() {
        let mut cmd = localized_command(crate::Cli::command(), Lang::Tr);
        let help = localize_labels(&cmd.render_long_help().to_string(), Lang::Tr);
        assert!(help.contains("kriptografi araç seti"), "{help}");
        assert!(help.contains("Kullanım:"));
        assert!(help.contains("Komutlar:"));
        assert!(help.contains("Seçenekler:"));
    }

    #[test]
    fn english_help_stays_english() {
        let mut cmd = localized_command(crate::Cli::command(), Lang::En);
        let help = cmd.render_long_help().to_string();
        assert!(help.contains("from-scratch cryptography toolkit"));
        assert!(help.contains("Usage:"));
    }

    #[test]
    fn subcommand_help_is_localized() {
        let mut cmd = localized_command(crate::Cli::command(), Lang::Tr);
        let sub = cmd.find_subcommand_mut("encrypt").unwrap();
        let help = localize_labels(&sub.render_long_help().to_string(), Lang::Tr);
        assert!(help.contains("Veriyi şifrele"), "{help}");
        assert!(help.contains("Onaltılık anahtar"));
    }
}
