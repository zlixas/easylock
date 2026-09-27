//! Runtime localisation of clap's generated `--help` / `--version` output.
//!
//! The command *structure* comes from the `#[derive(Parser)]` types; here every
//! `about` and argument `help` string is swapped for the English, Turkish or
//! Spanish version, and clap's own section labels are translated after
//! rendering.

use crate::i18n::Lang;
use clap::{Arg, ArgAction, ArgMatches, Command};

type L3 = [&'static str; 3];

/// Set an argument's help text if the argument exists on this command.
fn arg_help(cmd: Command, id: &str, lang: Lang, text: L3) -> Command {
    if cmd.get_arguments().any(|a| a.get_id() == id) {
        cmd.mut_arg(id, |a| a.help(lang.pick(text)))
    } else {
        cmd
    }
}

const INPUT: L3 = [
    "Input file (omitted or `-` = stdin)",
    "Girdi dosyası (belirtilmezse veya `-` ise stdin)",
    "Archivo de entrada (omitido o `-` = stdin)",
];
const OUTPUT: L3 = [
    "Output file (omitted or `-` = stdout)",
    "Çıktı dosyası (belirtilmezse veya `-` ise stdout)",
    "Archivo de salida (omitido o `-` = stdout)",
];

/// `(subcommand, about, [(arg id, help)])`.
type SubSpec = (&'static str, L3, &'static [(&'static str, L3)]);

const SUBCOMMANDS: &[SubSpec] = &[
    (
        "hash",
        [
            "Hash data with SHA-256/512, SHA3-256, Keccak-256 or BLAKE3",
            "Veriyi SHA-256/512, SHA3-256, Keccak-256 veya BLAKE3 ile özetle",
            "Calcular hash con SHA-256/512, SHA3-256, Keccak-256 o BLAKE3",
        ],
        &[
            ("algo", [
                "Hash algorithm: sha256, sha512, keccak256, sha3-256, blake3",
                "Özet algoritması: sha256, sha512, keccak256, sha3-256, blake3",
                "Algoritmo de hash: sha256, sha512, keccak256, sha3-256, blake3",
            ]),
            ("encoding", [
                "Digest output encoding: hex, base64 or raw",
                "Özet çıktı kodlaması: hex, base64 veya raw",
                "Codificación de salida: hex, base64 o raw",
            ]),
        ],
    ),
    (
        "encode",
        [
            "Encode bytes to text (hex/base64/base64url/base58/rot13), chainable",
            "Baytları metne kodla (hex/base64/base64url/base58/rot13), zincirlenebilir",
            "Codificar bytes a texto (hex/base64/base64url/base58/rot13), encadenable",
        ],
        &[
            ("transform", [
                "Transform(s), comma-separated; applied left to right (e.g. base64,hex)",
                "Dönüşüm(ler), virgülle ayrılır; soldan sağa uygulanır (örn. base64,hex)",
                "Transformación(es) separadas por comas; de izquierda a derecha (p. ej. base64,hex)",
            ]),
            ("newline", [
                "Append a trailing newline when writing text to stdout",
                "stdout'a metin yazarken sona satır sonu ekle",
                "Añadir un salto de línea final al escribir en stdout",
            ]),
        ],
    ),
    (
        "decode",
        [
            "Decode text back to bytes (reverses an `encode` pipeline)",
            "Metni baytlara geri çöz (`encode` işlem hattını tersine çevirir)",
            "Decodificar texto a bytes (invierte una cadena de `encode`)",
        ],
        &[("transform", [
            "The same transform spec used to encode; it is reversed automatically",
            "Kodlarken kullanılan dönüşüm dizisi; otomatik olarak tersine çevrilir",
            "La misma cadena usada al codificar; se invierte automáticamente",
        ])],
    ),
    (
        "lock",
        [
            "Encrypt files or folders to a password and/or public keys (.elk)",
            "Dosya veya klasörleri parolaya ve/veya açık anahtarlara şifrele (.elk)",
            "Cifrar archivos o carpetas con contraseña y/o claves públicas (.elk)",
        ],
        &[
            ("inputs", [
                "Files or folders to encrypt (`-` = stdin)",
                "Şifrelenecek dosya veya klasörler (`-` = stdin)",
                "Archivos o carpetas a cifrar (`-` = stdin)",
            ]),
            ("output", [
                "Output file (default: PATH.elk; `-` = stdout). Single input only",
                "Çıktı dosyası (varsayılan: YOL.elk; `-` = stdout). Yalnızca tek girdi",
                "Archivo de salida (predeterminado: RUTA.elk; `-` = stdout). Solo una entrada",
            ]),
            ("cipher", ["aes-256-gcm or chacha20-poly1305", "aes-256-gcm veya chacha20-poly1305", "aes-256-gcm o chacha20-poly1305"]),
            ("recipients", [
                "Encrypt to a public key (elkpub1…) or a file of keys; repeatable",
                "Bir açık anahtara (elkpub1…) veya anahtar dosyasına şifrele; tekrarlanabilir",
                "Cifrar para una clave pública (elkpub1…) o un archivo de claves; repetible",
            ]),
            ("password", [
                "Password (prefer the prompt or EASYLOCK_PASSWORD)",
                "Parola (istem veya EASYLOCK_PASSWORD tercih edin)",
                "Contraseña (mejor el aviso o EASYLOCK_PASSWORD)",
            ]),
            ("with_password", [
                "With -r: also allow unlocking with a password",
                "-r ile: parolayla açmaya da izin ver",
                "Con -r: permitir también abrir con contraseña",
            ]),
            ("shred", [
                "After encrypting, overwrite and delete the original",
                "Şifreledikten sonra orijinalin üzerine yaz ve sil",
                "Tras cifrar, sobrescribir y borrar el original",
            ]),
            ("force", ["Replace an existing output file", "Var olan çıktı dosyasını değiştir", "Reemplazar un archivo de salida existente"]),
            ("quiet", ["No progress or status output", "İlerleme veya durum çıktısı yok", "Sin progreso ni mensajes de estado"]),
        ],
    ),
    (
        "unlock",
        ["Decrypt .elk files and folders", ".elk dosya ve klasörlerini çöz", "Descifrar archivos y carpetas .elk"],
        &[
            ("inputs", [".elk files to decrypt (`-` = stdin)", "Çözülecek .elk dosyaları (`-` = stdin)", "Archivos .elk a descifrar (`-` = stdin)"]),
            ("output", [
                "Output file or folder (default: FILE without .elk; `-` = stdout)",
                "Çıktı dosyası veya klasörü (varsayılan: .elk olmadan DOSYA; `-` = stdout)",
                "Archivo o carpeta de salida (predeterminado: ARCHIVO sin .elk; `-` = stdout)",
            ]),
            ("password", [
                "Password (prefer the prompt or EASYLOCK_PASSWORD)",
                "Parola (istem veya EASYLOCK_PASSWORD tercih edin)",
                "Contraseña (mejor el aviso o EASYLOCK_PASSWORD)",
            ]),
            ("identity", [
                "Identity file(s) for files encrypted to a public key; repeatable",
                "Açık anahtara şifrelenmiş dosyalar için kimlik dosyası; tekrarlanabilir",
                "Archivo(s) de identidad para archivos cifrados con clave pública; repetible",
            ]),
            ("list", ["List the contents instead of extracting", "Çıkarmak yerine içeriği listele", "Listar el contenido en lugar de extraer"]),
            ("force", ["Replace an existing output file", "Var olan çıktı dosyasını değiştir", "Reemplazar un archivo de salida existente"]),
            ("quiet", ["No progress or status output", "İlerleme veya durum çıktısı yok", "Sin progreso ni mensajes de estado"]),
        ],
    ),
    (
        "inspect",
        [
            "Show what an .elk file contains and how it can be unlocked",
            "Bir .elk dosyasının ne içerdiğini ve nasıl açılabileceğini göster",
            "Mostrar qué contiene un archivo .elk y cómo se puede abrir",
        ],
        &[("inputs", [".elk files (no password needed)", ".elk dosyaları (parola gerekmez)", "Archivos .elk (no requiere contraseña)"])],
    ),
    (
        "identity",
        [
            "Create (or show) your public-key identity",
            "Açık anahtar kimliğinizi oluşturun (veya gösterin)",
            "Crear (o mostrar) su identidad de clave pública",
        ],
        &[
            ("output", [
                "Where to write it (default: ~/.config/easylock/identity.key)",
                "Nereye yazılacağı (varsayılan: ~/.config/easylock/identity.key)",
                "Dónde guardarla (predeterminado: ~/.config/easylock/identity.key)",
            ]),
            ("show", [
                "Print the public key of an existing identity",
                "Var olan kimliğin açık anahtarını yazdır",
                "Mostrar la clave pública de una identidad existente",
            ]),
            ("identity", ["Identity file for --show", "--show için kimlik dosyası", "Archivo de identidad para --show"]),
            ("plain", [
                "Store the secret key without password protection",
                "Gizli anahtarı parola koruması olmadan sakla",
                "Guardar la clave secreta sin protección por contraseña",
            ]),
            ("force", [
                "Replace an existing identity (the old key is lost)",
                "Var olan kimliği değiştir (eski anahtar kaybolur)",
                "Reemplazar una identidad existente (se pierde la anterior)",
            ]),
        ],
    ),
    (
        "hmac",
        [
            "Compute a keyed message authentication code (HMAC)",
            "Anahtarlı mesaj doğrulama kodu (HMAC) hesapla",
            "Calcular un código de autenticación con clave (HMAC)",
        ],
        &[
            ("algo", ["Hash: sha256, sha512, sha3-256, keccak256", "Özet: sha256, sha512, sha3-256, keccak256", "Hash: sha256, sha512, sha3-256, keccak256"]),
            ("key", ["Key as hex", "Onaltılık anahtar", "Clave en hex"]),
            ("key_text", ["Key as UTF-8 text", "UTF-8 metin anahtar", "Clave como texto UTF-8"]),
        ],
    ),
    (
        "kdf",
        [
            "Hash a password / derive a key (Argon2id, PBKDF2)",
            "Parola özetle / anahtar türet (Argon2id, PBKDF2)",
            "Hash de contraseña / derivar clave (Argon2id, PBKDF2)",
        ],
        &[
            ("algo", ["argon2id (default) or pbkdf2", "argon2id (varsayılan) veya pbkdf2", "argon2id (predeterminado) o pbkdf2"]),
            ("password", ["Password (omit to read from stdin)", "Parola (belirtilmezse stdin'den okunur)", "Contraseña (omitir para leer de stdin)"]),
            ("salt", ["Salt as hex (random if omitted)", "Onaltılık tuz (belirtilmezse rastgele)", "Sal en hex (aleatoria si se omite)"]),
            ("memory", ["Argon2 memory in KiB", "Argon2 belleği (KiB)", "Memoria de Argon2 en KiB"]),
            ("iterations", ["Argon2 passes / PBKDF2 iterations", "Argon2 geçişleri / PBKDF2 yinelemeleri", "Pasadas de Argon2 / iteraciones PBKDF2"]),
            ("parallelism", ["Argon2 parallelism (lanes)", "Argon2 paralelliği (şerit)", "Paralelismo de Argon2 (carriles)"]),
            ("length", ["Output key length in bytes", "Çıktı anahtar uzunluğu (bayt)", "Longitud de la clave en bytes"]),
            ("verify", [
                "Verify the password against a PHC string instead of hashing",
                "Özetlemek yerine parolayı bir PHC dizesine karşı doğrula",
                "Verificar la contraseña contra una cadena PHC en lugar de calcularla",
            ]),
        ],
    ),
    (
        "password",
        [
            "Generate strong random passwords",
            "Güçlü rastgele parolalar üret",
            "Generar contraseñas aleatorias robustas",
        ],
        &[
            ("length", ["Password length (4–256)", "Parola uzunluğu (4–256)", "Longitud (4–256)"]),
            ("count", ["How many passwords to print", "Kaç parola yazdırılacak", "Cuántas contraseñas imprimir"]),
            ("symbols", ["Include symbols (!@#$…)", "Sembolleri dahil et (!@#$…)", "Incluir símbolos (!@#$…)"]),
            ("no_lower", ["Exclude lowercase letters", "Küçük harfleri çıkar", "Excluir minúsculas"]),
            ("no_upper", ["Exclude uppercase letters", "Büyük harfleri çıkar", "Excluir mayúsculas"]),
            ("no_digits", ["Exclude digits", "Rakamları çıkar", "Excluir dígitos"]),
        ],
    ),
    (
        "keygen",
        [
            "Generate a key pair (Ed25519, X25519, ML-KEM/Kyber, RSA-2048)",
            "Anahtar çifti üret (Ed25519, X25519, ML-KEM/Kyber, RSA-2048)",
            "Generar un par de claves (Ed25519, X25519, ML-KEM/Kyber, RSA-2048)",
        ],
        &[
            ("kind", [
                "ed25519, x25519, mlkem512, mlkem768, mlkem1024, rsa2048",
                "ed25519, x25519, mlkem512, mlkem768, mlkem1024, rsa2048",
                "ed25519, x25519, mlkem512, mlkem768, mlkem1024, rsa2048",
            ]),
            ("json", ["Output as JSON", "JSON olarak yazdır", "Salida en JSON"]),
        ],
    ),
    (
        "sign",
        ["Sign data with an Ed25519 seed", "Veriyi Ed25519 tohumuyla imzala", "Firmar datos con una semilla Ed25519"],
        &[("seed", ["32-byte seed as hex", "32 baytlık onaltılık tohum", "Semilla de 32 bytes en hex"])],
    ),
    (
        "verify",
        ["Verify an Ed25519 signature", "Ed25519 imzasını doğrula", "Verificar una firma Ed25519"],
        &[
            ("public", ["32-byte public key as hex", "32 baytlık onaltılık açık anahtar", "Clave pública de 32 bytes en hex"]),
            ("signature", ["64-byte signature as hex", "64 baytlık onaltılık imza", "Firma de 64 bytes en hex"]),
        ],
    ),
    (
        "info",
        [
            "Show version, hardware backends and supported algorithms",
            "Sürüm, donanım arka uçları ve desteklenen algoritmaları göster",
            "Mostrar versión, backends de hardware y algoritmos",
        ],
        &[],
    ),
    (
        "tui",
        [
            "Open the full-screen terminal UI",
            "Tam ekran terminal arayüzünü aç",
            "Abrir la interfaz de terminal a pantalla completa",
        ],
        &[],
    ),
];

const CRYPT_ARGS: &[(&str, L3)] = &[
    (
        "cipher",
        [
            "Cipher: aes-256-gcm, chacha20-poly1305, aes-256-ctr, xor",
            "Şifre: aes-256-gcm, chacha20-poly1305, aes-256-ctr, xor",
            "Cifrado: aes-256-gcm, chacha20-poly1305, aes-256-ctr, xor",
        ],
    ),
    (
        "key",
        [
            "Key as hex (32 bytes for AES/ChaCha; any length for xor)",
            "Onaltılık anahtar (AES/ChaCha için 32 bayt; xor için herhangi bir uzunluk)",
            "Clave en hex (32 bytes para AES/ChaCha; cualquier longitud para xor)",
        ],
    ),
    (
        "key_file",
        [
            "Read the raw key bytes from a file",
            "Ham anahtar baytlarını bir dosyadan oku",
            "Leer los bytes de la clave desde un archivo",
        ],
    ),
    (
        "nonce",
        [
            "Nonce/IV as hex. Required to decrypt; auto-generated when encrypting",
            "Onaltılık nonce/IV. Şifre çözmek için gerekli; şifrelerken otomatik üretilir",
            "Nonce/IV en hex. Necesario para descifrar; se genera al cifrar",
        ],
    ),
    (
        "aad",
        [
            "Additional authenticated data as hex (AEAD ciphers only)",
            "Onaltılık ek kimlik doğrulama verisi (yalnızca AEAD şifreleri)",
            "Datos autenticados adicionales en hex (solo AEAD)",
        ],
    ),
    (
        "armor",
        [
            "Base64-armor the output (encrypt) / expect Base64 input (decrypt)",
            "Çıktıyı Base64 ile sarmala (şifrele) / Base64 girdisi bekle (çöz)",
            "Salida en Base64 (cifrar) / esperar entrada Base64 (descifrar)",
        ],
    ),
];

fn localize_sub(sc: Command, lang: Lang, about: L3, args: &[(&str, L3)]) -> Command {
    let mut sc = sc.about(lang.pick(about));
    sc = arg_help(sc, "input", lang, INPUT);
    sc = arg_help(sc, "output", lang, OUTPUT);
    for (id, text) in args {
        sc = arg_help(sc, id, lang, *text);
    }
    sc
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

/// Build the fully-localised top-level command.
pub fn localized_command(base: Command, lang: Lang) -> Command {
    let mut cmd = disable_builtin_help(base)
        .subcommand_required(false)
        .arg(
            Arg::new("help")
                .short('h')
                .long("help")
                .global(true)
                .action(ArgAction::SetTrue)
                .help(lang.pick(["Print help", "Yardımı göster", "Mostrar ayuda"])),
        )
        .arg(
            Arg::new("version")
                .short('V')
                .long("version")
                .global(true)
                .action(ArgAction::SetTrue)
                .help(lang.pick(["Print version", "Sürümü göster", "Mostrar versión"])),
        )
        .about(lang.pick([
            "easylock — a from-scratch cryptography toolkit",
            "easylock — sıfırdan yazılmış bir kriptografi araç seti",
            "easylock — un kit de criptografía escrito desde cero",
        ]))
        .after_help(match lang {
            Lang::En => format!(
                "Active language: {} · switch with --lang en|tr|es or the LANG / LC_ALL locale.\n\
                 Try `easylock tui` for the interactive terminal UI.",
                lang.endonym()
            ),
            Lang::Tr => format!(
                "Etkin dil: {} · --lang en|tr|es ile ya da LANG / LC_ALL yerel ayarıyla değiştirin.\n\
                 Etkileşimli terminal arayüzü için `easylock tui` deneyin.",
                lang.endonym()
            ),
            Lang::Es => format!(
                "Idioma activo: {} · cámbielo con --lang en|tr|es o la configuración LANG / LC_ALL.\n\
                 Pruebe `easylock tui` para la interfaz interactiva de terminal.",
                lang.endonym()
            ),
        })
        .mut_arg("lang", |a| {
            a.help(lang.pick([
                "Interface language for messages and help: `en`, `tr` or `es`",
                "Mesajlar ve yardım için arayüz dili: `en`, `tr` veya `es`",
                "Idioma de la interfaz para mensajes y ayuda: `en`, `tr` o `es`",
            ]))
        });

    for (name, about, args) in SUBCOMMANDS {
        cmd = cmd.mut_subcommand(*name, |sc| localize_sub(sc, lang, *about, args));
    }
    cmd = cmd.mut_subcommand("encrypt", |sc| {
        localize_sub(
            sc,
            lang,
            [
                "Encrypt data (AEAD output is `ciphertext||tag`)",
                "Veriyi şifrele (AEAD çıktısı `şifreli metin||etiket` biçimindedir)",
                "Cifrar datos (la salida AEAD es `texto cifrado||etiqueta`)",
            ],
            CRYPT_ARGS,
        )
    });
    cmd.mut_subcommand("decrypt", |sc| {
        localize_sub(
            sc,
            lang,
            [
                "Decrypt data produced by `easylock encrypt`",
                "`easylock encrypt` ile üretilmiş veriyi çöz",
                "Descifrar datos producidos por `easylock encrypt`",
            ],
            CRYPT_ARGS,
        )
    })
}

/// `true` if `-h/--help` was passed at any nesting level.
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

/// Descend to the deepest named (sub)command in `m`.
fn locate<'a>(cmd: &'a mut Command, m: &ArgMatches) -> &'a mut Command {
    if let Some((name, sub_m)) = m.subcommand() {
        if cmd.find_subcommand(name).is_some() {
            return locate(cmd.find_subcommand_mut(name).unwrap(), sub_m);
        }
    }
    cmd
}

fn localize_labels(s: &str, lang: Lang) -> String {
    let pairs: &[(&str, L3)] = &[
        ("Usage:", ["Usage:", "Kullanım:", "Uso:"]),
        ("Commands:", ["Commands:", "Komutlar:", "Comandos:"]),
        (
            "Arguments:",
            ["Arguments:", "Bağımsız değişkenler:", "Argumentos:"],
        ),
        ("Options:", ["Options:", "Seçenekler:", "Opciones:"]),
        (
            "[default:",
            ["[default:", "[varsayılan:", "[predeterminado:"],
        ),
        (
            "[possible values:",
            [
                "[possible values:",
                "[olası değerler:",
                "[valores posibles:",
            ],
        ),
        ("[aliases:", ["[aliases:", "[takma adlar:", "[alias:"]),
    ];
    let mut out = s.to_string();
    for (en, l3) in pairs {
        out = out.replace(en, lang.pick(*l3));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn root_help(lang: Lang) -> String {
        let mut cmd = localized_command(crate::Cli::command(), lang);
        localize_labels(&cmd.render_long_help().to_string(), lang)
    }

    #[test]
    fn root_help_in_three_languages() {
        let en = root_help(Lang::En);
        assert!(en.contains("from-scratch cryptography toolkit") && en.contains("Usage:"));
        let tr = root_help(Lang::Tr);
        assert!(
            tr.contains("kriptografi araç seti")
                && tr.contains("Kullanım:")
                && tr.contains("Komutlar:")
        );
        let es = root_help(Lang::Es);
        assert!(
            es.contains("kit de criptografía") && es.contains("Uso:") && es.contains("Comandos:")
        );
    }

    #[test]
    fn every_subcommand_is_localized() {
        let es = root_help(Lang::Es);
        for needle in [
            "Generar un par de claves",
            "Abrir la interfaz",
            "Verificar una firma",
        ] {
            assert!(es.contains(needle), "{needle}\n{es}");
        }
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
