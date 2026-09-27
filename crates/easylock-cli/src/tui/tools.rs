//! The tools shown in the TUI. Each tool is a set of input fields plus a pure
//! `compute` function that turns them into labelled result lines.

use crate::commands::{hmac, info, keygen, password};
use crate::i18n::Lang;
use easylock_core::ec::{SigningKey, StaticSecret, VerifyingKey};
use easylock_core::encode::{hex, Transform};
use easylock_core::hash::Algorithm;

type L3 = [&'static str; 3];
type Output = Vec<(String, String)>;
type Compute = fn(&[Field], Lang) -> Result<Output, String>;

#[derive(Clone)]
pub enum FieldKind {
    Text,
    Secret,
    Choice(&'static [&'static str]),
    Number { min: i64, max: i64 },
    Toggle,
}

#[derive(Clone)]
pub struct Field {
    pub label: L3,
    pub kind: FieldKind,
    pub value: String,
}

fn text(label: L3) -> Field {
    Field {
        label,
        kind: FieldKind::Text,
        value: String::new(),
    }
}
fn secret(label: L3) -> Field {
    Field {
        label,
        kind: FieldKind::Secret,
        value: String::new(),
    }
}
fn choice(label: L3, opts: &'static [&'static str]) -> Field {
    Field {
        label,
        kind: FieldKind::Choice(opts),
        value: opts[0].to_string(),
    }
}
fn number(label: L3, min: i64, max: i64, default: i64) -> Field {
    Field {
        label,
        kind: FieldKind::Number { min, max },
        value: default.to_string(),
    }
}
fn toggle(label: L3, on: bool) -> Field {
    Field {
        label,
        kind: FieldKind::Toggle,
        value: if on { "on" } else { "off" }.into(),
    }
}

pub struct Tool {
    pub icon: &'static str,
    pub name: L3,
    pub about: L3,
    pub hint: L3,
    pub fields: Vec<Field>,
    /// Recompute on every keystroke (deterministic tools only).
    pub live: bool,
    pub output: Output,
    pub error: Option<String>,
    compute: Compute,
}

impl Tool {
    pub fn run(&mut self, lang: Lang) {
        match (self.compute)(&self.fields, lang) {
            Ok(o) => {
                self.output = o;
                self.error = None;
            }
            Err(e) => {
                self.output.clear();
                self.error = Some(e);
            }
        }
    }
}

fn row(label: impl Into<String>, value: impl Into<String>) -> (String, String) {
    (label.into(), value.into())
}

const PRESS_ENTER: L3 = [
    "Press Enter to run.",
    "Çalıştırmak için Enter'a basın.",
    "Pulse Enter para ejecutar.",
];

#[allow(clippy::too_many_lines)] // a data table of tools
pub fn all() -> Vec<Tool> {
    vec![
        Tool {
            icon: "🔎",
            name: ["Hash", "Özet", "Hash"],
            about: [
                "A hash turns any input into a fixed-size fingerprint. Change one letter and the whole fingerprint changes. Results update as you type.",
                "Özet fonksiyonu her girdiyi sabit uzunlukta bir parmak izine çevirir. Tek bir harf değişse bile parmak izi tamamen değişir. Sonuçlar siz yazdıkça güncellenir.",
                "Un hash convierte cualquier entrada en una huella de tamaño fijo. Cambie una letra y cambia toda la huella. Los resultados se actualizan mientras escribe.",
            ],
            hint: ["Type some text.", "Bir metin yazın.", "Escriba un texto."],
            fields: vec![text(["Text", "Metin", "Texto"])],
            live: true,
            output: vec![],
            error: None,
            compute: |f, _| {
                let data = f[0].value.as_bytes();
                Ok([
                    Algorithm::Sha256,
                    Algorithm::Blake3,
                    Algorithm::Sha3_256,
                    Algorithm::Keccak256,
                    Algorithm::Sha512,
                ]
                .iter()
                .map(|a| row(a.name().to_uppercase(), hex::encode(&a.hash(data))))
                .collect())
            },
        },
        Tool {
            icon: "🔄",
            name: ["Encode / decode", "Kodla / çöz", "Codificar / decodificar"],
            about: [
                "Encodings are not encryption — they only change how bytes are written (Hex, Base64, Base58…). Anyone can reverse them.",
                "Kodlama şifreleme değildir — yalnızca baytların nasıl yazıldığını değiştirir (Hex, Base64, Base58…). Herkes geri çevirebilir.",
                "Las codificaciones no son cifrado: solo cambian cómo se escriben los bytes (Hex, Base64, Base58…). Cualquiera puede revertirlas.",
            ],
            hint: ["Type some text.", "Bir metin yazın.", "Escriba un texto."],
            fields: vec![
                text(["Text", "Metin", "Texto"]),
                choice(["Format", "Biçim", "Formato"], &["base64", "hex", "base64url", "base58", "rot13"]),
                choice(["Direction", "Yön", "Dirección"], &["encode", "decode"]),
            ],
            live: true,
            output: vec![],
            error: None,
            compute: |f, lang| {
                let t = Transform::parse(&f[1].value).ok_or("bad transform")?;
                let out = if f[2].value == "decode" {
                    let b = t.decode(f[0].value.trim()).map_err(|_| {
                        lang.pick(["not valid for this format", "bu biçim için geçersiz", "no válido para este formato"])
                            .to_string()
                    })?;
                    String::from_utf8_lossy(&b).into_owned()
                } else {
                    t.encode(f[0].value.as_bytes())
                };
                Ok(vec![row(format!("{} ({})", lang.pick(["Output", "Çıktı", "Salida"]), f[1].value), out)])
            },
        },
        Tool {
            icon: "🎲",
            name: ["Password generator", "Parola üretici", "Generador de contraseñas"],
            about: [
                "Random passwords from the OS random generator, with look-alike characters (0/O, 1/l) removed. Entropy tells you how hard it is to guess.",
                "İşletim sisteminin rastgele üretecinden parolalar; birbirine benzeyen karakterler (0/O, 1/l) çıkarıldı. Entropi, tahmin etmenin ne kadar zor olduğunu gösterir.",
                "Contraseñas aleatorias del generador del sistema, sin caracteres parecidos (0/O, 1/l). La entropía indica lo difícil que es adivinarla.",
            ],
            hint: PRESS_ENTER,
            fields: vec![
                number(["Length", "Uzunluk", "Longitud"], 4, 128, 20),
                toggle(["Symbols", "Semboller", "Símbolos"], true),
                toggle(["Digits", "Rakamlar", "Dígitos"], true),
            ],
            live: false,
            output: vec![],
            error: None,
            compute: |f, lang| {
                let len: usize = f[0].value.parse().unwrap_or(20);
                let pool = password::pool(true, true, f[2].value == "on", f[1].value == "on");
                let mut rows = Vec::new();
                for _ in 0..3 {
                    let p = password::generate(len, &pool).map_err(|e| e.msg.text(lang))?;
                    rows.push(row(lang.pick(["Password", "Parola", "Contraseña"]), p));
                }
                let bits = password::entropy_bits(len, pool.len());
                let strength = if bits >= 100.0 {
                    lang.pick(["excellent", "mükemmel", "excelente"])
                } else if bits >= 70.0 {
                    lang.pick(["strong", "güçlü", "fuerte"])
                } else if bits >= 45.0 {
                    lang.pick(["fair", "orta", "aceptable"])
                } else {
                    lang.pick(["weak", "zayıf", "débil"])
                };
                rows.push(row(
                    lang.pick(["Entropy", "Entropi", "Entropía"]),
                    format!("{bits:.1} bits — {strength}"),
                ));
                Ok(rows)
            },
        },
        Tool {
            icon: "🔑",
            name: ["Key pair", "Anahtar çifti", "Par de claves"],
            about: [
                "Public-key crypto uses two keys: share the public one, keep the secret one. ML-KEM (Kyber) is the new post-quantum standard (FIPS 203).",
                "Açık anahtarlı kriptografi iki anahtar kullanır: açık olanı paylaşın, gizli olanı saklayın. ML-KEM (Kyber) yeni kuantum sonrası standarttır (FIPS 203).",
                "La criptografía de clave pública usa dos claves: comparta la pública, guarde la secreta. ML-KEM (Kyber) es el nuevo estándar poscuántico (FIPS 203).",
            ],
            hint: PRESS_ENTER,
            fields: vec![choice(
                ["Type", "Tür", "Tipo"],
                &["ed25519", "x25519", "mlkem768", "mlkem512", "mlkem1024", "rsa2048"],
            )],
            live: false,
            output: vec![],
            error: None,
            compute: |f, lang| {
                let kp = keygen::generate(&f[0].value).map_err(|e| e.msg.text(lang))?;
                Ok(vec![
                    row(format!("{} — {}", kp.kind, lang.pick(["public", "açık", "pública"])), kp.public),
                    row(lang.pick(["secret (keep private!)", "gizli (paylaşmayın!)", "secreta (¡no la comparta!)"]), kp.secret),
                ])
            },
        },
        Tool {
            icon: "🔒",
            name: ["Encrypt text", "Metin şifrele", "Cifrar texto"],
            about: [
                "Password-based encryption: Argon2id stretches your password into a key, then an AEAD cipher encrypts and seals the text so any change is detected.",
                "Parola tabanlı şifreleme: Argon2id parolanızı bir anahtara dönüştürür, ardından AEAD şifresi metni şifreler ve mühürler; her değişiklik fark edilir.",
                "Cifrado con contraseña: Argon2id convierte su contraseña en una clave y un cifrado AEAD cifra y sella el texto para detectar cualquier cambio.",
            ],
            hint: PRESS_ENTER,
            fields: vec![
                choice(["Mode", "Mod", "Modo"], &["encrypt", "decrypt"]),
                choice(["Cipher", "Şifre", "Cifrado"], &["chacha20-poly1305", "aes-256-gcm"]),
                secret(["Password", "Parola", "Contraseña"]),
                text(["Text / token", "Metin / belirteç", "Texto / token"]),
            ],
            live: false,
            output: vec![],
            error: None,
            compute: encrypt_tool,
        },
        Tool {
            icon: "🏷",
            name: ["HMAC", "HMAC", "HMAC"],
            about: [
                "HMAC is a hash with a secret key. Only someone with the key can produce the same tag, so it proves who sent a message and that it wasn't changed.",
                "HMAC gizli anahtarlı bir özettir. Aynı etiketi yalnızca anahtara sahip olan üretebilir; mesajı kimin gönderdiğini ve değişmediğini kanıtlar.",
                "HMAC es un hash con clave secreta. Solo quien tiene la clave produce la misma etiqueta: prueba quién envió el mensaje y que no cambió.",
            ],
            hint: ["Enter a key and a message.", "Bir anahtar ve mesaj girin.", "Introduzca una clave y un mensaje."],
            fields: vec![
                secret(["Key", "Anahtar", "Clave"]),
                text(["Message", "Mesaj", "Mensaje"]),
                choice(["Hash", "Özet", "Hash"], &["sha256", "sha512", "sha3-256", "keccak256"]),
            ],
            live: true,
            output: vec![],
            error: None,
            compute: |f, lang| {
                if f[0].value.is_empty() {
                    return Ok(vec![]);
                }
                let tag = hmac::compute(&f[2].value, f[0].value.as_bytes(), f[1].value.as_bytes())
                    .map_err(|e| e.msg.text(lang))?;
                Ok(vec![row(format!("HMAC-{}", f[2].value.to_uppercase()), tag)])
            },
        },
        Tool {
            icon: "✍",
            name: ["Sign & verify", "İmzala & doğrula", "Firmar y verificar"],
            about: [
                "Ed25519 digital signatures: sign with the secret seed, anyone can verify with the public key. Leave the seed empty to create a new one.",
                "Ed25519 dijital imzaları: gizli tohumla imzalayın, herkes açık anahtarla doğrulayabilir. Yeni bir tohum için alanı boş bırakın.",
                "Firmas digitales Ed25519: firme con la semilla secreta y cualquiera verifica con la clave pública. Deje la semilla vacía para crear una nueva.",
            ],
            hint: PRESS_ENTER,
            fields: vec![
                text(["Seed (hex, optional)", "Tohum (hex, isteğe bağlı)", "Semilla (hex, opcional)"]),
                text(["Message", "Mesaj", "Mensaje"]),
            ],
            live: false,
            output: vec![],
            error: None,
            compute: |f, lang| {
                let seed: [u8; 32] = if f[0].value.trim().is_empty() {
                    let mut s = [0u8; 32];
                    crate::io::os_random(&mut s).map_err(|e| e.msg.text(lang))?;
                    s
                } else {
                    hex::decode(f[0].value.trim())
                        .ok()
                        .and_then(|v| v.try_into().ok())
                        .ok_or_else(|| lang.pick(["seed must be 64 hex characters", "tohum 64 hex karakter olmalı", "la semilla debe tener 64 caracteres hex"]).to_string())?
                };
                let sk = SigningKey::from_seed(seed);
                let sig = sk.sign(f[1].value.as_bytes());
                let vk = VerifyingKey::from_bytes(*sk.verifying_key().as_bytes());
                let ok = vk.verify(f[1].value.as_bytes(), &sig);
                Ok(vec![
                    row(lang.pick(["Seed (secret)", "Tohum (gizli)", "Semilla (secreta)"]), hex::encode(&seed)),
                    row(lang.pick(["Public key", "Açık anahtar", "Clave pública"]), hex::encode(sk.verifying_key().as_bytes())),
                    row(lang.pick(["Signature", "İmza", "Firma"]), hex::encode(&sig.to_bytes())),
                    row(
                        lang.pick(["Self-check", "Öz-kontrol", "Autoverificación"]),
                        if ok { "✓" } else { "✕" }.to_string(),
                    ),
                ])
            },
        },
        Tool {
            icon: "🤝",
            name: ["Key exchange demo", "Anahtar değişimi demosu", "Demo de intercambio"],
            about: [
                "X25519 Diffie–Hellman: Alice and Bob each make a key pair, swap only public keys, and still compute the SAME shared secret. An eavesdropper can't.",
                "X25519 Diffie–Hellman: Alice ve Bob birer anahtar çifti üretir, yalnızca açık anahtarları değiş tokuş eder ve yine de AYNI ortak sırrı hesaplar. Dinleyen biri yapamaz.",
                "X25519 Diffie–Hellman: Alice y Bob crean un par de claves, intercambian solo las públicas y aun así calculan el MISMO secreto compartido. Un espía no puede.",
            ],
            hint: PRESS_ENTER,
            fields: vec![],
            live: false,
            output: vec![],
            error: None,
            compute: |_, lang| {
                let mut a = [0u8; 32];
                let mut b = [0u8; 32];
                crate::io::os_random(&mut a).map_err(|e| e.msg.text(lang))?;
                crate::io::os_random(&mut b).map_err(|e| e.msg.text(lang))?;
                let (alice, bob) = (StaticSecret::from_bytes(a), StaticSecret::from_bytes(b));
                let (pa, pb) = (alice.public_key(), bob.public_key());
                let s1 = alice.diffie_hellman(&pb);
                let s2 = bob.diffie_hellman(&pa);
                let same = s1.as_bytes() == s2.as_bytes();
                Ok(vec![
                    row(lang.pick(["Alice → public", "Alice → açık", "Alice → pública"]), hex::encode(pa.as_bytes())),
                    row(lang.pick(["Bob → public", "Bob → açık", "Bob → pública"]), hex::encode(pb.as_bytes())),
                    row(lang.pick(["Alice's shared secret", "Alice'in ortak sırrı", "Secreto de Alice"]), hex::encode(s1.as_bytes())),
                    row(lang.pick(["Bob's shared secret", "Bob'un ortak sırrı", "Secreto de Bob"]), hex::encode(s2.as_bytes())),
                    row(
                        lang.pick(["Match?", "Eşleşiyor mu?", "¿Coinciden?"]),
                        if same { lang.pick(["✓ identical", "✓ aynı", "✓ idénticos"]) } else { "✕" }.to_string(),
                    ),
                ])
            },
        },
        Tool {
            icon: "ℹ",
            name: ["About", "Hakkında", "Acerca de"],
            about: [
                "easylock — a from-scratch cryptography toolkit in Rust. Everything below is implemented in this project and tested against official vectors.",
                "easylock — Rust ile sıfırdan yazılmış bir kriptografi araç seti. Aşağıdakilerin hepsi bu projede uygulandı ve resmi test vektörleriyle doğrulandı.",
                "easylock — un kit de criptografía escrito desde cero en Rust. Todo lo siguiente está implementado aquí y probado con vectores oficiales.",
            ],
            hint: [" ", " ", " "],
            fields: vec![],
            live: true,
            output: vec![],
            error: None,
            compute: |_, lang| {
                let mut rows = vec![
                    row("version", format!("easylock {}", env!("CARGO_PKG_VERSION"))),
                    row(
                        lang.pick(["hardware backends", "donanım arka uçları", "backends de hardware"]),
                        format!(
                            "aes={}  ghash={}",
                            easylock_core::cipher::aes::active_backend(),
                            easylock_core::aead::ghash::active_backend()
                        ),
                    ),
                ];
                for (fam, algos) in info::CATALOGUE {
                    rows.push(row((*fam).to_string(), algos.join(" · ")));
                }
                Ok(rows)
            },
        },
    ]
}

fn encrypt_tool(f: &[Field], lang: Lang) -> Result<Output, String> {
    use easylock_core::container::{self, Cipher};
    let pw = f[2].value.as_bytes();
    if pw.is_empty() {
        return Err(lang
            .pick([
                "enter a password",
                "bir parola girin",
                "introduzca una contraseña",
            ])
            .into());
    }
    if f[0].value == "encrypt" {
        let cipher = Cipher::parse(&f[1].value).unwrap_or(Cipher::ChaCha20Poly1305);
        let mut rng = |b: &mut [u8]| crate::io::os_random(b).expect("OS randomness");
        let token = container::seal_token(f[3].value.as_bytes(), pw, cipher, &mut rng)
            .map_err(|e| e.to_string())?;
        Ok(vec![row(
            lang.pick([
                "Token (share this)",
                "Belirteç (bunu paylaşın)",
                "Token (comparta esto)",
            ]),
            token,
        )])
    } else {
        let pt = container::open_token(&f[3].value, pw).map_err(|_| {
            lang.pick([
                "wrong password or corrupted token",
                "yanlış parola veya bozuk belirteç",
                "contraseña incorrecta o token dañado",
            ])
            .to_string()
        })?;
        Ok(vec![row(
            lang.pick(["Plaintext", "Düz metin", "Texto plano"]),
            String::from_utf8_lossy(&pt).into_owned(),
        )])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_token() {
        let mut t = all().into_iter().find(|t| t.icon == "🔒").unwrap();
        t.fields[2].value = "hunter2".into();
        t.fields[3].value = "attack at dawn".into();
        t.run(Lang::En);
        let token = t.output[0].1.clone();
        assert!(token.starts_with("elk1."));

        t.fields[0].value = "decrypt".into();
        t.fields[3].value = token.clone();
        t.run(Lang::En);
        assert_eq!(t.output[0].1, "attack at dawn");

        t.fields[2].value = "wrong".into();
        t.run(Lang::En);
        assert!(t.error.is_some());
    }

    #[test]
    fn key_exchange_matches() {
        let mut t = all().into_iter().find(|t| t.icon == "🤝").unwrap();
        t.run(Lang::Tr);
        assert!(t.output.last().unwrap().1.contains('✓'));
    }
}
