const DICT = {
  en: {
    "app.subtitle": "cryptography dashboard",
    "nav.symmetric": "Symmetric Encryption",
    "nav.asymmetric": "Asymmetric & Keys",
    "nav.hashing": "Hashing & KDF",
    "nav.pipeline": "Pipeline Converters",
    "nav.utilities": "Utilities",
    "tool.aes": "AES-256-GCM",
    "tool.chacha": "ChaCha20-Poly1305",
    "tool.rsa": "RSA keys",
    "tool.ed25519": "Ed25519",
    "tool.kyber": "Kyber / ML-KEM",
    "tool.sha": "SHA-2 / SHA-3 / Keccak",
    "tool.blake3": "BLAKE3",
    "tool.argon2": "Argon2id",
    "tool.pbkdf2": "PBKDF2",
    "tool.b64": "Base64 / Base64URL",
    "tool.hex": "Hex",
    "tool.rot13": "ROT13 / chain",
    "tool.pwgen": "Password Generator",
    "tool.verify": "Checksum Verifier",

    "field.key": "Key (hex, 32 bytes)",
    "field.nonce": "Nonce (hex, 12 bytes)",
    "field.aad": "Associated data (hex, optional)",
    "field.plaintext": "Plaintext",
    "field.ciphertext": "Ciphertext (Base64)",
    "field.password": "Password",
    "field.salt": "Salt (hex)",
    "field.message": "Message",
    "field.input": "Input",
    "field.output": "Output",
    "field.length": "Length",
    "field.iterations": "Iterations",
    "field.algo": "Algorithm",
    "field.expected": "Expected checksum",

    "btn.encrypt": "Encrypt",
    "btn.decrypt": "Decrypt",
    "btn.hash": "Hash",
    "btn.generate": "Generate",
    "btn.random": "Random",
    "btn.encode": "Encode →",
    "btn.decode": "← Decode",
    "btn.sign": "Sign",
    "btn.verify": "Verify",
    "btn.encaps": "Encapsulate",
    "btn.decaps": "Decapsulate",
    "btn.clearAll": "Clear all",
    "btn.copy": "Copy",

    "clip.title": "Clipboard",
    "clip.empty": "Nothing captured yet",
    "clip.hint": "Results land here automatically · cleared on close/idle",

    "drop.hash": "Drop a file to checksum",
    "drop.file": "Drop a file here",

    "msg.copied": "Copied to OS clipboard",
    "msg.done": "Done",
    "msg.match": "MATCH",
    "msg.nomatch": "NO MATCH",
    "msg.working": "Working…",
    "msg.valid": "Signature valid ✓",
    "msg.invalid": "Signature INVALID ✕",
    "msg.serverDown": "easylock-server not reachable at :8080",
    "engine.local": "everything runs in your browser",
  },
  tr: {
    "app.subtitle": "kriptografi panosu",
    "nav.symmetric": "Simetrik Şifreleme",
    "nav.asymmetric": "Asimetrik & Anahtarlar",
    "nav.hashing": "Özet & KDF",
    "nav.pipeline": "İşlem Hattı Dönüştürücüler",
    "nav.utilities": "Araçlar",
    "tool.aes": "AES-256-GCM",
    "tool.chacha": "ChaCha20-Poly1305",
    "tool.rsa": "RSA anahtarları",
    "tool.ed25519": "Ed25519",
    "tool.kyber": "Kyber / ML-KEM",
    "tool.sha": "SHA-2 / SHA-3 / Keccak",
    "tool.blake3": "BLAKE3",
    "tool.argon2": "Argon2id",
    "tool.pbkdf2": "PBKDF2",
    "tool.b64": "Base64 / Base64URL",
    "tool.hex": "Onaltılık (Hex)",
    "tool.rot13": "ROT13 / zincir",
    "tool.pwgen": "Parola Üretici",
    "tool.verify": "Sağlama Doğrulayıcı",

    "field.key": "Anahtar (hex, 32 bayt)",
    "field.nonce": "Nonce (hex, 12 bayt)",
    "field.aad": "İlişkili veri (hex, isteğe bağlı)",
    "field.plaintext": "Düz metin",
    "field.ciphertext": "Şifreli metin (Base64)",
    "field.password": "Parola",
    "field.salt": "Tuz (hex)",
    "field.message": "Mesaj",
    "field.input": "Girdi",
    "field.output": "Çıktı",
    "field.length": "Uzunluk",
    "field.iterations": "Yineleme",
    "field.algo": "Algoritma",
    "field.expected": "Beklenen sağlama",

    "btn.encrypt": "Şifrele",
    "btn.decrypt": "Çöz",
    "btn.hash": "Özetle",
    "btn.generate": "Üret",
    "btn.random": "Rastgele",
    "btn.encode": "Kodla →",
    "btn.decode": "← Çöz",
    "btn.sign": "İmzala",
    "btn.verify": "Doğrula",
    "btn.encaps": "Kapsülle",
    "btn.decaps": "Kapsül çöz",
    "btn.clearAll": "Tümünü temizle",
    "btn.copy": "Kopyala",

    "clip.title": "Pano",
    "clip.empty": "Henüz bir şey yakalanmadı",
    "clip.hint": "Sonuçlar buraya otomatik düşer · kapanış/boşta temizlenir",

    "drop.hash": "Sağlaması için bir dosya bırakın",
    "drop.file": "Dosyayı buraya bırakın",

    "msg.copied": "İşletim sistemi panosuna kopyalandı",
    "msg.done": "Tamam",
    "msg.match": "EŞLEŞTİ",
    "msg.nomatch": "EŞLEŞMEDİ",
    "msg.working": "Çalışıyor…",
    "msg.valid": "İmza geçerli ✓",
    "msg.invalid": "İmza GEÇERSİZ ✕",
    "msg.serverDown": ":8080 üzerinde easylock-server'a ulaşılamıyor",
    "engine.local": "her şey tarayıcınızda çalışır",
  },
};

let lang = localStorage.getItem("easylock-lang") ||
  ((navigator.language || "en").toLowerCase().startsWith("tr") ? "tr" : "en");

const listeners = new Set();

export function t(key) {
  return (DICT[lang] && DICT[lang][key]) || DICT.en[key] || key;
}
export function getLang() {
  return lang;
}
export function setLang(next) {
  if (!DICT[next] || next === lang) return;
  lang = next;
  localStorage.setItem("easylock-lang", lang);
  document.documentElement.lang = lang;
  listeners.forEach((fn) => fn());
}
export function onLangChange(fn) {
  listeners.add(fn);
}
