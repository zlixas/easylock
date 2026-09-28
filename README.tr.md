<div align="center">

# 🔒 easylock

**Rust ile sıfırdan yazılmış, içini görebileceğiniz, öğrenebileceğiniz ve deneyebileceğiniz kriptografi.**

Bağımlılığı olmayan tek bir çekirdek var ve onu dört şekilde kullanabilirsiniz: **komut satırı**, **terminal arayüzü**,
**masaüstü uygulaması** ve **tamamen tarayıcınızda çalışan web sitesi**.

[![CI](https://github.com/zlixas/easylock/actions/workflows/ci.yml/badge.svg)](https://github.com/zlixas/easylock/actions/workflows/ci.yml)
[![Pages](https://github.com/zlixas/easylock/actions/workflows/pages.yml/badge.svg)](https://zlixas.github.io/easylock/)
[![Lisans: MIT VEYA Apache-2.0](https://img.shields.io/badge/lisans-MIT%20%2F%20Apache--2.0-blue.svg)](#lisans)

**[🌐 Tarayıcıda deneyin →](https://zlixas.github.io/easylock/)**

[English](README.md) · Türkçe · [Español](README.es.md)

</div>

> [!WARNING]
> **Eğitim amaçlıdır ve denetlenmemiştir.** Her algoritma temel ilkelerden yola çıkılarak yazıldı ve resmi test
> vektörleriyle (NIST, FIPS, RFC) doğrulandı. Bu gerekli bir adımdır ama kodu üretimde güvenle kullanmak için
> **yeterli değildir**. Gerçek sırlarınızı korumak için `ring`, RustCrypto veya libsodium gibi denetlenmiş kütüphaneler kullanın.

## Neden easylock?

- **Sıfırdan yazıldı.** `easylock-core` hiçbir çalışma zamanı bağımlılığı kullanmaz. SHA-2/3, BLAKE3, AES-GCM, ChaCha20-Poly1305,
  Argon2id, Curve25519, RSA ve kuantum sonrası ML-KEM bu çekirdekte, okunabilir Rust koduyla uygulandı.
- **Doğrulandı.** 170'ten fazla test kodu yayımlanmış test vektörleriyle karşılaştırır. Kod `clippy::pedantic` altında hiç uyarı vermez.
- **Açıklandı.** Web sitesindeki her aracın bir **Öğren** paneli var. Panel aracın *ne olduğunu*, *nasıl çalıştığını*,
  *ne zaman kullanılacağını* ve *nelere dikkat edilmesi gerektiğini* üç dilde anlatır.
- **Birlikte çalışır.** Terminalde kilitlediğiniz `.elk` dosyası web sitesinde açılır, web sitesinde kilitlediğiniz dosya da terminalde açılır.
- **Gizli kalır.** Web sitesi aynı Rust çekirdeğini WebAssembly olarak çalıştırır. Hiçbir veri sunucuya gönderilmez.

## Hızlı başlangıç

```sh
curl -fsSL https://raw.githubusercontent.com/zlixas/easylock/main/install.sh | sh     # Linux, macOS
# Windows: irm https://raw.githubusercontent.com/zlixas/easylock/main/install.ps1 | iex
# veya kaynaktan: cargo install --git https://github.com/zlixas/easylock easylock-cli

easylock --lang tr tui                     # tam ekran terminal arayüzü
easylock lock vergiler.pdf                 # → vergiler.pdf.elk (parola sorar)
easylock unlock vergiler.pdf.elk
easylock lock ~/Fotograflar --shred        # tüm klasör → tek .elk, orijinaller silinir
easylock identity                          # anahtar çiftiniz (X25519 + ML-KEM-768)
easylock lock rapor.pdf -r elkpub1…        # ortak parola olmadan birine şifrele
echo -n abc | easylock hash -a blake3
easylock password -n 3 -l 24 --symbols
easylock --lang tr --help
```

`LANG=tr_TR.UTF-8` ortam değişkeni ayarlıysa arayüz kendiliğinden Türkçe açılır.

## Neler var?

| Aile | Algoritmalar |
|---|---|
| Özet | SHA-256/512, SHA3-256/512, SHAKE, Keccak-256, BLAKE2b, BLAKE3 |
| MAC | HMAC, Poly1305 |
| Anahtar türetme | Argon2id/i/d (PHC), PBKDF2, HKDF |
| AEAD | AES-256-GCM (donanım hızlandırmalı), ChaCha20-Poly1305 |
| Eliptik eğri | X25519, Ed25519 |
| RSA | anahtar üretimi, PKCS#1 v1.5, OAEP |
| Kuantum sonrası | ML-KEM-512/768/1024 (FIPS 203) |
| Kapsayıcı | `.elk` dosyaları ve `elk1.` metin belirteçleri ([biçim](docs/FILE_FORMAT.md)) |


## Şifreli kasa

Kasa, dosyaların **şifreli kaldığı** bir klasördür. Dosya adları, boyutları ve tarihleri de şifreli bir dizinde saklanır.

```sh
easylock vault init ~/Gizli.vault
easylock vault add  ~/Gizli.vault vergiler/ kimlik.pdf --shred
easylock vault ls   ~/Gizli.vault
easylock vault get  ~/Gizli.vault vergiler -o ~/Masaüstü
easylock vault passwd ~/Gizli.vault -r elkpub1…     # dosyaları yeniden şifrelemeden anahtar değiştir
```

## Dört arayüz

- **🌐 Web sitesi:** 5 kategoride 20 araç. Dosya ve mesaj şifreleme, canlı özet, sağlama doğrulama,
  Argon2 ile özetleme ve doğrulama, X25519 anahtar değişimi gösterimi, JWT inceleyici, parola gücü analizi, UUID/PIN üreteci ve
  daha fazlası. <kbd>Ctrl</kbd>+<kbd>K</kbd> komut paletini açar, telefonda da rahat kullanılır.
- **⌨️ Terminal arayüzü (`easylock tui`):** 9 araç var. <kbd>F2</kbd> dili değiştirir, <kbd>F5</kbd> kopyalar, <kbd>F1</kbd> yardımı açar.
- **💻 Komut satırı:** `hash`, `encode`/`decode`, `encrypt`/`decrypt`, `lock`/`unlock`, `hmac`, `kdf`, `password`,
  `keygen`, `sign`/`verify`, `info`, `tui`
- **🖥️ Masaüstü (Tauri v2):** Dosyalar, Özet, Dönüştür ve Anahtarlar sekmeleri, EN/TR/ES dil desteği.

## Derleme ve test

```sh
cargo test --workspace
cargo clippy --workspace --all-targets
cd crates/easylock-web && npm install && npm run wasm && npm run dev
```

Ayrıntılar için [mimari belgesine](docs/ARCHITECTURE.md), katkıda bulunmak için [CONTRIBUTING.md](CONTRIBUTING.md) dosyasına,
güvenlik politikası için [SECURITY.md](SECURITY.md) dosyasına bakın.

## Lisans

Apache-2.0 **veya** MIT lisansı altında dağıtılır. İkisinden birini seçebilirsiniz.
