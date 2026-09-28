<div align="center">

<a href="https://zlixas.github.io/easylock/"><img src="docs/images/banner.svg" alt="easylock" width="100%"></a>

<p>
  <a href="https://github.com/zlixas/easylock/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/zlixas/easylock?style=flat-square&color=3d8fd6&label=release"></a>
  <a href="https://github.com/zlixas/easylock/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/zlixas/easylock/ci.yml?branch=main&style=flat-square&label=CI"></a>
  <a href="https://zlixas.github.io/easylock/"><img alt="Website" src="https://img.shields.io/github/actions/workflow/status/zlixas/easylock/pages.yml?branch=main&style=flat-square&label=website"></a>
  <img alt="License" src="https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-8a2be2?style=flat-square">
  <img alt="Zero dependencies" src="https://img.shields.io/badge/core%20deps-0-success?style=flat-square">
  <img alt="Wycheproof" src="https://img.shields.io/badge/Wycheproof-1%2C485-success?style=flat-square">
</p>

<h3><a href="https://zlixas.github.io/easylock/">🌐 Web uygulamasını aç</a> &nbsp;·&nbsp; <a href="#kurulum">⬇️ Kurulum</a> &nbsp;·&nbsp; <a href="docs/FILE_FORMAT.md">📄 Dosya biçimi</a> &nbsp;·&nbsp; <a href="docs/ARCHITECTURE.md">🧭 Mimari</a></h3>

[English](README.md) · Türkçe · [Español](README.es.md)

</div>

<br>

**easylock**, AES'ten kuantum sonrası ML-KEM'e kadar her yapı taşı temel ilkelerden ve **sıfır bağımlılıkla** **Rust ile sıfırdan** yazılmış bir kriptografi araç setidir. Aynı motor **komut satırını**, **terminal arayüzünü**, **masaüstü uygulamasını** ve **tamamen tarayıcınızda çalışan web sitesini** çalıştırır; dördü de aynı şifreli dosya biçimini paylaşır.

<table>
<tr>
<td width="33%" valign="top">

### 📦 Her şeyi şifreleyin
Dosyalar ve tüm klasörler; parolayla, başkalarının **açık anahtarıyla** ya da ikisiyle. Sabit bellekle GB/s hızında akış.

</td>
<td width="33%" valign="top">

### 🛰️ Kuantum sonrası paylaşım
Alıcılar karma **X25519 + ML-KEM-768** anahtarı kullanır; kaydedilen dosyalar gelecekteki kuantum bilgisayarlara karşı da güvende.

</td>
<td width="33%" valign="top">

### 🔐 Şifreli kasalar
Dosyaların **şifreli kaldığı** bir klasör. Adlar ve boyutlar da gizli; iCloud, Dropbox veya Git ile güvenle eşitlenir.

</td>
</tr>
<tr>
<td valign="top">

### 🎓 Yaparak öğrenin
Her birinde **Öğren** paneli (*ne · nasıl · ne zaman · dikkat*) olan 20 etkileşimli araç; Türkçe, İngilizce ve İspanyolca.

</td>
<td valign="top">

### ⚡ Gerçekten hızlı
Elle yazılmış AES-NI / ARMv8, PCLMUL / PMULL, SHA-NI, NEON ve SSE2 yolları: **4,3 GB/s** AES-GCM, **2,4 GB/s** SHA-256.

</td>
<td valign="top">

### 🧪 Denetlenmek için yapıldı
Resmî NIST/RFC vektörleri, **1.485 Wycheproof** uç durumu, fuzz testleri, karşılaştırmalı testler ve imzalı sürümler.

</td>
</tr>
</table>

<div align="center">
<a href="https://zlixas.github.io/easylock/"><picture><source media="(prefers-color-scheme: light)" srcset="docs/images/web-home-light.png"><img src="docs/images/web-home.png" alt="easylock web" width="100%"></picture></a>
<sub>Tarayıcınızda açık ve koyu temalı macOS tarzı bir uygulama. Ana sayfa, yazdığınızı WebAssembly'e derlenmiş Rust motoruyla canlı olarak şifreler ve özetler.</sub>
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


## Kurulum

| Platform | Komut satırı + terminal arayüzü | Masaüstü uygulaması |
|---|---|---|
| **macOS** | `brew install zlixas/tap/easylock` | [Apple Silicon `.dmg`](https://github.com/zlixas/easylock/releases/latest/download/easylock-desktop-macos-arm64.dmg) · [Intel `.dmg`](https://github.com/zlixas/easylock/releases/latest/download/easylock-desktop-macos-x64.dmg) |
| **Linux** | `curl -fsSL https://raw.githubusercontent.com/zlixas/easylock/main/install.sh \| sh` | [`.AppImage`](https://github.com/zlixas/easylock/releases/latest/download/easylock-desktop-linux-x64.AppImage) · [`.deb`](https://github.com/zlixas/easylock/releases/latest/download/easylock-desktop-linux-x64.deb) |
| **Windows** | `irm https://raw.githubusercontent.com/zlixas/easylock/main/install.ps1 \| iex` | [`.exe`](https://github.com/zlixas/easylock/releases/latest/download/easylock-desktop-windows-x64.exe) · [`.msi`](https://github.com/zlixas/easylock/releases/latest/download/easylock-desktop-windows-x64.msi) |
| **Web** | kurulum yok: **<https://zlixas.github.io/easylock/>** (PWA olarak çevrimdışı çalışır) | |
| **Kaynak** | `cargo install --git https://github.com/zlixas/easylock easylock-cli` | `cd crates/easylock-gui && cargo tauri build` |

Kurulum betikleri indirilen dosyayı sürümün `SHA256SUMS` dosyasıyla doğrular. Tüm dosyalar Ed25519 ile imzalı `SHA256SUMS` içinde listelenir ve GitHub derleme kanıtına sahiptir. Masaüstü uygulamaları henüz Apple/Microsoft imzalı değil: macOS'ta ilk seferde sağ tık → **Aç**, Windows'ta **Ek bilgi → Yine de çalıştır**.

## Hızlı başlangıç

```sh
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

## Sık sorulanlar

<details>
<summary><b>Web sitesini kullanınca dosyalarım bir yere yükleniyor mu?</b></summary>

Hayır. Rust motoru tarayıcınızda WebAssembly olarak çalışır. Güvenlik politikası (CSP) yalnızca sitenin kendi dosyalarına izin verir ve site bir kez açıldıktan sonra uçak modunda da çalışır.
</details>

<details>
<summary><b>Sitede kilitlenen dosya terminalde açılır mı?</b></summary>

Evet. Web sitesi, CLI, terminal arayüzü ve masaüstü uygulaması aynı `.elk` biçimini bayt bayt okur ve yazar.
</details>

<details>
<summary><b>Açık anahtarlı dosyalarda "kuantum sonrası" ne demek?</b></summary>

Her alıcı yuvası X25519'u ML-KEM-768 (FIPS 203) ile birleştirir. Saldırganın ikisini de kırması gerekir; yalnızca X25519'u kıran bir kuantum bilgisayar dosyayı açamaz.
</details>

<details>
<summary><b>age veya GPG'den farkı ne?</b></summary>

age ve GPG olgun ve denetlenmiş araçlardır; gerçek sırlar için onları tercih edin. easylock **okunmak ve öğrenilmek** için var: altındaki her yapı taşı bu depoda, okunabilir, test edilmiş ve açıklanmış halde; üstelik hepsi tarayıcıda da çalışır.
</details>

<details>
<summary><b>Parolamı unutursam?</b></summary>

Dosya kurtarılamaz; amaç da budur. Önemli dosyalar için ikinci bir yol olarak açık anahtarınızı ekleyin: `easylock lock dosya -r "$(easylock identity --show)" --with-password`.
</details>

## Lisans

Apache-2.0 **veya** MIT lisansı altında dağıtılır. İkisinden birini seçebilirsiniz.

<div align="center">
<br>
<sub>🦀 · <a href="https://zlixas.github.io/easylock/">zlixas.github.io/easylock</a></sub>
</div>
