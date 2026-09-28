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

<h3><a href="https://zlixas.github.io/easylock/">🌐 Abrir la app web</a> &nbsp;·&nbsp; <a href="#instalar">⬇️ Instalar</a> &nbsp;·&nbsp; <a href="docs/FILE_FORMAT.md">📄 Formato de archivo</a> &nbsp;·&nbsp; <a href="docs/ARCHITECTURE.md">🧭 Arquitectura</a></h3>

[English](README.md) · [Türkçe](README.tr.md) · Español

</div>

<br>

**easylock** es un kit de criptografía escrito **desde cero en Rust**, con cada primitiva, de AES al poscuántico ML-KEM, implementada desde los principios y **sin dependencias**. El mismo motor impulsa una **línea de comandos**, una **interfaz de terminal**, una **app de escritorio** y un **sitio web que se ejecuta por completo en su navegador**, y los cuatro comparten un formato de archivo cifrado.

<table>
<tr>
<td width="33%" valign="top">

### 📦 Cifre cualquier cosa
Archivos y carpetas completas, con contraseña, con **claves públicas** de otras personas o ambas. Flujo a GB/s con memoria constante.

</td>
<td width="33%" valign="top">

### 🛰️ Compartir poscuántico
Los destinatarios usan una clave híbrida **X25519 + ML-KEM-768**: los archivos grabados siguen seguros ante un futuro ordenador cuántico.

</td>
<td width="33%" valign="top">

### 🔐 Almacenes cifrados
Una carpeta donde los archivos **siguen cifrados**. Nombres y tamaños también ocultos; se sincroniza con iCloud, Dropbox o Git.

</td>
</tr>
<tr>
<td valign="top">

### 🎓 Aprenda practicando
20 herramientas interactivas con panel **Aprender** (*qué · cómo · cuándo · cuidado*) en español, inglés y turco.

</td>
<td valign="top">

### ⚡ Realmente rápido
Rutas AES-NI / ARMv8, PCLMUL / PMULL, SHA-NI, NEON y SSE2 escritas a mano: **4,3 GB/s** AES-GCM, **2,4 GB/s** SHA-256.

</td>
<td valign="top">

### 🧪 Hecho para verificarse
Vectores oficiales NIST/RFC, **1.485 casos Wycheproof**, fuzzing, pruebas diferenciales y versiones firmadas.

</td>
</tr>
</table>

<div align="center">
<a href="https://zlixas.github.io/easylock/"><picture><source media="(prefers-color-scheme: light)" srcset="docs/images/web-home-light.png"><img src="docs/images/web-home.png" alt="easylock web" width="100%"></picture></a>
<sub>Una app al estilo de macOS en su navegador, en modo claro y oscuro. La página de inicio cifra y calcula el hash de lo que escribe, en vivo, con el motor en Rust compilado a WebAssembly.</sub>
</div>

> [!WARNING]
> **Proyecto educativo y sin auditar.** Cada primitiva está implementada desde cero y comprobada con vectores de prueba
> oficiales (NIST, FIPS, RFC). Esa comprobación es necesaria, pero **no basta** para usar el código en producción.
> Para proteger secretos reales, use bibliotecas auditadas como `ring`, RustCrypto o libsodium.

## ¿Por qué easylock?

- **Escrito desde cero.** `easylock-core` no tiene dependencias en tiempo de ejecución. Implementa SHA-2/3, BLAKE3, AES-GCM,
  ChaCha20-Poly1305, Argon2id, Curve25519, RSA y el algoritmo post-cuántico ML-KEM en Rust legible.
- **Verificado.** Más de 170 pruebas comparan el código con vectores publicados, y compila sin ningún aviso con `clippy::pedantic`.
- **Explicado.** Cada herramienta del sitio tiene un panel **Aprender** que explica *qué es*, *cómo funciona*,
  *cuándo usarla* y *con qué tener cuidado*, en tres idiomas.
- **Interoperable.** Un archivo `.elk` que bloquee en la terminal se abre en el sitio web, y uno que bloquee en el sitio se abre en la terminal.
- **Privado.** El sitio ejecuta el mismo núcleo de Rust compilado a WebAssembly, así que ningún dato sale de su dispositivo.


## Instalar

| Plataforma | Línea de comandos + interfaz de terminal | App de escritorio |
|---|---|---|
| **macOS** | `brew install zlixas/tap/easylock` | [Apple Silicon `.dmg`](https://github.com/zlixas/easylock/releases/latest/download/easylock-desktop-macos-arm64.dmg) · [Intel `.dmg`](https://github.com/zlixas/easylock/releases/latest/download/easylock-desktop-macos-x64.dmg) |
| **Linux** | `curl -fsSL https://raw.githubusercontent.com/zlixas/easylock/main/install.sh \| sh` | [`.AppImage`](https://github.com/zlixas/easylock/releases/latest/download/easylock-desktop-linux-x64.AppImage) · [`.deb`](https://github.com/zlixas/easylock/releases/latest/download/easylock-desktop-linux-x64.deb) |
| **Windows** | `irm https://raw.githubusercontent.com/zlixas/easylock/main/install.ps1 \| iex` | [`.exe`](https://github.com/zlixas/easylock/releases/latest/download/easylock-desktop-windows-x64.exe) · [`.msi`](https://github.com/zlixas/easylock/releases/latest/download/easylock-desktop-windows-x64.msi) |
| **Web** | nada que instalar: **<https://zlixas.github.io/easylock/>** (funciona sin conexión como PWA) | |
| **Código fuente** | `cargo install --git https://github.com/zlixas/easylock easylock-cli` | `cd crates/easylock-gui && cargo tauri build` |

Los scripts comprueban la descarga contra el `SHA256SUMS` de la versión. Cada archivo figura en el `SHA256SUMS` firmado con Ed25519 y tiene procedencia de compilación de GitHub. Las apps de escritorio aún no están firmadas por Apple/Microsoft: en macOS, clic derecho → **Abrir** la primera vez; en Windows, **Más información → Ejecutar de todas formas**.

## Inicio rápido

```sh
easylock --lang es tui                     # interfaz de terminal a pantalla completa
easylock lock impuestos.pdf                # → impuestos.pdf.elk (pide una contraseña)
easylock unlock impuestos.pdf.elk
easylock lock ~/Fotos --shred              # carpeta entera → un .elk, originales borrados
easylock identity                          # su par de claves (X25519 + ML-KEM-768)
easylock lock informe.pdf -r elkpub1…      # cifrar para alguien sin contraseña compartida
echo -n abc | easylock hash -a blake3
easylock password -n 3 -l 24 --symbols
easylock --lang es --help
```

Si su sistema tiene configurado `LANG=es_ES.UTF-8`, la interfaz se abre en español sin necesidad de `--lang`.

## Contenido

| Familia | Algoritmos |
|---|---|
| Hash | SHA-256/512, SHA3-256/512, SHAKE, Keccak-256, BLAKE2b, BLAKE3 |
| MAC | HMAC, Poly1305 |
| Derivación de claves | Argon2id/i/d (PHC), PBKDF2, HKDF |
| AEAD | AES-256-GCM (acelerado por hardware), ChaCha20-Poly1305 |
| Curvas elípticas | X25519, Ed25519 |
| RSA | generación de claves, PKCS#1 v1.5, OAEP |
| Post-cuántico | ML-KEM-512/768/1024 (FIPS 203) |
| Contenedores | archivos `.elk` y tokens de texto `elk1.` ([formato](docs/FILE_FORMAT.md)) |


## Almacén cifrado

Un almacén es una carpeta donde los archivos **siguen cifrados**. Los nombres, tamaños y fechas también quedan ocultos en un índice cifrado.

```sh
easylock vault init ~/Privado.vault
easylock vault add  ~/Privado.vault impuestos/ dni.pdf --shred
easylock vault ls   ~/Privado.vault
easylock vault get  ~/Privado.vault impuestos -o ~/Escritorio
easylock vault passwd ~/Privado.vault -r elkpub1…   # cambiar claves sin volver a cifrar los archivos
```

## Las cuatro interfaces

- **🌐 Sitio web:** 20 herramientas en 5 categorías. Incluye cifrado de archivos y mensajes, hash en vivo,
  verificación de sumas, hash y verificación con Argon2, una demostración del intercambio X25519, un inspector de JWT, un
  analizador de fortaleza de contraseñas y generadores de UUID y PIN, entre otras. <kbd>Ctrl</kbd>+<kbd>K</kbd> abre la paleta de comandos,
  y el diseño se adapta a móviles.
- **⌨️ Interfaz de terminal (`easylock tui`):** 9 herramientas. <kbd>F2</kbd> cambia el idioma, <kbd>F5</kbd> copia y <kbd>F1</kbd> abre la ayuda.
- **💻 Línea de comandos:** `hash`, `encode`/`decode`, `encrypt`/`decrypt`, `lock`/`unlock`, `hmac`, `kdf`, `password`,
  `keygen`, `sign`/`verify`, `info`, `tui`
- **🖥️ Escritorio (Tauri v2):** pestañas de archivos, hash, conversión y claves, en EN/TR/ES.

## Compilar y probar

```sh
cargo test --workspace
cargo clippy --workspace --all-targets
cd crates/easylock-web && npm install && npm run wasm && npm run dev
```

Consulte la [arquitectura](docs/ARCHITECTURE.md) para conocer el diseño, [CONTRIBUTING.md](CONTRIBUTING.md) para contribuir y
[SECURITY.md](SECURITY.md) para la política de seguridad.

## Preguntas frecuentes

<details>
<summary><b>¿Se suben mis archivos al usar el sitio web?</b></summary>

No. El motor en Rust se ejecuta en su navegador como WebAssembly. La política de seguridad (CSP) solo permite los archivos del propio sitio y, tras la primera visita, funciona en modo avión.
</details>

<details>
<summary><b>¿Un archivo bloqueado en el sitio se abre en la terminal?</b></summary>

Sí. El sitio, la CLI, la interfaz de terminal y la app de escritorio leen y escriben el mismo formato `.elk`, byte a byte.
</details>

<details>
<summary><b>¿Qué significa "poscuántico" en los archivos de clave pública?</b></summary>

Cada ranura de destinatario combina X25519 con ML-KEM-768 (FIPS 203). Hay que romper ambos, así que un ordenador cuántico que rompa solo X25519 no abre el archivo.
</details>

<details>
<summary><b>¿En qué se diferencia de age o GPG?</b></summary>

age y GPG son herramientas maduras y revisadas; prefiéralas para secretos reales. easylock existe para **leerse y aprender**: cada primitiva está en este repositorio, legible, probada y explicada, y todo funciona también en el navegador.
</details>

<details>
<summary><b>¿Y si olvido mi contraseña?</b></summary>

El archivo no se puede recuperar; esa es la idea. Para archivos importantes, añada su clave pública como segunda vía: `easylock lock archivo -r "$(easylock identity --show)" --with-password`.
</details>

## Licencia

Se distribuye bajo Apache-2.0 **o** MIT, a su elección.

<div align="center">
<br>
<sub>🦀 · <a href="https://zlixas.github.io/easylock/">zlixas.github.io/easylock</a></sub>
</div>
