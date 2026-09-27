<div align="center">

# 🔒 easylock

**Criptografía escrita desde cero en Rust, que puede ver por dentro, estudiar y probar.**

Un núcleo sin dependencias y cuatro formas de usarlo: **línea de comandos**, **interfaz de terminal**,
**aplicación de escritorio** y **un sitio web que se ejecuta por completo en su navegador**.

[![CI](https://github.com/zlixas/easylock/actions/workflows/ci.yml/badge.svg)](https://github.com/zlixas/easylock/actions/workflows/ci.yml)
[![Pages](https://github.com/zlixas/easylock/actions/workflows/pages.yml/badge.svg)](https://zlixas.github.io/easylock/)
[![Licencia: MIT O Apache-2.0](https://img.shields.io/badge/licencia-MIT%20%2F%20Apache--2.0-blue.svg)](#licencia)

**[🌐 Pruébelo en el navegador →](https://zlixas.github.io/easylock/)**

[English](README.md) · [Türkçe](README.tr.md) · Español

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

## Inicio rápido

```sh
cargo install --git https://github.com/zlixas/easylock easylock-cli

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

## Licencia

Se distribuye bajo Apache-2.0 **o** MIT, a su elección.
