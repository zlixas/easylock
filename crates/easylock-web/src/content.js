// Tool catalogue: names, one-line summaries, search keywords and the
// educational "Learn" panel for every tool, in English, Turkish and Spanish.

export const CATEGORIES = [
  { id: "sym", key: "nav.symmetric", emoji: "🔒" },
  { id: "asym", key: "nav.asymmetric", emoji: "🔑" },
  { id: "hash", key: "nav.hashing", emoji: "⚡" },
  { id: "pipe", key: "nav.pipeline", emoji: "🔄" },
  { id: "util", key: "nav.utilities", emoji: "🛡️" },
];

export const META = {
  /* ------------------------------------------------------------ symmetric */
  "sym.file": {
    cat: "sym", emoji: "📦", spec: ".elk · Argon2id + AEAD",
    name: { en: "Encrypt a file", tr: "Dosya şifrele", es: "Cifrar un archivo" },
    summary: {
      en: "Lock any file with a password. The result opens with the easylock CLI, TUI and desktop app too.",
      tr: "Herhangi bir dosyayı parolayla kilitleyin. Sonuç easylock CLI, TUI ve masaüstü uygulamasıyla da açılır.",
      es: "Bloquee cualquier archivo con una contraseña. El resultado también se abre con la CLI, la TUI y la app de escritorio.",
    },
    keywords: "file lock password elk dosya kilit archivo",
    learn: {
      what: {
        en: "Password-based file encryption: your password is stretched into a 256-bit key, and the file is encrypted and authenticated with an AEAD cipher.",
        tr: "Parola tabanlı dosya şifreleme: parolanız 256 bitlik bir anahtara dönüştürülür ve dosya bir AEAD şifresiyle hem şifrelenir hem de doğrulanır.",
        es: "Cifrado de archivos basado en contraseña: su contraseña se convierte en una clave de 256 bits y el archivo se cifra y autentica con un cifrado AEAD.",
      },
      how: {
        en: "A random 16-byte salt + Argon2id (64 MiB, 3 passes) derive the key. The file is split into 256 KiB chunks; each chunk gets its own nonce and is sealed with AES-256-GCM or ChaCha20-Poly1305. The chunk index and a 'last chunk' flag are authenticated, so chunks cannot be reordered, dropped or truncated.",
        tr: "Rastgele 16 baytlık bir tuz + Argon2id (64 MiB, 3 geçiş) anahtarı türetir. Dosya 256 KiB'lık parçalara bölünür; her parça kendi nonce'u ile AES-256-GCM veya ChaCha20-Poly1305 kullanılarak mühürlenir. Parça sırası ve 'son parça' bayrağı doğrulandığı için parçalar yer değiştiremez, silinemez veya kesilemez.",
        es: "Una sal aleatoria de 16 bytes + Argon2id (64 MiB, 3 pasadas) derivan la clave. El archivo se divide en bloques de 256 KiB; cada bloque tiene su propio nonce y se sella con AES-256-GCM o ChaCha20-Poly1305. El índice del bloque y una marca de 'último bloque' se autentican, así que no se pueden reordenar, eliminar ni truncar.",
      },
      when: {
        en: "Backing up documents to the cloud, sending a file over an untrusted channel, keeping a private archive on a USB stick.",
        tr: "Belgeleri buluta yedeklerken, bir dosyayı güvenilmeyen bir kanaldan gönderirken, bir USB bellekte özel arşiv tutarken.",
        es: "Copias de seguridad en la nube, enviar un archivo por un canal no confiable, guardar un archivo privado en un USB.",
      },
      careful: {
        en: "There is no password recovery — lose the password and the data is gone. Large files are processed in browser memory; use the CLI (`easylock lock`) for multi-GB files.",
        tr: "Parola kurtarma yoktur — parolayı kaybederseniz veri de gider. Büyük dosyalar tarayıcı belleğinde işlenir; çok GB'lık dosyalar için CLI'yi (`easylock lock`) kullanın.",
        es: "No hay recuperación de contraseña: si la pierde, pierde los datos. Los archivos grandes se procesan en la memoria del navegador; use la CLI (`easylock lock`) para archivos de varios GB.",
      },
    },
  },
  "sym.text": {
    cat: "sym", emoji: "✉️", spec: "elk1 token · Argon2id + AEAD",
    name: { en: "Encrypt a message", tr: "Mesaj şifrele", es: "Cifrar un mensaje" },
    summary: {
      en: "Turn a text message into a compact, copy-pasteable encrypted token protected by a password.",
      tr: "Bir metin mesajını parolayla korunan, kopyalanıp yapıştırılabilir kısa bir şifreli belirtece dönüştürün.",
      es: "Convierta un mensaje de texto en un token cifrado compacto, protegido por contraseña y fácil de copiar.",
    },
    keywords: "text message token password elk1 metin mesaj belirteç mensaje",
    learn: {
      what: {
        en: "An `elk1.` token is a self-contained encrypted message: everything needed to decrypt it (except the password) is inside.",
        tr: "`elk1.` belirteci kendi kendine yeten şifreli bir mesajdır: çözmek için gereken her şey (parola hariç) içindedir.",
        es: "Un token `elk1.` es un mensaje cifrado autónomo: contiene todo lo necesario para descifrarlo (excepto la contraseña).",
      },
      how: {
        en: "Layout: `elk1.` + Base64URL(cipher id ‖ 16-byte salt ‖ 12-byte nonce ‖ ciphertext ‖ 16-byte tag). The key comes from Argon2id (19 MiB, 2 passes — the OWASP interactive profile).",
        tr: "Yapı: `elk1.` + Base64URL(şifre kimliği ‖ 16 bayt tuz ‖ 12 bayt nonce ‖ şifreli metin ‖ 16 bayt etiket). Anahtar Argon2id'den (19 MiB, 2 geçiş — OWASP etkileşimli profili) gelir.",
        es: "Estructura: `elk1.` + Base64URL(id de cifrado ‖ sal de 16 bytes ‖ nonce de 12 bytes ‖ texto cifrado ‖ etiqueta de 16 bytes). La clave sale de Argon2id (19 MiB, 2 pasadas: el perfil interactivo de OWASP).",
      },
      when: {
        en: "Sharing a secret in chat or email when you can tell the password to the other person through a different channel (in person, by phone).",
        tr: "Parolayı karşı tarafa başka bir kanaldan (yüz yüze, telefonla) söyleyebildiğinizde, sohbet veya e-postada bir sır paylaşmak için.",
        es: "Compartir un secreto por chat o correo cuando puede decirle la contraseña a la otra persona por otro canal (en persona, por teléfono).",
      },
      careful: {
        en: "Never send the password in the same message as the token. Short passwords can be brute-forced — use a passphrase.",
        tr: "Parolayı asla belirteçle aynı mesajda göndermeyin. Kısa parolalar kaba kuvvetle kırılabilir — bir parola cümlesi kullanın.",
        es: "Nunca envíe la contraseña en el mismo mensaje que el token. Las contraseñas cortas pueden romperse por fuerza bruta: use una frase.",
      },
    },
  },
  "sym.aes": {
    cat: "sym", emoji: "🧱", spec: "NIST SP 800-38D · AEAD",
    name: { en: "AES-256-GCM", tr: "AES-256-GCM", es: "AES-256-GCM" },
    summary: {
      en: "The world's most widely deployed cipher, in authenticated Galois/Counter Mode. Raw key + nonce.",
      tr: "Dünyada en yaygın kullanılan şifre, doğrulamalı Galois/Sayaç Modunda. Ham anahtar + nonce.",
      es: "El cifrado más usado del mundo, en modo autenticado Galois/Contador. Clave + nonce en bruto.",
    },
    keywords: "aes gcm aead block cipher rijndael blok",
    learn: {
      what: {
        en: "AES is a 128-bit block cipher (standardised 2001). GCM turns it into an AEAD: it encrypts and produces a 16-byte tag that detects any tampering.",
        tr: "AES, 128 bitlik bir blok şifresidir (2001'de standartlaştı). GCM onu bir AEAD'e dönüştürür: şifreler ve her türlü değişikliği tespit eden 16 baytlık bir etiket üretir.",
        es: "AES es un cifrado por bloques de 128 bits (estandarizado en 2001). GCM lo convierte en AEAD: cifra y produce una etiqueta de 16 bytes que detecta cualquier manipulación.",
      },
      how: {
        en: "14 rounds of SubBytes/ShiftRows/MixColumns/AddRoundKey encrypt a counter stream (CTR mode) that is XORed with the data. GHASH — multiplication in GF(2¹²⁸) — authenticates the ciphertext and associated data. easylock uses AES-NI / ARMv8 instructions natively and a constant-time bitsliced fallback here in WebAssembly.",
        tr: "SubBytes/ShiftRows/MixColumns/AddRoundKey'in 14 turu, verilerle XOR'lanan bir sayaç akışını (CTR modu) şifreler. GHASH — GF(2¹²⁸) içinde çarpma — şifreli metni ve ilişkili veriyi doğrular. easylock yerelde AES-NI / ARMv8 komutlarını, burada WebAssembly'de ise sabit zamanlı bir yedek uygulamayı kullanır.",
        es: "14 rondas de SubBytes/ShiftRows/MixColumns/AddRoundKey cifran un flujo de contador (modo CTR) que se combina con XOR con los datos. GHASH —multiplicación en GF(2¹²⁸)— autentica el texto cifrado y los datos asociados. easylock usa AES-NI / ARMv8 de forma nativa y una implementación de tiempo constante aquí en WebAssembly.",
      },
      when: {
        en: "TLS, disk encryption, VPNs — anywhere you already share a random 256-bit key. For password-based encryption use “Encrypt a file” instead.",
        tr: "TLS, disk şifreleme, VPN'ler — zaten rastgele 256 bitlik bir anahtar paylaştığınız her yerde. Parola tabanlı şifreleme için “Dosya şifrele” aracını kullanın.",
        es: "TLS, cifrado de disco, VPN: donde ya comparta una clave aleatoria de 256 bits. Para cifrar con contraseña use “Cifrar un archivo”.",
      },
      careful: {
        en: "NEVER reuse a nonce with the same key — doing so leaks the XOR of the plaintexts and lets an attacker forge messages. Use a fresh random nonce every time.",
        tr: "Aynı anahtarla bir nonce'u ASLA tekrar kullanmayın — bu, düz metinlerin XOR'unu sızdırır ve saldırganın mesaj sahtelemesine izin verir. Her seferinde yeni rastgele bir nonce kullanın.",
        es: "NUNCA reutilice un nonce con la misma clave: filtra el XOR de los textos planos y permite falsificar mensajes. Use un nonce aleatorio nuevo cada vez.",
      },
    },
  },
  "sym.chacha": {
    cat: "sym", emoji: "💃", spec: "RFC 8439 · AEAD",
    name: { en: "ChaCha20-Poly1305", tr: "ChaCha20-Poly1305", es: "ChaCha20-Poly1305" },
    summary: {
      en: "A fast, software-friendly AEAD designed by Daniel J. Bernstein. Used by TLS 1.3, WireGuard and SSH.",
      tr: "Daniel J. Bernstein tarafından tasarlanmış hızlı, yazılım dostu bir AEAD. TLS 1.3, WireGuard ve SSH kullanır.",
      es: "Un AEAD rápido y apto para software diseñado por Daniel J. Bernstein. Lo usan TLS 1.3, WireGuard y SSH.",
    },
    keywords: "chacha poly1305 stream aead wireguard akış",
    learn: {
      what: {
        en: "ChaCha20 is a stream cipher built only from Add-Rotate-XOR (ARX) operations; Poly1305 is a one-time authenticator. Together they form an AEAD.",
        tr: "ChaCha20 yalnızca Topla-Döndür-XOR (ARX) işlemlerinden oluşan bir akış şifresidir; Poly1305 tek seferlik bir doğrulayıcıdır. Birlikte bir AEAD oluştururlar.",
        es: "ChaCha20 es un cifrado de flujo hecho solo con operaciones Suma-Rotación-XOR (ARX); Poly1305 es un autenticador de un solo uso. Juntos forman un AEAD.",
      },
      how: {
        en: "A 512-bit state (constants, key, counter, nonce) goes through 20 rounds of quarter-rounds to produce 64-byte keystream blocks. Block 0 supplies the Poly1305 key, which evaluates a polynomial modulo 2¹³⁰−5 over the ciphertext.",
        tr: "512 bitlik bir durum (sabitler, anahtar, sayaç, nonce), 64 baytlık anahtar akışı blokları üretmek için 20 tur çeyrek-turdan geçer. Blok 0, şifreli metin üzerinde 2¹³⁰−5 modunda bir polinom hesaplayan Poly1305 anahtarını sağlar.",
        es: "Un estado de 512 bits (constantes, clave, contador, nonce) pasa por 20 rondas de cuartos de ronda para producir bloques de 64 bytes de flujo. El bloque 0 da la clave de Poly1305, que evalúa un polinomio módulo 2¹³⁰−5 sobre el texto cifrado.",
      },
      when: {
        en: "On devices without AES hardware (phones, embedded, WebAssembly) it is faster than AES and naturally constant-time.",
        tr: "AES donanımı olmayan cihazlarda (telefonlar, gömülü sistemler, WebAssembly) AES'ten daha hızlıdır ve doğal olarak sabit zamanlıdır.",
        es: "En dispositivos sin hardware AES (móviles, embebidos, WebAssembly) es más rápido que AES y de tiempo constante por naturaleza.",
      },
      careful: {
        en: "Same rule as GCM: a (key, nonce) pair must never repeat. The 96-bit nonce is safe to pick at random for up to ~2³² messages per key.",
        tr: "GCM ile aynı kural: bir (anahtar, nonce) çifti asla tekrarlanmamalıdır. 96 bitlik nonce, anahtar başına ~2³² mesaja kadar rastgele seçilebilir.",
        es: "La misma regla que GCM: un par (clave, nonce) nunca debe repetirse. El nonce de 96 bits puede elegirse al azar hasta ~2³² mensajes por clave.",
      },
    },
  },

  /* ----------------------------------------------------------- asymmetric */
  "asym.ed25519": {
    cat: "asym", emoji: "✍️", spec: "RFC 8032 · EdDSA",
    name: { en: "Sign & verify (Ed25519)", tr: "İmzala & doğrula (Ed25519)", es: "Firmar y verificar (Ed25519)" },
    summary: {
      en: "Digital signatures: prove a message was written by the holder of a secret key and not modified.",
      tr: "Dijital imzalar: bir mesajın gizli anahtar sahibi tarafından yazıldığını ve değiştirilmediğini kanıtlayın.",
      es: "Firmas digitales: demuestre que un mensaje lo escribió quien tiene la clave secreta y que no se modificó.",
    },
    keywords: "sign signature verify ed25519 eddsa imza firma",
    learn: {
      what: {
        en: "Ed25519 is an elliptic-curve signature scheme. Anyone with your 32-byte public key can check a 64-byte signature; only your secret seed can create one.",
        tr: "Ed25519 bir eliptik eğri imza şemasıdır. 32 baytlık açık anahtarınıza sahip herkes 64 baytlık bir imzayı kontrol edebilir; imzayı yalnızca gizli tohumunuz oluşturabilir.",
        es: "Ed25519 es un esquema de firma de curva elíptica. Cualquiera con su clave pública de 32 bytes puede comprobar una firma de 64 bytes; solo su semilla secreta puede crearla.",
      },
      how: {
        en: "The seed is hashed with SHA-512 into a scalar a and a prefix. Signing computes a deterministic nonce r = H(prefix‖M), R = r·B, S = r + H(R‖A‖M)·a (mod ℓ). Verification checks S·B = R + H(R‖A‖M)·A on the twisted Edwards curve.",
        tr: "Tohum, SHA-512 ile bir a skalerine ve bir öneke dönüştürülür. İmzalama, deterministik bir nonce r = H(önek‖M), R = r·B, S = r + H(R‖A‖M)·a (mod ℓ) hesaplar. Doğrulama, bükülmüş Edwards eğrisinde S·B = R + H(R‖A‖M)·A'yı kontrol eder.",
        es: "La semilla se resume con SHA-512 en un escalar a y un prefijo. Firmar calcula un nonce determinista r = H(prefijo‖M), R = r·B, S = r + H(R‖A‖M)·a (mod ℓ). Verificar comprueba S·B = R + H(R‖A‖M)·A en la curva de Edwards torcida.",
      },
      when: {
        en: "Software releases, Git commits, SSH keys, package managers, JWTs (EdDSA).",
        tr: "Yazılım sürümleri, Git commit'leri, SSH anahtarları, paket yöneticileri, JWT'ler (EdDSA).",
        es: "Publicación de software, commits de Git, claves SSH, gestores de paquetes, JWT (EdDSA).",
      },
      careful: {
        en: "A signature proves who signed, not that the content is secret — the message stays readable. Keep the seed offline; anyone who has it can sign as you.",
        tr: "İmza kimin imzaladığını kanıtlar, içeriğin gizli olduğunu değil — mesaj okunabilir kalır. Tohumu çevrimdışı tutun; ona sahip olan herkes sizin adınıza imzalayabilir.",
        es: "Una firma prueba quién firmó, no que el contenido sea secreto: el mensaje sigue siendo legible. Guarde la semilla sin conexión; quien la tenga puede firmar como usted.",
      },
    },
  },
  "asym.x25519": {
    cat: "asym", emoji: "🤝", spec: "RFC 7748 · ECDH",
    name: { en: "Key exchange (X25519)", tr: "Anahtar değişimi (X25519)", es: "Intercambio de claves (X25519)" },
    summary: {
      en: "Watch Alice and Bob agree on the same secret over a public channel — without ever sending it.",
      tr: "Alice ve Bob'un, sırrı hiç göndermeden, açık bir kanal üzerinden aynı sırda anlaşmasını izleyin.",
      es: "Vea cómo Alice y Bob acuerdan el mismo secreto por un canal público, sin enviarlo nunca.",
    },
    keywords: "x25519 ecdh diffie hellman key exchange agreement anahtar değişimi intercambio",
    learn: {
      what: {
        en: "Diffie–Hellman key agreement on Curve25519. Each side publishes a public key; combining your secret with their public key gives a shared secret an eavesdropper cannot compute.",
        tr: "Curve25519 üzerinde Diffie–Hellman anahtar anlaşması. Her taraf bir açık anahtar yayınlar; kendi gizli anahtarınızı onların açık anahtarıyla birleştirmek, dinleyen birinin hesaplayamayacağı ortak bir sır verir.",
        es: "Acuerdo de claves Diffie–Hellman sobre Curve25519. Cada parte publica una clave pública; combinar su secreto con la clave pública del otro da un secreto compartido que un espía no puede calcular.",
      },
      how: {
        en: "Public key = a·G. Alice computes a·(b·G), Bob computes b·(a·G) — both equal (ab)·G. The Montgomery ladder performs the scalar multiplication in constant time using only the x-coordinate.",
        tr: "Açık anahtar = a·G. Alice a·(b·G), Bob b·(a·G) hesaplar — ikisi de (ab)·G'ye eşittir. Montgomery merdiveni skaler çarpımı yalnızca x koordinatını kullanarak sabit zamanda yapar.",
        es: "Clave pública = a·G. Alice calcula a·(b·G), Bob calcula b·(a·G): ambos son (ab)·G. La escalera de Montgomery hace la multiplicación escalar en tiempo constante usando solo la coordenada x.",
      },
      when: {
        en: "Every TLS 1.3 handshake, Signal, WireGuard and SSH use X25519 to create session keys.",
        tr: "Her TLS 1.3 el sıkışması, Signal, WireGuard ve SSH oturum anahtarları oluşturmak için X25519 kullanır.",
        es: "Cada handshake de TLS 1.3, Signal, WireGuard y SSH usan X25519 para crear claves de sesión.",
      },
      careful: {
        en: "Plain DH is unauthenticated — a man-in-the-middle can run two exchanges. Real protocols sign the public keys. Pass the raw shared secret through a KDF (e.g. HKDF) before using it as a key.",
        tr: "Düz DH kimlik doğrulamasızdır — ortadaki adam iki ayrı değişim yürütebilir. Gerçek protokoller açık anahtarları imzalar. Ham ortak sırrı anahtar olarak kullanmadan önce bir KDF'den (ör. HKDF) geçirin.",
        es: "El DH simple no está autenticado: un intermediario puede hacer dos intercambios. Los protocolos reales firman las claves públicas. Pase el secreto bruto por un KDF (p. ej., HKDF) antes de usarlo como clave.",
      },
    },
  },
  "asym.kyber": {
    cat: "asym", emoji: "🛰️", spec: "FIPS 203 · post-quantum",
    name: { en: "ML-KEM (Kyber)", tr: "ML-KEM (Kyber)", es: "ML-KEM (Kyber)" },
    summary: {
      en: "NIST's post-quantum key-encapsulation standard. Safe even against a future quantum computer.",
      tr: "NIST'in kuantum sonrası anahtar kapsülleme standardı. Gelecekteki bir kuantum bilgisayara karşı bile güvenli.",
      es: "El estándar post-cuántico de encapsulación de claves de NIST. Seguro incluso frente a un futuro ordenador cuántico.",
    },
    keywords: "kyber mlkem kem post quantum lattice kuantum cuántico",
    learn: {
      what: {
        en: "A Key Encapsulation Mechanism: the sender uses your public key to create a random shared secret plus a ciphertext; only your secret key can recover the same secret from the ciphertext.",
        tr: "Bir Anahtar Kapsülleme Mekanizması: gönderen, açık anahtarınızı kullanarak rastgele bir ortak sır ve bir şifreli metin oluşturur; aynı sırrı şifreli metinden yalnızca sizin gizli anahtarınız çıkarabilir.",
        es: "Un mecanismo de encapsulación de claves: el emisor usa su clave pública para crear un secreto compartido aleatorio y un texto cifrado; solo su clave secreta puede recuperar el mismo secreto.",
      },
      how: {
        en: "Security rests on Module Learning-With-Errors: solving noisy linear equations over polynomial rings Z_q[X]/(X²⁵⁶+1), q = 3329. The Number-Theoretic Transform makes the polynomial multiplication fast; the Fujisaki–Okamoto transform makes it CCA-secure.",
        tr: "Güvenlik, Modül Hatalarla Öğrenme'ye dayanır: Z_q[X]/(X²⁵⁶+1), q = 3329 polinom halkaları üzerinde gürültülü doğrusal denklemleri çözmek. Sayı Kuramsal Dönüşüm polinom çarpımını hızlandırır; Fujisaki–Okamoto dönüşümü onu CCA-güvenli yapar.",
        es: "La seguridad se basa en Module Learning-With-Errors: resolver ecuaciones lineales con ruido sobre anillos de polinomios Z_q[X]/(X²⁵⁶+1), q = 3329. La Transformada Teórica de Números acelera la multiplicación; la transformación Fujisaki–Okamoto la hace segura frente a CCA.",
      },
      when: {
        en: "Protecting today's traffic against “harvest now, decrypt later”. Chrome, Cloudflare and Signal already combine ML-KEM with X25519 (hybrid).",
        tr: "Bugünün trafiğini “şimdi topla, sonra çöz” saldırısına karşı korumak için. Chrome, Cloudflare ve Signal zaten ML-KEM'i X25519 ile birleştiriyor (hibrit).",
        es: "Proteger el tráfico actual contra “recolectar ahora, descifrar después”. Chrome, Cloudflare y Signal ya combinan ML-KEM con X25519 (híbrido).",
      },
      careful: {
        en: "Keys and ciphertexts are much bigger than elliptic-curve ones (ML-KEM-768: 1184-byte public key). Use a hybrid with X25519 while the algorithm matures.",
        tr: "Anahtarlar ve şifreli metinler eliptik eğrilerdekinden çok daha büyüktür (ML-KEM-768: 1184 baytlık açık anahtar). Algoritma olgunlaşırken X25519 ile hibrit kullanın.",
        es: "Las claves y textos cifrados son mucho mayores que los de curva elíptica (ML-KEM-768: clave pública de 1184 bytes). Use un híbrido con X25519 mientras el algoritmo madura.",
      },
    },
  },
  "asym.rsa": {
    cat: "asym", emoji: "🏛️", spec: "PKCS#1 · 2048-bit",
    name: { en: "RSA key pair", tr: "RSA anahtar çifti", es: "Par de claves RSA" },
    summary: {
      en: "Generate a 2048-bit RSA key from scratch: prime search, modular inverse and CRT components.",
      tr: "Sıfırdan 2048 bitlik bir RSA anahtarı üretin: asal arama, modüler ters ve CRT bileşenleri.",
      es: "Genere una clave RSA de 2048 bits desde cero: búsqueda de primos, inverso modular y componentes CRT.",
    },
    keywords: "rsa prime pkcs oaep asal primo",
    learn: {
      what: {
        en: "RSA (1977) was the first practical public-key system. Its security relies on how hard it is to factor n = p·q.",
        tr: "RSA (1977) ilk pratik açık anahtar sistemiydi. Güvenliği n = p·q'yu çarpanlarına ayırmanın ne kadar zor olduğuna dayanır.",
        es: "RSA (1977) fue el primer sistema práctico de clave pública. Su seguridad depende de lo difícil que es factorizar n = p·q.",
      },
      how: {
        en: "Pick two random 1024-bit primes (Miller–Rabin tests), n = p·q, e = 65537, d = e⁻¹ mod λ(n). Encryption is m^e mod n; decryption is c^d mod n, sped up ~4× with the Chinese Remainder Theorem (dp, dq, qinv).",
        tr: "Rastgele iki 1024 bitlik asal seçin (Miller–Rabin testleri), n = p·q, e = 65537, d = e⁻¹ mod λ(n). Şifreleme m^e mod n; çözme c^d mod n'dir ve Çin Kalan Teoremi (dp, dq, qinv) ile ~4 kat hızlanır.",
        es: "Elija dos primos aleatorios de 1024 bits (pruebas de Miller–Rabin), n = p·q, e = 65537, d = e⁻¹ mod λ(n). Cifrar es m^e mod n; descifrar es c^d mod n, ~4× más rápido con el Teorema Chino del Resto (dp, dq, qinv).",
      },
      when: {
        en: "Legacy compatibility: older TLS certificates, PGP, smart cards. For new designs prefer Ed25519 / X25519.",
        tr: "Eski sistemlerle uyumluluk: eski TLS sertifikaları, PGP, akıllı kartlar. Yeni tasarımlar için Ed25519 / X25519'u tercih edin.",
        es: "Compatibilidad heredada: certificados TLS antiguos, PGP, tarjetas inteligentes. Para diseños nuevos prefiera Ed25519 / X25519.",
      },
      careful: {
        en: "Never use “textbook” RSA — always a padding scheme (OAEP for encryption, PSS/PKCS#1 v1.5 for signatures). RSA is broken by a large quantum computer.",
        tr: "Asla “ders kitabı” RSA kullanmayın — her zaman bir dolgu şeması kullanın (şifreleme için OAEP, imza için PSS/PKCS#1 v1.5). RSA büyük bir kuantum bilgisayar tarafından kırılır.",
        es: "Nunca use RSA “de libro”: siempre un esquema de relleno (OAEP para cifrar, PSS/PKCS#1 v1.5 para firmar). Un ordenador cuántico grande rompe RSA.",
      },
    },
  },

  /* -------------------------------------------------------------- hashing */
  "hash.sha": {
    cat: "hash", emoji: "🔎", spec: "FIPS 180-4 · FIPS 202 · BLAKE3",
    name: { en: "Hash (live)", tr: "Özet (canlı)", es: "Hash (en vivo)" },
    summary: {
      en: "See every digest of your text or file update as you type — SHA-256, SHA-512, SHA3-256, Keccak-256 and BLAKE3.",
      tr: "Metninizin veya dosyanızın tüm özetlerinin siz yazdıkça güncellenmesini izleyin — SHA-256, SHA-512, SHA3-256, Keccak-256 ve BLAKE3.",
      es: "Vea cómo cada resumen de su texto o archivo se actualiza mientras escribe: SHA-256, SHA-512, SHA3-256, Keccak-256 y BLAKE3.",
    },
    keywords: "hash digest sha256 sha512 sha3 keccak blake3 özet resumen",
    learn: {
      what: {
        en: "A cryptographic hash turns any input into a fixed-size fingerprint. Change one bit and about half of the output bits flip (the avalanche effect). It's one-way: you cannot recover the input.",
        tr: "Kriptografik özet, herhangi bir girdiyi sabit boyutlu bir parmak izine dönüştürür. Bir biti değiştirin, çıktı bitlerinin yaklaşık yarısı değişir (çığ etkisi). Tek yönlüdür: girdiyi geri elde edemezsiniz.",
        es: "Un hash criptográfico convierte cualquier entrada en una huella de tamaño fijo. Cambie un bit y cambian cerca de la mitad de los bits de salida (efecto avalancha). Es unidireccional: no se puede recuperar la entrada.",
      },
      how: {
        en: "SHA-2 uses the Merkle–Damgård construction with 64/80 compression rounds. SHA-3 and Keccak use a sponge over a 1600-bit permutation. BLAKE3 uses a binary Merkle tree of ChaCha-like compressions, so it parallelises.",
        tr: "SHA-2, 64/80 sıkıştırma turlu Merkle–Damgård yapısını kullanır. SHA-3 ve Keccak, 1600 bitlik bir permütasyon üzerinde sünger yapısı kullanır. BLAKE3, ChaCha benzeri sıkıştırmalardan oluşan ikili bir Merkle ağacı kullanır, bu yüzden paralelleşir.",
        es: "SHA-2 usa la construcción Merkle–Damgård con 64/80 rondas de compresión. SHA-3 y Keccak usan una esponja sobre una permutación de 1600 bits. BLAKE3 usa un árbol de Merkle binario de compresiones tipo ChaCha, por lo que se paraleliza.",
      },
      when: {
        en: "Checking file integrity, content addressing (Git, IPFS), building blocks for signatures, HMAC and KDFs. Keccak-256 is what Ethereum uses.",
        tr: "Dosya bütünlüğünü kontrol etmek, içerik adreslemesi (Git, IPFS), imzalar, HMAC ve KDF'ler için yapı taşı. Keccak-256, Ethereum'un kullandığıdır.",
        es: "Comprobar la integridad de archivos, direccionamiento por contenido (Git, IPFS), base de firmas, HMAC y KDF. Keccak-256 es el que usa Ethereum.",
      },
      careful: {
        en: "Do NOT store passwords with a plain hash — they are too fast to brute-force. Use Argon2id. MD5 and SHA-1 are broken; they are intentionally not offered.",
        tr: "Parolaları düz bir özetle SAKLAMAYIN — kaba kuvvete karşı çok hızlıdırlar. Argon2id kullanın. MD5 ve SHA-1 kırılmıştır; bilerek sunulmuyorlar.",
        es: "NO guarde contraseñas con un hash simple: son demasiado rápidos de romper. Use Argon2id. MD5 y SHA-1 están rotos; a propósito no se ofrecen.",
      },
    },
  },
  "hash.verify": {
    cat: "hash", emoji: "✅", spec: "hash + constant-time compare",
    name: { en: "Verify a checksum", tr: "Sağlama doğrula", es: "Verificar una suma" },
    summary: {
      en: "Drop a download and paste the checksum from the website. The algorithm is detected automatically.",
      tr: "İndirdiğiniz dosyayı bırakın ve web sitesindeki sağlamayı yapıştırın. Algoritma otomatik algılanır.",
      es: "Suelte una descarga y pegue la suma del sitio web. El algoritmo se detecta automáticamente.",
    },
    keywords: "checksum verify integrity download sağlama bütünlük integridad",
    learn: {
      what: {
        en: "A checksum is the hash of a file published by its author. If your copy hashes to the same value, it is bit-for-bit identical.",
        tr: "Sağlama, yazarı tarafından yayınlanan bir dosyanın özetidir. Kopyanız aynı değere özetleniyorsa, bit bit aynıdır.",
        es: "Una suma de verificación es el hash de un archivo publicado por su autor. Si su copia da el mismo valor, es idéntica bit a bit.",
      },
      how: {
        en: "The file is hashed locally, then compared with the expected value. The algorithm is guessed from the length (64 hex → SHA-256, 128 hex → SHA-512).",
        tr: "Dosya yerel olarak özetlenir, sonra beklenen değerle karşılaştırılır. Algoritma uzunluktan tahmin edilir (64 hex → SHA-256, 128 hex → SHA-512).",
        es: "El archivo se resume localmente y se compara con el valor esperado. El algoritmo se deduce de la longitud (64 hex → SHA-256, 128 hex → SHA-512).",
      },
      when: {
        en: "After downloading an OS image, installer or release binary.",
        tr: "Bir işletim sistemi imajı, yükleyici veya sürüm dosyası indirdikten sonra.",
        es: "Tras descargar una imagen de sistema, un instalador o un binario.",
      },
      careful: {
        en: "A checksum from the same server as the file only protects against corruption, not a hacked server. A signature (Ed25519) protects against both.",
        tr: "Dosyayla aynı sunucudan gelen bir sağlama yalnızca bozulmaya karşı korur, ele geçirilmiş bir sunucuya karşı değil. Bir imza (Ed25519) ikisine karşı da korur.",
        es: "Una suma del mismo servidor que el archivo solo protege contra la corrupción, no contra un servidor comprometido. Una firma (Ed25519) protege contra ambos.",
      },
    },
  },
  "hash.hmac": {
    cat: "hash", emoji: "🏷️", spec: "RFC 2104 · FIPS 198-1",
    name: { en: "HMAC", tr: "HMAC", es: "HMAC" },
    summary: {
      en: "A keyed hash: proves a message came from someone who knows the shared key. Live, as you type.",
      tr: "Anahtarlı özet: bir mesajın ortak anahtarı bilen biri tarafından gönderildiğini kanıtlar. Siz yazdıkça canlı.",
      es: "Un hash con clave: prueba que un mensaje viene de alguien que conoce la clave compartida. En vivo.",
    },
    keywords: "hmac mac authentication webhook api signature kimlik doğrulama",
    learn: {
      what: {
        en: "A Message Authentication Code built from a hash function and a secret key.",
        tr: "Bir özet fonksiyonu ve gizli bir anahtardan oluşturulan Mesaj Kimlik Doğrulama Kodu.",
        es: "Un código de autenticación de mensajes construido con una función hash y una clave secreta.",
      },
      how: {
        en: "HMAC(K, m) = H((K ⊕ opad) ‖ H((K ⊕ ipad) ‖ m)). The two nested hashes defeat length-extension attacks that break the naive H(K ‖ m).",
        tr: "HMAC(K, m) = H((K ⊕ opad) ‖ H((K ⊕ ipad) ‖ m)). İç içe iki özet, saf H(K ‖ m)'yi kıran uzunluk uzatma saldırılarını engeller.",
        es: "HMAC(K, m) = H((K ⊕ opad) ‖ H((K ⊕ ipad) ‖ m)). Los dos hashes anidados frustran los ataques de extensión de longitud que rompen el ingenuo H(K ‖ m).",
      },
      when: {
        en: "Webhook signatures (GitHub, Stripe), API request signing (AWS SigV4), JWT HS256, cookies.",
        tr: "Webhook imzaları (GitHub, Stripe), API isteği imzalama (AWS SigV4), JWT HS256, çerezler.",
        es: "Firmas de webhooks (GitHub, Stripe), firma de peticiones API (AWS SigV4), JWT HS256, cookies.",
      },
      careful: {
        en: "Compare tags in constant time, otherwise timing can leak the correct tag byte by byte. Both sides need the same key, so HMAC cannot prove to a third party who sent a message.",
        tr: "Etiketleri sabit zamanda karşılaştırın, aksi halde zamanlama doğru etiketi bayt bayt sızdırabilir. İki tarafın da aynı anahtara ihtiyacı vardır, bu yüzden HMAC mesajı kimin gönderdiğini üçüncü bir kişiye kanıtlayamaz.",
        es: "Compare las etiquetas en tiempo constante; si no, el tiempo puede filtrar la etiqueta byte a byte. Ambas partes tienen la misma clave, así que HMAC no demuestra a un tercero quién envió el mensaje.",
      },
    },
  },
  "hash.argon2": {
    cat: "hash", emoji: "🧂", spec: "RFC 9106 · PHC winner",
    name: { en: "Password hashing (Argon2id)", tr: "Parola özetleme (Argon2id)", es: "Hash de contraseñas (Argon2id)" },
    summary: {
      en: "Create and verify password hashes the way modern servers should store them.",
      tr: "Parola özetlerini modern sunucuların saklaması gerektiği şekilde oluşturun ve doğrulayın.",
      es: "Cree y verifique hashes de contraseñas como deberían guardarlos los servidores modernos.",
    },
    keywords: "argon2 argon2id password hash kdf phc memory hard parola bellek",
    learn: {
      what: {
        en: "Argon2id won the Password Hashing Competition (2015). It is deliberately slow and memory-hungry so that guessing billions of passwords on GPUs becomes expensive.",
        tr: "Argon2id, Parola Özetleme Yarışması'nı (2015) kazandı. GPU'larda milyarlarca parola denemeyi pahalı kılmak için bilerek yavaş ve bellek açtır.",
        es: "Argon2id ganó la Password Hashing Competition (2015). Es lento y consume memoria a propósito, para que probar miles de millones de contraseñas en GPU sea caro.",
      },
      how: {
        en: "It fills m KiB of memory with BLAKE2b-based blocks, where each new block depends on earlier ones chosen partly by the data (the 'd' half) and partly independently of it (the 'i' half), then makes t passes. The output is stored as a PHC string with all parameters.",
        tr: "m KiB belleği BLAKE2b tabanlı bloklarla doldurur; her yeni blok, kısmen veriye göre ('d' yarısı) kısmen veriden bağımsız ('i' yarısı) seçilen önceki bloklara bağlıdır, sonra t geçiş yapar. Çıktı, tüm parametrelerle birlikte bir PHC dizesi olarak saklanır.",
        es: "Llena m KiB de memoria con bloques basados en BLAKE2b, donde cada bloque depende de otros anteriores elegidos en parte según los datos (mitad 'd') y en parte independientemente (mitad 'i'), y hace t pasadas. El resultado se guarda como cadena PHC con todos los parámetros.",
      },
      when: {
        en: "Storing user passwords in a database; deriving encryption keys from passwords.",
        tr: "Kullanıcı parolalarını bir veritabanında saklamak; parolalardan şifreleme anahtarları türetmek.",
        es: "Guardar contraseñas de usuarios en una base de datos; derivar claves de cifrado a partir de contraseñas.",
      },
      careful: {
        en: "Always use a unique random salt. OWASP minimum: m=19456 KiB, t=2, p=1. Increase memory as much as your server allows.",
        tr: "Her zaman benzersiz, rastgele bir tuz kullanın. OWASP asgarisi: m=19456 KiB, t=2, p=1. Belleği sunucunuzun izin verdiği kadar artırın.",
        es: "Use siempre una sal aleatoria única. Mínimo de OWASP: m=19456 KiB, t=2, p=1. Aumente la memoria tanto como permita su servidor.",
      },
    },
  },
  "hash.pbkdf2": {
    cat: "hash", emoji: "🔁", spec: "RFC 8018 · HMAC-SHA-256",
    name: { en: "PBKDF2", tr: "PBKDF2", es: "PBKDF2" },
    summary: {
      en: "The classic password-based key derivation: many iterations of HMAC. Still required by some standards.",
      tr: "Klasik parola tabanlı anahtar türetme: HMAC'in çok sayıda yinelemesi. Bazı standartlarda hâlâ zorunlu.",
      es: "La derivación de claves clásica basada en contraseña: muchas iteraciones de HMAC. Aún exigida por algunos estándares.",
    },
    keywords: "pbkdf2 kdf password iterations wpa türetme derivación",
    learn: {
      what: {
        en: "Password-Based Key Derivation Function 2 turns a password + salt into a key by iterating HMAC thousands of times.",
        tr: "Parola Tabanlı Anahtar Türetme Fonksiyonu 2, HMAC'i binlerce kez yineleyerek bir parola + tuzu bir anahtara dönüştürür.",
        es: "La Función de Derivación de Claves Basada en Contraseña 2 convierte contraseña + sal en una clave iterando HMAC miles de veces.",
      },
      how: {
        en: "U₁ = HMAC(P, S ‖ i), Uⱼ = HMAC(P, Uⱼ₋₁); the block is U₁ ⊕ U₂ ⊕ … ⊕ U_c.",
        tr: "U₁ = HMAC(P, S ‖ i), Uⱼ = HMAC(P, Uⱼ₋₁); blok U₁ ⊕ U₂ ⊕ … ⊕ U_c'dir.",
        es: "U₁ = HMAC(P, S ‖ i), Uⱼ = HMAC(P, Uⱼ₋₁); el bloque es U₁ ⊕ U₂ ⊕ … ⊕ U_c.",
      },
      when: {
        en: "FIPS-compliant systems, Wi-Fi WPA2, older password stores.",
        tr: "FIPS uyumlu sistemler, Wi-Fi WPA2, eski parola depoları.",
        es: "Sistemas conformes con FIPS, Wi-Fi WPA2, almacenes de contraseñas antiguos.",
      },
      careful: {
        en: "It uses almost no memory, so GPUs attack it cheaply. OWASP recommends ≥600 000 iterations for SHA-256. Prefer Argon2id for new systems.",
        tr: "Neredeyse hiç bellek kullanmaz, bu yüzden GPU'lar ona ucuza saldırır. OWASP, SHA-256 için ≥600 000 yineleme önerir. Yeni sistemler için Argon2id'yi tercih edin.",
        es: "Casi no usa memoria, así que las GPU lo atacan de forma barata. OWASP recomienda ≥600 000 iteraciones con SHA-256. Prefiera Argon2id en sistemas nuevos.",
      },
    },
  },
  "hash.hkdf": {
    cat: "hash", emoji: "🌱", spec: "RFC 5869 · HKDF-SHA-256",
    name: { en: "HKDF", tr: "HKDF", es: "HKDF" },
    summary: {
      en: "Expand one strong secret into many independent keys (e.g. one for encryption, one for MAC).",
      tr: "Güçlü bir sırrı birçok bağımsız anahtara genişletin (ör. biri şifreleme, biri MAC için).",
      es: "Expanda un secreto fuerte en muchas claves independientes (p. ej., una para cifrar y otra para MAC).",
    },
    keywords: "hkdf kdf extract expand derive key türet derivar",
    learn: {
      what: {
        en: "HMAC-based Key Derivation Function. It is NOT for passwords — its input must already be high-entropy (like a DH shared secret).",
        tr: "HMAC tabanlı Anahtar Türetme Fonksiyonu. Parolalar için DEĞİLDİR — girdisi zaten yüksek entropili olmalıdır (bir DH ortak sırrı gibi).",
        es: "Función de derivación de claves basada en HMAC. NO es para contraseñas: su entrada ya debe tener alta entropía (como un secreto DH).",
      },
      how: {
        en: "Extract: PRK = HMAC(salt, IKM). Expand: T(i) = HMAC(PRK, T(i−1) ‖ info ‖ i). Different `info` strings yield independent keys.",
        tr: "Çıkar: PRK = HMAC(tuz, IKM). Genişlet: T(i) = HMAC(PRK, T(i−1) ‖ info ‖ i). Farklı `info` dizeleri bağımsız anahtarlar üretir.",
        es: "Extraer: PRK = HMAC(sal, IKM). Expandir: T(i) = HMAC(PRK, T(i−1) ‖ info ‖ i). Distintos `info` producen claves independientes.",
      },
      when: {
        en: "TLS 1.3 key schedule, Signal's ratchet, turning an X25519 output into AEAD keys.",
        tr: "TLS 1.3 anahtar takvimi, Signal'in cırcırı, bir X25519 çıktısını AEAD anahtarlarına dönüştürmek.",
        es: "El calendario de claves de TLS 1.3, el ratchet de Signal, convertir una salida X25519 en claves AEAD.",
      },
      careful: {
        en: "Use a distinct `info` label for each purpose; never feed a human password into HKDF.",
        tr: "Her amaç için ayrı bir `info` etiketi kullanın; HKDF'ye asla insan parolası vermeyin.",
        es: "Use una etiqueta `info` distinta para cada propósito; nunca le dé a HKDF una contraseña humana.",
      },
    },
  },

  /* ------------------------------------------------------------- pipeline */
  "pipe.encode": {
    cat: "pipe", emoji: "🔄", spec: "Hex · Base64 · Base58 · ROT13",
    name: { en: "Encoding pipeline", tr: "Kodlama hattı", es: "Cadena de codificación" },
    summary: {
      en: "Chain Hex, Base64, Base64URL, Base58 and ROT13. Decoding runs the chain in reverse.",
      tr: "Hex, Base64, Base64URL, Base58 ve ROT13'ü zincirleyin. Çözme zinciri tersten çalıştırır.",
      es: "Encadene Hex, Base64, Base64URL, Base58 y ROT13. Decodificar ejecuta la cadena al revés.",
    },
    keywords: "base64 hex base58 rot13 encode decode kodla çöz codificar",
    learn: {
      what: {
        en: "Encodings represent bytes as printable text. They are NOT encryption — anyone can reverse them.",
        tr: "Kodlamalar baytları yazdırılabilir metin olarak gösterir. Şifreleme DEĞİLDİR — herkes onları geri çevirebilir.",
        es: "Las codificaciones representan bytes como texto imprimible. NO son cifrado: cualquiera puede revertirlas.",
      },
      how: {
        en: "Hex: 4 bits per character. Base64: 6 bits per character (3 bytes → 4 chars). Base58: big-number base conversion without look-alike characters (Bitcoin). ROT13: rotates letters by 13.",
        tr: "Hex: karakter başına 4 bit. Base64: karakter başına 6 bit (3 bayt → 4 karakter). Base58: benzer görünen karakterler olmadan büyük sayı taban dönüşümü (Bitcoin). ROT13: harfleri 13 kaydırır.",
        es: "Hex: 4 bits por carácter. Base64: 6 bits por carácter (3 bytes → 4 caracteres). Base58: conversión de base de números grandes sin caracteres parecidos (Bitcoin). ROT13: rota las letras 13 posiciones.",
      },
      when: {
        en: "Embedding keys in JSON/URLs, email attachments, Bitcoin addresses.",
        tr: "Anahtarları JSON/URL'lere gömmek, e-posta ekleri, Bitcoin adresleri.",
        es: "Incrustar claves en JSON/URL, adjuntos de correo, direcciones Bitcoin.",
      },
      careful: {
        en: "Base64 is not security. If you see a 'password' stored in Base64, it's stored in plain text.",
        tr: "Base64 güvenlik değildir. Base64 ile saklanan bir 'parola' görürseniz, düz metin olarak saklanıyordur.",
        es: "Base64 no es seguridad. Si ve una 'contraseña' guardada en Base64, está guardada en texto plano.",
      },
    },
  },
  "pipe.jwt": {
    cat: "pipe", emoji: "🎫", spec: "RFC 7519 · HS256 check",
    name: { en: "JWT inspector", tr: "JWT inceleyici", es: "Inspector de JWT" },
    summary: {
      en: "Decode a JSON Web Token, see its claims and expiry, and check an HS256 signature with your secret.",
      tr: "Bir JSON Web Token'ı çözün, taleplerini ve süresini görün, HS256 imzasını kendi sırrınızla kontrol edin.",
      es: "Decodifique un JSON Web Token, vea sus claims y caducidad, y compruebe una firma HS256 con su secreto.",
    },
    keywords: "jwt json web token bearer oauth claims exp",
    learn: {
      what: {
        en: "A JWT is `header.payload.signature`, each part Base64URL-encoded. Servers hand them out after login.",
        tr: "JWT, her parçası Base64URL ile kodlanmış `başlık.yük.imza` biçimindedir. Sunucular giriş sonrası bunları verir.",
        es: "Un JWT es `cabecera.carga.firma`, cada parte codificada en Base64URL. Los servidores los entregan tras iniciar sesión.",
      },
      how: {
        en: "For HS256 the signature is HMAC-SHA-256(secret, header ‖ '.' ‖ payload). For EdDSA/RS256 it is a public-key signature.",
        tr: "HS256 için imza HMAC-SHA-256(sır, başlık ‖ '.' ‖ yük)'tür. EdDSA/RS256 için açık anahtar imzasıdır.",
        es: "En HS256 la firma es HMAC-SHA-256(secreto, cabecera ‖ '.' ‖ carga). En EdDSA/RS256 es una firma de clave pública.",
      },
      when: {
        en: "Debugging authentication, checking when a session token expires, auditing what data a token carries.",
        tr: "Kimlik doğrulamada hata ayıklama, bir oturum belirtecinin ne zaman sona erdiğini kontrol etme, belirtecin hangi veriyi taşıdığını denetleme.",
        es: "Depurar la autenticación, comprobar cuándo caduca un token, auditar qué datos lleva.",
      },
      careful: {
        en: "The payload is only encoded, not encrypted — anyone can read it. Never accept `alg: none`. This page never sends your token anywhere.",
        tr: "Yük yalnızca kodlanmıştır, şifrelenmemiştir — herkes okuyabilir. `alg: none`'ı asla kabul etmeyin. Bu sayfa belirtecinizi hiçbir yere göndermez.",
        es: "La carga solo está codificada, no cifrada: cualquiera puede leerla. Nunca acepte `alg: none`. Esta página nunca envía su token a ningún sitio.",
      },
    },
  },

  /* ------------------------------------------------------------ utilities */
  "util.pwgen": {
    cat: "util", emoji: "🎲", spec: "CSPRNG · rejection sampling",
    name: { en: "Password generator", tr: "Parola üreteci", es: "Generador de contraseñas" },
    summary: {
      en: "Unbiased random passwords from the OS random generator, with the entropy shown in bits.",
      tr: "İşletim sistemi rastgele üretecinden yanlılıksız rastgele parolalar, entropi bit olarak gösterilir.",
      es: "Contraseñas aleatorias sin sesgo del generador del sistema, con la entropía en bits.",
    },
    keywords: "password generator random parola üret generar contraseña",
    learn: {
      what: {
        en: "Generates passwords using a cryptographically secure random number generator (crypto.getRandomValues).",
        tr: "Kriptografik olarak güvenli bir rastgele sayı üreteci (crypto.getRandomValues) kullanarak parola üretir.",
        es: "Genera contraseñas con un generador de números aleatorios criptográficamente seguro (crypto.getRandomValues).",
      },
      how: {
        en: "Rejection sampling: random bytes that would bias the result (byte ≥ 256 − 256 mod |pool|) are discarded. Look-alike characters (0/O, 1/l/I) are removed from the pool.",
        tr: "Reddetme örneklemesi: sonucu yanlı yapacak rastgele baytlar (bayt ≥ 256 − 256 mod |havuz|) atılır. Benzer görünen karakterler (0/O, 1/l/I) havuzdan çıkarılır.",
        es: "Muestreo por rechazo: se descartan los bytes que sesgarían el resultado (byte ≥ 256 − 256 mod |conjunto|). Se quitan los caracteres parecidos (0/O, 1/l/I).",
      },
      when: {
        en: "New accounts, Wi-Fi passwords, API secrets. Store them in a password manager.",
        tr: "Yeni hesaplar, Wi-Fi parolaları, API sırları. Bir parola yöneticisinde saklayın.",
        es: "Cuentas nuevas, contraseñas Wi-Fi, secretos de API. Guárdelas en un gestor de contraseñas.",
      },
      careful: {
        en: "Aim for ≥ 80 bits of entropy for online accounts and ≥ 128 bits for encryption keys.",
        tr: "Çevrimiçi hesaplar için ≥ 80 bit, şifreleme anahtarları için ≥ 128 bit entropi hedefleyin.",
        es: "Apunte a ≥ 80 bits de entropía para cuentas en línea y ≥ 128 bits para claves de cifrado.",
      },
    },
  },
  "util.strength": {
    cat: "util", emoji: "📏", spec: "entropy estimate · offline",
    name: { en: "Password strength", tr: "Parola gücü", es: "Fortaleza de contraseña" },
    summary: {
      en: "Estimate how long a password would survive an offline guessing attack — analysed locally, never sent.",
      tr: "Bir parolanın çevrimdışı tahmin saldırısına ne kadar dayanacağını tahmin edin — yerelde analiz edilir, asla gönderilmez.",
      es: "Estime cuánto resistiría una contraseña un ataque de adivinación sin conexión: se analiza localmente, nunca se envía.",
    },
    keywords: "strength entropy password check crack güç entropi fortaleza",
    learn: {
      what: {
        en: "An estimate of how many guesses an attacker needs, expressed in bits of entropy (each bit doubles the work).",
        tr: "Bir saldırganın kaç tahmine ihtiyaç duyduğunun tahmini; entropi biti olarak ifade edilir (her bit işi ikiye katlar).",
        es: "Una estimación de cuántos intentos necesita un atacante, expresada en bits de entropía (cada bit duplica el trabajo).",
      },
      how: {
        en: "We measure the character pool and length, then subtract penalties for repeats, sequences and very common passwords. Time assumes 100 billion guesses/second — a GPU rig against a fast hash.",
        tr: "Karakter havuzunu ve uzunluğu ölçer, sonra tekrarlar, diziler ve çok yaygın parolalar için ceza düşeriz. Süre saniyede 100 milyar tahmin varsayar — hızlı bir özete karşı bir GPU düzeneği.",
        es: "Medimos el conjunto de caracteres y la longitud, y restamos penalizaciones por repeticiones, secuencias y contraseñas muy comunes. El tiempo supone 100 mil millones de intentos/s: un equipo de GPU contra un hash rápido.",
      },
      when: {
        en: "Choosing a master password or a passphrase for an encrypted file.",
        tr: "Ana parola veya şifreli bir dosya için parola cümlesi seçerken.",
        es: "Al elegir una contraseña maestra o una frase para un archivo cifrado.",
      },
      careful: {
        en: "Any estimator is a heuristic: a password that is 'strong' but reused, or leaked in a breach, is still weak.",
        tr: "Her tahminci bir sezgiseldir: 'güçlü' ama tekrar kullanılan veya bir sızıntıda ifşa olmuş parola yine zayıftır.",
        es: "Todo estimador es heurístico: una contraseña 'fuerte' pero reutilizada o filtrada sigue siendo débil.",
      },
    },
  },
  "util.random": {
    cat: "util", emoji: "🎰", spec: "CSPRNG",
    name: { en: "Random generator", tr: "Rastgele üreteç", es: "Generador aleatorio" },
    summary: {
      en: "Secure random bytes, API tokens, UUIDs, PINs and diceware-style passphrases.",
      tr: "Güvenli rastgele baytlar, API belirteçleri, UUID'ler, PIN'ler ve zar tarzı parola cümleleri.",
      es: "Bytes aleatorios seguros, tokens de API, UUID, PIN y frases estilo diceware.",
    },
    keywords: "random uuid token pin diceware passphrase bytes rastgele aleatorio",
    learn: {
      what: {
        en: "Cryptographic randomness is the foundation of every key, nonce and salt.",
        tr: "Kriptografik rastgelelik her anahtarın, nonce'un ve tuzun temelidir.",
        es: "La aleatoriedad criptográfica es la base de toda clave, nonce y sal.",
      },
      how: {
        en: "Bytes come from the browser's CSPRNG (seeded by the OS). UUID v4 sets 6 fixed version/variant bits, leaving 122 random bits.",
        tr: "Baytlar tarayıcının CSPRNG'sinden (işletim sistemi tarafından tohumlanır) gelir. UUID v4, 6 sabit sürüm/varyant biti ayarlar ve 122 rastgele bit bırakır.",
        es: "Los bytes vienen del CSPRNG del navegador (sembrado por el SO). UUID v4 fija 6 bits de versión/variante y deja 122 bits aleatorios.",
      },
      when: {
        en: "Session IDs, API keys, salts, test data, one-time codes.",
        tr: "Oturum kimlikleri, API anahtarları, tuzlar, test verileri, tek kullanımlık kodlar.",
        es: "IDs de sesión, claves de API, sales, datos de prueba, códigos de un solo uso.",
      },
      careful: {
        en: "Never use Math.random() or timestamps for secrets — they are predictable.",
        tr: "Sırlar için asla Math.random() veya zaman damgaları kullanmayın — tahmin edilebilirler.",
        es: "Nunca use Math.random() ni marcas de tiempo para secretos: son predecibles.",
      },
    },
  },
};

export const TOOL_IDS = Object.keys(META);

/** Goal cards on the home page: [i18n key, tool id, emoji]. */
export const GOALS = [
  ["goal.file", "sym.file", "📦"],
  ["goal.text", "sym.text", "✉️"],
  ["goal.checksum", "hash.verify", "✅"],
  ["goal.store", "hash.argon2", "🧂"],
  ["goal.sign", "asym.ed25519", "✍️"],
  ["goal.exchange", "asym.x25519", "🤝"],
  ["goal.pq", "asym.kyber", "🛰️"],
  ["goal.pw", "util.pwgen", "🎲"],
  ["goal.jwt", "pipe.jwt", "🎫"],
  ["goal.encode", "pipe.encode", "🔄"],
];

/** Algorithms implemented from scratch in easylock-core. */
export const ALGORITHMS = [
  "AES-256-GCM", "AES-256-CTR", "ChaCha20-Poly1305", "Poly1305", "SHA-256", "SHA-512",
  "SHA3-256", "SHAKE128/256", "Keccak-256", "BLAKE2b", "BLAKE3", "HMAC", "HKDF",
  "PBKDF2", "Argon2id", "X25519", "Ed25519", "RSA (OAEP/PKCS#1)", "ML-KEM (FIPS 203)",
];
