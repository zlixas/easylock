// The landing page: live demo, downloads, performance, format diagram, trust, FAQ.
import { h, icon, ICONS, copyToOS } from "./ui.js";
import { t, L } from "./i18n.js";
import { api, enc, bytesToHex } from "./api.js";
import { META, TOOL_IDS, GOALS, ALGORITHMS } from "./content.js";

const REPO = "https://github.com/zlixas/easylock";
const DL = REPO + "/releases/latest/download/";
const RAW = "https://raw.githubusercontent.com/zlixas/easylock/main/";

/* Strings that exist only on the landing page. */
const S = {
  eyebrow: { en: "From-scratch Rust · WebAssembly · Post-quantum", tr: "Sıfırdan Rust · WebAssembly · Kuantum sonrası", es: "Rust desde cero · WebAssembly · Poscuántico" },
  title1: { en: "Cryptography you can", tr: "Görebileceğiniz,", es: "Criptografía que puede" },
  title2: { en: "see, learn and trust.", tr: "öğrenebileceğiniz kriptografi.", es: "ver, aprender y entender." },
  lead: {
    en: "Every primitive, from AES to ML-KEM, written from first principles in Rust with zero dependencies, then compiled to WebAssembly. Encrypt files, share them with public keys, hash, sign and learn how each piece works. Nothing ever leaves your device.",
    tr: "AES'ten ML-KEM'e kadar her yapı taşı, Rust ile sıfır bağımlılıkla temel ilkelerden yazıldı ve WebAssembly'e derlendi. Dosya şifreleyin, açık anahtarla paylaşın, özetleyin, imzalayın ve her parçanın nasıl çalıştığını öğrenin. Hiçbir şey cihazınızdan çıkmaz.",
    es: "Cada primitiva, de AES a ML-KEM, escrita desde los principios en Rust sin dependencias y compilada a WebAssembly. Cifre archivos, compártalos con claves públicas, calcule hashes, firme y aprenda cómo funciona cada pieza. Nada sale de su dispositivo.",
  },
  pill1: { en: "No uploads", tr: "Yükleme yok", es: "Sin subidas" },
  pill2: { en: "Works offline", tr: "Çevrimdışı çalışır", es: "Funciona sin conexión" },
  pill3: { en: "Open source", tr: "Açık kaynak", es: "Código abierto" },
  demoTitle: { en: "Live: type anything", tr: "Canlı: bir şey yazın", es: "En vivo: escriba algo" },
  demoInit: { en: "Hello, world! 👋", tr: "Merhaba dünya! 👋", es: "¡Hola, mundo! 👋" },
  demoCt: { en: "ChaCha20-Poly1305 ciphertext", tr: "ChaCha20-Poly1305 şifreli metni", es: "Texto cifrado ChaCha20-Poly1305" },
  demoNewKey: { en: "New key", tr: "Yeni anahtar", es: "Nueva clave" },
  demoNote: {
    en: "One changed letter changes every hash byte (the avalanche effect). The ciphertext is 16 bytes longer because of the authentication tag.",
    tr: "Tek bir harf değişince özetin tüm baytları değişir (çığ etkisi). Şifreli metin, doğrulama etiketi yüzünden 16 bayt daha uzundur.",
    es: "Cambiar una letra cambia todos los bytes del hash (efecto avalancha). El texto cifrado es 16 bytes más largo por la etiqueta de autenticación.",
  },
  statVectors: { en: "Wycheproof vectors pass", tr: "Wycheproof vektörü geçiyor", es: "vectores Wycheproof superados" },
  statSpeed: { en: "AES-256-GCM on one core", tr: "tek çekirdekte AES-256-GCM", es: "AES-256-GCM en un núcleo" },
  dlTitle: { en: "Get easylock", tr: "easylock'u edinin", es: "Obtenga easylock" },
  dlLead: {
    en: "The command line and terminal UI install in one line. Every download is listed in an Ed25519-signed SHA256SUMS with GitHub build provenance.",
    tr: "Komut satırı ve terminal arayüzü tek satırla kurulur. Her indirme, Ed25519 ile imzalı SHA256SUMS dosyasında listelenir ve GitHub derleme kanıtına sahiptir.",
    es: "La línea de comandos y la interfaz de terminal se instalan con una línea. Cada descarga figura en un SHA256SUMS firmado con Ed25519 y tiene procedencia de compilación de GitHub.",
  },
  desktop: { en: "Desktop app", tr: "Masaüstü uygulaması", es: "App de escritorio" },
  unsigned: {
    en: "Not code-signed by Apple/Microsoft yet: on macOS right-click → Open the first time; on Windows choose More info → Run anyway.",
    tr: "Henüz Apple/Microsoft imzalı değil: macOS'ta ilk seferde sağ tık → Aç; Windows'ta Ek bilgi → Yine de çalıştır.",
    es: "Aún sin firma de Apple/Microsoft: en macOS, clic derecho → Abrir la primera vez; en Windows, Más información → Ejecutar de todas formas.",
  },
  allReleases: { en: "All releases & checksums", tr: "Tüm sürümler ve sağlamalar", es: "Todas las versiones y sumas" },
  copied: { en: "Copied", tr: "Kopyalandı", es: "Copiado" },
  perfTitle: { en: "Fast, without shortcuts", tr: "Kestirmesiz hız", es: "Rápido, sin atajos" },
  perfLead: {
    en: "Hand-written SIMD and hardware instructions (AES-NI, ARMv8 AES/SHA2, PCLMUL/PMULL, NEON, SSE2) are chosen at runtime. Each fast path is tested byte-for-byte against the portable code. Measured on an Apple M4.",
    tr: "Elle yazılmış SIMD ve donanım komutları (AES-NI, ARMv8 AES/SHA2, PCLMUL/PMULL, NEON, SSE2) çalışma anında seçilir. Her hızlı yol, taşınabilir kodla bayt bayt karşılaştırılarak test edilir. Apple M4 üzerinde ölçüldü.",
    es: "Instrucciones SIMD y de hardware escritas a mano (AES-NI, ARMv8 AES/SHA2, PCLMUL/PMULL, NEON, SSE2) se eligen en tiempo de ejecución. Cada ruta rápida se prueba byte a byte contra el código portable. Medido en un Apple M4.",
  },
  before: { en: "before", tr: "önce", es: "antes" },
  lock500: { en: "Lock a 500 MB file", tr: "500 MB dosya kilitleme", es: "Bloquear un archivo de 500 MB" },
  fmtTitle: { en: "Inside a .elk file", tr: ".elk dosyasının içi", es: "Dentro de un archivo .elk" },
  fmtLead: {
    en: "A random 32-byte file key encrypts the data. That key is then wrapped once per way to open the file, so a password and several people's public keys can all unlock the same file.",
    tr: "Rastgele 32 baytlık bir dosya anahtarı veriyi şifreler. Bu anahtar, dosyayı açmanın her yolu için ayrıca sarılır; böylece bir parola ve birden çok kişinin açık anahtarı aynı dosyayı açabilir.",
    es: "Una clave de archivo aleatoria de 32 bytes cifra los datos. Esa clave se envuelve una vez por cada forma de abrir el archivo, así una contraseña y las claves públicas de varias personas pueden abrir el mismo archivo.",
  },
  fmtSteps: [
    { en: ["Header", "Magic, cipher, a random base nonce."], tr: ["Başlık", "Sihirli bayt, şifre türü, rastgele temel nonce."], es: ["Cabecera", "Magia, cifrado y un nonce base aleatorio."] },
    { en: ["Key slots", "The file key, wrapped by Argon2id (password) or X25519 + ML-KEM-768 (public key)."], tr: ["Anahtar yuvaları", "Dosya anahtarı; Argon2id (parola) veya X25519 + ML-KEM-768 (açık anahtar) ile sarılır."], es: ["Ranuras", "La clave del archivo, envuelta con Argon2id (contraseña) o X25519 + ML-KEM-768 (clave pública)."] },
    { en: ["Header MAC", "HMAC-SHA256 over everything above, so no slot can be swapped or edited."], tr: ["Başlık MAC", "Yukarıdaki her şeyin HMAC-SHA256'sı; hiçbir yuva değiştirilemez."], es: ["MAC de cabecera", "HMAC-SHA256 sobre todo lo anterior: ninguna ranura puede cambiarse."] },
    { en: ["256 KiB chunks", "Each one sealed with AES-256-GCM or ChaCha20-Poly1305. The last chunk is marked, so truncation is detected."], tr: ["256 KiB parçalar", "Her biri AES-256-GCM veya ChaCha20-Poly1305 ile mühürlenir. Son parça işaretlidir; kesilme fark edilir."], es: ["Bloques de 256 KiB", "Cada uno sellado con AES-256-GCM o ChaCha20-Poly1305. El último está marcado, así se detecta el truncado."] },
  ],
  trustTitle: { en: "Built to be checked", tr: "Denetlenmek için yapıldı", es: "Hecho para ser verificado" },
  trust: [
    ["🧪", { en: "Official vectors", tr: "Resmî vektörler", es: "Vectores oficiales" }, { en: "NIST CAVP, FIPS 197/180-4/202/203 and RFC vectors for every primitive.", tr: "Her yapı taşı için NIST CAVP, FIPS 197/180-4/202/203 ve RFC vektörleri.", es: "Vectores NIST CAVP, FIPS 197/180-4/202/203 y RFC para cada primitiva." }],
    ["🧨", { en: "Wycheproof", tr: "Wycheproof", es: "Wycheproof" }, { en: "1,485 adversarial edge cases from Google's Project Wycheproof.", tr: "Google'ın Project Wycheproof'undan 1.485 saldırgan uç durum.", es: "1.485 casos límite adversarios del Project Wycheproof de Google." }],
    ["🐛", { en: "Fuzzed", tr: "Fuzz testli", es: "Fuzzing" }, { en: "cargo-fuzz on headers, chunk streams, archives and decoders in every CI run.", tr: "Her CI çalışmasında başlıklar, parça akışları, arşivler ve kod çözücüler üzerinde cargo-fuzz.", es: "cargo-fuzz sobre cabeceras, flujos, archivos y decodificadores en cada CI." }],
    ["⏱️", { en: "Constant-time", tr: "Sabit zamanlı", es: "Tiempo constante" }, { en: "Secret-dependent branches and table lookups are avoided; secrets are zeroized.", tr: "Sırra bağlı dallanma ve tablo erişimi yok; sırlar bellekten silinir.", es: "Sin ramas ni tablas dependientes de secretos; los secretos se borran." }],
    ["🛡️", { en: "Strict CSP & offline", tr: "Sıkı CSP ve çevrimdışı", es: "CSP estricta y offline" }, { en: "This page loads nothing from third parties and keeps working with no network.", tr: "Bu sayfa üçüncü taraflardan hiçbir şey yüklemez ve ağ olmadan da çalışır.", es: "Esta página no carga nada de terceros y funciona sin red." }],
    ["✍️", { en: "Signed releases", tr: "İmzalı sürümler", es: "Versiones firmadas" }, { en: "Ed25519-signed checksums and SLSA build provenance for every binary.", tr: "Her ikili dosya için Ed25519 imzalı sağlamalar ve SLSA derleme kanıtı.", es: "Sumas firmadas con Ed25519 y procedencia SLSA para cada binario." }],
  ],
  faqTitle: { en: "Questions", tr: "Sorular", es: "Preguntas" },
  faq: [
    [{ en: "Are my files uploaded anywhere?", tr: "Dosyalarım bir yere yükleniyor mu?", es: "¿Se suben mis archivos a algún sitio?" },
     { en: "No. The Rust engine runs inside your browser as WebAssembly. The Content-Security-Policy only allows this site's own files, and once loaded the site works in airplane mode.", tr: "Hayır. Rust motoru tarayıcınızın içinde WebAssembly olarak çalışır. Güvenlik politikası yalnızca bu sitenin kendi dosyalarına izin verir; bir kez yüklendikten sonra site uçak modunda da çalışır.", es: "No. El motor en Rust se ejecuta en su navegador como WebAssembly. La política de seguridad solo permite los archivos de este sitio y, una vez cargado, funciona en modo avión." }],
    [{ en: "Can I open a website-locked file in the terminal?", tr: "Sitede kilitlediğim dosyayı terminalde açabilir miyim?", es: "¿Puedo abrir en la terminal un archivo bloqueado aquí?" },
     { en: "Yes. The website, CLI, terminal UI and desktop app all share the .elk format: `easylock unlock file.elk`.", tr: "Evet. Site, CLI, terminal arayüzü ve masaüstü uygulaması aynı .elk biçimini kullanır: `easylock unlock dosya.elk`.", es: "Sí. El sitio, la CLI, la interfaz de terminal y la app de escritorio comparten el formato .elk: `easylock unlock archivo.elk`." }],
    [{ en: "What does post-quantum mean here?", tr: "Burada kuantum sonrası ne demek?", es: "¿Qué significa poscuántico aquí?" },
     { en: "Public-key files combine X25519 with ML-KEM-768 (FIPS 203). An attacker must break both, so a future quantum computer that breaks X25519 alone is not enough.", tr: "Açık anahtarlı dosyalar X25519'u ML-KEM-768 (FIPS 203) ile birleştirir. Saldırganın ikisini de kırması gerekir; yalnızca X25519'u kıran gelecekteki bir kuantum bilgisayar yetmez.", es: "Los archivos de clave pública combinan X25519 con ML-KEM-768 (FIPS 203). Hay que romper ambos, así que un futuro ordenador cuántico que rompa solo X25519 no basta." }],
    [{ en: "Should I protect real secrets with it?", tr: "Gerçek sırlarımı bununla korumalı mıyım?", es: "¿Debo proteger secretos reales con esto?" },
     { en: "Not yet. It is tested hard, but no independent audit has happened. For high-stakes data use an audited tool such as age, libsodium or ring.", tr: "Henüz değil. Yoğun şekilde test edildi ama bağımsız bir denetimden geçmedi. Kritik veriler için age, libsodium veya ring gibi denetlenmiş araçlar kullanın.", es: "Todavía no. Está muy probado, pero sin auditoría independiente. Para datos críticos use herramientas auditadas como age, libsodium o ring." }],
    [{ en: "What if I forget my password?", tr: "Parolamı unutursam ne olur?", es: "¿Y si olvido mi contraseña?" },
     { en: "The file cannot be recovered. That is the point. Consider adding your public key as a second way to unlock important files.", tr: "Dosya kurtarılamaz; amaç da budur. Önemli dosyalara ikinci bir açma yolu olarak açık anahtarınızı eklemeyi düşünün.", es: "El archivo no se puede recuperar; esa es la idea. Considere añadir su clave pública como segunda forma de abrir archivos importantes." }],
  ],
};

const tx = (k) => L(S[k]);

/* ---------------------------------------------------------- helpers */

function copyBtn(text) {
  const b = h("button", { class: "copy-btn", "aria-label": "copy", title: "copy" }, icon(ICONS.copy, "h-3.5 w-3.5"));
  b.addEventListener("click", async () => {
    if (await copyToOS(typeof text === "function" ? text() : text)) {
      b.replaceChildren(icon(ICONS.check, "h-3.5 w-3.5"), h("span", {}, tx("copied")));
      b.classList.add("ok");
      setTimeout(() => { b.replaceChildren(icon(ICONS.copy, "h-3.5 w-3.5")); b.classList.remove("ok"); }, 1400);
    }
  });
  return b;
}

const section = (id, title, lead, ...body) => h("section", { class: "reveal space-y-5", id },
  h("div", { class: "space-y-2" },
    h("h2", { class: "section-title" }, title),
    lead && h("p", { class: "max-w-3xl text-sm leading-relaxed text-slate-400" }, lead)),
  ...body);

function detectOS() {
  const p = (navigator.userAgentData?.platform || navigator.platform || navigator.userAgent).toLowerCase();
  if (p.includes("win")) return "windows";
  if (p.includes("mac") || p.includes("iphone") || p.includes("ipad")) return "macos";
  return "linux";
}

/* ---------------------------------------------------------- live demo */

function liveDemo() {
  let key = api.random(32);
  const nonce = new Uint8Array(12);
  const ta = h("textarea", { class: "field !min-h-[4.5rem] resize-none font-mono !text-[13px]", rows: 2, spellcheck: false, "aria-label": tx("demoTitle") });
  ta.value = tx("demoInit");
  const row = (label, cls) => {
    const v = h("div", { class: "demo-val " + cls });
    return [v, h("div", { class: "space-y-1" },
      h("div", { class: "flex items-center justify-between text-[10px] font-semibold uppercase tracking-wider text-slate-500" },
        h("span", {}, label), copyBtn(() => v.textContent)), v)];
  };
  const [ct, ctRow] = row(tx("demoCt"), "text-fuchsia-300");
  const [sha, shaRow] = row("SHA-256", "text-emerald-300");
  const [b3, b3Row] = row("BLAKE3", "text-sky-300");
  const size = h("span", { class: "font-mono text-[10px] text-slate-500" });

  let timer = 0;
  const scramble = (el, target) => {
    const hex = "0123456789abcdef";
    let frame = 0;
    const tick = () => {
      frame++;
      const done = Math.floor((target.length * frame) / 8);
      el.textContent = target.slice(0, done) + Array.from({ length: Math.max(0, target.length - done) }, () => hex[(Math.random() * 16) | 0]).join("");
      if (done < target.length) el._raf = requestAnimationFrame(tick);
    };
    cancelAnimationFrame(el._raf);
    tick();
  };
  const update = (animate) => {
    const pt = enc.encode(ta.value);
    const out = [
      [ct, bytesToHex(api.aeadSeal("chacha20-poly1305", key, nonce, new Uint8Array(0), pt))],
      [sha, api.hash("sha256", pt)],
      [b3, api.hash("blake3", pt)],
    ];
    for (const [el, v] of out) animate ? scramble(el, v) : (cancelAnimationFrame(el._raf), el.textContent = v);
    size.textContent = `${pt.length} B → ${pt.length + 16} B`;
  };
  ta.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => update(false), 30); });
  const newKey = h("button", { class: "btn-ghost !py-1 !text-[11px]" }, icon(ICONS.key, "h-3.5 w-3.5"), tx("demoNewKey"));
  newKey.addEventListener("click", () => { key = api.random(32); update(true); });
  requestAnimationFrame(() => update(true));

  return h("div", { class: "demo" },
    h("div", { class: "flex items-center justify-between gap-2" },
      h("div", { class: "flex items-center gap-2 text-[12px] font-semibold text-slate-200" },
        h("span", { class: "live-dot" }), tx("demoTitle")),
      h("div", { class: "flex items-center gap-2" }, size, newKey)),
    ta, ctRow, shaRow, b3Row,
    h("p", { class: "text-[11px] leading-relaxed text-slate-500" }, tx("demoNote")));
}

/* ---------------------------------------------------------- sections */

function hero(navigate) {
  const pill = (text) => h("span", { class: "flex items-center gap-1.5" }, icon(ICONS.check, "h-3.5 w-3.5 text-emerald-400"), text);
  return h("section", { class: "hero" },
    h("div", { class: "hero-grid" }),
    h("div", { class: "relative grid grid-cols-1 items-center gap-10 lg:grid-cols-[1.1fr_1fr]" },
      h("div", {},
        h("a", { class: "eyebrow", href: REPO + "/releases/latest", target: "_blank", rel: "noopener" },
          h("span", { class: "rounded-full bg-accent-500 px-2 py-0.5 text-[10px] font-bold text-white" }, "v" + api.version()),
          tx("eyebrow"), icon(ICONS.chevron, "h-3 w-3")),
        h("h1", { class: "mt-5 text-4xl font-extrabold leading-[1.08] tracking-tight text-slate-50 sm:text-5xl" },
          tx("title1"), h("br"), h("span", { class: "grad-text" }, tx("title2"))),
        h("p", { class: "mt-5 max-w-xl text-[15px] leading-relaxed text-slate-400" }, tx("lead")),
        h("div", { class: "mt-7 flex flex-wrap gap-3" },
          h("button", { class: "btn btn-lg", onClick: () => navigate("sym.file") }, icon(ICONS.lock, "h-4 w-4"), t("home.cta.file")),
          h("a", { class: "btn-ghost btn-lg", href: "#get" , onClick: (e) => { e.preventDefault(); document.getElementById("get")?.scrollIntoView({ behavior: "smooth" }); } },
            icon(ICONS.download, "h-4 w-4"), tx("dlTitle")),
          h("a", { class: "btn-ghost btn-lg", href: REPO, target: "_blank", rel: "noopener" }, icon(ICONS.github, "h-4 w-4"), "GitHub")),
        h("div", { class: "mt-6 flex flex-wrap gap-x-5 gap-y-2 text-[12px] text-slate-400" },
          pill(tx("pill1")), pill(tx("pill2")), pill(tx("pill3")), pill("EN · TR · ES"))),
      liveDemo()));
}

function stats() {
  const stat = (n, label) => h("div", { class: "stat" },
    h("div", { class: "stat-n" }, n), h("div", { class: "stat-l" }, label));
  return h("section", { class: "reveal grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5" },
    stat(String(ALGORITHMS.length), t("home.stat.algos")),
    stat(String(TOOL_IDS.length), t("home.stat.tools")),
    stat("1,485", tx("statVectors")),
    stat("4.3 GB/s", tx("statSpeed")),
    stat("0", t("home.stat.server")));
}

function goals(navigate) {
  return section("goals", t("home.choose"), null,
    h("div", { class: "grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3" },
      ...GOALS.map(([key, id, emoji]) => h("button", { class: "goal", onClick: () => navigate(id) },
        h("span", { class: "goal-emoji" }, emoji),
        h("span", { class: "min-w-0 flex-1 text-left" },
          h("span", { class: "block text-sm font-semibold text-slate-100" }, t(key)),
          h("span", { class: "block truncate text-[11px] text-slate-500" }, L(META[id].name) + " · " + META[id].spec)),
        icon(ICONS.chevron, "h-4 w-4 text-slate-600")))));
}

const INSTALL = {
  macos: { label: "macOS", cmds: [["Homebrew", "brew install zlixas/tap/easylock"], ["Shell", `curl -fsSL ${RAW}install.sh | sh`]],
    apps: [["Apple Silicon (.dmg)", "easylock-desktop-macos-arm64.dmg"], ["Intel (.dmg)", "easylock-desktop-macos-x64.dmg"]] },
  linux: { label: "Linux", cmds: [["Shell", `curl -fsSL ${RAW}install.sh | sh`], ["Homebrew", "brew install zlixas/tap/easylock"]],
    apps: [[".AppImage", "easylock-desktop-linux-x64.AppImage"], [".deb", "easylock-desktop-linux-x64.deb"]] },
  windows: { label: "Windows", cmds: [["PowerShell", `irm ${RAW}install.ps1 | iex`]],
    apps: [["Installer (.exe)", "easylock-desktop-windows-x64.exe"], [".msi", "easylock-desktop-windows-x64.msi"]] },
  cargo: { label: "Cargo", cmds: [["Rust 1.98+", "cargo install --git https://github.com/zlixas/easylock easylock-cli"]], apps: [] },
};

function install() {
  let os = detectOS();
  const tabs = h("div", { class: "seg", role: "tablist" });
  const body = h("div", { class: "grid grid-cols-1 gap-4 lg:grid-cols-[1.4fr_1fr]" });
  const render = () => {
    tabs.replaceChildren(...Object.entries(INSTALL).map(([k, v]) => h("button", {
      type: "button", role: "tab", class: k === os ? "active" : "", "aria-selected": String(k === os),
      onClick: () => { os = k; render(); },
    }, v.label)));
    const d = INSTALL[os];
    body.replaceChildren(
      h("div", { class: "card space-y-3" },
        h("div", { class: "flex items-center gap-2 text-sm font-semibold text-slate-100" }, icon(ICONS.terminal, "h-4 w-4 text-accent-400"), t("home.eco.cli") + " + " + t("home.eco.tui")),
        ...d.cmds.map(([label, cmd]) => h("div", { class: "space-y-1" },
          h("div", { class: "text-[10px] font-semibold uppercase tracking-wider text-slate-500" }, label),
          h("div", { class: "term" }, h("span", { class: "select-none text-slate-600" }, "$ "), h("code", { class: "min-w-0 flex-1 break-all" }, cmd), copyBtn(cmd)))),
        h("div", { class: "term !text-slate-400" }, h("span", { class: "select-none text-slate-600" }, "$ "),
          h("code", {}, "easylock tui"), h("span", { class: "ml-auto text-[11px] text-slate-600" }, "# ⌨️"))),
      h("div", { class: "card flex flex-col gap-3" },
        h("div", { class: "flex items-center gap-2 text-sm font-semibold text-slate-100" }, icon(ICONS.desktop, "h-4 w-4 text-accent-400"), tx("desktop")),
        d.apps.length
          ? h("div", { class: "grid grid-cols-1 gap-2" }, ...d.apps.map(([label, file]) =>
              h("a", { class: "dl-btn", href: DL + file, rel: "noopener" }, icon(ICONS.download, "h-4 w-4"), h("span", { class: "flex-1" }, label), h("span", { class: "chip" }, INSTALL[os].label))))
          : h("p", { class: "text-[12px] text-slate-500" }, "cd crates/easylock-gui && cargo tauri build"),
        d.apps.length ? h("p", { class: "text-[11px] leading-relaxed text-slate-500" }, tx("unsigned")) : null,
        h("a", { class: "mt-auto text-[12px] text-accent-400 hover:underline", href: REPO + "/releases", target: "_blank", rel: "noopener" }, tx("allReleases") + " →")));
  };
  render();
  return section("get", tx("dlTitle"), tx("dlLead"), h("div", {}, tabs), body);
}

// CSSOM (not a style attribute), so the strict CSP allows it.
function widthVar(el, frac) {
  el.style.setProperty("--w", `${(frac * 100).toFixed(1)}%`);
  return el;
}

function performance() {
  const rows = [
    ["AES-256-GCM", 1.0, 4.3, "GB/s"],
    ["SHA-256", 0.37, 2.4, "GB/s"],
    ["ChaCha20-Poly1305", 0.49, 1.05, "GB/s"],
  ];
  const times = [
    ["Argon2id 64 MiB", 121, 32, "ms"],
    [tx("lock500"), 1410, 120, "ms"],
  ];
  const max = 4.3;
  const bar = ([name, b, a, unit]) => h("div", { class: "space-y-1.5" },
    h("div", { class: "flex items-baseline justify-between text-[12px]" },
      h("span", { class: "font-semibold text-slate-200" }, name),
      h("span", { class: "font-mono text-slate-400" }, h("span", { class: "text-slate-600" }, `${b} → `), h("b", { class: "text-emerald-300" }, `${a} ${unit}`))),
    h("div", { class: "bar" },
      widthVar(h("div", { class: "bar-old" }), b / max),
      widthVar(h("div", { class: "bar-new" }), a / max)));
  const speedup = ([name, b, a, unit]) => h("div", { class: "stat" },
    h("div", { class: "stat-n text-emerald-300" }, `${(b / a).toFixed(1)}×`),
    h("div", { class: "stat-l" }, `${name}: ${b} → ${a} ${unit}`));
  return section("perf", tx("perfTitle"), tx("perfLead"),
    h("div", { class: "grid grid-cols-1 gap-4 lg:grid-cols-[1.6fr_1fr]" },
      h("div", { class: "card space-y-4" }, ...rows.map(bar),
        h("div", { class: "flex gap-4 pt-1 text-[11px] text-slate-500" },
          h("span", { class: "flex items-center gap-1.5" }, h("i", { class: "legend bg-obsidian-600" }), tx("before")),
          h("span", { class: "flex items-center gap-1.5" }, h("i", { class: "legend bg-gradient-to-r from-accent-500 to-emerald-400" }), "v" + api.version()))),
      h("div", { class: "grid grid-cols-1 gap-3" }, ...times.map(speedup))));
}

function format() {
  const cells = [
    ["ELK2", "magic", "c-slate"], ["cipher · flags · nonce", "", "c-slate"],
    ["🔑 password", "Argon2id", "c-amber"], ["🪪 public key", "X25519+ML-KEM", "c-violet"],
    ["HMAC", "SHA-256", "c-sky"], ["chunk 0", "AEAD", "c-emerald"], ["chunk 1", "AEAD", "c-emerald"], ["…", "", "c-emerald"], ["last ✓", "AEAD", "c-emerald"],
  ];
  return section("format", tx("fmtTitle"), tx("fmtLead"),
    h("div", { class: "card space-y-5" },
      h("div", { class: "elk-strip" }, ...cells.map(([a, b, c]) => h("div", { class: "elk-cell " + c },
        h("span", { class: "font-mono text-[11px] font-semibold" }, a), b && h("span", { class: "text-[10px] opacity-70" }, b)))),
      h("ol", { class: "grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4" }, ...S.fmtSteps.map((s, i) => {
        const [title, body] = L(s);
        return h("li", { class: "space-y-1" },
          h("div", { class: "flex items-center gap-2 text-sm font-semibold text-slate-100" },
            h("span", { class: "step-n" }, String(i + 1)), title),
          h("p", { class: "text-[12px] leading-relaxed text-slate-400" }, body));
      })),
      h("a", { class: "inline-block text-[12px] text-accent-400 hover:underline", href: REPO + "/blob/main/docs/FILE_FORMAT.md", target: "_blank", rel: "noopener" }, "docs/FILE_FORMAT.md →")));
}

function ecosystem() {
  const eco = (ic, key, cmd) => h("div", { class: "card card-hover !p-4 space-y-2" },
    h("div", { class: "flex items-center gap-2 text-sm font-semibold text-slate-100" },
      h("span", { class: "icon-tile" }, icon(ic, "h-4 w-4")), t(key)),
    h("code", { class: "block whitespace-pre-wrap break-all font-mono text-[11px] text-emerald-300" }, cmd));
  return section("eco", t("home.ecosystem"), t("home.ecosystem.lead"),
    h("div", { class: "grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4" },
      eco(ICONS.terminal, "home.eco.cli", "easylock lock taxes.pdf\neasylock vault add ~/Private.vault id.pdf"),
      eco(ICONS.keyboard, "home.eco.tui", "easylock tui"),
      eco(ICONS.desktop, "home.eco.desktop", ".dmg · .msi · .exe · .deb · .AppImage"),
      eco(ICONS.globe, "home.eco.web", "WebAssembly · PWA · offline")));
}

function trust() {
  return section("trust", tx("trustTitle"), null,
    h("div", { class: "grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3" },
      ...S.trust.map(([emoji, title, body]) => h("div", { class: "card card-hover !p-4 space-y-1.5" },
        h("div", { class: "flex items-center gap-2 text-sm font-semibold text-slate-100" }, h("span", { class: "text-lg" }, emoji), L(title)),
        h("p", { class: "text-[12px] leading-relaxed text-slate-400" }, L(body))))),
    h("div", { class: "flex flex-wrap gap-2" }, ...ALGORITHMS.map((a) => h("span", { class: "chip" }, a))));
}

function faq() {
  return section("faq", tx("faqTitle"), null,
    h("div", { class: "space-y-2" }, ...S.faq.map(([q, a]) => h("details", { class: "faq" },
      h("summary", {}, h("span", { class: "flex-1" }, L(q)), icon(ICONS.chevron, "faq-chev h-4 w-4 text-slate-500")),
      h("p", { class: "px-4 pb-4 text-[13px] leading-relaxed text-slate-400" }, L(a))))));
}

function warning() {
  return h("section", { class: "reveal rounded-xl border border-amber-500/30 bg-amber-500/5 p-5" },
    h("div", { class: "mb-1 text-sm font-bold text-amber-300" }, "⚠ " + t("home.warn.title")),
    h("p", { class: "text-[13px] leading-relaxed text-slate-300" }, t("home.warn.body")));
}

/* Fade sections in as they scroll into view (skipped for reduced motion). */
function observeReveal(root) {
  const els = root.querySelectorAll(".reveal");
  if (!("IntersectionObserver" in window) || matchMedia("(prefers-reduced-motion: reduce)").matches) {
    els.forEach((el) => el.classList.add("in"));
    return;
  }
  const io = new IntersectionObserver((entries) => {
    for (const e of entries) if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); }
  }, { threshold: 0.12 });
  els.forEach((el) => io.observe(el));
}

export function homeView(navigate) {
  const root = h("div", { class: "mx-auto max-w-6xl space-y-16" },
    hero(navigate), stats(), goals(navigate), install(), performance(), format(), ecosystem(), trust(), faq(), warning());
  requestAnimationFrame(() => observeReveal(root));
  return root;
}

