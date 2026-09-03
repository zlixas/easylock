"use strict";

const T = window.__TAURI__ || {};
const invoke = T.core ? T.core.invoke : async () => { throw new Error("Tauri IPC unavailable"); };
const listen = T.event ? T.event.listen : async () => () => {};
const openDialog = T.dialog ? T.dialog.open : null;

/* ---------------- i18n ---------------- */
const I18N = {
  en: {
    "tab.files": "Files", "tab.hash": "Hash", "tab.convert": "Convert", "tab.keys": "Keys",
    "files.title": "Encrypt / decrypt a file",
    "files.hint": "Drag a file onto the box, or browse. The key is derived from your password with Argon2id; salt and nonces are generated automatically.",
    "files.drop": "Drop a file here", "files.browse": "Browse…", "files.cipher": "Cipher",
    "files.password": "Password", "files.encrypt": "Encrypt", "files.decrypt": "Decrypt",
    "hash.title": "Hash & checksum", "hash.algo": "Algorithm", "hash.text": "Text",
    "hash.dropfile": "…or drop a file to checksum", "hash.compute": "Compute",
    "hash.digest": "Digest (hex)", "hash.compare": "Compare with",
    "convert.title": "Text & pipeline converter",
    "convert.hint": "Chain transforms left → right. Decoding reverses the same chain.",
    "convert.clear": "Clear", "convert.input": "Input", "convert.output": "Output",
    "convert.encode": "Encode →", "convert.decode": "← Decode",
    "keys.title": "Password & key generator", "keys.pw": "Secure password", "keys.length": "Length",
    "keys.generate": "Generate", "keys.argon": "Argon2id password hash", "keys.password": "Password",
    "keys.hash": "Hash", "keys.keypair": "Key pair", "keys.kind": "Type",
    "keys.public": "Public", "keys.secret": "Secret",
    "status.ready": "Ready",
    "msg.encrypted": "Encrypted", "msg.decrypted": "Decrypted", "msg.wrote": "wrote",
    "msg.copied": "Copied to clipboard", "msg.match": "MATCH", "msg.nomatch": "NO MATCH",
    "msg.working": "Working…", "msg.generating": "Generating key — this can take a moment…",
    "msg.pickfile": "Pick a file first", "msg.needpw": "Enter a password",
    "pipeline.empty": "empty pipeline — add a transform",
  },
  tr: {
    "tab.files": "Dosyalar", "tab.hash": "Özet", "tab.convert": "Dönüştür", "tab.keys": "Anahtarlar",
    "files.title": "Dosya şifrele / çöz",
    "files.hint": "Bir dosyayı kutuya sürükleyin veya seçin. Anahtar, parolanızdan Argon2id ile türetilir; tuz ve nonce'lar otomatik üretilir.",
    "files.drop": "Dosyayı buraya bırakın", "files.browse": "Gözat…", "files.cipher": "Şifre",
    "files.password": "Parola", "files.encrypt": "Şifrele", "files.decrypt": "Çöz",
    "hash.title": "Özet & sağlama", "hash.algo": "Algoritma", "hash.text": "Metin",
    "hash.dropfile": "…veya sağlaması için bir dosya bırakın", "hash.compute": "Hesapla",
    "hash.digest": "Özet (hex)", "hash.compare": "Şununla karşılaştır",
    "convert.title": "Metin & işlem hattı dönüştürücü",
    "convert.hint": "Dönüşümleri soldan sağa zincirleyin. Çözme aynı zinciri tersine çevirir.",
    "convert.clear": "Temizle", "convert.input": "Girdi", "convert.output": "Çıktı",
    "convert.encode": "Kodla →", "convert.decode": "← Çöz",
    "keys.title": "Parola & anahtar üretici", "keys.pw": "Güvenli parola", "keys.length": "Uzunluk",
    "keys.generate": "Üret", "keys.argon": "Argon2id parola özeti", "keys.password": "Parola",
    "keys.hash": "Özetle", "keys.keypair": "Anahtar çifti", "keys.kind": "Tür",
    "keys.public": "Açık", "keys.secret": "Gizli",
    "status.ready": "Hazır",
    "msg.encrypted": "Şifrelendi", "msg.decrypted": "Çözüldü", "msg.wrote": "yazıldı",
    "msg.copied": "Panoya kopyalandı", "msg.match": "EŞLEŞTİ", "msg.nomatch": "EŞLEŞMEDİ",
    "msg.working": "Çalışıyor…", "msg.generating": "Anahtar üretiliyor — biraz sürebilir…",
    "msg.pickfile": "Önce bir dosya seçin", "msg.needpw": "Bir parola girin",
    "pipeline.empty": "boş hat — bir dönüşüm ekleyin",
  },
};
let lang = localStorage.getItem("easylock-lang") || (navigator.language || "en").slice(0, 2);
if (!I18N[lang]) lang = "en";
const t = (k) => (I18N[lang] && I18N[lang][k]) || I18N.en[k] || k;

function applyLang() {
  document.documentElement.lang = lang;
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
  document.querySelectorAll(".lang-btn").forEach((b) =>
    b.classList.toggle("active", b.dataset.lang === lang));
  document.getElementById("pipeline").dataset.empty = t("pipeline.empty");
  localStorage.setItem("easylock-lang", lang);
}
document.querySelectorAll(".lang-btn").forEach((b) =>
  b.addEventListener("click", () => { lang = b.dataset.lang; applyLang(); }));

/* ---------------- status ---------------- */
const statusbar = document.getElementById("statusbar");
function status(msg, kind) {
  statusbar.textContent = msg;
  statusbar.className = "statusbar" + (kind ? " " + kind : "");
}

/* ---------------- tabs ---------------- */
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((x) => x.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById("panel-" + tab.dataset.tab).classList.add("active");
  });
});

/* ---------------- shared drag-drop (Tauri gives real paths) ---------------- */
let filesTarget = null; // "file" | "hash"
if (T.webview && T.webview.getCurrentWebview) {
  T.webview.getCurrentWebview().onDragDropEvent((event) => {
    const p = event.payload;
    const zoneFile = document.getElementById("dropzone");
    const zoneHash = document.getElementById("hash-dropzone");
    if (p.type === "over") {
      zoneFile.classList.toggle("drag", inZone(p.position, zoneFile));
      zoneHash.classList.toggle("drag", inZone(p.position, zoneHash));
    } else if (p.type === "drop") {
      zoneFile.classList.remove("drag");
      zoneHash.classList.remove("drag");
      const path = p.paths && p.paths[0];
      if (!path) return;
      if (inZone(p.position, zoneHash)) setHashFile(path);
      else setEncFile(path);
    } else {
      zoneFile.classList.remove("drag");
      zoneHash.classList.remove("drag");
    }
  });
}
function inZone(pos, el) {
  if (!pos) return false;
  const r = el.getBoundingClientRect();
  return pos.x >= r.left && pos.x <= r.right && pos.y >= r.top && pos.y <= r.bottom;
}

/* ---------------- FILES tab ---------------- */
let encFilePath = null;
function setEncFile(p) {
  encFilePath = p;
  document.getElementById("file-name").textContent = p;
  status(p);
}
document.getElementById("browse-file").addEventListener("click", async () => {
  if (!openDialog) return;
  const sel = await openDialog({ multiple: false });
  if (sel) setEncFile(Array.isArray(sel) ? sel[0] : sel);
});

const fileProgress = document.getElementById("file-progress");
const fileBar = document.getElementById("file-bar");
const fileProgressLabel = document.getElementById("file-progress-label");
listen("file-progress", (e) => {
  const { op, done, total } = e.payload;
  fileProgress.hidden = false;
  const pct = total ? Math.min(100, (done / total) * 100) : 0;
  fileBar.style.width = pct.toFixed(1) + "%";
  fileProgressLabel.textContent = `${op} · ${fmtBytes(done)} / ${fmtBytes(total)} (${pct.toFixed(0)}%)`;
});

async function runFileOp(cmd) {
  if (!encFilePath) return status(t("msg.pickfile"), "err");
  const password = document.getElementById("file-password").value;
  if (!password) return status(t("msg.needpw"), "err");
  const resultEl = document.getElementById("file-result");
  resultEl.hidden = true;
  fileProgress.hidden = true;
  fileBar.style.width = "0%";
  status(t("msg.working"));
  try {
    const args = { path: encFilePath, password };
    if (cmd === "encrypt_file") args.cipher = document.getElementById("file-cipher").value;
    const r = await invoke(cmd, args);
    const verb = cmd === "encrypt_file" ? t("msg.encrypted") : t("msg.decrypted");
    resultEl.className = "result";
    resultEl.replaceChildren(
      elem("strong", `${verb} `),
      text(`— ${r.cipher}`),
      elem("br"),
      text(`${t("msg.wrote")}: `),
      elem("span", r.out_path, "mono"),
      elem("br"),
      text(`${fmtBytes(r.bytes_in)} → ${fmtBytes(r.bytes_out)}`),
    );
    resultEl.hidden = false;
    status(verb + " ✓", "ok");
  } catch (err) {
    resultEl.className = "result error";
    resultEl.textContent = String(err);
    resultEl.hidden = false;
    status(String(err), "err");
  }
}
document.getElementById("do-encrypt").addEventListener("click", () => runFileOp("encrypt_file"));
document.getElementById("do-decrypt").addEventListener("click", () => runFileOp("decrypt_file"));

/* ---------------- HASH tab ---------------- */
let hashFilePath = null;
function setHashFile(p) {
  hashFilePath = p;
  document.getElementById("hash-file-name").textContent = p;
  document.querySelector('.tab[data-tab="hash"]').click();
  status(p);
}
async function doHash() {
  const algo = document.getElementById("hash-algo").value;
  const out = document.getElementById("hash-out");
  try {
    let digest;
    if (hashFilePath) {
      const r = await invoke("hash_file", { path: hashFilePath, algo });
      digest = r.digest;
      status(`${fmtBytes(r.size)} · ${algo}`, "ok");
    } else {
      digest = await invoke("hash_text", {
        input: document.getElementById("hash-text").value,
        isBase64: false,
        algo,
      });
      status(algo, "ok");
    }
    out.textContent = digest;
    compareChecksum();
  } catch (err) {
    out.textContent = "";
    status(String(err), "err");
  }
}
document.getElementById("do-hash").addEventListener("click", doHash);
document.getElementById("hash-text").addEventListener("input", () => {
  hashFilePath = null;
  document.getElementById("hash-file-name").textContent = "";
});
function compareChecksum() {
  const badge = document.getElementById("compare-badge");
  const want = document.getElementById("hash-compare").value.trim().toLowerCase();
  const got = document.getElementById("hash-out").textContent.trim().toLowerCase();
  if (!want || !got) { badge.hidden = true; return; }
  const ok = want === got;
  badge.hidden = false;
  badge.className = "compare-badge " + (ok ? "match" : "nomatch");
  badge.textContent = ok ? "✓ " + t("msg.match") : "✕ " + t("msg.nomatch");
}
document.getElementById("hash-compare").addEventListener("input", compareChecksum);

/* ---------------- CONVERT tab ---------------- */
let pipeline = [];
function renderPipeline() {
  const el = document.getElementById("pipeline");
  el.replaceChildren();
  pipeline.forEach((step, i) => {
    const chip = document.createElement("span");
    chip.className = "chip";
    chip.append(text(step));
    const rm = document.createElement("button");
    rm.textContent = "×";
    rm.title = "remove";
    rm.addEventListener("click", () => { pipeline.splice(i, 1); renderPipeline(); });
    chip.append(rm);
    el.appendChild(chip);
  });
}
document.querySelectorAll("[data-add]").forEach((b) =>
  b.addEventListener("click", () => { pipeline.push(b.dataset.add); renderPipeline(); }));
document.getElementById("pipeline-clear").addEventListener("click", () => { pipeline = []; renderPipeline(); });

async function doConvert(decode) {
  const out = document.getElementById("convert-out");
  try {
    const r = await invoke("transform", {
      input: document.getElementById("convert-in").value,
      steps: pipeline,
      decode,
    });
    out.textContent = r;
    status(decode ? "decode ✓" : "encode ✓", "ok");
  } catch (err) {
    out.textContent = "";
    status(String(err), "err");
  }
}
document.getElementById("do-encode").addEventListener("click", () => doConvert(false));
document.getElementById("do-decode").addEventListener("click", () => doConvert(true));

/* ---------------- KEYS tab ---------------- */
document.getElementById("do-genpw").addEventListener("click", async () => {
  try {
    const p = await invoke("gen_password", {
      length: parseInt(document.getElementById("pw-length").value, 10),
      lower: document.getElementById("pw-lower").checked,
      upper: document.getElementById("pw-upper").checked,
      digits: document.getElementById("pw-digit").checked,
      symbols: document.getElementById("pw-symbol").checked,
    });
    document.getElementById("pw-out").textContent = p;
    status("password ✓", "ok");
  } catch (err) { status(String(err), "err"); }
});

document.getElementById("do-argon").addEventListener("click", async () => {
  const out = document.getElementById("argon-out");
  out.textContent = t("msg.working");
  try {
    const r = await invoke("gen_argon2", {
      password: document.getElementById("argon-pw").value,
      mCost: parseInt(document.getElementById("argon-m").value, 10),
      tCost: parseInt(document.getElementById("argon-t").value, 10),
      parallelism: parseInt(document.getElementById("argon-p").value, 10),
    });
    out.textContent = r;
    status("argon2id ✓", "ok");
  } catch (err) { out.textContent = ""; status(String(err), "err"); }
});

document.getElementById("do-keypair").addEventListener("click", async () => {
  const spin = document.getElementById("kp-spin");
  const kind = document.getElementById("kp-kind").value;
  spin.hidden = false;
  status(kind === "rsa2048" ? t("msg.generating") : t("msg.working"));
  try {
    const r = await invoke("gen_keypair", { kind });
    document.getElementById("kp-public").textContent = r.public;
    document.getElementById("kp-secret").textContent = r.secret;
    document.getElementById("kp-note").textContent = r.note;
    status(r.kind + " ✓", "ok");
  } catch (err) {
    status(String(err), "err");
  } finally {
    spin.hidden = true;
  }
});

/* ---------------- click-to-copy on outputs ---------------- */
document.querySelectorAll("output").forEach((o) => {
  o.style.cursor = "copy";
  o.addEventListener("click", async () => {
    const text = o.textContent.trim();
    if (!text) return;
    try { await navigator.clipboard.writeText(text); status(t("msg.copied"), "ok"); } catch {}
  });
});

/* ---------------- helpers ---------------- */
function text(s) { return document.createTextNode(s); }
function elem(tag, content, cls) {
  const e = document.createElement(tag);
  if (content != null) e.textContent = content;
  if (cls) e.className = cls;
  return e;
}
function fmtBytes(n) {
  if (n < 1024) return n + " B";
  const u = ["KB", "MB", "GB", "TB"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(1) + " " + u[i];
}

/* ---------------- boot ---------------- */
applyLang();
renderPipeline();
invoke("sys_info")
  .then((s) => {
    document.getElementById("build-info").textContent =
      `v${s.version} · aes:${s.aes_backend} · ghash:${s.ghash_backend}`;
  })
  .catch(() => {});
