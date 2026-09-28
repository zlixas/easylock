// Tool views. Each factory returns a DOM tree; ids match content.js META.
import { h, ICONS, icon, fmtBytes } from "./ui.js";
import { t, L } from "./i18n.js";
import {
  api, enc, dec, hexToBytes, bytesToHex, bytesToB64, b64ToBytes, bytesToB64url,
} from "./api.js";
import { pushClip } from "./clipboard.js";
import {
  toolView, field, input, textarea, select, hexInput, outputBox, actions, button,
  ghostButton, dropZone, status, busy, passwordInput, segmented, kvRow, badge, download,
} from "./widgets.js";

const card = (...kids) => h("div", { class: "card space-y-4" }, ...kids);
const hidden = (el, yes) => { el.classList.toggle("hidden", yes); return el; };

/* ================================================================ helpers */

/** Uniform random integer in [0, n) via rejection sampling. */
function randInt(n) {
  const limit = Math.floor(0x1_0000_0000 / n) * n;
  for (;;) {
    const b = api.random(4);
    const x = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
    if (x < limit) return x % n;
  }
}

const COMMON = [
  "password", "123456", "12345678", "qwerty", "abc123", "111111", "letmein", "welcome",
  "monkey", "dragon", "iloveyou", "admin", "login", "master", "sunshine", "princess",
  "football", "baseball", "shadow", "superman", "trustno1", "passw0rd", "parola", "sifre",
  "şifre", "contraseña", "hola123", "galatasaray", "fenerbahce", "besiktas", "123456789",
  "qwertyuiop", "asdfgh", "zxcvbn", "000000", "654321", "starwars", "whatever", "freedom",
];

/** Heuristic password strength: { bits, score 0-4, seconds, tips[] }. */
export function estimate(pw) {
  if (!pw) return { bits: 0, score: 0, seconds: 0, tips: [] };
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
  const chars = [...pw];
  let bits = chars.length * Math.log2(pool || 1);
  const tips = [];
  const lower = pw.toLowerCase();

  const common = COMMON.some((c) => lower.includes(c));
  if (common) { bits = Math.min(bits, 12 + Math.max(0, chars.length - 8) * 2); tips.push("common"); }
  const repeats = /(.)\1{2,}/.test(pw);
  const seq = /(abc|bcd|cde|123|234|345|456|567|678|789|890|qwe|wer|asd|zxc)/i.test(pw);
  if (repeats || seq) { bits *= 0.75; tips.push("repeat"); }
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter((r) => r.test(pw)).length;
  if (chars.length < 14) tips.push("length");
  if (classes < 3 && chars.length < 20) tips.push("classes");

  bits = Math.max(0, Math.round(bits * 10) / 10);
  const score = bits < 28 ? 0 : bits < 45 ? 1 : bits < 65 ? 2 : bits < 90 ? 3 : 4;
  if (score >= 3 && !common) tips.length = 0;
  if (!tips.length) tips.push("good");
  return { bits, score, seconds: 2 ** bits / 2 / 1e11, tips };
}

export function fmtDuration(s) {
  if (s < 1) return t("time.instant");
  const units = [[60, "seconds"], [60, "minutes"], [24, "hours"], [365, "days"], [100, "years"]];
  let v = s;
  for (const [div, name] of units) {
    if (v < div) return `${Math.round(v)} ${t("time." + name)}`;
    v /= div;
  }
  if (s > 4.3e17) return t("time.forever");
  return v < 1e6 ? `${Math.round(v)} ${t("time.centuries")}` : `${v.toExponential(1)} ${t("time.centuries")}`;
}

const SCORE_COLORS = ["bg-red-500", "bg-orange-500", "bg-yellow-400", "bg-emerald-500", "bg-accent-500"];

/** A live strength bar bound to a password <input>. */
function strengthMeter(inp, { detailed = false } = {}) {
  const bar = h("div", { class: "h-full rounded-full transition-all" });
  const label = h("span", { class: "font-mono text-[11px] text-slate-400" });
  const detail = h("div", { class: "space-y-2 text-sm" });
  const wrap = h("div", { class: "space-y-2" },
    h("div", { class: "flex items-center gap-3" },
      h("div", { class: "h-2 flex-1 overflow-hidden rounded-full bg-obsidian-700" }, bar), label),
    detailed && detail);
  const update = () => {
    const r = estimate(inp.value);
    bar.className = "h-full rounded-full transition-all " + SCORE_COLORS[r.score];
    bar.style.width = inp.value ? `${Math.max(6, Math.min(100, r.bits))}%` : "0%";
    label.textContent = inp.value ? `${t("strength." + r.score)} · ${r.bits} bits` : "";
    if (detailed) {
      detail.replaceChildren(...(inp.value ? [
        kvRow(t("strength.entropy"), `${r.bits} bits`),
        kvRow(t("strength.crack"), fmtDuration(r.seconds), { mono: false }),
        h("div", { class: "space-y-1 pt-1" },
          h("div", { class: "label" }, t("strength.tips")),
          ...r.tips.map((k) => h("div", { class: "text-[13px] text-slate-300" }, "• " + t("strength.tip." + k)))),
      ] : []));
    }
  };
  inp.addEventListener("input", update);
  update();
  return wrap;
}

const CIPHERS = [["chacha20-poly1305", "ChaCha20-Poly1305"], ["aes-256-gcm", "AES-256-GCM"]];

/* ============================================================ symmetric */

function fileTool() {
  let mode = "encrypt", protect = "password";
  let data = null, fileName = "", info = null;
  const pw = passwordInput();
  const pw2 = passwordInput();
  const recips = textarea({ placeholder: "elkpub1…", rows: 3 });
  const secret = textarea({ placeholder: "ELK-SECRET-KEY-1…", rows: 2 });
  const cipher = select(CIPHERS);
  const infoLine = h("div", { class: "font-mono text-[11px] text-accent-400" });
  const result = h("div", { class: "space-y-2" });

  const pwField = field("field.password", pw);
  const meter = strengthMeter(pw.input);
  const pw2Field = field("field.password2", pw2);
  const recipField = field("field.recipients", recips);
  const secretField = field("field.identity", secret);
  const cipherField = field("field.cipher", cipher);
  const go = button("btn.encrypt", null, ICONS.lock);

  const protectSeg = segmented(
    [["password", t("protect.password")], ["keys", t("protect.keys")], ["both", t("protect.both")]],
    protect, (v) => { protect = v; layout(); });

  function layout() {
    const enc = mode === "encrypt";
    const usePw = enc ? protect !== "keys" : !info || info.password || info.version === 1;
    const useKeys = enc ? protect !== "password" : Boolean(info && info.recipients > 0);
    hidden(protectSeg, !enc);
    hidden(pwField, !usePw); hidden(meter, !enc || !usePw); hidden(pw2Field, !enc || !usePw);
    hidden(recipField, !enc || !useKeys); hidden(secretField, enc || !useKeys);
    hidden(cipherField, !enc);
    go.lastChild.textContent = t(enc ? "btn.encrypt" : "btn.decrypt");
  }

  const zone = dropZone("drop.file", (bytes, f) => {
    data = bytes; fileName = f.name; result.replaceChildren(); info = null; infoLine.textContent = "";
    if (mode === "decrypt") {
      try {
        info = api.elkInfo(bytes);
        infoLine.textContent = "🔐 " + info.summary;
        if (info.folder) result.replaceChildren(badge(false, t("msg.folder")));
        else if (info.recipients > 0 && !info.password) result.replaceChildren(h("div", { class: "text-[12px] text-slate-400" }, t("msg.needKey")));
      } catch (e) { infoLine.textContent = "✕ " + (e.message || e); }
      layout();
    }
    status(`${f.name} ${t("drop.loaded")}`, "ok");
  });

  const seg = segmented([["encrypt", t("mode.encrypt")], ["decrypt", t("mode.decrypt")]], mode, (m) => {
    mode = m; data = null; info = null; zone.reset(); infoLine.textContent = ""; result.replaceChildren();
    layout();
  });

  go.onclick = busy(go, async () => {
    if (!data) throw new Error(t("msg.pickFile"));
    let out, name;
    if (mode === "encrypt") {
      const usePw = protect !== "keys";
      if (usePw && !pw.input.value) throw new Error(t("msg.pwEmpty"));
      if (usePw && pw.input.value !== pw2.input.value) throw new Error(t("msg.pwDiffer"));
      out = await api.elkSeal(data, usePw ? pw.input.value : "", protect === "password" ? "" : recips.value, cipher.value);
      name = fileName + ".elk";
    } else {
      if (info && info.folder) throw new Error(t("msg.folder"));
      out = await api.elkOpen(data, pw.input.value, secret.value);
      name = fileName.endsWith(".elk") ? fileName.slice(0, -4) : fileName + ".dec";
    }
    const dl = h("button", { class: "btn", type: "button", onClick: () => download(out, name) },
      icon(ICONS.download, "h-4 w-4"), `${t("btn.download")} ${name}`);
    result.replaceChildren(
      badge(true, `✓ ${name} · ${fmtBytes(out.length)}`), dl,
      mode === "encrypt" && h("p", { class: "font-mono text-[11px] text-slate-500" }, `$ easylock unlock ${name}`));
    download(out, name);
    status(`${t("msg.done")} ✓`, "ok");
  }, t("msg.deriving"));

  layout();
  return toolView("sym.file",
    card(seg, zone, infoLine, protectSeg, recipField, secretField, pwField, meter, pw2Field, cipherField, actions(go), result));
}

function identityTool() {
  const view = h("div", { class: "space-y-3" });
  const show = (idt, withSecret) => {
    const rows = [
      h("span", { class: "label" }, t("id.public")),
      h("output", { class: "out" }, idt.public),
      kvRow(t("id.fingerprint"), idt.fingerprint),
    ];
    if (withSecret) {
      rows.push(h("span", { class: "label !text-amber-300" }, "⚠ " + t("id.secret")),
        h("output", { class: "out !text-amber-300" }, idt.secret),
        h("button", {
          class: "btn-ghost", type: "button",
          onClick: () => download(enc.encode(
            `# easylock identity: KEEP THIS FILE SECRET and back it up.\n# public key: ${idt.public}\n${idt.secret}\n`), "identity.key"),
        }, icon(ICONS.download, "h-3.5 w-3.5"), t("id.download")),
        h("p", { class: "font-mono text-[11px] text-slate-500" }, "$ easylock lock report.pdf -r elkpub1…   ·   $ easylock unlock report.pdf.elk -i identity.key"));
    }
    view.replaceChildren(...rows);
  };
  const gen = button("id.new", null, ICONS.key);
  gen.onclick = busy(gen, async () => {
    const idt = api.identityGenerate();
    pushClip("key", "easylock public key", idt.public);
    show(idt, true);
    status(`${t("msg.done")} ✓`, "ok");
  });
  const paste = textarea({ placeholder: "ELK-SECRET-KEY-1…", rows: 2 });
  paste.addEventListener("input", () => {
    if (!paste.value.trim()) return;
    try { show(api.identityPublic(paste.value), false); } catch (e) { view.replaceChildren(badge(false, String(e.message || e))); }
  });
  return toolView("asym.identity",
    card(actions(gen), view, h("div", { class: "border-t border-obsidian-700 pt-4" }, field("id.derive", paste))));
}

function textTool() {
  let mode = "encrypt";
  const msg = textarea({ placeholder: "…" });
  const pw = passwordInput();
  const cipher = select(CIPHERS);
  const out = outputBox("cipher", "elk1 token");
  const msgField = field("field.message", msg);
  const cipherField = field("field.cipher", cipher);
  const go = button("btn.encrypt", null, ICONS.lock);

  const seg = segmented([["encrypt", t("mode.encrypt")], ["decrypt", t("mode.decrypt")]], mode, (m) => {
    mode = m; out.clear();
    msgField.firstChild.textContent = t(m === "encrypt" ? "field.message" : "field.token");
    msg.placeholder = m === "encrypt" ? "…" : "elk1.…";
    hidden(cipherField, m === "decrypt");
    go.lastChild.textContent = t(m === "encrypt" ? "btn.encrypt" : "btn.decrypt");
  });

  go.onclick = busy(go, async () => {
    if (!pw.input.value) throw new Error(t("msg.pwEmpty"));
    if (mode === "encrypt") out.set(await api.elkSealToken(msg.value, pw.input.value, cipher.value));
    else out.set(await api.elkOpenToken(msg.value, pw.input.value), { capture: false });
    status(`${t("msg.done")} ✓`, "ok");
  }, t("msg.deriving"));

  return toolView("sym.text",
    card(seg, msgField, field("field.password", pw), strengthMeter(pw.input), cipherField, actions(go),
      field("field.output", out.el)));
}

function rawAead(id, alg) {
  let mode = "encrypt";
  const key = hexInput("field.key", 32);
  const nonce = hexInput("field.nonce", 12);
  const aad = input({ placeholder: "" });
  const data = textarea({ placeholder: "…" });
  const out = outputBox("cipher", alg);
  const dataField = field("field.plaintext", data);
  const go = button("btn.encrypt", null, ICONS.lock);

  const seg = segmented([["encrypt", t("mode.encrypt")], ["decrypt", t("mode.decrypt")]], mode, (m) => {
    mode = m; out.clear();
    dataField.firstChild.textContent = t(m === "encrypt" ? "field.plaintext" : "field.ciphertext");
    go.lastChild.textContent = t(m === "encrypt" ? "btn.encrypt" : "btn.decrypt");
  });

  go.onclick = busy(go, async () => {
    const k = hexToBytes(key.get()), n = hexToBytes(nonce.get()), a = enc.encode(aad.value);
    if (mode === "encrypt") {
      out.set(bytesToB64(api.aeadSeal(alg, k, n, a, enc.encode(data.value))));
    } else {
      out.set(dec.decode(api.aeadOpen(alg, k, n, a, b64ToBytes(data.value))), { capture: false });
    }
    status(`${t("msg.done")} ✓`, "ok");
  });

  // Fresh random key + nonce by default so the tool works immediately.
  key.set(bytesToHex(api.random(32)));
  nonce.set(bytesToHex(api.random(12)));

  return toolView(id,
    card(seg, key.el, nonce.el, field("field.aad", aad), dataField, actions(go), field("field.output", out.el)));
}

/* =========================================================== asymmetric */

function ed25519Tool() {
  let mode = "sign";
  const seed = hexInput("field.seed", 32);
  const msg = textarea({ placeholder: "…" });
  const pub = input({ placeholder: "64 hex" });
  const sig = input({ placeholder: "128 hex" });
  const result = h("div", { class: "space-y-2" });
  const pubField = field("field.public", pub);
  const sigField = field("field.signature", sig);
  const go = button("btn.sign", null, ICONS.check);

  const genBtn = ghostButton("btn.generate", () => {
    const k = api.keygen("ed25519");
    seed.set(k.secret); pub.value = k.public;
    pushClip("key", "Ed25519 seed", k.secret);
    status("Ed25519 ✓", "ok");
  }, ICONS.key);

  const seg = segmented([["sign", t("btn.sign")], ["verify", t("btn.verify")]], mode, (m) => {
    mode = m; result.replaceChildren();
    hidden(seed.el, m === "verify"); hidden(genBtn, m === "verify");
    hidden(pubField, m === "sign"); hidden(sigField, m === "sign");
    go.lastChild.textContent = t(m === "sign" ? "btn.sign" : "btn.verify");
  });
  hidden(pubField, true); hidden(sigField, true);

  go.onclick = busy(go, async () => {
    if (mode === "sign") {
      const r = api.edSign(seed.get(), enc.encode(msg.value));
      pub.value = r.public_hex; sig.value = r.sig_hex;
      pushClip("sig", "Ed25519 signature", r.sig_hex);
      result.replaceChildren(kvRow(t("field.public"), r.public_hex), kvRow(t("field.signature"), r.sig_hex));
      status(`${t("msg.done")} ✓`, "ok");
    } else {
      const ok = api.edVerify(pub.value.trim(), enc.encode(msg.value), sig.value.trim());
      result.replaceChildren(badge(ok, ok ? t("msg.valid") : t("msg.invalid")));
    }
  });

  return toolView("asym.ed25519",
    card(seg, seed.el, actions(genBtn), field("field.message", msg), pubField, sigField, actions(go), result));
}

function x25519Tool() {
  const board = h("div", { class: "space-y-4" });
  const party = (name, emoji, secret, pub, color) =>
    h("div", { class: `rounded-lg border ${color} bg-obsidian-850/60 p-4 space-y-2` },
      h("div", { class: "text-sm font-bold text-slate-100" }, `${emoji} ${name}`),
      kvRow(t("field.secret"), secret, { warn: true }),
      kvRow(t("field.public"), pub));

  const run = button("btn.run", null, ICONS.swap);
  run.onclick = busy(run, async () => {
    const a = api.keygen("x25519"), b = api.keygen("x25519");
    const sa = api.x25519(a.secret, b.public);
    const sb = api.x25519(b.secret, a.public);
    const k = api.hkdf(hexToBytes(sa), new Uint8Array(), enc.encode("easylock demo v1"), 32);
    board.replaceChildren(
      h("div", { class: "grid gap-3 md:grid-cols-2" },
        party("Alice", "👩", a.secret, a.public, "border-pink-500/40"),
        party("Bob", "👨", b.secret, b.public, "border-sky-500/40")),
      h("div", { class: "flex items-center gap-2 text-[12px] text-slate-400" },
        icon(ICONS.swap, "h-4 w-4"),
        L({ en: "Only the public keys travel over the network.", tr: "Ağ üzerinden yalnızca açık anahtarlar gider.", es: "Solo las claves públicas viajan por la red." })),
      h("div", { class: "grid gap-2" },
        kvRow("Alice: X25519(a, B)", sa),
        kvRow("Bob: X25519(b, A)", sb)),
      badge(sa === sb, sa === sb ? t("msg.sharedMatch") : t("msg.nomatch")),
      kvRow("HKDF-SHA-256 → AEAD key", k));
    status(`${t("msg.done")} ✓`, "ok");
  });
  return toolView("asym.x25519", card(actions(run), board));
}

function kyberTool() {
  const param = select([["mlkem768", "ML-KEM-768"], ["mlkem512", "ML-KEM-512"], ["mlkem1024", "ML-KEM-1024"]]);
  const ek = textarea({ placeholder: "encapsulation key (hex)", rows: 3 });
  const dk = textarea({ placeholder: "decapsulation key (hex)", rows: 3 });
  const ct = textarea({ placeholder: "ciphertext (hex)", rows: 3 });
  const res = h("div", { class: "space-y-2" });
  let senderSecret = null;

  const genBtn = button("btn.generate", null, ICONS.key);
  const encBtn = button("btn.encaps", null, ICONS.lock);
  const decBtn = button("btn.decaps", null, ICONS.key);
  genBtn.onclick = busy(genBtn, async () => {
    const k = api.keygen(param.value);
    ek.value = k.public; dk.value = k.secret; ct.value = ""; senderSecret = null;
    res.replaceChildren(h("div", { class: "font-mono text-[11px] text-slate-400" },
      `${k.kind}: ek ${k.public.length / 2} B · dk ${k.secret.length / 2} B`));
    pushClip("key", `${k.kind} dk`, k.secret);
  });
  encBtn.onclick = busy(encBtn, async () => {
    const r = api.mlkemEncaps(param.value, ek.value.trim());
    ct.value = r.ciphertext_hex; senderSecret = r.shared_secret_hex;
    res.replaceChildren(
      kvRow(L({ en: "Sender's shared secret", tr: "Gönderenin ortak sırrı", es: "Secreto del emisor" }), r.shared_secret_hex),
      h("div", { class: "font-mono text-[11px] text-slate-400" }, `ciphertext ${r.ciphertext_hex.length / 2} B`));
  });
  decBtn.onclick = busy(decBtn, async () => {
    const ss = api.mlkemDecaps(param.value, dk.value.trim(), ct.value.trim());
    res.append(kvRow(L({ en: "Receiver's shared secret", tr: "Alıcının ortak sırrı", es: "Secreto del receptor" }), ss));
    if (senderSecret) res.append(badge(ss === senderSecret, ss === senderSecret ? t("msg.sharedMatch") : t("msg.nomatch")));
  });

  return toolView("asym.kyber",
    card(field("field.algo", param), actions(genBtn, encBtn, decBtn),
      field("field.public", ek), field("field.secret", dk), field("field.ciphertext", ct), res));
}

function rsaTool() {
  const res = h("div", { class: "space-y-2" });
  const genBtn = button("btn.generate", null, ICONS.key);
  genBtn.onclick = busy(genBtn, async () => {
    const t0 = performance.now();
    const k = await api.keygenAsync("rsa2048");
    const ms = Math.round(performance.now() - t0);
    pushClip("key", "RSA-2048 secret", k.secret);
    res.replaceChildren(
      h("span", { class: "label" }, t("field.public")), h("output", { class: "out" }, k.public),
      h("span", { class: "label" }, t("field.secret")), h("output", { class: "out !text-amber-300" }, k.secret),
      h("p", { class: "text-[11px] text-slate-500" }, `${k.note} · ${ms} ms`));
    status(`RSA-2048 ✓ (${ms} ms)`, "ok");
  }, "RSA prime search…");
  return toolView("asym.rsa", card(actions(genBtn), res));
}

/* ============================================================== hashing */

const HASH_ROWS = [
  ["sha256", "SHA-256"], ["sha512", "SHA-512"], ["sha3_256", "SHA3-256"],
  ["keccak256", "Keccak-256"], ["blake3", "BLAKE3"],
];

function hashTool() {
  const text = textarea({ placeholder: "…" });
  const rows = h("div", { class: "space-y-2" });
  const meta = h("div", { class: "font-mono text-[11px] text-slate-500" });
  const render = (bytes, label) => {
    const d = api.hashAll(bytes);
    rows.replaceChildren(...HASH_ROWS.map(([k, name]) => kvRow(name, d[k])));
    meta.textContent = `${label} · ${fmtBytes(bytes.length)}`;
  };
  text.addEventListener("input", () => render(enc.encode(text.value), "UTF-8"));
  const zone = dropZone("drop.hash", (bytes, f) => {
    text.value = "";
    render(bytes, f.name);
    pushClip("hash", `${f.name} SHA-256`, api.hash("sha256", bytes));
  });
  render(new Uint8Array(), "UTF-8");
  return toolView("hash.sha", card(field("field.input", text), zone, meta, rows));
}

function checksumTool() {
  let bytes = null;
  const expected = input({ placeholder: "e3b0c442…" });
  const result = h("div", { class: "space-y-2" });
  const text = textarea({ placeholder: "…", rows: 2 });
  const check = () => {
    // Accept "sha256:abc…", "abc…  file.iso", or a bare hex digest.
    const want = expected.value.trim().toLowerCase().replace(/^[a-z0-9-]+[:=]\s*/, "").split(/\s+/)[0];
    if (!want || !bytes) { result.replaceChildren(); return; }
    const all = api.hashAll(bytes);
    const hit = HASH_ROWS.find(([k]) => all[k] === want);
    const guess = want.length === 128 ? "SHA-512" : want.length === 64 ? "SHA-256 / SHA3-256 / Keccak-256 / BLAKE3" : "?";
    result.replaceChildren(
      badge(Boolean(hit), hit ? `✓ ${t("msg.match")} — ${hit[1]}` : `✕ ${t("msg.nomatch")}`),
      h("div", { class: "font-mono text-[11px] text-slate-500" }, `${t("msg.algoDetected")}: ${guess}`),
      ...(!hit ? HASH_ROWS.filter(([k]) => all[k].length === want.length).map(([k, n]) => kvRow(n, all[k])) : []));
  };
  expected.addEventListener("input", check);
  text.addEventListener("input", () => { bytes = enc.encode(text.value); check(); });
  const zone = dropZone("drop.file", (b) => { bytes = b; text.value = ""; check(); });
  return toolView("hash.verify", card(zone, field("field.input", text), field("field.expected", expected), result));
}

function hmacTool() {
  const algo = select([["sha256", "HMAC-SHA-256"], ["sha512", "HMAC-SHA-512"], ["sha3-256", "HMAC-SHA3-256"], ["keccak256", "HMAC-Keccak-256"]]);
  let keyMode = "text";
  const key = input({ placeholder: "secret" });
  const msg = textarea({ placeholder: "…" });
  const out = outputBox("mac", "HMAC");
  const b64 = h("div", { class: "break-all font-mono text-[11px] text-slate-500" });
  const seg = segmented([["text", "Text"], ["hex", "Hex"]], keyMode, (m) => { keyMode = m; update(); });
  function update() {
    try {
      const k = keyMode === "hex" ? hexToBytes(key.value) : enc.encode(key.value);
      const tag = api.hmac(algo.value, k, enc.encode(msg.value));
      out.set(tag, { capture: false });
      b64.textContent = `Base64: ${bytesToB64(hexToBytes(tag))}`;
    } catch (e) { out.set("—", { capture: false }); b64.textContent = String(e.message || e); }
  }
  [key, msg].forEach((el) => el.addEventListener("input", update));
  algo.addEventListener("change", update);
  out.el.addEventListener("click", () => pushClip("mac", algo.selectedOptions[0].text, out.el.textContent));
  update();
  return toolView("hash.hmac",
    card(field("field.algo", algo),
      h("label", { class: "block" }, h("span", { class: "label" }, t("field.key")),
        h("div", { class: "flex gap-2" }, key, seg)),
      field("field.message", msg), field("field.output", out.el), b64));
}

const ARGON_PRESETS = { owasp: [19456, 2, 1], file: [65536, 3, 4], fast: [4096, 1, 1] };

function argon2Tool() {
  let mode = "hash";
  const pw = passwordInput();
  const salt = hexInput("field.salt", 16);
  const m = input({ type: "number", value: 19456, min: 8 });
  const tt = input({ type: "number", value: 2, min: 1 });
  const p = input({ type: "number", value: 1, min: 1, max: 16 });
  const preset = segmented([["owasp", "OWASP"], ["file", "easylock .elk"], ["fast", "demo"]], "owasp", (k) => {
    [m.value, tt.value, p.value] = ARGON_PRESETS[k];
  });
  const phc = textarea({ placeholder: "$argon2id$v=19$m=…", rows: 2 });
  const out = outputBox("hash", "Argon2id PHC");
  const result = h("div", { class: "space-y-2" });
  const go = button("btn.hash", null, ICONS.bolt);

  const hashPart = h("div", { class: "space-y-4" },
    salt.el, preset,
    h("div", { class: "grid grid-cols-3 gap-3" }, field("field.memory", m), field("field.passes", tt), field("field.lanes", p)));
  const verifyPart = field("field.phc", phc);
  let seg;
  const useBtn = ghostButton("btn.useThis", () => { phc.value = out.el.textContent; seg.querySelectorAll("button")[1].click(); }, ICONS.check);
  const outPart = h("div", { class: "space-y-2" }, field("field.output", out.el), actions(useBtn));

  seg = segmented([["hash", t("mode.hash")], ["verify", t("mode.verify")]], mode, (md) => {
    mode = md; result.replaceChildren();
    hidden(hashPart, md === "verify"); hidden(outPart, md === "verify"); hidden(verifyPart, md === "hash");
    go.lastChild.textContent = t(md === "hash" ? "btn.hash" : "btn.verify");
  });
  hidden(verifyPart, true);
  salt.set(bytesToHex(api.random(16)));

  go.onclick = busy(go, async () => {
    if (!pw.input.value) throw new Error(t("msg.pwEmpty"));
    const t0 = performance.now();
    if (mode === "hash") {
      out.set(await api.argon2Phc(pw.input.value, hexToBytes(salt.get()), +m.value, +tt.value, +p.value));
      result.replaceChildren();
    } else {
      const ok = await api.argon2Verify(pw.input.value, phc.value);
      result.replaceChildren(badge(ok, ok ? t("msg.pwMatch") : t("msg.pwNoMatch")));
    }
    status(`${t("msg.done")} ✓ · ${Math.round(performance.now() - t0)} ms`, "ok");
  }, t("msg.deriving"));

  return toolView("hash.argon2",
    card(seg, field("field.password", pw), hashPart, verifyPart, actions(go), outPart, result));
}

function pbkdf2Tool() {
  const pw = passwordInput();
  const salt = hexInput("field.salt", 16);
  const iters = input({ type: "number", value: 600000, min: 1 });
  const len = input({ type: "number", value: 32, min: 1, max: 256 });
  const out = outputBox("hash", "PBKDF2");
  const go = button("btn.derive", null, ICONS.bolt);
  salt.set(bytesToHex(api.random(16)));
  go.onclick = busy(go, async () => {
    const t0 = performance.now();
    out.set(await api.pbkdf2(pw.input.value, hexToBytes(salt.get()), +iters.value, +len.value));
    status(`${t("msg.done")} ✓ · ${Math.round(performance.now() - t0)} ms`, "ok");
  });
  return toolView("hash.pbkdf2",
    card(field("field.password", pw), salt.el,
      h("div", { class: "grid grid-cols-2 gap-3" }, field("field.iterations", iters), field("field.length", len)),
      actions(go), field("field.output", out.el)));
}

function hkdfTool() {
  const ikm = hexInput("field.key", 32);
  const salt = hexInput("field.salt", 16);
  const info = input({ value: "my-app v1 encryption key" });
  const len = input({ type: "number", value: 32, min: 1, max: 8160 });
  const out = outputBox("key", "HKDF");
  const go = button("btn.derive", null, ICONS.bolt);
  ikm.set(bytesToHex(api.random(32)));
  go.onclick = busy(go, async () => {
    const s = salt.get() ? hexToBytes(salt.get()) : new Uint8Array();
    out.set(api.hkdf(hexToBytes(ikm.get()), s, enc.encode(info.value), +len.value));
    status(`${t("msg.done")} ✓`, "ok");
  });
  return toolView("hash.hkdf",
    card(ikm.el, salt.el,
      h("div", { class: "grid grid-cols-3 gap-3" },
        h("div", { class: "col-span-2" }, field("field.info", info)), field("field.length", len)),
      actions(go), field("field.output", out.el)));
}

/* ============================================================= pipeline */

function pipelineTool() {
  let chain = ["base64"];
  const chips = h("div", { class: "flex min-h-[2.25rem] flex-wrap items-center gap-2" });
  const inField = textarea({ placeholder: "Hello, world" });
  const out = outputBox("encode", "pipeline");

  function renderChips() {
    chips.replaceChildren();
    if (chain.length === 0) chips.append(h("span", { class: "text-[11px] italic text-slate-600" }, "+ …"));
    chain.forEach((step, i) => {
      if (i) chips.append(h("span", { class: "text-slate-600" }, "→"));
      chips.append(h("span", { class: "chip flex items-center gap-1.5" }, step,
        h("button", { class: "text-slate-500 hover:text-red-400", type: "button",
          onClick: () => { chain.splice(i, 1); renderChips(); } }, "×")));
    });
  }
  renderChips();

  const addRow = h("div", { class: "flex flex-wrap gap-2" },
    ...["hex", "base64", "base64url", "base58", "rot13"].map((tr) =>
      h("button", { class: "btn-ghost", type: "button", onClick: () => { chain.push(tr); renderChips(); } }, `+ ${tr}`)),
    h("button", { class: "btn-ghost hover:!border-red-400 hover:!text-red-400", type: "button",
      onClick: () => { chain = []; renderChips(); } }, t("btn.clearAll")));

  const encBtn = button("btn.encode");
  const decBtn = h("button", { class: "btn !bg-obsidian-700 hover:!bg-obsidian-600", type: "button" }, t("btn.decode"));
  encBtn.onclick = busy(encBtn, async () => { out.set(api.encode(inField.value, chain, false)); status("✓", "ok"); });
  decBtn.onclick = busy(decBtn, async () => { out.set(api.encode(inField.value, chain, true)); status("✓", "ok"); });

  return toolView("pipe.encode",
    card(chips, addRow, field("field.input", inField), actions(encBtn, decBtn), field("field.output", out.el)));
}

function jwtTool() {
  const tok = textarea({ placeholder: "eyJhbGciOi…", rows: 4 });
  const secret = input({ placeholder: "HS256 / HS512 secret — or Ed25519 public key (hex)" });
  const view = h("div", { class: "space-y-3" });
  const sample = ghostButton("btn.generate", () => {
    // Build a demo HS256 token signed with the secret "secret".
    const head = bytesToB64url(enc.encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
    const now = Math.floor(Date.now() / 1000);
    const body = bytesToB64url(enc.encode(JSON.stringify({ sub: "1234567890", name: "Ada Lovelace", iat: now, exp: now + 3600 })));
    const sig = bytesToB64url(hexToBytes(api.hmac("sha256", enc.encode("secret"), enc.encode(`${head}.${body}`))));
    tok.value = `${head}.${body}.${sig}`; secret.value = "secret"; render();
  }, ICONS.bolt);

  const pretty = (obj) => h("pre", { class: "out !cursor-text !text-slate-200" }, JSON.stringify(obj, null, 2));
  function render() {
    const parts = tok.value.trim().split(".");
    if (parts.length < 2 || !parts[0]) { view.replaceChildren(); return; }
    try {
      const header = JSON.parse(dec.decode(b64ToBytes(parts[0])));
      const payload = JSON.parse(dec.decode(b64ToBytes(parts[1])));
      const rows = [
        h("span", { class: "label !text-rose-300" }, "Header"), pretty(header),
        h("span", { class: "label !text-violet-300" }, "Payload"), pretty(payload),
      ];
      const now = Date.now() / 1000;
      for (const k of ["iat", "nbf", "exp"]) {
        if (typeof payload[k] === "number") {
          const d = new Date(payload[k] * 1000).toLocaleString();
          const expired = k === "exp" && payload.exp < now;
          const note = k === "exp" ? (expired ? ` · ⚠ ${t("msg.expired")}` : ` · ✓ ${t("msg.valid_until")}`) : "";
          rows.push(kvRow(k, d + note, { mono: false, warn: expired }));
        }
      }
      if (header.alg === "none") rows.push(badge(false, "alg: none — reject this token!"));
      const s = secret.value.trim();
      if (s && parts[2]) {
        const signed = enc.encode(`${parts[0]}.${parts[1]}`);
        let ok = null;
        if (header.alg === "HS256" || header.alg === "HS512") {
          const mac = api.hmac(header.alg === "HS256" ? "sha256" : "sha512", enc.encode(s), signed);
          ok = bytesToB64url(hexToBytes(mac)) === parts[2];
        } else if (header.alg === "EdDSA") {
          ok = api.edVerify(s, signed, bytesToHex(b64ToBytes(parts[2])));
        }
        rows.push(ok === null
          ? h("div", { class: "text-[12px] text-slate-500" }, `alg ${header.alg}: signature check not supported here`)
          : badge(ok, ok ? t("msg.valid") : t("msg.invalid")));
      }
      view.replaceChildren(...rows);
    } catch (e) {
      view.replaceChildren(badge(false, String(e.message || e)));
    }
  }
  tok.addEventListener("input", render);
  secret.addEventListener("input", render);
  return toolView("pipe.jwt", card(field("field.jwt", tok), actions(sample), field("field.key", secret), view));
}

/* ============================================================ utilities */

function pwgenTool() {
  const len = h("input", { type: "range", min: 8, max: 64, value: 20, class: "w-full accent-accent-500" });
  const lenLabel = h("span", { class: "font-mono text-sm text-accent-400" }, "20");
  const boxes = ["lower", "upper", "digits", "symbols"].map((k) =>
    h("label", { class: "flex items-center gap-2 text-sm text-slate-300" },
      h("input", { type: "checkbox", checked: true, class: "accent-accent-500", dataset: { k } }),
      { lower: "a–z", upper: "A–Z", digits: "0–9", symbols: "!@#" }[k]));
  const list = h("div", { class: "space-y-2" });
  const gen = () => {
    const opts = { length: +len.value };
    boxes.forEach((b) => { const c = b.querySelector("input"); opts[c.dataset.k] = c.checked; });
    if (!opts.lower && !opts.upper && !opts.digits && !opts.symbols) opts.lower = true;
    list.replaceChildren(...Array.from({ length: 5 }, () => {
      const r = api.password(opts);
      return kvRow(`${r.bits} bits`, r.password);
    }));
  };
  len.addEventListener("input", () => { lenLabel.textContent = len.value; gen(); });
  boxes.forEach((b) => b.addEventListener("change", gen));
  const genBtn = button("btn.generate", gen, ICONS.bolt);
  gen();
  return toolView("util.pwgen",
    card(h("div", {}, h("div", { class: "flex items-center justify-between" },
      h("span", { class: "label" }, t("field.length")), lenLabel), len),
    h("div", { class: "flex flex-wrap gap-5" }, ...boxes), actions(genBtn), list));
}

function strengthTool() {
  const pw = passwordInput({ placeholder: "correct horse battery staple" });
  const meter = strengthMeter(pw.input, { detailed: true });
  return toolView("util.strength",
    card(field("field.password", pw), meter,
      h("p", { class: "text-[11px] text-slate-500" }, "🔒 " + t("msg.noServer"))));
}

const CONS = "bdfghjklmnprstvz", VOWELS = "aeiou";

function randomTool() {
  const kind = select([
    ["bytes", t("random.bytes")], ["b64", t("random.b64")], ["uuid", t("random.uuid")],
    ["pin", t("random.pin")], ["phrase", t("random.dice")],
  ]);
  const size = input({ type: "number", value: 32, min: 1, max: 1024 });
  const sizeField = field("field.length", size);
  const count = input({ type: "number", value: 3, min: 1, max: 20 });
  const list = h("div", { class: "space-y-2" });
  const words = () => Math.max(3, Math.min(12, +size.value || 5));

  const one = () => {
    switch (kind.value) {
      case "bytes": return bytesToHex(api.random(+size.value));
      case "b64": return bytesToB64url(api.random(+size.value));
      case "uuid": {
        const b = api.random(16);
        b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
        const x = bytesToHex(b);
        return `${x.slice(0, 8)}-${x.slice(8, 12)}-${x.slice(12, 16)}-${x.slice(16, 20)}-${x.slice(20)}`;
      }
      case "pin": return Array.from({ length: 6 }, () => randInt(10)).join("");
      default:
        return Array.from({ length: words() }, () =>
          Array.from({ length: 3 }, () => CONS[randInt(16)] + VOWELS[randInt(5)]).join("")).join("-");
    }
  };
  const bitsOf = () => ({
    bytes: +size.value * 8, b64: +size.value * 8, uuid: 122, pin: 19.9,
    phrase: Math.round(words() * 3 * Math.log2(80)),
  })[kind.value];

  const gen = () => {
    list.replaceChildren(...Array.from({ length: Math.max(1, Math.min(20, +count.value || 1)) },
      () => kvRow(`${bitsOf()} bits`, one())));
  };
  kind.addEventListener("change", () => {
    hidden(sizeField, kind.value === "uuid" || kind.value === "pin");
    if (kind.value === "phrase") size.value = 5;
    else if (+size.value < 8) size.value = 32;
    gen();
  });
  [size, count].forEach((el) => el.addEventListener("input", gen));
  const genBtn = button("btn.generate", gen, ICONS.bolt);
  gen();
  return toolView("util.random",
    card(h("div", { class: "grid gap-3 sm:grid-cols-3" }, field("field.format", kind), sizeField, field("field.count", count)),
      actions(genBtn), list));
}

/* ============================================================= registry */
export const TOOLS = {
  "sym.file": fileTool,
  "sym.text": textTool,
  "sym.aes": () => rawAead("sym.aes", "aes-256-gcm"),
  "sym.chacha": () => rawAead("sym.chacha", "chacha20-poly1305"),
  "asym.identity": identityTool,
  "asym.ed25519": ed25519Tool,
  "asym.x25519": x25519Tool,
  "asym.kyber": kyberTool,
  "asym.rsa": rsaTool,
  "hash.sha": hashTool,
  "hash.verify": checksumTool,
  "hash.hmac": hmacTool,
  "hash.argon2": argon2Tool,
  "hash.pbkdf2": pbkdf2Tool,
  "hash.hkdf": hkdfTool,
  "pipe.encode": pipelineTool,
  "pipe.jwt": jwtTool,
  "util.pwgen": pwgenTool,
  "util.strength": strengthTool,
  "util.random": randomTool,
};

/** Old URLs (#hash.blake3 etc.) → new tool ids. */
export const ALIASES = {
  "hash.blake3": "hash.sha", "util.verify": "hash.verify",
  "pipe.b64": "pipe.encode", "pipe.hex": "pipe.encode", "pipe.rot13": "pipe.encode",
};
