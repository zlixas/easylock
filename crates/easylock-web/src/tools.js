import { h, ICONS } from "./ui.js";
import { t } from "./i18n.js";
import { api, toB64, fromB64 } from "./api.js";
import { pushClip } from "./clipboard.js";
import {
  toolView, field, input, textarea, select, hexInput, outputBox, actions,
  button, ghostButton, dropZone, status, busy,
} from "./widgets.js";

/* ---------------- Symmetric (AES-GCM / ChaCha20-Poly1305) ---------------- */
function symmetric(alg, titleKey) {
  const key = hexInput("field.key", 32);
  const nonce = hexInput("field.nonce", 12);
  const aad = input({ placeholder: "optional" });
  const pt = textarea({ placeholder: "plaintext or Base64 ciphertext" });
  const out = outputBox("cipher", alg);
  let fileB64 = null;

  const encBtn = button("btn.encrypt", null, ICONS.lock);
  const decBtn = button("btn.decrypt", null, ICONS.key);
  encBtn.onclick = busy(encBtn, async () => {
    const data = fileB64 ?? toB64(pt.value);
    out.set(await api.aeadSeal(alg, key.get(), nonce.get(), aad.value.trim(), data));
    status("sealed ✓", "ok");
  });
  decBtn.onclick = busy(decBtn, async () => {
    const b64 = await api.aeadOpen(alg, key.get(), nonce.get(), aad.value.trim(), pt.value.trim());
    out.set(fileB64 ? `(binary, ${atob(b64).length} bytes, Base64 below)\n${b64}` : fromB64(b64));
    status("opened ✓", "ok");
  });

  return toolView(titleKey, `${alg} · AEAD`,
    h("div", { class: "card space-y-4" },
      key.el, nonce.el,
      field("field.aad", aad),
      dropZone("drop.file", (b64, f) => { fileB64 = b64; status(`${f.name} loaded`, "ok"); pt.placeholder = "(file loaded — Encrypt seals it)"; }),
      field("field.plaintext", pt),
      actions(encBtn, decBtn,
        ghostButton("btn.random", () => { key.set(""); key.input.dispatchEvent(new Event("input")); }, null)),
      field("field.output", out.el)));
}

/* ---------------- Asymmetric & Keys ---------------- */
function rsaKeys() {
  const out = h("div", { class: "space-y-3" });
  const pub = outputBox("key", "RSA public");
  const sec = h("output", { class: "out !text-amber-300" });
  const note = h("p", { class: "text-[11px] text-slate-500" });
  const genBtn = button("btn.generate", null, ICONS.key);
  genBtn.onclick = busy(genBtn, async () => {
    status(t("msg.working") + " (RSA prime search)");
    const k = await api.keygen("rsa2048");
    pub.set(k.public);
    sec.textContent = k.secret;
    pushClip("key", "RSA secret (CRT)", k.secret);
    note.textContent = k.note;
    status(k.kind + " ✓", "ok");
  });
  return toolView("tool.rsa", "RSA-2048 · PKCS#1",
    h("div", { class: "card space-y-3" }, actions(genBtn),
      h("span", { class: "label" }, "Public"), pub.el,
      h("span", { class: "label" }, "Secret (CRT components)"), sec, note));
}

function ed25519() {
  const seed = hexInput("field.key", 32);
  const msg = textarea({ placeholder: "message to sign / verify" });
  const sig = input({ placeholder: "signature hex (for verify)" });
  const pub = input({ placeholder: "public key hex (for verify)" });
  const out = outputBox("key", "Ed25519");

  const genBtn = ghostButton("btn.generate", async () => {
    const k = await api.keygen("ed25519");
    seed.set(k.secret); pub.value = k.public;
    out.set(`public=${k.public}\nseed=${k.secret}`);
    status("keypair ✓", "ok");
  }, ICONS.key);
  const signBtn = button("btn.sign", null, ICONS.check);
  const verBtn = button("btn.verify", null, ICONS.shield);
  signBtn.onclick = busy(signBtn, async () => {
    const r = await api.edSign(seed.get(), toB64(msg.value));
    pub.value = r.public_hex; sig.value = r.sig_hex;
    out.set(`public=${r.public_hex}\nsig=${r.sig_hex}`);
    status("signed ✓", "ok");
  });
  verBtn.onclick = busy(verBtn, async () => {
    const ok = await api.edVerify(pub.value.trim(), toB64(msg.value), sig.value.trim());
    status(ok ? t("msg.valid") : t("msg.invalid"), ok ? "ok" : "err");
  });

  return toolView("tool.ed25519", "RFC 8032 signatures",
    h("div", { class: "card space-y-4" },
      h("div", { class: "flex gap-2" }, seed.el),
      actions(genBtn),
      field("field.message", msg),
      field("field.key", pub), field("field.output", sig),
      actions(signBtn, verBtn),
      field("field.output", out.el)));
}

function kyber() {
  const param = select([["mlkem512", "ML-KEM-512"], ["mlkem768", "ML-KEM-768"], ["mlkem1024", "ML-KEM-1024"]]);
  const ek = textarea({ placeholder: "encapsulation key (hex)" });
  const dk = textarea({ placeholder: "decapsulation key (hex)" });
  const ct = textarea({ placeholder: "ciphertext (hex)" });
  const out = outputBox("key", "ML-KEM");

  const genBtn = button("btn.generate", null, ICONS.key);
  const encBtn = button("btn.encaps", null, ICONS.lock);
  const decBtn = button("btn.decaps", null, ICONS.key);
  genBtn.onclick = busy(genBtn, async () => {
    const k = await api.keygen(param.value);
    ek.value = k.public; dk.value = k.secret;
    out.set(`ek(${k.public.length / 2}B) dk(${k.secret.length / 2}B) generated`, { capture: false });
    pushClip("key", `${k.kind} dk`, k.secret);
    status(k.kind + " ✓", "ok");
  });
  encBtn.onclick = busy(encBtn, async () => {
    const r = await api.mlkemEncaps(param.value, ek.value.trim());
    ct.value = r.ciphertext_hex;
    out.set(`shared secret: ${r.shared_secret_hex}`);
    status("encapsulated ✓", "ok");
  });
  decBtn.onclick = busy(decBtn, async () => {
    const ss = await api.mlkemDecaps(param.value, dk.value.trim(), ct.value.trim());
    out.set(`shared secret: ${ss}`);
    status("decapsulated ✓", "ok");
  });

  return toolView("tool.kyber", "FIPS 203 · post-quantum KEM",
    h("div", { class: "card space-y-4" },
      field("field.algo", param),
      actions(genBtn, encBtn, decBtn),
      field("field.key", ek), field("field.key", dk), field("field.ciphertext", ct),
      field("field.output", out.el)));
}

/* ---------------- Hashing & KDF ---------------- */
function hashTool() {
  const algo = select([
    ["sha256", "SHA-256"], ["blake3", "BLAKE3"], ["keccak256", "Keccak-256"],
    ["sha512", "SHA-512"], ["sha3-256", "SHA3-256"],
  ]);
  const text = textarea({ placeholder: "type or paste…" });
  const out = outputBox("hash", "digest");
  let fileB64 = null;

  const hashBtn = button("btn.hash", null, ICONS.bolt);
  hashBtn.onclick = busy(hashBtn, async () => {
    const d = fileB64 ?? toB64(text.value);
    out.set(await api.hash(algo.value, d, false));
    status(algo.value + " ✓", "ok");
  });
  text.addEventListener("input", () => { fileB64 = null; });

  return toolView("tool.sha", "one-shot digests",
    h("div", { class: "card space-y-4" },
      field("field.algo", algo),
      dropZone("drop.hash", (b64, f) => { fileB64 = b64; text.value = ""; status(`${f.name} loaded`, "ok"); }),
      field("field.input", text),
      actions(hashBtn),
      field("field.output", out.el)));
}

function blake3Tool() {
  const v = hashTool();
  // reuse hashTool but pin BLAKE3
  const sel = v.querySelector("select");
  sel.value = "blake3";
  v.querySelector("h1").textContent = "BLAKE3";
  return v;
}

function kdfTool(kind) {
  const pw = input({ type: "password", placeholder: "password" });
  const salt = hexInput("field.salt", 16);
  const iters = input({ type: "number", value: kind === "argon2" ? 3 : 100000, min: 1 });
  const mCost = input({ type: "number", value: 65536, min: 8 });
  const par = input({ type: "number", value: 4, min: 1 });
  const out = outputBox("hash", kind === "argon2" ? "Argon2id" : "PBKDF2");

  const runBtn = button("btn.hash", null, ICONS.bolt);
  runBtn.onclick = busy(runBtn, async () => {
    if (kind === "argon2") {
      const r = await api.argon2(pw.value, {
        salt_hex: salt.get() || undefined,
        m_cost: +mCost.value, t_cost: +iters.value, parallelism: +par.value,
      });
      out.set(r.phc);
      status("argon2id ✓", "ok");
    } else {
      const hexOut = await api.pbkdf2(pw.value, salt.get(), +iters.value, 32, "sha256");
      out.set(hexOut);
      status("pbkdf2 ✓", "ok");
    }
  });

  const rows =
    kind === "argon2"
      ? [field("field.password", pw), salt.el,
         h("div", { class: "grid grid-cols-3 gap-3" },
           field("field.iterations", iters),
           h("label", { class: "block" }, h("span", { class: "label" }, "m (KiB)"), mCost),
           h("label", { class: "block" }, h("span", { class: "label" }, "p"), par))]
      : [field("field.password", pw), salt.el, field("field.iterations", iters)];

  return toolView(kind === "argon2" ? "tool.argon2" : "tool.pbkdf2",
    kind === "argon2" ? "RFC 9106 · memory-hard" : "RFC 8018 · PBKDF2-HMAC-SHA-256",
    h("div", { class: "card space-y-4" }, ...rows, actions(runBtn), field("field.output", out.el)));
}

/* ---------------- Pipeline converters ---------------- */
export function pipelineTool(preset = []) {
  let chain = [...preset];
  const chips = h("div", { class: "flex min-h-[2.25rem] flex-wrap gap-2" });
  const inField = textarea({ placeholder: "input" });
  const out = outputBox("encode", "pipeline");

  function renderChips() {
    chips.replaceChildren();
    if (chain.length === 0)
      chips.append(h("span", { class: "text-[11px] italic text-slate-600" }, "add a transform →"));
    chain.forEach((step, i) => {
      chips.append(h("span",
        { class: "flex items-center gap-1.5 rounded-full border border-obsidian-600 bg-obsidian-800 px-2.5 py-1 text-xs" },
        step,
        h("button", {
          class: "text-slate-500 hover:text-red-400", type: "button",
          onClick: () => { chain.splice(i, 1); renderChips(); },
        }, "×")));
    });
  }
  renderChips();

  const addRow = h("div", { class: "flex flex-wrap gap-2" },
    ...["hex", "base64", "base64url", "base58", "rot13"].map((tr) =>
      h("button", { class: "btn-ghost", type: "button", onClick: () => { chain.push(tr); renderChips(); } }, `+ ${tr}`)),
    h("button", {
      class: "btn-ghost hover:!border-red-400 hover:!text-red-400", type: "button",
      onClick: () => { chain = []; renderChips(); },
    }, t("btn.clearAll")),
  );

  const encBtn = button("btn.encode");
  const decBtn = h("button", { class: "btn bg-obsidian-700 hover:bg-obsidian-600", type: "button" }, t("btn.decode"));
  encBtn.onclick = busy(encBtn, async () => {
    out.set(await api.encode(inField.value, chain, false));
    status("encoded ✓", "ok");
  });
  decBtn.onclick = busy(decBtn, async () => {
    out.set(await api.encode(inField.value, chain, true));
    status("decoded ✓", "ok");
  });

  return toolView("nav.pipeline", "chain transforms · decode reverses the chain",
    h("div", { class: "card space-y-4" },
      chips, addRow,
      field("field.input", inField),
      actions(encBtn, decBtn),
      field("field.output", out.el)));
}

/* ---------------- Utilities ---------------- */
function passwordGen() {
  const len = input({ type: "number", value: 20, min: 4, max: 128 });
  const boxes = ["lower", "upper", "digits", "symbols"].map((k) =>
    h("label", { class: "flex items-center gap-2 text-sm text-slate-300" },
      h("input", { type: "checkbox", checked: k !== "symbols", class: "accent-accent-500", dataset: { k } }),
      k));
  const out = outputBox("password", "password");
  const meter = h("div", { class: "font-mono text-[11px] text-slate-500" });

  const genBtn = button("btn.generate", null, ICONS.bolt);
  genBtn.onclick = busy(genBtn, async () => {
    const opts = { length: +len.value };
    boxes.forEach((b) => { opts[b.querySelector("input").dataset.k] = b.querySelector("input").checked; });
    const r = await api.password(opts);
    out.set(r.password);
    meter.textContent = `≈ ${r.bits_of_entropy} bits of entropy`;
    status("generated ✓", "ok");
  });

  return toolView("tool.pwgen", "CSPRNG · rejection-sampled, unbiased",
    h("div", { class: "card space-y-4" },
      field("field.length", len),
      h("div", { class: "flex flex-wrap gap-4" }, ...boxes),
      actions(genBtn),
      field("field.output", out.el), meter));
}

function checksumVerify() {
  const algo = select([["sha256", "SHA-256"], ["blake3", "BLAKE3"], ["keccak256", "Keccak-256"], ["sha512", "SHA-512"]]);
  const text = textarea({ placeholder: "text, or drop a file" });
  const expected = input({ placeholder: "paste the checksum you expect" });
  const digest = outputBox("hash", "digest");
  const badge = h("div", { class: "hidden rounded-md px-3 py-1.5 text-xs font-bold" });
  let fileB64 = null;

  function compare() {
    const want = expected.value.trim().toLowerCase();
    const got = digest.el.textContent.trim().toLowerCase();
    if (!want || !got) { badge.className = "hidden"; return; }
    const ok = want === got;
    badge.className = "rounded-md px-3 py-1.5 text-xs font-bold " +
      (ok ? "bg-emerald-500/15 text-emerald-400" : "bg-red-500/15 text-red-400");
    badge.textContent = ok ? "✓ " + t("msg.match") : "✕ " + t("msg.nomatch");
  }
  expected.addEventListener("input", compare);

  const runBtn = button("btn.hash", null, ICONS.shield);
  runBtn.onclick = busy(runBtn, async () => {
    digest.set(await api.hash(algo.value, fileB64 ?? toB64(text.value), false));
    status("hashed ✓", "ok");
    compare();
  });
  text.addEventListener("input", () => { fileB64 = null; });

  return toolView("tool.verify", "hash then compare",
    h("div", { class: "card space-y-4" },
      field("field.algo", algo),
      dropZone("drop.hash", (b64, f) => { fileB64 = b64; text.value = ""; status(`${f.name} loaded`, "ok"); }),
      field("field.input", text),
      actions(runBtn),
      field("field.output", digest.el),
      field("field.expected", expected),
      badge));
}

/* ---------------- registry ---------------- */
export const TOOLS = {
  "sym.aes": () => symmetric("aes-256-gcm", "tool.aes"),
  "sym.chacha": () => symmetric("chacha20-poly1305", "tool.chacha"),
  "asym.rsa": rsaKeys,
  "asym.ed25519": ed25519,
  "asym.kyber": kyber,
  "hash.sha": hashTool,
  "hash.blake3": blake3Tool,
  "hash.argon2": () => kdfTool("argon2"),
  "hash.pbkdf2": () => kdfTool("pbkdf2"),
  "pipe.b64": () => pipelineTool(["base64"]),
  "pipe.hex": () => pipelineTool(["hex"]),
  "pipe.rot13": () => pipelineTool(["rot13"]),
  "util.pwgen": passwordGen,
  "util.verify": checksumVerify,
};
