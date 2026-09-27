// Reusable form widgets used by the tool views.
import { h, icon, ICONS, copyToOS, fmtBytes } from "./ui.js";
import { t, L } from "./i18n.js";
import { pushClip } from "./clipboard.js";
import { randomHex, yieldUI } from "./api.js";
import { META } from "./content.js";

let statusEl;
export function bindStatus(el) { statusEl = el; }
export function status(msg, kind = "") {
  if (!statusEl) return;
  statusEl.textContent = msg;
  statusEl.className =
    "truncate font-mono text-[11px] " +
    (kind === "err" ? "text-red-400" : kind === "ok" ? "text-emerald-400" : "text-slate-500");
}

export function field(labelKey, inputEl, hint) {
  return h("label", { class: "block" },
    h("span", { class: "label" }, t(labelKey)),
    inputEl,
    hint && h("span", { class: "mt-1 block text-[11px] text-slate-500" }, hint));
}

export function input(props = {}) {
  return h("input", { class: "field", autocomplete: "off", spellcheck: "false", ...props });
}
export function textarea(props = {}) {
  return h("textarea", { class: "field font-mono min-h-[6rem]", rows: 4, spellcheck: "false", ...props });
}
export function select(options, props = {}) {
  const s = h("select", { class: "field", ...props });
  for (const [val, text] of options) s.append(h("option", { value: val }, text));
  return s;
}

/** Password input with a show/hide eye. `.input` is the <input>. */
export function passwordInput(props = {}) {
  const inp = input({ type: "password", autocomplete: "new-password", ...props });
  const eye = h("button", {
    class: "btn-ghost !px-2.5", type: "button", title: "show / hide",
    onClick: () => { inp.type = inp.type === "password" ? "text" : "password"; },
  }, icon(ICONS.eye, "h-4 w-4"));
  const wrap = h("div", { class: "flex gap-2" }, inp, eye);
  wrap.input = inp;
  return wrap;
}

/** Segmented control. `options` = [[value, label]]; the element's `.value` is the selection. */
export function segmented(options, initial, onChange) {
  const el = h("div", { class: "seg", role: "tablist" });
  el.value = initial;
  const render = () => {
    el.replaceChildren(...options.map(([v, label]) =>
      h("button", {
        type: "button", class: v === el.value ? "active" : "", role: "tab",
        onClick: () => { el.value = v; render(); onChange?.(v); },
      }, label)));
  };
  render();
  return el;
}

/** hex input with a "Random N bytes" helper button. */
export function hexInput(labelKey, byteLen, initial = "") {
  const inp = input({ value: initial, placeholder: `${byteLen * 2} hex` });
  const btn = h("button", {
    class: "btn-ghost", type: "button",
    onClick: () => { inp.value = randomHex(byteLen); inp.dispatchEvent(new Event("input")); },
  }, icon(ICONS.bolt, "h-3.5 w-3.5"), t("btn.random"));
  return {
    el: h("label", { class: "block" },
      h("span", { class: "label" }, t(labelKey)),
      h("div", { class: "flex gap-2" }, inp, btn)),
    get: () => inp.value.trim(),
    set: (v) => { inp.value = v; },
    input: inp,
  };
}

/** An output box; click copies, and every write pushes to the clipboard dock. */
export function outputBox(clipKind, clipLabel, extraClass = "") {
  const el = h("output", { class: "out " + extraClass, title: t("btn.copy") });
  el.addEventListener("click", async () => {
    if (el.textContent.trim() && (await copyToOS(el.textContent.trim())))
      status(t("msg.copied"), "ok");
  });
  return {
    el,
    set(value, { capture = true } = {}) {
      el.textContent = value;
      if (capture && value) pushClip(clipKind, clipLabel, value);
    },
    clear() { el.textContent = ""; },
  };
}

/** Labelled key/value row with a copy button. */
export function kvRow(label, value, { mono = true, warn = false } = {}) {
  return h("div", { class: "kv" },
    h("span", { class: "kv-k" }, label),
    h("span", { class: (mono ? "font-mono " : "") + "kv-v" + (warn ? " !text-amber-300" : "") }, value),
    h("button", {
      class: "btn-ghost !px-2 !py-1", type: "button", title: t("btn.copy"),
      onClick: async () => { if (await copyToOS(value)) status(t("msg.copied"), "ok"); },
    }, icon(ICONS.copy, "h-3.5 w-3.5")));
}

export function badge(ok, text) {
  return h("div", {
    class: "rounded-md px-3 py-2 text-sm font-bold " +
      (ok ? "bg-emerald-500/15 text-emerald-400" : "bg-red-500/15 text-red-400"),
  }, text);
}

export function actions(...btns) {
  return h("div", { class: "flex flex-wrap items-center gap-2 pt-1" }, ...btns);
}
export function button(labelKey, onClick, iconPath) {
  return h("button", { class: "btn", type: "button", onClick },
    iconPath && icon(iconPath, "h-4 w-4"), t(labelKey));
}
export function ghostButton(labelKey, onClick, iconPath) {
  return h("button", { class: "btn-ghost", type: "button", onClick },
    iconPath && icon(iconPath, "h-3.5 w-3.5"), t(labelKey));
}

/** Drag-and-drop file zone. `onFile(bytes: Uint8Array, file)` fires on drop or pick. */
export function dropZone(labelKey, onFile) {
  const info = h("div", { class: "mt-1 font-mono text-[11px] text-slate-300" });
  const picker = h("input", { type: "file", class: "hidden" });
  picker.addEventListener("change", () => picker.files[0] && handle(picker.files[0]));

  async function handle(file) {
    info.textContent = `${file.name} · ${fmtBytes(file.size)}`;
    onFile(new Uint8Array(await file.arrayBuffer()), file);
  }

  const zone = h("div", {
    class: "drop",
    role: "button", tabindex: "0",
    onClick: () => picker.click(),
    onKeydown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); picker.click(); } },
    onDragover: (e) => { e.preventDefault(); zone.classList.add("hot"); },
    onDragleave: () => zone.classList.remove("hot"),
    onDrop: (e) => {
      e.preventDefault();
      zone.classList.remove("hot");
      const f = e.dataTransfer.files[0];
      if (f) handle(f);
    },
  }, icon(ICONS.upload, "h-6 w-6 text-slate-500"), t(labelKey), picker, info);
  zone.reset = () => { info.textContent = ""; picker.value = ""; };
  return zone;
}

/** Trigger a browser download of bytes. */
export function download(bytes, name) {
  const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
  const a = h("a", { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

/** Collapsible "Learn" panel for a tool. */
function learnPanel(meta) {
  const content = meta.learn;
  if (!content) return null;
  const sec = (k, emoji) => content[k] && h("div", { class: "space-y-1" },
    h("h3", { class: "text-xs font-bold uppercase tracking-wide text-accent-400" }, `${emoji} ${t("learn." + k)}`),
    h("p", { class: "text-[13px] leading-relaxed text-slate-300" }, L(content[k])));
  let open = true;
  try { open = localStorage.getItem("easylock-learn") !== "closed"; } catch {}
  const det = h("details", { class: "learn", open },
    h("summary", {}, icon(ICONS.book, "h-4 w-4"), t("learn.title")),
    h("div", { class: "grid gap-4 p-4 pt-1 sm:grid-cols-2" },
      sec("what", "💡"), sec("how", "⚙️"), sec("when", "🎯"), sec("careful", "⚠️")));
  det.addEventListener("toggle", () => {
    try { localStorage.setItem("easylock-learn", det.open ? "open" : "closed"); } catch {}
  });
  return det;
}

/** Standard tool container: header (emoji, name, spec, summary) + body + learn panel. */
export function toolView(id, ...sections) {
  const meta = META[id];
  return h("div", { class: "mx-auto max-w-3xl space-y-5" },
    h("header", { class: "space-y-2" },
      h("div", { class: "flex flex-wrap items-center gap-3" },
        h("span", { class: "text-2xl" }, meta.emoji),
        h("h1", { class: "text-xl font-semibold text-slate-100" }, L(meta.name)),
        h("span", { class: "chip" }, meta.spec)),
      h("p", { class: "text-sm text-slate-400" }, L(meta.summary))),
    ...sections,
    learnPanel(meta));
}

/** Wrap an async action: disables the button, shows progress and errors. */
export function busy(btn, fn, workingMsg) {
  return async (...a) => {
    btn.disabled = true;
    status(workingMsg || t("msg.working"));
    await yieldUI();
    try {
      await fn(...a);
    } catch (e) {
      status(String(e?.message || e), "err");
    } finally {
      btn.disabled = false;
    }
  };
}
