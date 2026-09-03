// Reusable form widgets used by the tool views.
import { h, icon, ICONS, copyToOS, fileToBase64, fmtBytes } from "./ui.js";
import { t } from "./i18n.js";
import { pushClip } from "./clipboard.js";
import { randomHex } from "./api.js";

let statusEl;
export function bindStatus(el) { statusEl = el; }
export function status(msg, kind = "") {
  if (!statusEl) return;
  statusEl.textContent = msg;
  statusEl.className =
    "font-mono text-[11px] " +
    (kind === "err" ? "text-red-400" : kind === "ok" ? "text-emerald-400" : "text-slate-500");
}

export function field(labelKey, inputEl) {
  return h("label", { class: "block" },
    h("span", { class: "label" }, t(labelKey)),
    inputEl);
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

/** hex input with a "Random N bytes" helper button. */
export function hexInput(labelKey, byteLen, initial = "") {
  const inp = input({ value: initial, placeholder: `${byteLen * 2} hex chars` });
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
export function outputBox(clipKind, clipLabel) {
  const el = h("output", { class: "out" });
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

/** Drag-and-drop file zone. `onFile(base64, file)` fires on drop or pick. */
export function dropZone(labelKey, onFile) {
  const info = h("div", { class: "mt-2 font-mono text-[11px] text-slate-300" });
  const picker = h("input", { type: "file", class: "hidden" });
  picker.addEventListener("change", () => picker.files[0] && handle(picker.files[0]));

  async function handle(file) {
    info.textContent = `${file.name} · ${fmtBytes(file.size)}`;
    onFile(await fileToBase64(file), file);
  }

  const zone = h("div", {
    class:
      "flex flex-col items-center gap-2 rounded-lg border border-dashed border-obsidian-600 " +
      "bg-obsidian-850/60 px-4 py-6 text-center text-xs text-slate-500 transition",
    onClick: () => picker.click(),
    onDragover: (e) => { e.preventDefault(); zone.classList.add("border-accent-500", "text-slate-200"); },
    onDragleave: () => zone.classList.remove("border-accent-500", "text-slate-200"),
    onDrop: (e) => {
      e.preventDefault();
      zone.classList.remove("border-accent-500", "text-slate-200");
      const f = e.dataTransfer.files[0];
      if (f) handle(f);
    },
  }, icon(ICONS.file, "h-6 w-6 text-slate-500"), t(labelKey), picker, info);
  return zone;
}

/** Standard tool container. */
export function toolView(titleKey, subtitle, ...sections) {
  return h("div", { class: "mx-auto max-w-3xl space-y-5" },
    h("header", { class: "space-y-1" },
      h("h1", { class: "text-xl font-semibold text-slate-100" }, t(titleKey)),
      subtitle && h("p", { class: "text-sm text-slate-500" }, subtitle)),
    ...sections);
}

export function busy(btn, fn) {
  return async (...a) => {
    btn.disabled = true;
    status(t("msg.working"));
    try {
      await fn(...a);
    } catch (e) {
      status(String(e.message || e), "err");
    } finally {
      btn.disabled = false;
    }
  };
}
