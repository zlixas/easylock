import "./style.css";
import { h, clear, icon, ICONS } from "./ui.js";
import { t, L, LANGS, getLang, setLang, cycleLang, onLangChange } from "./i18n.js";
import { api } from "./api.js";
import { initWasm } from "./wasm.js";
import { mountClipboard } from "./clipboard.js";
import { bindStatus } from "./widgets.js";
import { TOOLS, ALIASES } from "./tools.js";
import { META, CATEGORIES, TOOL_IDS } from "./content.js";
import { homeView } from "./home.js";

const REPO = "https://github.com/zlixas/easylock";
const app = document.getElementById("app");
const collapsed = new Set();
let current = resolve(location.hash.slice(1));
let sidebarEl, workspaceEl, statusLine, titleEl, subEl, mainEl, asideEl;

function resolve(id) {
  id = ALIASES[id] || id;
  return TOOLS[id] ? id : "home";
}

/* ------------------------------------------------------------- chrome */

function langToggle() {
  return h("div", { class: "seg", title: "F2 / Alt+L" },
    ...LANGS.map((l) => h("button", {
      type: "button", class: getLang() === l.code ? "active" : "", title: l.name,
      onClick: () => setLang(l.code),
    }, l.label)));
}

const tile = (cat, emoji, cls = "") => h("span", { class: `tile t-${cat} ${cls}` }, emoji);

function renderSidebar() {
  clear(sidebarEl);
  sidebarEl.append(h("button", {
    class: "tree-cat" + (current === "home" ? " active" : ""),
    onClick: () => navigate("home"),
  }, h("span", { class: "tile t-home" }, icon(ICONS.home, "h-3.5 w-3.5 text-white")), h("span", { class: "flex-1 truncate text-left" }, t("nav.home"))));

  for (const cat of CATEGORIES) {
    const isOpen = !collapsed.has(cat.id);
    sidebarEl.append(h("button", {
      class: "side-section",
      "aria-expanded": String(isOpen),
      onClick: () => { isOpen ? collapsed.add(cat.id) : collapsed.delete(cat.id); renderSidebar(); },
    },
      h("span", { class: "flex-1 text-left" }, t(cat.key)),
      icon(ICONS.chevron, "chev h-3 w-3 " + (isOpen ? "rotate-90" : ""))));
    if (!isOpen) continue;
    for (const id of TOOL_IDS.filter((x) => META[x].cat === cat.id)) {
      sidebarEl.append(h("button", {
        class: "tree-leaf" + (id === current ? " active" : ""),
        onClick: () => navigate(id),
      }, tile(cat.id, META[id].emoji),
        h("span", { class: "flex-1 truncate text-left" }, L(META[id].name))));
    }
  }
}

/* ----------------------------------------------------- command palette */

let paletteEl = null;
function openPalette() {
  if (paletteEl) return;
  const q = h("input", { class: "field !border-0 !bg-transparent !ring-0 text-base", placeholder: t("nav.search"), autofocus: true });
  const list = h("div", { class: "max-h-[60vh] overflow-y-auto p-2" });
  let sel = 0, results = [];

  const score = (id, s) => {
    const m = META[id];
    const hay = [m.name.en, m.name.tr, m.name.es, m.summary.en, m.keywords, m.spec, id].join(" ").toLowerCase();
    return s.split(/\s+/).every((w) => hay.includes(w));
  };
  const render = () => {
    const s = q.value.trim().toLowerCase();
    results = s ? TOOL_IDS.filter((id) => score(id, s)) : TOOL_IDS;
    sel = Math.min(sel, Math.max(0, results.length - 1));
    list.replaceChildren(...results.map((id, i) => h("button", {
      class: "pal-item" + (i === sel ? " active" : ""),
      onMouseenter: () => { sel = i; render(); },
      onClick: () => { closePalette(); navigate(id); },
    }, h("span", { class: "text-lg" }, META[id].emoji),
      h("span", { class: "min-w-0 flex-1 text-left" },
        h("span", { class: "block truncate text-sm text-slate-100" }, L(META[id].name)),
        h("span", { class: "block truncate text-[11px] text-slate-500" }, L(META[id].summary))),
      h("span", { class: "chip hidden sm:inline" }, t(CATEGORIES.find((c) => c.id === META[id].cat).key)))));
    list.querySelector(".active")?.scrollIntoView({ block: "nearest" });
  };
  q.addEventListener("input", () => { sel = 0; render(); });
  q.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); sel = Math.min(sel + 1, results.length - 1); render(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); sel = Math.max(sel - 1, 0); render(); }
    else if (e.key === "Enter" && results[sel]) { closePalette(); navigate(results[sel]); }
  });

  paletteEl = h("div", { class: "overlay", onClick: (e) => e.target === paletteEl && closePalette() },
    h("div", { class: "dialog max-w-xl" },
      h("div", { class: "flex items-center gap-2 border-b border-obsidian-700 px-3" },
        icon(ICONS.search, "h-4 w-4 text-slate-500"), q, h("kbd", {}, "Esc")),
      list));
  document.body.append(paletteEl);
  render();
  q.focus();
}
function closePalette() { paletteEl?.remove(); paletteEl = null; }

let helpEl = null;
function toggleHelp() {
  if (helpEl) { helpEl.remove(); helpEl = null; return; }
  const mod = /Mac|iPhone|iPad/.test(navigator.platform) ? "⌘" : "Ctrl";
  const row = (keys, key) => h("div", { class: "flex items-center justify-between gap-6 py-1.5" },
    h("span", { class: "text-sm text-slate-300" }, t(key)),
    h("span", { class: "flex gap-1" }, ...keys.map((k) => h("kbd", {}, k))));
  helpEl = h("div", { class: "overlay", onClick: (e) => e.target === helpEl && toggleHelp() },
    h("div", { class: "dialog max-w-sm p-5" },
      h("h2", { class: "mb-3 text-base font-semibold text-slate-100" }, t("kbd.title")),
      row([mod, "K"], "kbd.search"), row(["/"], "kbd.search"), row(["g", "h"], "kbd.home"),
      row(["Alt", "L"], "kbd.lang"), row(["?"], "kbd.help"), row(["Esc"], "kbd.close")));
  document.body.append(helpEl);
}

let lastKey = "";
document.addEventListener("keydown", (e) => {
  const typing = /INPUT|TEXTAREA|SELECT/.test(document.activeElement?.tagName || "");
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); paletteEl ? closePalette() : openPalette(); return; }
  if (e.key === "Escape") { closePalette(); if (helpEl) toggleHelp(); document.body.classList.remove("nav-open"); return; }
  if ((e.altKey && e.code === "KeyL") || e.key === "F2") { e.preventDefault(); cycleLang(); return; }
  if (typing || paletteEl) return;
  if (e.key === "/") { e.preventDefault(); openPalette(); }
  else if (e.key === "?") toggleHelp();
  else if (lastKey === "g" && e.key === "h") navigate("home");
  lastKey = e.key;
});

/* -------------------------------------------------------------- layout */

function renderWorkspace() {
  clear(workspaceEl);
  try {
    workspaceEl.append(current === "home" ? homeView(navigate) : TOOLS[current]());
  } catch (e) {
    workspaceEl.append(h("pre", { class: "text-xs text-red-400" }, String(e.stack || e)));
  }
  statusLine.textContent = "";
  mainEl.scrollTop = 0;
  const home = current === "home";
  titleEl.textContent = home ? "easylock" : L(META[current].name);
  subEl.textContent = home ? t("app.tagline") : META[current].spec;
  document.title = `${home ? t("app.tagline") : L(META[current].name)} · easylock`;
}

function navigate(id) {
  current = resolve(id);
  if (location.hash.slice(1) !== current) history.pushState(null, "", current === "home" ? location.pathname : "#" + current);
  document.body.classList.remove("nav-open");
  renderSidebar();
  renderWorkspace();
}

function layout() {
  clear(app);
  sidebarEl = h("nav", { class: "space-y-px", "aria-label": "tools" });
  workspaceEl = h("div", { class: "min-h-full" });
  statusLine = h("span", { class: "st" });
  titleEl = h("b");
  subEl = h("span", { class: "sub" });
  bindStatus(statusLine);

  const mod = /Mac|iPhone|iPad/.test(navigator.platform) ? "⌘K" : "Ctrl K";
  const searchBtn = h("button", { class: "search-btn", onClick: openPalette, "aria-label": t("nav.search") },
    icon(ICONS.search, "h-3.5 w-3.5"), h("span", { class: "hidden flex-1 text-left sm:inline" }, t("nav.search")),
    h("kbd", { class: "hidden !shadow-none sm:inline" }, mod));
  const tb = (path, label, onClick, cls = "") => h("button", { class: "tb-btn " + cls, "aria-label": label, title: label, onClick }, icon(path, "h-[18px] w-[18px]"));

  asideEl = h("aside", { class: "sidebar" },
    h("div", { class: "traffic", "aria-hidden": "true" }, h("i"), h("i"), h("i")),
    h("div", { class: "sidebar-scroll" },
      h("button", { class: "mb-2 mt-1 flex w-full items-center gap-2.5 rounded-[8px] px-2 py-1.5 text-left", onClick: () => navigate("home") },
        h("span", { class: "logo" }, "🔒"),
        h("span", { class: "min-w-0 leading-tight" },
          h("span", { class: "block text-[13px] font-semibold text-slate-100" }, "easylock"),
          h("span", { class: "block truncate text-[11px] text-slate-500" }, "Version " + api.version()))),
      sidebarEl),
    h("div", { class: "space-y-0.5 border-t border-obsidian-700 px-2.5 py-2 text-[12px]" },
      h("a", { class: "tree-cat !text-slate-400", href: REPO, target: "_blank", rel: "noopener" },
        icon(ICONS.github, "h-4 w-4"), t("nav.github")),
      h("button", { class: "tree-cat !text-slate-400", onClick: toggleHelp },
        icon(ICONS.keyboard, "h-4 w-4"), t("kbd.title"))));

  mainEl = h("main", { class: "flex-1 overflow-y-auto px-4 pb-40 pt-6 sm:px-8" }, workspaceEl,
    h("footer", { class: "mx-auto mt-16 flex max-w-6xl flex-wrap items-center justify-between gap-3 border-t border-obsidian-700 pt-5 text-[11px] text-slate-500" },
      h("span", {}, "easylock · " + t("footer.built")),
      h("span", { class: "flex flex-wrap gap-4" },
        h("a", { class: "hover:text-slate-300", href: REPO, target: "_blank", rel: "noopener" }, "GitHub"),
        h("a", { class: "hover:text-slate-300", href: REPO + "/blob/main/SECURITY.md", target: "_blank", rel: "noopener" }, "Security"),
        h("span", {}, t("footer.license")),
        h("span", { class: "text-amber-300" }, t("footer.audit")))));

  const toolbar = h("header", { class: "toolbar" },
    tb(ICONS.menu, t("nav.menu"), () => document.body.classList.toggle("nav-open"), "md:hidden"),
    tb("M15 6l-6 6 6 6", "Back", () => history.back()),
    tb(ICONS.chevron, "Forward", () => history.forward(), "hidden sm:grid"),
    h("div", { class: "tb-title" }, titleEl, subEl, statusLine),
    h("div", { class: "flex shrink-0 items-center gap-2" }, searchBtn, langToggle()));

  app.append(h("div", { class: "mac-desktop" },
    h("div", { class: "mac-window" },
      h("div", { class: "scrim md:hidden", onClick: () => document.body.classList.remove("nav-open") }),
      asideEl,
      h("div", { class: "flex min-w-0 flex-1 flex-col" }, toolbar, mainEl))));
  mountClipboard(app);
}

function renderAll() { layout(); renderSidebar(); renderWorkspace(); }

onLangChange(renderAll);
window.addEventListener("popstate", () => {
  const id = resolve(location.hash.slice(1));
  if (id !== current) { current = id; renderSidebar(); renderWorkspace(); }
});

document.documentElement.lang = getLang();

// Offline support: cache the app once so every tool works without a network.
if (import.meta.env.PROD && "serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("./sw.js").catch(() => {});
  });
}

// Boot: show a loading state, initialise WASM, then render the app.
app.append(h("div", { class: "flex h-screen flex-col items-center justify-center gap-3 font-mono text-sm text-slate-500" },
  h("span", { class: "logo animate-pulse" }, "🔒"), t("msg.engineLoading")));
initWasm()
  .then(() => {
    renderAll();
    // Load the crypto worker in idle time so the first slow operation starts instantly.
    (window.requestIdleCallback || ((f) => setTimeout(f, 500)))(() => api.warmWorker());
  })
  .catch((e) => {
    clear(app);
    app.append(h("div", { class: "m-10 rounded-lg border border-red-500/40 bg-red-500/10 p-6 text-sm text-red-300" },
      h("div", { class: "mb-2 font-bold" }, t("msg.engineFail")),
      h("pre", { class: "whitespace-pre-wrap text-xs" }, String(e.stack || e))));
  });
