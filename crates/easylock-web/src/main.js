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
let sidebarEl, workspaceEl, statusLine, enginePill, mainEl, asideEl;

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

function renderSidebar() {
  clear(sidebarEl);
  sidebarEl.append(h("button", {
    class: "tree-cat" + (current === "home" ? " !text-accent-400" : ""),
    onClick: () => navigate("home"),
  }, icon(ICONS.home, "h-4 w-4"), h("span", { class: "flex-1 text-left" }, t("nav.home"))));

  for (const cat of CATEGORIES) {
    const isOpen = !collapsed.has(cat.id);
    sidebarEl.append(h("button", {
      class: "tree-cat",
      "aria-expanded": String(isOpen),
      onClick: () => { isOpen ? collapsed.add(cat.id) : collapsed.delete(cat.id); renderSidebar(); },
    },
      h("span", { class: "w-4 text-center text-[13px]" }, cat.emoji),
      h("span", { class: "flex-1 text-left" }, t(cat.key)),
      icon(ICONS.chevron, "h-3.5 w-3.5 text-slate-500 transition " + (isOpen ? "rotate-90" : ""))));
    if (!isOpen) continue;
    for (const id of TOOL_IDS.filter((x) => META[x].cat === cat.id)) {
      sidebarEl.append(h("button", {
        class: "tree-leaf" + (id === current ? " active" : ""),
        onClick: () => navigate(id),
      }, h("span", { class: "w-4 text-center text-[12px]" }, META[id].emoji),
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
  const name = current === "home" ? t("app.tagline") : L(META[current].name);
  document.title = `${name} · easylock`;
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
  sidebarEl = h("nav", { class: "space-y-0.5", "aria-label": "tools" });
  workspaceEl = h("div", { class: "min-h-full" });
  statusLine = h("span", { class: "truncate font-mono text-[11px] text-slate-500" });
  enginePill = h("span", { class: "hidden font-mono text-[11px] text-emerald-400 md:inline", title: api.buildInfo() },
    `● easylock-core ${api.version()} · ${t("msg.engineReady")}`);
  bindStatus(statusLine);

  const searchBtn = h("button", { class: "search-btn", onClick: openPalette },
    icon(ICONS.search, "h-4 w-4"), h("span", { class: "hidden flex-1 text-left sm:inline" }, t("nav.search")),
    h("kbd", { class: "hidden sm:inline" }, /Mac/.test(navigator.platform) ? "⌘K" : "Ctrl K"));

  asideEl = h("aside", { class: "sidebar" },
    sidebarEl,
    h("div", { class: "mt-6 space-y-2 border-t border-obsidian-700 px-2.5 pt-4 text-[11px] text-slate-500" },
      h("a", { class: "flex items-center gap-2 hover:text-slate-200", href: REPO, target: "_blank", rel: "noopener" },
        icon(ICONS.github, "h-4 w-4"), t("nav.github")),
      h("button", { class: "flex items-center gap-2 hover:text-slate-200", onClick: toggleHelp },
        icon(ICONS.keyboard, "h-4 w-4"), t("kbd.title"))));

  mainEl = h("main", { class: "flex-1 overflow-y-auto p-4 pb-40 sm:p-6 sm:pb-40" }, workspaceEl,
    h("footer", { class: "mx-auto mt-16 flex max-w-6xl flex-wrap items-center justify-between gap-3 border-t border-obsidian-800 pt-5 text-[11px] text-slate-600" },
      h("span", {}, "easylock · " + t("footer.built")),
      h("span", { class: "flex gap-4" },
        h("a", { class: "hover:text-slate-300", href: REPO, target: "_blank", rel: "noopener" }, "GitHub"),
        h("a", { class: "hover:text-slate-300", href: REPO + "/blob/main/SECURITY.md", target: "_blank", rel: "noopener" }, "Security"),
        h("span", {}, t("footer.license")),
        h("span", { class: "text-amber-500/70" }, t("footer.audit")))));

  app.append(h("div", { class: "flex h-screen flex-col" },
    h("header", { class: "flex items-center justify-between gap-3 border-b border-obsidian-700 bg-obsidian-900 px-3 py-2.5 sm:px-5" },
      h("div", { class: "flex items-center gap-3" },
        h("button", { class: "btn-ghost !px-2 md:hidden", "aria-label": t("nav.menu"), onClick: () => document.body.classList.toggle("nav-open") },
          icon(ICONS.menu, "h-5 w-5")),
        h("button", { class: "flex items-center gap-2.5", onClick: () => navigate("home") },
          h("span", { class: "logo" }, "🔒"),
          h("span", { class: "text-left" },
            h("span", { class: "block text-sm font-bold tracking-tight text-slate-100" }, "easylock"),
            h("span", { class: "hidden text-[11px] text-slate-500 lg:block" }, t("app.tagline"))))),
      h("div", { class: "flex items-center gap-3" }, searchBtn, enginePill, langToggle())),
    h("div", { class: "relative flex flex-1 overflow-hidden" },
      h("div", { class: "scrim md:hidden", onClick: () => document.body.classList.remove("nav-open") }),
      asideEl, mainEl),
    h("div", { class: "flex items-center gap-4 border-t border-obsidian-700 bg-obsidian-900 px-5 py-1.5" },
      statusLine, h("span", { class: "ml-auto hidden text-[11px] text-slate-600 sm:inline" }, "🔒 " + t("msg.noServer")))));
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
