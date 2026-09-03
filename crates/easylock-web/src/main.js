import "./style.css";
import { h, clear, icon, ICONS } from "./ui.js";
import { t, getLang, setLang, onLangChange } from "./i18n.js";
import { api } from "./api.js";
import { mountClipboard } from "./clipboard.js";
import { bindStatus } from "./widgets.js";
import { TOOLS } from "./tools.js";

const TREE = [
  { id: "sym", labelKey: "nav.symmetric", emoji: "🔒", icon: ICONS.lock, children: [
    { id: "sym.aes", labelKey: "tool.aes" },
    { id: "sym.chacha", labelKey: "tool.chacha" },
  ] },
  { id: "asym", labelKey: "nav.asymmetric", emoji: "🔑", icon: ICONS.key, children: [
    { id: "asym.rsa", labelKey: "tool.rsa" },
    { id: "asym.ed25519", labelKey: "tool.ed25519" },
    { id: "asym.kyber", labelKey: "tool.kyber" },
  ] },
  { id: "hash", labelKey: "nav.hashing", emoji: "⚡", icon: ICONS.bolt, children: [
    { id: "hash.sha", labelKey: "tool.sha" },
    { id: "hash.blake3", labelKey: "tool.blake3" },
    { id: "hash.argon2", labelKey: "tool.argon2" },
    { id: "hash.pbkdf2", labelKey: "tool.pbkdf2" },
  ] },
  { id: "pipe", labelKey: "nav.pipeline", emoji: "🔄", icon: ICONS.swap, children: [
    { id: "pipe.b64", labelKey: "tool.b64" },
    { id: "pipe.hex", labelKey: "tool.hex" },
    { id: "pipe.rot13", labelKey: "tool.rot13" },
  ] },
  { id: "util", labelKey: "nav.utilities", emoji: "🛡️", icon: ICONS.shield, children: [
    { id: "util.pwgen", labelKey: "tool.pwgen" },
    { id: "util.verify", labelKey: "tool.verify" },
  ] },
];

const collapsed = new Set(); // collapsed category ids
let current = location.hash.slice(1) || "sym.aes";

const app = document.getElementById("app");
let sidebarEl, workspaceEl, statusLine, serverPill;

function langToggle() {
  return h("div", { class: "flex overflow-hidden rounded-md border border-obsidian-700" },
    ...["en", "tr"].map((l) =>
      h("button", {
        class: "px-2.5 py-1 text-xs font-bold transition " +
          (getLang() === l ? "bg-accent-600 text-white" : "bg-obsidian-800 text-slate-400 hover:text-white"),
        onClick: () => setLang(l),
      }, l.toUpperCase())));
}

function renderSidebar() {
  clear(sidebarEl);
  for (const cat of TREE) {
    const isOpen = !collapsed.has(cat.id);
    sidebarEl.append(
      h("button", {
        class: "tree-cat",
        onClick: () => { if (isOpen) collapsed.add(cat.id); else collapsed.delete(cat.id); renderSidebar(); },
      },
        h("span", { class: "text-[13px]" }, cat.emoji),
        h("span", { class: "flex-1 text-left" }, t(cat.labelKey)),
        icon(ICONS.chevron, "h-3.5 w-3.5 text-slate-500 transition " + (isOpen ? "rotate-90" : ""))),
    );
    if (isOpen) {
      for (const leaf of cat.children) {
        sidebarEl.append(
          h("button", {
            class: "tree-leaf" + (leaf.id === current ? " active" : ""),
            onClick: () => navigate(leaf.id),
          },
            h("span", { class: "text-slate-600" }, "├─"),
            h("span", { class: "flex-1 text-left" }, t(leaf.labelKey))),
        );
      }
    }
  }
}

function renderWorkspace() {
  clear(workspaceEl);
  const factory = TOOLS[current] || TOOLS["sym.aes"];
  try {
    workspaceEl.append(factory());
  } catch (e) {
    workspaceEl.append(h("pre", { class: "text-red-400 text-xs" }, String(e.stack || e)));
  }
  statusLine.textContent = t("msg.done");
  statusLine.className = "font-mono text-[11px] text-slate-500";
}

function navigate(id) {
  current = id;
  location.hash = id;
  renderSidebar();
  renderWorkspace();
}

async function checkServer() {
  try {
    const hb = await api.health();
    serverPill.textContent = `● server ${hb.version} · aes:${hb.aes_backend} · ghash:${hb.ghash_backend}`;
    serverPill.className = "font-mono text-[11px] text-emerald-400";
  } catch {
    serverPill.textContent = "● " + t("msg.serverDown");
    serverPill.className = "font-mono text-[11px] text-red-400";
  }
}

function layout() {
  clear(app);
  sidebarEl = h("nav", { class: "space-y-0.5" });
  workspaceEl = h("div", { class: "min-h-full" });
  statusLine = h("span", { class: "font-mono text-[11px] text-slate-500" });
  serverPill = h("span", { class: "font-mono text-[11px] text-slate-500" });
  bindStatus(statusLine);

  const shell = h("div", { class: "flex h-screen flex-col" },
    // top bar
    h("header", {
      class: "flex items-center justify-between border-b border-obsidian-700 bg-obsidian-900 px-5 py-3",
    },
      h("div", { class: "flex items-center gap-3" },
        h("span", { class: "text-xl" }, "🔒"),
        h("div", {},
          h("div", { class: "text-sm font-bold tracking-tight text-slate-100" }, "easylock"),
          h("div", { class: "text-[11px] text-slate-500" }, t("app.subtitle")))),
      h("div", { class: "flex items-center gap-4" }, serverPill, langToggle())),
    // body: sidebar + workspace
    h("div", { class: "flex flex-1 overflow-hidden" },
      h("aside", {
        class: "w-64 shrink-0 overflow-y-auto border-r border-obsidian-700 bg-obsidian-900/60 p-3",
      }, sidebarEl),
      h("main", { class: "flex-1 overflow-y-auto p-6" }, workspaceEl)),
    // status bar
    h("footer", {
      class: "flex items-center gap-4 border-t border-obsidian-700 bg-obsidian-900 px-5 py-2",
    }, statusLine),
  );
  app.append(shell);
  mountClipboard(app);
}

onLangChange(() => { layout(); renderSidebar(); renderWorkspace(); checkServer(); });
window.addEventListener("hashchange", () => {
  const id = location.hash.slice(1);
  if (id && id !== current && TOOLS[id]) navigate(id);
});

document.documentElement.lang = getLang();
layout();
renderSidebar();
renderWorkspace();
checkServer();
setInterval(checkServer, 15000);
