// Tiny hyperscript helper — no framework, safe DOM construction (no innerHTML).
export function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v == null || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "html") el.textContent = v; // deliberately text, never HTML
      else if (k.startsWith("on") && typeof v === "function") {
        el.addEventListener(k.slice(2).toLowerCase(), v);
      } else if (k === "dataset") {
        Object.assign(el.dataset, v);
      } else if (k in el && k !== "list") {
        el[k] = v;
      } else {
        el.setAttribute(k, v);
      }
    }
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

export const clear = (el) => el.replaceChildren();

/** An SVG icon from a 24x24 path string. */
export function icon(path, cls = "h-4 w-4") {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.7");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("class", cls);
  for (const d of path.split("|")) {
    const p = document.createElementNS(ns, "path");
    p.setAttribute("d", d);
    svg.append(p);
  }
  return svg;
}

export const ICONS = {
  lock: "M7 11V8a5 5 0 0 1 10 0v3|M5 11h14v10H5z",
  key: "M15 7a4 4 0 1 1-5.66 5.66L4 18v3h3l5.34-5.34A4 4 0 0 1 15 7z",
  bolt: "M13 2 3 14h7l-1 8 10-12h-7l1-8z",
  swap: "M7 7h11l-3-3|M17 17H6l3 3|M7 7v10|M17 7v10",
  shield: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z",
  chevron: "M9 6l6 6-6 6",
  copy: "M9 9h11v11H9z|M5 15H4V4h11v1",
  trash: "M4 7h16|M9 7V4h6v3|M6 7l1 13h10l1-13",
  check: "M4 12l5 5L20 6",
  file: "M6 3h9l5 5v13H6z|M15 3v6h6",
  globe: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18|M3 12h18|M12 3c3 3.5 3 14.5 0 18|M12 3c-3 3.5-3 14.5 0 18",
};

/** Copy text to the OS clipboard, returning a boolean. */
export async function copyToOS(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/** Read a File as base64 (no data-URI prefix). */
export function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result).split(",", 2)[1] ?? "");
    r.onerror = () => reject(r.error);
    r.readAsDataURL(file);
  });
}

export function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  const u = ["KB", "MB", "GB"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return `${n.toFixed(1)} ${u[i]}`;
}
