import { defineConfig } from "vite";
import tailwindcss from "@tailwindcss/vite";

// Start downloading the crypto engine (.wasm) from <head>, in parallel with the
// main script, instead of only after that script has loaded and run. The hashed
// file name is only known at build time, so the tag is injected here.
// `crossorigin` makes the preload match wasm-bindgen's `fetch()` (same-origin
// credentials), so the browser reuses the response rather than fetching twice.
function preloadWasm() {
  return {
    name: "easylock-preload-wasm",
    apply: "build",
    transformIndexHtml(html, ctx) {
      const wasm = Object.keys(ctx.bundle ?? {}).filter((f) => f.endsWith(".wasm"));
      return wasm.map((f) => ({
        tag: "link",
        attrs: { rel: "preload", href: "./" + f, as: "fetch", type: "application/wasm", crossorigin: "" },
        injectTo: "head",
      }));
    },
  };
}

// The dashboard is fully client-side: easylock-core compiled to WebAssembly
// (`npm run wasm` -> src/pkg/). No backend. `base: "./"` keeps asset paths
// relative so it works both at "/" and under a GitHub Pages sub-path.
export default defineConfig({
  base: "./",
  plugins: [tailwindcss(), preloadWasm()],
  server: { port: 5173 },
  worker: { format: "es" },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    target: "es2022",
    assetsInlineLimit: 0, // keep the .wasm as a real file
  },
});
