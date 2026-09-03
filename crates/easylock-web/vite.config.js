import { defineConfig } from "vite";
import tailwindcss from "@tailwindcss/vite";

// The dashboard is fully client-side: easylock-core compiled to WebAssembly
// (`npm run wasm` -> src/pkg/). No backend. `base: "./"` keeps asset paths
// relative so it works both at "/" and under a GitHub Pages sub-path.
export default defineConfig({
  base: "./",
  plugins: [tailwindcss()],
  server: { port: 5173 },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    target: "es2022",
    assetsInlineLimit: 0, // keep the .wasm as a real file
  },
});
