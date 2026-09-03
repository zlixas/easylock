import { defineConfig } from "vite";
import tailwindcss from "@tailwindcss/vite";

// The dashboard talks to easylock-server. In dev, Vite proxies the API so the
// browser sees a single origin (no CORS). In prod, easylock-server serves the
// built `dist/` and the API from the same origin.
export default defineConfig({
  plugins: [tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      "/v1": "http://127.0.0.1:8080",
      "/health": "http://127.0.0.1:8080",
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
