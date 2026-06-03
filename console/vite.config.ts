import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Vite dev server port comes from the project-shared port registry
// (`gnet-console-spa-dev = 6017`). The dispatcher admin API runs on
// :6016 — `/api/*` is reverse-proxied so the SPA can use same-origin
// cookies in dev exactly the way it will in prod (where the same SPA
// gets embedded into the dispatcher binary via include_dir!).
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: "127.0.0.1",
    port: 6017,
    strictPort: true,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:6016",
        changeOrigin: false,
      },
    },
  },
});
