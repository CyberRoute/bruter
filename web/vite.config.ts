import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The SPA is embedded into the Go binary (see web/embed.go) and served from the
// same origin as the API in production, so all asset paths stay relative.
// During development, `npm run dev` proxies the API routes to the Go server on
// :8080 so the React app and the backend behave as one origin.
export default defineConfig({
  plugins: [react()],
  // The SPA is always served from the site root by the Go server, and uses
  // history-mode client routing (/ssl, /whois), so asset URLs must be absolute.
  base: "/",
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8080",
      "/consumer": "http://127.0.0.1:8080",
    },
  },
});
