import { defineConfig } from "vite";

// Tauri expects a fixed dev-server port (matches devPath in tauri.conf.json).
export default defineConfig({
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
  },
  build: {
    outDir: "dist",
    target: "es2021",
  },
});
