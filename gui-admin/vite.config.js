import { defineConfig } from "vite";

// Fixed dev-server port (matches devPath in tauri.conf.json). Uses 5174 so the
// admin console can run alongside the user GUI (which owns 5173).
export default defineConfig({
  clearScreen: false,
  server: {
    port: 5174,
    strictPort: true,
  },
  build: {
    outDir: "dist",
    target: "es2021",
  },
});
