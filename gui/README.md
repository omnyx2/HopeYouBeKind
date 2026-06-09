# Lattice GUI (Tauri)

The desktop app. A thin web front-end (`index.html` + `src/`) inside a Tauri
shell (`src-tauri/`). The shell's `#[tauri::command]` functions are the only
bridge to the daemon — the web layer never touches the network.

> This directory is **excluded from the Cargo workspace** on purpose: the
> Tauri/webview toolchain is heavy and is built with `cargo tauri`, not
> `cargo check`. Keeping it separate keeps core builds fast.

## Prerequisites (one-time)

1. Tauri system dependencies for your OS — follow
   <https://tauri.app/v1/guides/getting-started/prerequisites>.
   (macOS: Xcode command-line tools + nothing else; Linux: webkit2gtk; Windows:
   WebView2 + MSVC build tools.)
2. Node.js 20+ and Rust 1.79+ (already pinned by `rust-toolchain.toml`).

## Run it

```bash
cd gui
npm install
npm run tauri dev        # opens the app with hot-reloading front-end
```

Until the daemon's IPC server lands (ROADMAP v0.4), the front-end uses a local
mock (`src/main.js`) so the whole UI is clickable. The Rust `#[tauri::command]`
stubs return placeholder state for the same reason.

## App icons (needed for `tauri build`)

`tauri dev` works without icons, but bundling does not. Generate a set from a
1024×1024 PNG:

```bash
npm run tauri icon path/to/logo.png
```

## Build installers

```bash
npm run tauri build      # produces a .app/.dmg, .msi, or .deb/.AppImage per OS
```

CI wires the per-OS bundling into the release workflow once the GUI is feature-
complete (see `.github/workflows/release.yml`).
