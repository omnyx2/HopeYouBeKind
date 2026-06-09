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
2. Node.js 20+ and **current stable Rust**.

> **Toolchain note:** the core workspace is pinned to Rust 1.79 for a stable
> MSRV, but the Tauri dependency tree pulls transitive crates that require
> `edition2024` (Rust ≥ 1.85). The GUI is excluded from the workspace and builds
> with current stable. Force it with `RUSTUP_TOOLCHAIN=stable` (or `cargo
> +stable`) so the repo's 1.79 pin doesn't apply here.

## Run it

```bash
cd gui
npm install
RUSTUP_TOOLCHAIN=stable npm run tauri dev   # opens the app, hot-reloading FE
```

Verified: `npm run build` (frontend) + `cargo +stable build` (shell) compile, and
`tauri build --bundles app` produces a runnable `Lattice.app`.

Until the daemon's IPC server lands (ROADMAP v0.4), the front-end uses a local
mock (`src/main.js`) so the whole UI is clickable. The Rust `#[tauri::command]`
stubs return placeholder state for the same reason.

## App icons

An icon set is already generated under `src-tauri/icons/` from
`src-tauri/icons/source.png` (a placeholder Lattice mark). Regenerate from your
own art with:

```bash
npx tauri icon path/to/logo.png
```

## Build installers

```bash
RUSTUP_TOOLCHAIN=stable npx tauri build --bundles app   # → Lattice.app
RUSTUP_TOOLCHAIN=stable npx tauri build                 # .dmg / .msi / .deb / .AppImage
```

Output lands in `src-tauri/target/release/bundle/`. Bundles are ad-hoc signed;
notarization (macOS) / code signing (Windows) is wired in the release workflow
once signing certs are configured.

CI wires the per-OS bundling into the release workflow once the GUI is feature-
complete (see `.github/workflows/release.yml`).
