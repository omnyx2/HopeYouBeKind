# Lattice Admin Console (`gui-admin/`)

A standalone Tauri desktop app for the **mesh administrator** — separate from the
user GUI (`gui/`), which deliberately hides admin capability. It attaches to an
already-running **admin daemon** (one started with `--network-key`) over the local
IPC socket `/tmp/lattice.sock`; it never spawns a daemon.

See [`docs/ADMIN_CONSOLE.md`](../docs/ADMIN_CONSOLE.md) for the full design and the
phased plan. Status:

- **Phase 1 — Membership & eviction** ✅ — Overview (network identity, admin badge,
  live peers) + Members (roster, enroll → join token, evict). No daemon changes
  (the `Members` / `IssueCert` / `RevokeMember` IPC already exists).
- **Phase 2 — Packet-level traffic inspector** — pending (daemon plumbing).
- **Phase 3 — Crypto-suite swap lab** — pending (daemon plumbing).

## Build & run

Like `gui/`, this is **not** a workspace member and must be built with **current
stable Rust** (the repo pins 1.79 for the core, but the Tauri/webview deps need a
newer toolchain — they pull `edition2024` crates). Force stable with
`RUSTUP_TOOLCHAIN=stable` / `cargo +stable`.

```bash
cd gui-admin
npm install
RUSTUP_TOOLCHAIN=stable npm run tauri dev          # hot-reloading dev app
RUSTUP_TOOLCHAIN=stable npx tauri build --bundles app   # → "Lattice Admin.app"
```

Then `open src-tauri/target/release/bundle/macos/"Lattice Admin.app"`.

The dev server runs on port **5174** (the user GUI owns 5173), so both can run at
once.

> **Lockfile note:** `src-tauri/Cargo.lock` is seeded from `gui/`'s lock to reuse
> its known-good resolution. If a fresh resolve pulls an `edition2024` crate that
> your toolchain can't parse, build with a newer stable (≥1.85) — that is the
> supported path.
