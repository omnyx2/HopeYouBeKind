# BUILD.md — how to build Lattice (read this BEFORE any build/bundle/release)

This file is the single source of truth for building. The canonical CI recipe lives in
`.github/workflows/release.yml`; this document mirrors it and adds the rules that keep a
build from *silently shipping a stale binary*. If a step here disagrees with `release.yml`,
`release.yml` wins — fix this file.

---

## 0. The one mistake that keeps happening (READ FIRST)

**The crate's package name is NOT the binary name.**

| crate dir        | package name (`-p …`) | produced binary |
|------------------|-----------------------|-----------------|
| `crates/meshd`   | **`lattice-meshd`**   | `meshd`         |
| `crates/mesh`    | `lattice-mesh`        | (lib)           |
| `crates/meshrun` | `lattice-meshrun`     | (lib)           |
| `gui/src-tauri`  | `lattice-gui`         | `Lattice` app   |

`cargo build -p meshd` **does not build meshd** — it fails with
`error: package ID specification 'meshd' did not match any packages` and exits non-zero.
If that command is chained before a `cp target/release/meshd …`, the `cp` then copies a
**stale, possibly months-old** binary into the bundle and everything *looks* like it worked.
This is exactly how a pre-extensions `meshd` got shipped in a "0.7.3" bundle.

**Rules:**
- Build meshd as **`cargo build --release -p lattice-meshd`** (or `--bin meshd`). Never `-p meshd`.
- **Never chain `cargo build …; cp …` without checking the build's exit code.** A failed
  build must abort the copy. Don't `| tail` the rc away.
- After producing any binary you intend to ship, **verify it is fresh AND correct** (§4).

---

## 1. Toolchains — core is pinned 1.79, the GUI is stable

`rust-toolchain.toml` pins the **core workspace** to **Rust 1.79** (MSRV). The **Tauri GUI is
excluded from the workspace** and must build with **current stable** — its transitive deps
(`getrandom`, `idna_adapter`, `time-core`, …) require `edition2024` (Rust ≥ 1.85), which 1.79
cannot parse. This is **by design, not a bug** (see `gui/README.md`).

| target                         | toolchain | how |
|--------------------------------|-----------|-----|
| core crates (mesh/meshd/meshrun) | 1.79 (pinned) | plain `cargo …` (rust-toolchain.toml applies) |
| GUI / Tauri bundle             | stable    | prefix every cargo/npm cmd with `RUSTUP_TOOLCHAIN=stable` |

- A `getrandom`/`edition2024` build error means you ran a **GUI** build under the 1.79 pin.
  Fix: re-run with `RUSTUP_TOOLCHAIN=stable`. Do **not** "fix" it by downgrading lock deps.
- `cargo fmt` must use the **pinned 1.79** (`cargo fmt --all`) — CI fmt is 1.79 and stable's
  rustfmt formats differently, so a stable override false-passes locally then fails CI.

---

## 2. Core workspace (no GUI)

```bash
cargo build --workspace            # 1.79
cargo test  --workspace            # all tests must pass
cargo clippy --all-targets --all-features
cargo fmt --all --check            # 1.79 rustfmt; CI gate
```

Build just the daemon:

```bash
cargo build --release -p lattice-meshd   # → target/release/meshd
```

## 3. GUI desktop app + bundle (mirrors release.yml)

The app version shown in-GUI is baked from `gui/src-tauri/tauri.conf.json` at compile time.
Keep `tauri.conf.json`, `gui/src-tauri/Cargo.toml`, and `gui/package.json` versions in sync.

```bash
# 1) build the daemon sidecar with the CORRECT package name, on stable
RUSTUP_TOOLCHAIN=stable cargo build --release -p lattice-meshd
test -f target/release/meshd                       # abort if missing

# 2) stage it as the bundle resource (macOS/Linux; .exe on Windows)
mkdir -p gui/src-tauri/resources
cp target/release/meshd gui/src-tauri/resources/meshd

# 3) bundle the app (runs vite build + cargo build of lattice-gui, on stable)
cd gui && RUSTUP_TOOLCHAIN=stable npm run tauri build
# → gui/src-tauri/target/release/bundle/macos/Lattice.app  (+ dmg, which may fail; .app is enough)
```

Dev (hot-reload) instead of a bundle: `cd gui && RUSTUP_TOOLCHAIN=stable npm run tauri dev`.

### 3.1 One command (use this) — `scripts/build-app.sh`

```bash
scripts/build-app.sh
```

Does §3 atomically with the §4 gates baked in: builds with the right package name, **fails
loudly if the binary doesn't carry the current commit's SHA** (stale-build guard), bundles,
**hash-compares the bundled meshd against the freshly built one** (anti-mix guard), prints the
app version, and warns if a now-outdated meshd is still running. Prefer this over hand-typing
the steps — that is what shipped a stale binary in the first place.

### 3.2 Which build is actually running?

`meshd` logs its identity on the first lines of `/tmp/lattice-meshd.log`:

```
meshd: version v0.7.3 build 0457b74      # CARGO_PKG_VERSION + git short SHA (from build.rs)
```

So "old vs new binary" is never a guess: compare that SHA to `git rev-parse --short HEAD`.
The running daemon is whatever was launched — building to disk does NOT change it until the
app is relaunched (§5).

---

## 4. Verification gate — DO NOT trust a build you didn't verify

A green-looking log is not proof. Before claiming a build/bundle is done:

1. **Exit codes.** Every build step returned `0`. If you piped to `tail`, re-check `rc`
   explicitly — a failed `cargo build` mid-pipe is easy to miss.
2. **Freshness.** The artifact's mtime is *now*, not an old date:
   ```bash
   ls -la target/release/meshd gui/src-tauri/resources/meshd \
          gui/src-tauri/target/release/bundle/macos/Lattice.app/Contents/Resources/resources/meshd
   ```
   All three should be the same fresh build. An old date = a stale copy slipped in (§0).
3. **Content / behavior.** The binary actually contains the change you built:
   ```bash
   strings target/release/meshd | grep -c ListExtensions      # >0 if extensions are in
   ```
   or, for a running daemon, query it (read-only):
   ```bash
   python3 scripts/lattice raw '"ListExtensions"'             # must NOT say "unknown variant"
   ```
   "unknown variant" / 0 string hits ⇒ you shipped a binary without that code.
4. **Bundle version.**
   ```bash
   /usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" \
     gui/src-tauri/target/release/bundle/macos/Lattice.app/Contents/Info.plist
   ```

If any check fails, the build is **not** done — find the stale/failed step and redo it.

---

## 5. Live-VPN safety (macOS)

The GUI launches a **bundled, root-elevated** `meshd` (from the `.app`'s
`Resources/resources/meshd`) — *not* the workspace `target/` binary. Building to disk is safe
and never touches the running daemon. **Relaunching** the app swaps the daemon, which:

- restarts `meshd` → repeated restarts can **wedge the macOS utun** (kernel stops delivering
  packets → kill-switch reverts the tunnel). Avoid casual rebuild-relaunch cycles.
- means daemon code should be **verified OFFLINE** (separate socket + `MESHD_STATE_DIR`, no
  `DATA_PLANE`) or on a dedicated test mesh — never by hammering the live VPN socket.
- when you do swap: `lattice off` (restore routes) → `lattice shutdown` (clean teardown) →
  quit the app → relaunch once → re-auth → re-enable. Diagnose reachability with
  `curl`/TCP, not `ping` (campus blocks ICMP).

---

## 6. One-glance checklist

- [ ] meshd built with `-p lattice-meshd` (never `-p meshd`)
- [ ] GUI/bundle steps all prefixed `RUSTUP_TOOLCHAIN=stable`
- [ ] core build/test/clippy/fmt under plain 1.79
- [ ] every step exited 0 (rc checked, not tail-swallowed)
- [ ] artifact mtime is fresh; bundled meshd == freshly built meshd
- [ ] bundled meshd verified by content/behavior (`ListExtensions` etc.)
- [ ] bundle version (Info.plist) is what you expect
- [ ] live VPN not disturbed unless a swap was explicitly agreed
