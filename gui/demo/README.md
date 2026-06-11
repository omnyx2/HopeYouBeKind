# GUI click-through demo: create → issue → join → revoke

Scaffolding so Claude (or you) can drive the **Lattice** GUI by clicking real
buttons and capture a step-by-step screenshot walkthrough of mesh membership:
**망 생성 → 발급 → 가입 → 추방**.

macOS only. Coordinate-driven: we pin the window to a fixed rectangle, then
click and screenshot against it.

## One-time prerequisites (you must do these — Claude can't)

Grant the app that runs these scripts (Terminal, iTerm, or the Claude Code
host) **both** permissions in System Settings → Privacy & Security:

- **Accessibility** — to move the window and send clicks (`cliclick`, System Events)
- **Screen Recording** — to capture window screenshots (`screencapture`)

Without these, clicks/captures silently no-op. `cliclick` is already installed
(`brew install cliclick`, v5).

## Capability split (the design we're demoing)

Admin power (the network CA key) is a privileged capability and is kept
**isolated from the user GUI**. The GUI is the member/user surface; the admin
lifecycle runs through a separate CLI tool on its own socket. A dedicated admin
GUI can come later — but the *capability* stays separated, not bolted onto the
user app.

| Step | Surface | Driven by | Who |
|------|---------|-----------|-----|
| 망 생성 (create) | — (automatic) | admin daemon first start with `--network_key` | admin (CLI) |
| 발급 (issue)  | CLI: `./nodes.sh issue` | `lattice net issue` on the admin socket | admin (CLI) |
| 가입 (join)   | **GUI** Mesh ▸ "Join" button | `join_network` | the user |
| 추방 (revoke) | CLI: `./nodes.sh revoke` | `lattice net revoke` on the admin socket | admin (CLI) |

The membership UI is on the GUI's **Mesh** tab (`gui/index.html`). The only
membership action a user performs there is **Join**. The GUI then *reflects* the
effects of admin actions — role flips to "member" after a join, and the node is
cut off after a revoke — without ever holding admin power itself.

Why this maps cleanly onto the code:
- A network is created the first time a daemon starts with `--network_key`
  (`crates/daemon/src/main.rs:90`) — that's the isolated admin daemon, never the GUI.
- The bundled GUI's "Start node" launches the daemon with `--bind 0.0.0.0:41000`
  only, no `--network_key` (`gui/src-tauri/src/main.rs:291`) → a GUI node is
  always open-mode/non-admin. We lean into that instead of fighting it.
- The GUI hardcodes IPC socket `/tmp/lattice.sock` (`:16`) → that's the member.
  The admin tool lives on `/tmp/lattice-admin.sock`, fully separate.

> Note: the current GUI still *contains* an admin card (Issue/Revoke), shown only
> when `is_admin` is true. With this split it never appears (the GUI is never
> admin). Pulling that card out of the user GUI entirely — so admin code doesn't
> even ship in the user surface — is a possible follow-up refactor; see the repo
> discussion. For the demo it simply stays hidden.

## Files

- `lib.sh` — shared helpers: `fit_window`, `shot <name>`, `click`/`rel_click`, `type_text`
- `fit-window.sh` — pin the window to the demo rect + baseline shot (run first)
- `probe.sh` — calibration: pin window, print geometry, drop a `probe` shot to read button coords from
- `shot.sh <name>` — capture the window rect to `shots/NN-<name>.png`
- `nodes.sh` — member (GUI socket) + isolated admin tool (`build|up|member-id|issue|revoke|members|down`)
- `shots/` — output screenshots (gitignored)

## Run sheet (next session)

```bash
cd gui/demo

# 0. backend: build once, then start member (GUI socket) + isolated admin
./nodes.sh build
./nodes.sh up

# 1. open the GUI and pin the window
open -a Lattice          # or: cargo tauri dev  (from gui/)
./fit-window.sh          # pins window, saves shots/01-baseline.png

# 2. calibrate click targets against a fresh shot
./probe.sh               # read button x,y (relative to window) from shots/

# --- 망 생성 (admin, CLI): created automatically when the admin daemon started ---
./nodes.sh members       # admin tool: network exists, no members yet (CLI screenshot)
#   GUI Mesh tab shows 'open mode (no network)' for the user
./shot.sh gui-open

# --- 발급 (admin, CLI): mint a token for the GUI member ---
TOKEN=$(./nodes.sh issue mac-laptop)   # prints the join token (CLI screenshot)
echo "$TOKEN"

# --- 가입 (GUI click): user pastes the token and clicks Join ---
#   click Mesh ▸ join-token field, type/paste $TOKEN, click "Join"
#   GUI role flips 'open mode' -> 'member' within ~2s (poll)
./shot.sh gui-joined

# --- 추방 (admin, CLI): evict the member ---
./nodes.sh revoke        # admin tool drops the member across the mesh
#   GUI reflects the member being cut off
./shot.sh gui-revoked

# 3. teardown
./nodes.sh down
```

The 망생성/발급/추방 steps are admin (CLI) — capture the terminal output for those.
Only 가입 is a GUI button click. The GUI screenshots show the *user's* view of
each transition (open → member → cut off).

Coordinates aren't hardcoded on purpose — read them off `shots/` each run
(`probe.sh`), since DPI/theme/window position can shift them. `rel_click X Y`
takes coordinates measured from the window's top-left.
