// The meshd bridge — the GUI's ONLY daemon channel. Everything goes through the
// Tauri `meshd` proxy command (newline-JSON over the daemon's local socket); in a
// plain browser (no Tauri) `mockInvoke` makes every call fail soft so the page
// still renders as a demo.

function mockInvoke(cmd) {
  if (cmd === "meshd") return Promise.reject("meshd not running (browser demo)");
  return Promise.resolve(null);
}

export const invoke = window.__TAURI__?.invoke ?? mockInvoke;
if (!window.__TAURI__) console.warn("Lattice: Tauri API not found — meshd unreachable (browser demo).");

/// One request → one reply. Throws on a daemon `Error` response so call sites
/// surface it (usually via toast).
export async function meshd(req) {
  const s = await invoke("meshd", { request: JSON.stringify(req) });
  let r;
  try { r = JSON.parse(s); } catch { throw new Error("bad meshd response"); }
  if (r && r.Error) throw new Error(r.Error.message);
  return r;
}
