// Pure helpers shared across the GUI — no DOM, no daemon calls (so each is
// trivially testable and importable anywhere without ordering concerns).

// `'` included: some call sites interpolate into single-quoted attributes (data-scopes etc.).
export function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// ---- join-flow codes (§2b): base64(JSON) so each is one copy-pasteable string ----
export function b64encode(obj) { return btoa(unescape(encodeURIComponent(JSON.stringify(obj)))); }
// The CLI (scripts/lattice) emits URL-SAFE base64 (`-`/`_`); `atob` only takes the standard
// alphabet (`+`/`/`), so normalize before decoding or every CLI→GUI code fails as "invalid".
// (CLI→GUI needed this; GUI→CLI already worked — Python's decoder takes both alphabets.)
export function b64decode(s) {
  try {
    const t = (s || "").trim().replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(decodeURIComponent(escape(atob(t))));
  } catch { return null; }
}
export function encodeIdentity(id) { return b64encode({ m: id.member_pubkey_hex, e: id.enc_pubkey_hex, t: id.issued_at || 0 }); }
export function decodeIdentity(code) {
  const o = b64decode(code);
  if (!o) return null;
  // Accept BOTH the GUI short form {m,e,t} AND the CLI/daemon form
  // {member_pubkey_hex, enc_pubkey_hex, issued_at} so CLI ↔ GUI invites interoperate.
  const m = o.m || o.member_pubkey_hex, e = o.e || o.enc_pubkey_hex, t = o.t ?? o.issued_at ?? 0;
  return m && e ? { m, e, t } : null;
}
export function encodeInvite(w) { return b64encode(w); }
// P-C6: the invite is a WrappedInvite {salt, n, ct}.
export function decodeInvite(code) { const o = b64decode(code); return o && o.ct != null && o.salt != null ? o : null; }

// ---- formatting ----
export function fmtBytes(n) {
  const u = ["B", "KB", "MB", "GB"]; let i = 0;
  while (n >= 1024 && i < 3) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : n.toFixed(0)) + u[i];
}
// Duration string → seconds ('600' | '10m' | '2h' | '1d').
export function parseDur(s) {
  s = String(s || "").trim().toLowerCase();
  const m = { s: 1, m: 60, h: 3600, d: 86400 };
  const last = s.slice(-1);
  return last in m ? Math.round(parseFloat(s) * m[last]) : parseInt(s, 10);
}
export const optList = (list, sel) => list.map((x) => `<option${x === sel ? " selected" : ""}>${esc(x)}</option>`).join("");

// ---- SDN flow table (docs/FLOW_TABLE.md) ----
export function fmtFlowAction(act) {
  if (typeof act === "string") return act;          // ToOverlayOwner / Local / Drop
  const k = Object.keys(act)[0], v = act[k];
  if (k === "ToExit") return v == null ? "→ exit" : `→ exit node ${v}`;
  if (k === "ToPeer") return `→ peer ${v}`;
  return `${k}(${v})`;
}
export function fmtFlowMatch(m) {
  const p = [];
  if (m.scope != null) p.push(m.scope.toLowerCase());
  if (m.dst_cidr != null) p.push(`dst ${m.dst_cidr[0]}/${m.dst_cidr[1]}`);
  if (m.proto != null) p.push({ 1: "icmp", 6: "tcp", 17: "udp" }[m.proto] || `proto ${esc(m.proto)}`);
  if (m.dport != null) p.push(`dport ${m.dport}`);
  return p.length ? p.join(", ") : "any";
}
export function parseCidr(s) {
  s = s.trim();
  if (s.includes("/")) { const [n, l] = s.split("/"); return [n, parseInt(l, 10)]; }
  return [s, 32];
}
export function defaultFlowTable() {
  return [
    { priority: 0, match_: { scope: "Overlay", dst_cidr: null, proto: null, dport: null }, action: "ToOverlayOwner" },
    { priority: 0, match_: { scope: "Internet", dst_cidr: null, proto: null, dport: null }, action: { ToExit: null } },
  ];
}

// ---- egress mode (docs/SPLIT_TUNNEL.md) — the ONE derivation ----
// The split proxy selects its own mesh (SplitList.active_mesh); a full tunnel sets
// is_current WITHOUT split. So for a mesh: split-active → "split", else
// is_current → "full", else "off". This used to be hand-rolled (with two different
// spellings) at four call sites — derive it here only.
export function egressModeOf(meshId, isCurrent, splitActiveMesh) {
  if (splitActiveMesh != null && splitActiveMesh === meshId) return "split";
  return isCurrent ? "full" : "off";
}
export const EGRESS_LABEL = { off: "Off", split: "Split", full: "Full" };
