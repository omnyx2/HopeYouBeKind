// Lattice GUI (v2) — talks ONLY to meshd via the `meshd` proxy command.
// Two view modes (widget-bar toggle): User (manage the set of meshes) and Mesh
// (operate one mesh). See docs/GUI.md and docs/GUI_PAGES.md.

const invoke = window.__TAURI__?.invoke ?? mockInvoke;
if (!window.__TAURI__) console.warn("Lattice: Tauri API not found — meshd unreachable (browser demo).");

const el = (id) => document.getElementById(id);

// ---- helpers ----
function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
function randHex64() {
  let s = "";
  for (let i = 0; i < 64; i++) s += "0123456789abcdef"[Math.floor(Math.random() * 16)];
  return s;
}
let toastTimer;
function toast(msg) {
  const t = el("toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add("hidden"), 2600);
}

// ---- join-flow codes (§2b): base64(JSON) so each is one copy-pasteable string ----
function b64encode(obj) { return btoa(unescape(encodeURIComponent(JSON.stringify(obj)))); }
function b64decode(s) { try { return JSON.parse(decodeURIComponent(escape(atob((s || "").trim())))); } catch { return null; } }
function encodeIdentity(id) { return b64encode({ m: id.member_pubkey_hex, e: id.enc_pubkey_hex, t: id.issued_at || 0 }); }
function decodeIdentity(code) {
  const o = b64decode(code);
  if (!o) return null;
  // Accept BOTH the GUI short form {m,e,t} AND the CLI/daemon form
  // {member_pubkey_hex, enc_pubkey_hex, issued_at} so CLI ↔ GUI invites interoperate.
  const m = o.m || o.member_pubkey_hex, e = o.e || o.enc_pubkey_hex, t = o.t ?? o.issued_at ?? 0;
  return m && e ? { m, e, t } : null;
}
function encodeInvite(w) { return b64encode(w); }
// P-C6: the invite is now a WrappedInvite {salt, n, ct}.
function decodeInvite(code) { const o = b64decode(code); return o && o.ct != null && o.salt != null ? o : null; }

// ---- meshd bridge (the only daemon channel) ----
async function meshd(req) {
  const s = await invoke("meshd", { request: JSON.stringify(req) });
  let r;
  try { r = JSON.parse(s); } catch { throw new Error("bad meshd response"); }
  if (r && r.Error) throw new Error(r.Error.message);
  return r;
}

// ---- view mode (§1 toggle) ----
let MODE = "user";        // "user" | "mesh"
let CURRENT_MESH = null;  // the mesh Mesh-mode operates on (set via `manage ›`)
let ACTIVE_TAB = null;    // current panel, so the live poll re-renders the right one

function activateTab(name) {
  ACTIVE_TAB = name;
  document.querySelectorAll(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("hidden", p.dataset.panel !== name));
}

async function setMode(mode) {
  // No auto-picking a mesh: Mesh mode shows whatever mesh is current (set via the
  // egress dropdown / `manage ›`), or a plain page when on the default network.
  MODE = mode;
  document.body.classList.toggle("mode-mesh", mode === "mesh");
  document.body.classList.toggle("mode-user", mode === "user");
  document.querySelectorAll("#mode-toggle .seg-btn").forEach((b) => b.classList.toggle("active", b.dataset.mode === mode));
  activateTab(mode === "mesh" ? "mesh-overview" : "meshes");
  await refreshMode();
}

async function refreshMode() {
  if (MODE === "mesh") {
    if (CURRENT_MESH != null) await renderOverview(CURRENT_MESH);
    else renderMeshPlain();
  } else {
    await renderMeshes();
  }
  refreshTopbar();
}

// Mesh mode with no mesh selected (you're on the default network) — a plain page.
function renderMeshPlain() {
  el("mesh-detail").innerHTML = `<div class="empty" style="padding:48px 24px;text-align:center">
      On the default network — no mesh selected.
      <div class="muted small" style="margin-top:8px">Pick a mesh as egress above, or open one from the Meshes page.</div>
    </div>`;
}

// ---- Mesh mode: Topology page (§4 — static graph from MeshInfo) ----
async function renderTopologyFor(id) {
  let d;
  try { d = (await meshd({ MeshInfo: { mesh: id } })).Mesh; }
  catch (e) { toast(String(e)); return; }
  renderTopology(d);
}

// Distinct colours for network groups (regions). Cycles if there are more groups.
const NET_PALETTE = ["#22c55e", "#a78bfa", "#f59e0b", "#38bdf8", "#f472b6", "#34d399", "#fb7185", "#c084fc", "#facc15"];

// RFC1918 / link-local — a private address means we learned it over the LAN multicast
// beacon, which only crosses the *same* local network. So any peer reachable at a private
// address is on MY LAN (regardless of its exact host octet / subnet within that LAN).
function isPrivateIp(ip) {
  return /^10\./.test(ip) || /^192\.168\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) || /^169\.254\./.test(ip);
}
// The network a member sits in. `me` and any peer reachable at a private address are on
// my local network → one "LAN" group. A peer at a public address is remote, grouped by
// its public IP (same NAT = same group).
function netKeyOf(m) {
  if (!m.endpoint) return m.is_me ? "LAN" : null; // me w/o a learned addr ⇒ assume local
  const ip = m.endpoint.replace(/:\d+$/, "").replace(/[[\]]/g, "");
  return isPrivateIp(ip) ? "LAN" : ip;            // private ⇒ same LAN as me; else by NAT IP
}
// Human label for a network group. A future GeoIP layer can map a public IP → country/org.
function netLabel(key) {
  if (key === "LAN") return "local network (LAN)";
  return key || "network unknown";
}
function hexA(hex, a) {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`;
}

function renderTopology(d) {
  const c = el("topo-canvas");
  if (!c) return;
  const g = c.getContext("2d");
  const W = (c.width = c.clientWidth || 600);
  const H = (c.height = 360);
  g.clearRect(0, 0, W, H);
  const cx = W / 2, cy = H / 2;
  const members = d.members.slice();
  const me = members.find((m) => m.is_me);

  // --- group ALL members (me included) by network: my LAN vs each remote NAT ---
  // If any peer is reachable at a private address, I'm on that same LAN (the beacon is
  // LAN-scoped), so put me in the LAN group too — even though my *own* endpoint is the
  // public reflexive address (learned via STUN), which would otherwise split me off.
  const onSharedLan = members.some((m) => !m.is_me && netKeyOf(m) === "LAN");
  const groups = [];
  const byKey = new Map();
  for (const m of members) {
    const k = m.is_me && onSharedLan ? "LAN" : netKeyOf(m);
    let grp = byKey.get(k);
    if (!grp) { grp = { key: k, label: netLabel(k), members: [] }; byKey.set(k, grp); groups.push(grp); }
    grp.members.push(m);
  }
  groups.forEach((grp, gi) => (grp.color = NET_PALETTE[gi % NET_PALETTE.length]));

  // --- cluster layout: each network is its OWN cluster placed around the canvas, with
  // its nodes packed together — so groups read as communities in a graph, not pie slices ---
  const pos = {};
  const GC = groups.length;
  const Rx = Math.max(70, W / 2 - 155), Ry = Math.max(54, H / 2 - 90);
  groups.forEach((grp, gi) => {
    if (GC === 1) { grp.cx = cx; grp.cy = cy; }
    else {
      const a = (gi / GC) * Math.PI * 2; // 0 = right → spread around, using the width
      grp.cx = cx + Rx * Math.cos(a);
      grp.cy = cy + Ry * Math.sin(a);
    }
    const k = grp.members.length;
    // spread wide enough that the name + address sublabels below each node don't collide
    grp.rr = k === 1 ? 0 : Math.max(62, 30 + k * 18);
    grp.members.forEach((m, j) => {
      const a = (j / Math.max(1, k)) * Math.PI * 2 - Math.PI / 2;
      pos[m.id] = { x: grp.cx + grp.rr * Math.cos(a), y: grp.cy + grp.rr * Math.sin(a) };
    });
  });

  // --- soft organic "blob" per network: overlapping radial gradients merge into a region ---
  for (const grp of groups) {
    for (const m of grp.members) {
      const p = pos[m.id];
      const rad = 52;
      const grad = g.createRadialGradient(p.x, p.y, 6, p.x, p.y, rad);
      grad.addColorStop(0, hexA(grp.color, 0.22));
      grad.addColorStop(1, hexA(grp.color, 0));
      g.fillStyle = grad;
      g.beginPath(); g.arc(p.x, p.y, rad, 0, 7); g.fill();
    }
    // network label above the cluster (clamped on-canvas)
    g.fillStyle = grp.color; g.font = "11px ui-monospace, monospace"; g.textAlign = "center";
    g.fillText(grp.label, grp.cx, Math.max(13, grp.cy - grp.rr - 20));
  }

  // --- edges: me → each other member (graph links); exit violet, live green, rest faint ---
  if (me) {
    const mp = pos[me.id];
    for (const m of members) {
      if (m.is_me) continue;
      const p = pos[m.id];
      const isExit = d.exit === m.id;
      const live = m.state === "live";
      g.setLineDash(live || isExit ? [] : [4, 4]);
      g.strokeStyle = isExit ? "#a78bfa" : live ? "rgba(34,197,94,.5)" : "rgba(148,163,184,.22)";
      g.lineWidth = isExit ? 2.5 : live ? 2 : 1;
      g.beginPath(); g.moveTo(mp.x, mp.y); g.lineTo(p.x, p.y); g.stroke();
    }
  }
  g.setLineDash([]);

  const node = (x, y, label, sub, fill, r, ring) => {
    if (ring) { g.beginPath(); g.arc(x, y, r + 3, 0, 7); g.strokeStyle = ring; g.lineWidth = 2; g.stroke(); }
    g.beginPath(); g.arc(x, y, r, 0, 7);
    g.fillStyle = fill; g.fill();
    g.textAlign = "center";
    g.fillStyle = "#e2e8f0"; g.font = "11px ui-monospace, monospace";
    g.fillText(label, x, y + r + 14);
    // current endpoint under the name — so a live address change is visible immediately.
    if (sub) { g.fillStyle = "#64748b"; g.font = "9px ui-monospace, monospace"; g.fillText(sub, x, y + r + 26); }
  };
  // nodes: me blue, exit violet, live green, else slate; each ringed by its network colour.
  for (const grp of groups) for (const m of grp.members) {
    const fill = m.is_me ? "#3b82f6" : d.exit === m.id ? "#a78bfa" : m.state === "live" ? "#22c55e" : "#475569";
    node(pos[m.id].x, pos[m.id].y, `${m.name} #${m.id}${m.is_me ? " (me)" : ""}`, m.endpoint || "—", fill, m.is_me ? 14 : 12, grp.color);
  }
}

// ---- Mesh mode: Peers page (§4 — members now, live state later) ----
async function renderPeersFor(id) {
  let d;
  try { d = (await meshd({ MeshInfo: { mesh: id } })).Mesh; }
  catch (e) { toast(String(e)); return; }
  const rows = d.members.map((m) => {
    const role = m.is_me ? "this node" : d.exit === m.id ? "exit" : "member";
    const st = m.state || "unknown";
    const badge = `<span class="state-badge state-${st}">${st}</span>`;
    const ep = m.endpoint ? `<span class="muted small mono"> ${esc(m.endpoint)}</span>` : "";
    // Unreachable peer (not me, not live / no endpoint) → offer an inline "set address" right
    // where the problem shows. A node behind NAT can't auto-find a public peer unless its DHT
    // was bootstrapped at launch; pointing it once lets reflexion + gossip take over. Same
    // SetPeer the CLI uses; also on the Overview "Peer address" card.
    const needsAddr = !m.is_me && (st !== "live" || !m.endpoint);
    const action = needsAddr
      ? `<div class="add-row" style="margin-top:6px"><input class="peer-ep-in" data-m="${m.id}" placeholder="the peer's ip:port" style="font-size:12px;flex:1" /><button class="small-btn peer-ep-set" data-m="${m.id}">set address</button></div>`
      : "";
    // Expel (kick) a member — shown unless the mesh forbids it (expel policy = none).
    const canExpel = !m.is_me && d.expel && d.expel !== "none";
    const expelBtn = canExpel
      ? ` <button class="small-btn peer-expel" data-m="${m.id}" data-name="${esc(m.name)}">expel</button>`
      : "";
    // The daemon explains a non-live peer (idle/unknown) in `reason` — show it verbatim.
    const why = m.reason ? `<div class="muted small" style="margin-top:4px">↳ ${esc(m.reason)}</div>` : "";
    // The overlay IP is the stable address you reach this member at over the tunnel
    // (e.g. ssh user@100.80.1.1) — far more useful day-to-day than the physical endpoint.
    const ov = m.overlay_ip ? `<span class="mono small">${esc(m.overlay_ip)}</span>` : "";
    return `<tr><td>${m.id}</td><td>${esc(m.name)}${m.is_me ? ' <span class="muted small">(me)</span>' : ""}</td>` +
      `<td>${ov}</td><td class="mono small">${m.pubkey_fp}</td><td>${role}</td><td>${badge}${ep}${why}${action}${expelBtn}</td></tr>`;
  }).join("");
  const tbl = el("peers-table");
  tbl.querySelector("tbody").innerHTML = rows;
  // Wire the inline set-address buttons (reach a peer that discovery hasn't found yet).
  tbl.querySelectorAll(".peer-ep-set").forEach((btn) => {
    btn.onclick = async () => {
      const m = parseInt(btn.dataset.m, 10);
      const inp = tbl.querySelector(`.peer-ep-in[data-m="${m}"]`);
      const ep = (inp?.value || "").trim();
      if (!ep || !/^.+:\d+$/.test(ep)) return toast("enter ip:port");
      try { await meshd({ SetPeer: { mesh: id, member: m, endpoint: ep } }); toast("peer address set — connecting…"); }
      catch (e) { return toast(String(e)); }
      setTimeout(() => renderPeersFor(id), 1500);
    };
  });
  // Invite a member now lives here on the Peers tab (moved from Configs). Only (re)build
  // it when the mesh actually changes — this panel is re-rendered every few seconds by the
  // live poll, and rebuilding the card each time would wipe whatever the user is typing
  // into the name / join-code fields mid-entry. Rebuilding on mesh-switch re-wires the
  // handlers to the new id; same-mesh polls leave the inputs (and their values) untouched.
  const extra = el("peers-extra");
  if (extra && extra.dataset.inviteMesh !== String(id)) {
    extra.innerHTML = inviteCardHtml();
    wireInviteCard(id);
    extra.dataset.inviteMesh = String(id);
  }
  // Wire the expel buttons (revoke a member per the mesh's expel policy).
  tbl.querySelectorAll(".peer-expel").forEach((btn) => {
    btn.onclick = async () => {
      const mid = parseInt(btn.dataset.m, 10);
      if (!confirm(`Expel "${btn.dataset.name}" (#${mid}) from this mesh?`)) return;
      try { const r = await meshd({ ExpelMember: { mesh: id, member: mid } }); toast(r.Info?.message || "expel sent"); }
      catch (e) { return toast(String(e)); }
      setTimeout(() => renderPeersFor(id), 1200);
    };
  });
}

// ---- Traffic monitor (user = this whole computer / mesh = one mesh) ----
// A = per-peer bytes/packets summary; press "Detail ▸" → B = recent packet flows.
let TRAFFIC_DETAIL = { user: false, mesh: false };
const TRAFFIC_LAST = {}; // scope:mesh → {at, rx, tx} for throughput between polls
function fmtBytes(n) {
  const u = ["B", "KB", "MB", "GB"]; let i = 0;
  while (n >= 1024 && i < 3) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : n.toFixed(0)) + u[i];
}
async function renderTraffic(scope) {
  const body = el(scope === "user" ? "user-traffic-body" : "mesh-traffic-body");
  if (!body) return;
  const meshArg = scope === "mesh" ? CURRENT_MESH : null;
  if (scope === "mesh" && meshArg == null) return;
  let t;
  try { t = (await meshd({ TrafficStats: { mesh: meshArg } })).Traffic; }
  catch (e) { body.innerHTML = `<div class="card"><p class="muted">traffic unavailable — ${esc(String(e))}</p></div>`; return; }
  const key = scope + ":" + (meshArg ?? "all");
  const now = Date.now(); const prev = TRAFFIC_LAST[key];
  let dn = "", up = "";
  if (prev && now > prev.at) {
    const dt = (now - prev.at) / 1000;
    dn = " · " + fmtBytes(Math.max(0, (t.rx_bytes - prev.rx) / dt)) + "/s";
    up = " · " + fmtBytes(Math.max(0, (t.tx_bytes - prev.tx) / dt)) + "/s";
  }
  TRAFFIC_LAST[key] = { at: now, rx: t.rx_bytes, tx: t.tx_bytes };
  const detail = TRAFFIC_DETAIL[scope];
  let html = `<div class="card">
    <div class="kv"><span>download</span><b>↓ ${fmtBytes(t.rx_bytes)} · ${t.rx_pkts} pkts<span class="muted">${dn}</span></b></div>
    <div class="kv"><span>upload</span><b>↑ ${fmtBytes(t.tx_bytes)} · ${t.tx_pkts} pkts<span class="muted">${up}</span></b></div>
    <div class="add-row" style="margin-top:8px"><button class="small-btn" id="${scope}-traffic-toggle">${detail ? "◂ Summary" : "Detail ▸"}</button></div>
  </div>`;
  if (!detail) {
    const rows = t.peers.map((p) =>
      `<tr>${meshArg == null ? `<td class="muted small">${esc(p.mesh_name)}</td>` : ""}` +
      `<td>${esc(p.name)} <span class="muted small">#${p.id}</span></td>` +
      `<td>↓ ${fmtBytes(p.rx_bytes)} / ${p.rx_pkts}</td><td>↑ ${fmtBytes(p.tx_bytes)} / ${p.tx_pkts}</td></tr>`
    ).join("") || `<tr><td colspan="4" class="muted">no traffic yet — send something over the mesh (e.g. ping a peer's 100.80.x.y)</td></tr>`;
    html += `<div class="card"><table class="topo-table"><thead><tr>${meshArg == null ? "<th>mesh</th>" : ""}<th>peer</th><th>down</th><th>up</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  } else {
    const rows = t.recent.map((f) => {
      const arrow = f.out ? '<span style="color:#e0a020">↑ out</span>' : '<span style="color:#22c55e">↓ in</span>';
      const port = (f.sport || f.dport) ? `:${f.sport}→${f.dport}` : "";
      const ex = f.via_exit ? ' <span class="muted small">via exit</span>' : "";
      const req = f.src_node || f.member_name; // the node that made the request
      const sn = f.src_node ? `${esc(f.src_node)} ` : "";
      const dn = f.dst_node ? `${esc(f.dst_node)} ` : "";
      return `<tr><td>${arrow}</td><td><b>${esc(req)}</b></td><td class="mono small">${esc(f.proto)}</td>` +
        `<td class="mono small">${sn}${esc(f.src)}→${dn}${esc(f.dst)}${port}</td><td>${f.bytes}B</td>` +
        `<td class="muted small">${meshArg == null ? esc(f.mesh_name) : ""}${ex}</td></tr>`;
    }).join("") || `<tr><td colspan="6" class="muted">no packet flows recorded yet</td></tr>`;
    html += `<div class="card"><table class="topo-table"><thead><tr><th>dir</th><th>requester</th><th>proto</th><th>src→dst</th><th>bytes</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }
  body.innerHTML = html;
  el(`${scope}-traffic-toggle`).onclick = () => { TRAFFIC_DETAIL[scope] = !TRAFFIC_DETAIL[scope]; renderTraffic(scope); };
}

// ---- Extensions / connectors (docs/EXTENSIONS.md) ----
// What each grantable scope means + its risk, so the enable UI is honest about exposure.
const SCOPE_INFO = {
  "events:peer":        { label: "Mesh & member changes",            risk: "low" },
  "events:exit":        { label: "Exit / full-tunnel status",        risk: "low" },
  "events:health":      { label: "Health & attack warnings",         risk: "low" },
  "registry:read":      { label: "Discover advertised services",     risk: "low" },
  "registry:advertise": { label: "Advertise a service on this node", risk: "low" },
  "command:exit":       { label: "Change egress/exit programmatically", risk: "high" },
  "command:flows":      { label: "Edit routing (flow) rules",        risk: "high" },
  "data:packet-meta":   { label: "Per-flow metadata (no payload)",   risk: "med" },
  "data:packet-raw":    { label: "Raw packet payloads",              risk: "high" },
};
// Bundled connectors the GUI knows how to enable. meshd has no catalog of its own — a
// connector only exists once enabled — so the requested scopes live here.
const CONNECTOR_CATALOG = [
  { id: "minisync", name: "MiniSync — folder sync",
    desc: "Keep a folder in sync across mesh members, peer-to-peer over the overlay.",
    scopes: ["events:peer", "registry:read", "registry:advertise"] },
];
const riskTag = (r) => r === "high"
  ? '<span class="pill warn" style="font-size:10px">high risk</span>'
  : r === "med" ? '<span class="pill warn" style="font-size:10px">caution</span>' : "";
const scopeChip = (s) => {
  const info = SCOPE_INFO[s] || { risk: "low" };
  const cls = info.risk === "low" ? "off" : "warn";
  return `<span class="pill ${cls}" title="${esc(info.label || s)}">${esc(s)}</span>`;
};
const metaShort = (meta) => {
  if (!meta || typeof meta !== "object") return "";
  try { return Object.entries(meta).map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : v}`).join(", "); }
  catch { return ""; }
};

function meshScopeChips(g, meshById) {
  if (g.all_meshes) return '<span class="pill on" title="every mesh, incl. future">all meshes</span>';
  if (!g.meshes || !g.meshes.length) return '<span class="pill warn" title="no mesh selected — connector can reach none">no meshes</span>';
  return g.meshes.map((id) => `<span class="pill off">${esc(meshById[id] || "#" + id)}</span>`).join(" ");
}

function extGrantRow(g, meshById) {
  const chips = g.scopes.map(scopeChip).join(" ") || '<span class="muted small">no scopes</span>';
  const tok = esc((g.token || "").slice(0, 8)) + "…";
  const toggle = g.enabled
    ? `<button class="small-btn" data-act="disable" data-id="${esc(g.id)}">Disable</button>`
    : `<button class="small-btn" data-act="enable" data-id="${esc(g.id)}" data-scopes='${esc(JSON.stringify(g.scopes))}' data-allmeshes='${g.all_meshes ? 1 : 0}' data-meshes='${esc(JSON.stringify(g.meshes || []))}'>Enable</button>`;
  return `<div class="ext-row" style="padding:10px 0;border-top:1px solid var(--line)">
    <div style="display:flex;align-items:center;gap:8px">
      <b>${esc(g.id)}</b>
      <span class="pill ${g.enabled ? "on" : "off"}">${g.enabled ? "enabled" : "disabled"}</span>
      <span style="margin-left:auto">${toggle}</span>
    </div>
    <div style="margin-top:6px">${chips}</div>
    <div class="kv" style="margin-top:6px"><span>meshes</span><span>${meshScopeChips(g, meshById)}</span></div>
    <div class="kv" style="margin-top:4px"><span>token</span>
      <span><code>${tok}</code>
        <button class="small-btn" data-act="copytoken" data-token="${esc(g.token || "")}">copy</button></span></div>
  </div>`;
}

function extCatalogCard(c, meshes) {
  const checks = c.scopes.map((s) => {
    const info = SCOPE_INFO[s] || { label: s, risk: "low" };
    return `<label class="toggle-row" style="margin:2px 0">
      <input type="checkbox" data-scope="${esc(s)}" checked />
      <span><code>${esc(s)}</code> — ${esc(info.label)} ${riskTag(info.risk)}</span></label>`;
  }).join("");
  // Per-mesh allow-list — the connector can ONLY touch the meshes ticked here. Default to
  // nothing ticked so enabling never silently exposes every mesh; pre-tick when there's
  // exactly one mesh (the unambiguous case).
  const one = meshes.length === 1;
  const meshChecks = meshes.length
    ? meshes.map((m) => `<label class="toggle-row" style="margin:2px 0">
        <input type="checkbox" data-mesh="${m.id}" ${one ? "checked" : ""} />
        <span>${esc(m.name)} <span class="muted small">#${m.id}</span></span></label>`).join("")
    : `<div class="muted small">No meshes yet — tick “All meshes”, or create/join one first.</div>`;
  return `<div class="ext-cat" data-conn="${esc(c.id)}" style="padding:10px 0;border-top:1px solid var(--line)">
    <div><b>${esc(c.name)}</b> <span class="muted small">(${esc(c.id)})</span></div>
    <p class="muted small" style="margin:4px 0">${esc(c.desc)}</p>
    <div class="muted small" style="margin-top:6px">What it may see:</div>
    <div>${checks}</div>
    <div class="muted small" style="margin-top:6px">Which meshes it may use:</div>
    <label class="toggle-row" style="margin:2px 0">
      <input type="checkbox" data-allmeshes />
      <span><b>All meshes</b> <span class="muted small">(incl. any joined later)</span></span></label>
    <div data-meshpicks>${meshChecks}</div>
    <div class="add-row" style="margin-top:6px">
      <button class="small-btn" data-act="enableconn" data-id="${esc(c.id)}">Enable</button>
    </div>
  </div>`;
}

async function onExtAction(e) {
  const b = e.currentTarget;
  try {
    switch (b.dataset.act) {
      case "copytoken":
        await navigator.clipboard.writeText(b.dataset.token || "");
        return toast("token copied — paste it into the connector");
      case "disable":
        await meshd({ DisableExtension: { id: b.dataset.id } });
        toast("disabled");
        return renderExtensions();
      case "enable":
        await meshd({ EnableExtension: {
          id: b.dataset.id,
          scopes: JSON.parse(b.dataset.scopes || "[]"),
          all_meshes: b.dataset.allmeshes === "1",
          meshes: JSON.parse(b.dataset.meshes || "[]"),
        } });
        toast("re-enabled");
        return renderExtensions();
      case "enableconn": {
        const card = b.closest(".ext-cat");
        const scopes = [...card.querySelectorAll("input[data-scope]:checked")].map((c) => c.dataset.scope);
        if (!scopes.length) return toast("pick at least one scope");
        const all_meshes = !!card.querySelector("input[data-allmeshes]:checked");
        const meshes = all_meshes ? [] : [...card.querySelectorAll("input[data-mesh]:checked")].map((c) => parseInt(c.dataset.mesh, 10));
        if (!all_meshes && !meshes.length) return toast("pick at least one mesh (or “All meshes”)");
        await meshd({ EnableExtension: { id: b.dataset.id, scopes, all_meshes, meshes } });
        toast("enabled — copy the token from the list above");
        return renderExtensions();
      }
    }
  } catch (err) { toast(String(err)); }
}

async function renderExtensions() {
  const body = el("ext-body");
  let grants = [];
  try { grants = (await meshd("ListExtensions")).Extensions || []; }
  catch (e) { body.innerHTML = `<div class="card"><div class="empty">meshd unreachable — ${esc(String(e))}</div></div>`; return; }
  let meshes = [];
  try { meshes = (await meshd("ListMeshes")).Meshes || []; } catch { /* show with no names */ }
  const meshById = Object.fromEntries(meshes.map((m) => [m.id, m.name]));
  const byId = Object.fromEntries(grants.map((g) => [g.id, g]));
  const grantsHtml = grants.length
    ? grants.map((g) => extGrantRow(g, meshById)).join("")
    : `<div class="muted small">No extensions enabled yet — enable one below.</div>`;
  const avail = CONNECTOR_CATALOG.filter((c) => !byId[c.id]);
  const availHtml = avail.length
    ? avail.map((c) => extCatalogCard(c, meshes)).join("")
    : `<div class="muted small">All bundled connectors are enabled.</div>`;
  body.innerHTML = `
    <div class="card">
      <div class="card-head"><h2 class="card-title">Enabled extensions</h2></div>
      <div id="ext-grants">${grantsHtml}</div>
    </div>
    <div class="card">
      <div class="card-head"><h2 class="card-title">Available connectors</h2></div>
      <p class="muted small">Pick what a connector may see, then enable it. It gets a
        <b>token</b> — give that to the connector so it can authenticate.</p>
      <div id="ext-catalog">${availHtml}</div>
    </div>
    <div class="card">
      <div class="card-head"><h2 class="card-title">Discovered services
        <span class="muted small">(advertised on the mesh)</span></h2></div>
      <div id="ext-services" class="muted small">loading…</div>
    </div>`;
  body.querySelectorAll("[data-act]").forEach((b) => b.addEventListener("click", onExtAction));
  renderExtServices();
}

// Aggregate advertised services across every mesh on this computer. Refreshed on the live
// poll; only touches its own card, so the enable checkboxes above are never disturbed.
async function renderExtServices() {
  const box = el("ext-services");
  if (!box) return;
  let meshes = [];
  try { meshes = (await meshd("ListMeshes")).Meshes || []; }
  catch { box.innerHTML = `<span class="muted small">meshd unreachable</span>`; return; }
  const rows = [];
  for (const m of meshes) {
    try {
      const svcs = (await meshd({ ListServices: { mesh: m.id } })).Services || [];
      for (const s of svcs) rows.push({ mesh: m, s });
    } catch { /* skip a mesh that errored */ }
  }
  if (!rows.length) {
    box.innerHTML = `<span class="muted small">No services advertised yet. A connector with
      <code>registry:advertise</code> publishes them here.</span>`;
    return;
  }
  box.innerHTML = `<table class="topo-table"><thead><tr>
      <th>mesh</th><th>service</th><th>owner</th><th>overlay address</th><th>state</th><th>info</th>
    </tr></thead><tbody>${rows.map(({ mesh, s }) => `<tr>
      <td>${esc(mesh.name)}</td>
      <td><b>${esc(s.proto)}</b>${s.name ? ` <span class="muted small">${esc(s.name)}</span>` : ""}</td>
      <td>${esc(s.member_name || "#" + s.member)}</td>
      <td><code>${esc(s.overlay_ip)}:${s.port}</code></td>
      <td><i class="tdot ${s.online ? "live" : "peer"}"></i> ${s.online ? "online" : "offline"}</td>
      <td class="small">${esc(metaShort(s.meta))}</td>
    </tr>`).join("")}</tbody></table>`;
}

document.querySelectorAll(".nav-item").forEach((b) =>
  b.addEventListener("click", () => {
    const tab = b.dataset.tab;
    if (tab === "meshes") return setMode("user");
    if (tab === "create-mesh") { populateCiphers(); return activateTab("create-mesh"); }
    if (tab === "join-mesh") { return activateTab("join-mesh"); }
    if (tab === "traffic") { activateTab("traffic"); return renderTraffic("user"); }
    if (tab === "extensions") { activateTab("extensions"); return renderExtensions(); }
    activateTab(tab);
    if (tab === "mesh-overview") return CURRENT_MESH != null ? renderOverview(CURRENT_MESH) : renderMeshPlain();
    if (CURRENT_MESH == null) return;
    if (tab === "mesh-topology") renderTopologyFor(CURRENT_MESH);
    if (tab === "mesh-traffic") renderTraffic("mesh");
    if (tab === "mesh-peers") renderPeersFor(CURRENT_MESH);
    if (tab === "mesh-configs") renderConfigs(CURRENT_MESH);
    if (tab === "mesh-warnings") renderWarnings(CURRENT_MESH);
  })
);

// "＋ New mesh" button on the Meshes list → the New mesh page.
el("goto-new-mesh")?.addEventListener("click", () => { populateCiphers(); activateTab("create-mesh"); });

// ---- New mesh page: join flow (§2b) ----
el("join-getcode")?.addEventListener("click", async () => {
  try {
    const r = await meshd("NewIdentity");
    el("join-code").value = encodeIdentity(r.Identity);
    el("join-code-box").classList.remove("hidden");
    toast("join code ready — copy + send it to the mesh owner");
  } catch (e) { toast(String(e)); }
});
el("join-code-copy")?.addEventListener("click", () => {
  navigator.clipboard.writeText(el("join-code").value); toast("copied");
});
el("join-do")?.addEventListener("click", async () => {
  const blob = decodeInvite(el("join-invite").value);
  if (!blob) return toast("invalid invite code");
  try {
    const r = await meshd({ JoinMesh: { invite: blob, algo: el("join-algo")?.value || null } });
    el("join-invite").value = "";
    toast(`joined mesh #${r.MeshCreated.mesh}`);
    CURRENT_MESH = r.MeshCreated.mesh;
    return setMode("mesh");
  } catch (e) { toast(String(e)); }
});

// ---- User mode: Meshes page (§2) ----
async function renderMeshes() {
  let meshes = [];
  try { meshes = (await meshd("ListMeshes")).Meshes || []; }
  catch {
    el("mesh-list").innerHTML = `<li class="empty">meshd not reachable — start it: <code>./target/debug/meshd</code></li>`;
    return;
  }
  const noEgress = !meshes.some((m) => m.is_current);
  const originRow = `<li>
      <div class="peer-left">
        <span class="dot ${noEgress ? "connected" : "known"}"></span>
        <b>Default network</b>
        <span class="muted small">${noEgress ? "in use — your normal internet, no mesh" : "your normal internet, no mesh"}</span>
        ${noEgress ? `<span class="pill on">in use</span>` : ""}
      </div>
      <div><button class="small-btn" data-origin ${noEgress ? "disabled" : ""}>use this</button></div>
    </li>`;
  const rows = meshes.length ? meshes.map((m) => {
    const egress = m.is_current ? `<span class="pill on">egress</span>` : "";
    const exit = m.exit != null ? `exit #${m.exit}` : "no exit";
    return `<li>
      <div class="peer-left">
        <span class="dot ${m.is_current ? "connected" : "known"}"></span>
        <b>${esc(m.name)}</b>
        <span class="muted small">#${m.id} · ${m.members} members · epoch ${m.epoch} · ${exit}</span>
        ${egress}
      </div>
      <div>
        <button class="small-btn" data-manage="${m.id}">manage ›</button>
        <button class="small-btn" data-egress="${m.id}">make egress</button>
      </div>
    </li>`;
  }).join("") : `<li class="empty">no meshes yet — create one above</li>`;
  el("mesh-list").innerHTML = originRow + rows;
}

el("mesh-list").addEventListener("click", async (e) => {
  const origin = e.target.closest("[data-origin]");
  const manage = e.target.closest("[data-manage]");
  const egress = e.target.closest("[data-egress]");
  if (origin) {
    try { await meshd({ SetCurrent: { mesh: null } }); toast("Using default network"); }
    catch (x) { toast(String(x)); }
    CURRENT_MESH = null;
    return refreshMode();
  }
  if (manage) { CURRENT_MESH = parseInt(manage.dataset.manage, 10); return setMode("mesh"); }
  if (egress) {
    const id = parseInt(egress.dataset.egress, 10);
    try { await meshd({ SetCurrent: { mesh: id } }); toast("egress set"); }
    catch (x) { toast(String(x)); }
    CURRENT_MESH = id;
    return refreshMode();
  }
});

el("mesh-create").addEventListener("click", async () => {
  const name = el("mesh-name").value.trim();
  const myName = el("mesh-myname").value.trim() || "me";
  const maxRaw = el("mesh-max").value.trim();
  const max = maxRaw === "" ? 254 : parseInt(maxRaw, 10);
  if (!name) return toast("mesh name required");
  if (Number.isNaN(max) || max < 1 || max > 254) return toast("max must be 1–254");
  const cipher = el("mesh-cipher").value || null;
  const selfDestruct = el("mesh-selfdestruct").checked;
  const masterGated = el("mesh-mastergated").checked;
  const expel = el("mesh-expel")?.value || null;
  const header = el("mesh-header")?.value || null;
  const exitPolicy = el("mesh-exit-policy")?.value || null;
  try {
    const r = await meshd({ CreateMesh: { name, my_name: myName, max_members: max, cipher, self_destruct: selfDestruct, master_gated: masterGated, expel, header, exit_policy: exitPolicy } });
    el("mesh-name").value = "";
    el("mesh-myname").value = "";
    toast(`mesh created (#${r.MeshCreated.mesh})`);
    CURRENT_MESH = r.MeshCreated.mesh;
    return setMode("mesh");
  } catch (e) { toast(String(e)); }
  refreshMode();
});

// ---- Mesh mode: Overview page (§3) ----
async function renderOverview(id) {
  let d;
  try { d = (await meshd({ MeshInfo: { mesh: id } })).Mesh; }
  catch (e) { toast(String(e)); return setMode("user"); }
  const rows = d.members.map((mb) =>
    `<tr><td>${mb.id}</td><td>${esc(mb.name)}${mb.is_me ? ' <span class="muted small">(me)</span>' : ""}</td><td class="mono small">${mb.pubkey_fp}</td></tr>`
  ).join("");
  const warn = meshWarnings(d);
  el("mesh-detail").innerHTML = `
    <div class="card-head">
      <h2 class="card-title">⬢ ${esc(d.name)} <span class="muted small">#${d.id}</span></h2>
      <div><button class="small-btn" id="ov-egress">make egress</button></div>
    </div>
    ${warn.length ? `<div class="kv"><span>warnings</span><b><a href="#" id="ov-goto-warn" style="color:#ff6477">⚠ ${warn.length} active — open Warnings</a></b></div>` : ""}
    <div class="kv"><span>charter</span><b class="small">${d.invite} · ${esc(d.trigger)} · max ${d.max_members} · ${d.self_destruct ? "ephemeral (self-destruct)" : "persistent"}</b></div>
    <div class="kv"><span>network</span><b class="mono small">${esc(d.network_fp || "?")}</b></div>
    <div class="kv"><span>expel</span><b class="small">${esc(d.expel || "?")}</b></div>
    <div class="kv"><span>header (P-C5)</span><b class="small">${esc(d.header_placement || "?")}</b></div>
    <div class="kv"><span>exit policy</span><b class="small">${esc(d.exit_policy || "?")}</b></div>
    <div class="kv"><span>cipher</span><b class="mono small">${esc(d.cipher)}</b></div>
    <div class="kv"><span>epoch</span><b>${d.epoch}</b></div>
    <div class="kv"><span>health</span><b>${d.live}/${d.members.length} live · floor ${d.threshold}${d.attack_armed_secs_left != null ? ` · <span style="color:#e44">⚠ ARMED ${d.attack_armed_secs_left}s</span>` : ""}</b></div>
    ${d.dp_error ? `<div class="kv"><span>data plane</span><b style="color:#ff6477">⛔ DOWN — ${esc(d.dp_error)}</b></div>` : ""}
    <div class="kv"><span>my exit</span><b>${d.exit != null ? "#" + d.exit : "none"}</b></div>
    <h3 class="topo-h">Roster <span class="muted small">(${d.members.length})</span></h3>
    <table class="topo-table"><thead><tr><th>id</th><th>name</th><th>pubkey</th></tr></thead><tbody>${rows}</tbody></table>
    <p class="muted small" style="margin-top:10px">Manage exit, peers, invites and key rotation in <b>Configs</b>; see alerts in <b>Warnings</b>.</p>`;
  el("ov-egress").onclick = async () => {
    try { await meshd({ SetCurrent: { mesh: id } }); toast("set as egress"); } catch (e) { toast(String(e)); }
    refreshMode();
  };
  el("ov-goto-warn")?.addEventListener("click", (e) => { e.preventDefault(); activateTab("mesh-warnings"); renderWarnings(id); });
}

// ---- Mesh mode: Configs — this mesh's settings + controls ----
// ---- Reusable cards: Invite (lives on Peers) and Danger zone (lives on Warnings) ----
function inviteCardHtml() {
  return `<div class="card">
    <div class="card-head"><h2 class="card-title">Invite a member</h2></div>
    <p class="muted small">Paste the joiner's <b>join code</b> + a name → get an <b>invite code</b> to send back.</p>
    <div class="add-row">
      <input id="ov-inv-name" placeholder="their name in this mesh" />
      <label class="muted small" style="display:flex;align-items:center;gap:6px">algorithm
        <select id="ov-inv-algo" class="select">${optList(INVITE_ALGOS, INVITE_ALGOS[0])}</select>
      </label>
    </div>
    <textarea id="ov-inv-code" class="code" rows="2" placeholder="paste their join code" style="margin-top:8px"></textarea>
    <div class="add-row" style="margin-top:8px"><button class="small-btn" id="ov-invite">create invite</button></div>
    <div id="ov-inv-out" class="hidden" style="margin-top:10px">
      <p class="muted small">Invite code — send it back to them:</p>
      <textarea id="ov-inv-result" class="code" readonly rows="3"></textarea>
      <button class="small-btn" id="ov-inv-copy">Copy</button>
      <p class="small" style="color:#e0a020;margin-top:8px">Tell them the algorithm <b id="ov-inv-algo-out" class="mono"></b> — over a <i>different</i> channel than the code.</p>
    </div>
  </div>`;
}
function wireInviteCard(id) {
  el("ov-invite").onclick = async () => {
    const name = el("ov-inv-name").value.trim();
    const ident = decodeIdentity(el("ov-inv-code").value);
    const algo = el("ov-inv-algo").value || null;
    if (!name) return toast("name required");
    if (!ident) return toast("invalid join code");
    try {
      const r = await meshd({ CreateInvite: { mesh: id, name, member_pubkey_hex: ident.m, enc_pubkey_hex: ident.e, issued_at: ident.t || 0, algo } });
      el("ov-inv-result").value = encodeInvite(r.Invite);
      el("ov-inv-algo-out").textContent = algo || "(default)";
      el("ov-inv-out").classList.remove("hidden");
      toast("invite created — send the code AND the algorithm");
    } catch (e) { toast(String(e)); }
  };
  el("ov-inv-copy").onclick = () => { navigator.clipboard.writeText(el("ov-inv-result").value); toast("copied"); };
}
function dangerCardHtml(d) {
  return `<div class="card">
    <div class="card-head"><h2 class="card-title" style="color:#e44">Danger zone</h2></div>
    <div class="add-row">
      <button class="small-btn" id="ov-report-attack" style="background:#7a1020;color:#fff;border-color:#a33">Report attack</button>
      <button class="small-btn" id="ov-wipe">wipe mesh</button>
    </div>
    <p class="muted small"><b>Report attack</b> alerts every member and self-destructs the mesh in 30s unless ${d.is_creator ? "you" : "the creator"} call(s) it off — keys wiped everywhere. <b>Wipe</b> removes this mesh from this computer only.</p>
  </div>`;
}
function wireDangerCard(id, d) {
  el("ov-report-attack").onclick = async () => {
    const typed = prompt(`⚠ This ALERTS every member and DESTROYS mesh "${d.name}" in 30s unless ${d.is_creator ? "you" : "the creator"} call(s) it off — keys wiped everywhere.\n\nType the mesh name to confirm:`);
    if (typed !== d.name) return toast("cancelled");
    try { await meshd({ ReportAttack: { mesh: id } }); toast("attack reported — mesh armed"); } catch (e) { toast(String(e)); }
    refreshAttackBanner();
  };
  el("ov-wipe").onclick = async () => {
    if (!confirm(`Wipe mesh "${d.name}" locally? (the §5 compromise response)`)) return;
    try { await meshd({ RemoveMesh: { mesh: id } }); toast("mesh wiped"); } catch (e) { toast(String(e)); }
    CURRENT_MESH = null; setMode("user");
  };
}

async function renderConfigs(id) {
  let d;
  try { d = (await meshd({ MeshInfo: { mesh: id } })).Mesh; }
  catch (e) { toast(String(e)); return setMode("user"); }
  const exitOpts = [`<option value="">— none —</option>`].concat(
    d.members.map((mb) => `<option value="${mb.id}" ${d.exit === mb.id ? "selected" : ""}>#${mb.id} ${esc(mb.name)}</option>`)
  ).join("");
  const peerOpts = d.members.filter((mb) => !mb.is_me)
    .map((mb) => `<option value="${mb.id}">#${mb.id} ${esc(mb.name)}</option>`).join("");
  el("mesh-config-body").innerHTML = `
    <div class="card">
      <div class="card-head"><h2 class="card-title">Egress &amp; routing</h2></div>
      <div class="kv"><span>my exit</span><b>${d.exit != null ? "#" + d.exit : "none"}</b></div>
      <div class="add-row">
        <select id="ov-exit" class="select">${exitOpts}</select>
        <button class="small-btn" id="ov-exit-set">set exit</button>
        <button class="small-btn" id="ov-egress">make egress</button>
      </div>
    </div>
    <div class="card">
      <div class="card-head"><h2 class="card-title">Peer address <span class="muted small">(manual)</span></h2></div>
      <p class="muted small">Tell this node where to reach a member — its <code>ip:port</code> (a public node's reachable address). The rest is learned once a peer speaks.</p>
      <div class="add-row">
        <select id="ov-peer-id" class="select">${peerOpts}</select>
        <input id="ov-peer-ep" placeholder="the member's ip:port" />
        <button class="small-btn" id="ov-peer-set">set address</button>
      </div>
    </div>
    <div class="card">
      <div class="card-head"><h2 class="card-title">Security <span class="muted small">(re-cipher — P-C3)</span></h2></div>
      <div class="add-row">
        <select id="ov-recipher-cipher" class="select">${optList(CIPHERS, d.cipher)}</select>
        <button class="small-btn" id="ov-recipher">re-cipher</button>
      </div>
      <p class="muted small">Rotates this mesh's key (and the cipher, if changed). Needs ≥60% of members online; anyone offline now is evicted and must be re-invited.</p>
    </div>
    <div class="card" id="flow-card">
      <div class="card-head"><h2 class="card-title">Routing rules <span class="muted small">(flow table — SDN)</span></h2></div>
      <div id="flow-list" class="muted small">loading…</div>
      <p class="muted small" style="margin-top:8px">First match wins (highest priority, then order). Rules are gossiped to every member — newest version wins.</p>
      <div class="add-row">
        <select id="flow-act" class="select">
          <option value="block">block (drop)</option>
          <option value="exit">route via exit</option>
        </select>
        <input id="flow-cidr" placeholder="destination — e.g. 1.1.1.1 or 10.0.0.0/8" />
        <button class="small-btn" id="flow-add">add rule</button>
        <button class="small-btn" id="flow-reset">reset to default</button>
      </div>
    </div>
    <p class="muted small" style="margin-top:6px">Invite a member is on the <b>Peers</b> tab; Report attack / Wipe are on the <b>Warnings</b> tab.</p>`;
  renderFlows(id);
  el("ov-egress").onclick = async () => { try { await meshd({ SetCurrent: { mesh: id } }); toast("set as egress"); } catch (e) { toast(String(e)); } refreshMode(); };
  el("ov-exit-set").onclick = async () => {
    const v = el("ov-exit").value;
    try { await meshd({ SetExit: { mesh: id, exit: v === "" ? null : parseInt(v, 10) } }); toast("exit set"); } catch (e) { toast(String(e)); }
    renderConfigs(id);
  };
  el("ov-peer-set").onclick = async () => {
    const m = parseInt(el("ov-peer-id").value, 10);
    const ep = el("ov-peer-ep").value.trim();
    if (!ep || !/^.+:\d+$/.test(ep)) return toast("enter ip:port");
    try { await meshd({ SetPeer: { mesh: id, member: m, endpoint: ep } }); toast("peer address set"); } catch (e) { toast(String(e)); }
    el("ov-peer-ep").value = "";
  };
  el("ov-recipher").onclick = async () => {
    const cipher = el("ov-recipher-cipher").value;
    const changed = cipher !== d.cipher;
    if (!confirm(`Re-cipher "${d.name}"?\n\nRotates the key${changed ? ` and switches the cipher to "${cipher}"` : ""}. Needs ≥60% of members online; anyone offline now is evicted and must be re-invited.`)) return;
    try { await meshd({ Recipher: { mesh: id, cipher: changed ? cipher : null } }); toast("re-ciphered"); } catch (e) { toast(String(e)); }
    renderConfigs(id);
  };
}

// ---- SDN flow table editor (Phase 2: unsigned, gossiped) ----
function fmtFlowAction(act) {
  if (typeof act === "string") return act;          // ToOverlayOwner / Local / Drop
  const k = Object.keys(act)[0], v = act[k];
  if (k === "ToExit") return v == null ? "→ exit" : `→ exit node ${v}`;
  if (k === "ToPeer") return `→ peer ${v}`;
  return `${k}(${v})`;
}
function fmtFlowMatch(m) {
  const p = [];
  if (m.scope != null) p.push(m.scope.toLowerCase());
  if (m.dst_cidr != null) p.push(`dst ${m.dst_cidr[0]}/${m.dst_cidr[1]}`);
  if (m.proto != null) p.push({ 1: "icmp", 6: "tcp", 17: "udp" }[m.proto] || `proto ${m.proto}`);
  if (m.dport != null) p.push(`dport ${m.dport}`);
  return p.length ? p.join(", ") : "any";
}
function parseCidr(s) {
  s = s.trim();
  if (s.includes("/")) { const [n, l] = s.split("/"); return [n, parseInt(l, 10)]; }
  return [s, 32];
}
function defaultFlowTable() {
  return [
    { priority: 0, match_: { scope: "Overlay", dst_cidr: null, proto: null, dport: null }, action: "ToOverlayOwner" },
    { priority: 0, match_: { scope: "Internet", dst_cidr: null, proto: null, dport: null }, action: { ToExit: null } },
  ];
}
async function renderFlows(id) {
  let rules = [];
  try { rules = (await meshd({ GetFlows: { mesh: id } })).FlowRules || []; }
  catch (e) { el("flow-list").textContent = String(e); return; }
  const node = el("flow-list");
  if (!node) return;
  if (!rules.length) {
    node.innerHTML = `<span class="muted">empty — using the built-in default (overlay → owner, internet → exit).</span>`;
  } else {
    node.innerHTML = rules.map((r, i) =>
      `<div class="kv"><span><code>[${i}]</code> prio ${r.priority} · ${esc(fmtFlowMatch(r.match_))}</span>` +
      `<b>${esc(fmtFlowAction(r.action))} <button class="small-btn" data-flow-del="${i}">remove</button></b></div>`
    ).join("");
    node.querySelectorAll("[data-flow-del]").forEach((b) => {
      b.onclick = async () => {
        const idx = parseInt(b.getAttribute("data-flow-del"), 10);
        const next = rules.filter((_, j) => j !== idx);
        try { await meshd({ SetFlows: { mesh: id, flows: next } }); toast("rule removed"); } catch (e) { toast(String(e)); }
        renderFlows(id);
      };
    });
  }
  el("flow-add").onclick = async () => {
    const cidr = el("flow-cidr").value.trim();
    if (!cidr) return toast("enter a destination CIDR");
    const act = el("flow-act").value;
    const match_ = { scope: null, dst_cidr: parseCidr(cidr), proto: null, dport: null };
    const action = act === "block" ? "Drop" : { ToExit: null };
    const next = rules.concat([{ priority: 100, match_, action }]);
    try { await meshd({ SetFlows: { mesh: id, flows: next } }); toast("rule added"); } catch (e) { toast(String(e)); }
    el("flow-cidr").value = "";
    renderFlows(id);
  };
  el("flow-reset").onclick = async () => {
    if (!confirm("Reset this mesh's flow table to the default?")) return;
    try { await meshd({ SetFlows: { mesh: id, flows: defaultFlowTable() } }); toast("flow table reset"); } catch (e) { toast(String(e)); }
    renderFlows(id);
  };
}

// ---- Derive the active warnings for a mesh (attack detection + liveness/health) ----
// The DAEMON is authoritative for health warnings (data-plane down, below-floor,
// decrypt-fail / split-brain). The GUI only visualizes what the daemon reports in
// `d.warnings` — it does not re-derive them. The attack countdown is separate because it
// drives an interactive control (the creator's all-clear button).
function meshWarnings(d) {
  const w = [];
  if (d.attack_armed_secs_left != null) {
    w.push({ kind: "attack", secs: d.attack_armed_secs_left, is_creator: d.is_creator });
  }
  for (const msg of (d.warnings || [])) {
    w.push({ kind: "daemon", detail: msg });
  }
  return w;
}

// ---- Mesh mode: Warnings page (attack detection detail + health) ----
async function renderWarnings(id) {
  let d;
  try { d = (await meshd({ MeshInfo: { mesh: id } })).Mesh; }
  catch (e) { toast(String(e)); return setMode("user"); }
  const w = meshWarnings(d);
  const body = el("mesh-warn-body");
  const danger = dangerCardHtml(d); // Danger zone (report attack / wipe) moved here from Configs
  if (!w.length) {
    body.innerHTML = `<div class="card"><p class="warn-ok">✓ No warnings — this mesh is healthy.</p></div>` + danger;
    wireDangerCard(id, d);
    return;
  }
  body.innerHTML = w.map((x) => {
    if (x.kind === "attack") {
      return `<div class="warn-card">
        <h3>⚠ Attack reported — mesh self-destructing</h3>
        <p>An attack alert is armed on this mesh. When the grace ends every member's keys
          are wiped — the one-veto, fail-deadly response (P-C7). A single member can raise
          this; only the creator can call it off.</p>
        <p class="when">Self-destruct in <span class="warn-countdown">${x.secs}s</span>.
          ${x.is_creator ? "You are the creator — call it off if this is a false alarm." : "Waiting for the creator to call it off."}</p>
        ${x.is_creator ? `<div class="add-row" style="margin-top:8px"><button class="small-btn" id="warn-allclear">All clear (cancel self-destruct)</button></div>` : ""}
      </div>`;
    }
    // A daemon-reported warning (data-plane down, below-floor, decrypt-fail/split-brain).
    const dp = x.detail.startsWith("⛔");
    return `<div class="warn-card${dp ? "" : " amber"}"><h3>${dp ? "⛔ Data plane" : "⚠ Health"}</h3><p>${esc(x.detail)}</p></div>`;
  }).join("") + danger;
  const ac = el("warn-allclear");
  if (ac) ac.onclick = async () => { try { await meshd({ AllClear: { mesh: id } }); toast("all-clear sent"); } catch (e) { toast(String(e)); } renderWarnings(id); };
  wireDangerCard(id, d);
}

// ---- top widget bar (§1): status (left) + view toggle + egress dropdown ----
async function refreshTopbar() {
  const dot = el("tb-dot"), sum = el("tb-summary"), sel = el("tb-egress");
  let meshes = [];
  try { meshes = (await meshd("ListMeshes")).Meshes || []; }
  catch {
    dot.className = "conn-dot off"; sum.textContent = "meshd offline";
    sel.innerHTML = `<option value="origin">Origin</option>`; sel.disabled = true; return;
  }
  sel.disabled = false;
  const egress = meshes.find((m) => m.is_current);
  // egress dropdown: Origin + meshes; the selected one is the current egress.
  sel.innerHTML = [`<option value="origin" ${!egress ? "selected" : ""}>Default network</option>`]
    .concat(meshes.map((m) => `<option value="${m.id}" ${m.is_current ? "selected" : ""}>⬢ ${esc(m.name)} #${m.id}</option>`))
    .join("");
  // far-left status mirrors the current egress.
  if (egress) {
    dot.className = "conn-dot on";
    sum.textContent = `Routing via ${egress.name}${egress.exit != null ? " · exit #" + egress.exit : ""}`;
  } else {
    dot.className = "conn-dot warn";
    sum.textContent = "Using default network";
  }
}

// [User|Mesh] = view toggle (no daemon call).
document.querySelectorAll("#mode-toggle .seg-btn").forEach((b) =>
  b.addEventListener("click", () => setMode(b.dataset.mode))
);
// dropdown = egress selector (Origin or a mesh); independent of the view.
el("tb-egress").addEventListener("change", async (e) => {
  const v = e.target.value;
  try {
    await meshd({ SetCurrent: { mesh: v === "origin" ? null : parseInt(v, 10) } });
    toast(v === "origin" ? "Using default network" : "egress set");
  } catch (err) { toast(String(err)); }
  // The selected egress is also the mesh shown in Mesh mode — Default network ⇒
  // no mesh ⇒ plain Mesh page.
  CURRENT_MESH = v === "origin" ? null : parseInt(v, 10);
  refreshMode();
});

// ---- Cipher dropbox (P-C1): the data-plane cipher, fixed at mesh creation ----
let CIPHER_DEFAULT = "chachapoly-epoch";
function updateCipherWarn() {
  const sel = el("mesh-cipher"), warn = el("mesh-cipher-warn");
  if (!sel || !warn) return;
  // Warn whenever a non-default (experimental/permanent) cipher is chosen.
  warn.classList.toggle("hidden", sel.value === CIPHER_DEFAULT);
}
async function populateCiphers() {
  const sel = el("mesh-cipher");
  if (!sel || sel.options.length) return; // once populated, keep the user's choice
  let list = [];
  try { list = (await meshd("Ciphers")).Ciphers || []; } catch (_) { return; }
  if (!list.length) return;
  CIPHER_DEFAULT = list[0]; // meshd lists the default first
  sel.innerHTML = list
    .map((c, i) => `<option value="${esc(c)}"${i === 0 ? " selected" : ""}>${esc(c)}${i === 0 ? " (default)" : ""}</option>`)
    .join("");
  updateCipherWarn();
}
el("mesh-cipher").addEventListener("change", updateCipherWarn);
populateCiphers();

// ---- Cached lists: data-plane ciphers (re-cipher) + invite algorithms (P-C6) ----
let CIPHERS = [];
let INVITE_ALGOS = [];
async function loadLists() {
  try { CIPHERS = (await meshd("Ciphers")).Ciphers || []; } catch (_) {}
  try { INVITE_ALGOS = (await meshd("InviteAlgorithms")).Ciphers || []; } catch (_) {}
  const ja = el("join-algo");
  if (ja && INVITE_ALGOS.length)
    ja.innerHTML = INVITE_ALGOS.map((a, i) => `<option${i === 0 ? " selected" : ""}>${esc(a)}</option>`).join("");
  return CIPHERS.length && INVITE_ALGOS.length;
}
// meshd is launched by the GUI at startup and isn't reachable the instant the webview
// paints — so a one-shot fetch left the cipher/algorithm dropdowns permanently EMPTY
// (the error was swallowed, never retried). Retry until the lists load, then fill the
// create-mesh cipher select too.
(async () => {
  for (let i = 0; i < 40; i++) {
    if (await loadLists()) { await populateCiphers(); break; }
    await new Promise((r) => setTimeout(r, 1000));
  }
})();
const optList = (list, sel) => list.map((x) => `<option${x === sel ? " selected" : ""}>${esc(x)}</option>`).join("");

// ---- P-C7 attack banner (G-3): poll for any armed mesh; show countdown + all-clear ----
async function refreshAttackBanner() {
  const banner = el("attack-banner");
  if (!banner) return;
  let meshes = [];
  try { meshes = (await meshd("ListMeshes")).Meshes || []; } catch (_) { banner.classList.add("hidden"); return; }
  const armed = meshes.find((m) => m.attack_armed_secs_left != null);
  if (!armed) { banner.classList.add("hidden"); return; }
  banner.classList.remove("hidden");
  el("attack-banner-text").textContent =
    `⚠ ATTACK ALERT — mesh "${armed.name}" self-destructs in ~${armed.attack_armed_secs_left}s`
    + (armed.is_creator ? "" : " — waiting for the creator");
  const btn = el("attack-allclear");
  btn.classList.toggle("hidden", !armed.is_creator);
  btn.onclick = async () => {
    try { await meshd({ AllClear: { mesh: armed.id } }); toast("all-clear sent"); } catch (e) { toast(String(e)); }
    refreshAttackBanner();
  };
}
setInterval(refreshAttackBanner, 3000);

// ---- Mesh-mode Warnings: red badge count + desktop notification on attack ----
let ATTACK_NOTIFIED = {}; // mesh id → notified-this-episode, so we alert once
async function notify(title, body) {
  if (!window.__TAURI__) return;
  try { await invoke("notify", { title, body }); } catch (_) {}
}
async function updateMeshWarnings() {
  const badge = el("warn-badge");
  if (MODE !== "mesh" || CURRENT_MESH == null) { if (badge) badge.classList.add("hidden"); return; }
  let d;
  try { d = (await meshd({ MeshInfo: { mesh: CURRENT_MESH } })).Mesh; } catch (_) { return; }
  const w = meshWarnings(d);
  if (badge) { badge.textContent = String(w.length); badge.classList.toggle("hidden", w.length === 0); }
  // Notify once per attack episode (when an alert first appears for this mesh).
  const attacked = d.attack_armed_secs_left != null;
  if (attacked && !ATTACK_NOTIFIED[d.id]) {
    ATTACK_NOTIFIED[d.id] = true;
    notify("⚠ Lattice — attack detected", `Mesh "${d.name}" self-destructs in ~${d.attack_armed_secs_left}s. Open Warnings.`);
  }
  if (!attacked) ATTACK_NOTIFIED[d.id] = false;
  if (ACTIVE_TAB === "mesh-warnings") renderWarnings(CURRENT_MESH);
}
setInterval(updateMeshWarnings, 3000);

// ---- Update check (Feature 1): on launch, ask GitHub Releases for a newer build.
// If one exists, show a banner. "Update" backs up mesh state (Feature 2) then opens
// the download page so the user reinstalls; the new meshd re-imports the backup.
async function checkForUpdate() {
  if (!window.__TAURI__) return;
  let info;
  try { info = await invoke("check_update"); } catch { return; } // offline / rate-limited
  if (!info || !info.available) return;
  const banner = el("update-banner");
  el("update-banner-text").textContent =
    `New version ${info.latest} available (you have ${info.current}).`;
  banner.classList.remove("hidden");
  el("update-dismiss").onclick = () => banner.classList.add("hidden");
  el("update-now").onclick = async () => {
    el("update-now").disabled = true;
    // Back up every mesh so a reinstall (even one that wipes state) can't drop us.
    try { await meshd({ ExportState: { path: null } }); } catch (e) { /* best-effort */ }
    try { await invoke("open_url", { url: info.url }); }
    catch (e) { toast("could not open the download page: " + e); }
    toast("Mesh state backed up. Install the new version, then reopen Lattice.");
  };
}
checkForUpdate();

// ---- App version (small, bottom-left of the sidebar — for the user to check) ----
async function showAppVersion() {
  const node = el("app-version");
  if (!node) return;
  if (!window.__TAURI__) { node.textContent = "dev"; return; }
  try { node.textContent = "v" + (await invoke("app_version")); } catch { node.textContent = ""; }
}
showAppVersion();

setMode("user");
setInterval(refreshTopbar, 3000);
// Live poll: keep the Peers/Topology/Traffic views fresh while viewing them.
// Is the user currently typing into an input on the Peers tab (the invite fields or an
// inline peer-address box)? If so, the live poll must NOT re-render the panel out from
// under them — the table-row rebuild would destroy the focused input and drop the keys.
function typingInPeers() {
  const a = document.activeElement;
  if (!a || (a.tagName !== "INPUT" && a.tagName !== "TEXTAREA")) return false;
  const t = el("peers-table"), x = el("peers-extra");
  return (t && t.contains(a)) || (x && x.contains(a));
}
setInterval(() => {
  if (ACTIVE_TAB === "traffic") return renderTraffic("user"); // this computer (user mode)
  if (ACTIVE_TAB === "extensions") return renderExtServices(); // refresh only the services card
  if (MODE !== "mesh" || CURRENT_MESH == null) return;
  if (ACTIVE_TAB === "mesh-peers") { if (!typingInPeers()) renderPeersFor(CURRENT_MESH); }
  else if (ACTIVE_TAB === "mesh-topology") renderTopologyFor(CURRENT_MESH);
  else if (ACTIVE_TAB === "mesh-traffic") renderTraffic("mesh");
}, 3000);

// ---- browser demo (no Tauri): meshd is unreachable ----
function mockInvoke(cmd) {
  if (cmd === "meshd") return Promise.reject("meshd not running (browser demo)");
  return Promise.resolve(null);
}
