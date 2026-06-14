// Lattice GUI — sidebar layout. Polls the daemon over IPC (Tauri commands) and
// renders live state across the Status / Peers / Network panels.

const invoke = window.__TAURI__?.invoke ?? mockInvoke;
if (!window.__TAURI__) {
  console.warn("Lattice: Tauri API not found — showing DEMO data, NOT a real daemon.");
}

const el = (id) => document.getElementById(id);
let starting = false;

// ---- tab navigation ----
document.querySelectorAll(".nav-item").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    document.querySelectorAll(".panel").forEach((p) => {
      p.classList.toggle("hidden", p.dataset.panel !== btn.dataset.tab);
    });
  });
});

async function refresh() {
  let status = null;
  let reachable = true;
  try {
    status = await invoke("get_status");
  } catch {
    reachable = false;
  }

  el("stopped-card").classList.toggle("hidden", reachable);
  el("running-card").classList.toggle("hidden", !reachable);

  const dot = el("conn-dot");
  const txt = el("conn-text");
  if (!reachable) {
    dot.className = "conn-dot " + (starting ? "warn" : "off");
    txt.textContent = starting ? "starting…" : "stopped";
    setPeerBadge(0);
    return;
  }

  starting = false;
  const meshUp = !!status.running;
  dot.className = "conn-dot " + (meshUp ? "on" : "warn");
  txt.textContent = meshUp ? "online" : "paused";

  el("virtual-ip").textContent = status.virtual_ip ?? "—";
  el("public-addr").textContent = status.public_addr ?? "not detected (LAN only)";
  el("fingerprint").textContent = status.fingerprint ?? "—";
  const nodeId = status.node_id ?? "";
  el("node-id").textContent = nodeId ? nodeId.slice(0, 20) + "…" : "—";
  el("node-id").dataset.full = nodeId;
  el("mesh-toggle").checked = meshUp;
  el("relay-status").textContent = status.relay ?? "off";

  // peers
  let peers = [];
  try {
    peers = await invoke("list_peers");
  } catch {
    /* transient */
  }
  el("peer-count").textContent = `(${peers.length})`;
  setPeerBadge(peers.length);
  renderPeers(peers);
  updateExitSelect(peers, status.exit_node);
  el("exit-toggle").checked = !!status.is_exit;

  // traffic — only when the user hasn't paused the live view
  if (el("traffic-live").checked) {
    let flows = [];
    try {
      flows = await invoke("list_flows");
    } catch {
      /* transient */
    }
    renderFlows(flows);
  }

  // mesh / membership
  try {
    const net = await invoke("network_info");
    await renderMesh(net);
  } catch {
    /* transient */
  }

  // topology graph (this node + its peers) + the shared SDN flow table
  let flowRules = [];
  try {
    flowRules = await invoke("list_flow_rules");
  } catch {
    /* member node / transient */
  }
  updateTopology(status, peers, flowRules);
}

// The user GUI shows membership read-only: the node's role (open / member) and
// the network id. Admin capabilities (enrolling/revoking members, holding the
// network CA key) are deliberately NOT in the user surface — they live in the
// separate admin CLI/tooling. So there's no members list or issue/revoke UI here.
async function renderMesh(net) {
  const hasNet = !!net.network_id;
  el("mesh-role").textContent = hasNet ? "member" : "open mode (no network)";
  const idEl = el("mesh-id");
  idEl.textContent = hasNet ? net.fingerprint + "…" : "—";
  idEl.dataset.full = net.network_id ?? "";
}

function renderFlows(flows) {
  el("flow-count").textContent = `(${flows.length})`;
  el("total-flows").textContent = flows.length;

  let txBytes = 0, rxBytes = 0;
  for (const f of flows) {
    txBytes += f.tx_bytes;
    rxBytes += f.rx_bytes;
  }
  el("total-tx").textContent = fmtBytes(txBytes);
  el("total-rx").textContent = fmtBytes(rxBytes);

  const tbody = el("flows");
  tbody.innerHTML = "";
  el("flows-empty").classList.toggle("hidden", flows.length > 0);
  for (const f of flows) {
    const tr = document.createElement("tr");
    if (f.last_active_secs <= 3) tr.className = "hot";
    const peer = f.peer ? ` <span class="muted small">(${f.peer})</span>` : "";
    tr.innerHTML =
      `<td><span class="proto ${f.protocol.toLowerCase().replace(/\W/g, "")}">${f.protocol}</span></td>` +
      `<td class="mono small">${f.local}</td>` +
      `<td class="mono small">${f.remote}${peer}</td>` +
      `<td class="num mono small">${fmtBytes(f.tx_bytes)}<span class="muted"> / ${f.tx_packets}p</span></td>` +
      `<td class="num mono small">${fmtBytes(f.rx_bytes)}<span class="muted"> / ${f.rx_packets}p</span></td>` +
      `<td class="num mono small muted">${fmtAge(f.last_active_secs)}</td>`;
    tbody.appendChild(tr);
  }
}

function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function fmtAge(secs) {
  if (secs <= 1) return "now";
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m`;
  return `${Math.floor(secs / 3600)}h`;
}

function setPeerBadge(n) {
  const b = el("nav-peer-count");
  b.textContent = n;
  b.classList.toggle("hidden", n === 0);
}

function renderPeers(peers) {
  const ul = el("peers");
  ul.innerHTML = "";
  if (peers.length === 0) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "No peers yet.";
    ul.appendChild(li);
    return;
  }
  for (const p of peers) {
    const li = document.createElement("li");
    const ip = document.createElement("span");
    ip.className = "mono copy";
    ip.title = "Click to copy";
    ip.textContent = p.virtual_ip;
    ip.addEventListener("click", () => copy(p.virtual_ip));
    const left = document.createElement("span");
    left.innerHTML = `<span class="dot ${p.status}"></span>`;
    left.appendChild(ip);
    const right = document.createElement("span");
    right.className = "muted mono small";
    right.textContent = [osLabel(p.os), p.fingerprint, p.endpoint].filter(Boolean).join(" · ");
    li.appendChild(left);
    li.appendChild(right);
    ul.appendChild(li);
  }
}

function updateExitSelect(peers, exitNode) {
  const sel = el("exit-select");
  const sig = ["", ...peers.map((p) => p.node_id)].join(",");
  if (sel.dataset.sig !== sig) {
    sel.innerHTML = "";
    sel.add(new Option("Direct (no exit)", ""));
    for (const p of peers) sel.add(new Option(`${p.fingerprint} · ${p.virtual_ip}`, p.node_id));
    sel.dataset.sig = sig;
  }
  sel.value = exitNode ?? "";
}

// ---- actions ----
el("start").addEventListener("click", async () => {
  starting = true;
  refresh();
  try {
    await invoke("start_daemon");
  } catch (e) {
    starting = false;
    toast(String(e));
  }
  for (let i = 0; i < 15 && starting; i++) {
    await sleep(700);
    await refresh();
  }
});

el("stop").addEventListener("click", async () => {
  try {
    await invoke("stop_daemon");
  } catch (e) {
    toast(String(e));
  }
  await sleep(500);
  refresh();
});

el("mesh-toggle").addEventListener("change", async (e) => {
  try {
    await invoke(e.target.checked ? "mesh_up" : "mesh_down");
  } catch (err) {
    toast(String(err));
  }
  refresh();
});

el("exit-select").addEventListener("change", async (e) => {
  try {
    await invoke("set_exit", { nodeId: e.target.value || null });
  } catch (err) {
    toast(String(err));
  }
  refresh();
});

el("exit-toggle").addEventListener("change", async (e) => {
  try {
    await invoke("allow_exit", { enabled: e.target.checked });
  } catch (err) {
    toast(String(err));
  }
  refresh();
});

el("set-relay").addEventListener("click", async () => {
  try {
    await invoke("set_relay", { addr: el("relay-addr").value.trim() });
    toast(el("relay-addr").value.trim() ? "relay set" : "relay cleared");
  } catch (err) {
    toast(String(err));
  }
  refresh();
});

el("refresh-peers").addEventListener("click", async () => {
  const btn = el("refresh-peers");
  btn.classList.remove("spin");
  void btn.offsetWidth; // restart the animation
  btn.classList.add("spin");
  await refresh();
  toast("refreshed");
});

el("mesh-id").addEventListener("click", () => {
  const full = el("mesh-id").dataset.full;
  if (full) copy(full);
});

el("join-net").addEventListener("click", async () => {
  const token = el("join-token").value.trim();
  if (!token) return;
  try {
    await invoke("join_network", { token });
    el("join-token").value = "";
    toast("joined network");
  } catch (e) {
    toast(String(e));
  }
  refresh();
});

bindAdd("add-peer", "peer-spec", (v) => invoke("add_peer", { spec: v }), "peer added");
bindAdd("add-relay-peer", "relay-peer-id", (v) => invoke("relay_peer", { nodeId: v }), "peer added via relay");

el("virtual-ip").addEventListener("click", () => maybeCopy("virtual-ip"));
el("node-id").addEventListener("click", () => {
  const full = el("node-id").dataset.full;
  if (full) copy(full);
});

function bindAdd(btnId, inputId, fn, okMsg) {
  el(btnId).addEventListener("click", async () => {
    const v = el(inputId).value.trim();
    if (!v) return;
    try {
      await fn(v);
      el(inputId).value = "";
      toast(okMsg);
    } catch (err) {
      toast(String(err));
    }
    refresh();
  });
}

function maybeCopy(id) {
  const t = el(id).textContent;
  if (t && t !== "—") copy(t);
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
  toast(`Copied ${text}`);
}

let toastTimer;
function toast(msg) {
  const t = el("toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add("hidden"), 1800);
}

function osLabel(os) {
  if (!os) return "";
  return (
    { macos: "🍎 macOS", linux: "🐧 Linux", windows: "🪟 Windows", ios: "📱 iOS", android: "🤖 Android" }[os] || os
  );
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

refresh();
// ===================== Topology graph =====================
// A force-directed view of the mesh from this node: me at the centre, each peer
// a node, edges coloured by link type (direct / relayed / connecting), the exit
// node ringed. Click a node to see its routing + the shared SDN flow table.
const TOPO = { nodes: [], edges: [], byId: new Map(), selected: null, flows: [], peers: [], raf: 0, meId: null };

function topoPanelVisible() {
  const p = document.querySelector('[data-panel="topology"]');
  return p && !p.classList.contains("hidden");
}

// Deterministic small offset from an id, so nodes start spread (not all stacked).
function hashSpread(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return { dx: ((h & 0xff) / 255 - 0.5) * 240, dy: (((h >> 8) & 0xff) / 255 - 0.5) * 240 };
}

function linkType(p, exitNode) {
  if (p.status !== "connected") return "connecting";
  // The relay synthetic endpoint range 192.0.2.x/24 marks a relayed link.
  if (p.endpoint && p.endpoint.startsWith("192.0.2.")) return "relay";
  return "direct";
}

function updateTopology(status, peers, flowRules) {
  TOPO.flows = flowRules || [];
  TOPO.peers = peers || [];
  TOPO.meId = status?.node_id || null;
  const want = new Map();

  // me
  if (status?.node_id) {
    want.set(status.node_id, {
      id: status.node_id, label: status.fingerprint || "me", vip: status.virtual_ip || "—",
      endpoint: status.public_addr || "local", os: "me", state: "me", isMe: true, isExit: status.is_exit,
    });
  }
  for (const p of peers || []) {
    want.set(p.node_id, {
      id: p.node_id, label: p.fingerprint, vip: p.virtual_ip,
      endpoint: p.endpoint || "—", os: p.os, state: p.status,
      isMe: false, isExit: status?.exit_node === p.node_id, link: linkType(p, status?.exit_node),
    });
  }

  // Reconcile nodes, keeping positions of existing ones.
  const next = [];
  const byId = new Map();
  for (const [id, d] of want) {
    const prev = TOPO.byId.get(id);
    const node = prev || { x: (canvasW() / 2) + hashSpread(id).dx, y: (canvasH() / 2) + hashSpread(id).dy, vx: 0, vy: 0 };
    Object.assign(node, d);
    next.push(node);
    byId.set(id, node);
  }
  TOPO.nodes = next;
  TOPO.byId = byId;
  TOPO.edges = (peers || [])
    .filter((p) => byId.has(p.node_id) && TOPO.meId)
    .map((p) => ({ from: TOPO.meId, to: p.node_id, type: linkType(p, status?.exit_node), exit: status?.exit_node === p.node_id }));

  if (!TOPO.selected || !byId.has(TOPO.selected)) TOPO.selected = TOPO.meId;
  renderTopoSide();
  if (topoPanelVisible() && !TOPO.raf) TOPO.raf = requestAnimationFrame(topoTick);
}

const topoCanvas = () => el("topo-canvas");
function canvasW() { const c = topoCanvas(); return (c && c.clientWidth) || 600; }
function canvasH() { const c = topoCanvas(); return (c && c.clientHeight) || 420; }

function topoTick() {
  TOPO.raf = 0;
  const c = topoCanvas();
  if (!c || !topoPanelVisible()) return;
  const W = c.clientWidth, H = c.clientHeight;
  if (c.width !== W || c.height !== H) { c.width = W; c.height = H; }
  const nodes = TOPO.nodes;

  // physics: repulsion + edge springs + centre gravity
  for (const a of nodes) {
    for (const b of nodes) {
      if (a === b) continue;
      let dx = a.x - b.x, dy = a.y - b.y;
      let d2 = dx * dx + dy * dy || 1;
      const f = 9000 / d2;
      a.vx += (dx / Math.sqrt(d2)) * f; a.vy += (dy / Math.sqrt(d2)) * f;
    }
    a.vx += (W / 2 - a.x) * 0.01; a.vy += (H / 2 - a.y) * 0.01;
  }
  for (const e of TOPO.edges) {
    const a = TOPO.byId.get(e.from), b = TOPO.byId.get(e.to);
    if (!a || !b) continue;
    const dx = b.x - a.x, dy = b.y - a.y, d = Math.hypot(dx, dy) || 1;
    const f = (d - 150) * 0.02;
    a.vx += (dx / d) * f; a.vy += (dy / d) * f;
    b.vx -= (dx / d) * f; b.vy -= (dy / d) * f;
  }
  for (const a of nodes) {
    if (a.isMe) { a.x = W / 2; a.y = H / 2; a.vx = a.vy = 0; continue; } // pin me at centre
    a.vx *= 0.82; a.vy *= 0.82;
    a.x = Math.max(40, Math.min(W - 40, a.x + a.vx));
    a.y = Math.max(40, Math.min(H - 40, a.y + a.vy));
  }

  // draw
  const g = c.getContext("2d");
  g.clearRect(0, 0, W, H);
  const COL = { direct: "#34d399", relay: "#fbbf24", connecting: "#64748b" };
  for (const e of TOPO.edges) {
    const a = TOPO.byId.get(e.from), b = TOPO.byId.get(e.to);
    if (!a || !b) continue;
    g.beginPath(); g.moveTo(a.x, a.y); g.lineTo(b.x, b.y);
    g.strokeStyle = COL[e.type] || "#64748b";
    g.lineWidth = e.exit ? 3 : 1.6;
    g.setLineDash(e.type === "relay" ? [6, 5] : e.type === "connecting" ? [2, 4] : []);
    g.stroke(); g.setLineDash([]);
  }
  for (const n of nodes) {
    const sel = n.id === TOPO.selected;
    const r = n.isMe ? 16 : 12;
    if (n.isExit) { g.beginPath(); g.arc(n.x, n.y, r + 5, 0, 7); g.strokeStyle = "#a78bfa"; g.lineWidth = 2.5; g.stroke(); }
    g.beginPath(); g.arc(n.x, n.y, r, 0, 7);
    g.fillStyle = n.isMe ? "#60a5fa" : n.state === "connected" ? "#34d399" : "#475569";
    g.fill();
    if (sel) { g.strokeStyle = "#fff"; g.lineWidth = 2.5; g.stroke(); }
    g.fillStyle = "#e2e8f0"; g.font = "11px ui-monospace, monospace"; g.textAlign = "center";
    g.fillText(n.label, n.x, n.y - r - 6);
    g.fillStyle = "#94a3b8"; g.font = "10px ui-monospace, monospace";
    g.fillText(n.vip, n.x, n.y + r + 13);
  }
  // keep animating while it settles or stays visible
  TOPO.raf = requestAnimationFrame(topoTick);
}

function renderTopoSide() {
  const d = TOPO.byId.get(TOPO.selected);
  const det = el("topo-detail");
  if (det && d) {
    const kind = d.isMe ? "this node" : d.isExit ? "exit node" : d.link || d.state;
    det.innerHTML =
      `<h3 class="topo-h">${d.label} <span class="muted small">${kind}</span></h3>` +
      `<div class="kv"><span>virtual IP</span><b class="mono">${d.vip}</b></div>` +
      `<div class="kv"><span>endpoint</span><b class="mono">${d.endpoint}</b></div>` +
      `<div class="kv"><span>os</span><b>${osLabel(d.os) || d.os || "—"}</b></div>` +
      `<div class="kv"><span>state</span><b>${d.state}</b></div>`;
  }
  // routing table (this node's peers)
  const rt = el("topo-routes")?.querySelector("tbody");
  if (rt) {
    rt.innerHTML = TOPO.peers.length
      ? TOPO.peers.map((p) => {
          const via = p.status !== "connected" ? "—" : (p.endpoint || "").startsWith("192.0.2.") ? "relay" : "direct";
          return `<tr><td class="mono">${p.virtual_ip}</td><td>${via}</td><td><span class="dot ${p.status}"></span>${p.status}</td></tr>`;
        }).join("")
      : `<tr><td colspan="3" class="muted">no peers</td></tr>`;
  }
  // flow table (shared, signed)
  const ft = el("topo-flows")?.querySelector("tbody");
  if (ft) {
    ft.innerHTML = TOPO.flows.length
      ? TOPO.flows.map((r) => `<tr><td>${r.priority}</td><td class="mono small">${r.matcher}</td><td class="mono small">${r.action}</td></tr>`).join("")
      : `<tr><td colspan="3" class="muted">default (overlay→owner, internet→exit)</td></tr>`;
  }
}

// click a node in the graph
document.addEventListener("click", (e) => {
  const c = topoCanvas();
  if (!c || e.target !== c) return;
  const rect = c.getBoundingClientRect();
  const mx = e.clientX - rect.left, my = e.clientY - rect.top;
  let best = null, bd = 1e9;
  for (const n of TOPO.nodes) {
    const d = Math.hypot(n.x - mx, n.y - my);
    if (d < 22 && d < bd) { bd = d; best = n; }
  }
  if (best) { TOPO.selected = best.id; renderTopoSide(); }
});
// kick the animation when switching to the Topology tab
document.querySelectorAll('.nav-item[data-tab="topology"]').forEach((b) =>
  b.addEventListener("click", () => { if (!TOPO.raf) TOPO.raf = requestAnimationFrame(topoTick); }));

setInterval(refresh, 2000);

// ---- development mock (only outside Tauri) ----
function mockInvoke(cmd, args) {
  const s = (mockInvoke.s ??= { up: false, mesh: true, exit: null, isExit: false, relay: null });
  switch (cmd) {
    case "start_daemon": s.up = true; return Promise.resolve();
    case "stop_daemon": s.up = false; return Promise.resolve();
    case "mesh_up": s.mesh = true; return Promise.resolve();
    case "mesh_down": s.mesh = false; return Promise.resolve();
    case "set_exit": s.exit = args?.nodeId ?? null; return Promise.resolve();
    case "allow_exit": s.isExit = !!args?.enabled; return Promise.resolve();
    case "set_relay": s.relay = args?.addr || null; return Promise.resolve();
    case "add_peer": case "relay_peer": return Promise.resolve();
    case "get_status":
      return s.up
        ? Promise.resolve({
            running: s.mesh, virtual_ip: "0.0.0.0 (DEMO)", fingerprint: "demo",
            node_id: "00".repeat(32), public_addr: null,
            exit_node: s.exit, is_exit: s.isExit, relay: s.relay,
          })
        : Promise.reject("daemon not running");
    case "list_peers":
      return Promise.resolve(s.up ? [
        { virtual_ip: "0.0.0.0 (DEMO)", fingerprint: "demo", status: "known", endpoint: null, node_id: "00".repeat(32), os: "demo" },
      ] : []);
    case "network_info":
      return Promise.resolve(s.up
        ? { network_id: "44".repeat(32), fingerprint: "44447777", is_admin: false, member_count: 2, revocation_count: 0 }
        : { network_id: null, fingerprint: null, is_admin: false, member_count: 0, revocation_count: 0 });
    case "join_network": return Promise.resolve();
    case "list_flow_rules":
      return Promise.resolve(s.up ? [
        { priority: 100, matcher: "scope=overlay", action: "overlay-owner" },
        { priority: 90, matcher: "proto=udp dport=53", action: "exit(39d55445)" },
        { priority: 50, matcher: "scope=internet", action: "exit(configured)" },
        { priority: 0, matcher: "*", action: "DROP" },
      ] : []);
    case "list_flows":
      return Promise.resolve(s.up ? [
        { peer: "demo", protocol: "TCP", local: "100.64.0.1:54012", remote: "100.64.0.2:22", tx_packets: 128, tx_bytes: 18432, rx_packets: 140, rx_bytes: 196608, last_active_secs: 0 },
        { peer: "demo", protocol: "ICMP", local: "100.64.0.1", remote: "100.64.0.2", tx_packets: 50, tx_bytes: 4200, rx_packets: 50, rx_bytes: 4200, last_active_secs: 2 },
        { peer: "demo", protocol: "UDP", local: "100.64.0.1:51820", remote: "100.64.0.2:443", tx_packets: 12, tx_bytes: 1536, rx_packets: 9, rx_bytes: 12000, last_active_secs: 40 },
      ] : []);
    default: return Promise.resolve(null);
  }
}
