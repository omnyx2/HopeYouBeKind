// Lattice GUI — sidebar layout. Polls the daemon over IPC (Tauri commands) and
// renders live state across the Status / Peers / Network panels.

const invoke = window.__TAURI__?.invoke ?? mockInvoke;
if (!window.__TAURI__) {
  console.warn("Lattice: Tauri API not found — showing DEMO data, NOT a real daemon.");
}

const el = (id) => document.getElementById(id);
let starting = false;
// Whether this node holds the network CA key. Flow-table editing is admin-only;
// member nodes see the table read-only (the daemon rejects their edits anyway).
let IS_ADMIN = false;

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
  el("relay-status").textContent = status.relay ?? "automatic (bridge elected)";
  const rs = el("relay-state");
  if (rs) {
    rs.textContent = status.relay ? "manual" : "auto";
    rs.className = "pill " + (status.relay ? "warn" : "ok");
  }

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
  const exitOn = !!status.exit_node;
  const ep = el("exit-state");
  if (ep) {
    ep.textContent = exitOn ? (exitMode === "split" ? "split tunnel" : "full tunnel") : "direct";
    ep.className = "pill " + (exitOn ? "on" : "off");
  }

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
  IS_ADMIN = !!net.is_admin;
  el("flow-admin")?.classList.toggle("hidden", !IS_ADMIN);
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
    const ct = linkType(p); // "direct" | "relay" | "connecting"
    const ctLabel = ct === "relay" ? "via bridge" : ct;
    const ip = document.createElement("span");
    ip.className = "mono copy";
    ip.title = "Click to copy";
    ip.textContent = p.virtual_ip;
    ip.addEventListener("click", () => copy(p.virtual_ip));
    const left = document.createElement("span");
    left.className = "peer-left";
    left.innerHTML = `<span class="dot ${p.status}"></span><span class="conn ${ct}">${ctLabel}</span>`;
    left.appendChild(ip);
    const right = document.createElement("span");
    right.className = "muted mono small";
    // hide the synthetic 192.0.2.x relay endpoint from the readout — it's not a
    // real address; the "via bridge" badge already conveys the relayed path.
    const ep = p.endpoint && p.endpoint.startsWith("192.0.2.") ? null : p.endpoint;
    right.textContent = [osLabel(p.os), p.fingerprint, ep].filter(Boolean).join(" · ");
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

let exitMode = "split"; // "split" | "full"
async function applyExit() {
  const nodeId = el("exit-select").value || null;
  try {
    await invoke("set_exit", { nodeId, split: exitMode === "split" });
  } catch (err) {
    toast(String(err));
  }
  refresh();
}
el("exit-select").addEventListener("change", applyExit);
document.querySelectorAll("#exit-mode .seg-btn").forEach((b) =>
  b.addEventListener("click", () => {
    exitMode = b.dataset.mode;
    document
      .querySelectorAll("#exit-mode .seg-btn")
      .forEach((x) => x.classList.toggle("active", x === b));
    if (el("exit-select").value) applyExit(); // re-apply current exit in the new mode
  })
);

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

// ---- flow-table editor (admin) ----
// Delete buttons are delegated: the table body re-renders on every refresh, so
// we listen on the stable parent and read the rule's storage index off the click.
el("topo-flows")?.addEventListener("click", async (e) => {
  const btn = e.target.closest(".flow-del");
  if (!btn) return;
  const index = parseInt(btn.dataset.idx, 10);
  if (Number.isNaN(index)) return;
  try {
    await invoke("del_flow_rule", { index });
    toast("rule deleted");
  } catch (err) {
    toast(String(err));
  }
  refresh();
});

// The exit:/peer: actions need a node id — reveal the field only for those.
el("fr-action")?.addEventListener("change", () => {
  const v = el("fr-action").value;
  el("fr-node").classList.toggle("hidden", v !== "exit:" && v !== "peer:");
});

el("fr-add")?.addEventListener("click", async () => {
  const priRaw = el("fr-priority").value.trim();
  const priority = priRaw === "" ? 50 : parseInt(priRaw, 10);
  if (Number.isNaN(priority) || priority < 0 || priority > 65535) {
    return toast("priority must be 0–65535");
  }
  const dportRaw = el("fr-dport").value.trim();
  const dport = dportRaw === "" ? null : parseInt(dportRaw, 10);
  if (dport !== null && (Number.isNaN(dport) || dport < 0 || dport > 65535)) {
    return toast("dport must be 0–65535");
  }
  let action = el("fr-action").value;
  if (action === "exit:" || action === "peer:") {
    const node = el("fr-node").value.trim();
    if (!node) return toast("this action needs a node id (64 hex chars)");
    action += node;
  }
  try {
    await invoke("add_flow_rule", {
      priority,
      scope: el("fr-scope").value || null,
      dst: el("fr-dst").value.trim() || null,
      proto: el("fr-proto").value || null,
      dport,
      action,
    });
    el("fr-priority").value = "";
    el("fr-dst").value = "";
    el("fr-dport").value = "";
    el("fr-node").value = "";
    toast("rule added");
  } catch (err) {
    toast(String(err));
  }
  refresh();
});

el("fr-clear")?.addEventListener("click", async () => {
  if (!confirm("Clear the entire flow table? Every node reverts to the built-in default.")) return;
  try {
    await invoke("clear_flow_rules");
    toast("flow table cleared");
  } catch (err) {
    toast(String(err));
  }
  refresh();
});

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
  const COL = { direct: "#34d399", relay: "#a78bfa", connecting: "#64748b" };
  for (const e of TOPO.edges) {
    const a = TOPO.byId.get(e.from), b = TOPO.byId.get(e.to);
    if (!a || !b) continue;
    g.beginPath(); g.moveTo(a.x, a.y); g.lineTo(b.x, b.y);
    g.strokeStyle = COL[e.type] || "#64748b";
    g.lineWidth = e.exit ? 3 : 1.8;
    g.globalAlpha = e.type === "connecting" ? 0.5 : 0.85;
    g.setLineDash(e.type === "relay" ? [6, 5] : e.type === "connecting" ? [2, 4] : []);
    g.stroke(); g.setLineDash([]); g.globalAlpha = 1;
  }
  for (const n of nodes) {
    const sel = n.id === TOPO.selected;
    const r = n.isMe ? 17 : 12;
    const fill = n.isMe ? "#60a5fa" : n.state === "connected" ? "#34d399" : "#475569";
    if (n.isExit) { g.beginPath(); g.arc(n.x, n.y, r + 5, 0, 7); g.strokeStyle = "#a78bfa"; g.lineWidth = 2.5; g.stroke(); }
    // node with a soft glow (brighter for me / connected)
    g.save();
    g.shadowColor = fill; g.shadowBlur = n.isMe ? 18 : n.state === "connected" ? 10 : 0;
    g.beginPath(); g.arc(n.x, n.y, r, 0, 7); g.fillStyle = fill; g.fill();
    g.restore();
    if (sel) { g.beginPath(); g.arc(n.x, n.y, r + 3, 0, 7); g.strokeStyle = "#fff"; g.lineWidth = 2; g.stroke(); }
    g.fillStyle = "#e2e8f0"; g.font = "600 11px ui-monospace, monospace"; g.textAlign = "center";
    g.fillText(n.label, n.x, n.y - r - 7);
    g.fillStyle = "#94a3b8"; g.font = "10px ui-monospace, monospace";
    g.fillText(n.vip, n.x, n.y + r + 14);
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
      ? TOPO.flows.map((r) => {
          // Delete by the rule's storage index (carried from the backend), so
          // removing the visually-sorted row hits the right rule in the table.
          const del = IS_ADMIN ? `<button class="flow-del" data-idx="${r.index}" title="delete rule">×</button>` : "";
          return `<tr><td>${r.priority}</td><td class="mono small">${r.matcher}</td><td class="mono small">${r.action}</td><td class="flow-del-cell">${del}</td></tr>`;
        }).join("")
      : `<tr><td colspan="4" class="muted">default (overlay→owner, internet→exit)</td></tr>`;
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
// ===== v2 Meshes (multi-mesh control plane via meshd) =====
async function meshd(req) {
  const s = await invoke("meshd", { request: JSON.stringify(req) });
  let r;
  try { r = JSON.parse(s); } catch { throw new Error("bad meshd response"); }
  if (r && r.Error) throw new Error(r.Error.message);
  return r;
}

function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
function randHex64() {
  let s = "";
  for (let i = 0; i < 64; i++) s += "0123456789abcdef"[Math.floor(Math.random() * 16)];
  return s;
}

// Two modes toggled from the top widget bar: "user" (this computer — manage all
// your meshes) and "mesh" (manage the one mesh picked in the dropdown).
let MODE = "user";
let CURRENT_MESH = null;

function activateTab(name) {
  document.querySelectorAll(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("hidden", p.dataset.panel !== name));
}

async function setMode(mode) {
  if (mode === "mesh") {
    if (CURRENT_MESH == null) {
      try { CURRENT_MESH = ((await meshd("ListMeshes")).Meshes || [])[0]?.id ?? null; } catch {}
    }
    if (CURRENT_MESH == null) { toast("no mesh yet — create one in User mode"); mode = "user"; }
  }
  MODE = mode;
  document.body.classList.toggle("mode-mesh", mode === "mesh");
  document.body.classList.toggle("mode-user", mode === "user");
  document.querySelectorAll("#mode-toggle .seg-btn").forEach((b) => b.classList.toggle("active", b.dataset.mode === mode));
  // user mode lands on Meshes; mesh mode lands on the per-mesh Overview.
  activateTab(mode === "mesh" ? "mesh-overview" : "meshes");
  await refreshMode();
}

async function refreshMode() {
  if (MODE === "mesh" && CURRENT_MESH != null) await renderOneMesh(CURRENT_MESH);
  else await renderComputer();
  refreshTopbar();
}

// ---- User mode: manage the SET of meshes on this computer ----
async function renderComputer() {
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
        <b>Origin</b>
        <span class="muted small">your computer's normal internet — no mesh</span>
        ${noEgress ? `<span class="pill on">egress</span>` : ""}
      </div>
      <div>
        <button class="small-btn" data-mesh-origin="1" ${noEgress ? "disabled" : ""}>make egress</button>
      </div>
    </li>`;
  const meshRows = meshes.length ? meshes.map((m) => {
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
        <button class="small-btn" data-mesh-open="${m.id}">manage ›</button>
        <button class="small-btn" data-mesh-current="${m.id}">make egress</button>
      </div>
    </li>`;
  }).join("") : `<li class="empty">no meshes yet — create one above</li>`;
  el("mesh-list").innerHTML = originRow + meshRows;
}

// ---- Mesh scope: manage ONE mesh ----
async function renderOneMesh(id) {
  let d;
  try { d = (await meshd({ MeshInfo: { mesh: id } })).Mesh; }
  catch (e) { toast(String(e)); return setMode("user"); }
  const rows = d.members.map((mb) =>
    `<tr><td>${mb.id}</td><td>${esc(mb.name)}${mb.is_me ? ' <span class="muted small">(me)</span>' : ""}</td><td class="mono small">${mb.pubkey_fp}</td></tr>`
  ).join("");
  const exitOpts = [`<option value="">— none —</option>`].concat(
    d.members.map((mb) => `<option value="${mb.id}" ${d.exit === mb.id ? "selected" : ""}>#${mb.id} ${esc(mb.name)}</option>`)
  ).join("");
  el("mesh-detail").innerHTML = `
    <div class="card-head">
      <h2 class="card-title">⬢ ${esc(d.name)} <span class="muted small">#${d.id}</span></h2>
      <div>
        <button class="small-btn" id="mesh-make-current">make egress</button>
        <button class="small-btn" id="mesh-remove">wipe mesh</button>
      </div>
    </div>
    <div class="kv"><span>charter</span><b class="small">${d.invite} · ${esc(d.trigger)} · max ${d.max_members}</b></div>
    <div class="kv"><span>cipher</span><b class="mono small">${esc(d.cipher)}</b></div>
    <div class="kv"><span>epoch</span><b>${d.epoch}</b></div>
    <div class="kv"><span>my exit</span><b>${d.exit != null ? "#" + d.exit : "none"}</b></div>
    <h3 class="topo-h">Roster <span class="muted small">(${d.members.length})</span></h3>
    <table class="topo-table"><thead><tr><th>id</th><th>name</th><th>pubkey</th></tr></thead><tbody>${rows}</tbody></table>
    <h3 class="topo-h">Set my exit</h3>
    <div class="add-row">
      <select id="mesh-exit" class="select">${exitOpts}</select>
      <button class="small-btn" id="mesh-exit-set">set exit</button>
    </div>
    <h3 class="topo-h">Admit a member <span class="muted small">(demo)</span></h3>
    <div class="add-row">
      <input id="mesh-admit-name" placeholder="name" />
      <input id="mesh-admit-pk" placeholder="pubkey 64 hex (blank = random)" />
      <button class="small-btn" id="mesh-admit">admit</button>
    </div>`;
  el("mesh-make-current").onclick = async () => {
    try { await meshd({ SetCurrent: { mesh: id } }); toast("set as egress"); } catch (e) { toast(String(e)); }
    refreshMode();
  };
  el("mesh-remove").onclick = async () => {
    if (!confirm(`Wipe mesh "${d.name}" locally? (the §5 compromise response)`)) return;
    try { await meshd({ RemoveMesh: { mesh: id } }); toast("mesh wiped"); } catch (e) { toast(String(e)); }
    CURRENT_MESH = null;
    setMode("user");
  };
  el("mesh-exit-set").onclick = async () => {
    const v = el("mesh-exit").value;
    try { await meshd({ SetExit: { mesh: id, exit: v === "" ? null : parseInt(v, 10) } }); toast("exit set"); } catch (e) { toast(String(e)); }
    refreshMode();
  };
  el("mesh-admit").onclick = async () => {
    const name = el("mesh-admit-name").value.trim();
    let pk = el("mesh-admit-pk").value.trim();
    if (!name) return toast("name required");
    if (!/^[0-9a-fA-F]{64}$/.test(pk)) pk = randHex64();
    try { await meshd({ AdmitMember: { mesh: id, name, pubkey_hex: pk } }); toast("member admitted"); } catch (e) { toast(String(e)); }
    refreshMode();
  };
}

// computer-scope list buttons (delegated)
el("mesh-list").addEventListener("click", async (e) => {
  const origin = e.target.closest("[data-mesh-origin]");
  const open = e.target.closest("[data-mesh-open]");
  const cur = e.target.closest("[data-mesh-current]");
  if (origin) {
    try { await meshd({ SetCurrent: { mesh: null } }); toast("egress: origin"); }
    catch (err) { toast(String(err)); }
    return refreshMode();
  }
  if (open) { CURRENT_MESH = parseInt(open.dataset.meshOpen, 10); return setMode("mesh"); }
  if (cur) {
    try { await meshd({ SetCurrent: { mesh: parseInt(cur.dataset.meshCurrent, 10) } }); toast("egress set"); }
    catch (err) { toast(String(err)); }
    refreshMode();
  }
});

el("mesh-create").addEventListener("click", async () => {
  const name = el("mesh-name").value.trim();
  const myName = el("mesh-myname").value.trim() || "me";
  const maxRaw = el("mesh-max").value.trim();
  const max = maxRaw === "" ? 254 : parseInt(maxRaw, 10);
  if (!name) return toast("mesh name required");
  if (Number.isNaN(max) || max < 1 || max > 254) return toast("max must be 1–254");
  try {
    const r = await meshd({ CreateMesh: { name, my_name: myName, max_members: max } });
    el("mesh-name").value = "";
    el("mesh-myname").value = "";
    toast(`mesh created (#${r.MeshCreated.mesh})`);
    CURRENT_MESH = r.MeshCreated.mesh;
    return setMode("mesh"); // jump straight into the new mesh
  } catch (e) { toast(String(e)); }
  refreshMode();
});

// sidebar "Meshes" item → user mode (the meshes list)
document.querySelector('.nav-item[data-tab="meshes"]')?.addEventListener("click", () => setMode("user"));

// ===== top widget bar: status (far left) + User/Mesh toggle + mesh dropdown =====
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
  sel.innerHTML = [`<option value="origin" ${!egress ? "selected" : ""}>Origin (your internet)</option>`]
    .concat(meshes.map((m) => `<option value="${m.id}" ${m.is_current ? "selected" : ""}>⬢ ${esc(m.name)} #${m.id}</option>`))
    .join("");
  // far-left status: mirror the current egress.
  if (egress) {
    dot.className = "conn-dot on";
    sum.textContent = `egress: ${egress.name}${egress.exit != null ? " · exit #" + egress.exit : ""}`;
  } else {
    dot.className = "conn-dot warn";
    sum.textContent = "egress: origin";
  }
}

// [User|Mesh] = view toggle.
document.querySelectorAll("#mode-toggle .seg-btn").forEach((b) =>
  b.addEventListener("click", () => setMode(b.dataset.mode))
);
// the dropdown = egress selector (Origin or a mesh); independent of the view.
el("tb-egress").addEventListener("change", async (e) => {
  const v = e.target.value;
  try {
    await meshd({ SetCurrent: { mesh: v === "origin" ? null : parseInt(v, 10) } });
    toast(v === "origin" ? "egress: origin" : "egress set");
  } catch (err) { toast(String(err)); }
  refreshMode();
});

setMode("user");
setInterval(refreshTopbar, 3000);

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
        { index: 0, priority: 100, matcher: "scope=overlay", action: "overlay-owner" },
        { index: 3, priority: 90, matcher: "proto=udp dport=53", action: "exit(39d55445)" },
        { index: 1, priority: 50, matcher: "scope=internet", action: "exit(configured)" },
        { index: 2, priority: 0, matcher: "*", action: "DROP" },
      ] : []);
    case "list_flows":
      return Promise.resolve(s.up ? [
        { peer: "demo", protocol: "TCP", local: "100.64.0.1:54012", remote: "100.64.0.2:22", tx_packets: 128, tx_bytes: 18432, rx_packets: 140, rx_bytes: 196608, last_active_secs: 0 },
        { peer: "demo", protocol: "ICMP", local: "100.64.0.1", remote: "100.64.0.2", tx_packets: 50, tx_bytes: 4200, rx_packets: 50, rx_bytes: 4200, last_active_secs: 2 },
        { peer: "demo", protocol: "UDP", local: "100.64.0.1:51820", remote: "100.64.0.2:443", tx_packets: 12, tx_bytes: 1536, rx_packets: 9, rx_bytes: 12000, last_active_secs: 40 },
      ] : []);
    case "meshd": return Promise.reject("meshd not running (browser demo)");
    default: return Promise.resolve(null);
  }
}
