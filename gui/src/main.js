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
    default: return Promise.resolve(null);
  }
}
