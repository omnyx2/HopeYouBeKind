// Lattice GUI — full control, no terminal needed.
//
// Polls the daemon over IPC (via Tauri commands) and renders live state. The
// "Start node" button launches the bundled daemon as root (one admin prompt);
// everything else — mesh on/off, peer list, copy IP — is one click.

const invoke = window.__TAURI__?.invoke ?? mockInvoke;

const el = (id) => document.getElementById(id);
let starting = false;

async function refresh() {
  let status = null;
  let reachable = true;
  try {
    status = await invoke("get_status");
  } catch {
    reachable = false;
  }

  const pill = el("state-pill");
  el("stopped-card").classList.toggle("hidden", reachable);
  el("running-card").classList.toggle("hidden", !reachable);
  el("peers-card").classList.toggle("hidden", !reachable);

  if (!reachable) {
    pill.textContent = starting ? "starting…" : "stopped";
    pill.className = "pill " + (starting ? "warn" : "off");
    return;
  }

  starting = false;
  const meshUp = !!status.running;
  pill.textContent = meshUp ? "online" : "paused";
  pill.className = "pill " + (meshUp ? "on" : "warn");

  el("virtual-ip").textContent = status.virtual_ip ?? "—";
  el("fingerprint").textContent = status.fingerprint ?? "—";
  el("mesh-toggle").checked = meshUp;

  let peers = [];
  try {
    peers = await invoke("list_peers");
  } catch {
    /* transient */
  }
  el("peer-count").textContent = `(${peers.length})`;
  const ul = el("peers");
  ul.innerHTML = "";
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
    right.className = "muted mono";
    right.textContent = p.fingerprint;
    li.appendChild(left);
    li.appendChild(right);
    ul.appendChild(li);
  }
}

el("start").addEventListener("click", async () => {
  starting = true;
  refresh();
  try {
    await invoke("start_daemon");
  } catch (e) {
    starting = false;
    toast(String(e));
  }
  // The daemon takes a moment to bind + STUN; poll until it answers.
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

el("virtual-ip").addEventListener("click", () => {
  const ip = el("virtual-ip").textContent;
  if (ip && ip !== "—") copy(ip);
});

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

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

refresh();
setInterval(refresh, 2000);

// ---- development mock (only when not running inside Tauri) ----
function mockInvoke(cmd) {
  const s = (mockInvoke.s ??= { up: false, mesh: true });
  switch (cmd) {
    case "start_daemon": s.up = true; return Promise.resolve();
    case "stop_daemon": s.up = false; return Promise.resolve();
    case "mesh_up": s.mesh = true; return Promise.resolve();
    case "mesh_down": s.mesh = false; return Promise.resolve();
    case "get_status":
      return s.up
        ? Promise.resolve({ running: s.mesh, virtual_ip: "100.95.128.129", fingerprint: "a3f1c290" })
        : Promise.reject("daemon not running");
    case "list_peers":
      return Promise.resolve(s.up ? [
        { virtual_ip: "100.86.168.223", fingerprint: "db16a8df", status: "connected" },
      ] : []);
    default: return Promise.resolve(null);
  }
}
