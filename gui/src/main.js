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

function renderTopology(d) {
  const c = el("topo-canvas");
  if (!c) return;
  const g = c.getContext("2d");
  const W = (c.width = c.clientWidth || 600);
  const H = (c.height = 360);
  g.clearRect(0, 0, W, H);
  const cx = W / 2, cy = H / 2;
  const me = d.members.find((m) => m.is_me);
  const others = d.members.filter((m) => !m.is_me);
  const R = Math.min(W, H) / 2 - 56;
  const pos = {};
  others.forEach((m, i) => {
    const a = (i / Math.max(1, others.length)) * Math.PI * 2 - Math.PI / 2;
    pos[m.id] = { x: cx + R * Math.cos(a), y: cy + R * Math.sin(a) };
  });
  // edges: me → each member; exit edge violet, live links green+solid, the rest faint.
  others.forEach((m) => {
    const p = pos[m.id];
    const isExit = d.exit === m.id;
    const live = m.state === "live";
    g.setLineDash(live || isExit ? [] : [4, 4]);
    g.strokeStyle = isExit ? "#a78bfa" : live ? "rgba(34,197,94,.6)" : "rgba(148,163,184,.25)";
    g.lineWidth = isExit ? 2.5 : live ? 2 : 1;
    g.beginPath(); g.moveTo(cx, cy); g.lineTo(p.x, p.y); g.stroke();
  });
  g.setLineDash([]);
  const node = (x, y, label, fill, r) => {
    g.beginPath(); g.arc(x, y, r, 0, 7);
    g.fillStyle = fill; g.fill();
    g.fillStyle = "#cbd5e1"; g.font = "11px ui-monospace, monospace"; g.textAlign = "center";
    g.fillText(label, x, y + r + 14);
  };
  // node colour by role/liveness: exit violet, live peer green, otherwise slate.
  others.forEach((m) => {
    const fill = d.exit === m.id ? "#a78bfa" : m.state === "live" ? "#22c55e" : "#475569";
    node(pos[m.id].x, pos[m.id].y, `${m.name} #${m.id}`, fill, 12);
  });
  node(cx, cy, me ? `${me.name} #${me.id}` : "me", "#3b82f6", 16);
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
    return `<tr><td>${m.id}</td><td>${esc(m.name)}${m.is_me ? ' <span class="muted small">(me)</span>' : ""}</td>` +
      `<td class="mono small">${m.pubkey_fp}</td><td>${role}</td><td>${badge}${ep}</td></tr>`;
  }).join("");
  el("peers-table").querySelector("tbody").innerHTML = rows;
}

document.querySelectorAll(".nav-item").forEach((b) =>
  b.addEventListener("click", () => {
    if (b.dataset.tab === "meshes") return setMode("user");
    activateTab(b.dataset.tab);
    if (CURRENT_MESH == null) return;
    if (b.dataset.tab === "mesh-topology") renderTopologyFor(CURRENT_MESH);
    if (b.dataset.tab === "mesh-peers") renderPeersFor(CURRENT_MESH);
  })
);

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
  try {
    const r = await meshd({ CreateMesh: { name, my_name: myName, max_members: max } });
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
  const exitOpts = [`<option value="">— none —</option>`].concat(
    d.members.map((mb) => `<option value="${mb.id}" ${d.exit === mb.id ? "selected" : ""}>#${mb.id} ${esc(mb.name)}</option>`)
  ).join("");
  el("mesh-detail").innerHTML = `
    <div class="card-head">
      <h2 class="card-title">⬢ ${esc(d.name)} <span class="muted small">#${d.id}</span></h2>
      <div>
        <button class="small-btn" id="ov-egress">make egress</button>
        <button class="small-btn" id="ov-wipe">wipe mesh</button>
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
      <select id="ov-exit" class="select">${exitOpts}</select>
      <button class="small-btn" id="ov-exit-set">set exit</button>
    </div>
    <h3 class="topo-h">Admit a member <span class="muted small">(demo)</span></h3>
    <div class="add-row">
      <input id="ov-admit-name" placeholder="name" />
      <input id="ov-admit-pk" placeholder="pubkey 64 hex (blank = random)" />
      <button class="small-btn" id="ov-admit">admit</button>
    </div>`;
  el("ov-egress").onclick = async () => {
    try { await meshd({ SetCurrent: { mesh: id } }); toast("set as egress"); } catch (e) { toast(String(e)); }
    refreshMode();
  };
  el("ov-wipe").onclick = async () => {
    if (!confirm(`Wipe mesh "${d.name}" locally? (the §5 compromise response)`)) return;
    try { await meshd({ RemoveMesh: { mesh: id } }); toast("mesh wiped"); } catch (e) { toast(String(e)); }
    CURRENT_MESH = null;
    setMode("user");
  };
  el("ov-exit-set").onclick = async () => {
    const v = el("ov-exit").value;
    try { await meshd({ SetExit: { mesh: id, exit: v === "" ? null : parseInt(v, 10) } }); toast("exit set"); } catch (e) { toast(String(e)); }
    refreshMode();
  };
  el("ov-admit").onclick = async () => {
    const name = el("ov-admit-name").value.trim();
    let pk = el("ov-admit-pk").value.trim();
    if (!name) return toast("name required");
    if (!/^[0-9a-fA-F]{64}$/.test(pk)) pk = randHex64();
    try { await meshd({ AdmitMember: { mesh: id, name, pubkey_hex: pk } }); toast("member admitted"); } catch (e) { toast(String(e)); }
    refreshMode();
  };
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

setMode("user");
setInterval(refreshTopbar, 3000);
// Live poll: keep the Peers/Topology connection state fresh while viewing them.
setInterval(() => {
  if (MODE !== "mesh" || CURRENT_MESH == null) return;
  if (ACTIVE_TAB === "mesh-peers") renderPeersFor(CURRENT_MESH);
  else if (ACTIVE_TAB === "mesh-topology") renderTopologyFor(CURRENT_MESH);
}, 3000);

// ---- browser demo (no Tauri): meshd is unreachable ----
function mockInvoke(cmd) {
  if (cmd === "meshd") return Promise.reject("meshd not running (browser demo)");
  return Promise.resolve(null);
}
