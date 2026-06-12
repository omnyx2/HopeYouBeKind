// Lattice Admin Console — front-end logic.
// Talks to the daemon through the Tauri commands in src-tauri/src/main.rs.

const invoke = window.__TAURI__?.invoke;
if (!window.__TAURI__) {
  console.warn("Lattice Admin: Tauri API not found — running outside the app shell.");
}

const el = (id) => document.getElementById(id);
let isAdmin = false;

// ---- nav ----
document.querySelectorAll(".nav-item").forEach((b) => {
  if (b.disabled) return;
  b.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    document.querySelectorAll(".panel").forEach((p) => {
      p.classList.toggle("hidden", p.dataset.panel !== b.dataset.tab);
    });
  });
});

// ---- polling refresh ----
async function refresh() {
  const dot = el("conn-dot");
  const text = el("conn-text");
  let status = null;
  try {
    status = await invoke("get_status");
  } catch {
    dot.className = "conn-dot off";
    text.textContent = "daemon offline";
    el("ov-status").textContent = "unreachable";
    return;
  }
  dot.className = "conn-dot " + (status.running ? "on" : "warn");
  text.textContent = status.running ? "online" : "paused";

  // this node
  el("ov-status").textContent = status.running ? "mesh up" : "mesh down";
  setCopy("ov-vip", status.virtual_ip ?? "—");
  el("ov-fp").textContent = status.fingerprint ?? "—";
  setCopy("ov-nodeid", status.node_id ?? "—", (status.node_id ?? "").slice(0, 24) + "…");
  el("ov-public").textContent = status.public_addr ?? "not detected (LAN only)";

  // network info
  try {
    const net = await invoke("network_info");
    isAdmin = !!net.is_admin;
    const role = el("ov-role");
    if (net.network_id) {
      role.textContent = isAdmin ? "admin (holds CA)" : "member (read-only)";
      role.className = "badge " + (isAdmin ? "admin" : "readonly");
    } else {
      role.textContent = "open mode (no network)";
      role.className = "badge readonly";
    }
    setCopy("ov-netid", net.network_id ? `${net.fingerprint}… (${net.network_id.slice(0, 12)}…)` : "—", net.network_id || "—");
    el("ov-netid").dataset.full = net.network_id ?? "";
    el("ov-members").textContent = isAdmin ? String(net.member_count) : "— (admin only)";
    el("ov-revocations").textContent = String(net.revocation_count);
    el("not-admin").classList.toggle("hidden", isAdmin);
  } catch {
    /* leave as-is */
  }

  // peers
  try {
    const peers = await invoke("list_peers");
    el("ov-peercount").textContent = peers.length;
    renderPeers(peers);
  } catch {}

  // members (admin only — daemon refuses otherwise)
  if (isAdmin) {
    try {
      const members = await invoke("list_members");
      el("mem-count").textContent = members.length;
      renderMembers(members);
    } catch {
      renderMembers([]);
    }
  } else {
    el("mem-count").textContent = "0";
    renderMembers([]);
  }
}

function renderPeers(peers) {
  const tb = el("ov-peers");
  if (!peers.length) {
    tb.innerHTML = `<tr class="empty"><td colspan="5">No peers.</td></tr>`;
    return;
  }
  tb.innerHTML = "";
  for (const p of peers) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      `<td><span class="dot ${p.status}"></span>${p.status}</td>` +
      `<td class="mono">${p.virtual_ip}</td>` +
      `<td class="mono small">${p.fingerprint}</td>` +
      `<td class="small">${osLabel(p.os)}</td>` +
      `<td class="mono small">${p.endpoint ?? "—"}</td>`;
    tb.appendChild(tr);
  }
}

function renderMembers(members) {
  const tb = el("mem-rows");
  if (!members.length) {
    tb.innerHTML = `<tr class="empty"><td colspan="6">${isAdmin ? "No members enrolled." : "Members are visible to the network admin only."}</td></tr>`;
    return;
  }
  tb.innerHTML = "";
  for (const m of members) {
    const tr = document.createElement("tr");
    const status = m.revoked
      ? `<span class="badge revoked">revoked</span>`
      : `<span class="badge live">live</span>`;
    const action = m.revoked
      ? `<button class="danger" disabled>evicted</button>`
      : `<button class="danger" data-revoke="${m.node_id}" data-fp="${m.fingerprint}">Evict</button>`;
    tr.innerHTML =
      `<td class="mono small">${m.fingerprint}</td>` +
      `<td class="mono small copy" title="click to copy" data-copy="${m.node_id}">${m.node_id.slice(0, 18)}…</td>` +
      `<td class="right mono">${m.serial}</td>` +
      `<td>${m.label ? escapeHtml(m.label) : '<span class="muted small">—</span>'}</td>` +
      `<td>${status}</td>` +
      `<td class="right">${action}</td>`;
    tb.appendChild(tr);
  }
  // wire up revoke + copy
  tb.querySelectorAll("[data-revoke]").forEach((btn) => {
    btn.addEventListener("click", () => revoke(btn.dataset.revoke, btn.dataset.fp));
  });
  tb.querySelectorAll("[data-copy]").forEach((c) => {
    c.addEventListener("click", () => copy(c.dataset.copy));
  });
}

// ---- actions ----
el("issue-btn").addEventListener("click", async () => {
  const id = el("issue-id").value.trim();
  const label = el("issue-label").value.trim();
  if (id.length !== 64) {
    toast("Node ID must be 64 hex characters.");
    return;
  }
  el("issue-btn").disabled = true;
  try {
    const token = await invoke("issue_cert", { nodeId: id, label: label || null });
    el("token").textContent = token;
    el("token-box").classList.remove("hidden");
    el("issue-id").value = "";
    el("issue-label").value = "";
    toast("Token issued.");
    refresh();
  } catch (e) {
    toast(String(e));
  } finally {
    el("issue-btn").disabled = false;
  }
});

el("copy-token").addEventListener("click", () => copy(el("token").textContent));

async function revoke(nodeId, fp) {
  if (!confirm(`Evict member ${fp}?\n\nThis revokes its certificate and drops its session across the mesh on the next keepalive tick. The node must be re-enrolled to rejoin.`)) {
    return;
  }
  try {
    await invoke("revoke_member", { nodeId });
    toast(`Evicted ${fp}.`);
    refresh();
  } catch (e) {
    toast(String(e));
  }
}

// ---- helpers ----
function setCopy(id, shown, full) {
  const node = el(id);
  node.textContent = shown;
  node.dataset.full = full ?? shown;
}
document.querySelectorAll(".copy").forEach((c) => {
  c.addEventListener("click", () => {
    const v = c.dataset.full || c.textContent;
    if (v && v !== "—") copy(v);
  });
});

function osLabel(os) {
  if (!os) return "—";
  return { macos: "🍎 macOS", linux: "🐧 Linux", windows: "🪟 Windows" }[os] || os;
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

async function copy(textVal) {
  const t = String(textVal ?? "").trim();
  if (!t || t === "—") return;
  try {
    await navigator.clipboard.writeText(t);
  } catch {
    const ta = document.createElement("textarea");
    ta.value = t;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
  toast(`Copied ${t.length > 28 ? t.slice(0, 28) + "…" : t}`);
}

let toastTimer;
function toast(msg) {
  const t = el("toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add("hidden"), 2600);
}

refresh();
setInterval(refresh, 2000);
