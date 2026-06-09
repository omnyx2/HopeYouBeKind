// Lattice GUI front-end.
//
// The browser layer never touches the network. It calls Tauri commands (Rust,
// in src-tauri) which forward to the daemon over IPC. While the daemon's IPC
// server is still being built (ROADMAP v0.4), `invoke` falls back to a local
// mock so the UI is fully clickable during development.

const invoke = window.__TAURI__?.invoke ?? mockInvoke;

let running = false;

async function refresh() {
  const status = await invoke("get_status");
  document.getElementById("virtual-ip").textContent = status.virtual_ip ?? "—";
  document.getElementById("fingerprint").textContent = status.fingerprint ?? "—";
  running = status.running;

  const pill = document.getElementById("state-pill");
  pill.textContent = running ? "online" : "offline";
  pill.className = "pill " + (running ? "on" : "off");
  document.getElementById("toggle").textContent = running ? "Disconnect mesh" : "Connect mesh";

  const peers = await invoke("list_peers");
  document.getElementById("peer-count").textContent = `(${peers.length})`;
  const ul = document.getElementById("peers");
  ul.innerHTML = "";
  for (const p of peers) {
    const li = document.createElement("li");
    li.innerHTML =
      `<span><span class="dot ${p.status}"></span><span class="mono">${p.virtual_ip}</span></span>` +
      `<span class="muted mono">${p.fingerprint}</span>`;
    ul.appendChild(li);
  }
}

document.getElementById("toggle").addEventListener("click", async () => {
  await invoke(running ? "mesh_down" : "mesh_up");
  await refresh();
});

refresh();

// ---- development mock (removed once the real daemon IPC is wired) ----
function mockInvoke(cmd) {
  const state = (mockInvoke.state ??= {
    running: false,
    virtual_ip: "100.64.12.8",
    fingerprint: "a3f1c290",
    peers: [
      { virtual_ip: "100.64.31.2", fingerprint: "9b22ef10", status: "connected" },
      { virtual_ip: "100.64.7.55", fingerprint: "12aa90fe", status: "known" },
    ],
  });
  switch (cmd) {
    case "mesh_up": state.running = true; return Promise.resolve();
    case "mesh_down": state.running = false; return Promise.resolve();
    case "get_status": return Promise.resolve({
      running: state.running,
      virtual_ip: state.running ? state.virtual_ip : null,
      fingerprint: state.fingerprint,
    });
    case "list_peers": return Promise.resolve(state.running ? state.peers : []);
    default: return Promise.resolve(null);
  }
}
