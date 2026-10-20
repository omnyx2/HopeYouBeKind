//! The extension/connector framework (docs/EXTENSIONS.md): per-connection
//! [`ConnSession`] auth + scope state, Hello/Subscribe handling with the live
//! grant re-check, the scope gate, and the management/registry handlers
//! (enable/advertise/unadvertise/list). 🟡 security-sensitive: grants are
//! re-checked on EVERY request/event so Disable works on live connections.
//! Pure code motion out of main.rs (Phase 2); behavior unchanged.

use crate::*;

/// Per-connection extension session (docs/EXTENSIONS.md §3). Plain GUI/CLI clients leave
/// this empty; a connector's `Hello` fills it and `Subscribe` attaches a forwarder.
#[derive(Default)]
pub(crate) struct ConnSession {
    /// Set once a valid `Hello` authenticated this connection as an extension. All
    /// authorization (scopes, per-mesh allow-list, `enabled`) is re-read from the LIVE grant
    /// (`State::extensions`) on every gated request/event — never snapshotted here — so
    /// `DisableExtension` / scope- or mesh-narrowing takes effect on an already-connected
    /// connector (docs/EXTENSIONS.md §3).
    pub(crate) ext_id: Option<String>,
    /// Abort handle for the event-forwarder task spawned by `Subscribe` (one per
    /// connection; a re-subscribe replaces it; connection close aborts it).
    pub(crate) sub_abort: Option<tokio::task::AbortHandle>,
}

/// Random 16-byte hex grant token (docs/EXTENSIONS.md §3). Local secret, not a network
/// credential — it only identifies which extension a local connection claims to be.
pub(crate) fn gen_token() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The scope a bus `topic` requires (docs/EXTENSIONS.md §4/§5). `None` = unknown topic.
pub(crate) fn scope_for_topic(topic: &str) -> Option<&'static str> {
    match topic {
        "peer" => Some("events:peer"),
        "exit" => Some("events:exit"),
        "health" => Some("events:health"),
        "service" => Some("registry:read"),
        _ => None,
    }
}

/// Authenticate a connector connection from its `Hello` (docs/EXTENSIONS.md §3): match the
/// token against the enabled grant for `id`, and on success bind the session to that grant
/// id. Scopes/meshes are NOT snapshotted — they're re-read from the live grant on every
/// gated request/event so a later disable/narrow takes effect. `version` is informational.
pub(crate) fn ext_hello(
    state: &Arc<Mutex<State>>,
    sess: &mut ConnSession,
    id: String,
    _version: String,
    token: String,
) -> Response {
    let st = state.lock().unwrap();
    match st.extensions.get(&id) {
        Some(g) if !g.enabled => err("extension is disabled"),
        Some(g) if g.token == token => {
            let scopes = g.scopes.clone();
            sess.ext_id = Some(id);
            Response::HelloOk { scopes }
        }
        Some(_) => err("invalid extension token"),
        None => err("unknown extension — enable it first"),
    }
}

/// Attach an event-forwarder to a `Subscribe`'d connection (docs/EXTENSIONS.md §5). Each
/// requested topic must map to a granted scope; on success a task drains the bus and pushes
/// scope-matching events (with a per-connection `seq`) onto the connection's outbound
/// channel. A lag drops events and emits a `_lagged` marker so the connector re-queries.
pub(crate) fn ext_subscribe(
    state: &Arc<Mutex<State>>,
    sess: &mut ConnSession,
    out_tx: &tokio::sync::mpsc::Sender<String>,
    topics: Vec<String>,
) -> Response {
    let Some(ext_id) = sess.ext_id.clone() else {
        return err("not authenticated — send Hello first");
    };
    // Validate the requested topics against the LIVE grant (so a just-narrowed grant is
    // honored at subscribe time too); the forwarder re-checks every event against it.
    let mut wanted: HashSet<String> = HashSet::new();
    {
        let st = state.lock().unwrap();
        let Some(g) = st.extensions.get(&ext_id).filter(|g| g.enabled) else {
            return err("extension is disabled");
        };
        for t in &topics {
            match scope_for_topic(t) {
                Some(scope) if g.scopes.iter().any(|s| s == scope) => {
                    wanted.insert(t.clone());
                }
                Some(scope) => return err(&format!("scope {scope} not granted for topic {t}")),
                None => return err(&format!("unknown topic {t}")),
            }
        }
    }
    let rx = match state.lock().unwrap().bus.as_ref() {
        Some(b) => b.subscribe(),
        None => return err("event bus unavailable"),
    };
    // One subscription per connection — a re-subscribe replaces the prior forwarder.
    if let Some(h) = sess.sub_abort.take() {
        h.abort();
    }
    let tx = out_tx.clone();
    let state = Arc::clone(state);
    let fwd = tokio::spawn(async move {
        use tokio::sync::broadcast::error::RecvError;
        use tokio::sync::mpsc::error::TrySendError;
        let mut rx = rx;
        let mut seq: u64 = 0;
        loop {
            let env = match rx.recv().await {
                Ok(ev) => {
                    if !wanted.contains(ev.topic) {
                        continue;
                    }
                    // Re-validate against the LIVE grant so DisableExtension / scope- or
                    // mesh-narrowing takes effect on this already-attached stream: a removed
                    // or disabled grant tears the stream down; a now-ungranted topic or an
                    // out-of-scope mesh just drops the event.
                    let decision = {
                        let st = state.lock().unwrap();
                        match st.extensions.get(&ext_id).filter(|g| g.enabled) {
                            None => None, // disabled / removed → stop forwarding
                            Some(g) => {
                                let scope_ok = scope_for_topic(ev.topic)
                                    .is_some_and(|sc| g.scopes.iter().any(|s| s == sc));
                                let mesh_ok = ev.mesh.map_or(true, |m| g.allows_mesh(m));
                                Some(scope_ok && mesh_ok)
                            }
                        }
                    };
                    match decision {
                        None => break,
                        Some(false) => continue,
                        Some(true) => {}
                    }
                    seq += 1;
                    Response::Event {
                        topic: ev.topic.to_string(),
                        seq,
                        ts_ms: ev.ts_ms,
                        data: ev.data,
                    }
                }
                Err(RecvError::Lagged(_)) => {
                    seq += 1;
                    Response::Event {
                        topic: "_lagged".to_string(),
                        seq,
                        ts_ms: now_ms(),
                        data: serde_json::json!({ "dropped": true }),
                    }
                }
                Err(RecvError::Closed) => break,
            };
            let line = match serde_json::to_string(&env) {
                Ok(s) => s,
                Err(_) => break,
            };
            // Bounded outbound queue: a connector that stops draining its socket must not
            // grow the daemon's memory without limit. Drop the event when the queue is full
            // — the jump in `seq` is the documented signal to the connector to re-query.
            match tx.try_send(line) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {}
                Err(TrySendError::Closed(_)) => break,
            }
        }
    });
    sess.sub_abort = Some(fwd.abort_handle());
    Response::Ok
}

/// **RISK 🟡 MED** — connector authorization; re-reads the LIVE grant (not a Hello-time snapshot)
/// so a disable/narrow takes effect on an open connection. A gap here = a privilege leak.
/// Deny connector-only requests that lack the required scope/auth/mesh (docs/EXTENSIONS.md
/// §3/§4). `None` = allowed. Management calls (Enable/Disable/List) stay open to trusted
/// local clients. `ListServices` is open to the management GUI (no `Hello`) but, for a
/// connector, is gated by `registry:read` + the per-mesh allow-list — so a connector can't
/// read services from a mesh it wasn't enabled for.
pub(crate) fn scope_gate(req: &Request, sess: &ConnSession, st: &State) -> Option<Response> {
    // Re-validate connector requests against the LIVE grant (not a Hello-time snapshot) so
    // DisableExtension / scope- or mesh-narrowing takes effect on an already-connected
    // connector (docs/EXTENSIONS.md §3). `None` once a connector is authenticated means its
    // grant was disabled or removed out from under it.
    let live = sess
        .ext_id
        .as_ref()
        .and_then(|id| st.extensions.get(id))
        .filter(|g| g.enabled);
    match req {
        Request::Advertise { mesh, .. } | Request::Unadvertise { mesh, .. } => {
            if sess.ext_id.is_none() {
                Some(err("not authenticated — send Hello first"))
            } else {
                match live {
                    None => Some(err("extension is disabled")),
                    Some(g) if !g.scopes.iter().any(|s| s == "registry:advertise") => {
                        Some(err("scope registry:advertise not granted"))
                    }
                    Some(g) if !g.allows_mesh(*mesh) => {
                        Some(err("extension not enabled for this mesh"))
                    }
                    Some(_) => None,
                }
            }
        }
        // A connector (authenticated) is mesh-gated; the management GUI (no Hello) is not.
        Request::ListServices { mesh, .. } if sess.ext_id.is_some() => match live {
            None => Some(err("extension is disabled")),
            Some(g) if !g.scopes.iter().any(|s| s == "registry:read") => {
                Some(err("scope registry:read not granted"))
            }
            Some(g) if !g.allows_mesh(*mesh) => Some(err("extension not enabled for this mesh")),
            Some(_) => None,
        },
        _ => None,
    }
}

/// Enable an extension and (re)grant it `scopes` + the meshes it may touch (`all_meshes`
/// or the `meshes` allow-list). A first enable mints a token; re-enabling keeps the existing
/// token so a running connector's `Hello` keeps working, and just updates the scope/mesh set
/// + flips `enabled` on. Returns the grant view (carries the token).
pub(crate) fn enable_extension(
    st: &mut State,
    id: String,
    scopes: Vec<String>,
    all_meshes: bool,
    mut meshes: Vec<MeshId>,
) -> Response {
    // Keep only meshes that actually exist on this node (drop stale/typo ids).
    meshes.retain(|m| st.meshes.contains_key(m));
    meshes.sort_unstable();
    meshes.dedup();
    let grant = st
        .extensions
        .entry(id.clone())
        .or_insert_with(|| ExtensionGrant {
            id,
            token: gen_token(),
            scopes: Vec::new(),
            enabled: false,
            all_meshes: false,
            meshes: Vec::new(),
        });
    grant.scopes = scopes;
    grant.all_meshes = all_meshes;
    grant.meshes = meshes;
    grant.enabled = true;
    Response::Extension(grant.view())
}

/// Advertise that THIS node offers `proto` on its overlay IP at `port` (docs/EXTENSIONS.md
/// §6). Supersedes our prior record for the same proto (bumped `seq`); the next gossip tick
/// carries it mesh-wide. Emits a `service` event so subscribed connectors re-query.
pub(crate) fn advertise(
    st: &mut State,
    mesh: MeshId,
    proto: String,
    port: u16,
    name: String,
    meta: serde_json::Value,
) -> Response {
    let now = now_ms();
    {
        let Some(ms) = st.meshes.get_mut(&mesh) else {
            return no_mesh(mesh);
        };
        let member = ms.my_id();
        ms.service_seq += 1;
        let rec = ServiceRecord {
            member,
            proto: proto.clone(),
            port,
            name,
            meta,
            seq: ms.service_seq,
        };
        match ms
            .services
            .iter_mut()
            .find(|e| e.rec.member == member && e.rec.proto == proto)
        {
            Some(e) => {
                e.rec = rec;
                e.last_refresh_ms = now;
            }
            None => {
                if ms.services.len() >= MAX_SERVICES {
                    return err("service registry full");
                }
                ms.services.push(ServiceEntry {
                    rec,
                    last_refresh_ms: now,
                });
            }
        }
    }
    emit(
        st,
        "service",
        Some(mesh),
        serde_json::json!({ "kind": "advertised", "mesh": mesh, "proto": proto }),
    );
    Response::Ok
}

/// Withdraw a service this node advertised (docs/EXTENSIONS.md §6). Removed locally and no
/// longer gossiped; peers expire it after [`registry::SERVICE_TTL_MS`].
pub(crate) fn unadvertise(st: &mut State, mesh: MeshId, proto: String) -> Response {
    {
        let Some(ms) = st.meshes.get_mut(&mesh) else {
            return no_mesh(mesh);
        };
        let member = ms.my_id();
        let before = ms.services.len();
        ms.services
            .retain(|e| !(e.rec.member == member && e.rec.proto == proto));
        if ms.services.len() == before {
            return err("no such advertised service");
        }
    }
    emit(
        st,
        "service",
        Some(mesh),
        serde_json::json!({ "kind": "withdrawn", "mesh": mesh, "proto": proto }),
    );
    Response::Ok
}

/// Discover services advertised in `mesh` (optionally one `proto`), each resolved to the
/// owner's overlay IP + online state (docs/EXTENSIONS.md §6). Expired peer entries are
/// hidden; our own entries never expire.
pub(crate) fn list_services(st: &State, mesh: MeshId, proto: Option<String>) -> Response {
    let Some(ms) = st.meshes.get(&mesh) else {
        return no_mesh(mesh);
    };
    let now = now_ms();
    let me = ms.my_id();
    let p = ms.mesh.charter.overlay_prefix;
    let roster = ms.roster();
    let links = ms.links.lock().unwrap();
    let mut out = Vec::new();
    for e in &ms.services {
        if let Some(f) = &proto {
            if &e.rec.proto != f {
                continue;
            }
        }
        if e.rec.member != me && now.saturating_sub(e.last_refresh_ms) >= registry::SERVICE_TTL_MS {
            continue;
        }
        let member_name = roster
            .iter()
            .find(|c| c.id == e.rec.member)
            .map(|c| c.name.clone())
            .unwrap_or_default();
        let online = e.rec.member == me
            || links
                .get(&e.rec.member)
                .map(|l| l.last_seen_ms != 0 && now.saturating_sub(l.last_seen_ms) < LIVE_WINDOW_MS)
                .unwrap_or(false);
        out.push(ServiceView {
            mesh,
            member: e.rec.member,
            member_name,
            overlay_ip: format!("{}.{}.{}.{}", p[0], p[1], ms.mesh.id, e.rec.member),
            proto: e.rec.proto.clone(),
            port: e.rec.port,
            name: e.rec.name.clone(),
            meta: e.rec.meta.clone(),
            online,
        });
    }
    Response::Services(out)
}
