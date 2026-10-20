//! The daemon's background loops: periodic roster/flows/registry gossip, the
//! network-change watcher (re-route + re-advertise on interface change), DHT
//! re-discovery of moved peers, and the P-C4/P-C7 self-destruct watchdog.
//! Each is a `tokio::spawn` loop over `Arc<Mutex<State>>`.
//! Pure code motion out of main.rs (Phase 2); behavior unchanged.

use crate::*;

/// Membership roster gossip. Every `ROSTER_GOSSIP_TICK_SECS`, send each mesh's validated
/// roster (signed certs) to its peers; the receiver merges any new, valid cert. Endpoints
/// already gossip (P-D2) but the **roster** did not — so a node admitted via one member
/// never reached the others. This closes that: membership converges like endpoints do.
/// (One UDP frame per mesh; fine for small meshes — large rosters would need chunking.)
pub(crate) fn spawn_roster_gossip(state: Arc<Mutex<State>>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(ROSTER_GOSSIP_TICK_SECS)).await;
            let sends: Vec<(u8, Vec<u8>, Vec<MemberId>, UnboundedSender<LoopCmd>)> = {
                let mut st = state.lock().unwrap();
                // Drop peer service records that stopped refreshing (crash / unadvertise)
                // before building this round's gossip (docs/EXTENSIONS.md §6).
                let now = now_ms();
                for ms in st.meshes.values_mut() {
                    let me = ms.my_id();
                    registry::expire(&mut ms.services, me, now);
                }
                st.meshes
                    .values()
                    .flat_map(|ms| {
                        let mut out = Vec::new();
                        let Some(tx) = ms.loop_cmd.clone() else {
                            return out;
                        };
                        let peers: Vec<MemberId> =
                            ms.links.lock().unwrap().keys().copied().collect();
                        if peers.is_empty() {
                            return out;
                        }
                        // Roster (signed certs) — converges membership across the mesh. Cert-only
                        // (no synthetic quick rows) so the wire is byte-identical to older nodes.
                        let certs = ms.cert_roster();
                        if certs.len() >= 2 {
                            if let Ok(body) = bincode::serialize(&certs) {
                                out.push((CTRL_ROSTER, body, peers.clone(), tx.clone()));
                            }
                        }
                        // Revocations (signed expulsions) — converges expulsions the same way.
                        if !ms.revocations.is_empty() {
                            if let Ok(body) = bincode::serialize(&ms.revocations) {
                                out.push((CTRL_REVOKE, body, peers.clone(), tx.clone()));
                            }
                        }
                        // Quick-invite members (self-registered under a Grant) — a SEPARATE channel
                        // (CTRL_QGRANT); old nodes ignore it, keeping the classic roster untouched.
                        if !ms.grant_certs.is_empty() {
                            if let Ok(body) = bincode::serialize(&ms.grant_certs) {
                                out.push((CTRL_QGRANT, body, peers.clone(), tx.clone()));
                            }
                        }
                        // SDN flow table — only once edited away from the default (version > 0);
                        // newest version wins, so periodic re-gossip heals any node that missed it.
                        if ms.flow_version > 0 {
                            if let Ok(enc) = bincode::serialize(&ms.flows) {
                                let mut body = ms.flow_version.to_be_bytes().to_vec();
                                body.extend_from_slice(&enc);
                                out.push((CTRL_FLOWS, body, peers.clone(), tx.clone()));
                            }
                        }
                        // Service registry — gossip only OUR OWN advertised services (never
                        // re-broadcast peers', or a crashed node's record would never die).
                        // Each node advertises its own; peers expire what stops arriving.
                        let me = ms.my_id();
                        let own: Vec<ServiceRecord> = ms
                            .services
                            .iter()
                            .filter(|e| e.rec.member == me)
                            .map(|e| e.rec.clone())
                            .collect();
                        if !own.is_empty() {
                            if let Ok(body) = serde_json::to_vec(&own) {
                                out.push((CTRL_REGISTRY, body, peers, tx));
                            }
                        }
                        out
                    })
                    .collect()
            };
            for (tag, body, peers, tx) in sends {
                let _ = tx.send(LoopCmd::SendControl(tag, body, peers));
            }
        }
    });
}

/// Self-heal across **network changes** (docs/DYNAMIC_NETWORK.md). A laptop/desktop/server
/// can get a new IP from sleep/wake, Wi-Fi↔cellular roaming, or a new network after an
/// outage. On each default-gateway change this:
/// 1. **cleans a now-stale exit `/32` pin** — pinned via the OLD gateway it blackholes the
///    exit's IP (a connect to it fails with `EADDRNOTAVAIL`) even with full-tunnel off — or
///    **re-pins it via the NEW gateway** if full-tunnel is on, so the tunnel survives roaming;
/// 2. **re-learns our local address** and writes it to each mesh's advertised endpoint, so the
///    next gossip/DHT tick tells every peer our new address and they re-discover us.
///
/// The data-plane socket is bound to the wildcard, so it keeps working across the change;
/// only routes + the advertised address need refreshing. A pinned public node
/// (`MESHD_ADVERTISE`) never re-learns its address.
pub(crate) fn spawn_netchange_watcher(state: Arc<Mutex<State>>) {
    let pinned = std::env::var("MESHD_ADVERTISE").is_ok();
    tokio::spawn(async move {
        // Start from `None` so the first tick also cleans any leftover pin from a prior run.
        let mut last_gw: Option<String> = None;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(NETCHANGE_TICK_SECS)).await;
            let gw = tokio::task::spawn_blocking(exit::current_gateway)
                .await
                .ok()
                .flatten();
            // `None` means either full-tunnel has diverted the default route through our own
            // mesh tun (the gateway is then a link/interface, not an IP — see
            // `macos_default_gateway`) or there is momentarily no network. Either way there is
            // no *physical* gateway to re-pin to, and self-healing here would fight the
            // full-tunnel route the kill-switch already manages. Idle until a real underlay
            // gateway reappears (full-tunnel off, or roamed onto a new network), keeping the
            // last physical gateway so a later toggle back to it is a no-op, not a false change.
            let Some(_) = gw else {
                continue;
            };
            if gw == last_gw {
                continue;
            }
            elog!("meshd: network change — default gateway {last_gw:?} -> {gw:?}; self-healing");
            last_gw = gw;
            // (1) Re-assert (full-tunnel on) or clean (off) the exit pin via the new gateway.
            let full_tunnel: Option<(String, std::net::IpAddr)> = {
                let st = state.lock().unwrap();
                // Only re-assert the full-tunnel diversion after a network change if we are
                // actually full-tunnelling — a split-tunnel selection (`current` set, general
                // traffic direct) must NOT get its default route diverted here.
                st.current.filter(|_| st.full_tunnel).and_then(|id| {
                    let ms = st.meshes.get(&id)?;
                    let exit_id = ms.mesh.exit?;
                    let tun = ms.tun_name.clone()?;
                    let ip = ms
                        .links
                        .lock()
                        .unwrap()
                        .get(&exit_id)
                        .map(|l| l.endpoint.ip())?;
                    Some((tun, ip))
                })
            };
            let route_res = tokio::task::spawn_blocking(move || match full_tunnel {
                Some((tun, ip)) => {
                    exit::clear_exit_pin();
                    Some(exit::route_through(&tun, ip))
                }
                None => {
                    exit::clear_exit_pin();
                    None
                }
            })
            .await;
            // Don't let a failed re-route after a network change look like success:
            // record it on the current mesh so `lattice info` / the GUI show it.
            if let Ok(Some(Err(e))) = route_res {
                let mut st = state.lock().unwrap();
                if let Some(id) = st.current {
                    if let Some(ms) = st.meshes.get_mut(&id) {
                        ms.dp_error = Some(format!(
                            "full-tunnel re-route after network change failed: {e}"
                        ));
                    }
                }
            }
            // (2) Re-learn our local address so peers re-find us (unless a pinned public node).
            if !pinned {
                if let Some(ip) = local_ip() {
                    let st = state.lock().unwrap();
                    for ms in st.meshes.values() {
                        let mut me = ms.my_endpoint.lock().unwrap();
                        let port = me
                            .map(|a| a.port())
                            .filter(|p| *p != 0)
                            .unwrap_or(ms.dp_port);
                        if port != 0 {
                            *me = Some(SocketAddr::new(ip, port));
                        }
                    }
                    elog!("meshd: re-learned local address {ip} after network change");
                }
            }
        }
    });
}

/// DHT rendezvous reconnect loop (`MESHD_DHT=1`, docs/DHT_RENDEZVOUS.md). Every
/// `DHT_RECONNECT_TICK_SECS`: (1) **republish** our own signed endpoint record for each
/// mesh so a moved peer can re-find us, and (2) for each roster member we have **no fresh
/// endpoint** for, DHT-**look up** their record and seed the endpoint into the peer table
/// — the same seam `SetPeer`/gossip use. This is what closes the "both moved with no
/// overlap" gap that first-contact discovery (P-D1..D4) can't. All work is snapshotted
/// under the lock and the network round-trips happen lock-free.
pub(crate) fn spawn_dht_reconnect(state: Arc<Mutex<State>>) {
    struct Work {
        mesh: MeshId,
        network: PubKey,
        my_seed: [u8; 32],
        my_endpoint: Option<SocketAddr>,
        /// roster members with no fresh endpoint: (member id, their pubkey).
        missing: Vec<(MemberId, PubKey)>,
    }
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(DHT_RECONNECT_TICK_SECS)).await;
            let Some(dht) = state.lock().unwrap().dht.clone() else {
                continue;
            };
            let now = now_ms();
            let work: Vec<Work> = {
                let st = state.lock().unwrap();
                st.meshes
                    .values()
                    .map(|ms| {
                        let me = ms.my_id();
                        let links = ms.links.lock().unwrap();
                        let missing = ms
                            .roster()
                            .into_iter()
                            .filter(|c| c.id != me)
                            .filter(|c| match links.get(&c.id) {
                                Some(l) => {
                                    l.last_seen_ms == 0
                                        || now.saturating_sub(l.last_seen_ms) >= LIVE_WINDOW_MS
                                }
                                None => true,
                            })
                            .map(|c| (c.id, c.member))
                            .collect();
                        Work {
                            mesh: ms.mesh.id,
                            network: ms.mesh.charter.master_pubkey,
                            my_seed: ms.my_key.to_seed(),
                            my_endpoint: *ms.my_endpoint.lock().unwrap(),
                            missing,
                        }
                    })
                    .collect()
            };
            for w in work {
                // (1) Republish our current endpoint so peers that lost us can re-find it.
                if let Some(ep) = w.my_endpoint {
                    let key = MemberKey::from_seed(&w.my_seed);
                    let rec = key.publish_endpoints(w.network, vec![ep], now, now);
                    dht.publish(&rec).await;
                }
                // (2) Re-discover each member we can't currently reach.
                for (mid, pk) in w.missing {
                    let Some(rec) = dht.lookup(pk).await else {
                        continue;
                    };
                    // verify() (sig + member) already passed inside lookup; require the
                    // record to belong to THIS mesh before trusting its endpoint.
                    if rec.network != w.network {
                        continue;
                    }
                    if let Some(&ep) = rec.endpoints.first() {
                        let st = state.lock().unwrap();
                        if let Some(ms) = st.meshes.get(&w.mesh) {
                            ms.links
                                .lock()
                                .unwrap()
                                .entry(mid)
                                .or_insert(Link {
                                    endpoint: ep,
                                    last_seen_ms: 0,
                                    last_direct_ms: 0,
                                })
                                .endpoint = ep;
                        }
                        elog!(
                            "meshd: DHT re-discovered mesh {} member {mid} at {ep}",
                            w.mesh
                        );
                    }
                }
            }
        }
    });
}

/// Live-paired self-destruct (P-C4, docs/PROTOCOL_DESIGN.md §5-2): once a mesh has
/// been healthy (≥ the live threshold), if it then sits **below** the threshold for
/// `SELF_DESTRUCT_GRACE_SECS`, the secret is (by the threshold-sharing model)
/// unrecoverable — so we wipe it and drop the mesh. A still-forming mesh (never yet
/// at quorum) is exempt, so onboarding doesn't trip it. `MESHD_NO_SELF_DESTRUCT=1`
/// disables it. (v1 = cooperative wipe; true never-hold-the-secret Shamir sharing is
/// P-C4b.)
pub(crate) fn spawn_self_destruct_watchdog(mesh_id: MeshId, state: Arc<Mutex<State>>) {
    if std::env::var("MESHD_NO_SELF_DESTRUCT").is_ok() {
        return;
    }
    tokio::spawn(async move {
        let mut established = false;
        let mut below_since: Option<u64> = None;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(SELF_DESTRUCT_TICK_SECS)).await;
            let now = now_ms();
            let mut st = state.lock().unwrap();
            let Some(ms) = st.meshes.get(&mesh_id) else {
                return; // mesh already gone (RemoveMesh / earlier self-destruct)
            };
            let armed = ms.attack_armed_at;
            let n = ms.roster().len().max(1);
            let live = 1 + ms
                .links
                .lock()
                .unwrap()
                .values()
                .filter(|l| {
                    l.last_seen_ms != 0 && now.saturating_sub(l.last_seen_ms) < LIVE_WINDOW_MS
                })
                .count();
            let threshold = quorum_threshold(n);

            // P-C7: an attack alert that the creator never cleared ⇒ fail-deadly.
            let attack =
                matches!(armed, Some(t) if now.saturating_sub(t) >= ATTACK_GRACE_SECS * 1000);

            // P-C4: an established mesh that has sat below the live threshold past grace.
            // Opt-in per mesh (charter.self_destruct): a laptop-friendly mesh leaves this
            // off so a sleeping member never nukes the keys; only `OnIsolation` arms it.
            let liveness_armed =
                ms.mesh.charter.self_destruct == lattice_mesh::charter::SelfDestruct::OnIsolation;
            let mut starved = false;
            if live >= threshold {
                established = true;
                below_since = None;
            } else if established && liveness_armed {
                let since = *below_since.get_or_insert(now);
                starved = now.saturating_sub(since) >= SELF_DESTRUCT_GRACE_SECS * 1000;
            }

            if !attack && !starved {
                continue;
            }
            let reason = if attack {
                format!("attack alert un-cleared after {ATTACK_GRACE_SECS}s (one-veto, P-C7)")
            } else {
                format!("live {live}/{n} below threshold {threshold} for {SELF_DESTRUCT_GRACE_SECS}s (live-paired, P-C4)")
            };
            elog!("meshd: mesh {mesh_id} SELF-DESTRUCT — {reason}");
            if let Some(mut gone) = st.meshes.remove(&mesh_id) {
                gone.secret.iter_mut().for_each(|byte| *byte = 0); // wipe the secret
                if let Some(t) = &gone.dp_task {
                    t.abort();
                }
                if st.current == Some(mesh_id) {
                    st.current = None;
                    exit::restore_routes();
                    exit::restore_dns();
                }
            }
            persist(&st); // P-S1: erase the on-disk copy too (keeps the ephemeral property)
            persist_egress(&st); // if the destroyed mesh was the full-tunnel egress, forget it
            return;
        }
    });
}

/// Drain one mesh's data-plane loop events — a re-cipher landing (sync our stored
/// secret/epoch/cipher), a P-C7 attack signal (arm / cancel the destroy grace), or
/// a gossip merge (roster certs / revocations / flow table / service registry /
/// quick-invite members). Each arm mutates `MeshState` under the global lock and
/// flags persist/emit work for after the `&mut` borrow ends.
/// Extracted verbatim from `bringup_dataplane` (Phase 2); behavior unchanged.
pub(crate) fn spawn_loop_event_drain(
    mesh_id: MeshId,
    state: Arc<Mutex<State>>,
    mut applied_rx: tokio::sync::mpsc::UnboundedReceiver<LoopEvent>,
) {
    let st = state;
    let mid = mesh_id;
    tokio::spawn(async move {
        while let Some(ev) = applied_rx.recv().await {
            let mut state = st.lock().unwrap();
            let Some(ms) = state.meshes.get_mut(&mid) else {
                continue;
            };
            let mut persist_after = false;
            // Deferred event emits: `ms` (a &mut into `state`) is alive across the match,
            // so we can't borrow `state` for `emit` until after it. NLL frees `ms` once the
            // match ends, so we flag here and emit below.
            let mut emit_peer = false;
            let mut emit_service = false;
            match ev {
                LoopEvent::Recipher(r) => {
                    ms.secret = r.secret;
                    ms.epoch = r.epoch;
                    ms.mesh.epoch = r.epoch;
                    ms.cipher = r.cipher;
                    persist_after = true; // P-S1: the new secret must reach disk
                }
                LoopEvent::Control(CTRL_ATTACK) => {
                    if ms.attack_armed_at.is_none() {
                        elog!("meshd: mesh {mid} ATTACK ALERT received — destroy grace armed ({ATTACK_GRACE_SECS}s; creator can all-clear)");
                        ms.attack_armed_at = Some(now_ms());
                    }
                }
                LoopEvent::Control(CTRL_ALLCLEAR) => {
                    if ms.attack_armed_at.take().is_some() {
                        elog!("meshd: mesh {mid} ALL-CLEAR received — destroy grace cancelled");
                    }
                }
                LoopEvent::Control(_) => {}
                // A peer gossiped its roster — merge any new cert for THIS mesh that we
                // don't already hold; `roster()` re-validates the chain to the master, so
                // pushing is safe (an invalid cert just never counts). This is what makes
                // a member added via a third node propagate to everyone.
                LoopEvent::Roster(bytes) => {
                    if bytes.len() <= MAX_GOSSIP_BYTES {
                        if let Ok(incoming) = bincode::deserialize::<Vec<Cert>>(&bytes) {
                            let net = ms.mesh.charter.master_pubkey;
                            let before = ms.roster().len();
                            for c in incoming {
                                if ms.certs.len() >= MAX_ROSTER_CERTS {
                                    elog!("meshd: mesh {mid} roster cert cap ({MAX_ROSTER_CERTS}) reached — dropping further gossiped certs");
                                    break;
                                }
                                if c.network == net
                                    && !ms
                                        .certs
                                        .iter()
                                        .any(|h| h.member == c.member && h.id == c.id)
                                {
                                    ms.certs.push(c);
                                }
                            }
                            let after = ms.roster().len();
                            if after > before {
                                elog!(
                                    "meshd: mesh {mid} roster grew {before} -> {after} via gossip"
                                );
                                persist_after = true;
                                emit_peer = true;
                            }
                        }
                    }
                }
                // A peer gossiped revocations — merge new ones (and fold co-signers into an
                // existing one, so a quorum expulsion accumulates votes). `roster()`
                // re-checks authorization, so an unauthorized revocation simply never bites.
                LoopEvent::Revoke(bytes) => {
                    if bytes.len() <= MAX_GOSSIP_BYTES {
                        if let Ok(incoming) = bincode::deserialize::<Vec<Revocation>>(&bytes) {
                            let net = ms.mesh.charter.master_pubkey;
                            let before = ms.roster().len();
                            let mut changed = false;
                            for r in incoming {
                                if r.network != net {
                                    continue;
                                }
                                match ms.revocations.iter_mut().find(|e| e.member == r.member) {
                                    Some(existing) => changed |= existing.merge_signers(&r),
                                    None => {
                                        if ms.revocations.len() >= MAX_REVOCATIONS {
                                            elog!("meshd: mesh {mid} revocation cap ({MAX_REVOCATIONS}) reached — dropping further gossiped revocations");
                                            break;
                                        }
                                        ms.revocations.push(r);
                                        changed = true;
                                    }
                                }
                            }
                            let after = ms.roster().len();
                            if changed {
                                persist_after = true;
                                emit_peer = true;
                                if after < before {
                                    elog!("meshd: mesh {mid} roster shrank {before} -> {after} via revocation gossip");
                                }
                            }
                        }
                    }
                }
                // A peer gossiped its SDN flow table (`version(8 BE) ‖ bincode(flows)`).
                // Newest version wins; ties are ignored. On adopting a newer table we
                // store it, persist it, and push it down to the live data plane.
                LoopEvent::Flows(bytes) => {
                    if (8..=MAX_GOSSIP_BYTES).contains(&bytes.len()) {
                        let mut v = [0u8; 8];
                        v.copy_from_slice(&bytes[..8]);
                        let version = u64::from_be_bytes(v);
                        if version > ms.flow_version {
                            if let Ok(flows) = bincode::deserialize::<Vec<FlowRule>>(&bytes[8..]) {
                                if flows.len() > MAX_FLOW_RULES {
                                    elog!("meshd: mesh {mid} ignored gossiped flow table v{version} — {} rules exceeds cap {MAX_FLOW_RULES}", flows.len());
                                    continue;
                                }
                                elog!(
                                    "meshd: mesh {mid} adopted flow table v{version} ({} rules) via gossip",
                                    flows.len()
                                );
                                ms.flow_version = version;
                                ms.flows = flows.clone();
                                if let Some(tx) = &ms.loop_cmd {
                                    let _ = tx.send(LoopCmd::SetFlows(flows));
                                }
                                persist_after = true;
                            }
                        }
                    }
                }
                // A peer gossiped its advertised services — merge them (soft state,
                // newest-per-(member, proto) wins) so the registry converges mesh-wide. Not
                // persisted; a `service` event tells subscribed connectors to re-query.
                LoopEvent::Registry(bytes) => {
                    if bytes.len() <= MAX_GOSSIP_BYTES {
                        if let Ok(incoming) = serde_json::from_slice::<Vec<ServiceRecord>>(&bytes) {
                            let me = ms.my_id();
                            // Don't let a peer's batch overwrite our OWN records.
                            let incoming = incoming.into_iter().filter(|r| r.member != me);
                            if registry::merge(&mut ms.services, incoming, now_ms(), MAX_SERVICES) {
                                emit_service = true;
                            }
                        }
                    }
                }
                // A peer gossiped quick-invite members (self-registered under a Grant) — merge any
                // new record for THIS mesh; `roster()` re-validates via `grant_members`, so an
                // invalid/surplus one simply never counts (docs/JOIN_MODES.md).
                LoopEvent::Quick(bytes) => {
                    if bytes.len() <= MAX_GOSSIP_BYTES {
                        if let Ok(incoming) = bincode::deserialize::<Vec<GrantCert>>(&bytes) {
                            let net = ms.mesh.charter.master_pubkey;
                            let before = ms.roster().len();
                            for q in incoming {
                                if ms.grant_certs.len() >= MAX_ROSTER_CERTS {
                                    break;
                                }
                                if q.grant.network == net
                                    && !ms
                                        .grant_certs
                                        .iter()
                                        .any(|h| h.member == q.member && h.id == q.id)
                                {
                                    ms.grant_certs.push(q);
                                }
                            }
                            if ms.roster().len() > before {
                                persist_after = true;
                                emit_peer = true;
                            }
                        }
                    }
                }
            }
            if persist_after {
                persist(&state);
            }
            // `ms` is dead after the match (NLL), so `state` can be shared-borrowed now.
            if emit_peer {
                emit(
                    &state,
                    "peer",
                    Some(mid),
                    serde_json::json!({ "kind": "roster_changed", "mesh": mid }),
                );
            }
            if emit_service {
                emit(
                    &state,
                    "service",
                    Some(mid),
                    serde_json::json!({ "kind": "changed", "mesh": mid }),
                );
            }
        }
    });
}
