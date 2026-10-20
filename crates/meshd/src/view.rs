//! Read-only view projection: MeshState/State → the IPC DTOs the GUI/CLI render
//! ([`detail`], traffic views) plus the tiny response helpers. Never mutates —
//! safe to call under the State lock.
//! Pure code motion out of main.rs (Phase 2); behavior unchanged.

use crate::*;

/// 🟡 Project a `MeshState` into the IPC `MeshDetail` (members, health, exit, policy) for `MeshInfo`.
pub(crate) fn detail(ms: &MeshState) -> MeshDetail {
    let me = ms.my_key.pubkey();
    let now = now_ms();
    // Snapshot decrypt-fail stats (frames from a known endpoint that didn't open). A
    // recent fail from a member's endpoint IP is the "different mesh / different epoch"
    // signal — it turns an opaque `idle` into an explained one and raises a warning.
    let fails = ms.decrypt_fails.lock().unwrap().clone();
    let links = ms.links.lock().unwrap();
    // IPs that have a currently-live member: we ARE decrypting frames from them, so a
    // decrypt fail on that IP is a DIFFERENT sender sharing the same NAT/public IP — not
    // this peer. Suppress decrypt-fail attribution for those IPs, so two members behind one
    // NAT (or a stray node on a shared campus NAT) don't raise a false split-brain warning.
    let live_ips: std::collections::HashSet<std::net::IpAddr> = links
        .values()
        .filter(|l| l.last_seen_ms != 0 && now.saturating_sub(l.last_seen_ms) < LIVE_WINDOW_MS)
        .map(|l| l.endpoint.ip())
        .collect();
    let recent_fail = |ip: std::net::IpAddr| -> Option<u64> {
        if live_ips.contains(&ip) {
            return None;
        }
        fails.get(&ip).and_then(|s: &DecryptFailStat| {
            (s.count > 0 && now.saturating_sub(s.last_ms) < DECRYPT_FAIL_WINDOW_MS)
                .then_some(s.count)
        })
    };
    let members: Vec<MemberView> = ms
        .roster()
        .iter()
        .map(|c| {
            let is_me = c.member == me;
            let link = links.get(&c.id).copied();
            // For peers, where we currently reach them. For us, our real physical LAN
            // address (NIC list, not a route lookup) so the topology places us on our true
            // network even when full-tunnel diverts the default route; fall back to the
            // advertised/reflexive address only if no LAN address is found.
            let endpoint = if is_me {
                local_lan_ipv4()
                    .map(|ip| format!("{ip}:{}", ms.dp_port))
                    .or_else(|| ms.my_endpoint.lock().unwrap().map(|a| a.to_string()))
            } else {
                link.map(|l| l.endpoint.to_string())
            };
            // `state` is the legacy badge ({me,live,idle,unknown}); `reason` explains an
            // idle/unknown peer in plain language so the user isn't left guessing why.
            let (state, reason): (String, Option<String>) = if is_me {
                ("me".into(), None)
            } else {
                match link {
                    Some(l)
                        if l.last_seen_ms != 0
                            && now.saturating_sub(l.last_seen_ms) < LIVE_WINDOW_MS =>
                    {
                        ("live".into(), None)
                    }
                    Some(l) => {
                        let why = if let Some(n) = recent_fail(l.endpoint.ip()) {
                            format!(
                                "이 주소에서 온 프레임 {n}건이 복호 실패 — 상대가 다른 mesh이거나 \
                                 epoch 불일치일 수 있음 (재초대 필요)"
                            )
                        } else if l.last_seen_ms == 0 {
                            "주소만 알고 아직 한 번도 수신 못함 — 상대 데몬이 꺼졌거나 방화벽/NAT가 \
                             막는 중일 수 있음"
                                .into()
                        } else {
                            "최근 30초간 수신 없음 — 상대가 오프라인이거나 IP가 바뀌었을 수 있음".into()
                        };
                        ("idle".into(), Some(why))
                    }
                    None => (
                        "unknown".into(),
                        Some("엔드포인트 미상 — 아직 상대 위치를 모름 (discovery/DHT 대기)".into()),
                    ),
                }
            };
            // Overlay (virtual) IP: <prefix>.<mesh_id>.<member_id> — the address peers
            // reach this member at over the tunnel (e.g. ssh user@100.80.1.1).
            let p = ms.mesh.charter.overlay_prefix;
            let overlay_ip = format!("{}.{}.{}.{}", p[0], p[1], ms.mesh.id, c.id);
            // The auto-discovered path (for `lattice conns`): `direct` if a fresh direct frame,
            // `relay` if reachable only via a public hop, `offline` if not heard, `me` for self.
            let (path, last_seen_secs) = if is_me {
                ("me".to_string(), Some(0))
            } else {
                match link {
                    Some(l) if l.last_seen_ms != 0 => {
                        let age = now.saturating_sub(l.last_seen_ms) / 1000;
                        let live = now.saturating_sub(l.last_seen_ms) < LIVE_WINDOW_MS;
                        let direct = l.last_direct_ms != 0
                            && now.saturating_sub(l.last_direct_ms) < LIVE_WINDOW_MS;
                        let p = if !live {
                            "offline"
                        } else if direct {
                            "direct"
                        } else {
                            "relay"
                        };
                        (p.to_string(), Some(age))
                    }
                    _ => ("offline".to_string(), None),
                }
            };
            MemberView {
                id: c.id,
                name: c.name.clone(),
                pubkey_fp: fp(&c.member),
                overlay_ip,
                is_me,
                endpoint,
                state,
                reason,
                path,
                last_seen_secs,
            }
        })
        .collect();
    // Health + attack state for the GUI (G-0): live count, the self-destruct floor,
    // and the attack countdown.
    let live = 1 + links
        .values()
        .filter(|l| l.last_seen_ms != 0 && now.saturating_sub(l.last_seen_ms) < LIVE_WINDOW_MS)
        .count();
    // Known peer endpoint IPs (name, ip) — captured while `links` is held, for warnings.
    let known_eps: Vec<(String, std::net::IpAddr)> = ms
        .roster()
        .iter()
        .filter(|c| c.member != me)
        .filter_map(|c| links.get(&c.id).map(|l| (c.name.clone(), l.endpoint.ip())))
        .collect();
    drop(links);
    let threshold = quorum_threshold(ms.roster().len().max(1));
    // Mesh-level warnings: the daemon SAYS what it already knows instead of dropping it.
    let mut warnings: Vec<String> = Vec::new();
    let mut warned_ips: std::collections::HashSet<std::net::IpAddr> =
        std::collections::HashSet::new();
    for (name, ip) in &known_eps {
        if let Some(n) = recent_fail(*ip) {
            if warned_ips.insert(*ip) {
                warnings.push(format!(
                    "⚠ '{name}'({ip})에서 온 프레임 {n}건이 복호 실패 — 다른 mesh이거나 epoch \
                     불일치 의심. 양쪽의 network id(net {})가 같은지 확인하세요.",
                    fp(&ms.mesh.charter.master_pubkey)
                ));
            }
        }
    }
    if ms.attack_armed_at.is_none()
        && ms.mesh.charter.self_destruct == lattice_mesh::charter::SelfDestruct::OnIsolation
        && live < threshold
    {
        warnings.push(format!(
            "⚠ 온라인 {live} < floor {threshold} — ephemeral mesh가 임계 미만입니다. \
             멤버가 더 떨어지면 self-destruct로 mesh가 사라질 수 있습니다."
        ));
    }
    if let Some(e) = &ms.dp_error {
        warnings.push(format!("⛔ data plane DOWN: {e}"));
    }
    let attack_armed_secs_left = ms.attack_armed_at.map(|armed| {
        let elapsed = now.saturating_sub(armed) / 1000;
        ATTACK_GRACE_SECS.saturating_sub(elapsed)
    });
    let ch = &ms.mesh.charter;
    MeshDetail {
        id: ms.mesh.id,
        name: ms.mesh.name.clone(),
        epoch: ms.epoch,
        me: ms.my_id(),
        exit: ms.mesh.exit,
        exitable: ms.exitable,
        invite: format!("{:?}", ch.invite),
        trigger: format!("{:?}", ch.trigger),
        max_members: ch.max_members,
        cipher: ms.cipher.clone(), // current cipher (may differ from charter post-re-cipher)
        members,
        live,
        threshold,
        attack_armed_secs_left,
        is_creator: ms.master.is_some(),
        self_destruct: ch.self_destruct == lattice_mesh::charter::SelfDestruct::OnIsolation,
        dp_error: ms.dp_error.clone(),
        warnings,
        network_fp: fp(&ch.master_pubkey),
        expel: expel_name(ch.expel),
        header_placement: header_placement_name(ch.header_placement),
        exit_policy: exit_policy_name(ch.exit_policy).to_string(),
    }
}

/// 🟢 Human name for an IP protocol number (tcp/udp/icmp/…) for the traffic monitor.
pub(crate) fn proto_name(p: u8) -> String {
    match p {
        1 => "icmp".into(),
        6 => "tcp".into(),
        17 => "udp".into(),
        n => format!("proto {n}"),
    }
}

/// Fold one mesh's live traffic (per-peer totals + recent flows) into `out`.
pub(crate) fn mesh_traffic(ms: &MeshState, out: &mut TrafficView) {
    let names: HashMap<MemberId, String> =
        ms.roster().iter().map(|c| (c.id, c.name.clone())).collect();
    let name_of = |id: MemberId| names.get(&id).cloned().unwrap_or_else(|| format!("#{id}"));
    // Resolve an overlay address (prefix + member-id last octet) to its member name, so the
    // flow view shows WHO sent/received instead of a raw `100.80.x.y`. Empty if not in-mesh.
    let prefix = ms.mesh.charter.overlay_prefix;
    let overlay_node = |ip: std::net::Ipv4Addr| -> String {
        let o = ip.octets();
        if [o[0], o[1]] == prefix {
            names.get(&o[3]).cloned().unwrap_or_default()
        } else {
            String::new()
        }
    };
    let t = ms.traffic.lock().unwrap();
    for (id, pt) in &t.per_peer {
        out.rx_bytes += pt.rx_bytes;
        out.rx_pkts += pt.rx_pkts;
        out.tx_bytes += pt.tx_bytes;
        out.tx_pkts += pt.tx_pkts;
        out.peers.push(PeerTrafficView {
            mesh: ms.mesh.id,
            mesh_name: ms.mesh.name.clone(),
            id: *id,
            name: name_of(*id),
            rx_bytes: pt.rx_bytes,
            rx_pkts: pt.rx_pkts,
            tx_bytes: pt.tx_bytes,
            tx_pkts: pt.tx_pkts,
        });
    }
    for ev in &t.recent {
        out.recent.push(FlowView {
            at_ms: ev.at_ms,
            out: ev.out,
            mesh: ms.mesh.id,
            mesh_name: ms.mesh.name.clone(),
            member: ev.member,
            member_name: name_of(ev.member),
            src: ev.src.to_string(),
            dst: ev.dst.to_string(),
            src_node: overlay_node(ev.src),
            dst_node: overlay_node(ev.dst),
            proto: proto_name(ev.proto),
            sport: ev.sport,
            dport: ev.dport,
            bytes: ev.bytes,
            via_exit: ev.via_exit,
        });
    }
}

/// Build the traffic monitor view: one mesh (`Some`) or this whole computer (`None`).
pub(crate) fn traffic_view(st: &State, mesh: Option<MeshId>) -> TrafficView {
    let mut v = TrafficView::default();
    match mesh {
        Some(id) => {
            if let Some(ms) = st.meshes.get(&id) {
                mesh_traffic(ms, &mut v);
            }
        }
        None => {
            for ms in st.meshes.values() {
                mesh_traffic(ms, &mut v);
            }
        }
    }
    v.recent.sort_by(|a, b| b.at_ms.cmp(&a.at_ms)); // newest first
    v.recent.truncate(200);
    v.peers
        .sort_by(|a, b| (b.rx_bytes + b.tx_bytes).cmp(&(a.rx_bytes + a.tx_bytes))); // top talkers
    v
}

/// 🟢 Standard "no such mesh" error response.
pub(crate) fn no_mesh(id: MeshId) -> Response {
    Response::Error {
        message: format!("no mesh {id}"),
    }
}

/// 🟢 Build a `Response::Error` from a message.
pub(crate) fn err(message: &str) -> Response {
    Response::Error {
        message: message.to_string(),
    }
}
