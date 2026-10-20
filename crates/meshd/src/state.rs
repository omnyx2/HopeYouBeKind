//! The daemon's shared in-memory model: [`State`] (the one global, behind
//! `Arc<Mutex<_>>`), per-mesh [`MeshState`], the extension-grant/event types, and
//! the deferred-work carriers ([`Bringup`], [`PostAction`]). Pure code motion out
//! of main.rs (Phase 2); behavior unchanged.
use crate::*;

/// One mesh plus the real trust state for it.
pub(crate) struct MeshState {
    pub(crate) mesh: Mesh,
    /// The mesh's root of trust. `Some` only on the creator (it holds the master
    /// key and can issue invites); a joiner installs the mesh with `None`.
    pub(crate) master: Option<MasterKey>,
    /// This node's own member keypair in this mesh.
    pub(crate) my_key: MemberKey,
    /// This node's encryption key in this mesh (receives sealed secrets — rekeys).
    #[allow(dead_code)]
    pub(crate) my_enc: EncKey,
    /// Every known cert. The roster = those that validly chain to the master, minus any
    /// that carry an authorized revocation (see `revocations`).
    pub(crate) certs: Vec<Cert>,
    /// Known membership revocations (signed expulsions), gossiped + merged like certs.
    /// `roster()` drops a member that carries one authorized under the charter's
    /// `ExpelPolicy` — this is what actually removes a member (re-cipher only denies keys).
    pub(crate) revocations: Vec<Revocation>,
    /// Quick-invite membership records (docs/JOIN_MODES.md) — members that self-registered under a
    /// signed `Grant`. Kept SEPARATE from `certs` so the classic cert roster wire format never
    /// changes; gossiped on their own control channel and folded into `roster()` via `grant_members`.
    pub(crate) grant_certs: Vec<GrantCert>,
    /// Member ids handed out in invites that have **not yet joined** (id, invitee pubkey,
    /// issued-at ms). Reserved so inviting several people in a row — before any of them
    /// connect and gossip back — assigns DISTINCT ids instead of all reusing the next free
    /// slot. Pruned once the invitee appears in the roster, or after `INVITE_RESERVE_MS`.
    pub(crate) invited: Vec<(MemberId, PubKey, u64)>,
    /// The mesh's shared symmetric secret (epoch 0) — keys the data-plane cipher.
    /// Held for rekey / re-bringup / sealing to joiners (keydist).
    pub(crate) secret: [u8; 32],
    /// Live peer table, shared with this mesh's data-plane loop (endpoints +
    /// last-seen). Empty until peers are seeded (SetPeer) or heard from.
    pub(crate) links: PeerLinks,
    /// The egress member, shared with the loop so SetExit steers it live.
    pub(crate) exit_sel: SharedExit,
    /// Domain split-tunnel routes (matched IP → its rule's exit member), shared with the loop so
    /// split traffic goes to the rule's exit without touching the mesh-wide exit. Empty when
    /// split mode is off (docs/SPLIT_TUNNEL.md).
    pub(crate) split_routes: SharedSplitRoutes,
    /// Whether THIS node lets this mesh's members use it as their internet exit (per-mesh
    /// opt-in, docs/EXIT_SHARING.md). LOCAL, persisted, never gossiped; default false. When on
    /// (or on a pinned exit), this mesh's subnet gets forwarding+NAT so members can egress
    /// through us. Default-off keeps a mesh intruder from turning us into a proxy.
    pub(crate) exitable: bool,
    /// The OS interface name of this mesh's TUN (set at bringup) — needed to divert
    /// the default route for full-tunnel egress.
    pub(crate) tun_name: Option<String>,
    /// This node's own advertised data-plane endpoint (`ip:port`), shared with the
    /// run loop. Set at bringup; the loop upgrades it to our public address when a
    /// public peer reflects it (P-D3). Read by CreateInvite to hand joiners (P-D1).
    pub(crate) my_endpoint: SharedEndpoint,
    /// This mesh's local data-plane UDP port (set at bringup; 0 = not up). Advertised
    /// in the LAN beacon so same-router peers reach us directly (P-D4).
    pub(crate) dp_port: u16,
    /// Non-fatal data-plane bring-up error (e.g. the UDP port is held by another
    /// process), surfaced in `MeshInfo` so the GUI can show "data plane DOWN" instead
    /// of a mesh that looks joined but silently can't send or receive. `None` = healthy.
    pub(crate) dp_error: Option<String>,
    /// Abort handle for this mesh's data-plane loop (set at bringup). `RemoveMesh`
    /// aborts it so the loop's future is dropped, freeing its TUN + UDP socket —
    /// otherwise the port leaks and a re-created mesh can't bind it.
    pub(crate) dp_task: Option<tokio::task::AbortHandle>,
    /// The mesh's **current** data-plane cipher + epoch (P-C3). Start from the
    /// charter; a re-cipher rotates `secret`, bumps `epoch`, and may change `cipher`.
    pub(crate) cipher: String,
    pub(crate) epoch: u64,
    /// Sender into this mesh's data-plane loop (re-cipher trigger / attack signals,
    /// set at bringup).
    pub(crate) loop_cmd: Option<UnboundedSender<LoopCmd>>,
    /// When an attack alert armed the destroy grace (P-C7); `None` = not armed. Set on
    /// `ReportAttack` / a received alert, cleared by the creator's all-clear; the
    /// self-destruct watchdog wipes the mesh once the grace elapses.
    pub(crate) attack_armed_at: Option<u64>,
    /// Frames that arrived on this mesh's socket but failed to decrypt, keyed by source
    /// IP — shared with the data-plane loop. A nonzero count from a known peer's
    /// endpoint IP is the "peer is on a different mesh/epoch" signal, surfaced as a
    /// health warning + per-member reason in `MeshInfo` instead of a silent drop.
    pub(crate) decrypt_fails: DecryptFails,
    /// Live per-peer byte/packet counters + recent overlay flows, shared with the data-plane
    /// loop. Projected into the GUI traffic monitor (`TrafficStats`).
    pub(crate) traffic: SharedTraffic,
    /// The mesh's SDN flow table (docs/FLOW_TABLE.md) + a monotonic version. Edited via
    /// `SetFlows`, gossiped (`CTRL_FLOWS`, newest version wins, no signing), applied to the
    /// live data plane and persisted. `flow::default_table()` = the classic behavior.
    pub(crate) flows: Vec<FlowRule>,
    pub(crate) flow_version: u64,
    /// Connector service registry (docs/EXTENSIONS.md §6): services THIS node advertises
    /// plus those learned from peers. Soft state — not persisted; peer entries expire if
    /// not re-gossiped. Gossiped via `CTRL_REGISTRY`.
    pub(crate) services: Vec<ServiceEntry>,
    /// Monotonic counter for OUR advertised services' `seq`, so a re-advertise supersedes
    /// the previous record at every peer.
    pub(crate) service_seq: u64,
}

impl MeshState {
    pub(crate) fn topology(&self) -> InviteTopology {
        self.mesh.charter.invite
    }
    /// The effective roster (certs chaining to the master, minus authorized
    /// revocations), id-sorted.
    pub(crate) fn roster(&self) -> Vec<Cert> {
        let master = self.mesh.charter.master_pubkey;
        let cert_valid = effective_members(
            &master,
            &self.certs,
            self.topology(),
            &self.revocations,
            self.mesh.charter.expel,
        );
        let mut v: Vec<Cert> = cert_valid.iter().map(|c| (*c).clone()).collect();
        // Fold in quick-invite members (a separate record set) as synthetic cert rows so every
        // existing roster consumer sees them uniformly (docs/JOIN_MODES.md). They chain to the
        // master via their grant, validated by `grant_members`.
        for q in lattice_mesh::membership::grant_members(
            &master,
            &cert_valid,
            &self.grant_certs,
            self.topology(),
        ) {
            v.push(Cert {
                network: master,
                member: q.member,
                id: q.id,
                name: q.name.clone(),
                inviter: q.member, // self-registered
                issued_at: q.issued_at,
                sig: q.sig,
            });
        }
        // A cert member wins over a quick member on an id clash (certs were pushed first; stable).
        v.sort_by_key(|c| c.id);
        v.dedup_by_key(|c| c.id);
        v
    }
    /// The classic-cert roster only (NO synthetic quick-member rows) — what `CTRL_ROSTER` gossips,
    /// so the wire stays byte-identical to older nodes. Quick members ride `CTRL_QGRANT` instead.
    pub(crate) fn cert_roster(&self) -> Vec<Cert> {
        effective_members(
            &self.mesh.charter.master_pubkey,
            &self.certs,
            self.topology(),
            &self.revocations,
            self.mesh.charter.expel,
        )
        .into_iter()
        .cloned()
        .collect()
    }
    /// This node's in-mesh id (from its own cert).
    pub(crate) fn my_id(&self) -> MemberId {
        let me = self.my_key.pubkey();
        self.certs
            .iter()
            .find(|c| c.member == me)
            .map(|c| c.id)
            .unwrap_or(0)
    }
}

#[derive(Default)]
pub(crate) struct State {
    pub(crate) meshes: HashMap<MeshId, MeshState>,
    /// The mesh currently selected for egress (the §1 cur-mesh). Set by BOTH full-tunnel
    /// (`SetCurrent`) and split-tunnel (`SplitOn`) — it means "the selected mesh", not "full
    /// tunnel". Use [`State::full_tunnel`] to tell the two apart.
    pub(crate) current: Option<MeshId>,
    /// True only when `current` was selected as a FULL tunnel (`SetCurrent`), false when it was
    /// selected merely to host split-tunnel routing (`SplitOn`, general traffic stays direct).
    /// The network-change re-route + shutdown restore key off THIS, not `current.is_some()`, so a
    /// split selection never accidentally diverts the default route.
    pub(crate) full_tunnel: bool,
    /// The node's preferred "default" mesh (docs-only UX): the mesh the GUI/CLI pre-selects and
    /// shows first on startup. PERSISTED (survives restart) and purely a view/selection hint — it
    /// does NOT change routing (unlike `current`), so it can safely persist without any DNS/route
    /// side effects. `None` = no default set.
    pub(crate) default_mesh: Option<MeshId>,
    /// Whether to spawn data-plane loops (`DATA_PLANE=1`).
    pub(crate) data_plane: bool,
    /// Freshly minted identities (member + enc keypair) awaiting an invite, keyed
    /// by member public key. Drained when `JoinMesh` consumes one.
    pub(crate) pending: HashMap<PubKey, (MemberKey, EncKey)>,
    /// Where meshes are persisted (P-S1); `None` = persistence off. Saved on every
    /// state change, pruned on self-destruct/remove, reloaded at startup so a reboot
    /// (or a network change) doesn't drop the node from its meshes.
    pub(crate) persist_dir: Option<PathBuf>,
    /// Node-wide DHT rendezvous (`MESHD_DHT=1`); `None` = off. Re-finds a peer whose
    /// address changed with no overlapping live window — docs/DHT_RENDEZVOUS.md.
    pub(crate) dht: Option<Arc<dht::DhtService>>,
    /// Extension event bus (docs/EXTENSIONS.md §1). Subsystems publish [`MeshEvent`]s;
    /// each subscribed connector connection drains a `broadcast::Receiver` and forwards
    /// scope-matching events. Bounded — a slow connector lags and drops events, it never
    /// back-pressures the data plane. Set once at startup (`None` only before that).
    pub(crate) bus: Option<tokio::sync::broadcast::Sender<MeshEvent>>,
    /// Installed extension grants (docs/EXTENSIONS.md §3), keyed by extension id. Created
    /// by `EnableExtension`, persisted to `extensions.json` (0600). A connector's `Hello`
    /// token is checked against these; a grant gates which scopes the connection holds.
    pub(crate) extensions: HashMap<String, ExtensionGrant>,
    /// Domain split-tunnel rules (docs/SPLIT_TUNNEL.md) — LOCAL to this node, persisted to
    /// `split.json` (0600), never gossiped. Each maps a domain to the mesh whose exit its
    /// traffic egresses through.
    pub(crate) split_rules: Vec<dns_split::SplitRule>,
    /// The running split-tunnel proxy, if split mode is on (`None` = off).
    pub(crate) split: Option<SplitActive>,
}

/// A running domain split-tunnel session (docs/SPLIT_TUNNEL.md).
pub(crate) struct SplitActive {
    /// The mesh whose tun/exit matched traffic is routed into.
    pub(crate) mesh: MeshId,
    /// The DNS-proxy task; aborted on `SplitOff`.
    pub(crate) task: tokio::task::JoinHandle<()>,
    /// Every `/32` IP we injected a host route for — removed on `SplitOff`.
    pub(crate) injected: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<Ipv4Addr>>>,
}

/// One enabled extension's grant — the local record a connector authenticates against.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ExtensionGrant {
    pub(crate) id: String,
    /// Local secret the connector presents in `Hello`. Not a network credential — it
    /// only identifies which extension a local connection claims to be.
    pub(crate) token: String,
    /// The scopes the user granted (subset of what the extension requested).
    pub(crate) scopes: Vec<String>,
    pub(crate) enabled: bool,
    /// Allowed on every mesh, including ones joined later. `#[serde(default)]` so grants
    /// written before per-mesh scoping load as "no meshes" (safe — must be re-granted).
    #[serde(default)]
    pub(crate) all_meshes: bool,
    /// The specific meshes this grant may touch (when `all_meshes` is false). A connector
    /// can advertise/list/receive events ONLY for these — so enabling one connector never
    /// silently exposes a mesh the user didn't pick (docs/EXTENSIONS.md §3).
    #[serde(default)]
    pub(crate) meshes: Vec<MeshId>,
}

impl ExtensionGrant {
    pub(crate) fn view(&self) -> ExtensionView {
        ExtensionView {
            id: self.id.clone(),
            scopes: self.scopes.clone(),
            enabled: self.enabled,
            token: self.token.clone(),
            all_meshes: self.all_meshes,
            meshes: self.meshes.clone(),
        }
    }
    /// Whether this grant is allowed to touch `mesh`.
    pub(crate) fn allows_mesh(&self, mesh: MeshId) -> bool {
        self.all_meshes || self.meshes.contains(&mesh)
    }
}

/// An event published on the extension bus (docs/EXTENSIONS.md §5). `topic` is the bus
/// channel (`peer` | `service` | `exit` | `health`); `data` is a topic-specific JSON
/// payload. `mesh` is the mesh the event concerns (so a subscriber only gets events for
/// meshes its grant allows); `None` = node-level, delivered to any subscriber. Events are
/// coarse — a connector that sees one re-queries authoritative state (e.g. `ListServices`).
#[derive(Clone, Debug)]
pub(crate) struct MeshEvent {
    pub(crate) topic: &'static str,
    pub(crate) mesh: Option<MeshId>,
    pub(crate) ts_ms: u64,
    pub(crate) data: serde_json::Value,
}

/// Bus capacity. A connector that falls this far behind gets a `Lagged` (we surface it as
/// a `_lagged` marker so it re-queries) rather than stalling the publisher.
pub(crate) const EVENT_BUS_CAP: usize = 1024;
/// Per-connection outbound queue depth. Bounds memory if a connector stops reading its
/// socket: responses backpressure the request loop, pushed events are dropped past this.
pub(crate) const OUT_CHAN_CAP: usize = 256;
/// Cap on registry entries per mesh (own + learned), mirroring the roster/flow caps.
pub(crate) const MAX_SERVICES: usize = 256;

/// Publish an event to the extension bus, if it is up and has subscribers. Best-effort:
/// `send` errors only when there are zero receivers, which we ignore.
pub(crate) fn emit(st: &State, topic: &'static str, mesh: Option<MeshId>, data: serde_json::Value) {
    if let Some(bus) = &st.bus {
        let _ = bus.send(MeshEvent {
            topic,
            mesh,
            ts_ms: now_ms(),
            data,
        });
    }
}

/// Work the IPC handler defers to the async caller (it can't `.await` or spawn
/// under the state lock): data-plane bringup, or arming the full-tunnel watchdog.
pub(crate) enum PostAction {
    Bringup(Bringup),
    /// Full tunnel just went up for this mesh — start the kill-switch.
    ArmKillSwitch(MeshId),
    /// Start domain split-tunnel for this mesh (bind the DNS proxy + point the host resolver at
    /// it). Async work done after the lock is released (docs/SPLIT_TUNNEL.md).
    SplitOn(MeshId),
    /// Stop domain split-tunnel (abort proxy, remove injected `/32` routes, restore DNS).
    SplitOff,
    /// Apply the (just-changed) `exitable` flag for this mesh: enable/disable forwarding+NAT for
    /// its subnet so its members can/can't use us as their exit (docs/EXIT_SHARING.md).
    ApplyExitable(MeshId),
    /// Cleanly stop the whole daemon (after the response is sent to the client).
    Shutdown,
}

/// Everything `bringup_dataplane` needs to spawn a mesh's live loop — built inside
/// the locked handler, executed (async TUN/UDP open) after the lock is released.
pub(crate) struct Bringup {
    pub(crate) mesh_id: MeshId,
    pub(crate) my_id: MemberId,
    pub(crate) prefix: [u8; 2],
    pub(crate) secret: [u8; 32],
    pub(crate) cipher: String,
    pub(crate) epoch: u64,
    pub(crate) links: PeerLinks,
    pub(crate) exit_sel: SharedExit,
    pub(crate) split_routes: SharedSplitRoutes,
    pub(crate) my_endpoint: SharedEndpoint,
    pub(crate) decrypt_fails: DecryptFails,
    pub(crate) traffic: SharedTraffic,
    pub(crate) header_placement: HeaderPlacement,
    pub(crate) flows: Vec<FlowRule>,
}
