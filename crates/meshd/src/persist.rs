//! P-S1 persistence: every on-disk state file the daemon writes/reads —
//! `mesh-<id>.json`, `extensions.json`, `split.json`, `split-active.json`,
//! `default-mesh.json`, `egress.json`, the update-migration backup — plus
//! [`restore_mesh`] and [`request_mutates`] (the "which request triggers a
//! re-save" table). The on-disk formats are FROZEN (tests in main.rs lock them);
//! keep each file's exact serializer (`to_vec` vs `to_vec_pretty`).
//! Pure code motion out of main.rs (Phase 2); behavior unchanged.

use crate::*;

// ---- P-S1 persistence: survive reboots / network changes ---------------------
// v1 stores keys/secret in plaintext JSON with 0600 perms. NOTE: this trades the
// RAM-only ephemerality for reboot-survival; a self-destruct / RemoveMesh deletes the
// file too, so the ephemeral property still holds for those. At-rest encryption is a
// follow-on (P-S1b).

/// The on-disk form of one mesh.
#[derive(Serialize, Deserialize)]
pub(crate) struct PersistedMesh {
    pub(crate) mesh_id: MeshId,
    pub(crate) mesh_name: String,
    pub(crate) charter: GenesisCharter,
    pub(crate) certs: Vec<Cert>,
    /// Signed expulsions (P-revoke). `#[serde(default)]` so older state files load.
    #[serde(default)]
    pub(crate) revocations: Vec<Revocation>,
    /// Quick-invite membership records (docs/JOIN_MODES.md). `#[serde(default)]` so older files load.
    #[serde(default)]
    pub(crate) grant_certs: Vec<GrantCert>,
    /// SDN flow table + version (docs/FLOW_TABLE.md). `#[serde(default)]` so older state
    /// files load; an empty table is treated as the default at restore.
    #[serde(default)]
    pub(crate) flows: Vec<FlowRule>,
    #[serde(default)]
    pub(crate) flow_version: u64,
    pub(crate) secret: [u8; 32],
    pub(crate) epoch: u64,
    pub(crate) cipher: String,
    pub(crate) member_seed: [u8; 32],
    pub(crate) enc_bytes: [u8; 32],
    pub(crate) master_seed: Option<[u8; 32]>,
    pub(crate) exit: Option<MemberId>,
    /// Last-known peer endpoints — re-seeded on load so reconnect is fast (discovery
    /// then re-learns the rest, e.g. after a network change).
    pub(crate) peers: Vec<(MemberId, String)>,
    /// Whether this node serves as an exit for this mesh (docs/EXIT_SHARING.md). `#[serde(default)]`
    /// so older state files load as `false` (safe-off).
    #[serde(default)]
    pub(crate) exitable: bool,
}

/// Where to persist (env `MESHD_STATE_DIR`, else `$HOME/.lattice/meshd`), or `None`
/// if `MESHD_NO_PERSIST` is set or no home is found. Creates the dir (0700).
pub(crate) fn persist_dir() -> Option<PathBuf> {
    if std::env::var("MESHD_NO_PERSIST").is_ok() {
        return None;
    }
    let dir = std::env::var("MESHD_STATE_DIR")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join(".lattice/meshd"))
        })?;
    std::fs::create_dir_all(&dir).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    Some(dir)
}

/// 🟢 On-disk JSON path for mesh `id` under the state dir.
pub(crate) fn mesh_file(dir: &std::path::Path, id: MeshId) -> PathBuf {
    dir.join(format!("mesh-{id}.json"))
}

/// Snapshot one live mesh into its serializable persisted form. Shared by on-disk
/// persistence and the `ExportState` update-migration backup.
pub(crate) fn to_persisted(ms: &MeshState) -> PersistedMesh {
    PersistedMesh {
        mesh_id: ms.mesh.id,
        mesh_name: ms.mesh.name.clone(),
        charter: ms.mesh.charter.clone(),
        certs: ms.certs.clone(),
        revocations: ms.revocations.clone(),
        grant_certs: ms.grant_certs.clone(),
        flows: ms.flows.clone(),
        flow_version: ms.flow_version,
        secret: ms.secret,
        epoch: ms.epoch,
        cipher: ms.cipher.clone(),
        member_seed: ms.my_key.to_seed(),
        enc_bytes: ms.my_enc.to_bytes(),
        master_seed: ms.master.as_ref().map(|m| m.to_seed()),
        exit: *ms.exit_sel.lock().unwrap(),
        peers: ms
            .links
            .lock()
            .unwrap()
            .iter()
            .map(|(m, l)| (*m, l.endpoint.to_string()))
            .collect(),
        exitable: ms.exitable,
    }
}

/// Shared writer tail of every `persist_*`: serialize (compact or pretty — the
/// choice is PER FILE and FROZEN: mesh files + lists are pretty, the small
/// `Option<MeshId>` marker files are compact; tests in main.rs lock the formats),
/// write, chmod 0600. Best-effort, like every state write here.
fn write_json_secure<T: Serialize>(f: &std::path::Path, value: &T, pretty: bool) {
    let json = if pretty {
        serde_json::to_vec_pretty(value)
    } else {
        serde_json::to_vec(value)
    };
    if let Ok(json) = json {
        if std::fs::write(f, &json).is_ok() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
}

/// Shared reader: missing/corrupt state file ⇒ `T::default()` — startup never
/// fails on a bad file, it just starts without that piece of state.
fn read_json_or_default<T: serde::de::DeserializeOwned + Default>(f: &std::path::Path) -> T {
    std::fs::read(f)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// An `Option<MeshId>` marker file (`split-active` / `default-mesh` / `egress`):
/// `Some` ⇒ write it (compact, 0600), `None` ⇒ remove the file.
fn persist_marker(dir: &std::path::Path, file: &str, v: Option<MeshId>) {
    let f = dir.join(file);
    match v {
        None => {
            let _ = std::fs::remove_file(&f);
        }
        Some(_) => write_json_secure(&f, &v, false),
    }
}

/// Where the update-migration backup lives: env `MESHD_IMPORT`, else
/// `<tempdir>/lattice-mesh-backup.json`. `ExportState` writes it before an update and
/// startup reads (then deletes) it, so a reinstall never drops a node from its meshes
/// even if the persist dir is wiped.
pub(crate) fn migration_backup_path() -> PathBuf {
    std::env::var("MESHD_IMPORT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("lattice-mesh-backup.json"))
}

/// Read the update-migration backup (a JSON array of meshes) if present.
pub(crate) fn load_backup(path: &std::path::Path) -> Vec<PersistedMesh> {
    read_json_or_default(path)
}

/// Save all current meshes and prune files for meshes that are gone (so a
/// self-destruct / RemoveMesh erases the on-disk copy too).
pub(crate) fn persist(st: &State) {
    let Some(dir) = &st.persist_dir else { return };
    persist_extensions(st);
    persist_split(st);
    for ms in st.meshes.values() {
        write_json_secure(&mesh_file(dir, ms.mesh.id), &to_persisted(ms), true);
    }
    // Prune meshes no longer present.
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if let Some(idstr) = name
                .strip_prefix("mesh-")
                .and_then(|s| s.strip_suffix(".json"))
            {
                if let Ok(id) = idstr.parse::<MeshId>() {
                    if !st.meshes.contains_key(&id) {
                        let _ = std::fs::remove_file(e.path());
                    }
                }
            }
        }
    }
}

/// Path of the extension-grant store (docs/EXTENSIONS.md §3) within the persist dir.
pub(crate) fn extensions_file(dir: &std::path::Path) -> PathBuf {
    dir.join("extensions.json")
}

/// Persist the extension grants to `extensions.json` (0600). Called from [`persist`].
pub(crate) fn persist_extensions(st: &State) {
    let Some(dir) = &st.persist_dir else { return };
    let grants: Vec<&ExtensionGrant> = st.extensions.values().collect();
    write_json_secure(&extensions_file(dir), &grants, true);
}

/// Persist the local split-tunnel rules to `split.json` (0600). Called from [`persist`].
pub(crate) fn persist_split(st: &State) {
    let Some(dir) = &st.persist_dir else { return };
    write_json_secure(&dir.join("split.json"), &st.split_rules, true);
}

/// Load the split-tunnel rules at startup. Missing/corrupt file ⇒ empty.
pub(crate) fn load_split(dir: &std::path::Path) -> Vec<dns_split::SplitRule> {
    read_json_or_default(&dir.join("split.json"))
}

/// Persist WHICH mesh's split-tunnel is currently on (a separate file so `split.json`'s format is
/// unchanged) so it survives a restart — otherwise a domain bypass silently drops off every reboot
/// (the rules stay, but the on/off state was in-memory). `None` (split off) removes the file.
pub(crate) fn persist_split_active(st: &State) {
    let Some(dir) = &st.persist_dir else { return };
    persist_marker(dir, "split-active.json", st.split.as_ref().map(|s| s.mesh));
}

/// The mesh whose split-tunnel was on at last persist (`None` = it was off). Re-enabled at startup.
pub(crate) fn load_split_active(dir: &std::path::Path) -> Option<MeshId> {
    read_json_or_default(&dir.join("split-active.json"))
}

/// Persist the node's preferred default mesh (a view/selection hint; no routing). `None` removes it.
pub(crate) fn persist_default_mesh(st: &State) {
    let Some(dir) = &st.persist_dir else { return };
    persist_marker(dir, "default-mesh.json", st.default_mesh);
}

/// The node's preferred default mesh at startup (`None` = unset). Loaded once; safe (no routing).
pub(crate) fn load_default_mesh(dir: &std::path::Path) -> Option<MeshId> {
    read_json_or_default(&dir.join("default-mesh.json"))
}

/// Persist the FULL-tunnel egress selection so it survives a daemon restart (mirrors
/// `persist_split_active` for split). Only a full tunnel is sticky here — a split selection has its
/// own `split-active.json`, and "default network" (`full_tunnel=false`) removes the file. Call after
/// any mutation of `current`/`full_tunnel`; it always reflects the live full-tunnel mesh (or none).
pub(crate) fn persist_egress(st: &State) {
    let Some(dir) = &st.persist_dir else { return };
    persist_marker(dir, "egress.json", st.current.filter(|_| st.full_tunnel));
}

/// The mesh that was the full-tunnel egress at last persist (`None` = default network). Re-applied at
/// startup — but only once the exit is reachable (see [`restore_full_tunnel`]), never blindly at boot.
pub(crate) fn load_egress(dir: &std::path::Path) -> Option<MeshId> {
    read_json_or_default(&dir.join("egress.json"))
}

/// Load the extension grants at startup (id → grant). Missing/corrupt file ⇒ empty.
pub(crate) fn load_extensions(dir: &std::path::Path) -> HashMap<String, ExtensionGrant> {
    read_json_or_default::<Vec<ExtensionGrant>>(&extensions_file(dir))
        .into_iter()
        .map(|g| (g.id.clone(), g))
        .collect()
}

/// Load persisted meshes from disk (startup).
pub(crate) fn load_persisted(dir: &std::path::Path) -> Vec<PersistedMesh> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().starts_with("mesh-") {
                if let Ok(bytes) = std::fs::read(e.path()) {
                    if let Ok(p) = serde_json::from_slice::<PersistedMesh>(&bytes) {
                        out.push(p);
                    }
                }
            }
        }
    }
    out.sort_by_key(|p| p.mesh_id);
    out
}

/// Rebuild a `MeshState` (+ a `Bringup`) from its persisted form (startup).
pub(crate) fn restore_mesh(p: PersistedMesh) -> (MeshState, Bringup) {
    let my_key = MemberKey::from_seed(&p.member_seed);
    let my_enc = EncKey::from_bytes(&p.enc_bytes);
    let master = p.master_seed.map(|s| MasterKey::from_seed(&s));
    let my_pub = my_key.pubkey();
    let my_id = p
        .certs
        .iter()
        .find(|c| c.member == my_pub)
        .map(|c| c.id)
        .unwrap_or(0);
    let mut mesh = Mesh::new(p.mesh_id, p.mesh_name.clone(), p.charter, my_id);
    mesh.epoch = p.epoch;
    mesh.exit = p.exit;
    let mut seed: HashMap<MemberId, SocketAddr> = HashMap::new();
    for (m, ep) in &p.peers {
        if let Ok(a) = ep.parse() {
            seed.insert(*m, a);
        }
    }
    // An empty persisted table (older state files) means "use the default".
    let flows = if p.flows.is_empty() {
        lattice_proto::flow::default_table()
    } else {
        p.flows
    };
    NewMesh {
        mesh,
        master,
        my_key,
        my_enc,
        certs: p.certs,
        revocations: p.revocations,
        grant_certs: p.grant_certs,
        secret: p.secret,
        cipher: p.cipher,
        epoch: p.epoch,
        exit: p.exit,
        exitable: p.exitable,
        seed,
        flows,
        flow_version: p.flow_version,
    }
    .build()
}

/// Whether a request mutates persistent mesh state (⇒ re-save afterward).
pub(crate) fn request_mutates(req: &Request) -> bool {
    matches!(
        req,
        Request::CreateMesh { .. }
            | Request::JoinMesh { .. }
            | Request::CreateInvite { .. }
            | Request::AdmitMember { .. }
            | Request::SetExit { .. }
            | Request::SetPeer { .. }
            | Request::SetCurrent { .. }
            | Request::RemoveMesh { .. }
            | Request::Recipher { .. }
            | Request::AllClear { .. }
            | Request::ExpelMember { .. }
            | Request::EnableExtension { .. }
            | Request::DisableExtension { .. }
            | Request::SplitAdd { .. }
            | Request::SplitDel { .. }
            | Request::SetExitable { .. }
    )
}
