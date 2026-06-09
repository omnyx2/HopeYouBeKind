//! The contract between the privileged daemon and its unprivileged clients
//! (the CLI and the Tauri GUI). Requests go client→daemon, responses come back.
//!
//! Transport is a local-only channel (Unix socket / Windows named pipe); these
//! types are the payloads, serialized as JSON for easy cross-language consumption
//! from the GUI frontend.

use serde::{Deserialize, Serialize};

use crate::{NodeId, PeerInfo, VirtualIp};

/// A command from a client to the daemon.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Bring the mesh interface up.
    Up,
    /// Tear the mesh interface down.
    Down,
    /// Current node + mesh status.
    Status,
    /// List known peers.
    Peers,
}

/// The daemon's reply.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "ok", rename_all = "snake_case")]
pub enum Response {
    Status(NodeStatus),
    Peers(Vec<PeerInfo>),
    /// A command that returns no data succeeded.
    Done,
    /// Something went wrong; `message` is human-readable.
    Error {
        message: String,
    },
}

/// Snapshot of this node's state for the GUI dashboard.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeStatus {
    pub id: NodeId,
    pub virtual_ip: Option<VirtualIp>,
    pub running: bool,
    pub peer_count: usize,
}
