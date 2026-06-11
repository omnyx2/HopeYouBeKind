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
///
/// Adjacently tagged (`{"ok": <variant>, "data": <payload>}`): a sequence payload
/// like `Peers(Vec<…>)` cannot be *internally* tagged (serde can only inline a
/// tag into a map), so the content lives in a separate `data` field.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "ok", content = "data", rename_all = "snake_case")]
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
    /// Our public (reflexive) address as seen via STUN, if known.
    pub public_addr: Option<std::net::SocketAddr>,
    pub running: bool,
    pub peer_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every response variant — including the `Vec` payload that broke internal
    /// tagging — must serialize to JSON and parse back.
    #[test]
    fn responses_round_trip_as_json() {
        let cases = vec![
            Response::Status(NodeStatus {
                id: NodeId([1u8; 32]),
                virtual_ip: None,
                public_addr: None,
                running: true,
                peer_count: 0,
            }),
            Response::Peers(vec![]),
            Response::Done,
            Response::Error {
                message: "nope".into(),
            },
        ];
        for r in cases {
            let json = serde_json::to_string(&r).expect("serialize");
            let back: Response = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(format!("{r:?}"), format!("{back:?}"), "round-trip: {json}");
        }
    }
}
