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
    /// Route this node's internet traffic through `node_id` (or `None` to stop
    /// using an exit node and go direct again).
    SetExit { node_id: Option<NodeId> },
    /// Allow (or stop allowing) this node to act as an exit for others.
    AllowExit { enabled: bool },
    /// Manually pin a peer by node id + physical address — connect across the
    /// internet without discovery (e.g. to a port-forwarded node).
    AddPeer {
        node_id: NodeId,
        addr: std::net::SocketAddr,
    },
    /// Set (or clear with `None`) the relay this node uses to reach peers that
    /// can't be connected to directly.
    SetRelay { addr: Option<std::net::SocketAddr> },
    /// Reach a peer (by node id) through the configured relay.
    RelayPeer { node_id: NodeId },
    /// Live traffic flows seen crossing the tunnel — what is talking to what.
    Flows,
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
    Flows(Vec<FlowRecord>),
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
    /// The peer we're routing internet traffic through, if any.
    pub exit_node: Option<NodeId>,
    /// Whether we're acting as an exit node for others.
    pub is_exit: bool,
    /// The relay address currently configured, if any.
    pub relay: Option<std::net::SocketAddr>,
}

/// One aggregated traffic flow observed crossing the tunnel. The engine groups
/// packets by `(peer, protocol, local endpoint, remote endpoint)` and counts
/// bytes/packets in each direction — this is what the GUI's traffic monitor
/// renders so the user can see exactly what is flowing between peers.
///
/// "Local" is this node's side of the conversation (our virtual IP/port);
/// "remote" is the other end — a peer's virtual IP for mesh traffic, or a public
/// address for internet traffic carried through an exit node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlowRecord {
    /// The mesh peer carrying this flow, if attributable to one.
    pub peer: Option<NodeId>,
    /// Transport protocol name: "TCP", "UDP", "ICMP", or "IP/<n>".
    pub protocol: String,
    /// Our side of the conversation, "ip" or "ip:port".
    pub local: String,
    /// The far side, "ip" or "ip:port".
    pub remote: String,
    /// Packets/bytes we sent out over this flow (local → remote).
    pub tx_packets: u64,
    pub tx_bytes: u64,
    /// Packets/bytes we received on this flow (remote → local).
    pub rx_packets: u64,
    pub rx_bytes: u64,
    /// Seconds since the flow last carried a packet (lower = more recent).
    pub last_active_secs: u64,
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
                exit_node: None,
                is_exit: false,
                relay: None,
            }),
            Response::Peers(vec![]),
            Response::Flows(vec![FlowRecord {
                peer: Some(NodeId([2u8; 32])),
                protocol: "TCP".into(),
                local: "100.64.0.1:54321".into(),
                remote: "100.64.0.2:22".into(),
                tx_packets: 3,
                tx_bytes: 180,
                rx_packets: 2,
                rx_bytes: 1400,
                last_active_secs: 1,
            }]),
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
