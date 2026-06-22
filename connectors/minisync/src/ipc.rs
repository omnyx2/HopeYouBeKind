//! The meshd control-plane IPC contract, mirrored on the connector side.
//!
//! These types are a **subset** of `crates/mesh/src/ipc.rs` — only the request
//! and response variants a connector actually exchanges (docs/EXTENSIONS.md
//! §3/§5). They reproduce meshd's serde shapes exactly so the newline-JSON wire
//! is identical, while keeping this crate fully decoupled from the workspace
//! crates (no path dependency on `lattice-mesh`).
//!
//! Wire format: one JSON value per line, `\n`-terminated, both directions.
//! serde's default external tagging means each enum variant is
//! `{ "VariantName": <payload> }`, except unit variants which serialize as the
//! bare string `"VariantName"` (e.g. [`Response::Ok`]).

use serde::{Deserialize, Serialize};

/// Mesh id — `u8` in `lattice_proto::wire_v2`, so a plain JSON number on the wire.
pub type MeshId = u8;
/// Member id — `u8` likewise.
pub type MemberId = u8;

/// A connector → meshd request. Only the variants MiniSync sends are modelled;
/// meshd's `Request` enum is a superset and deserializes these fine.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Request {
    /// Authenticate this connection as an enabled extension. Must be first.
    Hello {
        id: String,
        #[serde(default)]
        version: String,
        token: String,
    },
    /// Turn the connection into an event stream for the given bus topics.
    ///
    /// NOTE (contract gap, see README): meshd's `scope_for_topic` matches the
    /// SHORT topic names `"peer" | "exit" | "health" | "service"`, **not** the
    /// `"events:peer"` form shown in docs/EXTENSIONS.md §3/§5. We send the short
    /// form so this works against the real daemon.
    Subscribe { topics: Vec<String> },
    /// Advertise that THIS node offers `proto` on its overlay IP at `port`.
    Advertise {
        mesh: MeshId,
        proto: String,
        port: u16,
        #[serde(default)]
        name: String,
        #[serde(default)]
        meta: serde_json::Value,
    },
    /// Withdraw a previously advertised service.
    Unadvertise { mesh: MeshId, proto: String },
    /// Discover services advertised in `mesh` (optionally filtered to one `proto`).
    ListServices {
        mesh: MeshId,
        #[serde(default)]
        proto: Option<String>,
    },
}

/// A meshd → connector reply (the subset a connector connection can receive).
///
/// `#[serde(untagged)]` is intentionally NOT used: meshd tags externally. Unit
/// variant `Ok` is the bare string `"Ok"` on the wire.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Response {
    /// `Hello` accepted — the scopes this connection now holds (long form,
    /// e.g. `["events:peer", "registry:read", "registry:advertise"]`).
    HelloOk { scopes: Vec<String> },
    /// Generic success ack (e.g. for `Subscribe` / `Advertise`).
    Ok,
    /// Success carrying a human message.
    Info { message: String },
    /// Failure with a reason.
    Error { message: String },
    /// Discovered services (reply to `ListServices`).
    Services(Vec<ServiceView>),
    /// A pushed event on a subscribed connection — NOT a reply. `seq` is
    /// monotonic per connection; a gap (or a `"_lagged"` topic) means events
    /// were dropped and the connector should re-query authoritative state.
    Event {
        topic: String,
        seq: u64,
        ts_ms: u64,
        data: serde_json::Value,
    },
}

/// One discovered service (mirrors `mesh::ipc::ServiceView`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceView {
    pub mesh: MeshId,
    pub member: MemberId,
    pub member_name: String,
    /// The owner's overlay IP — where a connector connects to reach the service.
    pub overlay_ip: String,
    pub proto: String,
    pub port: u16,
    pub name: String,
    pub meta: serde_json::Value,
    /// Whether the owner is currently live; self = always true.
    pub online: bool,
}

/// Parsed `events:peer` event payload (docs/EXTENSIONS.md §5). All fields past
/// `kind` are optional so a coarse/partial event still parses — the connector
/// treats any peer event as a trigger to re-query `ListServices` regardless.
#[derive(Clone, Debug, Deserialize)]
pub struct PeerEventData {
    /// `"peer_up"` | `"peer_down"` (informational; we re-query either way).
    pub kind: String,
    #[serde(default)]
    pub mesh: Option<MeshId>,
    #[serde(default)]
    pub member: Option<MemberId>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub overlay_ip: Option<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_is_bare_string() {
        // meshd serializes a unit variant as the bare string, not {"Ok":null}.
        assert_eq!(serde_json::to_string(&Response::Ok).unwrap(), "\"Ok\"");
        let r: Response = serde_json::from_str("\"Ok\"").unwrap();
        assert!(matches!(r, Response::Ok));
    }

    #[test]
    fn hello_roundtrips_externally_tagged() {
        let h = Request::Hello {
            id: "minisync".into(),
            version: "0.2.0".into(),
            token: "ab12".into(),
        };
        let s = serde_json::to_string(&h).unwrap();
        assert_eq!(
            s,
            r#"{"Hello":{"id":"minisync","version":"0.2.0","token":"ab12"}}"#
        );
    }

    #[test]
    fn services_and_event_parse() {
        let line = r#"{"Services":[{"mesh":42,"member":3,"member_name":"alice","overlay_ip":"100.80.42.3","proto":"minisync","port":48211,"name":"","meta":{"folder":"SharedFolder"},"online":true}]}"#;
        let r: Response = serde_json::from_str(line).unwrap();
        match r {
            Response::Services(v) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].overlay_ip, "100.80.42.3");
                assert_eq!(v[0].port, 48211);
            }
            _ => panic!("expected Services"),
        }

        let ev = r#"{"Event":{"topic":"peer","seq":1,"ts_ms":1718900000000,"data":{"kind":"peer_up","mesh":42,"member":3,"name":"alice","overlay_ip":"100.80.42.3"}}}"#;
        let r: Response = serde_json::from_str(ev).unwrap();
        match r {
            Response::Event { topic, data, .. } => {
                assert_eq!(topic, "peer");
                let pe: PeerEventData = serde_json::from_value(data).unwrap();
                assert_eq!(pe.kind, "peer_up");
                assert_eq!(pe.overlay_ip.as_deref(), Some("100.80.42.3"));
            }
            _ => panic!("expected Event"),
        }
    }
}
