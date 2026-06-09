//! DHT wire messages. Serialized with bincode for the UDP transport; passed
//! directly in the in-memory test transport.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::distance::Key;
use crate::routing::Contact;

/// A request or response exchanged between DHT nodes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Message {
    /// Liveness probe.
    Ping,
    /// Reply to `Ping`.
    Pong,
    /// "Tell me the contacts you know closest to `target`."
    FindNode { target: Key },
    /// "Give me the value stored under `key`, or the closest contacts you know."
    FindValue { key: Key },
    /// Response to `FindNode`/`FindValue` when no value is held.
    Nodes { contacts: Vec<Contact> },
    /// Response to `FindValue` when the value is held.
    Value { addrs: Vec<SocketAddr> },
    /// "Store these candidate addresses under `key`."
    Store { key: Key, addrs: Vec<SocketAddr> },
    /// Reply to `Store`.
    Stored,
}
