//! The SDN **flow table**: an ordered `match → action` forwarding program
//! (OpenFlow-style). Pure data + matching logic — the engine *executes* the
//! actions, the admin-signed `NetworkManifest` *carries* the table, the DHT
//! *distributes* it. See `docs/FLOW_TABLE.md`.
//!
//! Phase 1 scope: the types, matching, and a built-in default table that
//! reproduces the pre-flow-table behavior (overlay → owner, internet → exit).

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::NodeId;

/// Whether a packet's destination is inside the overlay or out to the internet.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum FlowScope {
    Overlay,
    Internet,
}

/// What a packet must look like to match a rule. Absent fields are **wildcards**
/// (match any); all present fields must match (AND).
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct FlowMatch {
    pub scope: Option<FlowScope>,
    /// Destination prefix `(network, prefix_len)`, e.g. `(1.1.1.1, 32)` or
    /// `(10.0.0.0, 8)`. `prefix_len` 0 matches everything.
    pub dst_cidr: Option<(Ipv4Addr, u8)>,
    /// IP protocol number: 1 = ICMP, 6 = TCP, 17 = UDP.
    pub proto: Option<u8>,
    /// Destination port (TCP/UDP).
    pub dport: Option<u16>,
}

/// What to do with a matched packet.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum FlowAction {
    /// Route to the overlay peer that owns the destination VIP (normal mesh).
    ToOverlayOwner,
    /// Forward to an exit node. `None` = the node's runtime-configured exit
    /// (`set_exit_node`), so the legacy behavior is one rule.
    ToExit(Option<NodeId>),
    /// Tunnel to a specific peer by id.
    ToPeer(NodeId),
    /// Deliver to this host's stack (meaningful on the inbound side — we are the
    /// destination/exit). On the outbound side it is a no-op.
    Local,
    /// Discard — isolation / kill-switch / deny.
    Drop,
}

/// One `match → action` rule. Higher `priority` wins; on a tie the earliest rule
/// in the table wins (OpenFlow semantics).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct FlowRule {
    pub priority: u16,
    pub match_: FlowMatch,
    pub action: FlowAction,
}

/// The packet fields the table matches on — the input to evaluation.
#[derive(Clone, Copy, Debug)]
pub struct FlowKey {
    pub scope: FlowScope,
    pub dst: Ipv4Addr,
    pub proto: u8,
    pub dport: u16,
}

impl FlowMatch {
    /// Does every present field match the key? (Absent fields are wildcards.)
    pub fn matches(&self, k: &FlowKey) -> bool {
        if let Some(s) = self.scope {
            if s != k.scope {
                return false;
            }
        }
        if let Some((net, len)) = self.dst_cidr {
            if !cidr_contains(net, len, k.dst) {
                return false;
            }
        }
        if let Some(p) = self.proto {
            if p != k.proto {
                return false;
            }
        }
        if let Some(dp) = self.dport {
            if dp != k.dport {
                return false;
            }
        }
        true
    }
}

fn cidr_contains(net: Ipv4Addr, len: u8, ip: Ipv4Addr) -> bool {
    if len == 0 {
        return true;
    }
    let mask: u32 = if len >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - len)
    };
    (u32::from(net) & mask) == (u32::from(ip) & mask)
}

/// Evaluate a rule set against a key: the **highest-priority match**, breaking
/// ties toward the earliest rule. `None` if nothing matches (caller drops).
pub fn first_match<'a>(rules: &'a [FlowRule], k: &FlowKey) -> Option<&'a FlowRule> {
    let mut best: Option<&FlowRule> = None;
    for r in rules {
        if r.match_.matches(k) {
            match best {
                Some(b) if b.priority >= r.priority => {}
                _ => best = Some(r),
            }
        }
    }
    best
}

/// The built-in default table — reproduces pre-flow-table behavior exactly:
/// overlay traffic to the owning peer, internet traffic to the configured exit.
/// Used when the manifest carries no `flows`, so adding the table is a no-op
/// until an admin programs one.
pub fn default_table() -> Vec<FlowRule> {
    vec![
        FlowRule {
            priority: 100,
            match_: FlowMatch {
                scope: Some(FlowScope::Overlay),
                ..Default::default()
            },
            action: FlowAction::ToOverlayOwner,
        },
        FlowRule {
            priority: 50,
            match_: FlowMatch {
                scope: Some(FlowScope::Internet),
                ..Default::default()
            },
            action: FlowAction::ToExit(None),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(scope: FlowScope, dst: [u8; 4], proto: u8, dport: u16) -> FlowKey {
        FlowKey {
            scope,
            dst: Ipv4Addr::from(dst),
            proto,
            dport,
        }
    }

    #[test]
    fn default_table_reproduces_overlay_and_exit() {
        let t = default_table();
        let overlay = key(FlowScope::Overlay, [100, 80, 0, 1], 6, 22);
        let inet = key(FlowScope::Internet, [1, 1, 1, 1], 6, 443);
        assert_eq!(
            first_match(&t, &overlay).unwrap().action,
            FlowAction::ToOverlayOwner
        );
        assert_eq!(
            first_match(&t, &inet).unwrap().action,
            FlowAction::ToExit(None)
        );
    }

    #[test]
    fn higher_priority_and_cidr_and_port_win() {
        let mut t = default_table();
        // DNS (udp/53) to a specific exit, above the generic internet rule.
        t.push(FlowRule {
            priority: 90,
            match_: FlowMatch {
                proto: Some(17),
                dport: Some(53),
                ..Default::default()
            },
            action: FlowAction::ToPeer(NodeId([7u8; 32])),
        });
        let dns = key(FlowScope::Internet, [9, 9, 9, 9], 17, 53);
        assert_eq!(
            first_match(&t, &dns).unwrap().action,
            FlowAction::ToPeer(NodeId([7u8; 32]))
        );
        // non-DNS internet still falls through to the generic exit rule.
        let web = key(FlowScope::Internet, [1, 1, 1, 1], 6, 443);
        assert_eq!(
            first_match(&t, &web).unwrap().action,
            FlowAction::ToExit(None)
        );
    }

    #[test]
    fn default_deny_drops_unmatched() {
        // A table with only a terminal default-deny + an explicit mesh allow.
        let t = vec![
            FlowRule {
                priority: 100,
                match_: FlowMatch {
                    scope: Some(FlowScope::Overlay),
                    ..Default::default()
                },
                action: FlowAction::ToOverlayOwner,
            },
            FlowRule {
                priority: 0,
                match_: FlowMatch::default(),
                action: FlowAction::Drop,
            },
        ];
        let inet = key(FlowScope::Internet, [1, 1, 1, 1], 6, 443);
        assert_eq!(first_match(&t, &inet).unwrap().action, FlowAction::Drop);
        let overlay = key(FlowScope::Overlay, [100, 80, 0, 1], 6, 22);
        assert_eq!(
            first_match(&t, &overlay).unwrap().action,
            FlowAction::ToOverlayOwner
        );
    }

    #[test]
    fn cidr_match() {
        let t = vec![FlowRule {
            priority: 10,
            match_: FlowMatch {
                dst_cidr: Some((Ipv4Addr::new(10, 0, 0, 0), 8)),
                ..Default::default()
            },
            action: FlowAction::Drop,
        }];
        assert!(first_match(&t, &key(FlowScope::Internet, [10, 5, 5, 5], 6, 80)).is_some());
        assert!(first_match(&t, &key(FlowScope::Internet, [11, 0, 0, 1], 6, 80)).is_none());
    }
}
