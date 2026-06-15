//! The per-computer **routing policy** — the TUN demux brain (§1 of
//! `docs/MESH_V2.md`).
//!
//! One TUN device captures all of this computer's traffic. The policy table is
//! *local user preference* (not mesh state): for each outbound flow it decides
//! which mesh (and exit) carries it, or leaves it untouched (`Direct`). Being at
//! the TUN layer is what lets one computer steer every mesh under a single policy.
//!
//! Priority (§1): a specific rule wins; otherwise the `default` — the user's
//! current-mesh selection, or `Direct` when nothing is selected (VPN idle).

use std::net::Ipv4Addr;

use lattice_proto::wire_v2::{MemberId, MeshId};

/// The fields a policy rule matches on, derived from the outbound IP packet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FlowKey {
    pub dst: Ipv4Addr,
    pub proto: u8,
    pub dport: u16,
}

/// What the data plane does with a flow.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RouteDecision {
    /// Untouched — leave it to the host's normal internet path. The VPN does
    /// nothing (the §1 "default").
    Direct,
    /// Carry it inside mesh `mesh`, egressing at member `exit`. For purely in-mesh
    /// traffic `exit` is the destination peer.
    Via { mesh: MeshId, exit: MemberId },
}

/// A destination match for a rule. Absent fields are wildcards (AND of present).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct FlowMatch {
    /// Destination prefix `(network, prefix_len)`; `prefix_len` 0 matches all.
    pub dst_cidr: Option<(Ipv4Addr, u8)>,
    pub proto: Option<u8>,
    pub dport: Option<u16>,
}

impl FlowMatch {
    fn matches(&self, k: &FlowKey) -> bool {
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

/// The per-computer routing table: an ordered rule list over a default.
#[derive(Clone, Debug)]
pub struct PolicyTable {
    /// Applied when no rule matches — the current-mesh selection, or `Direct`.
    pub default: RouteDecision,
    rules: Vec<(FlowMatch, RouteDecision)>,
}

impl Default for PolicyTable {
    /// Nothing selected ⇒ the VPN is idle, all traffic untouched.
    fn default() -> Self {
        Self {
            default: RouteDecision::Direct,
            rules: Vec::new(),
        }
    }
}

impl PolicyTable {
    pub fn new(default: RouteDecision) -> Self {
        Self {
            default,
            rules: Vec::new(),
        }
    }

    /// Append a rule; earlier rules win on a tie (first-match).
    pub fn push(&mut self, m: FlowMatch, decision: RouteDecision) {
        self.rules.push((m, decision));
    }

    pub fn clear_rules(&mut self) {
        self.rules.clear();
    }

    /// Demux one outbound flow: the first matching rule, else the default.
    pub fn route(&self, key: &FlowKey) -> RouteDecision {
        self.rules
            .iter()
            .find(|(m, _)| m.matches(key))
            .map(|(_, d)| *d)
            .unwrap_or(self.default)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(dst: [u8; 4], proto: u8, dport: u16) -> FlowKey {
        FlowKey {
            dst: Ipv4Addr::from(dst),
            proto,
            dport,
        }
    }

    #[test]
    fn idle_default_leaves_traffic_direct() {
        let p = PolicyTable::default();
        assert_eq!(p.route(&key([1, 1, 1, 1], 6, 443)), RouteDecision::Direct);
    }

    #[test]
    fn default_carries_when_a_cur_mesh_is_selected() {
        let p = PolicyTable::new(RouteDecision::Via { mesh: 3, exit: 7 });
        assert_eq!(
            p.route(&key([1, 1, 1, 1], 6, 443)),
            RouteDecision::Via { mesh: 3, exit: 7 }
        );
    }

    #[test]
    fn specific_rule_overrides_default() {
        // Default: everything via mesh 1; but DNS (udp/53) stays direct.
        let mut p = PolicyTable::new(RouteDecision::Via { mesh: 1, exit: 2 });
        p.push(
            FlowMatch {
                proto: Some(17),
                dport: Some(53),
                ..Default::default()
            },
            RouteDecision::Direct,
        );
        assert_eq!(p.route(&key([9, 9, 9, 9], 17, 53)), RouteDecision::Direct);
        assert_eq!(
            p.route(&key([1, 1, 1, 1], 6, 443)),
            RouteDecision::Via { mesh: 1, exit: 2 }
        );
    }

    #[test]
    fn cidr_rule_matches_subnet() {
        let mut p = PolicyTable::new(RouteDecision::Direct);
        p.push(
            FlowMatch {
                dst_cidr: Some((Ipv4Addr::new(10, 0, 0, 0), 8)),
                ..Default::default()
            },
            RouteDecision::Via { mesh: 5, exit: 1 },
        );
        assert_eq!(
            p.route(&key([10, 9, 9, 9], 6, 80)),
            RouteDecision::Via { mesh: 5, exit: 1 }
        );
        assert_eq!(p.route(&key([11, 0, 0, 1], 6, 80)), RouteDecision::Direct);
    }

    #[test]
    fn first_matching_rule_wins() {
        let mut p = PolicyTable::new(RouteDecision::Direct);
        p.push(
            FlowMatch {
                dst_cidr: Some((Ipv4Addr::new(1, 1, 1, 1), 32)),
                ..Default::default()
            },
            RouteDecision::Via { mesh: 1, exit: 1 },
        );
        p.push(
            FlowMatch::default(), // catch-all, but later — must not shadow the above
            RouteDecision::Via { mesh: 2, exit: 2 },
        );
        assert_eq!(
            p.route(&key([1, 1, 1, 1], 6, 443)),
            RouteDecision::Via { mesh: 1, exit: 1 }
        );
        assert_eq!(
            p.route(&key([8, 8, 8, 8], 6, 443)),
            RouteDecision::Via { mesh: 2, exit: 2 }
        );
    }
}
