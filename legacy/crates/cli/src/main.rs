//! `lattice` — the terminal control client. It speaks the IPC contract from
//! `lattice_proto::ipc` to the daemon; it never touches the network itself.

use anyhow::Result;
use clap::{Parser, Subcommand};
use lattice_proto::flow::{FlowAction, FlowMatch, FlowRule, FlowScope};
use lattice_proto::ipc::{Request, Response};
use lattice_proto::NodeId;

/// Control the Lattice mesh from the terminal.
#[derive(Parser, Debug)]
#[command(name = "lattice", version, about)]
struct Cli {
    /// Path to the daemon's IPC socket.
    #[arg(long, default_value = "/tmp/lattice.sock")]
    ipc_socket: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Bring the mesh interface up.
    Up,
    /// Tear the mesh interface down.
    Down,
    /// Show this node's status.
    Status,
    /// List known peers.
    Peers,
    /// Show live traffic flows crossing the tunnel.
    Flows,
    /// Health check: list every node's virtual IP on the mesh at once.
    /// SECURITY-SENSITIVE and access-controlled — the daemon only answers a
    /// caller whose process name is on its `--health-allow` list (default
    /// `minisync`), so run as a binary by that name. See docs/HEALTH_CHECK.md.
    Health,
    /// Manage mesh membership (network identity, enrollment, eviction).
    #[command(subcommand)]
    Net(NetCommand),
    /// Crypto swap-lab: list/compare suites, hot-swap, inspect sessions.
    #[command(subcommand)]
    Crypto(CryptoCommand),
    /// Packet inspector (admin): capture decrypted tunnel packets. Gated by the
    /// daemon's `--admin-allow` list (run this as a name on that list).
    #[command(subcommand)]
    Capture(CaptureCommand),
    /// Exit node (VPN-style full tunnel): act as an exit for others, or route
    /// this node's internet traffic out through a chosen exit peer.
    #[command(subcommand)]
    Exit(ExitCommand),
    /// Admin: program the SDN flow table (match→action). Published in the signed
    /// manifest and hot-reloaded by every node. See docs/FLOW_TABLE.md.
    #[command(subcommand)]
    Flow(FlowCommand),
}

#[derive(Subcommand, Debug)]
enum FlowCommand {
    /// Show the current flow table (numbered, highest-priority first).
    List,
    /// Append a match→action rule.
    Add {
        /// Higher wins; ties break toward the earliest rule. Default 50.
        #[arg(long, default_value_t = 50)]
        priority: u16,
        /// Match scope: `overlay` (mesh) or `internet`.
        #[arg(long)]
        scope: Option<String>,
        /// Match destination CIDR, e.g. `1.1.1.1/32` or `10.0.0.0/8`.
        #[arg(long)]
        dst: Option<String>,
        /// Match protocol: `tcp` | `udp` | `icmp` | a number.
        #[arg(long)]
        proto: Option<String>,
        /// Match destination port.
        #[arg(long)]
        dport: Option<u16>,
        /// Action: `drop` | `local` | `overlay` | `exit` | `exit:<64hex>` |
        /// `peer:<64hex>`.
        #[arg(long)]
        action: String,
    },
    /// Delete the rule at `index` (as numbered by `list`).
    Del { index: usize },
    /// Clear the flow table — every node reverts to the built-in default.
    Clear,
}

/// Parse an `--action` string into a `FlowAction`.
fn parse_action(s: &str) -> Result<FlowAction> {
    Ok(match s {
        "drop" => FlowAction::Drop,
        "local" => FlowAction::Local,
        "overlay" => FlowAction::ToOverlayOwner,
        "exit" => FlowAction::ToExit(None),
        other => {
            if let Some(hex) = other.strip_prefix("exit:") {
                FlowAction::ToExit(Some(parse_id(hex)?))
            } else if let Some(hex) = other.strip_prefix("peer:") {
                FlowAction::ToPeer(parse_id(hex)?)
            } else {
                anyhow::bail!(
                    "unknown action '{other}' (drop|local|overlay|exit|exit:<id>|peer:<id>)"
                );
            }
        }
    })
}

/// Build a `FlowMatch` from the optional CLI fields.
fn build_match(
    scope: &Option<String>,
    dst: &Option<String>,
    proto: &Option<String>,
    dport: Option<u16>,
) -> Result<FlowMatch> {
    let scope = match scope.as_deref() {
        None => None,
        Some("overlay") => Some(FlowScope::Overlay),
        Some("internet") => Some(FlowScope::Internet),
        Some(o) => anyhow::bail!("unknown scope '{o}' (overlay|internet)"),
    };
    let dst_cidr = match dst {
        None => None,
        Some(s) => {
            let (ip, len) = match s.split_once('/') {
                Some((ip, len)) => (
                    ip,
                    len.parse().map_err(|_| anyhow::anyhow!("bad prefix len"))?,
                ),
                None => (s.as_str(), 32u8),
            };
            Some((ip.parse().map_err(|_| anyhow::anyhow!("bad dst ip"))?, len))
        }
    };
    let proto = match proto.as_deref() {
        None => None,
        Some("tcp") => Some(6),
        Some("udp") => Some(17),
        Some("icmp") => Some(1),
        Some(n) => Some(n.parse().map_err(|_| anyhow::anyhow!("bad proto '{n}'"))?),
    };
    Ok(FlowMatch {
        scope,
        dst_cidr,
        proto,
        dport,
    })
}

#[derive(Subcommand, Debug)]
enum ExitCommand {
    /// Volunteer this node as an exit (IP forwarding + source-NAT). `--off` stops.
    Allow {
        /// Stop acting as an exit node.
        #[arg(long)]
        off: bool,
    },
    /// Route this node's internet traffic through exit peer `node_id` (full
    /// tunnel). `--off` (or omitting node_id) goes back to direct.
    Use {
        /// The exit peer's 64-hex node id (from `peers` / its Status).
        node_id: Option<String>,
        /// Go back to direct internet (no exit).
        #[arg(long)]
        off: bool,
        /// Split tunnel: forward to the exit but DON'T divert the OS default
        /// route — only destinations you route into the TUN egress via the exit.
        /// Non-disruptive (won't knock the host offline); use for verification.
        #[arg(long)]
        split: bool,
    },
}

#[derive(Subcommand, Debug)]
enum CaptureCommand {
    /// Arm the capture (optionally filtered) and clear any previous buffer.
    Start {
        /// Only this protocol: tcp | udp | icmp.
        #[arg(long)]
        proto: Option<String>,
        /// Only flows touching this port.
        #[arg(long)]
        port: Option<u16>,
        /// Only packets to/from this peer (short fingerprint prefix).
        #[arg(long)]
        peer: Option<String>,
    },
    /// Disarm the capture and clear its buffer.
    Stop,
    /// Show capture state (armed?, buffered, dropped).
    Status,
    /// Print captured packets with seq > `after` (cursor; default 0 = all).
    Packets {
        #[arg(long, default_value_t = 0)]
        after: u64,
    },
}

#[derive(Subcommand, Debug)]
enum CryptoCommand {
    /// List the crypto suites this node can run (* = active).
    List,
    /// Swap the active crypto suite by name → re-handshakes all sessions.
    Swap {
        /// Suite name, e.g. `noise-ik-aesgcm`.
        name: String,
    },
    /// Per-suite handshake comparison (init/resp bytes, median ms).
    Stats,
    /// Per-peer live session detail (suite, age, rekey countdown, counters).
    Sessions,
    /// Bench: encrypt text with the active suite → prints the ciphertext hex.
    Encrypt {
        /// Plaintext to seal.
        text: String,
    },
    /// Bench: decrypt a ciphertext hex with the active suite → prints the plaintext
    /// (or "rejected" if tampered/replayed/past a time-window cipher's window).
    Decrypt {
        /// Ciphertext as hex (from `crypto encrypt`).
        hex: String,
    },
}

#[derive(Subcommand, Debug)]
enum NetCommand {
    /// Show this node's network id and membership status.
    Info,
    /// Admin: issue a join token (membership cert) for a node id.
    Issue {
        /// The joining node's 64-hex node id (from its Status panel).
        node_id: String,
        /// Optional human label to remember this member by.
        #[arg(long)]
        label: Option<String>,
    },
    /// Adopt a join token issued for this node — join its network now.
    Join {
        /// The hex token printed by `net issue` on the admin node.
        token: String,
    },
    /// Admin: evict a member by node id (revoke its certificate).
    Revoke {
        /// The member's 64-hex node id.
        node_id: String,
    },
    /// Admin: designate (or with --off, undesignate) a member as a relay for
    /// peers that can't connect directly. Published in the signed manifest.
    Relay {
        /// The member's 64-hex node id.
        node_id: String,
        /// Remove the relay designation instead of adding it.
        #[arg(long)]
        off: bool,
    },
    /// Admin: list members this node's CA has enrolled.
    Members,
}

fn parse_id(hex: &str) -> Result<NodeId> {
    if hex.len() != 64 {
        anyhow::bail!("node id must be 64 hex chars");
    }
    let mut id = [0u8; 32];
    for (i, b) in id.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| anyhow::anyhow!("invalid hex in node id"))?;
    }
    Ok(NodeId(id))
}

impl Command {
    fn to_request(&self) -> Result<Request> {
        Ok(match self {
            Command::Up => Request::Up,
            Command::Down => Request::Down,
            Command::Status => Request::Status,
            Command::Peers => Request::Peers,
            Command::Flows => Request::Flows,
            Command::Health => Request::HealthCheck,
            Command::Net(NetCommand::Info) => Request::NetworkInfo,
            Command::Net(NetCommand::Members) => Request::Members,
            Command::Net(NetCommand::Issue { node_id, label }) => Request::IssueCert {
                node_id: parse_id(node_id)?,
                label: label.clone(),
            },
            Command::Net(NetCommand::Join { token }) => Request::JoinNetwork {
                token: token.clone(),
            },
            Command::Net(NetCommand::Revoke { node_id }) => Request::RevokeMember {
                node_id: parse_id(node_id)?,
            },
            Command::Net(NetCommand::Relay { node_id, off }) => Request::DesignateRelay {
                node_id: parse_id(node_id)?,
                on: !off,
            },
            Command::Crypto(CryptoCommand::List) => Request::CryptoSuites,
            Command::Crypto(CryptoCommand::Swap { name }) => {
                Request::SetCryptoSuite { name: name.clone() }
            }
            Command::Crypto(CryptoCommand::Stats) => Request::CryptoStats,
            Command::Crypto(CryptoCommand::Sessions) => Request::SessionDetails,
            Command::Crypto(CryptoCommand::Encrypt { text }) => {
                Request::CryptoEncrypt { text: text.clone() }
            }
            Command::Crypto(CryptoCommand::Decrypt { hex }) => {
                Request::CryptoDecrypt { hex: hex.clone() }
            }
            Command::Capture(CaptureCommand::Start { proto, port, peer }) => {
                Request::CaptureStart {
                    filter: lattice_proto::ipc::CaptureFilter {
                        peer: peer.clone(),
                        protocol: proto.clone(),
                        port: *port,
                    },
                }
            }
            Command::Capture(CaptureCommand::Stop) => Request::CaptureStop,
            Command::Capture(CaptureCommand::Status) => Request::CaptureStatus,
            Command::Capture(CaptureCommand::Packets { after }) => {
                Request::Packets { after: *after }
            }
            Command::Exit(ExitCommand::Allow { off }) => Request::AllowExit { enabled: !off },
            Command::Exit(ExitCommand::Use {
                node_id,
                off,
                split,
            }) => {
                let node_id = match (off, node_id) {
                    (true, _) | (false, None) => None,
                    (false, Some(hex)) => Some(parse_id(hex)?),
                };
                Request::SetExit {
                    node_id,
                    full_tunnel: !split,
                }
            }
            Command::Flow(FlowCommand::List) => Request::FlowList,
            Command::Flow(FlowCommand::Clear) => Request::FlowClear,
            Command::Flow(FlowCommand::Del { index }) => Request::FlowDel { index: *index },
            Command::Flow(FlowCommand::Add {
                priority,
                scope,
                dst,
                proto,
                dport,
                action,
            }) => Request::FlowAdd {
                rule: FlowRule {
                    priority: *priority,
                    match_: build_match(scope, dst, proto, *dport)?,
                    action: parse_action(action)?,
                },
            },
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let request = cli.command.to_request()?;

    let response = lattice_ipc::request(&cli.ipc_socket, request)
        .await
        .map_err(|e| anyhow::anyhow!("could not reach daemon at {}: {e}", cli.ipc_socket))?;

    print_response(response);
    Ok(())
}

fn print_response(response: Response) {
    match response {
        Response::Status(s) => {
            println!("node      {}", s.id.fingerprint());
            println!("node-id   {}", s.id.to_hex());
            println!(
                "virtual   {}",
                s.virtual_ip
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "—".into())
            );
            println!("mesh      {}", if s.running { "up" } else { "down" });
            println!("peers     {}", s.peer_count);
            println!(
                "exit-via  {}",
                s.exit_node
                    .map(|e| e.fingerprint())
                    .unwrap_or_else(|| "direct".into())
            );
            println!("is-exit   {}", if s.is_exit { "yes" } else { "no" });
        }
        Response::Peers(peers) => {
            if peers.is_empty() {
                println!("no peers yet");
            }
            for p in peers {
                println!(
                    "{}  {}  {:<10}  {:?}",
                    p.id.fingerprint(),
                    p.virtual_ip,
                    p.os.as_deref().unwrap_or("?"),
                    p.status
                );
            }
        }
        Response::Flows(flows) => {
            if flows.is_empty() {
                println!("no traffic yet");
            }
            for f in flows {
                println!(
                    "{:<5}  {:<22} <-> {:<22}  ↑{}p/{}B ↓{}p/{}B  {}s ago",
                    f.protocol,
                    f.local,
                    f.remote,
                    f.tx_packets,
                    f.tx_bytes,
                    f.rx_packets,
                    f.rx_bytes,
                    f.last_active_secs
                );
            }
        }
        Response::NetworkInfo(n) => match n.network_id {
            Some(id) => {
                println!("network   {}", id);
                println!("fingerprint {}", n.fingerprint.unwrap_or_default());
                println!(
                    "role      {}",
                    if n.is_admin { "admin (CA)" } else { "member" }
                );
                if n.is_admin {
                    println!("members   {}", n.member_count);
                }
                println!("revoked   {}", n.revocation_count);
            }
            None => println!("open mode (no network — any peer may join)"),
        },
        Response::Members(members) => {
            if members.is_empty() {
                println!("no members enrolled");
            }
            for m in members {
                println!(
                    "{}  serial {:<4} {:<16} {}{}",
                    m.fingerprint,
                    m.serial,
                    m.label.as_deref().unwrap_or("-"),
                    if m.revoked { "REVOKED" } else { "active" },
                    if m.relay { "  [relay]" } else { "" }
                );
            }
        }
        Response::Health(entries) => {
            if entries.is_empty() {
                println!("no nodes on the mesh");
            }
            for e in entries {
                println!("{:<15}  {:<8}  {}", e.virtual_ip, e.fingerprint, e.status);
            }
        }
        Response::Token(token) => {
            println!("join token (give to the node, then `lattice net join <token>`):\n{token}");
        }
        Response::Done => println!("ok"),
        // The packet capture is driven by the admin console, not this CLI; print a
        // terse summary if one ever lands here.
        Response::CaptureState(s) => println!(
            "capture {} — {} buffered / {} cap, {} dropped",
            if s.active { "active" } else { "stopped" },
            s.buffered,
            s.cap,
            s.dropped
        ),
        Response::Packets(pkts) => {
            if pkts.is_empty() {
                println!("no packets captured yet (only decrypted overlay data is captured — send traffic between overlay IPs)");
            }
            for p in pkts {
                let flags = p.tcp_flags.map(|f| format!(" [{f}]")).unwrap_or_default();
                println!(
                    "#{:<4} {:<3} {:<5} {} -> {}  {}B{}",
                    p.seq, p.dir, p.protocol, p.src, p.dst, p.length, flags
                );
            }
        }
        Response::CryptoSuites(suites) => {
            for s in suites {
                println!(
                    "{} {:<22} {}_{}_{}_{}",
                    if s.active { "*" } else { " " },
                    s.name,
                    s.pattern,
                    s.dh,
                    s.aead,
                    s.hash
                );
            }
        }
        Response::CryptoSuite(s) => println!("{} ({})", s.name, s.aead),
        Response::CryptoStats(stats) => {
            if stats.is_empty() {
                println!("no handshakes recorded yet");
            }
            println!(
                "{:<22} {:>6} {:>5} {:>5} {:>8}",
                "suite", "count", "init", "resp", "median"
            );
            for s in stats {
                println!(
                    "{:<22} {:>6} {:>5} {:>5} {:>6}ms",
                    s.name, s.handshakes, s.init_bytes, s.resp_bytes, s.median_ms
                );
            }
        }
        Response::CryptoBytes { hex } => println!("{hex}"),
        Response::CryptoText { text } => println!("{text}"),
        Response::SessionDetails(sessions) => {
            if sessions.is_empty() {
                println!("no live sessions");
            }
            for s in sessions {
                println!(
                    "{}  {:<22} age {}s  rekey in {}s  tx {}  rx {}  rejects {}",
                    s.peer,
                    s.suite,
                    s.age_secs,
                    s.rekey_in_secs,
                    s.send_counter,
                    s.replay_latest,
                    s.replay_rejects
                );
            }
        }
        Response::FlowRules(rules) => {
            if rules.is_empty() {
                println!("flow table empty — nodes use the built-in default (overlay→owner, internet→exit)");
            }
            // Show in evaluation order: highest priority first (ties keep input order).
            let mut idx: Vec<usize> = (0..rules.len()).collect();
            idx.sort_by(|&a, &b| rules[b].priority.cmp(&rules[a].priority));
            for i in idx {
                let r = &rules[i];
                println!(
                    "[{i}] prio {:>3}  {:<28} → {}",
                    r.priority,
                    fmt_match(&r.match_),
                    fmt_action(&r.action),
                );
            }
        }
        Response::Error { message } => eprintln!("error: {message}"),
    }
}

fn fmt_match(m: &FlowMatch) -> String {
    let mut parts = Vec::new();
    match m.scope {
        Some(FlowScope::Overlay) => parts.push("scope=overlay".to_string()),
        Some(FlowScope::Internet) => parts.push("scope=internet".to_string()),
        None => {}
    }
    if let Some((ip, len)) = m.dst_cidr {
        parts.push(format!("dst={ip}/{len}"));
    }
    if let Some(p) = m.proto {
        let name = match p {
            6 => "tcp".into(),
            17 => "udp".into(),
            1 => "icmp".into(),
            n => n.to_string(),
        };
        parts.push(format!("proto={name}"));
    }
    if let Some(dp) = m.dport {
        parts.push(format!("dport={dp}"));
    }
    if parts.is_empty() {
        "*".into()
    } else {
        parts.join(" ")
    }
}

fn fmt_action(a: &FlowAction) -> String {
    match a {
        FlowAction::ToOverlayOwner => "overlay-owner".into(),
        FlowAction::ToExit(None) => "exit(configured)".into(),
        FlowAction::ToExit(Some(id)) => format!("exit({})", id.fingerprint()),
        FlowAction::ToPeer(id) => format!("peer({})", id.fingerprint()),
        FlowAction::Local => "local".into(),
        FlowAction::Drop => "DROP".into(),
    }
}
