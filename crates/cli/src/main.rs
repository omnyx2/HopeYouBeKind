//! `lattice` — the terminal control client. It speaks the IPC contract from
//! `lattice_proto::ipc` to the daemon; it never touches the network itself.

use anyhow::Result;
use clap::{Parser, Subcommand};
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
            Command::Crypto(CryptoCommand::Swap { name }) => Request::SetCryptoSuite {
                name: name.clone(),
            },
            Command::Crypto(CryptoCommand::Stats) => Request::CryptoStats,
            Command::Crypto(CryptoCommand::Sessions) => Request::SessionDetails,
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
        Response::Packets(pkts) => println!("{} packet(s)", pkts.len()),
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
            println!("{:<22} {:>6} {:>5} {:>5} {:>8}", "suite", "count", "init", "resp", "median");
            for s in stats {
                println!(
                    "{:<22} {:>6} {:>5} {:>5} {:>6}ms",
                    s.name, s.handshakes, s.init_bytes, s.resp_bytes, s.median_ms
                );
            }
        }
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
        Response::Error { message } => eprintln!("error: {message}"),
    }
}
