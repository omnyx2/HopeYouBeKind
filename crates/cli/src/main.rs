//! `lattice` — the terminal control client. It speaks the IPC contract from
//! `lattice_proto::ipc` to the daemon; it never touches the network itself.

use anyhow::Result;
use clap::{Parser, Subcommand};
use lattice_proto::ipc::Request;

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
}

impl Command {
    fn to_request(&self) -> Request {
        match self {
            Command::Up => Request::Up,
            Command::Down => Request::Down,
            Command::Status => Request::Status,
            Command::Peers => Request::Peers,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let request = cli.command.to_request();

    // TODO(v0.4): connect to `cli.ipc_socket`, send `request` as JSON, await the
    // Response, and pretty-print it. Until the daemon's IPC server exists we
    // just show what would be sent.
    let wire = serde_json::to_string(&request)?;
    println!("→ {} (would send to {})", wire, cli.ipc_socket);
    Ok(())
}
