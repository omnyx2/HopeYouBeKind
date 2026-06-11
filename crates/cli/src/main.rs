//! `lattice` — the terminal control client. It speaks the IPC contract from
//! `lattice_proto::ipc` to the daemon; it never touches the network itself.

use anyhow::Result;
use clap::{Parser, Subcommand};
use lattice_proto::ipc::{Request, Response};

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
                println!("{}  {}  {:?}", p.id.fingerprint(), p.virtual_ip, p.status);
            }
        }
        Response::Done => println!("ok"),
        Response::Error { message } => eprintln!("error: {message}"),
    }
}
