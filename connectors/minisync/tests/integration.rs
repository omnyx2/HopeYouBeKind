//! End-to-end: two MiniSync instances discover each other through a
//! `mock_meshd` and sync a folder between them over localhost.
//!
//! Topology (no real meshd needed):
//!   instance A  ──UnixSocket──▶  mock A   (ListServices → "B at 127.0.0.1:portB")
//!   instance B  ──UnixSocket──▶  mock B   (ListServices → "A at 127.0.0.1:portA")
//! Each instance runs the real connector client + sync server + reconcile loop.
//! A starts with alpha.txt + sub/nested.txt; B starts with beta.txt. After
//! discovery they converge: both folders hold all three files, byte-identical.

#![cfg(unix)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use minisync::config::Config;
use minisync::ipc::ServiceView;
use minisync::mock::{self, MockConfig};
use minisync::{meshd, sync};

use tokio::net::TcpListener;
use tokio::sync::watch;

fn tmp_dir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "minisync-it-{}-{}-{:?}",
        std::process::id(),
        tag,
        Instant::now()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn write(root: &Path, rel: &str, content: &[u8]) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

fn service_at(port: u16, member: u8, name: &str) -> ServiceView {
    ServiceView {
        mesh: 0,
        member,
        member_name: name.into(),
        overlay_ip: "127.0.0.1".into(), // public-repo constraint: loopback only
        proto: "minisync".into(),
        port,
        name: format!("MiniSync — {name}"),
        meta: serde_json::json!({ "folder": name }),
        online: true,
    }
}

fn config_for(folder: PathBuf, port: u16, token: &str, endpoint: &str) -> Config {
    Config {
        folder,
        listen_port: port,
        meshd_endpoint: endpoint.into(),
        token: token.into(),
        mesh: 0,
        sync_interval_secs: 1,
        advertise_refresh_secs: 60,
        self_overlay_ip: None, // each mock returns only the *other* peer
    }
}

async fn read_to_string(path: &Path) -> Option<String> {
    tokio::fs::read_to_string(path).await.ok()
}

#[tokio::test]
async fn two_instances_sync_through_mock_meshd() {
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    // --- seed two folders with distinct content ---
    let dir_a = tmp_dir("a");
    let dir_b = tmp_dir("b");
    write(&dir_a, "alpha.txt", b"hello from A");
    write(&dir_a, "sub/nested.txt", b"nested A payload");
    write(&dir_b, "beta.txt", b"hello from B");

    // --- bind both sync servers on ephemeral ports so we know the addresses ---
    let lis_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lis_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port_a = lis_a.local_addr().unwrap().port();
    let port_b = lis_b.local_addr().unwrap().port();

    tokio::spawn(sync::run_server_on(dir_a.clone(), lis_a));
    tokio::spawn(sync::run_server_on(dir_b.clone(), lis_b));

    // --- one mock_meshd per instance, each pointing at the *other* peer ---
    let peer_up = serde_json::json!({
        "kind": "peer_up", "mesh": 0, "member": 2,
        "name": "peer", "overlay_ip": "127.0.0.1"
    });
    let mut mc_a = MockConfig::with_minisync_grant("token-A");
    mc_a.services = vec![service_at(port_b, 2, "B")];
    mc_a.peer_events = vec![peer_up.clone()];
    let mut mc_b = MockConfig::with_minisync_grant("token-B");
    mc_b.services = vec![service_at(port_a, 1, "A")];
    mc_b.peer_events = vec![peer_up];

    let mock_a = mock::start(mc_a).await.unwrap();
    let mock_b = mock::start(mc_b).await.unwrap();

    // --- meshd connector clients feed discovered peers into the sync loops ---
    let (tx_a, rx_a) = watch::channel::<Vec<SocketAddr>>(Vec::new());
    let (tx_b, rx_b) = watch::channel::<Vec<SocketAddr>>(Vec::new());

    let cfg_a = config_for(
        dir_a.clone(),
        port_a,
        "token-A",
        mock_a.path.to_str().unwrap(),
    );
    let cfg_b = config_for(
        dir_b.clone(),
        port_b,
        "token-B",
        mock_b.path.to_str().unwrap(),
    );

    {
        let cfg_a = cfg_a.clone();
        let path_a = mock_a.path.clone();
        tokio::spawn(async move {
            let stream = meshd::connect(path_a.to_str().unwrap()).await.unwrap();
            let _ = meshd::run_session(&cfg_a, stream, &tx_a).await;
        });
    }
    {
        let cfg_b = cfg_b.clone();
        let path_b = mock_b.path.clone();
        tokio::spawn(async move {
            let stream = meshd::connect(path_b.to_str().unwrap()).await.unwrap();
            let _ = meshd::run_session(&cfg_b, stream, &tx_b).await;
        });
    }

    tokio::spawn(sync::run_sync_loop(
        dir_a.clone(),
        rx_a,
        Duration::from_millis(500),
    ));
    tokio::spawn(sync::run_sync_loop(
        dir_b.clone(),
        rx_b,
        Duration::from_millis(500),
    ));

    // --- wait for convergence: every file present on both sides, identical ---
    let want: &[(&str, &str)] = &[
        ("alpha.txt", "hello from A"),
        ("sub/nested.txt", "nested A payload"),
        ("beta.txt", "hello from B"),
    ];
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let mut converged = true;
        for (rel, content) in want {
            for dir in [&dir_a, &dir_b] {
                if read_to_string(&dir.join(rel)).await.as_deref() != Some(*content) {
                    converged = false;
                }
            }
        }
        if converged {
            break;
        }
        if Instant::now() > deadline {
            panic!(
                "folders did not converge in time\n A={:?}\n B={:?}",
                list(&dir_a),
                list(&dir_b)
            );
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    // Explicit assertions for a clear failure message if something regresses.
    for (rel, content) in want {
        assert_eq!(
            std::fs::read_to_string(dir_a.join(rel)).unwrap(),
            *content,
            "A missing/!= {rel}"
        );
        assert_eq!(
            std::fs::read_to_string(dir_b.join(rel)).unwrap(),
            *content,
            "B missing/!= {rel}"
        );
    }

    drop(mock_a);
    drop(mock_b);
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

fn list(dir: &Path) -> Vec<String> {
    sync::manifest::scan(dir)
        .into_iter()
        .map(|e| e.path)
        .collect()
}

/// A bad token must be rejected at `Hello` (the grant gate, docs/EXTENSIONS.md §3).
#[tokio::test]
async fn bad_token_is_rejected() {
    let mock = mock::start(MockConfig::with_minisync_grant("right"))
        .await
        .unwrap();
    let (tx, _rx) = watch::channel::<Vec<SocketAddr>>(Vec::new());
    let cfg = config_for(tmp_dir("bt"), 1, "wrong", mock.path.to_str().unwrap());
    let stream = meshd::connect(mock.path.to_str().unwrap()).await.unwrap();
    let res = meshd::run_session(&cfg, stream, &tx).await;
    assert!(
        res.is_err(),
        "expected Hello to be rejected for a bad token"
    );
}
