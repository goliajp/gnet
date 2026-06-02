//! Admin IPC — a unix-socket query surface exposing the daemon's live
//! per-peer session state, current reflexive endpoint, and relay health, so
//! `gnet status` and ad-hoc operators do not have to dig through `journalctl`
//! to answer "is this peer up?" or "are we relaying or direct?".
//!
//! Wire format is line-oriented `event=`-style key=value tokens (one record
//! per line, values are space-free), matching the daemon's existing event-log
//! convention. No serde, no JSON — the daemon is a zero-deps binary by design
//! and the read end is plain-text parsing.
//!
//! Protocol: the client connects, the daemon writes a complete snapshot and
//! closes. No request body, no streaming. One connection at a time is handled
//! inline on the listener thread — a status call is cheap and concurrent
//! operators would only thrash the mutex.
//!
//! Bind failure (path unwritable, parent dir missing) is logged to the event
//! stream and the daemon continues without an admin surface — the wire path
//! must never be blocked on observability.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use super::types::{Node, Session};
use gnet_hex as hex;

/// Default admin-socket path. Mirrors `status::default_conf_path`'s platform
/// split so the daemon and `gnet status` agree on where to bind/connect
/// without a conf round-trip.
pub fn default_socket_path() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/var/run/gnet/admin.sock")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/usr/local/var/run/gnet/admin.sock")
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        PathBuf::from("/tmp/gnet-admin.sock")
    }
}

pub(crate) fn spawn(node: Arc<Mutex<Node>>, path: PathBuf) {
    thread::spawn(move || {
        if let Err(e) = serve(&node, &path) {
            eprintln!(
                "event=admin_socket_unavailable path={} err={}",
                path.display(),
                e
            );
        }
    });
}

fn serve(node: &Arc<Mutex<Node>>, path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    // a previous run's socket file is left on disk after crash/SIGKILL;
    // unlink before bind so the listener comes up cleanly.
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    // 0600: snapshot includes peer pubkeys + endpoints. gnet runs as root for
    // TUN; keep this owner-only.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    eprintln!("event=admin_socket_up path={}", path.display());
    for conn in listener.incoming() {
        match conn {
            Ok(mut stream) => {
                let body = render_snapshot(node);
                let _ = stream.write_all(body.as_bytes());
                let _ = stream.flush();
            }
            Err(e) => eprintln!("event=admin_accept_err err={e}"),
        }
    }
    Ok(())
}

fn render_snapshot(node: &Arc<Mutex<Node>>) -> String {
    let now = Instant::now();
    let g = node.lock().expect("node mutex");
    let mut out = String::with_capacity(256);

    out.push_str("metrics");
    push_kv(
        &mut out,
        "handshake_success",
        &g.metrics.handshake_success.to_string(),
    );
    push_kv(
        &mut out,
        "handshake_fail",
        &g.metrics.handshake_fail.to_string(),
    );
    push_kv(
        &mut out,
        "relay_register_sent",
        &g.metrics.relay_register_sent.to_string(),
    );
    push_kv(
        &mut out,
        "peer_relay_fallback",
        &g.metrics.peer_relay_fallback.to_string(),
    );
    out.push('\n');

    out.push_str("node");
    push_kv(&mut out, "public", &hex::encode(&g.public));
    push_kv(
        &mut out,
        "reflexive",
        &g.reflexive
            .map_or_else(|| "none".to_string(), |a| a.to_string()),
    );
    push_kv(
        &mut out,
        "self_is_nat",
        match g.self_is_nat {
            Some(true) => "true",
            Some(false) => "false",
            None => "unknown",
        },
    );
    out.push('\n');

    for ep in &g.relay_servers {
        out.push_str("relay");
        push_kv(&mut out, "endpoint", &ep.to_string());
        let age = g
            .relay_health
            .get(ep)
            .map(|t| now.saturating_duration_since(*t).as_millis().to_string())
            .unwrap_or_else(|| "never".to_string());
        push_kv(&mut out, "health_age_ms", &age);
        out.push('\n');
    }

    for p in &g.peers {
        out.push_str("peer");
        push_kv(
            &mut out,
            "alias",
            if p.alias.is_empty() { "-" } else { &p.alias },
        );
        push_kv(&mut out, "public", &hex::encode(&p.public));
        push_kv(&mut out, "vip", &p.vip.to_string());
        push_kv(
            &mut out,
            "vip6",
            &p.vip6.map_or_else(|| "none".to_string(), |v| v.to_string()),
        );
        push_kv(
            &mut out,
            "endpoint",
            &p.endpoint
                .map_or_else(|| "none".to_string(), |e| e.to_string()),
        );
        push_kv(
            &mut out,
            "session",
            match p.session {
                Session::Idle => "idle",
                Session::Initiating { .. } => "initiating",
                Session::Established(_) => "established",
            },
        );
        push_kv(
            &mut out,
            "last_established_age_s",
            &p.last_established_at
                .map(|t| now.saturating_duration_since(t).as_secs().to_string())
                .unwrap_or_else(|| "never".to_string()),
        );
        push_kv(&mut out, "relay", if p.relay { "true" } else { "false" });
        push_kv(
            &mut out,
            "relay_endpoint",
            &p.relay_endpoint
                .map_or_else(|| "none".to_string(), |e| e.to_string()),
        );
        push_kv(
            &mut out,
            "punched",
            if p.punched { "true" } else { "false" },
        );
        push_kv(&mut out, "punch_failures", &p.punch_failures.to_string());
        push_kv(&mut out, "pinned", if p.pinned { "true" } else { "false" });
        out.push('\n');
    }
    out
}

fn push_kv(out: &mut String, key: &str, value: &str) {
    out.push(' ');
    out.push_str(key);
    out.push('=');
    out.push_str(value);
}

#[cfg(test)]
mod tests {
    use super::super::punch::DIRECT_UPGRADE_BASE;
    use super::super::types::{Peer, Session, established_pair};
    use super::*;
    use gnet_crypto::mlkem;
    use gnet_punch::PunchState;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn node_with(peers: Vec<Peer>) -> Node {
        Node {
            private: [0u8; 32],
            public: [0xab; 32],
            mlkem_ek: vec![],
            mlkem_dk: vec![],
            peers,
            relay_servers: vec![],
            relay_health: HashMap::new(),
            reflexive: None,
            probe_txid: 0,
            self_is_nat: None,
            nat_override: false,
            metrics: Default::default(),
        }
    }

    fn peer(session: Session, established: bool) -> Peer {
        Peer {
            alias: "alpha".to_string(),
            pinned: false,
            public: [0x11; 32],
            mlkem_ek: vec![0u8; mlkem::EK_LEN]
                .into_boxed_slice()
                .try_into()
                .unwrap(),
            vip: IpAddr::V4(Ipv4Addr::new(10, 88, 0, 7)),
            vip6: None,
            endpoint: Some(SocketAddr::from(([1, 2, 3, 4], 9999))),
            rx_index: 0,
            tx_index: 0,
            session,
            punch: PunchState::Idle,
            punched: false,
            punch_failures: 0,
            relay: false,
            relay_endpoint: None,
            relay_eligible: false,
            direct_upgrade_at: Instant::now() + DIRECT_UPGRADE_BASE,
            direct_upgrade_failures: 0,
            last_established_at: established.then(Instant::now),
        }
    }

    #[test]
    fn snapshot_idle_node_has_metrics_and_node_lines_only() {
        let node = Arc::new(Mutex::new(node_with(vec![])));
        let snap = render_snapshot(&node);
        let lines: Vec<&str> = snap.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("metrics "));
        assert!(lines[0].contains("handshake_success=0"));
        assert!(lines[1].starts_with("node "));
        assert!(lines[1].contains("reflexive=none"));
    }

    #[test]
    fn snapshot_includes_session_and_age_for_established_peer() {
        let (a, _b) = established_pair();
        let node = Arc::new(Mutex::new(node_with(vec![peer(
            Session::Established(a),
            true,
        )])));
        let snap = render_snapshot(&node);
        assert!(snap.contains("session=established"), "{snap}");
        assert!(snap.contains("last_established_age_s="), "{snap}");
        assert!(!snap.contains("last_established_age_s=never"), "{snap}");
        assert!(snap.contains("alias=alpha"), "{snap}");
    }

    #[test]
    fn snapshot_marks_idle_peer_with_never_age() {
        let node = Arc::new(Mutex::new(node_with(vec![peer(Session::Idle, false)])));
        let snap = render_snapshot(&node);
        assert!(snap.contains("session=idle"), "{snap}");
        assert!(snap.contains("last_established_age_s=never"), "{snap}");
    }
}
