//! `gnet metrics` — Prometheus text exporter for the daemon's admin snapshot.
//!
//! Reads the admin unix-socket snapshot (the same surface as `gnet status`),
//! pulls the counters from its `metrics` line and a few peer-state gauges from
//! the `peer` rows, and prints `0.0.4`-format Prometheus exposition to stdout.
//!
//! The daemon itself does not speak HTTP — keeping `gnet` zero-deps. This
//! exporter is meant to be wired into node_exporter's textfile collector
//! (cron `gnet metrics > /var/lib/node_exporter/gnet.prom`) or scraped via a
//! tiny systemd-socket-activated wrapper. Splitting the HTTP surface out of
//! the daemon keeps the wire-side binary unchanged when an operator wants
//! richer scrape topology.

use std::io::{self, Read};
use std::time::Duration;

#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::os::unix::net::UnixStream;

pub fn run(_args: &[String]) -> io::Result<()> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let snap = fetch_admin_snapshot()?;
        print!("{}", render(&snap));
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(io::Error::other(
            "metrics requires macOS or Linux (admin unix socket)",
        ))
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn fetch_admin_snapshot() -> io::Result<String> {
    let path = gnet::node::admin_socket_path();
    let mut sock = UnixStream::connect(&path)?;
    sock.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut buf = String::new();
    sock.read_to_string(&mut buf)?;
    Ok(buf)
}

/// Translate one admin snapshot into Prometheus text. Public for tests.
pub(crate) fn render(snap: &str) -> String {
    let mut out = String::with_capacity(512);
    let mut metrics_line = None;
    let mut peer_lines = Vec::new();
    let mut relay_lines = Vec::new();
    for line in snap.lines() {
        if let Some(rest) = line.strip_prefix("metrics ") {
            metrics_line = Some(rest);
        } else if let Some(rest) = line.strip_prefix("peer ") {
            peer_lines.push(rest);
        } else if let Some(rest) = line.strip_prefix("relay ") {
            relay_lines.push(rest);
        }
    }

    let counter = |k: &str| -> &'static str {
        match k {
            "handshake_success" => "Noise_IK handshakes that reached Established (either side)",
            "handshake_fail" => {
                "Handshakes torn down by the expire path (msg1/msg2 lost, peer down)"
            }
            "relay_register_sent" => "Self-addressed RelayData registration datagrams sent",
            "peer_relay_fallback" => {
                "Peers tripped from direct/punch to relay after PUNCH_ATTEMPTS failures"
            }
            _ => "",
        }
    };
    if let Some(line) = metrics_line {
        for tok in line.split(' ') {
            let Some((k, v)) = tok.split_once('=') else {
                continue;
            };
            let help = counter(k);
            if help.is_empty() {
                continue;
            }
            let name = format!("gnet_{k}_total");
            out.push_str(&format!("# HELP {name} {help}\n"));
            out.push_str(&format!("# TYPE {name} counter\n"));
            out.push_str(&format!("{name} {v}\n"));
        }
    }

    // peer-state gauge: 1 per peer in each session phase. Lets a fleet
    // dashboard alert on "no peer has been established in X minutes" without
    // scraping the live block.
    let mut idle = 0u64;
    let mut initiating = 0u64;
    let mut established = 0u64;
    let mut via_relay = 0u64;
    let mut total = 0u64;
    for p in &peer_lines {
        total += 1;
        match kv(p, "session") {
            Some("idle") => idle += 1,
            Some("initiating") => initiating += 1,
            Some("established") => established += 1,
            _ => {}
        }
        if kv(p, "relay") == Some("true") {
            via_relay += 1;
        }
    }
    push_gauge(
        &mut out,
        "gnet_peers_total",
        "Peers currently known to the daemon (static + coordinator)",
        total,
    );
    push_gauge(
        &mut out,
        "gnet_peer_session_idle",
        "Peers whose session is currently Idle (no handshake in flight)",
        idle,
    );
    push_gauge(
        &mut out,
        "gnet_peer_session_initiating",
        "Peers whose session is mid-handshake (Initiating)",
        initiating,
    );
    push_gauge(
        &mut out,
        "gnet_peer_session_established",
        "Peers with a live Established transport",
        established,
    );
    push_gauge(
        &mut out,
        "gnet_peer_via_relay",
        "Peers currently routed through a relay (relay-fallback active)",
        via_relay,
    );

    // relay health: a gauge per relay, value = ms since last pong (or 0 when
    // we have never seen one yet; absence of a relay row means it is not
    // advertised). Operators alert on stale relay health from this.
    if !relay_lines.is_empty() {
        out.push_str("# HELP gnet_relay_health_age_ms Milliseconds since the last self-addressed keepalive echo from each relay (0 = no pong yet)\n");
        out.push_str("# TYPE gnet_relay_health_age_ms gauge\n");
        for r in &relay_lines {
            let ep = kv(r, "endpoint").unwrap_or("?");
            let age = kv(r, "health_age_ms").unwrap_or("0");
            let age_num = if age == "never" { "0" } else { age };
            out.push_str(&format!(
                "gnet_relay_health_age_ms{{endpoint=\"{ep}\"}} {age_num}\n"
            ));
        }
    }

    out
}

fn push_gauge(out: &mut String, name: &str, help: &str, value: u64) {
    out.push_str(&format!("# HELP {name} {help}\n"));
    out.push_str(&format!("# TYPE {name} gauge\n"));
    out.push_str(&format!("{name} {value}\n"));
}

fn kv<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    for tok in line.split(' ') {
        if let Some((k, v)) = tok.split_once('=')
            && k == key
        {
            return Some(v);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
metrics handshake_success=12 handshake_fail=3 relay_register_sent=99 peer_relay_fallback=1
node public=abcd reflexive=1.2.3.4:5 self_is_nat=true
relay endpoint=10.0.0.1:7 health_age_ms=42
peer alias=alpha public=11 vip=10.88.0.7 vip6=none endpoint=1.2.3.4:9 session=established last_established_age_s=10 relay=false relay_endpoint=none punched=false punch_failures=0 pinned=true
peer alias=beta public=22 vip=10.88.0.8 vip6=none endpoint=none session=idle last_established_age_s=never relay=true relay_endpoint=10.0.0.1:7 punched=false punch_failures=3 pinned=false
";

    #[test]
    fn renders_counters_with_help_and_type() {
        let out = render(SAMPLE);
        assert!(out.contains("# TYPE gnet_handshake_success_total counter"));
        assert!(out.contains("\ngnet_handshake_success_total 12\n"));
        assert!(out.contains("\ngnet_handshake_fail_total 3\n"));
        assert!(out.contains("\ngnet_peer_relay_fallback_total 1\n"));
    }

    #[test]
    fn renders_per_session_gauges() {
        let out = render(SAMPLE);
        assert!(out.contains("\ngnet_peers_total 2\n"));
        assert!(out.contains("\ngnet_peer_session_established 1\n"));
        assert!(out.contains("\ngnet_peer_session_idle 1\n"));
        assert!(out.contains("\ngnet_peer_via_relay 1\n"));
    }

    #[test]
    fn renders_relay_health_with_endpoint_label() {
        let out = render(SAMPLE);
        assert!(out.contains("gnet_relay_health_age_ms{endpoint=\"10.0.0.1:7\"} 42\n"));
    }

    #[test]
    fn empty_snapshot_renders_zeroed_gauges() {
        let out = render("");
        assert!(out.contains("\ngnet_peers_total 0\n"));
        assert!(!out.contains("gnet_handshake_success_total")); // no metrics line → no counters
    }
}
