//! Standalone gnet relay daemon.
//!
//! Receives `RelayData(0x08) ‖ src_pubkey(32) ‖ dst_pubkey(32) ‖ inner` UDP
//! datagrams, looks up the last-known endpoint for `dst_pubkey`, and forwards
//! the datagram unchanged. The inner bytes stay end-to-end encrypted — the
//! relay is not a handshake party and never sees plaintext.
//!
//! Peer endpoint registry is built from observed `src_pubkey` ↔ recv-from
//! pairs (trust-on-first-use, refreshed on every received envelope). No
//! coordinator state, no out-of-band registration — symmetric NAT peers
//! that have spoken to the relay at least once become routable.
//!
//! Stale entries (no activity for [`STALE_AFTER_DEFAULT`], or the override
//! from `--stale-after`) are pruned in-line on each `recv_from` wake-up so
//! the table size stays bounded by active peers and doesn't need a
//! background thread.
//!
//! # Wire contract
//!
//! - Only `Kind::RelayData` is honoured. Other datagrams are dropped — this
//!   binary is *only* a relay, not a daemon.
//! - The forwarded datagram is the **whole incoming datagram**, byte-for-byte.
//!   The relay rewrites nothing in the header or body; the receiver's gnet
//!   daemon handles inner re-dispatch (see `gnet::node::pump::handle_datagram`).
//!
//! # Operational profile
//!
//! - One UDP socket. One `recv_from` loop, single-threaded.
//! - Allocation-free hot path: a single fixed MTU buffer is reused across
//!   datagrams; the peer-endpoint `HashMap` allocates only on registration.
//! - Process traffic accounting via systemd's `IPAccounting=yes` so AWS data
//!   egress can be capped externally; the binary itself logs only one line
//!   per minute summarising relay throughput + active peer count.
//!
//! Usage:
//!
//! ```text
//! gnet-relay-server [--listen 0.0.0.0:65433] [--idle-secs 300]
//! ```

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::env;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use gnet_relay::KEY_LEN;
use gnet_wire::Kind;

/// MTU-sized recv buffer reused on every iteration. 1500 covers a typical
/// public-internet path MTU; gnet datagrams stay below 1400 by design.
const MTU: usize = 1500;

/// Drop a peer's registered endpoint if we haven't seen it in this long.
/// Five minutes is well past `gnet`'s keepalive cadence (~30 s), so a live
/// peer is always present; a dead peer's slot is recycled quickly.
const STALE_AFTER_DEFAULT: Duration = Duration::from_secs(300);

/// How often to print a one-line summary of relay throughput + peer count.
const LOG_INTERVAL: Duration = Duration::from_secs(60);

fn main() -> ExitCode {
    let cfg = match Config::from_argv(env::args().skip(1).collect()) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("gnet-relay-server: {msg}");
            eprintln!("usage: gnet-relay-server [--listen ADDR] [--idle-secs N]");
            return ExitCode::from(2);
        }
    };

    match run(cfg) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("gnet-relay-server: fatal: {e}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug)]
struct Config {
    listen: SocketAddr,
    stale_after: Duration,
}

impl Config {
    fn from_argv(args: Vec<String>) -> Result<Self, String> {
        let mut listen: SocketAddr = "0.0.0.0:65433".parse().expect("hardcoded default is valid");
        let mut stale_after = STALE_AFTER_DEFAULT;

        let mut it = args.into_iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--listen" => {
                    let v = it.next().ok_or("--listen needs an ADDR")?;
                    listen = v.parse().map_err(|e| format!("--listen {v:?}: {e}"))?;
                }
                "--idle-secs" => {
                    let v = it.next().ok_or("--idle-secs needs N")?;
                    let n: u64 = v.parse().map_err(|e| format!("--idle-secs {v:?}: {e}"))?;
                    stale_after = Duration::from_secs(n);
                }
                "-h" | "--help" => {
                    return Err("help".into());
                }
                other => return Err(format!("unknown arg {other:?}")),
            }
        }

        Ok(Self {
            listen,
            stale_after,
        })
    }
}

/// Per-peer registry entry: where we last saw them and when.
struct PeerEntry {
    endpoint: SocketAddr,
    last_seen: Instant,
}

/// Periodically-logged counters, reset on each emission.
#[derive(Default)]
struct Stats {
    forwarded: u64,
    bytes_in: u64,
    bytes_out: u64,
    unknown_dst: u64,
    non_relay: u64,
    self_addressed: u64,
}

fn run(cfg: Config) -> io::Result<()> {
    let sock = UdpSocket::bind(cfg.listen)?;
    eprintln!(
        "gnet-relay-server: listening on {} (idle prune after {}s)",
        cfg.listen,
        cfg.stale_after.as_secs()
    );

    let mut buf = [0u8; MTU];
    let mut peers: HashMap<[u8; KEY_LEN], PeerEntry> = HashMap::new();
    let mut stats = Stats::default();
    let mut last_log = Instant::now();
    let mut last_prune = Instant::now();
    let prune_interval = cfg.stale_after / 4;

    loop {
        // Periodic log + prune are inlined on the recv path: no background
        // thread, no mutex around the registry. Cadence is tied to recv
        // activity, which on a real relay is many packets/sec — fine.
        let now = Instant::now();
        if now.duration_since(last_log) >= LOG_INTERVAL {
            eprintln!(
                "gnet-relay-server: peers={} forwarded={} in={}B out={}B unknown_dst={} non_relay={} self_addr={}",
                peers.len(),
                stats.forwarded,
                stats.bytes_in,
                stats.bytes_out,
                stats.unknown_dst,
                stats.non_relay,
                stats.self_addressed,
            );
            stats = Stats::default();
            last_log = now;
        }
        if now.duration_since(last_prune) >= prune_interval {
            peers.retain(|_, e| now.duration_since(e.last_seen) < cfg.stale_after);
            last_prune = now;
        }

        let (n, from) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        stats.bytes_in = stats.bytes_in.saturating_add(n as u64);

        let Some((kind, body)) = gnet_wire::parse(&buf[..n]) else {
            stats.non_relay += 1;
            continue;
        };
        if kind != Kind::RelayData {
            stats.non_relay += 1;
            continue;
        }
        let Some((src, dst, _inner)) = gnet_relay::decode(body) else {
            stats.non_relay += 1;
            continue;
        };

        match register_and_route(&mut peers, src, dst, from, now) {
            Route::Echo(ep) => {
                stats.self_addressed += 1;
                // Echo the self-addressed keepalive back unchanged so the
                // sender can measure this relay's liveness + RTT and route
                // around a dead relay. The node identifies it by src==dst==self.
                match sock.send_to(&buf[..n], ep) {
                    Ok(sent) => stats.bytes_out = stats.bytes_out.saturating_add(sent as u64),
                    Err(e) => eprintln!("gnet-relay-server: echo to {ep} failed: {e}"),
                }
            }
            Route::UnknownDst => stats.unknown_dst += 1,
            Route::Forward(endpoint) => {
                // Forward the whole datagram unchanged. We don't rewrite
                // anything: the receiver's gnet daemon parses `RelayData ‖
                // src ‖ dst ‖ inner` exactly as it would from any path.
                match sock.send_to(&buf[..n], endpoint) {
                    Ok(sent) => {
                        stats.forwarded += 1;
                        stats.bytes_out = stats.bytes_out.saturating_add(sent as u64);
                    }
                    Err(e) => {
                        eprintln!("gnet-relay-server: send to {endpoint} failed: {e}");
                    }
                }
            }
        }
    }
}

/// Outcome of a single RelayData datagram after registration.
#[derive(Debug, PartialEq, Eq)]
enum Route {
    /// `dst` resolves to the same endpoint the datagram arrived from — a
    /// self-addressed envelope (`src == dst`, the idle-node registration
    /// keepalive). Registered, then echoed straight back to the sender: the
    /// echo is the health pong that lets the node probe this relay's liveness
    /// and RTT and route around a dead relay (see node-side relay selection).
    /// Carries the endpoint to echo to (the datagram's source).
    Echo(SocketAddr),
    /// `dst` is not in the registry yet — nothing to forward to.
    UnknownDst,
    /// Forward the datagram unchanged to this endpoint.
    Forward(SocketAddr),
}

/// Trust-on-first-use registration, then routing decision for one RelayData
/// datagram. `src@from` is recorded (refreshed on every packet so a NAT
/// mapping change rolls forward immediately); we never verify *who* `src`
/// claims to be, but since the relay never decrypts the inner payload a
/// spoofed `src` only redirects future replies to the spoofer, and that
/// peer's own next outbound refreshes the entry back.
///
/// A datagram whose `dst` resolves to the sender's own endpoint is
/// self-addressed (`gnet` nodes send `src == dst` to register without
/// forwarding — the relay-registration keepalive) and is dropped, not
/// looped back.
fn register_and_route(
    peers: &mut HashMap<[u8; KEY_LEN], PeerEntry>,
    src: &[u8; KEY_LEN],
    dst: &[u8; KEY_LEN],
    from: SocketAddr,
    now: Instant,
) -> Route {
    peers.insert(
        *src,
        PeerEntry {
            endpoint: from,
            last_seen: now,
        },
    );
    match peers.get(dst) {
        Some(entry) if entry.endpoint == from => Route::Echo(from),
        Some(entry) => Route::Forward(entry.endpoint),
        None => Route::UnknownDst,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> [u8; KEY_LEN] {
        [b; KEY_LEN]
    }

    #[test]
    fn self_addressed_registers_and_echoes() {
        // The idle-node registration keepalive: a node sends RelayData with
        // src == dst. The relay records its endpoint (so peers can later relay
        // to it) and echoes the datagram back to the sender — the health pong
        // the node uses to probe this relay's liveness + RTT.
        let mut peers = HashMap::new();
        let a = key(0xAA);
        let from: SocketAddr = "203.0.113.5:40000".parse().unwrap();

        let route = register_and_route(&mut peers, &a, &a, from, Instant::now());
        assert_eq!(
            route,
            Route::Echo(from),
            "src==dst echoes back to the sender"
        );
        assert_eq!(
            peers.get(&a).map(|e| e.endpoint),
            Some(from),
            "and the node is now registered and reachable"
        );
    }

    #[test]
    fn registered_dst_forwards_after_keepalive() {
        // After A has registered (via its keepalive), a datagram B→A forwards
        // to A's recorded endpoint — the reachability the keepalive buys.
        let mut peers = HashMap::new();
        let (a, b) = (key(0xAA), key(0xBB));
        let a_ep: SocketAddr = "203.0.113.5:40000".parse().unwrap();
        let b_ep: SocketAddr = "198.51.100.7:50000".parse().unwrap();

        // A's self-addressed keepalive registers it.
        register_and_route(&mut peers, &a, &a, a_ep, Instant::now());
        // B now relays to A.
        let route = register_and_route(&mut peers, &b, &a, b_ep, Instant::now());
        assert_eq!(route, Route::Forward(a_ep));
    }

    #[test]
    fn unknown_dst_is_dropped() {
        let mut peers = HashMap::new();
        let (a, b) = (key(0xAA), key(0xBB));
        let from: SocketAddr = "203.0.113.5:40000".parse().unwrap();
        // A→B but B never registered → nothing to forward to.
        let route = register_and_route(&mut peers, &a, &b, from, Instant::now());
        assert_eq!(route, Route::UnknownDst);
    }

    /// CLI parsing: defaults, custom listen, idle-secs, errors.
    #[test]
    fn cli_default() {
        let c = Config::from_argv(vec![]).unwrap();
        assert_eq!(c.listen.port(), 65433);
        assert_eq!(c.stale_after, Duration::from_secs(300));
    }

    #[test]
    fn cli_custom_listen() {
        let c = Config::from_argv(vec!["--listen".into(), "1.2.3.4:9999".into()]).unwrap();
        assert_eq!(c.listen.to_string(), "1.2.3.4:9999");
    }

    #[test]
    fn cli_custom_idle() {
        let c = Config::from_argv(vec!["--idle-secs".into(), "30".into()]).unwrap();
        assert_eq!(c.stale_after, Duration::from_secs(30));
    }

    #[test]
    fn cli_rejects_unknown_arg() {
        assert!(Config::from_argv(vec!["--no-such".into()]).is_err());
    }
}
