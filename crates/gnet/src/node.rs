//! Static multi-peer gnet node: one TUN + one UDP socket serving many peers.
//!
//! Outbound IP packets are routed by destination address to the matching
//! peer's session (initiating a Noise_IK handshake on demand); inbound
//! datagrams are demultiplexed by the [`wire`] type tag — handshakes are
//! matched to a configured peer by static key (init) or source endpoint
//! (response), transport datagrams to a peer by the receiver index each side
//! assigned during the handshake and decrypted with that peer's session.
//! Indexing transport by session (not by address) is what lets a peer's
//! endpoint roam. State is shared between the two pump threads behind a
//! `Mutex`; the lock is held only for in-memory routing/crypto, never across
//! an I/O syscall.
//!
//! Submodules: [`types`] (session state + `Node` helpers), [`pump`] (the
//! TUN↔UDP threads), [`handshake`] (inbound handshake handling).
//!
//! [`wire`]: gnet_wire

mod discovery;
mod handshake;
mod local_ips;
mod pump;
mod punch;
mod types;

use std::io;
use std::net::{IpAddr, UdpSocket};
use std::process::Command;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use gnet_tun::Tun;

use crate::keys;
use gnet_config::Config;
use gnet_punch::PunchState;
use types::{Node, Peer, Session};

/// AEAD tag length appended to every transport frame (Poly1305).
const TAG_LEN: usize = gnet_crypto::aead::TAG_LEN;

/// How long a whole handshake attempt may run (measured from its first msg1)
/// before it is abandoned back to `Idle`, so the next outbound packet starts a
/// fresh attempt rather than retransmitting an unreachable peer forever.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// How often the maintenance thread runs (expire + retransmit + probe +
/// keepalive). The retransmit interval itself is jittered per-peer inside
/// [`Node::retransmit_initiations`], not driven by this tick.
const MAINT_TICK: Duration = Duration::from_secs(1);

/// How long the punch-dial poller blocks when no dial is scheduled. It is woken
/// early by downlink whenever a connect-reply installs a `Syncing` state, and
/// otherwise sleeps exactly until the next scheduled dial, so there is no
/// steady-state lock traffic. This only bounds the worst case if a wake is ever
/// missed (every loop re-polls, so a missed wake just delays, never drops).
const DIAL_IDLE_WAIT: Duration = Duration::from_secs(3600);

/// How often to probe a peer to discover our reflexive (public) endpoint.
const PROBE_INTERVAL: Duration = Duration::from_secs(5);

/// Overlay subnet prefix length for an address family: a /24 (IPv4) or /64
/// (IPv6) subnet routes the whole overlay range into the TUN.
fn overlay_prefix(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 24,
        IpAddr::V6(_) => 64,
    }
}

/// Run a config command, mapping a non-zero exit to an error.
fn run_cmd(cmd: &mut Command) -> io::Result<()> {
    if cmd.status()?.success() {
        Ok(())
    } else {
        Err(io::Error::other("interface configuration command failed"))
    }
}

/// Bring the TUN up with our overlay address so the whole overlay subnet
/// (a /24 for IPv4, /64 for IPv6) routes into it. `ip addr add` infers the
/// address family from the literal.
#[cfg(target_os = "linux")]
fn configure(name: &str, address: IpAddr) -> io::Result<()> {
    let cidr = format!("{address}/{}", overlay_prefix(address));
    run_cmd(Command::new("ip").args(["addr", "add", &cidr, "dev", name]))?;
    run_cmd(Command::new("ip").args(["link", "set", name, "up"]))
}

/// Bring the TUN up and route the overlay subnet into it. IPv4 uses the
/// point-to-point `ifconfig` form; IPv6 needs the `inet6 … prefixlen` form.
#[cfg(target_os = "macos")]
fn configure(name: &str, address: IpAddr) -> io::Result<()> {
    let prefix = overlay_prefix(address);
    let net = format!("{address}/{prefix}");
    match address {
        IpAddr::V4(_) => {
            let a = address.to_string();
            run_cmd(Command::new("ifconfig").args([name, &a, &a, "up"]))?;
            run_cmd(Command::new("route").args(["-q", "add", "-net", &net, "-interface", name]))
        }
        IpAddr::V6(_) => {
            run_cmd(Command::new("ifconfig").args([
                name,
                "inet6",
                &address.to_string(),
                "prefixlen",
                &prefix.to_string(),
                "up",
            ]))?;
            run_cmd(Command::new("route").args([
                "-q",
                "add",
                "-inet6",
                "-net",
                &net,
                "-interface",
                name,
            ]))
        }
    }
}

/// Run a static multi-peer node until a fatal socket/device error.
pub fn run(config: Config) -> io::Result<()> {
    let socket = Arc::new(UdpSocket::bind(config.listen)?);
    let tun = Arc::new(Tun::open()?);
    configure(tun.name(), config.address)?;
    // Dual-stack: when an IPv6 overlay address is configured, attach it to the
    // same TUN so the kernel routes the v6 overlay subnet (/64) here too.
    if let Some(v6) = config.address6 {
        configure(tun.name(), v6)?;
    }
    eprintln!(
        "node up on {} ({}{}) with {} peer(s)",
        tun.name(),
        config.address,
        config
            .address6
            .map(|v| format!(" + {v}"))
            .unwrap_or_default(),
        config.peers.len()
    );

    let keepalive = config.keepalive;
    let coordinator = config.coordinator.clone();
    let device_token = config.device_token.clone();
    let peers = config
        .peers
        .into_iter()
        .map(|p| Peer {
            // static conf has no alias on peer lines — discovery fills it in
            // on the first coordinator poll. Empty string is a sentinel that
            // means "not yet known", distinct from "explicit empty alias".
            alias: String::new(),
            public: p.public,
            mlkem_ek: p.mlkem_ek,
            vip: p.vip,
            vip6: p.vip6,
            endpoint: p.endpoint,
            rx_index: 0,
            tx_index: 0,
            session: Session::Idle,
            punch: PunchState::Idle,
            punched: false,
            punch_failures: 0,
            relay: false,
            relay_endpoint: None,
            // static conf has no relay_eligible directive yet — coordinator
            // is the source of truth and pushes the flag via /peers polling.
            relay_eligible: false,
        })
        .collect();
    // our own ML-KEM key pair is derived from our X25519 private key.
    let (mlkem_ek, mlkem_dk) = keys::derive_mlkem(&config.private);
    let node = Arc::new(Mutex::new(Node {
        private: config.private,
        public: keys::public_key(&config.private),
        mlkem_ek,
        mlkem_dk,
        peers,
        reflexive: None,
        probe_txid: 0,
        self_is_nat: None,
    }));

    // condvar the punch-dial poller blocks on; downlink notifies it when a
    // connect-reply installs a Syncing state, so a scheduled dial fires on time
    // without a steady-state busy poll.
    let dial_wake = Arc::new(Condvar::new());

    // maintenance: abandon stale handshakes so a lost init/response can't
    // wedge a peer, and (if configured) send persistent keepalives to hold NAT
    // mappings open. Runs as a daemon for the process lifetime.
    {
        let node = node.clone();
        let socket = socket.clone();
        thread::spawn(move || {
            let mut last_keepalive = Instant::now();
            // probe on the first tick (discover our reflexive endpoint early)
            let mut last_probe = Instant::now()
                .checked_sub(PROBE_INTERVAL)
                .unwrap_or_else(Instant::now);
            loop {
                thread::sleep(MAINT_TICK);
                // crypto/state under the lock; send syscalls run unlocked.
                let mut probe = None;
                let sends = {
                    let mut g = node.lock().expect("node mutex");
                    // give up handshakes whose whole attempt has timed out, then
                    // retransmit msg1 for any still-in-flight initiation that has
                    // gone quiet — this drives simultaneous-open hole punching to
                    // completion without depending on more app traffic.
                    g.expire_handshakes(HANDSHAKE_TIMEOUT);
                    let mut sends = g.retransmit_initiations();
                    if last_probe.elapsed() >= PROBE_INTERVAL {
                        last_probe = Instant::now();
                        probe = g.make_probe();
                    }
                    if keepalive.is_some_and(|interval| last_keepalive.elapsed() >= interval) {
                        last_keepalive = Instant::now();
                        sends.extend(g.keepalive_datagrams());
                    }
                    sends
                };
                for (ep, dg) in sends {
                    let _ = socket.send_to(&dg, ep);
                }
                if let Some((ep, dg)) = probe {
                    let _ = socket.send_to(&dg, ep);
                }
            }
        });
    }

    // punch-dial poller: the origin's RTT/2-scheduled dial needs finer timing
    // than the 1s maintenance tick (a ~1s skew past the target's immediate dial
    // collides in conntrack). Rather than busy-poll, block on `dial_wake` until
    // the next scheduled dial deadline (or until downlink notifies a new one),
    // so there is no lock traffic when no punch is in flight.
    {
        let node = node.clone();
        let socket = socket.clone();
        let dial_wake = dial_wake.clone();
        thread::spawn(move || {
            let mut g = node.lock().expect("node mutex");
            loop {
                let sends = g.poll_punch_dials();
                let next = g.next_punch_dial();
                drop(g);
                for (ep, dg) in sends {
                    let _ = socket.send_to(&dg, ep);
                }
                let wait = next
                    .map(|t| t.saturating_duration_since(Instant::now()))
                    .unwrap_or(DIAL_IDLE_WAIT);
                let lock = node.lock().expect("node mutex");
                g = dial_wake.wait_timeout(lock, wait).expect("dial wake").0;
            }
        });
    }

    // start the discovery thread if a coordinator URL is configured —
    // it polls /peers and hot-adds newly-joined peers to `Node.peers`.
    if let Some(url) = coordinator.clone() {
        discovery::spawn(node.clone(), url, device_token.clone());
    }

    let up = pump::uplink(tun.clone(), socket.clone(), node.clone());
    let down = pump::downlink(tun, socket, node, dial_wake);
    up.join()
        .map_err(|_| io::Error::other("uplink panicked"))??;
    down.join()
        .map_err(|_| io::Error::other("downlink panicked"))??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_prefix_by_family() {
        let v4: IpAddr = "10.88.0.1".parse().unwrap();
        let v6: IpAddr = "fd00:88::1".parse().unwrap();
        assert_eq!(overlay_prefix(v4), 24);
        assert_eq!(overlay_prefix(v6), 64);
    }
}
