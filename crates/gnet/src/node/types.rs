//! Shared node state: the per-peer session state machine and the `Node` it
//! lives in, plus the routing/keepalive helpers the pump and handshake modules
//! drive. All in-memory; no I/O here.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use gnet_noise::handshake::Transport;
use gnet_noise::hybrid::HybridInitiator;

use super::TAG_LEN;
use gnet_crypto::mlkem;
use gnet_punch::PunchState;
use gnet_wire::{self as wire, Kind};

/// Base interval between handshake-init retransmits. WireGuard's REKEY_TIMEOUT
/// is 5s; we use a shorter base for snappy hole punching.
const RETRY_BASE: Duration = Duration::from_secs(1);
/// Maximum random jitter added on top of `RETRY_BASE`. Decorrelates two peers'
/// retransmits so a simultaneous open does not relock step-for-step on every
/// retry (WireGuard adds up to HZ/3 ≈ 333ms for exactly this reason).
const RETRY_JITTER_MS: u64 = 333;

/// Consecutive punch-originated handshake give-ups after which a peer is marked
/// for relay fallback. A path that keeps failing this many times is almost
/// certainly un-punchable (symmetric NAT / CGNAT / hairpin), so we stop dialing
/// it directly and route through a relay instead.
const PUNCH_ATTEMPTS: u32 = 3;

/// When the next handshake-init retransmit is due: now + base + random jitter.
fn next_retry_at() -> Instant {
    let jitter = u64::from(gnet_rand::random_u32()) % RETRY_JITTER_MS;
    Instant::now() + RETRY_BASE + Duration::from_millis(jitter)
}

/// Route a framed datagram to a peer: wrapped in a `gnet-relay` envelope through
/// the peer's relay when it has tripped to relay fallback, else sent directly to
/// its endpoint. Returns the target endpoint and the bytes to send, or `None`
/// if no path is known. `public` is our own static key (the envelope `src`).
pub(super) fn route_dg(
    public: &[u8; 32],
    peer: &Peer,
    dg: Vec<u8>,
) -> Option<(SocketAddr, Vec<u8>)> {
    if peer.relay
        && let Some(relay_ep) = peer.relay_endpoint
    {
        // on the wire a relayed datagram is `RelayData(0x08) ‖ src ‖ dst ‖ inner`
        // so the relay's wire demux routes it to the forward path.
        let envelope = gnet_relay::encode(public, &peer.public, &dg);
        return Some((relay_ep, wire::frame(Kind::RelayData, &envelope)));
    }
    peer.endpoint.map(|ep| (ep, dg))
}

/// Per-peer handshake / transport session.
pub(super) enum Session {
    /// No session and no handshake in flight.
    Idle,
    /// We have an in-flight initiation awaiting message 2. `started` is when
    /// this attempt first began (the basis for giving up via
    /// [`Node::expire_handshakes`]); `retry_at` is when the next msg1
    /// retransmit is due (jittered, the basis for
    /// [`Node::retransmit_initiations`]). Each retransmit is a fresh handshake
    /// (new ephemeral + index) that re-rolls `retry_at` but keeps `started`.
    Initiating {
        ini: Box<HybridInitiator>,
        started: Instant,
        retry_at: Instant,
    },
    /// Handshake complete; transport ciphers ready.
    Established(Transport),
}

/// Runtime state for one configured peer.
pub(super) struct Peer {
    /// Coordinator-side alias (bare, no `gnet-` prefix). Discovery uses it
    /// as the stable identifier across key rotations: when a `/peers` row's
    /// pubkey changes but the alias matches, the daemon treats it as the
    /// same peer with rotated keys and resets the session in-place.
    /// Empty string for peers loaded from static conf (no alias source).
    pub(super) alias: String,
    /// True for peers written in the static conf — discovery's reconcile never
    /// removes them, even if the coordinator stops advertising them (the conf
    /// is the operator's explicit intent and outranks coordinator removal; a
    /// static peer the coordinator later adopts keeps `pinned = true`). False
    /// for peers added from a `/peers` poll: those are coordinator-authoritative
    /// and get removed when they vanish from a successful poll (peer-leave).
    pub(super) pinned: bool,
    pub(super) public: [u8; 32],
    pub(super) mlkem_ek: Box<[u8; mlkem::EK_LEN]>,
    pub(super) vip: IpAddr,
    /// Peer's IPv6 overlay address when dual-stack. `None` keeps the peer
    /// v4-only — `by_vip` then matches v4 packets only.
    pub(super) vip6: Option<IpAddr>,
    pub(super) endpoint: Option<SocketAddr>,
    /// The index we assigned this session; peers stamp it on transport packets
    /// they send us, so we demux incoming transport by index, not by address.
    pub(super) rx_index: u32,
    /// The index the peer assigned; we stamp it on transport packets we send.
    pub(super) tx_index: u32,
    pub(super) session: Session,
    /// Rendezvous state for hole punching this peer. Drives the synchronized
    /// dial before the handshake; `Idle` once a session is established or when
    /// the peer has a direct endpoint and needs no punch.
    pub(super) punch: PunchState,
    /// True once this peer's endpoint came from a hole-punch dial rather than a
    /// configured direct path. Sticky across handshake retries so a run of
    /// punch-originated give-ups accrues toward [`Self::relay`].
    pub(super) punched: bool,
    /// Consecutive punch-originated handshake give-ups (see
    /// [`Node::expire_handshakes`]); reset to 0 once a session establishes.
    pub(super) punch_failures: u32,
    /// True once punching has failed `PUNCH_ATTEMPTS` times: route this peer's
    /// traffic through a relay instead of dialing it directly.
    pub(super) relay: bool,
    /// The relay endpoint to wrap this peer's traffic through when `relay` is
    /// set: the coordinator we tripped through, or — when we learn the peer is
    /// relaying to *us* — the relay a relayed datagram arrived from (reciprocal).
    pub(super) relay_endpoint: Option<SocketAddr>,
    /// Coordinator-side hint: this peer is a preferred relay candidate (e.g.
    /// always-on public host). `Node::coordinator_endpoint` filters on this
    /// first, then falls back to any peer with a known endpoint.
    pub(super) relay_eligible: bool,
    /// Earliest instant at which this peer is eligible for a direct-path
    /// upgrade attempt while routed via a relay. Only consulted when
    /// `relay` is true; [`Node::poll_direct_upgrades`] rolls it forward by
    /// the current backoff after each attempt. Initialised to
    /// `Instant::now() + DIRECT_UPGRADE_BASE` so a freshly-relayed peer
    /// first retries after a grace period rather than at startup.
    pub(super) direct_upgrade_at: Instant,
    /// Consecutive direct-upgrade attempt failures since the last successful
    /// upgrade. Drives the 1.5×-per-failure backoff inside
    /// [`super::punch::next_direct_upgrade_at`], capped at
    /// `DIRECT_UPGRADE_MAX`. Reset to 0 when a punch dial completes (peer
    /// is back on the direct path).
    pub(super) direct_upgrade_failures: u32,
}

/// Shared node state (our keys + peers), guarded by one `Mutex`.
pub(super) struct Node {
    pub(super) private: [u8; 32],
    /// Our X25519 static public key (derived from `private` once at startup).
    /// Used as the deterministic tie-break in handshake-glare resolution: when
    /// two peers init each other at the same time, the side whose key sorts
    /// higher keeps initiating and the other yields and responds.
    pub(super) public: [u8; 32],
    pub(super) mlkem_ek: Vec<u8>,
    pub(super) mlkem_dk: Vec<u8>,
    pub(super) peers: Vec<Peer>,
    /// Dedicated relay servers (gnet-relay-server) advertised by the
    /// coordinator via `/peers`. Preferred over relay_eligible peers for the
    /// *data* plane ([`Self::relay_data_endpoint`]) when a peer trips to relay
    /// fallback — they are always-on and purpose-built for RelayData forwarding.
    /// NOT used for punch *signaling* (PunchConnect/PunchSync): a relay server
    /// only honours RelayData and drops signaling frames, so DCUtR rendezvous
    /// still routes through a gnet peer ([`Self::coordinator_endpoint`]).
    /// Refreshed every discovery poll; empty when none configured.
    pub(super) relay_servers: Vec<SocketAddr>,
    /// Last time each relay server echoed our self-addressed keepalive — its
    /// health pong. `relay_data_endpoint` prefers a relay whose last pong is
    /// within `RELAY_HEALTH_WINDOW`, so a dead relay is routed around. Keyed by
    /// the relay's advertised endpoint; entries for relays no longer advertised
    /// just go stale and are ignored (the map is small — fleet has a handful).
    pub(super) relay_health: std::collections::HashMap<SocketAddr, Instant>,
    /// Our reflexive (public) endpoint as last reported by a peer via an
    /// EndpointReply — the basis for hole punching. `None` until discovered.
    pub(super) reflexive: Option<SocketAddr>,
    /// txid of the most recent EndpointProbe we sent, to match its reply.
    pub(super) probe_txid: u32,
    /// Whether the reflexive endpoint's IP matches one of our local interface
    /// IPs. `None` until reflexive is first learned and a local-IP scan runs.
    /// `Some(true)` means we are behind a NAT that rewrote our source —
    /// direct init to another NAT'd peer cold-starts unreliably, so pump
    /// prefers `start_punch` (DCUtR) for peers we have no relay path to yet.
    /// `Some(false)` means our reflexive equals a local interface IP, OR an
    /// operator pinned it via `behind_nat false` — we are effectively public
    /// and direct init works.
    pub(super) self_is_nat: Option<bool>,
    /// `true` when the operator pinned `behind_nat` in conf — `note_reflexive`
    /// then leaves `self_is_nat` alone (do not let probe outputs override the
    /// operator-known truth, e.g. AWS 1:1 NAT where the heuristic would lie).
    pub(super) nat_override: bool,
}

impl Node {
    pub(super) fn by_vip(&mut self, dst: IpAddr) -> Option<usize> {
        self.peers
            .iter()
            .position(|p| p.vip == dst || p.vip6 == Some(dst))
    }
    pub(super) fn by_endpoint(&mut self, addr: SocketAddr) -> Option<usize> {
        self.peers.iter().position(|p| p.endpoint == Some(addr))
    }
    /// Find the established session we assigned `index` to. Only established
    /// peers are considered — an index on a peer without a live session is
    /// stale and must not match incoming transport.
    pub(super) fn by_rx_index(&mut self, index: u32) -> Option<usize> {
        self.peers
            .iter()
            .position(|p| p.rx_index == index && matches!(p.session, Session::Established(_)))
    }
    pub(super) fn by_pubkey(&mut self, pk: &[u8; 32]) -> Option<usize> {
        self.peers.iter().position(|p| &p.public == pk)
    }

    /// Record a reflexive endpoint learned from an EndpointReply, but only if
    /// its `txid` matches the probe we sent (so a stray/forged reply with the
    /// wrong txid is ignored). Returns true if the reflexive endpoint changed.
    /// On change, also (re)evaluates `self_is_nat` by scanning local interface
    /// IPs — a daemon that moves networks (laptop suspend/resume) gets the
    /// new path-selection answer on the next probe.
    pub(super) fn note_reflexive(&mut self, txid: u32, observed: SocketAddr) -> bool {
        if txid != self.probe_txid {
            return false;
        }
        let changed = self.reflexive != Some(observed);
        self.reflexive = Some(observed);
        if changed && !self.nat_override {
            let locals = crate::node::local_ips::list_local_ips();
            let public = locals.iter().any(|ip| ip == &observed.ip());
            self.self_is_nat = Some(!public);
            eprintln!(
                "event=self_nat_detected is_nat={} reflexive={} reason={}",
                !public,
                observed.ip(),
                if public { "matches_local_if" } else { "no_local_match" }
            );
        }
        changed
    }

    /// Endpoint roaming: point peer `i` at `from` when an authenticated packet
    /// arrives from a new source address (NAT rebind / mobility). Returns true
    /// if the endpoint changed. Callers must only invoke this after a packet
    /// has decrypted, so a forged source cannot hijack the peer's endpoint.
    pub(super) fn roam(&mut self, i: usize, from: SocketAddr) -> bool {
        if self.peers[i].endpoint == Some(from) {
            return false;
        }
        self.peers[i].endpoint = Some(from);
        true
    }

    /// Abandon handshakes whose first attempt began longer than `timeout` ago,
    /// returning them to `Idle` so the next outbound packet re-initiates. The
    /// deadline is measured from `started`, not `retry_at`, so retransmits do
    /// not keep an unreachable peer in-flight forever.
    ///
    /// Also expires `PunchState::Connecting`: under symmetric NAT the DCUtR
    /// reply path can disappear silently (target's reply via coord lands on
    /// a different mini-side NAT mapping than the one mini opened to coord).
    /// Without this branch, `peer.punch` would sit in Connecting forever and
    /// the punch_failures counter would never advance to relay-fallback.
    pub(super) fn expire_handshakes(&mut self, timeout: Duration) {
        let mut tripped: Vec<usize> = Vec::new();
        for (i, p) in self.peers.iter_mut().enumerate() {
            let timed_out_session = matches!(
                &p.session,
                Session::Initiating { started, .. } if started.elapsed() > timeout
            );
            let timed_out_punch = matches!(
                &p.punch,
                PunchState::Connecting { sent_at } if sent_at.elapsed() > timeout
            );
            if timed_out_session || timed_out_punch {
                p.session = Session::Idle;
                p.punch = PunchState::Idle;
                if timed_out_punch && p.relay {
                    // A Connecting timeout on a peer already routed via relay
                    // is a failed direct-upgrade attempt: bump the failure
                    // count and roll the per-peer deadline forward by the new
                    // backoff so the next attempt sits further out (30s →
                    // 45s → 67s → … capped at 5 min).
                    p.direct_upgrade_failures = p.direct_upgrade_failures.saturating_add(1);
                    p.direct_upgrade_at =
                        super::punch::next_direct_upgrade_at(p.direct_upgrade_failures);
                }
                // Any handshake give-up against a peer with no relay yet is a
                // direct-path failure: count toward `PUNCH_ATTEMPTS` so that
                // PUNCH_ATTEMPTS consecutive give-ups trip to relay fallback.
                // Covers three cases:
                //   - punch-originated paths (the original `punched` case),
                //   - direct-init paths where the peer's endpoint is reflexive
                //     and the cold-start NAT-NAT first packet can't punch on
                //     its own (the v0.3 endpoint-report regression made every
                //     NAT peer look directly-reachable, shadowing the punch),
                //   - DCUtR Connecting state that never got a reply
                //     (symmetric-NAT mini-side mapping mismatch).
                if !p.relay {
                    p.punch_failures += 1;
                    if p.punch_failures >= PUNCH_ATTEMPTS {
                        tripped.push(i);
                    }
                }
            }
        }
        // trip in a second pass: picking a relay endpoint borrows &self, which
        // can't overlap the &mut iteration above.
        for i in tripped {
            let relay_ep = self.relay_data_endpoint(i);
            self.peers[i].relay = true;
            self.peers[i].relay_endpoint = relay_ep;
            // A fresh trip back to the relay path is logically a failed
            // direct-upgrade — whatever the failure mode (rendezvous never
            // completed, dial issued but handshake never finished, etc.).
            // Bump the upgrade failure count and roll the per-peer deadline
            // forward so the next attempt sits further out; without this,
            // direct_upgrade_at would still be in the past and the
            // scheduler would re-fire on the very next maintenance tick.
            self.peers[i].direct_upgrade_failures =
                self.peers[i].direct_upgrade_failures.saturating_add(1);
            self.peers[i].direct_upgrade_at =
                super::punch::next_direct_upgrade_at(self.peers[i].direct_upgrade_failures);
            eprintln!(
                "event=peer_relay_fallback peer={i} alias={} punch_failures={}",
                self.peers[i].alias,
                self.peers[i].punch_failures
            );
        }
    }

    /// Craft a fresh handshake init for peer `i` (new ephemeral + a new rx
    /// index the responder will stamp on packets it sends us), returning the
    /// wire datagram and the initiator state for the caller to stash in a
    /// session. The caller routes the datagram (directly or via relay).
    fn craft_init(&mut self, i: usize) -> (Vec<u8>, Box<HybridInitiator>) {
        let mut ini = HybridInitiator::new(
            self.private,
            self.peers[i].public,
            &self.peers[i].mlkem_ek[..],
            gnet_rand::random_32(),
            gnet_rand::random_32(),
        );
        let my_rx = gnet_rand::random_u32();
        let msg1 = ini.write_message_1(&my_rx.to_le_bytes());
        self.peers[i].rx_index = my_rx;
        (wire::frame(Kind::HandshakeInit, &msg1), Box::new(ini))
    }

    /// Begin a handshake with peer `i` (`Idle` → `Initiating`). Returns the
    /// init datagram to send with the lock released — relay-wrapped if the peer
    /// has tripped to relay fallback — or `None` if the peer has no path at all
    /// (neither a direct endpoint nor a relay). `started` is now; `retry_at` is
    /// the first jittered retransmit deadline.
    pub(super) fn initiate(&mut self, i: usize) -> Option<(SocketAddr, Vec<u8>)> {
        let (dg, ini) = self.craft_init(i);
        let public = self.public;
        // route first: with no path there is nowhere to send, so don't enter
        // Initiating (the rx index churned by craft_init is harmless).
        let routed = route_dg(&public, &self.peers[i], dg)?;
        self.peers[i].session = Session::Initiating {
            ini,
            started: Instant::now(),
            retry_at: next_retry_at(),
        };
        Some(routed)
    }

    /// Re-send message 1 for any in-flight initiation whose jittered `retry_at`
    /// has come due, so a dropped init or message 2 recovers on a timer instead
    /// of waiting for the next outbound app packet — the property simultaneous-
    /// open hole punching depends on. Each retry is a fresh handshake (new
    /// ephemeral + index) that re-rolls `retry_at` (with jitter, so two peers
    /// stop colliding in lockstep), but keeps the original `started` so
    /// [`Self::expire_handshakes`] can still give up. Returns
    /// `(endpoint, datagram)` pairs to send with the lock released.
    pub(super) fn retransmit_initiations(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        let now = Instant::now();
        let due: Vec<usize> = self
            .peers
            .iter()
            .enumerate()
            .filter(|(_, p)| {
                matches!(&p.session, Session::Initiating { retry_at, .. } if *retry_at <= now)
            })
            .map(|(i, _)| i)
            .collect();
        let mut out = Vec::new();
        for i in due {
            let Session::Initiating { started, .. } = &self.peers[i].session else {
                continue;
            };
            let started = *started;
            let (dg, ini) = self.craft_init(i);
            let public = self.public;
            if let Some(routed) = route_dg(&public, &self.peers[i], dg) {
                self.peers[i].session = Session::Initiating {
                    ini,
                    started,
                    retry_at: next_retry_at(),
                };
                out.push(routed);
            }
        }
        out
    }

    /// Build a keepalive transport datagram for every established peer with a
    /// known endpoint, advancing that session's send counter. The empty
    /// payload encrypts to just the AEAD tag (`HEADER + TAG_LEN` bytes); the
    /// peer decrypts it to a zero-length plaintext, which the downlink drops
    /// rather than writing to the TUN. Returns `(endpoint, datagram)` pairs to
    /// be sent with the lock released.
    pub(super) fn keepalive_datagrams(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut out = Vec::new();
        let public = self.public;
        for p in &mut self.peers {
            if !matches!(p.session, Session::Established(_)) {
                continue;
            }
            let tx = p.tx_index;
            let mut dg = [0u8; wire::TRANSPORT_HEADER + TAG_LEN];
            dg[0] = Kind::Transport as u8;
            wire::put_index(&mut dg, tx);
            let Session::Established(t) = &mut p.session else {
                continue;
            };
            wire::put_counter(&mut dg, t.send_counter());
            let framed = t
                .send
                .encrypt_in_place(&[], &mut dg[wire::TRANSPORT_HEADER..], 0);
            let bytes = dg[..wire::TRANSPORT_HEADER + framed].to_vec();
            // route_dg wraps to the relay if the peer has tripped to fallback,
            // else sends directly; None when the peer has no path at all.
            if let Some(routed) = route_dg(&public, p, bytes) {
                out.push(routed);
            }
        }
        out
    }

    /// Registration keepalives for the dedicated relay servers: one
    /// `RelayData` envelope addressed to ourselves (`src == dst == our static
    /// key`) per advertised relay. The relay registers our endpoint from the
    /// `src` key on receipt, then drops the datagram as self-addressed (`dst`
    /// resolves to the endpoint it just recorded) — so it never forwards, it
    /// only refreshes our entry. Without this an idle node that originates no
    /// other `RelayData` ages out of the relay's table after `STALE_AFTER` and
    /// becomes unreachable through the relay until it next speaks first.
    ///
    /// The cadence also holds the NAT pinhole toward the relay open, so the
    /// relay can actually reach us. Empty when no relay server is advertised,
    /// or when we are confirmed public (`self_is_nat == Some(false)`) — a
    /// public node is reached directly and is never a relay target.
    pub(super) fn relay_register_datagrams(&self) -> Vec<(SocketAddr, Vec<u8>)> {
        if self.relay_servers.is_empty() || self.self_is_nat == Some(false) {
            return Vec::new();
        }
        let envelope = gnet_relay::encode(&self.public, &self.public, &[]);
        let framed = wire::frame(Kind::RelayData, &envelope);
        self.relay_servers
            .iter()
            .map(|addr| (*addr, framed.clone()))
            .collect()
    }

    /// Record a health pong from `relay` — a self-addressed RelayData echo the
    /// relay sent back for our keepalive. Marks the relay alive as of now so
    /// `relay_data_endpoint` keeps (or resumes) routing through it.
    pub(super) fn note_relay_pong(&mut self, relay: SocketAddr) {
        self.relay_health.insert(relay, Instant::now());
    }

    /// Build an EndpointProbe aimed at any reachable peer to discover our
    /// reflexive (public) endpoint, recording the txid so the reply matches.
    /// Returns `(endpoint, datagram)`, or `None` if no peer has a known
    /// endpoint to probe through.
    pub(super) fn make_probe(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
        let ep = self.peers.iter().find_map(|p| p.endpoint)?;
        let txid = gnet_rand::random_u32();
        self.probe_txid = txid;
        Some((ep, wire::frame(Kind::EndpointProbe, &txid.to_le_bytes())))
    }
}

/// Run a full hybrid handshake and return the established (initiator,
/// responder) transports so transport-path behaviour can be unit tested.
/// Hoisted out of `mod tests` so sibling submodules' tests (`punch::tests`)
/// can build `Session::Established` peers without re-deriving the handshake.
#[cfg(test)]
pub(super) fn established_pair() -> (Transport, Transport) {
    use gnet_noise::hybrid::HybridResponder;

    let ini_priv = [11u8; 32];
    let resp_priv = [22u8; 32];
    let resp_pub = crate::keys::public_key(&resp_priv);
    let (resp_ek, resp_dk) = crate::keys::derive_mlkem(&resp_priv);

    let mut ini = HybridInitiator::new(
        ini_priv,
        resp_pub,
        &resp_ek,
        gnet_rand::random_32(),
        gnet_rand::random_32(),
    );
    let msg1 = ini.write_message_1(&[]);
    let mut resp = HybridResponder::new(resp_priv, &resp_ek, &resp_dk, gnet_rand::random_32());
    resp.read_message_1(&msg1).expect("read msg1");
    let (msg2, resp_t) = resp.write_message_2(&[]).expect("write msg2");
    let (ini_t, _) = ini.read_message_2(&msg2).expect("read msg2");
    (ini_t, resp_t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys;
    use std::net::Ipv4Addr;

    pub(super) fn test_peer(ek: &[u8], session: Session, endpoint: Option<SocketAddr>) -> Peer {
        Peer {
            alias: String::new(),
            pinned: false,
            public: [0u8; 32],
            mlkem_ek: Box::<[u8; mlkem::EK_LEN]>::try_from(ek.to_vec().into_boxed_slice())
                .expect("test ek must be EK_LEN bytes"),
            vip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            vip6: None,
            endpoint,
            rx_index: 0,
            tx_index: 0,
            session,
            punch: PunchState::Idle,
            punched: false,
            punch_failures: 0,
            relay: false,
            relay_endpoint: None,
            relay_eligible: false,
            direct_upgrade_at: Instant::now() + super::super::punch::DIRECT_UPGRADE_BASE,
            direct_upgrade_failures: 0,
        }
    }

    fn test_node(ek: &[u8], peers: Vec<Peer>) -> Node {
        Node {
            private: [0u8; 32],
            public: [0u8; 32],
            mlkem_ek: ek.to_vec(),
            mlkem_dk: ek.to_vec(),
            peers,
            relay_servers: Vec::new(),
            relay_health: Default::default(),
            reflexive: None,
            probe_txid: 0,
            self_is_nat: None,
            nat_override: false,
        }
    }

    #[test]
    fn keepalive_datagrams_only_for_established_with_endpoint() {
        let (ek, _dk) = keys::derive_mlkem(&[9u8; 32]);
        let (a_ini, mut a_resp) = established_pair();
        let (b_ini, _b_resp) = established_pair();
        let ep: SocketAddr = "192.168.50.2:7777".parse().unwrap();
        let mut p0 = test_peer(&ek, Session::Established(a_ini), Some(ep));
        p0.tx_index = 0x0102_0304; // stamped on outgoing transport
        let mut node = test_node(
            &ek,
            vec![
                p0,                                                // → keepalive
                test_peer(&ek, Session::Idle, Some(ep)),           // no session → skip
                test_peer(&ek, Session::Established(b_ini), None), // no endpoint → skip
            ],
        );

        let dgs = node.keepalive_datagrams();
        assert_eq!(dgs.len(), 1, "only the established+endpoint peer");
        let (got_ep, dg) = &dgs[0];
        assert_eq!(*got_ep, ep);
        assert_eq!(dg[0], Kind::Transport as u8);
        // the peer's tx_index is stamped after the tag, and the first packet
        // uses counter 0 (a fresh send cipher).
        assert_eq!(wire::index(dg), Some(0x0102_0304));
        assert_eq!(wire::counter(dg), Some(0));
        // empty payload → tag + index + counter + 16-byte AEAD tag only
        assert_eq!(dg.len(), wire::TRANSPORT_HEADER + 16);

        // the peer decrypts the keepalive via the real recv path (explicit
        // counter + replay check) to an empty payload — the case the downlink
        // must NOT forward to the TUN.
        let ctr = wire::counter(dg).expect("counter");
        let mut ct = dg[wire::TRANSPORT_HEADER..].to_vec();
        let ct_len = ct.len();
        let len = a_resp
            .recv_at(ctr, &[], &mut ct, ct_len)
            .expect("keepalive decrypts");
        assert_eq!(len, 0);
    }

    #[test]
    fn by_vip_matches_both_address_families() {
        let (ek, _dk) = keys::derive_mlkem(&[9u8; 32]);
        // peer 0: dual-stack — both vip and vip6 must route to it
        let mut dual = test_peer(&ek, Session::Idle, None);
        dual.vip = IpAddr::V4(Ipv4Addr::new(10, 42, 42, 8));
        dual.vip6 = Some("fd8d:f090:2ebb::8".parse().unwrap());
        // peer 1: v4-only — its v6 column stays None
        let mut v4only = test_peer(&ek, Session::Idle, None);
        v4only.vip = IpAddr::V4(Ipv4Addr::new(10, 42, 42, 9));
        let mut node = test_node(&ek, vec![dual, v4only]);

        assert_eq!(node.by_vip("10.42.42.8".parse().unwrap()), Some(0));
        assert_eq!(node.by_vip("fd8d:f090:2ebb::8".parse().unwrap()), Some(0));
        assert_eq!(node.by_vip("10.42.42.9".parse().unwrap()), Some(1));
        // v6 packet for a v4-only peer must not match
        assert_eq!(node.by_vip("fd8d:f090:2ebb::9".parse().unwrap()), None);
        // an unknown overlay address routes to no peer
        assert_eq!(node.by_vip("10.42.42.99".parse().unwrap()), None);
    }

    #[test]
    fn by_rx_index_matches_only_established() {
        let (ek, _dk) = keys::derive_mlkem(&[9u8; 32]);
        let (a_ini, _) = established_pair();
        let mut established = test_peer(&ek, Session::Established(a_ini), None);
        established.rx_index = 0xABCD;
        let mut idle = test_peer(&ek, Session::Idle, None);
        idle.rx_index = 0xABCD; // same index, but no session
        let mut node = test_node(&ek, vec![idle, established]);
        assert_eq!(node.by_rx_index(0xABCD), Some(1)); // the established one
        assert_eq!(node.by_rx_index(0x9999), None);
    }

    #[test]
    fn roam_follows_new_source_address() {
        let (ek, _dk) = keys::derive_mlkem(&[9u8; 32]);
        let (a_ini, _) = established_pair();
        let ep1: SocketAddr = "192.168.50.2:7777".parse().unwrap();
        let ep2: SocketAddr = "203.0.113.9:40001".parse().unwrap(); // NAT rebind
        let mut node = test_node(
            &ek,
            vec![test_peer(&ek, Session::Established(a_ini), Some(ep1))],
        );
        // unchanged source → no roam
        assert!(!node.roam(0, ep1));
        assert_eq!(node.peers[0].endpoint, Some(ep1));
        // new source → roam to it
        assert!(node.roam(0, ep2));
        assert_eq!(node.peers[0].endpoint, Some(ep2));
    }

    #[test]
    fn expire_handshakes_resets_stale_initiating() {
        let (ek, _dk) = keys::derive_mlkem(&[9u8; 32]);
        let peer = |session| test_peer(&ek, session, None);
        let new_ini = || HybridInitiator::new([1u8; 32], [2u8; 32], &ek, [3u8; 32], [4u8; 32]);
        let stale = Session::Initiating {
            ini: Box::new(new_ini()),
            started: Instant::now() - Duration::from_secs(10),
            retry_at: Instant::now(),
        };
        let fresh = Session::Initiating {
            ini: Box::new(new_ini()),
            started: Instant::now(),
            retry_at: Instant::now(),
        };
        let mut node = test_node(&ek, vec![peer(stale), peer(fresh)]);
        node.expire_handshakes(Duration::from_secs(3));
        assert!(matches!(node.peers[0].session, Session::Idle)); // stale → reset
        assert!(matches!(node.peers[1].session, Session::Initiating { .. })); // fresh kept
    }

    #[test]
    fn expire_measures_from_started_not_retry_at() {
        // a long-running attempt that keeps retransmitting (fresh retry_at) must
        // still be given up once `started` passes the timeout — otherwise an
        // unreachable peer would retransmit forever.
        let (ek, _dk) = keys::derive_mlkem(&[9u8; 32]);
        let new_ini = || HybridInitiator::new([1u8; 32], [2u8; 32], &ek, [3u8; 32], [4u8; 32]);
        let old_attempt = Session::Initiating {
            ini: Box::new(new_ini()),
            started: Instant::now() - Duration::from_secs(10),
            retry_at: Instant::now() + Duration::from_secs(1), // just retransmitted
        };
        let mut node = test_node(&ek, vec![test_peer(&ek, old_attempt, None)]);
        node.expire_handshakes(Duration::from_secs(3));
        assert!(matches!(node.peers[0].session, Session::Idle));
    }

    #[test]
    fn expire_handshakes_extends_direct_upgrade_backoff_on_relay_connecting_timeout() {
        // A punch upgrade that times out on a peer already routed via relay
        // is a failed direct-upgrade attempt: failures + 1, deadline rolled
        // forward by the new backoff. The session-side `punch_failures`
        // counter must stay untouched — those are direct-init failures, a
        // separate concern.
        let (ek, _dk) = keys::derive_mlkem(&[9u8; 32]);
        let relay_ep: SocketAddr = "203.0.113.9:7777".parse().unwrap();
        let mut p = test_peer(&ek, Session::Idle, None);
        p.relay = true;
        p.relay_endpoint = Some(relay_ep);
        p.direct_upgrade_failures = 1;
        p.direct_upgrade_at = Instant::now() + Duration::from_secs(60);
        p.punch = PunchState::Connecting {
            sent_at: Instant::now() - Duration::from_secs(10),
        };
        let mut node = test_node(&ek, vec![p]);

        let before = Instant::now();
        node.expire_handshakes(Duration::from_secs(3));

        assert_eq!(
            node.peers[0].direct_upgrade_failures, 2,
            "failure count bumped on relay-connecting timeout"
        );
        assert!(
            matches!(node.peers[0].punch, PunchState::Idle),
            "punch state reset after expire"
        );
        let advanced = node.peers[0].direct_upgrade_at;
        // backoff(2) ≈ DIRECT_UPGRADE_BASE × 1.5² = 67.5s
        assert!(
            advanced > before + Duration::from_secs(60),
            "deadline rolled past the previous slot"
        );
        assert!(
            advanced < before + Duration::from_secs(75),
            "deadline within the new backoff slot"
        );
        assert_eq!(
            node.peers[0].punch_failures, 0,
            "punch_failures untouched — relay peers do not accrue toward trip"
        );
    }

    #[test]
    fn expire_handshakes_leaves_direct_upgrade_alone_for_non_relay_peers() {
        // A peer not on the relay path that fails its handshake walks the
        // existing punch_failures path, not the direct_upgrade backoff.
        let (ek, _dk) = keys::derive_mlkem(&[9u8; 32]);
        let mut p = test_peer(&ek, Session::Idle, None);
        p.direct_upgrade_failures = 1;
        let initial_deadline = p.direct_upgrade_at;
        p.punch = PunchState::Connecting {
            sent_at: Instant::now() - Duration::from_secs(10),
        };
        let mut node = test_node(&ek, vec![p]);

        node.expire_handshakes(Duration::from_secs(3));

        assert_eq!(
            node.peers[0].direct_upgrade_failures, 1,
            "untouched — peer was not on the relay path"
        );
        assert_eq!(
            node.peers[0].direct_upgrade_at, initial_deadline,
            "deadline untouched"
        );
        assert_eq!(
            node.peers[0].punch_failures, 1,
            "ordinary punch-failure counter still increments"
        );
    }

    #[test]
    fn punch_failures_trip_relay_after_attempts() {
        // Any handshake initiation that keeps timing out trips the peer to
        // relay after PUNCH_ATTEMPTS consecutive give-ups. v0.4.3 widened the
        // counter to cover direct-init paths too — previously only `punched`
        // peers accrued, which masked the cold-start NAT↔NAT case where both
        // sides looked reachable (endpoint via reflexive-report) but neither
        // NAT had a return mapping yet.
        let (ek, _dk) = keys::derive_mlkem(&[9u8; 32]);
        let new_ini = || HybridInitiator::new([1u8; 32], [2u8; 32], &ek, [3u8; 32], [4u8; 32]);
        let stale = || Session::Initiating {
            ini: Box::new(new_ini()),
            started: Instant::now() - Duration::from_secs(10),
            retry_at: Instant::now(),
        };

        let mut punched = test_peer(&ek, stale(), None);
        punched.punched = true; // endpoint came from a hole-punch dial
        let direct = test_peer(&ek, stale(), None); // configured endpoint
        let mut node = test_node(&ek, vec![punched, direct]);

        for expected in 1..PUNCH_ATTEMPTS {
            node.expire_handshakes(Duration::from_secs(3));
            assert_eq!(node.peers[0].punch_failures, expected);
            assert_eq!(node.peers[1].punch_failures, expected, "direct-init paths now count too");
            assert!(!node.peers[0].relay, "not yet at threshold");
            assert!(!node.peers[1].relay);
            node.peers[0].session = stale();
            node.peers[1].session = stale();
        }
        // PUNCH_ATTEMPTS-th give-up trips relay on BOTH peers
        node.expire_handshakes(Duration::from_secs(3));
        assert!(node.peers[0].relay, "punched peer tripped at threshold");
        assert!(node.peers[1].relay, "direct peer also tripped (cold-start NAT-NAT recovery)");
    }

    #[test]
    fn route_dg_wraps_only_for_relay_peers() {
        let (ek, _dk) = keys::derive_mlkem(&[9u8; 32]);
        let public = [7u8; 32];
        let ep: SocketAddr = "192.168.1.2:7777".parse().unwrap();
        let relay_ep: SocketAddr = "203.0.113.9:5555".parse().unwrap();

        // direct peer: the datagram passes through unchanged to its endpoint
        let mut direct = test_peer(&ek, Session::Idle, Some(ep));
        direct.public = [1u8; 32];
        let (got_ep, bytes) = route_dg(&public, &direct, vec![0xAA, 0xBB]).expect("direct path");
        assert_eq!(got_ep, ep);
        assert_eq!(bytes, vec![0xAA, 0xBB]);

        // relay peer: the datagram is wrapped in a src‖dst envelope to the relay
        let mut relayed = test_peer(&ek, Session::Idle, Some(ep));
        relayed.public = [1u8; 32];
        relayed.relay = true;
        relayed.relay_endpoint = Some(relay_ep);
        let (got_ep, bytes) = route_dg(&public, &relayed, vec![0xAA, 0xBB]).expect("relay path");
        assert_eq!(got_ep, relay_ep);
        // on the wire: the RelayData tag, then the src‖dst‖inner envelope
        assert_eq!(bytes[0], Kind::RelayData as u8);
        let (src, dst, inner) = gnet_relay::decode(&bytes[1..]).expect("envelope");
        assert_eq!(src, &public);
        assert_eq!(dst, &[1u8; 32]);
        assert_eq!(inner, &[0xAA, 0xBB]);

        // no path: neither a direct endpoint nor a relay
        let mut nowhere = test_peer(&ek, Session::Idle, None);
        nowhere.public = [1u8; 32];
        assert!(route_dg(&public, &nowhere, vec![0xAA]).is_none());
    }

    #[test]
    fn retry_interval_is_jittered_within_bounds() {
        // next_retry_at must land in [base, base+jitter) and vary across samples,
        // proving the jitter is live rather than a fixed interval.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let before = Instant::now();
            let delta = next_retry_at().duration_since(before);
            assert!(delta >= RETRY_BASE, "never below base");
            assert!(
                delta < RETRY_BASE + Duration::from_millis(RETRY_JITTER_MS + 100),
                "within base + jitter (+slack for elapsed)"
            );
            seen.insert(delta.as_millis());
        }
        assert!(seen.len() > 1, "jitter must vary across samples");
    }

    #[test]
    fn retransmit_initiations_resends_when_due() {
        let (ek, _dk) = keys::derive_mlkem(&[9u8; 32]);
        let ep: SocketAddr = "192.168.50.9:7777".parse().unwrap();

        // a peer with no endpoint cannot be initiated through
        let mut no_ep = test_node(&ek, vec![test_peer(&ek, Session::Idle, None)]);
        assert!(no_ep.initiate(0).is_none());

        // initiate installs an in-flight handshake and returns the init datagram
        let mut node = test_node(&ek, vec![test_peer(&ek, Session::Idle, Some(ep))]);
        let (got_ep, dg) = node.initiate(0).expect("initiate sends");
        assert_eq!(got_ep, ep);
        assert_eq!(dg[0], Kind::HandshakeInit as u8);
        let rx_first = node.peers[0].rx_index;
        let started_first = match &node.peers[0].session {
            Session::Initiating { started, .. } => *started,
            _ => panic!("must be initiating after initiate"),
        };

        // freshly sent → retry_at is in the future, nothing due yet
        assert!(node.retransmit_initiations().is_empty());

        // backdate retry_at into the past → a fresh msg1 is produced
        if let Session::Initiating { retry_at, .. } = &mut node.peers[0].session {
            *retry_at = Instant::now() - Duration::from_secs(1);
        }
        let resend = node.retransmit_initiations();
        assert_eq!(resend.len(), 1);
        assert_eq!(resend[0].0, ep);
        assert_eq!(resend[0].1[0], Kind::HandshakeInit as u8);

        // a retry is a fresh handshake (new rx index), still in-flight, and the
        // original attempt start is preserved so expire can still time it out
        assert_ne!(node.peers[0].rx_index, rx_first, "retry rotates rx index");
        match &node.peers[0].session {
            Session::Initiating {
                started, retry_at, ..
            } => {
                assert_eq!(*started, started_first, "started preserved across retry");
                assert!(*retry_at > Instant::now(), "retry_at rolled forward");
            }
            _ => panic!("still initiating after retry"),
        }

        // Idle / Established peers are never retransmitted
        node.peers[0].session = Session::Idle;
        assert!(node.retransmit_initiations().is_empty());
    }

    #[test]
    fn note_reflexive_requires_matching_txid() {
        let (ek, _dk) = keys::derive_mlkem(&[9u8; 32]);
        let mut node = test_node(&ek, vec![]);
        node.probe_txid = 0x1234;
        let obs: SocketAddr = "203.0.113.7:50000".parse().unwrap();
        // a reply with the wrong txid is ignored
        assert!(!node.note_reflexive(0x9999, obs));
        assert_eq!(node.reflexive, None);
        // the matching txid is learned
        assert!(node.note_reflexive(0x1234, obs));
        assert_eq!(node.reflexive, Some(obs));
        // learning the same endpoint again is not a change
        assert!(!node.note_reflexive(0x1234, obs));
    }

    #[test]
    fn make_probe_targets_a_peer_with_endpoint() {
        let (ek, _dk) = keys::derive_mlkem(&[9u8; 32]);
        // no endpoints → nothing to probe through
        let mut node = test_node(&ek, vec![test_peer(&ek, Session::Idle, None)]);
        assert!(node.make_probe().is_none());
        // a peer with an endpoint → a probe to it, txid recorded
        let ep: SocketAddr = "192.168.50.9:7777".parse().unwrap();
        let mut node = test_node(&ek, vec![test_peer(&ek, Session::Idle, Some(ep))]);
        let (got_ep, dg) = node.make_probe().expect("probe");
        assert_eq!(got_ep, ep);
        assert_eq!(dg[0], Kind::EndpointProbe as u8);
        assert_eq!(dg.len(), wire::HEADER + 4); // tag + txid
        // the recorded txid matches the datagram, so its reply is accepted
        let txid = u32::from_le_bytes(dg[wire::HEADER..].try_into().unwrap());
        assert_eq!(node.probe_txid, txid);
    }

    #[test]
    fn relay_register_datagrams_target_each_relay_with_self_envelope() {
        let (ek, _dk) = keys::derive_mlkem(&[9u8; 32]);
        let r1: SocketAddr = "198.51.100.1:65433".parse().unwrap();
        let r2: SocketAddr = "[2001:db8::1]:65433".parse().unwrap();
        let mut node = test_node(&ek, vec![]);
        node.public = [0xAB; 32];

        // no relay servers advertised → nothing to register.
        assert!(node.relay_register_datagrams().is_empty());

        node.relay_servers = vec![r1, r2];

        // self_is_nat unknown (None) → register conservatively to both relays.
        let dgs = node.relay_register_datagrams();
        assert_eq!(dgs.len(), 2);
        assert_eq!(dgs[0].0, r1);
        assert_eq!(dgs[1].0, r2);
        // each datagram is RelayData carrying a src==dst==our-key envelope with
        // an empty inner — the relay registers us, then drops it self-addressed.
        for (_, dg) in &dgs {
            assert_eq!(dg[0], Kind::RelayData as u8);
            let (src, dst, inner) = gnet_relay::decode(&dg[1..]).expect("envelope decodes");
            assert_eq!(src, &node.public);
            assert_eq!(dst, &node.public);
            assert!(inner.is_empty(), "registration carries no payload");
        }

        // confirmed public → never a relay target, so no registration traffic.
        node.self_is_nat = Some(false);
        assert!(node.relay_register_datagrams().is_empty());

        // behind NAT → register.
        node.self_is_nat = Some(true);
        assert_eq!(node.relay_register_datagrams().len(), 2);
    }
}
