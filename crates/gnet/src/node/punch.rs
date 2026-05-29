//! Node-side hole-punch wiring: drives the `gnet-punch` rendezvous protocol
//! over the live peer table. Relays connect/sync by destination key, starts a
//! punch when a peer has no direct path, measures the coordinator RTT, and
//! turns a due dial into a normal handshake. The zero-I/O codec + state machine
//! live in the [`gnet_punch`] crate; this module owns only the `Node` glue.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use gnet_punch::{
    PunchState, candidates_around, decode_connect, decode_sync, encode_connect, encode_sync,
};
use gnet_wire::{self as wire, Kind};

use super::types::{Node, Session};

/// Sequential candidate radius for symmetric-NAT port-prediction fan-out:
/// dial the observed reflexive endpoint plus `±1..=±R` around it. `R=32`
/// matches the field-realistic Linux MASQUERADE walk distance covered by
/// the [`gnet_punch::predict`] sequential half (see its
/// `sequential_catches_small_walk` test). Total fan-out per dial is
/// `1 + 2·R = 65` UDP packets — within DCUtR's path-midpoint sync window.
pub(super) const PUNCH_SEQUENTIAL_RADIUS: u16 = 32;

/// Initial backoff between direct-path upgrade attempts on a relayed peer.
/// Tailscale's DERP→direct upgrade and libp2p's hole-punch retry both sit
/// in the 30-second neighbourhood: short enough that a transient relay
/// route is replaced quickly, long enough not to flood the rendezvous
/// coordinator with retries.
pub(super) const DIRECT_UPGRADE_BASE: Duration = Duration::from_secs(30);

/// Maximum backoff after repeated upgrade failures; growth caps at five
/// minutes so a peer behind an un-punchable symmetric NAT does not retry
/// every few seconds forever, while a network change (laptop roaming)
/// still recovers within bounded time without an operator nudge.
pub(super) const DIRECT_UPGRADE_MAX: Duration = Duration::from_secs(300);

/// A relay server counts as alive if it echoed our self-addressed keepalive
/// within this window. Three keepalive intervals (3 × 25s, the node-side
/// `RELAY_REGISTER_INTERVAL`): tolerates two consecutive lost keepalive/echo
/// round-trips before a relay is treated as down and routed around, so a single
/// dropped UDP datagram never flaps the relay route.
pub(super) const RELAY_HEALTH_WINDOW: Duration = Duration::from_secs(75);

/// Next direct-upgrade attempt deadline: `now + DIRECT_UPGRADE_BASE × 1.5^failures`
/// clamped to `DIRECT_UPGRADE_MAX`. The 1.5× step is realised as `× 3 / 2`
/// on `Duration` so the precision tracks `Instant`'s nanosecond units
/// without floating-point. The exponent is bounded at 20 iterations
/// purely to keep the helper bounded — the cap kicks in well before that.
pub(super) fn next_direct_upgrade_at(failures: u32) -> Instant {
    let mut delay = DIRECT_UPGRADE_BASE;
    for _ in 0..failures.min(20) {
        delay = (delay * 3) / 2;
        if delay >= DIRECT_UPGRADE_MAX {
            delay = DIRECT_UPGRADE_MAX;
            break;
        }
    }
    Instant::now() + delay
}

impl Node {
    /// Begin a synchronized punch to peer `i` as the origin: relay a
    /// PunchConnect carrying our reflexive endpoint through a coordinator (any
    /// other peer we already reach directly) and enter `Connecting`. Returns
    /// the datagram to send with the lock released, or `None` if we have no
    /// reflexive endpoint yet or no coordinator to relay through.
    ///
    /// Driven by [`Self::poll_direct_upgrades`]: periodically retries DCUtR
    /// on relayed peers so a relay hop drops back to a direct path when both
    /// sides' NAT topology allows it. Pump's v0.5 path selection still keeps
    /// the relay route as the always-works cold start; this is the warm-path
    /// upgrade that runs on top.
    pub(super) fn start_punch(&mut self, i: usize) -> Option<(SocketAddr, Vec<u8>)> {
        let reflexive = self.reflexive?;
        let coordinator = self.coordinator_endpoint(i)?;
        let target = self.peers[i].public;
        let body = encode_connect(&self.public, &target, reflexive);
        self.peers[i].punch = PunchState::Connecting {
            sent_at: Instant::now(),
        };
        Some((coordinator, wire::frame(Kind::PunchConnect, &body)))
    }

    /// A coordinator endpoint to relay rendezvous through: prefer peers
    /// explicitly marked `relay_eligible` by the operator (always-on public
    /// hosts), fall back to any peer other than `exclude` with a known endpoint
    /// so a deployment that has not yet flagged anyone still works.
    pub(super) fn coordinator_endpoint(&self, exclude: usize) -> Option<SocketAddr> {
        let reachable = || {
            self.peers
                .iter()
                .enumerate()
                .filter(|(j, p)| *j != exclude && p.endpoint.is_some())
        };
        reachable()
            .find(|(_, p)| p.relay_eligible)
            .or_else(|| reachable().next())
            .and_then(|(_, p)| p.endpoint)
    }

    /// A relay endpoint for the *data* plane: where to wrap this peer's traffic
    /// as `RelayData` when it trips to relay fallback. Prefers a dedicated
    /// gnet-relay-server (DERP-style, always-on, purpose-built for forwarding
    /// by dst key), falling back to [`Self::coordinator_endpoint`]'s peer-based
    /// logic so a deployment that advertises no relay server still relays
    /// through a `relay_eligible` peer.
    ///
    /// Distinct from `coordinator_endpoint` because the two planes have
    /// different reachability requirements: a relay server forwards only
    /// `RelayData` and drops punch signaling, so it can carry data but never
    /// rendezvous — see [`Node::relay_servers`].
    pub(super) fn relay_data_endpoint(&self, exclude: usize) -> Option<SocketAddr> {
        // Prefer a healthy relay server — one that echoed our keepalive within
        // RELAY_HEALTH_WINDOW — so a dead relay is routed around. The first
        // healthy entry wins (stable: no churn between equally-live relays;
        // RTT-ranked selection is deliberately deferred — overkill for a
        // handful of relays and a source of needless route flapping). When no
        // relay has ponged yet (cold start, before the first probe round), fall
        // back to first() so we still attempt a relay rather than stalling.
        let now = Instant::now();
        let healthy = self.relay_servers.iter().copied().find(|addr| {
            self.relay_health
                .get(addr)
                .is_some_and(|t| now.duration_since(*t) < RELAY_HEALTH_WINDOW)
        });
        healthy
            .or_else(|| self.relay_servers.first().copied())
            .or_else(|| self.coordinator_endpoint(exclude))
    }

    /// Handle an inbound PunchConnect that arrived from `from`. Three cases:
    /// relay it (we are the coordinator, not the target); treat it as the reply
    /// we awaited (we are the origin mid-`Connecting`) — measure RTT and send
    /// the sync; or act as the target — learn the origin's reflexive endpoint,
    /// reply with ours, and await the sync. Returns datagrams to send unlocked.
    pub(super) fn handle_connect(
        &mut self,
        body: &[u8],
        from: SocketAddr,
    ) -> Vec<(SocketAddr, Vec<u8>)> {
        let Some((origin, target, reflexive)) = decode_connect(body) else {
            return Vec::new();
        };
        // not addressed to us → we are the coordinator; relay to the target.
        if target != self.public {
            return self.relay(&target, Kind::PunchConnect, body);
        }
        let Some(i) = self.by_pubkey(&origin) else {
            return Vec::new(); // unknown origin
        };
        // we are already punching this peer as origin → this connect is the
        // reply we awaited: measure the RTT and send the sync.
        if matches!(self.peers[i].punch, PunchState::Connecting { .. }) {
            if self.peers[i]
                .punch
                .on_reply(reflexive, Instant::now(), PUNCH_SEQUENTIAL_RADIUS)
                && let Some(coord) = self.coordinator_endpoint(i)
            {
                let sync = encode_sync(&self.public, &origin);
                return vec![(coord, wire::frame(Kind::PunchSync, &sync))];
            }
            return Vec::new();
        }
        // otherwise we are the target: remember where to dial, then reply with
        // our own reflexive endpoint so the origin can measure the round trip.
        let Some(my_reflexive) = self.reflexive else {
            return Vec::new();
        };
        self.peers[i].punch = PunchState::Awaiting {
            candidates: candidates_around(reflexive, PUNCH_SEQUENTIAL_RADIUS),
        };
        let reply = encode_connect(&self.public, &origin, my_reflexive);
        vec![(from, wire::frame(Kind::PunchConnect, &reply))]
    }

    /// Handle an inbound PunchSync. Relay it if we are the coordinator;
    /// otherwise we are the target and fan-out dial the origin immediately
    /// (its first packets are already on the way). Returns the handshake
    /// inits — one per candidate — to send with the lock released.
    pub(super) fn handle_sync(&mut self, body: &[u8]) -> Vec<(SocketAddr, Vec<u8>)> {
        let Some((origin, target)) = decode_sync(body) else {
            return Vec::new();
        };
        if target != self.public {
            return self.relay(&target, Kind::PunchSync, body);
        }
        let Some(i) = self.by_pubkey(&origin) else {
            return Vec::new();
        };
        let PunchState::Awaiting { candidates } = &self.peers[i].punch else {
            return Vec::new();
        };
        let candidates = candidates.clone();
        self.dial_fanout(i, &candidates)
    }

    /// Origin-side delayed dials: fan-out dial any peer whose `Syncing`
    /// deadline (reply + RTT/2) has arrived. Called from the dial poller.
    /// Returns handshake inits — one per candidate — to send with the lock
    /// released.
    pub(super) fn poll_punch_dials(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        let now = Instant::now();
        let due: Vec<(usize, Vec<SocketAddr>)> = self
            .peers
            .iter()
            .enumerate()
            .filter_map(|(i, p)| p.punch.due_dial(now).map(|c| (i, c.to_vec())))
            .collect();
        let mut out = Vec::new();
        for (i, candidates) in due {
            out.extend(self.dial_fanout(i, &candidates));
        }
        out
    }

    /// The earliest pending origin dial deadline (`Syncing.dial_at`), if any.
    /// The dial poller waits until this instant before waking, so a scheduled
    /// dial fires on time without a fixed busy-poll tick.
    pub(super) fn next_punch_dial(&self) -> Option<Instant> {
        self.peers
            .iter()
            .filter_map(|p| match p.punch {
                PunchState::Syncing { dial_at, .. } => Some(dial_at),
                _ => None,
            })
            .min()
    }

    /// Maintenance sweep: for each peer routed via a relay whose session is
    /// up and whose `direct_upgrade_at` deadline has arrived, kick off a
    /// hole-punch upgrade to the direct path. The per-peer deadline is rolled
    /// forward by the current failure backoff *before* the attempt fires so
    /// the next try sits at the next backoff slot regardless of whether the
    /// punch succeeds — failure bookkeeping (clearing relay on success,
    /// incrementing `direct_upgrade_failures` on timeout) is owned by
    /// `dial` / `expire_handshakes` on completion. Returns the connect
    /// datagrams to send with the lock released.
    ///
    /// Skipped for any peer whose punch is already in flight (`PunchState`
    /// other than `Idle`): the active punch carries the upgrade to
    /// completion on its own. Skipped wholesale when we have no reflexive
    /// endpoint yet — without one [`Self::start_punch`] cannot encode a
    /// coherent connect, so there is nothing useful to attempt.
    pub(super) fn poll_direct_upgrades(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        if self.reflexive.is_none() {
            return Vec::new();
        }
        let now = Instant::now();
        let due: Vec<usize> = self
            .peers
            .iter()
            .enumerate()
            .filter(|(_, p)| {
                p.relay
                    && matches!(p.session, Session::Established(_))
                    && matches!(p.punch, PunchState::Idle)
                    && p.direct_upgrade_at <= now
            })
            .map(|(i, _)| i)
            .collect();
        let mut out = Vec::new();
        for i in due {
            let failures = self.peers[i].direct_upgrade_failures;
            self.peers[i].direct_upgrade_at = next_direct_upgrade_at(failures);
            if let Some(send) = self.start_punch(i) {
                out.push(send);
            }
        }
        out
    }

    /// Fan-out dial across all symmetric-NAT port-prediction candidates once
    /// rendezvous has aligned the timing: point the peer at the observed
    /// reflexive (`candidates[0]`), clear its punch state, and start the
    /// normal handshake (which the glare logic + jittered retransmit carry
    /// to completion). The same `HandshakeInit` datagram — Noise IK msg1 is
    /// not bound to its destination address — is then emitted to every
    /// candidate; under symmetric NAT only the one whose port the peer's
    /// NAT actually allocated for *us* makes it through. The hit address
    /// reaches us as the `from` of the subsequent `HandshakeResp`, where
    /// [`super::handshake::complete_initiation`] corrects `peer.endpoint`
    /// from the observed-port guess to the real one. Marks the peer
    /// `punched` so a run of give-ups on it accrues toward relay fallback.
    /// Returns one `(candidate, datagram)` per fan-out target.
    ///
    /// The dial commits to the direct path: the relay flag is cleared so
    /// `initiate`'s [`super::types::route_dg`] sends msg1 directly to the
    /// punched endpoint — sending it through the relay envelope would defeat
    /// DCUtR's simultaneous-open NAT-mapping property (the kernel needs an
    /// outbound packet on the direct 4-tuple for the inbound reply to land).
    /// If every candidate misses and the handshake fails, `expire_handshakes`
    /// walks the regular PUNCH_ATTEMPTS path back to relay fallback.
    fn dial_fanout(&mut self, i: usize, candidates: &[SocketAddr]) -> Vec<(SocketAddr, Vec<u8>)> {
        let Some((&observed, rest)) = candidates.split_first() else {
            return Vec::new();
        };
        self.peers[i].endpoint = Some(observed);
        self.peers[i].punch = PunchState::Idle;
        self.peers[i].punched = true;
        self.peers[i].relay = false;
        self.peers[i].relay_endpoint = None;
        self.peers[i].direct_upgrade_failures = 0;
        // `initiate` returns the routed (observed, dg) pair (relay is off, so
        // this is the direct branch of `route_dg`). The same dg bytes are then
        // cloned out to every other candidate.
        let Some((_, dg)) = self.initiate(i) else {
            return Vec::new();
        };
        let mut out = Vec::with_capacity(candidates.len());
        out.push((observed, dg.clone()));
        for &cand in rest {
            out.push((cand, dg.clone()));
        }
        out
    }

    /// Relay a rendezvous datagram to the peer identified by `target`'s pubkey,
    /// if we know its endpoint. The body is forwarded unchanged.
    fn relay(&mut self, target: &[u8; 32], kind: Kind, body: &[u8]) -> Vec<(SocketAddr, Vec<u8>)> {
        if let Some(j) = self.by_pubkey(target)
            && let Some(ep) = self.peers[j].endpoint
        {
            return vec![(ep, wire::frame(kind, body))];
        }
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::{Peer, Session, established_pair};
    use super::*;
    use crate::keys;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    /// Build a node from our private key with the given peers and reflexive.
    fn node(my_priv: [u8; 32], peers: Vec<Peer>, reflexive: Option<SocketAddr>) -> Node {
        let public = keys::public_key(&my_priv);
        let (mlkem_ek, mlkem_dk) = keys::derive_mlkem(&my_priv);
        Node {
            private: my_priv,
            public,
            mlkem_ek,
            mlkem_dk,
            peers,
            relay_servers: Vec::new(),
            relay_health: Default::default(),
            reflexive,
            probe_txid: 0,
            self_is_nat: None,
            nat_override: false,
        }
    }

    /// Build an idle peer with a known pubkey/ek and optional direct endpoint.
    fn peer(public: [u8; 32], ek: Vec<u8>, endpoint: Option<SocketAddr>) -> Peer {
        Peer {
            alias: String::new(),
            pinned: false,
            public,
            mlkem_ek: ek
                .into_boxed_slice()
                .try_into()
                .expect("test ek must be EK_LEN bytes"),
            vip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)),
            vip6: None,
            endpoint,
            rx_index: 0,
            tx_index: 0,
            session: Session::Idle,
            punch: PunchState::Idle,
            punched: false,
            punch_failures: 0,
            relay: false,
            relay_endpoint: None,
            relay_eligible: false,
            direct_upgrade_at: Instant::now() + DIRECT_UPGRADE_BASE,
            direct_upgrade_failures: 0,
        }
    }

    /// Derive (pubkey, ml-kem ek) for a seed private key.
    fn identity(seed: u8) -> ([u8; 32], Vec<u8>) {
        (
            keys::public_key(&[seed; 32]),
            keys::derive_mlkem(&[seed; 32]).0,
        )
    }

    #[test]
    fn start_punch_targets_coordinator_and_enters_connecting() {
        let (target_pub, target_ek) = identity(6);
        let (coord_pub, coord_ek) = identity(5);
        let coord_ep: SocketAddr = "203.0.113.9:7777".parse().unwrap();
        let my_reflexive: SocketAddr = "203.0.113.1:40000".parse().unwrap();

        // peer 0 = target (no endpoint), peer 1 = coordinator (has endpoint)
        let mut n = node(
            [1u8; 32],
            vec![
                peer(target_pub, target_ek, None),
                peer(coord_pub, coord_ek, Some(coord_ep)),
            ],
            Some(my_reflexive),
        );
        let (ep, dg) = n.start_punch(0).expect("punch starts");
        assert_eq!(ep, coord_ep, "connect is relayed via the coordinator");
        assert_eq!(dg[0], Kind::PunchConnect as u8);
        assert!(matches!(n.peers[0].punch, PunchState::Connecting { .. }));
        let (origin, tgt, refl) = decode_connect(&dg[1..]).expect("decode body");
        assert_eq!(origin, n.public);
        assert_eq!(tgt, target_pub);
        assert_eq!(refl, my_reflexive);

        // with no reflexive endpoint discovered yet there is nothing to punch
        let (t2, e2) = identity(6);
        let (c2, ce2) = identity(5);
        let mut n2 = node(
            [1u8; 32],
            vec![peer(t2, e2, None), peer(c2, ce2, Some(coord_ep))],
            None,
        );
        assert!(n2.start_punch(0).is_none());
    }

    #[test]
    fn relay_data_endpoint_prefers_relay_server_over_eligible_peer() {
        let (peer_pub, peer_ek) = identity(6);
        let (relay_peer_pub, relay_peer_ek) = identity(5);
        let eligible_ep: SocketAddr = "203.0.113.9:65432".parse().unwrap();
        let relay_server: SocketAddr = "198.51.100.1:65433".parse().unwrap();

        // peer 0 = a peer with no path; peer 1 = a relay_eligible gnet peer.
        let mut relay_peer = peer(relay_peer_pub, relay_peer_ek, Some(eligible_ep));
        relay_peer.relay_eligible = true;
        let mut n = node(
            [1u8; 32],
            vec![peer(peer_pub, peer_ek, None), relay_peer],
            None,
        );

        // no relay server configured → falls back to the relay_eligible peer.
        assert_eq!(n.relay_data_endpoint(0), Some(eligible_ep));

        // a configured relay server wins for the data plane …
        n.relay_servers = vec![relay_server];
        assert_eq!(n.relay_data_endpoint(0), Some(relay_server));

        // … but punch signaling still routes through the gnet peer, because a
        // relay server only forwards RelayData and drops PunchConnect/Sync.
        assert_eq!(n.coordinator_endpoint(0), Some(eligible_ep));
    }

    #[test]
    fn relay_data_endpoint_routes_around_dead_relay() {
        let (peer_pub, peer_ek) = identity(6);
        let r1: SocketAddr = "198.51.100.1:65433".parse().unwrap();
        let r2: SocketAddr = "198.51.100.2:65433".parse().unwrap();
        let mut n = node([1u8; 32], vec![peer(peer_pub, peer_ek, None)], None);
        n.relay_servers = vec![r1, r2];

        // cold start: no relay has echoed yet → fall back to first() so we
        // still attempt a relay rather than stalling.
        assert_eq!(n.relay_data_endpoint(0), Some(r1));

        // only r2 echoed our keepalive (r1 is dead/silent) → route around r1.
        n.note_relay_pong(r2);
        assert_eq!(n.relay_data_endpoint(0), Some(r2), "dead r1 is routed around");

        // both healthy → stable preference for the first (no churn).
        n.note_relay_pong(r1);
        assert_eq!(n.relay_data_endpoint(0), Some(r1), "prefer first when both live");
    }

    #[test]
    fn relay_data_endpoint_none_without_relay_or_peer() {
        let (peer_pub, peer_ek) = identity(6);
        // single peer, no endpoint, no relay server → nowhere to relay through.
        let n = node([1u8; 32], vec![peer(peer_pub, peer_ek, None)], None);
        assert_eq!(n.relay_data_endpoint(0), None);
    }

    #[test]
    fn coordinator_relays_connect_and_sync_to_target() {
        let (a_pub, a_ek) = identity(1);
        let (b_pub, b_ek) = identity(2);
        let a_ep: SocketAddr = "203.0.113.1:1111".parse().unwrap();
        let b_ep: SocketAddr = "203.0.113.2:2222".parse().unwrap();

        // coordinator C reaches both A and B directly
        let mut c = node(
            [9u8; 32],
            vec![peer(a_pub, a_ek, Some(a_ep)), peer(b_pub, b_ek, Some(b_ep))],
            None,
        );
        // A's connect to B → forwarded to B's endpoint, body unchanged
        let a_refl: SocketAddr = "203.0.113.1:40000".parse().unwrap();
        let out = c.handle_connect(&encode_connect(&a_pub, &b_pub, a_refl), a_ep);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, b_ep, "connect relayed to B");
        assert_eq!(out[0].1[0], Kind::PunchConnect as u8);
        assert_eq!(decode_connect(&out[0].1[1..]).unwrap().2, a_refl);
        // a sync addressed to B is relayed the same way
        let sout = c.handle_sync(&encode_sync(&a_pub, &b_pub));
        assert_eq!(sout.len(), 1);
        assert_eq!(sout[0].0, b_ep);
        assert_eq!(sout[0].1[0], Kind::PunchSync as u8);
    }

    #[test]
    fn target_replies_then_dials_on_sync() {
        let (origin_pub, origin_ek) = identity(3);
        let (coord_pub, coord_ek) = identity(5);
        let coord_ep: SocketAddr = "203.0.113.9:7777".parse().unwrap();
        let origin_refl: SocketAddr = "203.0.113.3:33333".parse().unwrap();
        let my_refl: SocketAddr = "203.0.113.4:44444".parse().unwrap();

        // we are the target; peer 0 = origin (no endpoint), peer 1 = coordinator
        let mut t = node(
            [4u8; 32],
            vec![
                peer(origin_pub, origin_ek, None),
                peer(coord_pub, coord_ek, Some(coord_ep)),
            ],
            Some(my_refl),
        );
        // origin's connect arrives (relayed via coordinator → from = coord_ep)
        let out = t.handle_connect(
            &encode_connect(&origin_pub, &t.public, origin_refl),
            coord_ep,
        );
        assert_eq!(out.len(), 1, "we reply with our own reflexive");
        assert_eq!(out[0].0, coord_ep, "reply heads back via the coordinator");
        let (ro, rt, rrefl) = decode_connect(&out[0].1[1..]).expect("decode reply");
        assert_eq!(ro, t.public);
        assert_eq!(rt, origin_pub);
        assert_eq!(rrefl, my_refl);
        match &t.peers[0].punch {
            PunchState::Awaiting { candidates } => {
                assert_eq!(candidates.len(), 1 + 2 * PUNCH_SEQUENTIAL_RADIUS as usize);
                assert_eq!(candidates[0], origin_refl, "observed candidate first");
            }
            _ => panic!("target must await the sync"),
        }

        // the sync lands → fan-out dial the origin's reflexive endpoint plus
        // ±R sequential candidates. dials[0] is the observed reflexive; the
        // remaining 2·R entries are alternating ±k samples (same dg, distinct
        // dst port — Noise IK msg1 is not bound to its destination).
        let dout = t.handle_sync(&encode_sync(&origin_pub, &t.public));
        let fanout_len = 1 + 2 * PUNCH_SEQUENTIAL_RADIUS as usize;
        assert_eq!(dout.len(), fanout_len);
        assert_eq!(
            dout[0].0, origin_refl,
            "first dial targets the observed reflexive"
        );
        for d in &dout {
            assert_eq!(d.1[0], Kind::HandshakeInit as u8);
            assert_eq!(d.1, dout[0].1, "all candidates share the same msg1 bytes");
        }
        assert!(matches!(t.peers[0].session, Session::Initiating { .. }));
        assert!(matches!(t.peers[0].punch, PunchState::Idle));
        assert_eq!(t.peers[0].endpoint, Some(origin_refl));
    }

    #[test]
    fn next_punch_dial_is_earliest_syncing() {
        use std::time::Duration;
        let ep: SocketAddr = "203.0.113.5:41000".parse().unwrap();
        let (p0, e0) = identity(1);
        let (p1, e1) = identity(2);
        let now = Instant::now();
        let mut n = node(
            [9u8; 32],
            vec![peer(p0, e0, None), peer(p1, e1, None)],
            None,
        );
        assert_eq!(n.next_punch_dial(), None);
        n.peers[0].punch = PunchState::Syncing {
            dial_at: now + Duration::from_millis(50),
            candidates: vec![ep],
        };
        n.peers[1].punch = PunchState::Syncing {
            dial_at: now + Duration::from_millis(20),
            candidates: vec![ep],
        };
        assert_eq!(n.next_punch_dial(), Some(now + Duration::from_millis(20)));
        n.peers[1].punch = PunchState::Idle;
        assert_eq!(n.next_punch_dial(), Some(now + Duration::from_millis(50)));
    }

    #[test]
    fn origin_reply_sends_sync_then_poll_dials() {
        use std::time::Duration;
        let (target_pub, target_ek) = identity(6);
        let (coord_pub, coord_ek) = identity(5);
        let coord_ep: SocketAddr = "203.0.113.9:7777".parse().unwrap();
        let my_refl: SocketAddr = "203.0.113.1:11111".parse().unwrap();
        let target_refl: SocketAddr = "203.0.113.6:60000".parse().unwrap();

        let mut o = node(
            [1u8; 32],
            vec![
                peer(target_pub, target_ek, None),
                peer(coord_pub, coord_ek, Some(coord_ep)),
            ],
            Some(my_refl),
        );
        o.start_punch(0).expect("start as origin");
        // backdate the send so the measured RTT is a real positive value
        if let PunchState::Connecting { sent_at } = &mut o.peers[0].punch {
            *sent_at = Instant::now() - Duration::from_millis(40);
        }
        // the target's reply connect arrives → measure RTT and send the sync
        let out = o.handle_connect(
            &encode_connect(&target_pub, &o.public, target_refl),
            coord_ep,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, coord_ep, "sync is relayed via the coordinator");
        assert_eq!(out[0].1[0], Kind::PunchSync as u8);
        assert!(matches!(o.peers[0].punch, PunchState::Syncing { .. }));

        // not yet due → nothing dialed
        assert!(o.poll_punch_dials().is_empty());
        // force the dial deadline past → poll fan-out dials across the
        // observed target reflexive plus ±R sequential candidate ports.
        if let PunchState::Syncing { dial_at, .. } = &mut o.peers[0].punch {
            *dial_at = Instant::now() - Duration::from_secs(1);
        }
        let dials = o.poll_punch_dials();
        let fanout_len = 1 + 2 * PUNCH_SEQUENTIAL_RADIUS as usize;
        assert_eq!(dials.len(), fanout_len);
        assert_eq!(dials[0].0, target_refl, "first dial is the observed reflexive");
        for d in &dials {
            assert_eq!(d.1[0], Kind::HandshakeInit as u8);
            assert_eq!(d.1, dials[0].1, "all candidates share the same msg1 bytes");
        }
        assert!(matches!(o.peers[0].session, Session::Initiating { .. }));
        assert!(matches!(o.peers[0].punch, PunchState::Idle));
    }

    /// Build a `(Established + relay)` target peer plus a directly-reachable
    /// coordinator. Callers set `direct_upgrade_at` / `punch` directly on
    /// `peers[0]` for the specific scenario under test.
    fn upgrade_fixture(
        target_pub: [u8; 32],
        target_ek: Vec<u8>,
        coord_pub: [u8; 32],
        coord_ek: Vec<u8>,
        coord_ep: SocketAddr,
        my_refl: Option<SocketAddr>,
    ) -> Node {
        let (ini_t, _resp_t) = established_pair();
        let mut target = peer(target_pub, target_ek, None);
        target.session = Session::Established(ini_t);
        target.relay = true;
        target.relay_endpoint = Some(coord_ep);
        let coord = peer(coord_pub, coord_ek, Some(coord_ep));
        node([1u8; 32], vec![target, coord], my_refl)
    }

    #[test]
    fn poll_direct_upgrades_fires_when_relayed_session_is_due() {
        let (target_pub, target_ek) = identity(6);
        let (coord_pub, coord_ek) = identity(5);
        let coord_ep: SocketAddr = "203.0.113.9:7777".parse().unwrap();
        let my_refl: SocketAddr = "203.0.113.1:40000".parse().unwrap();

        let mut n = upgrade_fixture(
            target_pub,
            target_ek,
            coord_pub,
            coord_ek,
            coord_ep,
            Some(my_refl),
        );
        n.peers[0].direct_upgrade_at = Instant::now() - Duration::from_secs(1);

        let before = Instant::now();
        let sends = n.poll_direct_upgrades();
        assert_eq!(sends.len(), 1, "one connect emitted for the due upgrade");
        assert_eq!(sends[0].0, coord_ep, "connect relayed via the coordinator");
        assert_eq!(sends[0].1[0], Kind::PunchConnect as u8);
        assert!(
            matches!(n.peers[0].punch, PunchState::Connecting { .. }),
            "peer now has an in-flight punch"
        );
        // deadline rolled forward by backoff(failures=0) = DIRECT_UPGRADE_BASE
        let advanced = n.peers[0].direct_upgrade_at;
        assert!(
            advanced > before + Duration::from_secs(20),
            "deadline rolled forward by ~30s base backoff"
        );
        assert!(
            advanced < before + Duration::from_secs(35),
            "deadline did not overshoot the base backoff"
        );
    }

    #[test]
    fn poll_direct_upgrades_skips_when_deadline_not_due() {
        let (target_pub, target_ek) = identity(6);
        let (coord_pub, coord_ek) = identity(5);
        let coord_ep: SocketAddr = "203.0.113.9:7777".parse().unwrap();
        let my_refl: SocketAddr = "203.0.113.1:40000".parse().unwrap();

        let mut n = upgrade_fixture(
            target_pub,
            target_ek,
            coord_pub,
            coord_ek,
            coord_ep,
            Some(my_refl),
        );
        n.peers[0].direct_upgrade_at = Instant::now() + Duration::from_secs(60);
        assert!(
            n.poll_direct_upgrades().is_empty(),
            "no upgrade before the deadline"
        );
        assert!(
            matches!(n.peers[0].punch, PunchState::Idle),
            "peer remains idle"
        );
    }

    #[test]
    fn poll_direct_upgrades_skips_when_punch_already_in_flight() {
        let (target_pub, target_ek) = identity(6);
        let (coord_pub, coord_ek) = identity(5);
        let coord_ep: SocketAddr = "203.0.113.9:7777".parse().unwrap();
        let my_refl: SocketAddr = "203.0.113.1:40000".parse().unwrap();

        let mut n = upgrade_fixture(
            target_pub,
            target_ek,
            coord_pub,
            coord_ek,
            coord_ep,
            Some(my_refl),
        );
        n.peers[0].direct_upgrade_at = Instant::now() - Duration::from_secs(1);
        // mimic a punch that another path already started
        n.peers[0].punch = PunchState::Connecting {
            sent_at: Instant::now(),
        };
        let before = n.peers[0].direct_upgrade_at;
        assert!(
            n.poll_direct_upgrades().is_empty(),
            "an in-flight punch is not re-triggered"
        );
        assert_eq!(
            n.peers[0].direct_upgrade_at, before,
            "deadline is not rolled forward when nothing new fired"
        );
    }

    #[test]
    fn poll_direct_upgrades_skips_without_reflexive() {
        let (target_pub, target_ek) = identity(6);
        let (coord_pub, coord_ek) = identity(5);
        let coord_ep: SocketAddr = "203.0.113.9:7777".parse().unwrap();

        let mut n = upgrade_fixture(
            target_pub,
            target_ek,
            coord_pub,
            coord_ek,
            coord_ep,
            None, // no reflexive endpoint discovered yet
        );
        n.peers[0].direct_upgrade_at = Instant::now() - Duration::from_secs(1);
        assert!(
            n.poll_direct_upgrades().is_empty(),
            "no reflexive → cannot encode a connect, so no upgrade attempt"
        );
    }

    #[test]
    fn poll_direct_upgrades_ignores_non_relay_and_unestablished_peers() {
        let (a_pub, a_ek) = identity(6);
        let (b_pub, b_ek) = identity(7);
        let (coord_pub, coord_ek) = identity(5);
        let coord_ep: SocketAddr = "203.0.113.9:7777".parse().unwrap();
        let my_refl: SocketAddr = "203.0.113.1:40000".parse().unwrap();

        // peer A: relay=false (already direct) but session=Established + deadline due
        // → must not be re-punched.
        let (a_t, _) = established_pair();
        let mut direct = peer(a_pub, a_ek, Some(coord_ep));
        direct.session = Session::Established(a_t);
        direct.direct_upgrade_at = Instant::now() - Duration::from_secs(1);

        // peer B: relay=true, deadline due, but session=Idle. We wait for the
        // session to come up over the relay before attempting an upgrade so we
        // do not race a cold-start handshake.
        let mut not_yet = peer(b_pub, b_ek, None);
        not_yet.relay = true;
        not_yet.relay_endpoint = Some(coord_ep);
        not_yet.direct_upgrade_at = Instant::now() - Duration::from_secs(1);

        let mut n = node(
            [1u8; 32],
            vec![
                direct,
                not_yet,
                peer(coord_pub, coord_ek, Some(coord_ep)),
            ],
            Some(my_refl),
        );
        assert!(
            n.poll_direct_upgrades().is_empty(),
            "neither candidate qualifies for an upgrade"
        );
    }

    #[test]
    fn relayed_peer_walks_through_full_upgrade_lifecycle() {
        // Single-Node integration of the direct-upgrade pipeline on the
        // origin side:
        //   Established+relay → poll_direct_upgrades → Connecting
        //   → handle_connect (target reply) → Syncing
        //   → poll_punch_dials → Initiating + endpoint=peer reflexive
        // (Handshake completion + relay clearing on the resulting msg2 is
        // covered by the dedicated complete_initiation tests in
        // node/handshake.rs — keeping it out of this fixture avoids
        // reaching into the HybridInitiator that initiate() captured.)
        let (target_pub, target_ek) = identity(6);
        let (coord_pub, coord_ek) = identity(5);
        let coord_ep: SocketAddr = "127.0.0.1:7777".parse().unwrap();
        let my_refl: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let target_refl: SocketAddr = "127.0.0.1:50000".parse().unwrap();

        let (initial_t, _) = established_pair();
        let mut target = peer(target_pub, target_ek, None);
        target.session = Session::Established(initial_t);
        target.relay = true;
        target.relay_endpoint = Some(coord_ep);
        target.direct_upgrade_failures = 2;
        target.direct_upgrade_at = Instant::now() - Duration::from_secs(1);
        let coord = peer(coord_pub, coord_ek, Some(coord_ep));
        let mut n = node([1u8; 32], vec![target, coord], Some(my_refl));

        // Stage A — the scheduler fires a connect through the coordinator.
        let sends = n.poll_direct_upgrades();
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].0, coord_ep, "connect relayed via coordinator");
        assert_eq!(sends[0].1[0], Kind::PunchConnect as u8);
        assert!(
            matches!(n.peers[0].punch, PunchState::Connecting { .. }),
            "stage A: peer entered Connecting"
        );

        // Stage B — the target replies with its reflexive endpoint, looped
        // back to us via the coordinator. handle_connect on Connecting state
        // measures the RTT and emits the sync to the coordinator. Backdate
        // sent_at so the measured RTT is a positive value.
        if let PunchState::Connecting { sent_at } = &mut n.peers[0].punch {
            *sent_at = Instant::now() - Duration::from_millis(40);
        }
        let reply_out = n.handle_connect(
            &encode_connect(&target_pub, &n.public, target_refl),
            coord_ep,
        );
        assert_eq!(reply_out.len(), 1);
        assert_eq!(reply_out[0].0, coord_ep, "sync relayed to coordinator");
        assert_eq!(reply_out[0].1[0], Kind::PunchSync as u8);
        assert!(
            matches!(n.peers[0].punch, PunchState::Syncing { .. }),
            "stage B: peer transitioned to Syncing"
        );

        // Stage C — force the dial deadline past; poll_punch_dials fan-out
        // dials the handshake init across the observed reflexive plus ±R
        // sequential candidates (symmetric-NAT port prediction).
        if let PunchState::Syncing { dial_at, .. } = &mut n.peers[0].punch {
            *dial_at = Instant::now() - Duration::from_secs(1);
        }
        let dials = n.poll_punch_dials();
        let fanout_len = 1 + 2 * PUNCH_SEQUENTIAL_RADIUS as usize;
        assert_eq!(dials.len(), fanout_len);
        assert_eq!(dials[0].0, target_refl, "first dial is the observed reflexive");
        for d in &dials {
            assert_eq!(d.1[0], Kind::HandshakeInit as u8);
            assert_eq!(d.1, dials[0].1, "all candidates share the same msg1 bytes");
        }
        assert!(
            matches!(n.peers[0].session, Session::Initiating { .. }),
            "stage C: handshake initiation in flight"
        );
        assert!(
            matches!(n.peers[0].punch, PunchState::Idle),
            "stage C: punch state cleared after dial",
        );
        assert_eq!(
            n.peers[0].endpoint,
            Some(target_refl),
            "endpoint repointed at the peer's direct reflexive address"
        );
        // The dial is the moment we commit to the direct path: relay state
        // drops here so the msg1 leaves via route_dg's direct branch (NOT
        // wrapped in a relay envelope, which would defeat the whole point
        // of opening a NAT mapping with that outbound packet). Tests in
        // handshake.rs cover the *handshake-side* relay-clear via
        // complete_initiation; this assertion is about the dial-side
        // commitment.
        assert!(
            !n.peers[0].relay,
            "stage C: dial committed to direct path — relay flag dropped"
        );
        assert!(
            n.peers[0].relay_endpoint.is_none(),
            "relay endpoint released alongside the flag"
        );
        assert_eq!(
            n.peers[0].direct_upgrade_failures, 0,
            "dial commits to direct path — upgrade backoff reset"
        );
    }

    #[test]
    fn next_direct_upgrade_at_backs_off_then_caps() {
        // f=0 → ~base, f=1 → ~base * 1.5, f=2 → ~base * 2.25, etc., until cap.
        let before = Instant::now();
        let at_0 = next_direct_upgrade_at(0);
        let at_1 = next_direct_upgrade_at(1);
        let at_2 = next_direct_upgrade_at(2);
        let at_capped = next_direct_upgrade_at(50);

        let d_0 = at_0.duration_since(before);
        let d_1 = at_1.duration_since(before);
        let d_2 = at_2.duration_since(before);
        let d_capped = at_capped.duration_since(before);

        assert!(d_0 >= DIRECT_UPGRADE_BASE);
        assert!(d_0 < DIRECT_UPGRADE_BASE + Duration::from_millis(100));
        assert!(d_1 >= DIRECT_UPGRADE_BASE * 3 / 2);
        assert!(d_2 >= DIRECT_UPGRADE_BASE * 9 / 4);
        // After many failures, deadline saturates at the cap.
        assert!(d_capped >= DIRECT_UPGRADE_MAX);
        assert!(d_capped < DIRECT_UPGRADE_MAX + Duration::from_millis(100));
    }
}
