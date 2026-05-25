//! Node-side hole-punch wiring: drives the `gnet-punch` rendezvous protocol
//! over the live peer table. Relays connect/sync by destination key, starts a
//! punch when a peer has no direct path, measures the coordinator RTT, and
//! turns a due dial into a normal handshake. The zero-I/O codec + state machine
//! live in the [`gnet_punch`] crate; this module owns only the `Node` glue.

use std::net::SocketAddr;
use std::time::Instant;

use gnet_punch::{PunchState, decode_connect, decode_sync, encode_connect, encode_sync};
use gnet_wire::{self as wire, Kind};

use super::types::Node;

impl Node {
    /// Begin a synchronized punch to peer `i` as the origin: relay a
    /// PunchConnect carrying our reflexive endpoint through a coordinator (any
    /// other peer we already reach directly) and enter `Connecting`. Returns
    /// the datagram to send with the lock released, or `None` if we have no
    /// reflexive endpoint yet or no coordinator to relay through.
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

    /// A coordinator endpoint to relay rendezvous through: any peer other than
    /// `exclude` that we already reach directly (has a known endpoint).
    pub(super) fn coordinator_endpoint(&self, exclude: usize) -> Option<SocketAddr> {
        self.peers
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != exclude)
            .find_map(|(_, p)| p.endpoint)
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
            if self.peers[i].punch.on_reply(reflexive, Instant::now())
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
            endpoint: reflexive,
        };
        let reply = encode_connect(&self.public, &origin, my_reflexive);
        vec![(from, wire::frame(Kind::PunchConnect, &reply))]
    }

    /// Handle an inbound PunchSync. Relay it if we are the coordinator;
    /// otherwise we are the target and dial the origin immediately (its first
    /// packet is already on its way). Returns the handshake init, if any.
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
        let PunchState::Awaiting { endpoint } = &self.peers[i].punch else {
            return Vec::new();
        };
        let endpoint = *endpoint;
        self.dial(i, endpoint).into_iter().collect()
    }

    /// Origin-side delayed dials: dial any peer whose `Syncing` deadline
    /// (reply + RTT/2) has arrived. Called from the dial poller. Returns
    /// handshake inits to send with the lock released.
    pub(super) fn poll_punch_dials(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        let now = Instant::now();
        let due: Vec<(usize, SocketAddr)> = self
            .peers
            .iter()
            .enumerate()
            .filter_map(|(i, p)| p.punch.due_dial(now).map(|ep| (i, ep)))
            .collect();
        due.into_iter()
            .filter_map(|(i, ep)| self.dial(i, ep))
            .collect()
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

    /// Dial a peer once rendezvous has aligned the timing: point the peer at
    /// `endpoint`, clear its punch state, and start the normal handshake (which
    /// the glare logic + jittered retransmit carry to completion). Marks the
    /// peer `punched` so its endpoint is known to be punch-derived: a run of
    /// give-ups on it accrues toward relay fallback. Returns the init datagram,
    /// or `None` if it cannot be built.
    fn dial(&mut self, i: usize, endpoint: SocketAddr) -> Option<(SocketAddr, Vec<u8>)> {
        self.peers[i].endpoint = Some(endpoint);
        self.peers[i].punch = PunchState::Idle;
        self.peers[i].punched = true;
        self.initiate(i)
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
    use super::super::types::{Peer, Session};
    use super::*;
    use crate::keys;
    use std::net::{IpAddr, Ipv4Addr};

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
            reflexive,
            probe_txid: 0,
        }
    }

    /// Build an idle peer with a known pubkey/ek and optional direct endpoint.
    fn peer(public: [u8; 32], ek: Vec<u8>, endpoint: Option<SocketAddr>) -> Peer {
        Peer {
            public,
            mlkem_ek: ek
                .into_boxed_slice()
                .try_into()
                .expect("test ek must be EK_LEN bytes"),
            vip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)),
            endpoint,
            rx_index: 0,
            tx_index: 0,
            session: Session::Idle,
            punch: PunchState::Idle,
            punched: false,
            punch_failures: 0,
            relay: false,
            relay_endpoint: None,
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
            PunchState::Awaiting { endpoint } => assert_eq!(*endpoint, origin_refl),
            _ => panic!("target must await the sync"),
        }

        // the sync lands → dial the origin's reflexive endpoint at once
        let dout = t.handle_sync(&encode_sync(&origin_pub, &t.public));
        assert_eq!(dout.len(), 1);
        assert_eq!(
            dout[0].0, origin_refl,
            "dial the origin's reflexive endpoint"
        );
        assert_eq!(dout[0].1[0], Kind::HandshakeInit as u8);
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
            endpoint: ep,
        };
        n.peers[1].punch = PunchState::Syncing {
            dial_at: now + Duration::from_millis(20),
            endpoint: ep,
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
        // force the dial deadline past → poll dials the target's reflexive ep
        if let PunchState::Syncing { dial_at, .. } = &mut o.peers[0].punch {
            *dial_at = Instant::now() - Duration::from_secs(1);
        }
        let dials = o.poll_punch_dials();
        assert_eq!(dials.len(), 1);
        assert_eq!(dials[0].0, target_refl);
        assert_eq!(dials[0].1[0], Kind::HandshakeInit as u8);
        assert!(matches!(o.peers[0].session, Session::Initiating { .. }));
        assert!(matches!(o.peers[0].punch, PunchState::Idle));
    }
}
