//! Inbound handshake handling: respond to a peer's init, and complete our own
//! in-flight initiation. The session indices ride in the Noise payloads.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};

use gnet_noise::hybrid::HybridResponder;

use super::types::{Node, Peer, Session, route_dg};
use gnet_wire::{self as wire, Kind};

/// Read a 4-byte little-endian session index from a handshake payload.
fn index_from_payload(payload: &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = payload.get(..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// Handshake-glare tie-break: when both peers init each other at once, the side
/// whose static key sorts higher keeps initiating; the lower-key side yields
/// and responds. `my > peer` is deterministic and antisymmetric, so the two
/// sides always pick opposite roles and converge on a single shared session.
fn initiator_wins(my: &[u8; 32], peer: &[u8; 32]) -> bool {
    my > peer
}

/// Respond to a handshake init: match the initiator's static key to a peer,
/// reply with message 2, and store the established session + learned endpoint.
pub(super) fn handle_init(
    node: &Arc<Mutex<Node>>,
    socket: &UdpSocket,
    body: &[u8],
    from: SocketAddr,
    via_relay: bool,
) -> io::Result<()> {
    let mut g = node.lock().expect("node mutex");
    let priv_k = g.private;
    let mut resp = HybridResponder::new(priv_k, &g.mlkem_ek, &g.mlkem_dk, gnet_rand::random_32());
    // msg1 payload carries the index the initiator wants stamped on packets we
    // send it; drop the handshake if it is missing.
    let Some(peer_index) = resp
        .read_message_1(body)
        .as_deref()
        .and_then(index_from_payload)
    else {
        return Ok(());
    };
    let Some(pk) = resp.peer_static() else {
        return Ok(());
    };
    let Some(i) = g.by_pubkey(&pk) else {
        return Ok(()); // unknown peer
    };
    // handshake glare: if we are mid-initiation to this same peer and our static
    // key sorts higher, ignore the peer's concurrent init. Without this, both
    // sides would overwrite their `Initiating` session with a responder session
    // (and `complete_initiation` would then skip the reply they each sent),
    // leaving two mismatched sessions and total transport-decrypt failure. By
    // having the higher-key side keep initiating and the lower-key side respond,
    // both converge on the single session rooted at the higher side's init.
    if matches!(g.peers[i].session, Session::Initiating { .. }) && initiator_wins(&g.public, &pk) {
        return Ok(());
    }
    // assign our own index and return it in msg2 so the initiator can stamp it.
    let my_rx = gnet_rand::random_u32();
    let Some((msg2, transport)) = resp.write_message_2(&my_rx.to_le_bytes()) else {
        return Ok(());
    };
    g.peers[i].tx_index = peer_index;
    g.peers[i].rx_index = my_rx;
    g.peers[i].session = Session::Established(transport);
    if !via_relay {
        // direct: learn the peer's real source address. For a relayed init the
        // source is the relay, not the peer — leave the endpoint untouched and
        // let route_dg send the reply back through the relay (set reciprocally
        // by the RelayData dispatch before this re-dispatch).
        g.peers[i].endpoint = Some(from);
        // A direct-path handshake completing means the direct-upgrade attempt
        // (or the cold-start direct path) succeeded — drop the relay flag and
        // reset the upgrade failure counter so a future re-trip restarts the
        // backoff from the base interval rather than the cap.
        g.peers[i].relay = false;
        g.peers[i].relay_endpoint = None;
        g.peers[i].direct_upgrade_failures = 0;
    }
    g.peers[i].punch_failures = 0; // handshake succeeded — clear punch-failure count
    let routed = route_dg(
        &g.public,
        &g.peers[i],
        wire::frame(Kind::HandshakeResp, &msg2),
    );
    drop(g);
    if let Some((ep, bytes)) = routed {
        socket.send_to(&bytes, ep)?;
    }
    Ok(())
}

/// Complete an in-flight initiation with the responder's message 2.
/// `from` is the wire source address of the msg2; `via_relay` mirrors
/// `handle_init`: when the msg2 reached us through a relay envelope, the
/// relay path is still load-bearing and any direct-upgrade state must stay
/// intact; when it arrived direct, the relay flag is cleared.
///
/// On a direct msg2 from a `punched` peer whose `endpoint` does not match
/// `from`, the endpoint is corrected to `from`. This is the symmetric-NAT
/// port-prediction hit-detection step: `dial_fanout` set `endpoint` to the
/// observed-port guess and emitted msg1 to every candidate; the candidate
/// the peer's NAT actually allocated for us is the one whose msg2 arrives,
/// and its real source port is exactly `from`.
pub(super) fn complete_initiation(peer: &mut Peer, body: &[u8], from: SocketAddr, via_relay: bool) {
    if !matches!(peer.session, Session::Initiating { .. }) {
        return;
    }
    if let Session::Initiating { ini, .. } = std::mem::replace(&mut peer.session, Session::Idle)
        && let Some((transport, payload)) = ini.read_message_2(body)
        && let Some(peer_index) = index_from_payload(&payload)
    {
        // our rx_index was set when we initiated; msg2 carries the peer's.
        peer.tx_index = peer_index;
        peer.session = Session::Established(transport);
        peer.punch_failures = 0; // handshake succeeded — clear punch-failure count
        if !via_relay {
            // mirror handle_init: the direct path is now live, so the relay
            // hop is no longer needed and any pending upgrade backoff resets.
            peer.relay = false;
            peer.relay_endpoint = None;
            peer.direct_upgrade_failures = 0;
            // symmetric-NAT fan-out hit detection: if the punched peer's
            // msg2 arrived from a candidate other than the observed-port
            // guess we stored, correct the endpoint to the real one before
            // any transport packets go out (they would otherwise re-target
            // the wrong NAT mapping and never land).
            if peer.punched && peer.endpoint != Some(from) {
                peer.endpoint = Some(from);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MTU_BUF;
    use crate::keys;
    use gnet_noise::hybrid::{HybridInitiator, HybridResponder};
    use gnet_punch::PunchState;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    #[test]
    fn index_from_payload_reads_le_u32() {
        assert_eq!(
            index_from_payload(&[0x04, 0x03, 0x02, 0x01]),
            Some(0x0102_0304)
        );
        // extra bytes are ignored (only the first four matter)
        assert_eq!(index_from_payload(&[1, 0, 0, 0, 9, 9]), Some(1));
        // too short → none
        assert_eq!(index_from_payload(&[1, 2, 3]), None);
        assert_eq!(index_from_payload(&[]), None);
    }

    #[test]
    fn initiator_wins_is_deterministic_and_antisymmetric() {
        let lo = [1u8; 32];
        let hi = [2u8; 32];
        assert!(initiator_wins(&hi, &lo));
        assert!(!initiator_wins(&lo, &hi));
        // distinct peers never tie; a tie would just mean neither yields
        // (both respond) — harmless, only a wasted round trip.
        assert!(!initiator_wins(&lo, &lo));
    }

    /// Build a one-peer node from our private key and the peer's identity.
    fn node_with_peer(my_priv: [u8; 32], peer_pub: [u8; 32], peer_ek: Vec<u8>) -> Arc<Mutex<Node>> {
        let (mlkem_ek, mlkem_dk) = keys::derive_mlkem(&my_priv);
        Arc::new(Mutex::new(Node {
            private: my_priv,
            public: keys::public_key(&my_priv),
            mlkem_ek,
            mlkem_dk,
            peers: vec![Peer {
                alias: String::new(),
                public: peer_pub,
                mlkem_ek: peer_ek
                    .into_boxed_slice()
                    .try_into()
                    .expect("test ek must be EK_LEN bytes"),
                vip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                vip6: None,
                endpoint: None,
                rx_index: 0,
                tx_index: 0,
                session: Session::Idle,
                punch: PunchState::Idle,
                punched: false,
                punch_failures: 0,
                relay: false,
                relay_endpoint: None,
                relay_eligible: false,
                direct_upgrade_at: Instant::now() + super::super::punch::DIRECT_UPGRADE_BASE,
                direct_upgrade_failures: 0,
            }],
            reflexive: None,
            probe_txid: 0,
            self_is_nat: None,
            nat_override: false,
        }))
    }

    /// Mirror the pump's initiation step: craft msg1, stash the `Initiating`
    /// session + our rx index, and return msg1 unframed (as `handle_init`
    /// receives it once the wire header has been stripped).
    fn start_init(
        node: &Arc<Mutex<Node>>,
        my_priv: [u8; 32],
        peer_pub: [u8; 32],
        peer_ek: &[u8],
        rx: u32,
    ) -> Vec<u8> {
        let mut ini = HybridInitiator::new(
            my_priv,
            peer_pub,
            peer_ek,
            gnet_rand::random_32(),
            gnet_rand::random_32(),
        );
        let msg1 = ini.write_message_1(&rx.to_le_bytes());
        let mut g = node.lock().expect("node mutex");
        g.peers[0].rx_index = rx;
        let now = Instant::now();
        g.peers[0].session = Session::Initiating {
            ini: Box::new(ini),
            started: now,
            retry_at: now,
        };
        msg1
    }

    #[test]
    fn concurrent_init_converges_to_one_session() {
        // hole punching requires BOTH peers to init at once (each init opens
        // that side's NAT mapping). Drive that bidirectional init through the
        // real handshake code and assert the two sides end up on ONE matching
        // session that can carry transport both ways. Without glare resolution
        // each side overwrites its Initiating session with a responder session
        // and the roundtrip at the end fails to decrypt.
        let pa = [7u8; 32];
        let pb = [9u8; 32];
        let pub_a = keys::public_key(&pa);
        let pub_b = keys::public_key(&pb);
        // winner = higher static key (keeps its initiator session); the other
        // yields and responds. Derive roles from the actual key ordering.
        let (win_priv, lose_priv) = if pub_a > pub_b { (pa, pb) } else { (pb, pa) };
        let win_pub = keys::public_key(&win_priv);
        let lose_pub = keys::public_key(&lose_priv);
        let (win_ek, _) = keys::derive_mlkem(&win_priv);
        let (lose_ek, _) = keys::derive_mlkem(&lose_priv);

        let win = node_with_peer(win_priv, lose_pub, lose_ek.clone());
        let lose = node_with_peer(lose_priv, win_pub, win_ek.clone());

        // real loopback sockets so handle_init can send msg2 and we can read it
        let win_sock = UdpSocket::bind("127.0.0.1:0").expect("bind win");
        let lose_sock = UdpSocket::bind("127.0.0.1:0").expect("bind lose");
        win_sock
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let win_addr = win_sock.local_addr().unwrap();
        let lose_addr = lose_sock.local_addr().unwrap();

        // both sides initiate simultaneously
        let msg1_win = start_init(&win, win_priv, lose_pub, &lose_ek, 0xA1A1_A1A1);
        let msg1_lose = start_init(&lose, lose_priv, win_pub, &win_ek, 0xB2B2_B2B2);

        // each receives the other's init
        handle_init(&win, &win_sock, &msg1_lose, lose_addr, false).unwrap();
        handle_init(&lose, &lose_sock, &msg1_win, win_addr, false).unwrap();

        // glare: the winner yielded (still Initiating, sent nothing); the loser
        // responded and sent msg2 to the winner. Deliver it and complete.
        let mut buf = [0u8; MTU_BUF];
        let (n, _) = win_sock.recv_from(&mut buf).expect("winner receives msg2");
        let (kind, _) = wire::parse(&buf[..n]).expect("parse msg2");
        assert!(matches!(kind, Kind::HandshakeResp));
        {
            let mut g = win.lock().unwrap();
            complete_initiation(&mut g.peers[0], &buf[wire::HEADER..n], lose_addr, false);
        }

        // both ends established; the winner's initiator session and the loser's
        // responder session are two halves of the SAME handshake.
        let mut wg = win.lock().unwrap();
        let mut lg = lose.lock().unwrap();
        let (Session::Established(wt), Session::Established(lt)) =
            (&mut wg.peers[0].session, &mut lg.peers[0].session)
        else {
            panic!("both sides must be established after glare resolution");
        };

        // winner → loser: encrypt with the winner's send cipher, decrypt with
        // the loser's recv cipher. A mismatched session (the un-fixed glare
        // bug) would fail to decrypt here.
        let plain = b"punched through double NAT";
        let mut pkt = [0u8; 128];
        pkt[..plain.len()].copy_from_slice(plain);
        let ctr = wt.send_counter();
        let clen = wt.send.encrypt_in_place(&[], &mut pkt, plain.len());
        let got = lt
            .recv_at(ctr, &[], &mut pkt, clen)
            .expect("loser decrypts the winner's transport packet");
        assert_eq!(&pkt[..got], plain);
    }

    /// Make `node`'s sole peer look like one currently routed via relay, so
    /// the clear-relay assertions in the handshake tests have something to
    /// clear: relay flag set, a relay endpoint pinned, and a non-zero
    /// direct_upgrade_failures count we can watch for reset.
    fn mark_peer_relayed(node: &Arc<Mutex<Node>>, relay_ep: SocketAddr, failures: u32) {
        let mut g = node.lock().unwrap();
        g.peers[0].relay = true;
        g.peers[0].relay_endpoint = Some(relay_ep);
        g.peers[0].direct_upgrade_failures = failures;
    }

    #[test]
    fn handle_init_clears_relay_state_on_direct_path() {
        // We are the responder; a peer currently routed via relay sends us a
        // handshake init through the direct path (its punch succeeded). The
        // direct-path init should swing the peer back to a direct route:
        // relay flag cleared, relay endpoint cleared, upgrade failures reset.
        let my_priv = [7u8; 32];
        let peer_priv = [8u8; 32];
        let my_pub = keys::public_key(&my_priv);
        let peer_pub = keys::public_key(&peer_priv);
        let (my_ek, _) = keys::derive_mlkem(&my_priv);
        let (peer_ek, _) = keys::derive_mlkem(&peer_priv);

        let node = node_with_peer(my_priv, peer_pub, peer_ek);
        let relay_ep: SocketAddr = "203.0.113.9:7777".parse().unwrap();
        mark_peer_relayed(&node, relay_ep, 3);

        // peer initiates a direct handshake to us
        let mut ini = HybridInitiator::new(
            peer_priv,
            my_pub,
            &my_ek,
            gnet_rand::random_32(),
            gnet_rand::random_32(),
        );
        let msg1 = ini.write_message_1(&0xCAFE_BABE_u32.to_le_bytes());

        let my_sock = UdpSocket::bind("127.0.0.1:0").expect("bind responder socket");
        let peer_sock = UdpSocket::bind("127.0.0.1:0").expect("bind peer socket (drain msg2)");
        let peer_addr = peer_sock.local_addr().unwrap();

        handle_init(&node, &my_sock, &msg1, peer_addr, false /* direct */).unwrap();

        let g = node.lock().unwrap();
        assert!(
            matches!(g.peers[0].session, Session::Established(_)),
            "responder session established"
        );
        assert!(!g.peers[0].relay, "relay flag dropped");
        assert!(g.peers[0].relay_endpoint.is_none(), "relay endpoint cleared");
        assert_eq!(
            g.peers[0].direct_upgrade_failures, 0,
            "upgrade failure counter reset"
        );
        assert_eq!(
            g.peers[0].endpoint,
            Some(peer_addr),
            "learned the peer's real endpoint",
        );
    }

    #[test]
    fn handle_init_preserves_relay_state_on_relayed_path() {
        // Same setup, but the init reached us through a relay envelope.
        // The relay route is still load-bearing — the upgrade has NOT
        // succeeded, so the relay flag, relay endpoint, and upgrade failure
        // counter must all stay intact.
        let my_priv = [7u8; 32];
        let peer_priv = [8u8; 32];
        let my_pub = keys::public_key(&my_priv);
        let peer_pub = keys::public_key(&peer_priv);
        let (my_ek, _) = keys::derive_mlkem(&my_priv);
        let (peer_ek, _) = keys::derive_mlkem(&peer_priv);

        let node = node_with_peer(my_priv, peer_pub, peer_ek);
        // bind the relay socket to localhost so the msg2 send_to that
        // route_dg triggers actually reaches a listening port — using a
        // docs-net address (203.0.113.x) would make send_to error out on
        // hosts without a default route to that net.
        let relay_sock = UdpSocket::bind("127.0.0.1:0").expect("bind relay socket");
        let relay_ep = relay_sock.local_addr().unwrap();
        mark_peer_relayed(&node, relay_ep, 3);

        let mut ini = HybridInitiator::new(
            peer_priv,
            my_pub,
            &my_ek,
            gnet_rand::random_32(),
            gnet_rand::random_32(),
        );
        let msg1 = ini.write_message_1(&0xCAFE_BABE_u32.to_le_bytes());

        let my_sock = UdpSocket::bind("127.0.0.1:0").expect("bind responder socket");

        handle_init(&node, &my_sock, &msg1, relay_ep, true /* via_relay */).unwrap();

        let g = node.lock().unwrap();
        assert!(matches!(g.peers[0].session, Session::Established(_)));
        assert!(g.peers[0].relay, "relay flag preserved on relayed handshake");
        assert_eq!(g.peers[0].relay_endpoint, Some(relay_ep));
        assert_eq!(
            g.peers[0].direct_upgrade_failures, 3,
            "upgrade failure counter untouched"
        );
    }

    #[test]
    fn complete_initiation_clears_relay_state_on_direct_path() {
        // We initiated through the relay path; the peer's msg2 reaches us
        // back through the direct path (its hole-punch reply landed). The
        // direct path is now alive — clear relay state and reset upgrade
        // backoff so future trips start fresh.
        let my_priv = [7u8; 32];
        let peer_priv = [8u8; 32];
        let peer_pub = keys::public_key(&peer_priv);
        let (peer_ek, peer_dk) = keys::derive_mlkem(&peer_priv);

        let node = node_with_peer(my_priv, peer_pub, peer_ek.clone());
        let relay_ep: SocketAddr = "203.0.113.9:7777".parse().unwrap();
        mark_peer_relayed(&node, relay_ep, 4);

        // we initiate; capture msg1 the way the pump would
        let msg1 = start_init(&node, my_priv, peer_pub, &peer_ek, 0xC0FF_EE00);
        // peer responds — build msg2 with their state machine
        let mut resp =
            HybridResponder::new(peer_priv, &peer_ek, &peer_dk, gnet_rand::random_32());
        resp.read_message_1(&msg1).expect("peer reads msg1");
        let peer_rx = 0xDEAD_BEEF_u32;
        let (msg2, _resp_t) = resp
            .write_message_2(&peer_rx.to_le_bytes())
            .expect("peer writes msg2");

        let from: SocketAddr = "203.0.113.42:50000".parse().unwrap();
        {
            let mut g = node.lock().unwrap();
            complete_initiation(&mut g.peers[0], &msg2, from, false /* direct */);
        }

        let g = node.lock().unwrap();
        assert!(matches!(g.peers[0].session, Session::Established(_)));
        assert!(!g.peers[0].relay, "relay flag dropped");
        assert!(g.peers[0].relay_endpoint.is_none(), "relay endpoint cleared");
        assert_eq!(
            g.peers[0].direct_upgrade_failures, 0,
            "upgrade failure counter reset"
        );
        assert_eq!(g.peers[0].tx_index, peer_rx, "tx_index taken from msg2");
    }

    #[test]
    fn complete_initiation_preserves_relay_state_on_relayed_path() {
        // Same setup, but msg2 arrived through the relay envelope: the
        // direct path is still not proven, so the relay state and the
        // upgrade backoff must stay intact for the next scheduled attempt.
        let my_priv = [7u8; 32];
        let peer_priv = [8u8; 32];
        let peer_pub = keys::public_key(&peer_priv);
        let (peer_ek, peer_dk) = keys::derive_mlkem(&peer_priv);

        let node = node_with_peer(my_priv, peer_pub, peer_ek.clone());
        let relay_ep: SocketAddr = "203.0.113.9:7777".parse().unwrap();
        mark_peer_relayed(&node, relay_ep, 4);

        let msg1 = start_init(&node, my_priv, peer_pub, &peer_ek, 0xC0FF_EE00);
        let mut resp =
            HybridResponder::new(peer_priv, &peer_ek, &peer_dk, gnet_rand::random_32());
        resp.read_message_1(&msg1).expect("peer reads msg1");
        let (msg2, _resp_t) = resp
            .write_message_2(&0u32.to_le_bytes())
            .expect("peer writes msg2");

        let from: SocketAddr = "203.0.113.42:50000".parse().unwrap();
        {
            let mut g = node.lock().unwrap();
            complete_initiation(&mut g.peers[0], &msg2, from, true /* via_relay */);
        }

        let g = node.lock().unwrap();
        assert!(matches!(g.peers[0].session, Session::Established(_)));
        assert!(g.peers[0].relay, "relay flag preserved");
        assert_eq!(g.peers[0].relay_endpoint, Some(relay_ep));
        assert_eq!(
            g.peers[0].direct_upgrade_failures, 4,
            "upgrade failure counter untouched"
        );
    }

    /// Symmetric-NAT port-prediction hit detection: `dial_fanout` set the
    /// peer's endpoint to the observed-port guess and emitted msg1 to every
    /// candidate; the candidate that the peer's NAT actually allocated for us
    /// is the one whose msg2 arrives, with its real source port in `from`. On
    /// a direct msg2 from a `punched` peer whose `endpoint` disagrees with
    /// `from`, `complete_initiation` corrects the endpoint so subsequent
    /// transport packets target the live NAT mapping rather than the
    /// observed-port guess.
    #[test]
    fn complete_initiation_corrects_endpoint_for_punched_fan_out_hit() {
        let my_priv = [7u8; 32];
        let peer_priv = [8u8; 32];
        let peer_pub = keys::public_key(&peer_priv);
        let (peer_ek, peer_dk) = keys::derive_mlkem(&peer_priv);

        let node = node_with_peer(my_priv, peer_pub, peer_ek.clone());

        // mimic `dial_fanout`: set the observed-port guess as endpoint and
        // mark the peer `punched`. The msg1 the pump would have emitted is
        // captured here for the responder to consume.
        let observed: SocketAddr = "203.0.113.4:60000".parse().unwrap();
        {
            let mut g = node.lock().unwrap();
            g.peers[0].endpoint = Some(observed);
            g.peers[0].punched = true;
        }
        let msg1 = start_init(&node, my_priv, peer_pub, &peer_ek, 0x1234_5678);

        // peer's NAT actually allocated a *different* port — the candidate
        // that landed is `actual_hit`, not `observed`.
        let actual_hit: SocketAddr = "203.0.113.4:60017".parse().unwrap();
        let mut resp =
            HybridResponder::new(peer_priv, &peer_ek, &peer_dk, gnet_rand::random_32());
        resp.read_message_1(&msg1).expect("peer reads msg1");
        let (msg2, _resp_t) = resp
            .write_message_2(&0u32.to_le_bytes())
            .expect("peer writes msg2");

        {
            let mut g = node.lock().unwrap();
            complete_initiation(&mut g.peers[0], &msg2, actual_hit, false /* direct */);
        }

        let g = node.lock().unwrap();
        assert!(matches!(g.peers[0].session, Session::Established(_)));
        assert_eq!(
            g.peers[0].endpoint,
            Some(actual_hit),
            "endpoint corrected from observed-port guess to the hit candidate"
        );
    }

    /// Mirror of the hit-detection test for the non-punched direct path:
    /// `complete_initiation` must NOT mutate the endpoint when `peer.punched`
    /// is false (regular direct init flow), because endpoint roaming is
    /// reserved for the post-decrypt `roam` path that guards against forged
    /// sources. A punched peer is the one exception, justified by the dial
    /// commitment in `dial_fanout`.
    #[test]
    fn complete_initiation_leaves_endpoint_alone_when_not_punched() {
        let my_priv = [7u8; 32];
        let peer_priv = [8u8; 32];
        let peer_pub = keys::public_key(&peer_priv);
        let (peer_ek, peer_dk) = keys::derive_mlkem(&peer_priv);

        let node = node_with_peer(my_priv, peer_pub, peer_ek.clone());
        let configured: SocketAddr = "203.0.113.4:60000".parse().unwrap();
        {
            let mut g = node.lock().unwrap();
            g.peers[0].endpoint = Some(configured);
            // punched stays false — this is a regular direct init.
        }
        let msg1 = start_init(&node, my_priv, peer_pub, &peer_ek, 0x1234_5678);
        let mut resp =
            HybridResponder::new(peer_priv, &peer_ek, &peer_dk, gnet_rand::random_32());
        resp.read_message_1(&msg1).expect("peer reads msg1");
        let (msg2, _resp_t) = resp
            .write_message_2(&0u32.to_le_bytes())
            .expect("peer writes msg2");

        let stray: SocketAddr = "198.51.100.99:33333".parse().unwrap();
        {
            let mut g = node.lock().unwrap();
            complete_initiation(&mut g.peers[0], &msg2, stray, false);
        }

        let g = node.lock().unwrap();
        assert_eq!(
            g.peers[0].endpoint,
            Some(configured),
            "non-punched peers do not roam through complete_initiation"
        );
    }
}
