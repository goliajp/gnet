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
pub(super) fn complete_initiation(peer: &mut Peer, body: &[u8]) {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MTU_BUF;
    use crate::keys;
    use gnet_noise::hybrid::HybridInitiator;
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
                public: peer_pub,
                mlkem_ek: peer_ek
                    .into_boxed_slice()
                    .try_into()
                    .expect("test ek must be EK_LEN bytes"),
                vip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                endpoint: None,
                rx_index: 0,
                tx_index: 0,
                session: Session::Idle,
                punch: PunchState::Idle,
                punched: false,
                punch_failures: 0,
                relay: false,
                relay_endpoint: None,
            }],
            reflexive: None,
            probe_txid: 0,
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
            complete_initiation(&mut g.peers[0], &buf[wire::HEADER..n]);
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
}
