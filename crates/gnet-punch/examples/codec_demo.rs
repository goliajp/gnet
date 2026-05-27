//! Encode + decode both rendezvous datagrams (PunchConnect, PunchSync)
//! and step the per-peer state machine through one upgrade cycle:
//! Idle → Connecting → Syncing → due-dial. No sockets — the codec and
//! state transitions are zero-I/O.
//!
//! ```sh
//! cargo run -p gnet-punch --example codec_demo
//! ```

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use gnet_punch::{PunchState, decode_connect, decode_sync, encode_connect, encode_sync};

fn main() {
    // Stand-in identities (X25519 pubkeys are 32 bytes).
    let origin_pk = [0x01u8; 32];
    let target_pk = [0x02u8; 32];
    // The origin's reflexive (NAT-mapped) endpoint, learned from a probe.
    let origin_refl: SocketAddr = "203.0.113.7:40000".parse().unwrap();

    // The origin builds a PunchConnect and sends it through a coordinator.
    let connect_body = encode_connect(&origin_pk, &target_pk, origin_refl);
    let (got_origin, got_target, got_refl) =
        decode_connect(&connect_body).expect("connect decodes");
    assert_eq!(got_origin, origin_pk);
    assert_eq!(got_target, target_pk);
    assert_eq!(got_refl, origin_refl);
    println!("PunchConnect: {} bytes (32 + 32 + addr)", connect_body.len());

    // Step the origin-side state machine.
    let sent_at = Instant::now() - Duration::from_millis(40); // back-dated RTT
    let mut state = PunchState::Connecting { sent_at };

    // The target's reply arrives via the coordinator; on_reply measures the
    // RTT and schedules the dial at RTT/2 past now.
    let target_refl: SocketAddr = "198.51.100.8:50000".parse().unwrap();
    let scheduled = state.on_reply(target_refl, Instant::now());
    assert!(scheduled, "Connecting + reply → Syncing");
    println!("on_reply ok: Connecting -> Syncing with dial scheduled at RTT/2");

    // The PunchSync ack carries (origin, target) so the coordinator can
    // forward it. The state machine doesn't touch it directly.
    let sync_body = encode_sync(&origin_pk, &target_pk);
    let (decoded_origin, decoded_target) = decode_sync(&sync_body).expect("sync decodes");
    assert_eq!(decoded_origin, origin_pk);
    assert_eq!(decoded_target, target_pk);
    println!("PunchSync:    {} bytes (32 + 32)", sync_body.len());

    // Past the dial deadline → state hands back the target endpoint so the
    // node binary can start a handshake.
    let endpoint = state.due_dial(Instant::now() + Duration::from_secs(1));
    assert_eq!(endpoint, Some(target_refl));
    println!("due_dial -> {target_refl} (ready to start the handshake)");
}
