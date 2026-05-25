//! End-to-end: two endpoints complete the Noise_IK handshake over real UDP
//! sockets and exchange an AEAD-protected message — the "secure UDP channel"
//! milestone (OS entropy + Noise_IK + UDP, no TUN).

use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

use gnet::{channel, keys};

#[test]
fn two_endpoints_handshake_and_exchange_over_udp() {
    let (responder_sk, responder_pk) = keys::generate_static();
    let (initiator_sk, _initiator_pk) = keys::generate_static();

    let responder_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    responder_sock
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let responder_addr = responder_sock.local_addr().unwrap();

    // responder: complete handshake, then echo one decrypted message back.
    let responder = thread::spawn(move || {
        let (mut transport, from) = channel::accept(&responder_sock, responder_sk).expect("accept");
        let received = channel::recv(&responder_sock, &mut transport).expect("recv");
        channel::send(&responder_sock, from, &mut transport, &received).expect("echo");
    });

    let initiator_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    initiator_sock
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut transport =
        channel::connect(&initiator_sock, responder_addr, initiator_sk, responder_pk)
            .expect("connect");

    channel::send(
        &initiator_sock,
        responder_addr,
        &mut transport,
        b"hello mesh",
    )
    .expect("send");
    let echoed = channel::recv(&initiator_sock, &mut transport).expect("recv echo");

    assert_eq!(echoed, b"hello mesh");
    responder.join().unwrap();
}

#[test]
fn sustained_round_trips_over_udp() {
    let (responder_sk, responder_pk) = keys::generate_static();
    let (initiator_sk, _) = keys::generate_static();

    let responder_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    responder_sock
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let responder_addr = responder_sock.local_addr().unwrap();

    let responder = thread::spawn(move || {
        let (mut transport, from) = channel::accept(&responder_sock, responder_sk).expect("accept");
        for _ in 0..50 {
            let m = channel::recv(&responder_sock, &mut transport).expect("recv");
            channel::send(&responder_sock, from, &mut transport, &m).expect("echo");
        }
    });

    let initiator_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    initiator_sock
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut transport =
        channel::connect(&initiator_sock, responder_addr, initiator_sk, responder_pk)
            .expect("connect");

    for i in 0..50u32 {
        let msg = format!("round-trip #{i}");
        channel::send(
            &initiator_sock,
            responder_addr,
            &mut transport,
            msg.as_bytes(),
        )
        .expect("send");
        let echo = channel::recv(&initiator_sock, &mut transport).expect("recv");
        assert_eq!(echo, msg.as_bytes());
    }
    responder.join().unwrap();
}

#[test]
fn large_payload_round_trip() {
    let (responder_sk, responder_pk) = keys::generate_static();
    let (initiator_sk, _) = keys::generate_static();

    let responder_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    responder_sock
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let responder_addr = responder_sock.local_addr().unwrap();

    let responder = thread::spawn(move || {
        let (mut transport, from) = channel::accept(&responder_sock, responder_sk).expect("accept");
        let m = channel::recv(&responder_sock, &mut transport).expect("recv");
        channel::send(&responder_sock, from, &mut transport, &m).expect("echo");
    });

    let initiator_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    initiator_sock
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut transport =
        channel::connect(&initiator_sock, responder_addr, initiator_sk, responder_pk)
            .expect("connect");

    let payload = vec![0x5au8; 1500];
    channel::send(&initiator_sock, responder_addr, &mut transport, &payload).expect("send");
    let echo = channel::recv(&initiator_sock, &mut transport).expect("recv");
    assert_eq!(echo, payload);
    responder.join().unwrap();
}
