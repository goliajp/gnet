//! Secure channel — drive the Noise_IK handshake over UDP, then send and
//! receive AEAD-protected datagrams. One Noise message per UDP datagram.
//!
//! This is the **point-to-point** layer: a single initiator ↔ responder
//! connection. It backs the `listen` / `connect` (interactive messages) and
//! `tunnel-listen` / `tunnel-connect` (1:1 TUN tunnel) CLI commands. The
//! multi-peer gnet (the `up` command) is a separate stack in the `node`
//! module; channel is **not** superseded by it — the two serve different
//! shapes (one connection vs a routed peer table), so both stay.

use std::io;
use std::net::{SocketAddr, UdpSocket};

use gnet_noise::handshake::{Initiator, Responder, Transport};

use gnet_wire::{self as wire, Kind};

/// Maximum UDP datagram read. Handshake messages are ~100 bytes; transport
/// payloads are bounded by this minus the 16-byte tag.
pub const MAX_DATAGRAM: usize = 2048;

/// Connect as the Noise_IK initiator: send message 1, await message 2, and
/// return the established transport. The responder's static public key must
/// be known in advance (the IK pattern). The ephemeral is drawn from the OS.
pub fn connect(
    socket: &UdpSocket,
    peer: SocketAddr,
    static_priv: [u8; 32],
    responder_static_pub: [u8; 32],
) -> io::Result<Transport> {
    let mut initiator = Initiator::new(static_priv, responder_static_pub, gnet_rand::random_32());
    socket.send_to(
        &wire::frame(Kind::HandshakeInit, &initiator.write_message_1(&[])),
        peer,
    )?;

    let mut buf = [0u8; MAX_DATAGRAM];
    let (n, _) = socket.recv_from(&mut buf)?;
    let (kind, body) =
        wire::parse(&buf[..n]).ok_or_else(|| io::Error::other("malformed datagram"))?;
    if kind != Kind::HandshakeResp {
        return Err(io::Error::other("expected handshake response"));
    }
    let (transport, _payload) = initiator
        .read_message_2(body)
        .ok_or_else(|| io::Error::other("noise message 2 verification failed"))?;
    Ok(transport)
}

/// Accept as the Noise_IK responder: await message 1, reply with message 2,
/// and return the transport plus the initiator's address.
pub fn accept(socket: &UdpSocket, static_priv: [u8; 32]) -> io::Result<(Transport, SocketAddr)> {
    let mut buf = [0u8; MAX_DATAGRAM];
    let (n, from) = socket.recv_from(&mut buf)?;

    let (kind, body) =
        wire::parse(&buf[..n]).ok_or_else(|| io::Error::other("malformed datagram"))?;
    if kind != Kind::HandshakeInit {
        return Err(io::Error::other("expected handshake init"));
    }
    let mut responder = Responder::new(static_priv, gnet_rand::random_32());
    responder
        .read_message_1(body)
        .ok_or_else(|| io::Error::other("noise message 1 verification failed"))?;
    let (msg2, transport) = responder
        .write_message_2(&[])
        .ok_or_else(|| io::Error::other("noise message 2 build failed"))?;
    socket.send_to(&wire::frame(Kind::HandshakeResp, &msg2), from)?;
    Ok((transport, from))
}

/// Encrypt `msg` and send it to `peer` over the transport.
pub fn send(
    socket: &UdpSocket,
    peer: SocketAddr,
    transport: &mut Transport,
    msg: &[u8],
) -> io::Result<()> {
    let ciphertext = transport.send.encrypt_with_ad(&[], msg);
    socket.send_to(&wire::frame(Kind::Transport, &ciphertext), peer)?;
    Ok(())
}

/// Receive and decrypt the next transport datagram.
pub fn recv(socket: &UdpSocket, transport: &mut Transport) -> io::Result<Vec<u8>> {
    let mut buf = [0u8; MAX_DATAGRAM];
    let (n, _) = socket.recv_from(&mut buf)?;
    let (kind, body) =
        wire::parse(&buf[..n]).ok_or_else(|| io::Error::other("malformed datagram"))?;
    if kind != Kind::Transport {
        return Err(io::Error::other("expected transport datagram"));
    }
    transport
        .recv
        .decrypt_with_ad(&[], body)
        .ok_or_else(|| io::Error::other("transport decryption failed"))
}
