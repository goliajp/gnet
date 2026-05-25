//! TUN ↔ UDP pump: bridge a `utun` device to the encrypted channel so real
//! IP traffic flows through the mesh. macOS only (depends on `mesh-tun`).

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::process::Command;
use std::sync::Arc;
use std::thread;

use gnet_noise::handshake::Transport;
use gnet_tun::Tun;

use gnet_wire::{self as wire, Kind};

use crate::MTU_BUF;

/// Run a config command, mapping a non-zero exit to an error.
fn run_cmd(cmd: &mut Command) -> io::Result<()> {
    if cmd.status()?.success() {
        Ok(())
    } else {
        Err(io::Error::other("interface configuration command failed"))
    }
}

/// Bring the interface up as a point-to-point link.
#[cfg(target_os = "macos")]
fn configure(name: &str, local_ip: &str, peer_ip: &str) -> io::Result<()> {
    run_cmd(Command::new("ifconfig").args([name, local_ip, peer_ip, "up"]))
}

/// Bring the interface up as a point-to-point link.
#[cfg(target_os = "linux")]
fn configure(name: &str, local_ip: &str, peer_ip: &str) -> io::Result<()> {
    run_cmd(Command::new("ip").args(["addr", "add", local_ip, "peer", peer_ip, "dev", name]))?;
    run_cmd(Command::new("ip").args(["link", "set", name, "up"]))
}

/// Open a `utun`, bring it up, and pump packets between it and `peer` over the
/// established `transport`. Two threads (TUN→UDP, UDP→TUN); runs until a
/// socket/device error.
pub fn run(
    socket: UdpSocket,
    peer: SocketAddr,
    transport: Transport,
    local_ip: &str,
    peer_ip: &str,
) -> io::Result<()> {
    let tun = Arc::new(Tun::open()?);
    configure(tun.name(), local_ip, peer_ip)?;
    eprintln!("tunnel up on {} ({local_ip} <-> {peer_ip})", tun.name());

    // the single-peer tunnel keeps the simple in-order transport; the
    // anti-replay window (recv_window) is only used by the multi-peer node.
    let Transport {
        mut send, mut recv, ..
    } = transport;
    let socket = Arc::new(socket);

    // TUN -> encrypt in place -> UDP. The packet is read into buf[HEADER..] so
    // the type tag occupies byte 0 of the same buffer (no per-packet alloc).
    let tun_up = tun.clone();
    let sock_up = socket.clone();
    let uplink = thread::spawn(move || -> io::Result<()> {
        let mut buf = [0u8; MTU_BUF];
        loop {
            let n = tun_up.recv(&mut buf[wire::HEADER..])?;
            if n > 0 {
                buf[0] = Kind::Transport as u8;
                let framed = send.encrypt_in_place(&[], &mut buf[wire::HEADER..], n);
                sock_up.send_to(&buf[..wire::HEADER + framed], peer)?;
            }
        }
    });

    // UDP -> demux tag -> decrypt in place -> TUN (no per-packet allocation).
    let downlink = thread::spawn(move || -> io::Result<()> {
        let mut buf = [0u8; MTU_BUF];
        loop {
            let (n, _) = socket.recv_from(&mut buf)?;
            // ignore empty / non-transport datagrams rather than tearing down.
            if n <= wire::HEADER || Kind::from_byte(buf[0]) != Some(Kind::Transport) {
                continue;
            }
            let body_len = n - wire::HEADER;
            if let Some(pt_len) = recv.decrypt_in_place(&[], &mut buf[wire::HEADER..n], body_len) {
                tun.send(&buf[wire::HEADER..wire::HEADER + pt_len])?;
            }
        }
    });

    uplink
        .join()
        .map_err(|_| io::Error::other("uplink thread panicked"))??;
    downlink
        .join()
        .map_err(|_| io::Error::other("downlink thread panicked"))??;
    Ok(())
}
