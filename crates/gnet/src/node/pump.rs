//! The two pump threads: TUN→UDP (uplink) and UDP→TUN (downlink). The lock is
//! held only for in-memory routing/crypto, never across an I/O syscall.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use gnet_tun::Tun;

use super::TAG_LEN;
use super::handshake::{complete_initiation, handle_init};
use super::types::{Node, Session};
use crate::MTU_BUF;
use gnet_wire::{self as wire, Kind};

/// Extract the destination IP from a raw IPv4/IPv6 packet, if well-formed.
fn dst_ip(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ))),
        6 if packet.len() >= 40 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&packet[24..40]);
            Some(IpAddr::V6(Ipv6Addr::from(a)))
        }
        _ => None,
    }
}

/// TUN -> route by dst IP -> encrypt -> UDP (handshake on demand).
pub(super) fn uplink(
    tun: Arc<Tun>,
    socket: Arc<UdpSocket>,
    node: Arc<Mutex<Node>>,
) -> thread::JoinHandle<io::Result<()>> {
    thread::spawn(move || -> io::Result<()> {
        let mut buf = [0u8; MTU_BUF];
        loop {
            // plaintext is read in past the transport header so the tag + index
            // can be written in front of it without moving the payload.
            let n = tun.recv(&mut buf[wire::TRANSPORT_HEADER..])?;
            if n == 0 {
                continue;
            }
            let Some(dst) = dst_ip(&buf[wire::TRANSPORT_HEADER..wire::TRANSPORT_HEADER + n]) else {
                continue;
            };

            // lock only for routing + crypto; the send syscall runs unlocked.
            let mut out: Option<(SocketAddr, usize)> = None; // direct: send buf[..len]
            let mut relay_out: Option<(SocketAddr, Vec<u8>)> = None; // relay-wrapped
            let mut init_dg: Option<(SocketAddr, Vec<u8>)> = None;
            {
                let mut g = node.lock().expect("node mutex");
                if let Some(i) = g.by_vip(dst) {
                    if matches!(g.peers[i].session, Session::Established(_)) {
                        let public = g.public;
                        let peer_pub = g.peers[i].public;
                        let relay = g.peers[i].relay;
                        let relay_ep = g.peers[i].relay_endpoint;
                        let ep = g.peers[i].endpoint;
                        let tx = g.peers[i].tx_index;
                        if let Session::Established(t) = &mut g.peers[i].session {
                            buf[0] = Kind::Transport as u8;
                            wire::put_index(&mut buf, tx);
                            wire::put_counter(&mut buf, t.send_counter());
                            let framed =
                                t.send
                                    .encrypt_in_place(&[], &mut buf[wire::TRANSPORT_HEADER..], n);
                            let len = wire::TRANSPORT_HEADER + framed;
                            if relay {
                                // un-punchable peer → wrap the transport datagram
                                // as RelayData(0x08) ‖ src ‖ dst ‖ inner and send
                                // it to the relay.
                                if let Some(rep) = relay_ep {
                                    let envelope =
                                        gnet_relay::encode(&public, &peer_pub, &buf[..len]);
                                    relay_out =
                                        Some((rep, wire::frame(Kind::RelayData, &envelope)));
                                }
                            } else if let Some(ep) = ep {
                                out = Some((ep, len));
                            }
                        }
                    } else if matches!(g.peers[i].session, Session::Idle) {
                        // v0.5 path selection — Tailscale-style "DERP-first
                        // for NAT-NAT, direct for anything involving a public
                        // node". DCUtR's simultaneous-open is unreliable for
                        // symmetric NAT (per-destination external ports break
                        // the reply path), so we don't put it in the critical
                        // path — direct upgrade can revisit later.
                        //
                        // Decision tree:
                        //   1. Peer already on relay → use it.
                        //   2. We are public OR peer is operator-marked
                        //      relay_eligible (treated as known-public): direct
                        //      init to peer.endpoint works.
                        //   3. Self NAT'd AND peer not known-public AND we can
                        //      pick a relay candidate: promote to relay
                        //      immediately, no probe. Pay one extra hop for
                        //      "always works" — solid > fast.
                        //   4. Peer endpoint known but no path resolution
                        //      (e.g. self_is_nat == None pre-probe): best-
                        //      effort direct init.
                        //   5. No endpoint and no relay candidate: drop.
                        if g.peers[i].relay {
                            init_dg = g.initiate(i);
                        } else {
                            let self_nat = matches!(g.self_is_nat, Some(true));
                            let peer_known_public = g.peers[i].relay_eligible;
                            if !self_nat || peer_known_public {
                                // direct: at least one side is public-reachable
                                if g.peers[i].endpoint.is_some() {
                                    init_dg = g.initiate(i);
                                }
                            } else if let Some(relay_ep) = g.coordinator_endpoint(i) {
                                // both presumed NAT'd → route via relay now.
                                g.peers[i].relay = true;
                                g.peers[i].relay_endpoint = Some(relay_ep);
                                eprintln!(
                                    "peer {i} routed via relay {relay_ep} (nat→nat, immediate)"
                                );
                                init_dg = g.initiate(i);
                            } else if g.peers[i].endpoint.is_some() {
                                // last-resort best-effort direct
                                init_dg = g.initiate(i);
                            }
                            // else: no path. retry next outbound.
                        }
                    }
                }
            }
            if let Some((ep, len)) = out {
                socket.send_to(&buf[..len], ep)?;
            }
            if let Some((ep, dg)) = relay_out {
                socket.send_to(&dg, ep)?;
            }
            if let Some((ep, dg)) = init_dg {
                socket.send_to(&dg, ep)?;
            }
        }
    })
}

/// Handles the downlink dispatch needs, bundled so `handle_datagram` can recurse
/// on a relayed inner datagram without a long argument list.
struct PumpCtx {
    tun: Arc<Tun>,
    socket: Arc<UdpSocket>,
    node: Arc<Mutex<Node>>,
    dial_wake: Arc<Condvar>,
}

/// UDP -> demux tag -> (handshake | decrypt) -> TUN.
pub(super) fn downlink(
    tun: Arc<Tun>,
    socket: Arc<UdpSocket>,
    node: Arc<Mutex<Node>>,
    dial_wake: Arc<Condvar>,
) -> thread::JoinHandle<io::Result<()>> {
    let ctx = PumpCtx {
        tun,
        socket,
        node,
        dial_wake,
    };
    thread::spawn(move || -> io::Result<()> {
        let mut buf = [0u8; MTU_BUF];
        loop {
            let (n, from) = ctx.socket.recv_from(&mut buf)?;
            handle_datagram(&ctx, &mut buf, n, from, None)?;
        }
    })
}

/// Dispatch one received datagram. `relay_src` is `Some(peer_pubkey)` when this
/// datagram was unwrapped from a relay envelope (a re-dispatched inner): it
/// routes HandshakeResp by key rather than source address, and suppresses
/// endpoint roaming, since the apparent source is the relay, not the peer.
fn handle_datagram(
    ctx: &PumpCtx,
    buf: &mut [u8],
    n: usize,
    from: SocketAddr,
    relay_src: Option<[u8; 32]>,
) -> io::Result<()> {
    let via_relay = relay_src.is_some();
    let Some((kind, _)) = wire::parse(&buf[..n]) else {
        return Ok(());
    };
    let body_off = wire::HEADER;
    match kind {
        Kind::HandshakeInit => {
            handle_init(&ctx.node, &ctx.socket, &buf[body_off..n], from, via_relay)?;
        }
        Kind::HandshakeResp => {
            let mut g = ctx.node.lock().expect("node mutex");
            // a relayed resp's source is the relay, so match it to the peer by
            // the envelope's src key instead of by source address.
            let i = match &relay_src {
                Some(src) => g.by_pubkey(src),
                None => g.by_endpoint(from),
            };
            if let Some(i) = i {
                complete_initiation(&mut g.peers[i], &buf[body_off..n]);
            }
        }
        Kind::Transport => {
            // demux by receiver index, decrypt under lock, write the
            // plaintext to the TUN with the lock released.
            let mut pt: Option<usize> = None;
            if n >= wire::TRANSPORT_HEADER + TAG_LEN
                && let Some(idx) = wire::index(&buf[..n])
                && let Some(ctr) = wire::counter(&buf[..n])
            {
                let mut g = ctx.node.lock().expect("node mutex");
                if let Some(i) = g.by_rx_index(idx) {
                    if let Session::Established(t) = &mut g.peers[i].session {
                        let blen = n - wire::TRANSPORT_HEADER;
                        // recv_at authenticates the explicit counter and
                        // rejects replays / out-of-window packets.
                        pt = t.recv_at(ctr, &[], &mut buf[wire::TRANSPORT_HEADER..n], blen);
                    }
                    // endpoint roaming: only after the packet decrypted, so a
                    // forged source can't redirect the peer — and never for a
                    // relayed packet, whose source is the relay, not the peer.
                    if pt.is_some() && !via_relay {
                        g.roam(i, from);
                    }
                }
            }
            // a zero-length plaintext is a keepalive — decrypted to
            // advance the replay counter, but never written to the TUN.
            if let Some(len) = pt
                && len > 0
            {
                ctx.tun
                    .send(&buf[wire::TRANSPORT_HEADER..wire::TRANSPORT_HEADER + len])?;
            }
        }
        Kind::EndpointProbe => {
            // reflect the source we observe back to the prober, echoing its
            // txid. Stateless (no lock) and allocation-free: the reply
            // (tag + txid + addr) is built in a stack buffer.
            if let Some(&txid) = buf[body_off..n].first_chunk::<4>() {
                let mut dg = [0u8; wire::HEADER + 4 + wire::ADDR_MAX];
                dg[0] = Kind::EndpointReply as u8;
                dg[wire::HEADER..wire::HEADER + 4].copy_from_slice(&txid);
                if let Some(addr_len) = wire::encode_addr_into(&mut dg[wire::HEADER + 4..], from) {
                    ctx.socket
                        .send_to(&dg[..wire::HEADER + 4 + addr_len], from)?;
                }
            }
        }
        Kind::EndpointReply => {
            // learn our reflexive (public) endpoint if the txid matches
            // the probe we sent.
            let body = &buf[body_off..n];
            if let Some(txid) = body.first_chunk::<4>()
                && let Some((observed, _)) = wire::decode_addr(&body[4..])
            {
                let txid = u32::from_le_bytes(*txid);
                let mut g = ctx.node.lock().expect("node mutex");
                if g.note_reflexive(txid, observed) {
                    eprintln!("discovered reflexive endpoint: {observed}");
                }
            }
        }
        Kind::PunchConnect => {
            // rendezvous connect: relay it on (we are the coordinator)
            // or act as origin/target. State under the lock; sends run
            // unlocked.
            let sends = {
                let mut g = ctx.node.lock().expect("node mutex");
                g.handle_connect(&buf[body_off..n], from)
            };
            for (ep, dg) in sends {
                ctx.socket.send_to(&dg, ep)?;
            }
            // a connect-reply may have installed a Syncing state with a
            // fresh dial deadline — wake the poller to recompute its wait.
            ctx.dial_wake.notify_one();
        }
        Kind::PunchSync => {
            // rendezvous sync: relay it on, or (as the target) dial the
            // origin immediately — its first packet is already inbound.
            let sends = {
                let mut g = ctx.node.lock().expect("node mutex");
                g.handle_sync(&buf[body_off..n])
            };
            for (ep, dg) in sends {
                ctx.socket.send_to(&dg, ep)?;
            }
        }
        Kind::RelayData => {
            // a relay envelope: src ‖ dst ‖ inner. We never decrypt the inner.
            let Some((src, dst, inner)) = gnet_relay::decode(&buf[body_off..n]) else {
                return Ok(());
            };
            let me = ctx.node.lock().expect("node mutex").public;
            if dst == &me {
                // addressed to us: copy the inner out and re-dispatch it as if it
                // had arrived directly (relay_src suppresses roaming + routes the
                // resp by key).
                let src = *src;
                let len = inner.len();
                let mut inner_buf = [0u8; MTU_BUF];
                if len > inner_buf.len() {
                    return Ok(());
                }
                inner_buf[..len].copy_from_slice(inner);
                // reciprocal: a peer reaching us via this relay means our own path
                // to it is relayed too — route our replies back the same way.
                {
                    let mut g = ctx.node.lock().expect("node mutex");
                    if let Some(j) = g.by_pubkey(&src) {
                        g.peers[j].relay = true;
                        g.peers[j].relay_endpoint = Some(from);
                    }
                }
                handle_datagram(ctx, &mut inner_buf, len, from, Some(src))?;
            } else {
                // we are the relay: forward the whole envelope to dst's endpoint,
                // unchanged — the inner stays end-to-end encrypted.
                let ep = {
                    let mut g = ctx.node.lock().expect("node mutex");
                    g.by_pubkey(dst).and_then(|j| g.peers[j].endpoint)
                };
                if let Some(ep) = ep {
                    ctx.socket.send_to(&buf[..n], ep)?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dst_ip_v4() {
        let mut p = [0u8; 20];
        p[0] = 0x45; // version 4, IHL 5
        p[16..20].copy_from_slice(&[10, 88, 0, 2]);
        assert_eq!(dst_ip(&p), Some(IpAddr::V4(Ipv4Addr::new(10, 88, 0, 2))));
    }

    #[test]
    fn dst_ip_v6() {
        let mut p = [0u8; 40];
        p[0] = 0x60; // version 6
        p[24..40].copy_from_slice(&[0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let want: Ipv6Addr = "2001::1".parse().unwrap();
        assert_eq!(dst_ip(&p), Some(IpAddr::V6(want)));
    }

    #[test]
    fn dst_ip_rejects_short_or_unknown() {
        assert_eq!(dst_ip(&[]), None);
        assert_eq!(dst_ip(&[0x45, 0, 0]), None); // too short for v4
        assert_eq!(dst_ip(&[0x35; 20]), None); // version 3
    }
}
