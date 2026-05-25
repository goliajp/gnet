//! Mesh wire framing: a one-byte type tag prefixes every UDP datagram so a
//! node can demultiplex handshake from transport traffic — the foundation for
//! routing datagrams to the right peer session once there is more than one.
//!
//! The transport path stays allocation-free: the tag occupies byte 0 of the
//! same buffer the ciphertext is built in (see [`HEADER`]), so the per-packet
//! data path never allocates. Handshake datagrams are rare, so [`frame`]
//! returns an owned buffer for them.
//!
//! ```
//! use gnet_wire::{Kind, frame, parse};
//! let payload: &[u8] = b"msg1 bytes";
//! let dg = frame(Kind::HandshakeInit, payload);
//! let (kind, body) = parse(&dg).unwrap();
//! assert_eq!(kind, Kind::HandshakeInit);
//! assert_eq!(body, payload);
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Bytes reserved at the front of a datagram for the type tag.
pub const HEADER: usize = 1;

/// Length of the little-endian receiver-index field (after the tag).
const INDEX_LEN: usize = 4;
/// Length of the little-endian per-packet counter field (after the index).
const COUNTER_LEN: usize = 8;

/// Offset of the counter field within a transport datagram.
const COUNTER_OFF: usize = HEADER + INDEX_LEN;

/// Bytes reserved at the front of a transport datagram: the 1-byte type tag,
/// a 4-byte little-endian receiver index, and an 8-byte little-endian packet
/// counter. The ciphertext begins here. The index lets a peer demultiplex
/// transport to a session by identity (not source address — the basis for
/// roaming); the counter is the AEAD nonce and drives anti-replay, so a peer
/// can authenticate packets that arrive out of order.
pub const TRANSPORT_HEADER: usize = COUNTER_OFF + COUNTER_LEN;

/// Write the receiver `index` into a transport datagram's index field.
/// The caller has already set the tag byte.
pub fn put_index(dg: &mut [u8], index: u32) {
    dg[HEADER..COUNTER_OFF].copy_from_slice(&index.to_le_bytes());
}

/// Read the receiver index from a transport datagram, or `None` if it is too
/// short to carry one.
pub fn index(dg: &[u8]) -> Option<u32> {
    let bytes: [u8; INDEX_LEN] = dg.get(HEADER..COUNTER_OFF)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// Write the per-packet `counter` into a transport datagram's counter field.
pub fn put_counter(dg: &mut [u8], counter: u64) {
    dg[COUNTER_OFF..TRANSPORT_HEADER].copy_from_slice(&counter.to_le_bytes());
}

/// Read the per-packet counter from a transport datagram, or `None` if it is
/// too short to carry one.
pub fn counter(dg: &[u8]) -> Option<u64> {
    let bytes: [u8; COUNTER_LEN] = dg.get(COUNTER_OFF..TRANSPORT_HEADER)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

/// Datagram type tag (byte 0 of every datagram).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// Noise_IK message 1 (initiator → responder).
    HandshakeInit = 0x01,
    /// Noise_IK message 2 (responder → initiator).
    HandshakeResp = 0x02,
    /// AEAD-protected transport datagram.
    Transport = 0x03,
    /// Reflexive-endpoint probe (STUN-like): "what source address do you see?"
    EndpointProbe = 0x04,
    /// Reply to a probe, carrying the observed source endpoint.
    EndpointReply = 0x05,
    /// Rendezvous connect, relayed through a mutually-reachable coordinator: an
    /// origin advertising its reflexive endpoint to a target so the two can
    /// synchronize a simultaneous hole-punch dial (DCUtR-style). Used both for
    /// the origin's request and the target's reply.
    PunchConnect = 0x06,
    /// Rendezvous sync: the origin has measured the coordinator-path RTT and is
    /// about to dial; the target dials immediately on receipt while the origin
    /// waits RTT/2, so both first packets cross at the path midpoint.
    PunchSync = 0x07,
    /// Relay fallback: an end-to-end-encrypted inner datagram wrapped with a
    /// `src ‖ dst` routing header (see `mesh-relay`) and forwarded by a
    /// mutually reachable relay when two peers cannot hole-punch a direct path
    /// (symmetric NAT / CGNAT / hairpin). The relay routes by `dst` and never
    /// decrypts — the inner bytes stay end-to-end encrypted.
    RelayData = 0x08,
}

impl Kind {
    /// Parse the tag byte, or `None` for an unknown type.
    pub fn from_byte(b: u8) -> Option<Kind> {
        match b {
            0x01 => Some(Kind::HandshakeInit),
            0x02 => Some(Kind::HandshakeResp),
            0x03 => Some(Kind::Transport),
            0x04 => Some(Kind::EndpointProbe),
            0x05 => Some(Kind::EndpointReply),
            0x06 => Some(Kind::PunchConnect),
            0x07 => Some(Kind::PunchSync),
            0x08 => Some(Kind::RelayData),
            _ => None,
        }
    }
}

/// Build an owned datagram `tag ‖ body` (for handshake messages).
pub fn frame(kind: Kind, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + body.len());
    out.push(kind as u8);
    out.extend_from_slice(body);
    out
}

/// Split a received datagram into its type tag and body, or `None` if it is
/// empty or carries an unknown tag.
pub fn parse(datagram: &[u8]) -> Option<(Kind, &[u8])> {
    let (&tag, body) = datagram.split_first()?;
    Some((Kind::from_byte(tag)?, body))
}

/// Largest encoded socket address: 1-byte family + 16-byte IPv6 + 2-byte port.
pub const ADDR_MAX: usize = 1 + 16 + 2;

/// Encode a socket address into `out` — a 1-byte family (4 or 6), the IP octets,
/// then a 2-byte little-endian port — returning the number of bytes written, or
/// `None` if `out` is too small. Allocation-free; an address needs at most
/// [`ADDR_MAX`] bytes.
pub fn encode_addr_into(out: &mut [u8], addr: SocketAddr) -> Option<usize> {
    let port = addr.port().to_le_bytes();
    match addr.ip() {
        IpAddr::V4(v4) => {
            let s = out.get_mut(..1 + 4 + 2)?;
            s[0] = 4;
            s[1..5].copy_from_slice(&v4.octets());
            s[5..7].copy_from_slice(&port);
            Some(7)
        }
        IpAddr::V6(v6) => {
            let s = out.get_mut(..1 + 16 + 2)?;
            s[0] = 6;
            s[1..17].copy_from_slice(&v6.octets());
            s[17..19].copy_from_slice(&port);
            Some(19)
        }
    }
}

/// Encode a socket address, appending to `out`. Convenience over
/// [`encode_addr_into`] for cold paths that already build a `Vec`.
pub fn encode_addr(out: &mut Vec<u8>, addr: SocketAddr) {
    let mut buf = [0u8; ADDR_MAX];
    let n = encode_addr_into(&mut buf, addr).expect("ADDR_MAX holds any address");
    out.extend_from_slice(&buf[..n]);
}

/// Decode a socket address from the front of `b`, returning it and the bytes
/// after it, or `None` if `b` is malformed or truncated.
pub fn decode_addr(b: &[u8]) -> Option<(SocketAddr, &[u8])> {
    let (&family, rest) = b.split_first()?;
    let (ip, rest) = match family {
        4 => {
            let (o, rest) = rest.split_at_checked(4)?;
            (IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3])), rest)
        }
        6 => {
            let (o, rest) = rest.split_at_checked(16)?;
            let arr: [u8; 16] = o.try_into().ok()?;
            (IpAddr::V6(Ipv6Addr::from(arr)), rest)
        }
        _ => return None,
    };
    let (p, rest) = rest.split_at_checked(2)?;
    let port = u16::from_le_bytes(p.try_into().ok()?);
    Some((SocketAddr::new(ip, port), rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_parse_roundtrip() {
        for kind in [
            Kind::HandshakeInit,
            Kind::HandshakeResp,
            Kind::Transport,
            Kind::EndpointProbe,
            Kind::EndpointReply,
            Kind::PunchConnect,
            Kind::PunchSync,
            Kind::RelayData,
        ] {
            let body = b"the body bytes";
            let dg = frame(kind, body);
            assert_eq!(dg[0], kind as u8);
            let (k, b) = parse(&dg).expect("parse");
            assert_eq!(k, kind);
            assert_eq!(b, body);
        }
    }

    #[test]
    fn punch_kinds_have_stable_tags() {
        // the rendezvous tags follow the endpoint-discovery tags (0x04/0x05);
        // their on-wire values are a protocol contract, so pin them explicitly.
        assert_eq!(Kind::PunchConnect as u8, 0x06);
        assert_eq!(Kind::PunchSync as u8, 0x07);
        assert_eq!(Kind::from_byte(0x06), Some(Kind::PunchConnect));
        assert_eq!(Kind::from_byte(0x07), Some(Kind::PunchSync));
    }

    #[test]
    fn relay_kind_has_stable_tag() {
        // the relay-fallback tag follows the rendezvous tags; a relay forwards
        // by this on-wire value, so it is a protocol contract — pin it.
        assert_eq!(Kind::RelayData as u8, 0x08);
        assert_eq!(Kind::from_byte(0x08), Some(Kind::RelayData));
    }

    #[test]
    fn addr_codec_roundtrip() {
        use std::net::SocketAddr;
        for s in ["192.168.1.5:7777", "[fd00::1]:443"] {
            let a: SocketAddr = s.parse().unwrap();
            let mut out = Vec::new();
            encode_addr(&mut out, a);
            let (got, rest) = decode_addr(&out).expect("decode");
            assert_eq!(got, a);
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn encode_addr_into_matches_owned_and_rejects_small() {
        use std::net::SocketAddr;
        for s in ["192.168.1.5:7777", "[fd00::1]:443"] {
            let a: SocketAddr = s.parse().unwrap();
            let mut buf = [0u8; ADDR_MAX];
            let n = encode_addr_into(&mut buf, a).expect("fits");
            // the allocation-free encoder agrees with the owned one
            let mut owned = Vec::new();
            encode_addr(&mut owned, a);
            assert_eq!(&buf[..n], owned.as_slice());
            // and round-trips through decode
            let (got, rest) = decode_addr(&buf[..n]).expect("decode");
            assert_eq!(got, a);
            assert!(rest.is_empty());
        }
        // a buffer too small for the v6 encoding is rejected, not truncated
        let v6: SocketAddr = "[fd00::1]:443".parse().unwrap();
        assert!(encode_addr_into(&mut [0u8; 7], v6).is_none());
    }

    #[test]
    fn decode_addr_rejects_bad() {
        assert!(decode_addr(&[]).is_none());
        assert!(decode_addr(&[9, 1, 2, 3]).is_none()); // unknown family
        assert!(decode_addr(&[4, 1, 2, 3]).is_none()); // v4 truncated
    }

    #[test]
    fn parse_rejects_empty_and_unknown() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x00]).is_none());
        assert!(parse(&[0xff, 1, 2, 3]).is_none());
    }

    #[test]
    fn parse_allows_empty_body() {
        let (k, b) = parse(&[Kind::Transport as u8]).expect("parse");
        assert_eq!(k, Kind::Transport);
        assert!(b.is_empty());
    }

    #[test]
    fn transport_index_roundtrip() {
        let mut dg = [0u8; TRANSPORT_HEADER + 8];
        dg[0] = Kind::Transport as u8;
        put_index(&mut dg, 0xDEAD_BEEF);
        assert_eq!(index(&dg), Some(0xDEAD_BEEF));
        // the tag byte is left untouched by the index write
        assert_eq!(dg[0], Kind::Transport as u8);
    }

    #[test]
    fn index_rejects_too_short() {
        // tag only, no room for the 4-byte index
        assert_eq!(index(&[Kind::Transport as u8]), None);
        assert_eq!(index(&[Kind::Transport as u8, 1, 2]), None);
    }

    #[test]
    fn transport_index_and_counter_roundtrip() {
        let mut dg = [0u8; TRANSPORT_HEADER + 8];
        dg[0] = Kind::Transport as u8;
        put_index(&mut dg, 0xDEAD_BEEF);
        put_counter(&mut dg, 0x0102_0304_0506_0708);
        assert_eq!(index(&dg), Some(0xDEAD_BEEF));
        assert_eq!(counter(&dg), Some(0x0102_0304_0506_0708));
        // index and counter occupy disjoint fields — neither clobbers the other
        assert_eq!(dg[0], Kind::Transport as u8);
    }

    #[test]
    fn counter_rejects_too_short() {
        // has an index but no counter field
        let mut dg = [0u8; HEADER + 4];
        dg[0] = Kind::Transport as u8;
        assert_eq!(counter(&dg), None);
    }
}
