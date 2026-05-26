//! Static multi-peer node configuration (WireGuard-style): our identity plus a
//! list of peers, each with a static public key, a virtual IP, and an optional
//! UDP endpoint we can initiate to.
//!
//! Text format (one directive per line; `#` and blank lines ignored):
//!
//! ```text
//! private  <64-hex>          # our static private key (ML-KEM key derived from it)
//! address  <ip>              # our IPv4 virtual (overlay) IP — the TUN address
//! address6 <ip6>             # optional: our IPv6 virtual (overlay) IP
//! listen   <bind_addr>       # UDP socket to bind, e.g. 0.0.0.0:7777
//! keepalive <secs>           # optional: send an empty transport packet to each
//!                            # established peer every <secs> to hold NAT mappings
//!                            # open (0 disables); absent = disabled
//! peer <pubkey-64hex> <mlkem-ek-hex> <vip4>[,<vip6>] [endpoint]
//! peer <pubkey-64hex> <mlkem-ek-hex> <vip4>[,<vip6>] [endpoint]
//! ```
//!
//! `mlkem-ek-hex` is the peer's (public) ML-KEM-768 encapsulation key, printed
//! by `gnet keygen` as `mlkem-public`.
//!
//! Part of a from-scratch, 0-external-dependency overlay: depends only on the
//! sibling stones `gnet-hex` (key codec) and `gnet-crypto` (the `EK_LEN`
//! constant). A cold-path text parser run once at node startup — no per-packet
//! budget, hence no bench/BUDGETS, in line with the other utility stones.

#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use gnet_crypto::mlkem;

use gnet_hex as hex;

/// One configured peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConfig {
    /// Peer X25519 static public key.
    pub public: [u8; 32],
    /// Peer ML-KEM-768 encapsulation key (public), for the hybrid handshake.
    /// Boxed fixed-size array: the length is part of the type, so a malformed
    /// length is rejected at parse rather than carried as a runtime invariant.
    pub mlkem_ek: Box<[u8; mlkem::EK_LEN]>,
    /// Peer's IPv4 virtual (overlay) IP — routes to this peer.
    pub vip: IpAddr,
    /// Peer's IPv6 virtual (overlay) IP, when dual-stack. `None` keeps the
    /// peer v4-only.
    pub vip6: Option<IpAddr>,
    /// Where to reach the peer over UDP. `None` means we only ever respond to
    /// this peer (we learn its endpoint from its handshake).
    pub endpoint: Option<SocketAddr>,
}

/// A node's full static configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Our static private key.
    pub private: [u8; 32],
    /// Our IPv4 virtual (overlay) IP — the TUN address.
    pub address: IpAddr,
    /// Our IPv6 virtual (overlay) IP — added to the TUN when set. `None`
    /// keeps the node v4-only.
    pub address6: Option<IpAddr>,
    /// UDP socket to bind.
    pub listen: SocketAddr,
    /// Persistent-keepalive interval. When set, an empty transport packet is
    /// sent to every established peer each interval to keep NAT mappings open.
    /// `None` disables keepalive.
    pub keepalive: Option<Duration>,
    /// gnet-discover coordinator base URL — when set, the daemon spawns a
    /// background discovery thread that polls `GET <coordinator>/peers`
    /// periodically and hot-adds newly-joined peers to the in-memory routing
    /// table. `None` keeps the daemon entirely conf-driven (legacy / offline
    /// deployments).
    pub coordinator: Option<String>,
    /// Configured peers.
    pub peers: Vec<PeerConfig>,
}

/// Parse a node configuration from its text form.
pub fn parse(text: &str) -> Result<Config, String> {
    let mut private: Option<[u8; 32]> = None;
    let mut address: Option<IpAddr> = None;
    let mut address6: Option<IpAddr> = None;
    let mut listen: Option<SocketAddr> = None;
    let mut keepalive: Option<Duration> = None;
    let mut coordinator: Option<String> = None;
    let mut peers = Vec::new();

    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut t = line.split_whitespace();
        let directive = t.next().unwrap_or("");
        let err = |m: &str| format!("line {}: {m}", lineno + 1);
        match directive {
            "private" => {
                let h = t.next().ok_or_else(|| err("private: missing key"))?;
                private = Some(hex::decode_32(h).ok_or_else(|| err("private: bad 32-byte hex"))?);
            }
            "address" => {
                let a = t.next().ok_or_else(|| err("address: missing ip"))?;
                address = Some(a.parse().map_err(|_| err("address: bad ip"))?);
            }
            "address6" => {
                let a = t.next().ok_or_else(|| err("address6: missing ip"))?;
                let v: IpAddr = a.parse().map_err(|_| err("address6: bad ip"))?;
                if !matches!(v, IpAddr::V6(_)) {
                    return Err(err("address6: must be IPv6"));
                }
                address6 = Some(v);
            }
            "listen" => {
                let a = t.next().ok_or_else(|| err("listen: missing addr"))?;
                listen = Some(a.parse().map_err(|_| err("listen: bad socket addr"))?);
            }
            "keepalive" => {
                let s = t.next().ok_or_else(|| err("keepalive: missing seconds"))?;
                let secs: u64 = s.parse().map_err(|_| err("keepalive: bad seconds"))?;
                // 0 disables, matching WireGuard's PersistentKeepalive semantics
                keepalive = (secs > 0).then(|| Duration::from_secs(secs));
            }
            "coordinator" => {
                let url = t.next().ok_or_else(|| err("coordinator: missing url"))?;
                if !(url.starts_with("http://") || url.starts_with("https://")) {
                    return Err(err("coordinator: url must start with http:// or https://"));
                }
                coordinator = Some(url.trim_end_matches('/').to_string());
            }
            "peer" => {
                let pk = t.next().ok_or_else(|| err("peer: missing public key"))?;
                let public = hex::decode_32(pk).ok_or_else(|| err("peer: bad 32-byte hex"))?;
                let ek_hex = t.next().ok_or_else(|| err("peer: missing mlkem ek"))?;
                let mlkem_ek: Box<[u8; mlkem::EK_LEN]> = hex::decode(ek_hex)
                    .and_then(|e| e.into_boxed_slice().try_into().ok())
                    .ok_or_else(|| err("peer: bad mlkem ek"))?;
                let vip_token = t.next().ok_or_else(|| err("peer: missing vip"))?;
                let (vip_s, vip6_s) = match vip_token.split_once(',') {
                    Some((a, b)) => (a, Some(b)),
                    None => (vip_token, None),
                };
                let vip: IpAddr = vip_s.parse().map_err(|_| err("peer: bad vip"))?;
                if !matches!(vip, IpAddr::V4(_)) {
                    return Err(err(
                        "peer: vip must be IPv4 (use `<v4>,<v6>` for dual-stack)",
                    ));
                }
                let vip6 = match vip6_s {
                    Some(s) => {
                        let v: IpAddr = s.parse().map_err(|_| err("peer: bad vip6"))?;
                        if !matches!(v, IpAddr::V6(_)) {
                            return Err(err("peer: vip6 must be IPv6"));
                        }
                        Some(v)
                    }
                    None => None,
                };
                let endpoint = match t.next() {
                    Some(e) => Some(e.parse().map_err(|_| err("peer: bad endpoint"))?),
                    None => None,
                };
                peers.push(PeerConfig {
                    public,
                    mlkem_ek,
                    vip,
                    vip6,
                    endpoint,
                });
            }
            other => return Err(err(&format!("unknown directive `{other}`"))),
        }
    }

    Ok(Config {
        private: private.ok_or("missing `private`")?,
        address: address.ok_or("missing `address`")?,
        address6,
        listen: listen.ok_or("missing `listen`")?,
        keepalive,
        coordinator,
        peers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid-length (but otherwise arbitrary) ML-KEM ek as hex. `parse` only
    /// checks the ek's byte length, so any `EK_LEN` bytes stand in for a real
    /// encapsulation key — no need to depend on the crypto keygen here.
    fn ek_hex(fill: u8) -> String {
        gnet_hex::encode(&[fill; mlkem::EK_LEN])
    }

    #[test]
    fn parses_full_config() {
        let ek2 = ek_hex(0x22);
        let ek3 = ek_hex(0x33);
        let text = format!(
            "\
# our node
private 0000000000000000000000000000000000000000000000000000000000000001
address 10.88.0.1
listen 0.0.0.0:7777

# peers
peer 0000000000000000000000000000000000000000000000000000000000000002 {ek2} 10.88.0.2 192.168.1.5:7777
peer 0000000000000000000000000000000000000000000000000000000000000003 {ek3} 10.88.0.3
"
        );
        let c = parse(&text).expect("parse");
        assert_eq!(c.private[31], 1);
        assert_eq!(c.address, "10.88.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(c.listen, "0.0.0.0:7777".parse::<SocketAddr>().unwrap());
        assert_eq!(c.peers.len(), 2);
        assert_eq!(c.peers[0].mlkem_ek.len(), mlkem::EK_LEN);
        assert_eq!(c.peers[0].vip, "10.88.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(
            c.peers[0].endpoint,
            Some("192.168.1.5:7777".parse().unwrap())
        );
        assert_eq!(c.peers[1].endpoint, None);
    }

    #[test]
    fn missing_required_fields_error() {
        assert!(parse("address 10.0.0.1\nlisten 0.0.0.0:1").is_err());
        assert!(parse("private 00\naddress 10.0.0.1\nlisten 0.0.0.0:1").is_err());
    }

    #[test]
    fn bad_mlkem_ek_errors() {
        // right public key, wrong-length ML-KEM ek
        let text = "private 0000000000000000000000000000000000000000000000000000000000000001\naddress 10.0.0.1\nlisten 0.0.0.0:1\npeer 0000000000000000000000000000000000000000000000000000000000000002 dead 10.0.0.2";
        assert!(parse(text).is_err());
    }

    #[test]
    fn unknown_directive_errors() {
        let text = "private 0000000000000000000000000000000000000000000000000000000000000001\naddress 10.0.0.1\nlisten 0.0.0.0:1\nbogus x";
        assert!(parse(text).is_err());
    }

    #[test]
    fn malformed_fields_rejected() {
        let priv1 = "private 0000000000000000000000000000000000000000000000000000000000000001";
        let base = format!("{priv1}\naddress 10.0.0.1\nlisten 0.0.0.0:1\n");
        let pk = "0000000000000000000000000000000000000000000000000000000000000002";
        let ek = ek_hex(0x22);

        // bad self address / listen
        assert!(parse(&format!("{priv1}\naddress not-an-ip\nlisten 0.0.0.0:1")).is_err());
        assert!(parse(&format!("{priv1}\naddress 10.0.0.1\nlisten not-a-socket")).is_err());
        // directive present but its value missing
        assert!(parse("private").is_err());
        assert!(parse(&format!("{priv1}\naddress")).is_err());
        assert!(parse(&format!("{base}keepalive")).is_err());
        // peer: bad pubkey hex, missing ek, bad vip, bad endpoint
        assert!(parse(&format!("{base}peer zz {ek} 10.0.0.2")).is_err());
        assert!(parse(&format!("{base}peer {pk}")).is_err());
        assert!(parse(&format!("{base}peer {pk} {ek} not-an-ip")).is_err());
        assert!(parse(&format!("{base}peer {pk} {ek} 10.0.0.2 not-an-endpoint")).is_err());
    }

    #[test]
    fn keepalive_directive() {
        let base = "private 0000000000000000000000000000000000000000000000000000000000000001\naddress 10.0.0.1\nlisten 0.0.0.0:1\n";
        // absent → no keepalive
        assert_eq!(parse(base).unwrap().keepalive, None);
        // a positive interval → Some(Duration)
        let c = parse(&format!("{base}keepalive 25")).unwrap();
        assert_eq!(c.keepalive, Some(Duration::from_secs(25)));
        // 0 disables (WireGuard semantics)
        assert_eq!(
            parse(&format!("{base}keepalive 0")).unwrap().keepalive,
            None
        );
        // non-numeric is an error
        assert!(parse(&format!("{base}keepalive soon")).is_err());
    }

    #[test]
    fn coordinator_directive() {
        let base = "private 0000000000000000000000000000000000000000000000000000000000000001\naddress 10.0.0.1\nlisten 0.0.0.0:1\n";
        // absent → None
        assert_eq!(parse(base).unwrap().coordinator, None);
        // valid http url
        let c = parse(&format!("{base}coordinator http://gnet.golia.jp:44520")).unwrap();
        assert_eq!(c.coordinator.as_deref(), Some("http://gnet.golia.jp:44520"));
        // trailing slash stripped (cosmetic — keeps URLs canonical for downstream concat)
        let c = parse(&format!("{base}coordinator https://example.test:443/")).unwrap();
        assert_eq!(c.coordinator.as_deref(), Some("https://example.test:443"));
        // unsupported scheme rejected
        assert!(parse(&format!("{base}coordinator ftp://x/")).is_err());
    }

    #[test]
    fn parses_dual_stack_self_and_peer() {
        let ek = ek_hex(0x22);
        let text = format!(
            "private 0000000000000000000000000000000000000000000000000000000000000001\n\
             address  10.42.42.7\n\
             address6 fd8d:f090:2ebb::7\n\
             listen 0.0.0.0:51820\n\
             peer 0000000000000000000000000000000000000000000000000000000000000002 \
                  {ek} 10.42.42.8,fd8d:f090:2ebb::8 192.168.1.5:51820\n\
             peer 0000000000000000000000000000000000000000000000000000000000000003 \
                  {ek} 10.42.42.9\n"
        );
        let c = parse(&text).expect("parse");
        assert_eq!(c.address, "10.42.42.7".parse::<IpAddr>().unwrap());
        assert_eq!(c.address6, Some("fd8d:f090:2ebb::7".parse().unwrap()));
        assert_eq!(c.peers.len(), 2);
        // dual-stack peer
        assert_eq!(c.peers[0].vip, "10.42.42.8".parse::<IpAddr>().unwrap());
        assert_eq!(c.peers[0].vip6, Some("fd8d:f090:2ebb::8".parse().unwrap()));
        assert_eq!(
            c.peers[0].endpoint,
            Some("192.168.1.5:51820".parse().unwrap())
        );
        // v4-only peer round-trips with vip6 = None
        assert_eq!(c.peers[1].vip, "10.42.42.9".parse::<IpAddr>().unwrap());
        assert_eq!(c.peers[1].vip6, None);
    }

    #[test]
    fn address6_default_none_when_absent() {
        let text = "private 0000000000000000000000000000000000000000000000000000000000000001\n\
                    address 10.42.42.7\n\
                    listen 0.0.0.0:51820\n";
        let c = parse(text).expect("parse");
        assert_eq!(c.address6, None);
    }

    #[test]
    fn address6_must_be_ipv6() {
        // v4 in address6 slot → reject
        let text = "private 0000000000000000000000000000000000000000000000000000000000000001\n\
                    address 10.42.42.7\n\
                    address6 10.0.0.1\n\
                    listen 0.0.0.0:51820\n";
        assert!(parse(text).is_err());
    }

    #[test]
    fn peer_vip_family_enforced() {
        let ek = ek_hex(0x22);
        let pk = "0000000000000000000000000000000000000000000000000000000000000002";
        let base = "private 0000000000000000000000000000000000000000000000000000000000000001\n\
                    address 10.42.42.7\n\
                    listen 0.0.0.0:51820\n";
        // v6 in vip4 slot (no comma)
        let t1 = format!("{base}peer {pk} {ek} fd00::1\n");
        assert!(parse(&t1).is_err());
        // v4 in vip6 slot (after comma)
        let t2 = format!("{base}peer {pk} {ek} 10.0.0.2,10.0.0.3\n");
        assert!(parse(&t2).is_err());
        // bad vip6 token
        let t3 = format!("{base}peer {pk} {ek} 10.0.0.2,not-an-ip\n");
        assert!(parse(&t3).is_err());
    }

    #[test]
    fn parses_ipv6_underlay() {
        let ek = ek_hex(0x22);
        let text = format!(
            "private 0000000000000000000000000000000000000000000000000000000000000001\n\
             address 10.88.0.1\n\
             listen [fd00:50::1]:7777\n\
             peer 0000000000000000000000000000000000000000000000000000000000000002 {ek} 10.88.0.2 [fd00:50::2]:7777\n"
        );
        let c = parse(&text).expect("parse");
        assert!(c.listen.is_ipv6(), "v6 underlay listen");
        assert!(
            c.peers[0].endpoint.unwrap().is_ipv6(),
            "v6 underlay endpoint"
        );
    }

    /// Randomized property test via the sibling 0-dep RNG (proptest stand-in):
    /// render a config from random identity + a random number of random peers,
    /// parse it back, and assert every field round-trips exactly.
    #[test]
    fn randomized_peer_roundtrip() {
        use std::net::Ipv4Addr;

        for _ in 0..200 {
            let private = gnet_rand::random_32();
            let address = Ipv4Addr::from(gnet_rand::random_u32());
            let listen_port = (gnet_rand::random_u32() % 65535) as u16 + 1;
            let mut text = format!(
                "private {}\naddress {address}\nlisten 0.0.0.0:{listen_port}\n",
                hex::encode(&private),
            );

            let n = (gnet_rand::random_u32() % 5) as usize;
            let mut want: Vec<PeerConfig> = Vec::with_capacity(n);
            for _ in 0..n {
                let public = gnet_rand::random_32();
                // a valid-length ek filled with fresh entropy (EK_LEN is a
                // multiple of 4, so the chunks tile exactly)
                let mut ek = [0u8; mlkem::EK_LEN];
                for chunk in ek.chunks_mut(4) {
                    chunk.copy_from_slice(&gnet_rand::random_u32().to_le_bytes());
                }
                let vip = Ipv4Addr::from(gnet_rand::random_u32());
                // roughly half the peers carry an explicit endpoint
                let endpoint = (gnet_rand::random_u32() & 1 == 0).then(|| {
                    let ip = Ipv4Addr::from(gnet_rand::random_u32());
                    let port = (gnet_rand::random_u32() % 65535) as u16 + 1;
                    SocketAddr::from((ip, port))
                });
                match endpoint {
                    Some(ep) => text.push_str(&format!(
                        "peer {} {} {vip} {ep}\n",
                        hex::encode(&public),
                        hex::encode(&ek),
                    )),
                    None => text.push_str(&format!(
                        "peer {} {} {vip}\n",
                        hex::encode(&public),
                        hex::encode(&ek),
                    )),
                }
                want.push(PeerConfig {
                    public,
                    mlkem_ek: Box::new(ek),
                    vip: IpAddr::V4(vip),
                    vip6: None,
                    endpoint,
                });
            }

            let c = parse(&text).expect("parse random config");
            assert_eq!(c.private, private);
            assert_eq!(c.address, IpAddr::V4(address));
            assert_eq!(
                c.listen,
                SocketAddr::from((Ipv4Addr::UNSPECIFIED, listen_port))
            );
            assert_eq!(c.peers, want);
        }
    }
}
