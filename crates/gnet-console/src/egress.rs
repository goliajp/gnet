//! Outbound HTTP to user-supplied dispatcher endpoints.
//!
//! A dispatcher endpoint is whatever URL a signed-in user typed, and
//! the proxy route returns the upstream response verbatim. Without a
//! guard that is a server-side request forgery primitive into the
//! console host: loopback services, the docker bridge, the VPC, cloud
//! metadata, the tailnet. Only globally routable unicast addresses
//! are allowed.
//!
//! The check runs at resolution time inside the HTTP client (not only
//! when the endpoint is saved), so a hostname that later re-resolves
//! to a private address is still refused. IP-literal hosts never reach
//! a resolver, so they are checked separately in [`check_url`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use reqwest::Url;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

#[derive(Debug, thiserror::Error)]
pub enum EgressError {
    #[error("dispatcher_endpoint must be an http(s) URL with a host")]
    BadUrl,
    #[error("dispatcher_endpoint resolves to a non-public address")]
    NonPublic,
    #[error("dispatcher_endpoint host does not resolve")]
    Unresolvable,
}

/// Whether `ip` is a globally routable unicast address.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..128).contains(&b)) // shared / CGNAT, tailscale
        || (a == 169 && b == 254)
        || (a == 172 && (16..32).contains(&b))
        || (a == 192 && b == 0 && c == 0) // ietf protocol assignments
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99) // 6to4 relay anycast
        || (a == 192 && b == 168)
        || (a == 198 && (18..20).contains(&b))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = embedded_v4(ip) {
        return is_public_v4(v4);
    }
    let s = ip.segments();
    // only 2000::/3 is global unicast; carve out the special blocks in it
    (s[0] & 0xe000) == 0x2000
        && !(s[0] == 0x2001 && s[1] < 0x0200) // teredo, benchmarking, orchid, …
        && !(s[0] == 0x2001 && s[1] == 0x0db8)
        && !(s[0] == 0x3fff && s[1] < 0x1000) // documentation (rfc 9637)
}

/// IPv4 addresses smuggled inside IPv6 forms that the kernel or a
/// translator will route to the embedded v4 host.
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = ip.segments();
    let tail = Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8);
    if let Some(v4) = ip.to_ipv4_mapped() {
        return Some(v4);
    }
    // ipv4-compatible ::a.b.c.d (deprecated, still parsed by some stacks)
    if s[..6] == [0; 6] && (s[6] != 0 || s[7] > 1) {
        return Some(tail);
    }
    // nat64 well-known prefix 64:ff9b::/96 and local-use 64:ff9b:1::/48
    if s[0] == 0x64 && s[1] == 0xff9b {
        return Some(tail);
    }
    // 6to4 2002:aabb:ccdd::/48
    if s[0] == 0x2002 {
        return Some(Ipv4Addr::new(
            (s[1] >> 8) as u8,
            s[1] as u8,
            (s[2] >> 8) as u8,
            s[2] as u8,
        ));
    }
    None
}

/// Validate a dispatcher endpoint URL before it is stored or used.
/// Rejects anything but http(s) with a host, and IP-literal hosts
/// that are not public. Hostnames are resolved here too so the user
/// gets an immediate error; the client re-checks on every request.
pub async fn check_url(raw: &str) -> Result<Url, EgressError> {
    let url = Url::parse(raw).map_err(|_| EgressError::BadUrl)?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(EgressError::BadUrl);
    }
    match url.host() {
        Some(url::Host::Ipv4(v4)) if is_public_v4(v4) => {}
        Some(url::Host::Ipv6(v6)) if is_public_v6(v6) => {}
        Some(url::Host::Ipv4(_) | url::Host::Ipv6(_)) => return Err(EgressError::NonPublic),
        Some(url::Host::Domain(d)) => {
            resolve_public(d).await?;
        }
        None => return Err(EgressError::BadUrl),
    }
    Ok(url)
}

/// Resolve `host` and fail unless every address is public. One private
/// record poisons the whole answer: picking only the public ones would
/// let an attacker mix records and race the connect order.
async fn resolve_public(host: &str) -> Result<Vec<SocketAddr>, EgressError> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, 0))
        .await
        .map_err(|_| EgressError::Unresolvable)?
        .collect();
    if addrs.is_empty() {
        return Err(EgressError::Unresolvable);
    }
    if addrs.iter().any(|a| !is_public(a.ip())) {
        return Err(EgressError::NonPublic);
    }
    Ok(addrs)
}

struct PublicOnly;

impl Resolve for PublicOnly {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let addrs = resolve_public(name.as_str()).await?;
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

/// HTTP client for dispatcher traffic: public-only resolution, no
/// redirects (a 30x to an internal address would bypass the resolver
/// check for IP literals), no environment proxy.
pub fn dispatcher_client() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent("gnet-console")
        .dns_resolver(Arc::new(PublicOnly))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> bool {
        is_public(s.parse().unwrap())
    }

    #[test]
    fn rejects_internal_v4() {
        for s in [
            "0.0.0.0",
            "127.0.0.1",
            "10.1.2.3",
            "100.97.189.55",
            "169.254.169.254",
            "169.254.170.2",
            "172.17.0.1",
            "172.31.11.182",
            "192.168.1.1",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!v4(s), "{s} must be rejected");
        }
    }

    #[test]
    fn accepts_public_v4() {
        for s in ["1.1.1.1", "18.179.107.143", "172.32.0.1", "100.128.0.1"] {
            assert!(v4(s), "{s} must be accepted");
        }
    }

    #[test]
    fn rejects_internal_v6_and_embedded_v4() {
        for s in [
            "::",
            "::1",
            "fe80::1",
            "fd00::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::7f00:1",
            "64:ff9b::a9fe:a9fe",
            "2002:a9fe:a9fe::1",
            "2001:db8::1",
            "2001::1",
        ] {
            assert!(!v4(s), "{s} must be rejected");
        }
    }

    #[test]
    fn accepts_public_v6() {
        assert!(v4("2606:4700:4700::1111"));
        assert!(v4("::ffff:1.1.1.1"));
    }

    #[tokio::test]
    async fn check_url_rejects_literals_and_shapes() {
        for s in [
            "http://127.0.0.1:8090",
            "http://169.254.169.254",
            "http://[::1]:80",
            "http://[::ffff:a9fe:a9fe]",
            "http://2130706433",
            "http://0x7f.1",
            "ftp://1.1.1.1",
            "http://user:pw@1.1.1.1",
            "not a url",
        ] {
            assert!(check_url(s).await.is_err(), "{s} must be rejected");
        }
        assert!(check_url("https://1.1.1.1:8443").await.is_ok());
    }

    #[tokio::test]
    async fn check_url_rejects_names_resolving_internal() {
        assert!(matches!(
            check_url("http://localhost:8090").await,
            Err(EgressError::NonPublic)
        ));
    }
}
