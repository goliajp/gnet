//! Client IP for rate-limit buckets.
//!
//! In production the console listens on a host-local port and Caddy is
//! the only peer. Caddy (with no `trusted_proxies`) overwrites
//! `X-Forwarded-For` with the address it accepted the connection from,
//! so the rightmost entry is the real client. The header is honoured
//! only when the TCP peer itself is non-public, so a console exposed
//! directly to the internet cannot be fed a forged header.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::StatusCode;
use axum::http::request::Parts;

pub struct ClientIp(pub IpAddr);

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip())
            .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "no peer address"))?;
        if crate::egress::is_public(peer) {
            return Ok(ClientIp(peer));
        }
        let forwarded = parts
            .headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .filter_map(|s| s.trim().parse::<IpAddr>().ok())
            .next_back();
        Ok(ClientIp(forwarded.unwrap_or(peer)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn extract(peer: &str, xff: Option<&str>) -> IpAddr {
        let mut req = axum::http::Request::builder();
        if let Some(v) = xff {
            req = req.header("x-forwarded-for", v);
        }
        let (mut parts, ()) = req.body(()).unwrap().into_parts();
        parts
            .extensions
            .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        ClientIp::from_request_parts(&mut parts, &())
            .await
            .unwrap()
            .0
    }

    #[tokio::test]
    async fn private_peer_uses_rightmost_forwarded() {
        let ip = extract("172.22.0.1:5000", Some("9.9.9.9, 203.0.114.7")).await;
        assert_eq!(ip, "203.0.114.7".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn public_peer_ignores_forwarded() {
        let ip = extract("8.8.8.8:5000", Some("1.1.1.1")).await;
        assert_eq!(ip, "8.8.8.8".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn private_peer_without_header_is_peer() {
        let ip = extract("127.0.0.1:5000", None).await;
        assert_eq!(ip, "127.0.0.1".parse::<IpAddr>().unwrap());
    }
}
