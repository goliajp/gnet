//! Minimal async HTTP/1.1 client for warm-standby state mirroring.
//!
//! A standby coordinator polls the primary's `GET /admin/state` and overwrites
//! its own store. We hand-roll the client (tokio + httparse, no reqwest/hyper)
//! to stay inside the control-plane dependency allow-list — same rationale as
//! the server in [`crate::http`].
//!
//! Scope is deliberately tiny: plaintext HTTP only (the control plane runs on a
//! trusted segment), `Connection: close`, response read to EOF. No redirects,
//! no chunked transfer-encoding, no keep-alive, no TLS.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::state::State;

/// Hard ceiling on a single `/admin/state` response. A device table is tiny
/// (a few hundred bytes per row); 16 MiB is generous and bounds a hostile or
/// buggy primary from growing the buffer without limit.
const RESP_MAX: usize = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse: {0}")]
    Parse(#[from] httparse::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("primary url must start with http:// (got {0:?})")]
    BadScheme(String),
    #[error("primary url has no host:port authority (got {0:?})")]
    NoAuthority(String),
    #[error("primary returned HTTP {0}")]
    Status(u16),
    #[error("response exceeded {RESP_MAX} bytes")]
    TooLarge,
    #[error("malformed response")]
    Malformed,
}

pub type Result<T> = std::result::Result<T, SyncError>;

/// Pull the full device table from `primary` (`http://host:port`), authenticating
/// with the shared admin token. Returns the parsed `State`; the caller decides
/// whether to commit it (a standby overwrites its store, see `main::run`).
pub async fn fetch_state(primary: &str, admin_token: &str) -> Result<State> {
    let authority = parse_authority(primary)?;
    let mut stream = TcpStream::connect(authority).await?;

    let req = format!(
        "GET /admin/state HTTP/1.1\r\n\
         Host: {authority}\r\n\
         Authorization: Bearer {admin_token}\r\n\
         Connection: close\r\n\
         \r\n"
    );
    stream.write_all(req.as_bytes()).await?;

    // Server always replies `Connection: close`, so reading to EOF yields the
    // complete response (headers + body) with no framing ambiguity.
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 8192];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > RESP_MAX {
            return Err(SyncError::TooLarge);
        }
    }

    parse_response(&buf)
}

/// Extract the `host:port` authority from an `http://…` base URL, hand-rolled to
/// avoid the `url` crate. Everything from the first `/`, `?` or `#` onward (the
/// path/query/fragment) is discarded — we always hit a fixed path.
fn parse_authority(url: &str) -> Result<&str> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| SyncError::BadScheme(url.to_string()))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Err(SyncError::NoAuthority(url.to_string()));
    }
    Ok(authority)
}

/// Parse a complete HTTP/1.1 response, require `200`, deserialize the body as
/// `State`. Split out from [`fetch_state`] so it can be tested against fixed
/// response bytes with no socket.
fn parse_response(buf: &[u8]) -> Result<State> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);
    let header_len = match resp.parse(buf)? {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => return Err(SyncError::Malformed),
    };
    let code = resp.code.ok_or(SyncError::Malformed)?;
    if code != 200 {
        return Err(SyncError::Status(code));
    }
    let body = &buf[header_len..];
    Ok(serde_json::from_slice(body)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_authority_ipv4_with_port() {
        assert_eq!(
            parse_authority("http://10.0.0.1:65432").unwrap(),
            "10.0.0.1:65432"
        );
    }

    #[test]
    fn parse_authority_strips_path() {
        assert_eq!(
            parse_authority("http://coord.internal:65432/admin/state").unwrap(),
            "coord.internal:65432"
        );
    }

    #[test]
    fn parse_authority_ipv6_literal() {
        assert_eq!(
            parse_authority("http://[::1]:65432/x").unwrap(),
            "[::1]:65432"
        );
    }

    #[test]
    fn parse_authority_rejects_https() {
        assert!(matches!(
            parse_authority("https://10.0.0.1:65432"),
            Err(SyncError::BadScheme(_))
        ));
    }

    #[test]
    fn parse_authority_rejects_empty() {
        assert!(matches!(
            parse_authority("http:///admin/state"),
            Err(SyncError::NoAuthority(_))
        ));
    }

    #[test]
    fn parse_response_decodes_state() {
        let body = r#"{"devices":[{
            "alias":"alpha","x25519_pubkey":"pk","mlkem_ek":"ek",
            "overlay_v4":"10.42.42.2","overlay_v6":"fd8d:f090:2ebb::2",
            "endpoint":null,"device_token":"dt-alpha","relay_eligible":true,
            "created_at":"2026-01-01T00:00:00Z"
        }]}"#;
        let raw = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        let state = parse_response(raw.as_bytes()).unwrap();
        assert_eq!(state.devices.len(), 1);
        assert_eq!(state.devices[0].alias, "alpha");
        assert_eq!(state.devices[0].device_token, "dt-alpha");
        assert!(state.devices[0].relay_eligible);
    }

    #[test]
    fn parse_response_rejects_non_200() {
        let raw = "HTTP/1.1 401 Unauthorized\r\ncontent-length: 11\r\nconnection: close\r\n\r\nbad admin t";
        assert!(matches!(
            parse_response(raw.as_bytes()),
            Err(SyncError::Status(401))
        ));
    }

    #[test]
    fn parse_response_rejects_partial() {
        // headers not yet terminated → not a complete response
        let raw = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n";
        assert!(matches!(
            parse_response(raw.as_bytes()),
            Err(SyncError::Malformed)
        ));
    }
}
