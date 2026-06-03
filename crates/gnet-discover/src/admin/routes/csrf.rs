//! Double-submit-cookie CSRF guard.
//!
//! On each successful login, the dispatcher issues two cookies in the same
//! response:
//!
//! - `gnet_sess` — HttpOnly, the bearer for [`super::auth::require_login`].
//! - `gnet_csrf` — **not** HttpOnly so the SPA can read it from JS and
//!   mirror it into an `X-Csrf-Token` request header.
//!
//! This middleware enforces that every state-changing request carries
//! both cookies with matching values. A cross-origin attacker who can
//! make the browser send `gnet_sess` (e.g. via `<img src=…>` ignored;
//! `SameSite=Lax` already blocks form posts cross-site) still cannot
//! read `gnet_csrf` to forge the header.
//!
//! The guard is intentionally a pure same-cookie-same-header comparison
//! — no Valkey lookup on the hot path. Token is rotated on every login.
//!
//! Skipped:
//! - safe methods (`GET`, `HEAD`, `OPTIONS`)
//! - unauthenticated endpoints (`/api/host-role`, `/api/auth/login`,
//!   `/api/auth/setup`, `/api/auth/logout`)

use axum::extract::Request;
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;

/// The cookie + header pair carrying the CSRF token.
pub const CSRF_COOKIE_NAME: &str = "gnet_csrf";
pub const CSRF_HEADER_NAME: &str = "x-csrf-token";

/// Paths that are exempt from CSRF: pre-auth surfaces + logout (which a
/// cross-site attacker can at worst trigger, with the only effect being
/// that the user has to sign in again).
const EXEMPT_PATHS: &[&str] = &[
    "/api/host-role",
    "/api/auth/login",
    "/api/auth/setup",
    "/api/auth/logout",
];

pub async fn guard(req: Request, next: Next) -> Result<Response, Response> {
    if matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        return Ok(next.run(req).await);
    }
    if EXEMPT_PATHS.contains(&req.uri().path()) {
        return Ok(next.run(req).await);
    }

    let headers = req.headers();
    let Some(cookie_value) = parse_cookie(headers, CSRF_COOKIE_NAME) else {
        return Err(forbidden("missing csrf cookie"));
    };
    let Some(header_value) = headers
        .get(CSRF_HEADER_NAME)
        .and_then(|v| v.to_str().ok())
    else {
        return Err(forbidden("missing csrf header"));
    };

    if !ct_eq(cookie_value.as_bytes(), header_value.as_bytes()) {
        return Err(forbidden("csrf mismatch"));
    }

    Ok(next.run(req).await)
}

fn forbidden(why: &'static str) -> Response {
    use axum::response::IntoResponse;
    (StatusCode::FORBIDDEN, why).into_response()
}

/// Extract one cookie value from the `Cookie` header. Returns `None` if
/// the header is absent, non-UTF-8, or the requested name isn't present.
fn parse_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for piece in raw.split(';') {
        let piece = piece.trim();
        if let Some((k, v)) = piece.split_once('=') {
            if k.trim() == name {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// Constant-time byte equality, used so token verification doesn't leak
/// the matching-prefix length through timing. Standard fold-XOR.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_headers(cookie: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(c) = cookie {
            h.insert(header::COOKIE, c.parse().unwrap());
        }
        h
    }

    #[test]
    fn parse_cookie_picks_named_value() {
        let h = make_headers(Some("foo=1; gnet_csrf=abc; bar=2"));
        assert_eq!(parse_cookie(&h, "gnet_csrf"), Some("abc".into()));
        assert_eq!(parse_cookie(&h, "foo"), Some("1".into()));
        assert_eq!(parse_cookie(&h, "missing"), None);
    }

    #[test]
    fn parse_cookie_handles_missing_header() {
        let h = make_headers(None);
        assert_eq!(parse_cookie(&h, "gnet_csrf"), None);
    }

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(ct_eq(b"", b""));
    }
}
