//! Double-submit CSRF middleware for the console binary.
//!
//! Same shape and discipline as the dispatcher's CSRF guard
//! (`gnet-discover/src/admin/routes/csrf.rs`). Kept as a parallel copy
//! for now; both will fold into the shared `gnet-adminapi` crate after
//! the federation handshake lands and gives us a real second consumer.

use axum::extract::Request;
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;

pub const CSRF_COOKIE_NAME: &str = "gnet_csrf";
pub const CSRF_HEADER_NAME: &str = "x-csrf-token";

const EXEMPT_PATHS: &[&str] = &[
    "/",
    "/health",
    "/ready",
    "/api/host-role",
    "/api/auth/email/login",
    "/api/auth/email/register",
    // The verification link arrives in mail and is opened in a fresh
    // tab; the user may not be signed in yet, so no session cookie
    // → no CSRF cookie → no double-submit token. The token in the
    // body IS the auth factor (single-use, one-hour TTL — see
    // routes/auth.rs::verify_email).
    "/api/auth/email/verify",
    // Same reasoning as verify: forgot-password / reset-password /
    // resend-verification all come in BEFORE a session exists — the
    // user is signed out by definition. The auth factor is either
    // the URL token (reset) or the rate-limit/enumeration-flat 200
    // (forgot, resend).
    "/api/auth/email/forgot-password",
    "/api/auth/email/reset-password",
    "/api/auth/email/resend-verification",
    "/api/auth/logout",
];

/// Path prefixes exempt from CSRF: the OAuth callback flow is a
/// browser-initiated GET (callback is GET, no CSRF surface); start is
/// also GET. They live under /api/auth/oauth/ so we whitelist the
/// prefix to cover every provider without enumerating each.
const EXEMPT_PREFIXES: &[&str] = &["/api/auth/oauth/"];

pub async fn guard(req: Request, next: Next) -> Result<Response, Response> {
    if matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        return Ok(next.run(req).await);
    }
    let path = req.uri().path();
    if EXEMPT_PATHS.contains(&path) {
        return Ok(next.run(req).await);
    }
    if EXEMPT_PREFIXES.iter().any(|p| path.starts_with(p)) {
        return Ok(next.run(req).await);
    }
    let headers = req.headers().clone();
    let Some(cookie_value) = parse_cookie(&headers, CSRF_COOKIE_NAME) else {
        return Err(forbidden("missing csrf cookie"));
    };
    let Some(header_value) = headers.get(CSRF_HEADER_NAME).and_then(|v| v.to_str().ok()) else {
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

fn parse_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for piece in raw.split(';') {
        let piece = piece.trim();
        if let Some((k, v)) = piece.split_once('=')
            && k.trim() == name
        {
            return Some(v.trim().to_string());
        }
    }
    None
}

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
