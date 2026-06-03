//! Defensive HTTP response headers — parallel-copy of the console
//! version (plan §17.12 hardening sweep). The dispatcher binary
//! reads `GNET_DISCOVER_SECURE_COOKIES` for the HSTS gate; self-host
//! defaults to plain HTTP (plan §11) so HSTS is OFF by default and
//! the operator opts in when they front the binary with a TLS
//! reverse proxy.
//!
//! See `crates/gnet-console/src/routes/headers.rs` for the full
//! rationale on each header — kept word-for-word the same so a
//! single security review covers both binaries.

use axum::body::Body;
use axum::extract::Request;
use axum::http::HeaderValue;
use axum::http::header::{self, HeaderName};
use axum::middleware::Next;
use axum::response::Response;

pub async fn add_headers(req: Request<Body>, next: Next) -> Response {
    // Self-host default = plain HTTP, so HSTS is off unless the
    // operator opts in. Mode A / SaaS operators (or Mode B users
    // who front the binary with TLS) set this to `1`.
    let send_hsts = std::env::var("GNET_DISCOVER_SECURE_COOKIES")
        .map(|v| v != "0" && !v.is_empty())
        .unwrap_or(false);

    let mut resp = next.run(req).await;
    let h = resp.headers_mut();

    set_static(h, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set_static(h, header::X_FRAME_OPTIONS, "DENY");
    set_static(h, header::REFERRER_POLICY, "same-origin");
    if send_hsts {
        set_static(
            h,
            header::STRICT_TRANSPORT_SECURITY,
            "max-age=63072000; includeSubDomains",
        );
    }

    resp
}

fn set_static(headers: &mut axum::http::HeaderMap, name: HeaderName, value: &'static str) {
    headers
        .entry(name)
        .or_insert_with(|| HeaderValue::from_static(value));
}
