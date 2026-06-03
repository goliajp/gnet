//! Defensive HTTP response headers — applied uniformly to every
//! response leaving the console (plan §17.12 hardening sweep). The
//! middleware adds the well-understood, low-risk headers; it
//! deliberately stops short of `Content-Security-Policy` (which
//! needs the SPA's exact asset shape to be useful without breaking
//! it) and `Permissions-Policy` (still in flux; revisit in v1.2).
//!
//! Headers added:
//!
//! - `X-Content-Type-Options: nosniff` — kills the browser's MIME
//!   sniff fallback. The SPA fallback router already returns a
//!   correct `Content-Type` per asset; this header makes that the
//!   only Content-Type interpretation a browser will honour.
//!
//! - `X-Frame-Options: DENY` — refuses to render the console inside
//!   a frame, blunting clickjacking. We don't embed our own UI in
//!   anyone else's page and nothing else embeds ours.
//!
//! - `Referrer-Policy: same-origin` — third-party links the SPA
//!   opens (OAuth redirects, marketing exits) see only the apex
//!   origin, not the full URL with network slug + path.
//!
//! - `Strict-Transport-Security: max-age=63072000; includeSubDomains`
//!   — added only when `GNET_CONSOLE_SECURE_COOKIES` is on (the same
//!   gate that makes cookies `Secure`). Two years matches what
//!   Chrome's HSTS preload list asks for; the apex + the per-network
//!   wildcard subdomains all share TLS so `includeSubDomains` is
//!   correct.
//!
//! The middleware is the LAST layer in `routes::router` so its
//! headers ride on top of anything an inner handler might have set
//! (and the inner handler's headers win if they collide, which they
//! shouldn't for any of the names above).

use axum::body::Body;
use axum::extract::Request;
use axum::http::HeaderValue;
use axum::http::header::{self, HeaderName};
use axum::middleware::Next;
use axum::response::Response;

pub async fn add_headers(req: Request<Body>, next: Next) -> Response {
    // Read the HSTS gate once per request from env — same env var
    // the auth layer reads to decide cookie `Secure`. We don't
    // cache here because the cost is one `env::var` per request
    // and the value is immutable for the process lifetime.
    let send_hsts = std::env::var("GNET_CONSOLE_SECURE_COOKIES")
        .map(|v| v != "0" && !v.is_empty())
        .unwrap_or(true);

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
    // Only insert if the inner handler didn't already set it (so a
    // route that wants a different policy on a single endpoint can
    // still win).
    headers
        .entry(name)
        .or_insert_with(|| HeaderValue::from_static(value));
}

// Note: in-isolation unit tests for axum `middleware::from_fn`
// require constructing a `Next` — its constructor is crate-private
// in axum 0.8. The middleware is exercised end-to-end via the
// router-level integration tests in `crates/gnet-discover/tests/`
// once those land (plan §17.12 follow-up); for now its surface is
// small enough that a code-review pass is the cost-effective
// guard.
