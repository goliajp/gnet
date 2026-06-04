//! SPA fallback — serves `console/dist/*` static assets and the SPA
//! shell for any non-API path (plan §3.4: the same SPA build is
//! embedded into the dispatcher / console / relay binaries; the role
//! detection happens client-side via `GET /api/host-role`).
//!
//! Lookup order on every request:
//!
//! 1. Exact match on the URL path under `SPA_DIST` (so `/assets/x.js`
//!    resolves to the file at that relative path).
//! 2. Otherwise serve `index.html` — the SPA's single shell — so deep
//!    links like `/networks/<uuid>` boot the SPA and let
//!    `react-router` resolve the route. This is the "history-mode
//!    fallback" that every SPA framework asks the server to do.
//!
//! The `/api/*` routes are merged BEFORE this fallback in
//! `routes::router`, so a real 404 from an API handler wins over the
//! shell-serve; a request to a path that doesn't start with `/api/`
//! and doesn't hit a real asset gets `index.html` and a 200, which is
//! what the SPA expects to bootstrap on a deep link.
//!
//! Code is intentionally parallel-copied between the console and
//! dispatcher (same posture as the auth / csrf / session modules — see
//! [[v1_1-handoff]]); the relay binary uses its own copy under
//! `crates/gnet-relay-server/src/admin/spa.rs`.

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use include_dir::{Dir, include_dir};

use crate::state::AppState;

/// The SPA bundle as built by `bun run build` in `console/`. A
/// pre-build stub from `build.rs` keeps the macro happy when the
/// operator hasn't run the SPA build yet (see `build.rs`).
static SPA_DIST: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../console/dist");

pub fn routes() -> Router<AppState> {
    Router::new().fallback(any(serve))
}

async fn serve(req: Request<Body>) -> Response {
    // Strip the leading `/`. include_dir's lookup is relative to the
    // embedded root, and `Path::new("/x")` would escape that root on
    // unix.
    let path = req.uri().path().trim_start_matches('/');

    // Exact-file hit: return that file with the right Content-Type.
    if !path.is_empty()
        && let Some(file) = SPA_DIST.get_file(path)
    {
        return file_response(req.uri(), file.contents());
    }

    // SPA shell — fallback for deep links. If even `index.html` is
    // absent (catastrophic: build.rs failed) return a plain 404 so
    // monitoring catches it.
    match SPA_DIST.get_file("index.html") {
        Some(index) => file_response(req.uri(), index.contents()),
        None => (StatusCode::NOT_FOUND, "SPA not embedded").into_response(),
    }
}

fn file_response(uri: &Uri, body: &'static [u8]) -> Response {
    let mime = guess_mime(uri);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CONTENT_LENGTH, body.len())
        // Vite hashes its asset filenames (`/assets/index-<hash>.js`),
        // so cached responses are safe to keep for a long time; the
        // shell `index.html` itself must not be cached aggressively
        // (a new SPA build changes the asset hashes referenced inside
        // but keeps the shell URL stable — clients refetch on every
        // load to pick the new hashes).
        .header(header::CACHE_CONTROL, cache_control_for(uri))
        .body(Body::from(body))
        .expect("static response is always valid")
}

fn cache_control_for(uri: &Uri) -> &'static str {
    let p = uri.path();
    if p.starts_with("/assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    }
}

/// Minimal content-type table. We only generate the asset shapes the
/// SPA bundler emits (JS, CSS, HTML, fonts, images) — anything else
/// falls back to `application/octet-stream`. Pinning the table
/// here keeps the binary independent of a runtime MIME-DB crate.
fn guess_mime(uri: &Uri) -> &'static str {
    let p = uri.path();
    let ext = match p.rsplit_once('.') {
        Some((_, e)) => e,
        None => "",
    };
    match ext.to_ascii_lowercase().as_str() {
        "html" | "htm" | "" => "text/html; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "map" => "application/json; charset=utf-8",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mime_known_extensions() {
        for (path, expected_starts_with) in [
            ("/assets/index-AbCd.js", "application/javascript"),
            ("/assets/index-AbCd.css", "text/css"),
            ("/index.html", "text/html"),
            ("/favicon.ico", "image/x-icon"),
            ("/logo.svg", "image/svg+xml"),
            ("/font.woff2", "font/woff2"),
        ] {
            let u: Uri = path.parse().unwrap();
            let mime = guess_mime(&u);
            assert!(mime.starts_with(expected_starts_with), "{path} -> {mime}");
        }
    }

    #[test]
    fn cache_control_assets_immutable_otherwise_no_cache() {
        let assets: Uri = "/assets/index-abcd.js".parse().unwrap();
        let shell: Uri = "/networks/anything".parse().unwrap();
        assert!(cache_control_for(&assets).contains("immutable"));
        assert_eq!(cache_control_for(&shell), "no-cache");
    }

    #[test]
    fn embeds_at_least_the_index() {
        // build.rs guarantees an index.html (either real SPA build or stub).
        assert!(
            SPA_DIST.get_file("index.html").is_some(),
            "build.rs must populate console/dist/index.html"
        );
    }
}
