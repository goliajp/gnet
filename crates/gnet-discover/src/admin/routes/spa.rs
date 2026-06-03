//! SPA fallback — serves `console/dist/*` static assets and the SPA
//! shell for any non-API path. Parallel-copy of the console-side
//! `routes/spa.rs` (same posture as the auth / csrf / session
//! modules — see [[v1_1-handoff]]). Plan §3.4 mandates embedding the
//! same SPA bundle into all three control-plane binaries; role
//! detection is client-side via `GET /api/host-role`.
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
//! The `/api/*` routes merge BEFORE this fallback in `routes::router`,
//! so a real 404 from an API handler wins over the shell-serve.

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use include_dir::{Dir, include_dir};

use crate::admin::AdminState;

static SPA_DIST: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../console/dist");

pub fn routes() -> Router<AdminState> {
    Router::new().fallback(any(serve))
}

async fn serve(req: Request<Body>) -> Response {
    let path = req.uri().path().trim_start_matches('/');
    if !path.is_empty()
        && let Some(file) = SPA_DIST.get_file(path)
    {
        return file_response(req.uri(), file.contents());
    }
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
        .header(header::CACHE_CONTROL, cache_control_for(uri))
        .body(Body::from(body))
        .expect("static response is always valid")
}

fn cache_control_for(uri: &Uri) -> &'static str {
    if uri.path().starts_with("/assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    }
}

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
    fn embeds_at_least_the_index() {
        assert!(
            SPA_DIST.get_file("index.html").is_some(),
            "build.rs must populate console/dist/index.html"
        );
    }

    #[test]
    fn mime_known_extensions() {
        let u: Uri = "/assets/index-AbCd.js".parse().unwrap();
        assert!(guess_mime(&u).starts_with("application/javascript"));
    }
}
