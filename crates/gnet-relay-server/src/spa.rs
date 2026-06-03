//! SPA fallback — serves `console/dist/*` static assets and the SPA
//! shell for any non-API path on the relay's admin server. Parallel-
//! copy of the dispatcher / console versions (plan §3.4: the same SPA
//! bundle is embedded into all three control-plane binaries; role
//! detection is client-side via `GET /api/host-role`, which the relay
//! answers `"relay"`).
//!
//! Wired into the admin router in `admin::router` after the API
//! routes, so `/api/{host-role,peers,traffic}` win on exact match and
//! everything else falls through to the SPA shell.

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
}
