use axum::Json;
use axum::Router;
use axum::routing::get;
use serde::Serialize;

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/", get(index))
}

#[derive(Serialize)]
struct Index {
    service: &'static str,
    version: &'static str,
    phase: &'static str,
}

/// Root-path banner — confirms the binary is what you think it is.
/// Real UI lives at `console/` (Vite SPA, embedded in 1.1-E).
async fn index() -> Json<Index> {
    Json(Index {
        service: "gnet-console",
        version: env!("CARGO_PKG_VERSION"),
        phase: "1.1-B",
    })
}
