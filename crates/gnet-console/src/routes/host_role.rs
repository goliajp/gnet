use axum::Json;
use axum::Router;
use axum::routing::get;
use serde::Serialize;

use crate::state::AppState;

#[derive(Serialize)]
pub struct HostRole {
    pub role: &'static str,
    pub version: &'static str,
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/api/host-role", get(host_role))
}

async fn host_role() -> Json<HostRole> {
    Json(HostRole {
        role: "console",
        version: env!("CARGO_PKG_VERSION"),
    })
}
