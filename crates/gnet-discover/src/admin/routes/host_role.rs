use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::routing::get;
use serde::Serialize;
use uuid::Uuid;

use crate::admin::AdminState;

/// What every shell of the SPA queries first to decide which UI to mount
/// (`docs/v1.1-plan.md` §3.4). `version` is the workspace version (§16.6),
/// so a console federating to a dispatcher can warn on mismatch.
#[derive(Serialize)]
pub struct HostRole {
    pub role: &'static str,
    pub version: &'static str,
    pub network_id: Uuid,
    pub network_name: String,
}

pub fn routes() -> Router<AdminState> {
    Router::new().route("/api/host-role", get(host_role))
}

async fn host_role(State(state): State<AdminState>) -> Json<HostRole> {
    Json(HostRole {
        role: "dispatcher",
        version: env!("CARGO_PKG_VERSION"),
        network_id: state.network_id,
        network_name: state.network_name,
    })
}
