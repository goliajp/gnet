use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;

use crate::error::AppError;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
}

/// Liveness probe — process is up and the router is mounted. No external
/// dependencies are checked; this returns 200 even if Postgres is
/// unreachable, so a healthy-but-degraded console doesn't get killed by a
/// transient DB blip.
async fn health() -> StatusCode {
    StatusCode::OK
}

/// Readiness probe — confirms the Postgres pool can serve a trivial query.
/// A 5xx here is the load balancer's signal to stop sending real requests.
async fn ready(State(state): State<AppState>) -> Result<StatusCode, AppError> {
    sqlx::query("SELECT 1").execute(&state.pool).await?;
    Ok(StatusCode::OK)
}
