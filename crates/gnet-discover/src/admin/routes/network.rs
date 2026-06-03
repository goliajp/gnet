use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::get;
use axum_extra::extract::cookie::CookieJar;
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::admin::AdminState;
use crate::admin::routes::auth::{AuthRouteError, require_login};

#[derive(Serialize)]
pub struct NetworkResponse {
    pub id: Uuid,
    pub name: String,
    /// Hex-encoded 3-byte v4 prefix (matches Config::overlay_v4_prefix in
    /// shape; e.g. `0a2a2a` for `10.42.42.0/24`).
    pub overlay_v4_prefix_hex: String,
    /// Hex-encoded 8-byte big-endian v6 prefix (four u16 words).
    pub overlay_v6_prefix_hex: String,
    pub created_at: DateTime<Utc>,
}

pub fn routes() -> Router<AdminState> {
    Router::new().route("/api/network", get(get_network))
}

async fn get_network(
    State(state): State<AdminState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<NetworkResponse>, AuthRouteError> {
    let _session = require_login(&state, &jar, &headers).await?;

    let row: (Uuid, String, Vec<u8>, Vec<u8>, DateTime<Utc>) = sqlx::query_as(
        "SELECT id, name, overlay_v4_prefix, overlay_v6_prefix, created_at \
         FROM networks WHERE id = $1",
    )
    .bind(state.network_id)
    .fetch_one(&state.pool)
    .await?;

    Ok(Json(NetworkResponse {
        id: row.0,
        name: row.1,
        overlay_v4_prefix_hex: gnet_hex::encode(&row.2),
        overlay_v6_prefix_hex: gnet_hex::encode(&row.3),
        created_at: row.4,
    }))
}
