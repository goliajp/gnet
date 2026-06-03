use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::get;
use axum_extra::extract::cookie::CookieJar;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

use crate::admin::AdminState;
use crate::admin::routes::auth::{AuthRouteError, require_login};

/// SPA-facing device shape. All BYTEA / INET columns are SQL-side
/// `encode(…, 'hex')` or `::text` cast so the JSON values are plain
/// strings the SPA can render without further decoding.
#[derive(Serialize, FromRow)]
pub struct DeviceResponse {
    pub id: Uuid,
    pub alias: String,
    pub x25519_pubkey_hex: String,
    pub vip_v4: String,
    pub vip_v6: String,
    pub relay_eligible: bool,
    pub last_reflexive: Option<String>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

pub fn routes() -> Router<AdminState> {
    Router::new().route("/api/devices", get(list_devices))
}

async fn list_devices(
    State(state): State<AdminState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<Vec<DeviceResponse>>, AuthRouteError> {
    let _session = require_login(&state, &jar, &headers).await?;

    // INET is cast to text because we didn't enable sqlx-postgres's
    // `ipnetwork` feature — and we never operate numerically on the vip
    // anyway, the SPA just renders it.
    let rows: Vec<DeviceResponse> = sqlx::query_as(
        "SELECT id, alias, \
                encode(x25519_pubkey, 'hex') AS x25519_pubkey_hex, \
                vip_v4::text AS vip_v4, \
                vip_v6::text AS vip_v6, \
                relay_eligible, last_reflexive, last_seen_at, created_at \
         FROM devices \
         WHERE network_id = $1 AND removed_at IS NULL \
         ORDER BY alias",
    )
    .bind(state.network_id)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(rows))
}
