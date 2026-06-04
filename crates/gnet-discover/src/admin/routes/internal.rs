//! Internal endpoints — node-facing, bearer-authenticated.
//!
//! These are NOT admin endpoints. They're the dispatcher side of the
//! daemon's push channel (plan §17 step 4): a daemon periodically POSTs
//! an admin snapshot here, authenticated by the same `device_token` it
//! already uses on the coord's `/endpoint-report`. No cookie session, no
//! CSRF (the daemon isn't a browser).
//!
//! The CSRF guard exempts `/api/internal/*` by prefix (see
//! `routes/csrf.rs::EXEMPT_PATHS`); the auth here is purely
//! `Authorization: Bearer <token_hex>`.

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use serde::Deserialize;
use serde_json::Value as Json_;
use uuid::Uuid;

use crate::admin::AdminState;

#[derive(Deserialize)]
pub struct SnapshotRequest {
    /// 64-char hex of the device's X25519 pubkey. Used together with the
    /// bearer token to look up the exact row this snapshot belongs to —
    /// two-factor lookup avoids a stolen device_token from another row
    /// authenticating as this device.
    pub device_pubkey_hex: String,
    /// Arbitrary JSON the daemon wants to record. v1.1 doesn't fix a
    /// schema yet — what the daemon sends today goes straight into
    /// `device_snapshots.snapshot` as a JSONB blob; the schema gets
    /// formalised when the SPA starts rendering it.
    pub snapshot: Json_,
}

#[derive(Debug, thiserror::Error)]
pub enum InternalError {
    #[error("missing or malformed Authorization header")]
    NoBearer,
    #[error("device pubkey hex did not decode")]
    BadPubkey,
    #[error("no device matched the token + pubkey")]
    Unauthorized,
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
}

impl IntoResponse for InternalError {
    fn into_response(self) -> Response {
        let code = match self {
            InternalError::NoBearer | InternalError::Unauthorized | InternalError::BadPubkey => {
                StatusCode::UNAUTHORIZED
            }
            InternalError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (code, self.to_string()).into_response()
    }
}

pub fn routes() -> Router<AdminState> {
    Router::new().route("/api/internal/snapshot", post(snapshot))
}

async fn snapshot(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(req): Json<SnapshotRequest>,
) -> Result<StatusCode, InternalError> {
    let token = bearer(&headers).ok_or(InternalError::NoBearer)?;
    // Hash the bearer bytes verbatim — matches the v1.0 `/endpoint-report`
    // wire (the daemon sends whatever `device_token` the coordinator
    // returned at `/join`; dispatcher stored SHA3-256 of those same bytes
    // at import time). No hex-decode dance.
    let token_hash = gnet_crypto::sha3::sha3_256(token.as_bytes());

    let pubkey_raw = gnet_hex::decode_32(&req.device_pubkey_hex).ok_or(InternalError::BadPubkey)?;

    // Two-factor lookup: a stolen token alone is not enough; the row's
    // x25519_pubkey must match too. (And we scope by network_id, since
    // each device belongs to exactly one network in v1.1.) A kicked row
    // (`removed_at IS NOT NULL`) is treated as if it didn't exist, so a
    // device that's been kicked stops being able to push snapshots —
    // the daemon sees 401 and stays disconnected until it re-registers.
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM devices \
         WHERE network_id = $1 \
           AND x25519_pubkey = $2 \
           AND device_token_hash = $3 \
           AND removed_at IS NULL",
    )
    .bind(state.network_id)
    .bind(&pubkey_raw[..])
    .bind(&token_hash[..])
    .fetch_optional(&state.pool)
    .await?;

    let (device_id,) = row.ok_or(InternalError::Unauthorized)?;

    sqlx::query(
        "INSERT INTO device_snapshots (device_id, taken_at, snapshot) \
         VALUES ($1, now(), $2)",
    )
    .bind(device_id)
    .bind(&req.snapshot)
    .execute(&state.pool)
    .await?;

    sqlx::query("UPDATE devices SET last_seen_at = now() WHERE id = $1")
        .bind(device_id)
        .execute(&state.pool)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let rest = v
        .strip_prefix("Bearer ")
        .or_else(|| v.strip_prefix("bearer "))?;
    let rest = rest.trim();
    if rest.is_empty() { None } else { Some(rest) }
}

#[cfg(test)]
mod tests {
    use super::bearer;
    use axum::http::{HeaderMap, HeaderValue, header};

    fn h(v: &str) -> HeaderMap {
        let mut m = HeaderMap::new();
        m.insert(header::AUTHORIZATION, HeaderValue::from_str(v).unwrap());
        m
    }

    #[test]
    fn bearer_picks_token() {
        assert_eq!(bearer(&h("Bearer abc")), Some("abc"));
        assert_eq!(bearer(&h("bearer  abc ")), Some("abc"));
    }

    #[test]
    fn bearer_rejects_garbage() {
        assert!(bearer(&HeaderMap::new()).is_none());
        assert!(bearer(&h("abc")).is_none());
        assert!(bearer(&h("Bearer ")).is_none());
    }
}
