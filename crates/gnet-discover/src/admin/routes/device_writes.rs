//! Device write paths (plan §17 step 7).
//!
//! - `rename`  PUT  /api/devices/{id}/alias     — already lived here
//! - `kick`    POST /api/devices/{id}/kick      — soft-delete + audit
//! - `rotate_key` POST /api/devices/{id}/rotate-key — 501 wire contract
//! - `restart` POST /api/devices/{id}/restart   — 501 wire contract
//!
//! Kick is a DB-only operation. We mark `devices.removed_at = now()`
//! inside a transaction with the matching audit row; the partial
//! unique indexes added in migration 0003 keep the (network, pubkey)
//! and (network, alias) slots free so the same device can re-register
//! after a kick, and `/api/internal/snapshot` filters on `removed_at
//! IS NULL` so the kicked daemon's next push gets 401 — that's how
//! "kick" becomes a daemon-visible event without a dispatcher→daemon
//! control channel.
//!
//! Rotate-key and restart need such a channel (plan §5.2: "forwarded
//! to the daemon via the relay or via a future control channel"); the
//! routes are stubbed with 501 so the SPA can wire them up against a
//! stable URL surface that v1.2 fills in.
//!
//! All writes:
//! - require a logged-in admin session (cookie + CSRF, already
//!   enforced by surrounding middleware);
//! - run inside a single transaction with the corresponding
//!   `audit_log` insert, so we never get a state change without its
//!   audit trail.

use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{post, put};
use axum_extra::extract::cookie::CookieJar;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::admin::AdminState;
use crate::admin::routes::auth::{AuthRouteError, require_login};
use crate::admin::routes::devices::DeviceResponse;

#[derive(Deserialize)]
pub struct UpdateAliasRequest {
    pub alias: String,
}

#[derive(Serialize, FromRow)]
struct AliasRow {
    id: Uuid,
    alias: String,
}

#[derive(Serialize, FromRow)]
struct KickRow {
    id: Uuid,
    alias: String,
    x25519_pubkey_hex: String,
}

#[derive(Debug, thiserror::Error)]
pub enum DeviceWriteError {
    #[error("not logged in")]
    NotLoggedIn,
    #[error("device not found")]
    NotFound,
    #[error("alias must be 3-32 chars of [a-z0-9_-]")]
    BadAlias,
    #[error("alias already in use in this network")]
    AliasConflict,
    #[error("session store: {0}")]
    Session(#[from] crate::admin::session::SessionError),
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    #[error("cache: {0}")]
    Cache(#[from] redis::RedisError),
}

impl From<AuthRouteError> for DeviceWriteError {
    fn from(e: AuthRouteError) -> Self {
        match e {
            AuthRouteError::NotLoggedIn => DeviceWriteError::NotLoggedIn,
            AuthRouteError::BadCreds => DeviceWriteError::NotLoggedIn,
            // Device-write callers come in already authenticated;
            // a Throttle here would mean a downstream re-auth path
            // hit the bucket. Surface as 401 — the SPA falls back
            // to the login flow which then emits the proper 429.
            AuthRouteError::Throttled { .. } => DeviceWriteError::NotLoggedIn,
            AuthRouteError::Session(s) => DeviceWriteError::Session(s),
            AuthRouteError::Db(d) => DeviceWriteError::Db(d),
            AuthRouteError::Cache(c) => DeviceWriteError::Cache(c),
        }
    }
}

impl IntoResponse for DeviceWriteError {
    fn into_response(self) -> Response {
        let code = match self {
            DeviceWriteError::NotLoggedIn => StatusCode::UNAUTHORIZED,
            DeviceWriteError::NotFound => StatusCode::NOT_FOUND,
            DeviceWriteError::BadAlias => StatusCode::BAD_REQUEST,
            DeviceWriteError::AliasConflict => StatusCode::CONFLICT,
            DeviceWriteError::Session(_) | DeviceWriteError::Db(_) | DeviceWriteError::Cache(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        (code, self.to_string()).into_response()
    }
}

pub fn routes() -> Router<AdminState> {
    Router::new()
        .route("/api/devices/{id}/alias", put(rename))
        .route("/api/devices/{id}/kick", post(kick))
        .route("/api/devices/{id}/rotate-key", post(rotate_key))
        .route("/api/devices/{id}/restart", post(restart))
}

async fn rename(
    State(state): State<AdminState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(device_id): Path<Uuid>,
    Json(req): Json<UpdateAliasRequest>,
) -> Result<Json<DeviceResponse>, DeviceWriteError> {
    let session = require_login(&state, &jar, &headers).await?;

    if !valid_alias(&req.alias) {
        return Err(DeviceWriteError::BadAlias);
    }

    let mut tx = state.pool.begin().await?;

    let existing: Option<AliasRow> = sqlx::query_as(
        "SELECT id, alias FROM devices \
         WHERE network_id = $1 AND id = $2 AND removed_at IS NULL \
         FOR UPDATE",
    )
    .bind(state.network_id)
    .bind(device_id)
    .fetch_optional(&mut *tx)
    .await?;
    let prev = existing.ok_or(DeviceWriteError::NotFound)?;

    let update = sqlx::query("UPDATE devices SET alias = $1 WHERE id = $2")
        .bind(&req.alias)
        .bind(prev.id)
        .execute(&mut *tx)
        .await;
    match update {
        Ok(_) => {}
        Err(sqlx::Error::Database(db_err)) if db_err.code().as_deref() == Some("23505") => {
            return Err(DeviceWriteError::AliasConflict);
        }
        Err(other) => return Err(other.into()),
    }

    let detail = serde_json::json!({ "from": prev.alias, "to": req.alias });
    sqlx::query(
        "INSERT INTO audit_log (network_id, actor_kind, actor_id, action, target, detail) \
         VALUES ($1, 'local_admin', $2, 'device.rename', $3, $4)",
    )
    .bind(state.network_id)
    .bind(session.user_id.to_string())
    .bind(device_id.to_string())
    .bind(&detail)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    let updated: DeviceResponse = sqlx::query_as(
        "SELECT id, alias, \
                encode(x25519_pubkey, 'hex') AS x25519_pubkey_hex, \
                vip_v4::text AS vip_v4, \
                vip_v6::text AS vip_v6, \
                relay_eligible, last_reflexive, last_seen_at, created_at \
         FROM devices WHERE id = $1",
    )
    .bind(device_id)
    .fetch_one(&state.pool)
    .await?;
    Ok(Json(updated))
}

/// Soft-delete: stamp `removed_at = now()` and write the audit row in
/// the same tx. A second kick on the same id returns 404 (the row is
/// no longer visible to the same `removed_at IS NULL` predicate), so
/// the operation is idempotent only by virtue of the 404 being safe
/// to ignore on the caller side.
async fn kick(
    State(state): State<AdminState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(device_id): Path<Uuid>,
) -> Result<StatusCode, DeviceWriteError> {
    let session = require_login(&state, &jar, &headers).await?;

    let mut tx = state.pool.begin().await?;

    let existing: Option<KickRow> = sqlx::query_as(
        "SELECT id, alias, encode(x25519_pubkey, 'hex') AS x25519_pubkey_hex \
         FROM devices \
         WHERE network_id = $1 AND id = $2 AND removed_at IS NULL \
         FOR UPDATE",
    )
    .bind(state.network_id)
    .bind(device_id)
    .fetch_optional(&mut *tx)
    .await?;
    let prev = existing.ok_or(DeviceWriteError::NotFound)?;

    sqlx::query("UPDATE devices SET removed_at = now() WHERE id = $1")
        .bind(prev.id)
        .execute(&mut *tx)
        .await?;

    let detail = serde_json::json!({
        "alias": prev.alias,
        "x25519_pubkey_hex": prev.x25519_pubkey_hex,
    });
    sqlx::query(
        "INSERT INTO audit_log (network_id, actor_kind, actor_id, action, target, detail) \
         VALUES ($1, 'local_admin', $2, 'device.kick', $3, $4)",
    )
    .bind(state.network_id)
    .bind(session.user_id.to_string())
    .bind(device_id.to_string())
    .bind(&detail)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}

/// 501 wire contract. The dispatcher decision is just a row edit, but
/// the daemon needs to acknowledge the new key before we can flip the
/// active row — that needs a dispatcher→daemon control channel that
/// v1.1 doesn't ship.
async fn rotate_key(
    State(state): State<AdminState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(device_id): Path<Uuid>,
) -> Result<Response, DeviceWriteError> {
    let _ = (require_login(&state, &jar, &headers).await?, device_id);
    Ok(not_implemented_v1_2("rotate_key"))
}

/// 501 wire contract. Restart needs the dispatcher→daemon control
/// channel (plan §5.2: "forwarded to the daemon via the relay or via
/// a future control channel"); v1.1 only carries the URL.
async fn restart(
    State(state): State<AdminState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(device_id): Path<Uuid>,
) -> Result<Response, DeviceWriteError> {
    let _ = (require_login(&state, &jar, &headers).await?, device_id);
    Ok(not_implemented_v1_2("restart"))
}

fn not_implemented_v1_2(op: &'static str) -> Response {
    let body = serde_json::json!({
        "not_implemented": op,
        "ships_in": "v1.2",
        "reason": "needs dispatcher→daemon control channel",
    });
    (StatusCode::NOT_IMPLEMENTED, Json(body)).into_response()
}

fn valid_alias(s: &str) -> bool {
    let len = s.len();
    if !(3..=32).contains(&len) {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

#[allow(dead_code)]
fn _force_imports() -> Option<DateTime<Utc>> {
    None
}

#[cfg(test)]
mod tests {
    use super::valid_alias;

    #[test]
    fn alias_rules_match_username() {
        assert!(valid_alias("alpha"));
        assert!(valid_alias("node-01"));
        assert!(!valid_alias("ab"));
        assert!(!valid_alias("Has Caps"));
        assert!(!valid_alias("dot.name"));
        assert!(!valid_alias(&"x".repeat(33)));
    }
}
