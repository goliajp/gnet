//! Internal endpoints — node-facing, bearer-authenticated.
//!
//! These are NOT admin endpoints. They're the dispatcher side of the
//! daemon's push channel (plan §17 step 4, extended in §18.A1 / v1.2-plan
//! §5.2): a daemon periodically POSTs an admin snapshot here, authenticated
//! by the same `device_token` it already uses on the coord's
//! `/endpoint-report`. No cookie session, no CSRF (the daemon isn't a
//! browser).
//!
//! The CSRF guard exempts `/api/internal/*` by prefix (see
//! `routes/csrf.rs::EXEMPT_PATHS`); the auth here is purely
//! `Authorization: Bearer <token_hex>`.
//!
//! Surface:
//! - `POST /api/internal/snapshot`     — record snapshot, drain pending ops
//! - `POST /api/internal/snapshot/ack` — daemon reports per-op result

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json_;
use sqlx::PgPool;
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

/// Body of a 200 snapshot reply (v1.2-plan §5.2). An empty queue stays a
/// 204 No Content so v1.1 daemons that don't know about the reply body
/// keep working unchanged; this struct is only serialised when at least
/// one op was drained.
#[derive(Serialize)]
pub struct SnapshotReply {
    pub ops: Vec<PendingOp>,
}

#[derive(Serialize)]
pub struct PendingOp {
    pub op_id: Uuid,
    pub op: String,
    pub args: Json_,
}

/// Daemon's rotate-key follow-up (v1.2-plan §18.A3.2). The daemon
/// generated `new_pubkey_hex` locally, persisted the new private key,
/// and is asking the dispatcher to atomically commit the new pubkey
/// and finalise the matching pending op in one tx. Same auth as the
/// snapshot push (token + OLD pubkey), so a stolen token alone is
/// not enough to rewrite a device's pubkey.
#[derive(Deserialize)]
pub struct RotateKeyCompleteRequest {
    /// Old pubkey hex (the one the row currently has). Two-factor
    /// lookup confirms the caller is the device that owns this row.
    pub device_pubkey_hex: String,
    /// The pending op being completed. Must belong to the same device.
    pub op_id: Uuid,
    /// Hex-encoded fresh 32-byte X25519 public key.
    pub new_pubkey_hex: String,
}

/// Daemon's per-op acknowledgement.
#[derive(Deserialize)]
pub struct AckRequest {
    /// Same two-factor identifier the snapshot push uses — a stolen
    /// device_token from another row should not be able to ack ops
    /// scheduled against this row.
    pub device_pubkey_hex: String,
    pub op_id: Uuid,
    pub status: AckStatus,
    /// Free-text detail, only consulted when status=error. Truncated to
    /// 1 KiB on insert so a runaway daemon can't blow up the audit row.
    #[serde(default)]
    pub detail: Option<String>,
}

#[derive(Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum AckStatus {
    Ok,
    Error,
}

#[derive(Debug, thiserror::Error)]
pub enum InternalError {
    #[error("missing or malformed Authorization header")]
    NoBearer,
    #[error("device pubkey hex did not decode")]
    BadPubkey,
    #[error("new pubkey hex did not decode")]
    BadNewPubkey,
    #[error("new pubkey already in use in this network")]
    PubkeyConflict,
    #[error("no device matched the token + pubkey")]
    Unauthorized,
    #[error("op_id does not belong to this device or is already finalised")]
    UnknownOp,
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
}

impl IntoResponse for InternalError {
    fn into_response(self) -> Response {
        let code = match self {
            InternalError::NoBearer | InternalError::Unauthorized | InternalError::BadPubkey => {
                StatusCode::UNAUTHORIZED
            }
            InternalError::BadNewPubkey => StatusCode::BAD_REQUEST,
            InternalError::PubkeyConflict => StatusCode::CONFLICT,
            InternalError::UnknownOp => StatusCode::NOT_FOUND,
            InternalError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (code, self.to_string()).into_response()
    }
}

pub fn routes() -> Router<AdminState> {
    Router::new()
        .route("/api/internal/snapshot", post(snapshot))
        .route("/api/internal/snapshot/ack", post(snapshot_ack))
        .route("/api/internal/rotate_key/complete", post(rotate_key_complete))
}

async fn snapshot(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(req): Json<SnapshotRequest>,
) -> Result<Response, InternalError> {
    let device_id = authenticate(&state.pool, state.network_id, &headers, &req.device_pubkey_hex).await?;

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

    // Drain pending ops for this device. CTE picks the oldest 32 pending
    // rows, the UPDATE stamps `delivered_at`, the outer SELECT re-orders
    // by `created_at` because Postgres does NOT guarantee that
    // `UPDATE … RETURNING` emits rows in the inner subquery's ORDER BY
    // — and v1.2-plan §5.2 says "the daemon executes them in order", so
    // wire order must match queue order.
    //
    // `delivered_at` is stamped before ack so an in-flight delivery that
    // crashes the daemon mid-run does NOT get redelivered until the row
    // is also explicitly failed or completed (intentional — we'd rather
    // a stuck op be visible than silently looped).
    //
    // LIMIT 32 caps one push's payload — well above any real backlog,
    // but stops a malformed accumulator from producing a huge 200 reply.
    let rows: Vec<PendingOpRow> = sqlx::query_as(
        "WITH picked AS ( \
             SELECT id, created_at FROM device_pending_ops \
             WHERE device_id = $1 \
               AND completed_at IS NULL \
               AND failed_at IS NULL \
             ORDER BY created_at \
             LIMIT 32 \
         ), updated AS ( \
             UPDATE device_pending_ops \
             SET delivered_at = now() \
             WHERE id IN (SELECT id FROM picked) \
             RETURNING id, op, args, created_at \
         ) \
         SELECT id, op, args FROM updated ORDER BY created_at",
    )
    .bind(device_id)
    .fetch_all(&state.pool)
    .await?;

    if rows.is_empty() {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }

    let reply = SnapshotReply {
        ops: rows
            .into_iter()
            .map(|r| PendingOp {
                op_id: r.id,
                op: r.op,
                args: r.args,
            })
            .collect(),
    };
    Ok((StatusCode::OK, Json(reply)).into_response())
}

#[derive(sqlx::FromRow)]
struct PendingOpRow {
    id: Uuid,
    op: String,
    args: Json_,
}

async fn snapshot_ack(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(req): Json<AckRequest>,
) -> Result<StatusCode, InternalError> {
    let device_id = authenticate(&state.pool, state.network_id, &headers, &req.device_pubkey_hex).await?;

    let affected = match req.status {
        AckStatus::Ok => {
            sqlx::query(
                "UPDATE device_pending_ops \
                 SET completed_at = now() \
                 WHERE id = $1 \
                   AND device_id = $2 \
                   AND completed_at IS NULL \
                   AND failed_at IS NULL",
            )
            .bind(req.op_id)
            .bind(device_id)
            .execute(&state.pool)
            .await?
            .rows_affected()
        }
        AckStatus::Error => {
            // last_error is operator-visible; truncate so a runaway daemon
            // can't push megabyte strings into the audit row.
            let detail = req.detail.unwrap_or_default();
            let truncated = if detail.len() > 1024 {
                &detail[..1024]
            } else {
                &detail
            };
            sqlx::query(
                "UPDATE device_pending_ops \
                 SET failed_at = now(), \
                     last_error = $3, \
                     attempts = attempts + 1 \
                 WHERE id = $1 \
                   AND device_id = $2 \
                   AND completed_at IS NULL \
                   AND failed_at IS NULL",
            )
            .bind(req.op_id)
            .bind(device_id)
            .bind(truncated)
            .execute(&state.pool)
            .await?
            .rows_affected()
        }
    };

    if affected == 0 {
        return Err(InternalError::UnknownOp);
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Daemon-driven key rotation commit (v1.2-plan §18.A3.2). The daemon
/// has already generated the fresh keypair and persisted the new private
/// key locally; this endpoint atomically swaps `devices.x25519_pubkey`,
/// finalises the matching `device_pending_ops` row (so the queue does
/// not need a separate ack POST), and records the swap in audit.
///
/// Auth is the snapshot pair (token + OLD pubkey) — done BEFORE the
/// pubkey is swapped so the daemon's still-current credentials let it
/// through. After this 204 the OLD pubkey stops authenticating; the
/// daemon's next snapshot push must use the new pubkey, which is why
/// the daemon side schedules a restart immediately after this call.
async fn rotate_key_complete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(req): Json<RotateKeyCompleteRequest>,
) -> Result<StatusCode, InternalError> {
    let device_id = authenticate(&state.pool, state.network_id, &headers, &req.device_pubkey_hex).await?;

    let new_pubkey_raw =
        gnet_hex::decode_32(&req.new_pubkey_hex).ok_or(InternalError::BadNewPubkey)?;

    let mut tx = state.pool.begin().await?;

    // Atomic swap. UNIQUE (network_id, x25519_pubkey) WHERE removed_at
    // IS NULL (migration 0003) catches a collision with another live
    // device row → 23505 → PubkeyConflict; everything else surfaces as
    // a DB error.
    match sqlx::query("UPDATE devices SET x25519_pubkey = $1 WHERE id = $2")
        .bind(&new_pubkey_raw[..])
        .bind(device_id)
        .execute(&mut *tx)
        .await
    {
        Ok(_) => {}
        Err(sqlx::Error::Database(db_err)) if db_err.code().as_deref() == Some("23505") => {
            return Err(InternalError::PubkeyConflict);
        }
        Err(other) => return Err(other.into()),
    }

    let affected = sqlx::query(
        "UPDATE device_pending_ops \
         SET completed_at = now() \
         WHERE id = $1 \
           AND device_id = $2 \
           AND op = 'rotate_key' \
           AND completed_at IS NULL \
           AND failed_at IS NULL",
    )
    .bind(req.op_id)
    .bind(device_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if affected == 0 {
        // Roll the pubkey swap back implicitly — no commit yet — and tell
        // the caller the op_id didn't match. (Most likely: op already
        // ack'd, or this complete arrived for a different device's op.)
        return Err(InternalError::UnknownOp);
    }

    // The daemon authenticates against (token, device_pubkey), so the
    // detail row carries both the old and the new pubkey for an audit
    // reader walking the chain without needing to join across snapshots.
    let detail = serde_json::json!({
        "op_id": req.op_id,
        "old_pubkey_hex": req.device_pubkey_hex,
        "new_pubkey_hex": req.new_pubkey_hex,
    });
    sqlx::query(
        "INSERT INTO audit_log (network_id, actor_kind, actor_id, action, target, detail) \
         VALUES ($1, 'daemon', $2, 'device.rotate_key.completed', $3, $4)",
    )
    .bind(state.network_id)
    .bind(device_id.to_string())
    .bind(device_id.to_string())
    .bind(&detail)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Two-factor lookup shared by snapshot + ack: bearer token bytes hash
/// matches the row, AND the row's x25519_pubkey matches the body's hex.
/// A kicked row (`removed_at IS NOT NULL`) is treated as if it didn't
/// exist, so a device that's been kicked stops being able to push
/// snapshots or ack ops — the daemon sees 401 and stays disconnected
/// until it re-registers.
async fn authenticate(
    pool: &PgPool,
    network_id: Uuid,
    headers: &HeaderMap,
    device_pubkey_hex: &str,
) -> Result<Uuid, InternalError> {
    let token = bearer(headers).ok_or(InternalError::NoBearer)?;
    // Hash the bearer bytes verbatim — matches the v1.0 `/endpoint-report`
    // wire (the daemon sends whatever `device_token` the coordinator
    // returned at `/join`; dispatcher stored SHA3-256 of those same bytes
    // at import time). No hex-decode dance.
    let token_hash = gnet_crypto::sha3::sha3_256(token.as_bytes());
    let pubkey_raw = gnet_hex::decode_32(device_pubkey_hex).ok_or(InternalError::BadPubkey)?;

    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM devices \
         WHERE network_id = $1 \
           AND x25519_pubkey = $2 \
           AND device_token_hash = $3 \
           AND removed_at IS NULL",
    )
    .bind(network_id)
    .bind(&pubkey_raw[..])
    .bind(&token_hash[..])
    .fetch_optional(pool)
    .await?;

    row.map(|(id,)| id).ok_or(InternalError::Unauthorized)
}

/// Enqueue a pending op against `device_id`. Used by operator-facing
/// writes (rotate-key / restart in §18.A2, upgrade in §18.A3). `op`
/// must match the schema's CHECK enum; callers pass a static `&str`.
///
/// Generic over `sqlx::Executor` so callers can either run it standalone
/// against `&state.pool` or join it to a transaction together with the
/// `audit_log` insert. device_writes always uses the tx form — schema
/// state without its audit row is exactly the half-state the audit
/// invariant exists to prevent.
pub(crate) async fn enqueue_op<'e, E>(
    executor: E,
    network_id: Uuid,
    device_id: Uuid,
    op: &str,
    args: Json_,
) -> Result<Uuid, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO device_pending_ops (id, network_id, device_id, op, args) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(network_id)
    .bind(device_id)
    .bind(op)
    .bind(args)
    .execute(executor)
    .await?;
    Ok(id)
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
