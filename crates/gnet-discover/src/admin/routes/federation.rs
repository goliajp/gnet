//! Federation handshake — receives a console-minted token from the
//! logged-in admin, records it as a trusted federation peer.
//!
//! Plan §6.3: the console mints a one-time-display federation token,
//! shows it to the user once (plaintext), and stores its hash. The
//! user pastes the plaintext into the dispatcher's admin UI; this
//! handler stores `SHA3_256(token)` in `federation_trust`. Future
//! `/api/federation/operate` calls (lands with the console-side proxy
//! route) hash the inbound bearer and match against this row.
//!
//! v1.1 first slice keeps `console_pubkey` zero-filled — Ed25519
//! signature verification of inbound tokens is its own concrete piece
//! and will land alongside the console-side proxy. Until then a row
//! in `federation_trust` is the trust anchor; the bearer-hash compare
//! is the verification.

use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, post};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::admin::AdminState;
use crate::admin::routes::auth::{AuthRouteError, require_login};

#[derive(Deserialize)]
pub struct RegisterRequest {
    /// Hex-encoded plaintext federation token, as displayed by the
    /// console exactly once at mint time.
    pub token: String,
    /// Origin of the console that minted the token, e.g.
    /// `https://gnet.golia.jp`. Stored for audit and for the eventual
    /// pull-based revocation check (plan §6.3); not parsed beyond
    /// length-limiting.
    pub console_origin: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub federation_id: Uuid,
}

#[derive(Debug, thiserror::Error)]
pub enum FederationError {
    #[error("not logged in")]
    NotLoggedIn,
    #[error("token must be 64-char hex")]
    BadToken,
    #[error("console_origin must be http(s)://… 1024 chars max")]
    BadOrigin,
    #[error("token already registered")]
    Duplicate,
    /// Operator asked to revoke a federation trust row that either
    /// doesn't exist or is already revoked. We collapse both into a
    /// single 404 so the dispatcher doesn't leak whether a given
    /// trust id ever existed.
    #[error("federation trust not found")]
    NotFound,
    #[error("session: {0}")]
    Session(#[from] crate::admin::session::SessionError),
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    #[error("cache: {0}")]
    Cache(#[from] redis::RedisError),
}

impl From<AuthRouteError> for FederationError {
    fn from(e: AuthRouteError) -> Self {
        match e {
            AuthRouteError::NotLoggedIn => FederationError::NotLoggedIn,
            AuthRouteError::BadCreds => FederationError::NotLoggedIn,
            // Throttle in this path means the caller hit the
            // bearer-auth route (federation) past the per-token
            // bucket — surface as 401, the federation client's
            // generic "auth failed" handler will retry with backoff.
            AuthRouteError::Throttled { .. } => FederationError::NotLoggedIn,
            AuthRouteError::Session(s) => FederationError::Session(s),
            AuthRouteError::Db(d) => FederationError::Db(d),
            AuthRouteError::Cache(c) => FederationError::Cache(c),
        }
    }
}

impl IntoResponse for FederationError {
    fn into_response(self) -> Response {
        let code = match self {
            FederationError::NotLoggedIn => StatusCode::UNAUTHORIZED,
            FederationError::BadToken | FederationError::BadOrigin => StatusCode::BAD_REQUEST,
            FederationError::Duplicate => StatusCode::CONFLICT,
            FederationError::NotFound => StatusCode::NOT_FOUND,
            FederationError::Session(_) | FederationError::Db(_) | FederationError::Cache(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        (code, self.to_string()).into_response()
    }
}

pub fn routes() -> Router<AdminState> {
    Router::new()
        .route("/api/federation/register", post(register))
        .route("/api/federation/{trust_id}", delete(revoke))
}

async fn register(
    State(state): State<AdminState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), FederationError> {
    let session = require_login(&state, &jar, &headers).await?;

    if req.token.len() != 64 {
        return Err(FederationError::BadToken);
    }
    let token_raw = gnet_hex::decode_32(&req.token).ok_or(FederationError::BadToken)?;
    let token_hash = gnet_crypto::sha3::sha3_256(&token_raw);

    let origin = req.console_origin.trim();
    if origin.is_empty()
        || origin.len() > 1024
        || !(origin.starts_with("http://") || origin.starts_with("https://"))
    {
        return Err(FederationError::BadOrigin);
    }

    let mut tx = state.pool.begin().await?;

    let dup: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM federation_trust \
         WHERE network_id = $1 AND token_hash = $2",
    )
    .bind(state.network_id)
    .bind(&token_hash[..])
    .fetch_optional(&mut *tx)
    .await?;
    if dup.is_some() {
        return Err(FederationError::Duplicate);
    }

    let federation_id = Uuid::new_v4();
    // console_pubkey + granted_user_id are NOT NULL in 0001; placeholders
    // until the console-side Ed25519 minting lands. Audit captures who
    // pasted the token so attribution survives.
    let placeholder_pubkey = vec![0u8; 32];
    let placeholder_granted_user = Uuid::nil();

    sqlx::query(
        "INSERT INTO federation_trust \
            (id, network_id, console_origin, console_pubkey, granted_user_id, token_hash) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(federation_id)
    .bind(state.network_id)
    .bind(origin)
    .bind(&placeholder_pubkey)
    .bind(placeholder_granted_user)
    .bind(&token_hash[..])
    .execute(&mut *tx)
    .await?;

    let detail = serde_json::json!({
        "console_origin": origin,
        "federation_id": federation_id,
    });
    sqlx::query(
        "INSERT INTO audit_log (network_id, actor_kind, actor_id, action, target, detail) \
         VALUES ($1, 'local_admin', $2, 'federation.register', $3, $4)",
    )
    .bind(state.network_id)
    .bind(session.user_id.to_string())
    .bind(federation_id.to_string())
    .bind(&detail)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse { federation_id }),
    ))
}

/// Operator-side revocation. Sets `revoked_at = now()` on a single
/// `federation_trust` row, writes an audit entry, and returns 204.
///
/// `require_login`'s federation-bearer branch already rejects rows
/// whose `revoked_at IS NOT NULL` (see `auth::require_login`), so
/// the next request bearing the revoked token gets 401 — no
/// further code path needs to know about revocation.
///
/// Idempotency: a second DELETE on the same trust id returns 404
/// (the UPDATE … WHERE revoked_at IS NULL returns 0 rows). This
/// trades easy retry for not leaking "the row used to exist but
/// you already revoked it" — the operator's audit log carries the
/// canonical history.
async fn revoke(
    State(state): State<AdminState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(trust_id): Path<Uuid>,
) -> Result<StatusCode, FederationError> {
    let session = require_login(&state, &jar, &headers).await?;

    let mut tx = state.pool.begin().await?;

    // Single UPDATE scoped to the live row for this network. WHERE
    // revoked_at IS NULL collapses "absent" + "already revoked"
    // into a single zero-rows outcome.
    let res = sqlx::query(
        "UPDATE federation_trust \
         SET revoked_at = now() \
         WHERE id = $1 AND network_id = $2 AND revoked_at IS NULL",
    )
    .bind(trust_id)
    .bind(state.network_id)
    .execute(&mut *tx)
    .await?;

    if res.rows_affected() == 0 {
        return Err(FederationError::NotFound);
    }

    let detail = serde_json::json!({
        "federation_id": trust_id,
    });
    sqlx::query(
        "INSERT INTO audit_log (network_id, actor_kind, actor_id, action, target, detail) \
         VALUES ($1, 'local_admin', $2, 'federation.revoke', $3, $4)",
    )
    .bind(state.network_id)
    .bind(session.user_id.to_string())
    .bind(trust_id.to_string())
    .bind(&detail)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}
