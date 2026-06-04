use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::admin::AdminState;
use crate::admin::auth::{AuthError, hash_password, setup_token_hash_from_hex};

#[derive(Deserialize)]
pub struct SetupRequest {
    pub token: String,
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct SetupResponse {
    pub user_id: Uuid,
    pub username: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    /// Bad token format, missing token, or token bytes do not match any
    /// stored hash. We deliberately do not distinguish these in the
    /// outward-facing response — all three are "your token is wrong".
    #[error("invalid setup token")]
    TokenInvalid,
    #[error("setup token has expired")]
    TokenExpired,
    #[error("username must be 3-32 chars of [a-z0-9_-]")]
    BadUsername,
    #[error("password must be at least 12 characters")]
    WeakPassword,
    #[error("admin already configured; setup is closed")]
    AlreadyDone,
    #[error("password hashing failed")]
    Hash(#[from] AuthError),
    #[error("internal error")]
    Db(#[from] sqlx::Error),
}

impl IntoResponse for SetupError {
    fn into_response(self) -> Response {
        let code = match self {
            SetupError::TokenInvalid | SetupError::TokenExpired => StatusCode::UNAUTHORIZED,
            SetupError::BadUsername | SetupError::WeakPassword => StatusCode::BAD_REQUEST,
            SetupError::AlreadyDone => StatusCode::CONFLICT,
            SetupError::Hash(_) | SetupError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (code, self.to_string()).into_response()
    }
}

pub fn routes() -> Router<AdminState> {
    Router::new().route("/api/auth/setup", post(setup))
}

async fn setup(
    State(state): State<AdminState>,
    Json(req): Json<SetupRequest>,
) -> Result<(StatusCode, Json<SetupResponse>), SetupError> {
    if !valid_username(&req.username) {
        return Err(SetupError::BadUsername);
    }
    if req.password.chars().count() < 12 {
        return Err(SetupError::WeakPassword);
    }
    let token_hash = setup_token_hash_from_hex(&req.token).ok_or(SetupError::TokenInvalid)?;

    let mut tx = state.pool.begin().await?;

    // Re-check the bootstrap precondition under the transaction. Bootstrap
    // and setup race in principle (operator double-submits); the
    // FOR UPDATE on the token row serializes them.
    let (admin_count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*)::bigint FROM admin_users WHERE network_id = $1")
            .bind(state.network_id)
            .fetch_one(&mut *tx)
            .await?;
    if admin_count > 0 {
        return Err(SetupError::AlreadyDone);
    }

    let row: Option<(Uuid, DateTime<Utc>, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT id, expires_at, consumed_at FROM setup_tokens \
         WHERE network_id = $1 AND token_hash = $2 \
         FOR UPDATE",
    )
    .bind(state.network_id)
    .bind(&token_hash[..])
    .fetch_optional(&mut *tx)
    .await?;
    let (token_id, expires_at, consumed_at) = row.ok_or(SetupError::TokenInvalid)?;
    if consumed_at.is_some() {
        return Err(SetupError::TokenInvalid);
    }
    if expires_at < Utc::now() {
        return Err(SetupError::TokenExpired);
    }

    let password_hash = hash_password(&req.password)?;
    let user_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO admin_users (id, network_id, username, password_hash, role) \
         VALUES ($1, $2, $3, $4, 'owner')",
    )
    .bind(user_id)
    .bind(state.network_id)
    .bind(&req.username)
    .bind(&password_hash)
    .execute(&mut *tx)
    .await?;

    sqlx::query("UPDATE setup_tokens SET consumed_at = now() WHERE id = $1")
        .bind(token_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(SetupResponse {
            user_id,
            username: req.username,
        }),
    ))
}

fn valid_username(u: &str) -> bool {
    let len = u.len();
    if !(3..=32).contains(&len) {
        return false;
    }
    u.bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::valid_username;

    #[test]
    fn username_accepts_simple_lowercase() {
        assert!(valid_username("alice"));
        assert!(valid_username("admin-1"));
        assert!(valid_username("op_99"));
    }

    #[test]
    fn username_rejects_bad() {
        assert!(!valid_username(""));
        assert!(!valid_username("ab"));
        assert!(!valid_username(&"x".repeat(33)));
        assert!(!valid_username("Alice"));
        assert!(!valid_username("alice@host"));
        assert!(!valid_username("admin user"));
    }
}
