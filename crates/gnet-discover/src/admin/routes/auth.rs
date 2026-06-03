use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::Utc;
use time::Duration;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::admin::AdminState;
use crate::admin::auth::verify_password;
use crate::admin::routes::csrf::CSRF_COOKIE_NAME;
use crate::admin::session::{self, SESSION_TTL_SECS, Session};

/// Cookie name. No `__Host-` prefix because that requires `Secure`, and
/// the self-host dispatcher commonly runs over plain HTTP (operators put
/// their own TLS in front). When the binary detects a TLS-terminating
/// reverse proxy via the future `X-Forwarded-Proto` config, we can bump
/// to `__Host-gnet_sess` + Secure.
const COOKIE_NAME: &str = "gnet_sess";

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub user_id: Uuid,
    pub username: String,
    pub role: String,
}

#[derive(Serialize)]
pub struct MeResponse {
    pub user_id: Uuid,
    pub username: String,
    pub role: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthRouteError {
    #[error("invalid credentials")]
    BadCreds,
    #[error("not logged in")]
    NotLoggedIn,
    #[error("session store: {0}")]
    Session(#[from] crate::admin::session::SessionError),
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
}

impl IntoResponse for AuthRouteError {
    fn into_response(self) -> Response {
        let code = match self {
            AuthRouteError::BadCreds | AuthRouteError::NotLoggedIn => StatusCode::UNAUTHORIZED,
            AuthRouteError::Session(_) | AuthRouteError::Db(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        (code, self.to_string()).into_response()
    }
}

pub fn routes() -> Router<AdminState> {
    Router::new()
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/me", get(me))
}

async fn login(
    State(state): State<AdminState>,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
) -> Result<(CookieJar, Json<LoginResponse>), AuthRouteError> {
    let row: Option<(Uuid, String, String)> = sqlx::query_as(
        "SELECT id, password_hash, role FROM admin_users \
         WHERE network_id = $1 AND username = $2",
    )
    .bind(state.network_id)
    .bind(&req.username)
    .fetch_optional(&state.pool)
    .await?;

    let (user_id, password_hash, role) = row.ok_or(AuthRouteError::BadCreds)?;
    if !verify_password(&password_hash, &req.password) {
        // Same error as "no such user" so we don't disclose user existence.
        return Err(AuthRouteError::BadCreds);
    }

    let sid = session::new(state.network_id);
    let key = sid.key();
    let session = Session {
        user_id,
        network_id: state.network_id,
        username: req.username.clone(),
        role: role.clone(),
        created_at: Utc::now(),
    };
    let mut kv = state.kv.clone();
    session::store(&mut kv, &key, &session).await?;

    let session_cookie = Cookie::build((COOKIE_NAME, sid.cookie_value()))
        .http_only(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(Duration::seconds(SESSION_TTL_SECS as i64))
        .build();

    // Double-submit CSRF token: same lifetime as the session, NOT HttpOnly
    // so the SPA can read it from `document.cookie` and echo it into the
    // `X-Csrf-Token` header on writes. Rotated per login.
    let mut csrf_raw = [0u8; 32];
    gnet_rand::fill(&mut csrf_raw);
    let csrf_token = gnet_hex::encode(&csrf_raw);
    let csrf_cookie = Cookie::build((CSRF_COOKIE_NAME, csrf_token))
        .http_only(false)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(Duration::seconds(SESSION_TTL_SECS as i64))
        .build();

    Ok((
        jar.add(session_cookie).add(csrf_cookie),
        Json(LoginResponse {
            user_id,
            username: req.username,
            role,
        }),
    ))
}

async fn logout(State(state): State<AdminState>, jar: CookieJar) -> (CookieJar, StatusCode) {
    if let Some(cookie) = jar.get(COOKIE_NAME) {
        if let Some(key) = session::key_from_cookie(state.network_id, cookie.value()) {
            // Best-effort: a delete failure shouldn't keep the user
            // logged in client-side, so we still clear the cookie below.
            let mut kv = state.kv.clone();
            let _ = session::delete(&mut kv, &key).await;
        }
    }
    let cleared_session = Cookie::build((COOKIE_NAME, ""))
        .path("/")
        .max_age(Duration::ZERO)
        .build();
    let cleared_csrf = Cookie::build((CSRF_COOKIE_NAME, ""))
        .path("/")
        .max_age(Duration::ZERO)
        .build();
    (
        jar.add(cleared_session).add(cleared_csrf),
        StatusCode::NO_CONTENT,
    )
}

async fn me(
    State(state): State<AdminState>,
    jar: CookieJar,
) -> Result<Json<MeResponse>, AuthRouteError> {
    let session = require_login(&state, &jar).await?;
    Ok(Json(MeResponse {
        user_id: session.user_id,
        username: session.username,
        role: session.role,
    }))
}

/// Shared helper for any handler that needs the current session. Returns
/// the loaded `Session` or `AuthRouteError::NotLoggedIn` on
/// missing/malformed cookie / absent session row.
pub async fn require_login(
    state: &AdminState,
    jar: &CookieJar,
) -> Result<Session, AuthRouteError> {
    let cookie = jar.get(COOKIE_NAME).ok_or(AuthRouteError::NotLoggedIn)?;
    let key = session::key_from_cookie(state.network_id, cookie.value())
        .ok_or(AuthRouteError::NotLoggedIn)?;
    let mut kv = state.kv.clone();
    let session = session::fetch(&mut kv, &key).await?.ok_or(AuthRouteError::NotLoggedIn)?;
    Ok(session)
}
