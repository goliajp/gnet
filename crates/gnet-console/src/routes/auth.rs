//! Email + password sign-in path.
//!
//! - POST /api/auth/email/register   create an account
//! - POST /api/auth/email/login      get a session
//! - GET  /api/auth/me                whoami
//! - POST /api/auth/logout            drop session + clear cookies
//!
//! OAuth providers (Google / GitHub / Apple) come in §17.5b–d.

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use time::Duration;
use uuid::Uuid;

use crate::auth::{AuthError, hash_password, looks_like_email, verify_password};
use crate::routes::csrf::CSRF_COOKIE_NAME;
use crate::session::{self, SESSION_TTL_SECS, Session};
use crate::state::AppState;

const SESSION_COOKIE: &str = "gnet_sess";
const MIN_PASSWORD_LEN: usize = 12;

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct MeResponse {
    pub user_id: Uuid,
    pub email: Option<String>,
    pub verified: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthRouteError {
    #[error("invalid email")]
    BadEmail,
    #[error("password must be at least 12 characters")]
    WeakPassword,
    #[error("invalid credentials")]
    BadCreds,
    #[error("email not yet verified")]
    Unverified,
    #[error("not logged in")]
    NotLoggedIn,
    #[error("email already registered")]
    AlreadyExists,
    #[error("password hash: {0}")]
    Hash(#[from] AuthError),
    #[error("session: {0}")]
    Session(#[from] crate::session::SessionError),
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
}

impl IntoResponse for AuthRouteError {
    fn into_response(self) -> Response {
        let code = match self {
            AuthRouteError::BadEmail | AuthRouteError::WeakPassword => StatusCode::BAD_REQUEST,
            AuthRouteError::BadCreds
            | AuthRouteError::NotLoggedIn
            | AuthRouteError::Unverified => StatusCode::UNAUTHORIZED,
            AuthRouteError::AlreadyExists => StatusCode::CONFLICT,
            AuthRouteError::Hash(_)
            | AuthRouteError::Session(_)
            | AuthRouteError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (code, self.to_string()).into_response()
    }
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/auth/email/register", post(register))
        .route("/api/auth/email/login", post(login))
        .route("/api/auth/me", get(me))
        .route("/api/auth/logout", post(logout))
}

async fn register(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<RegisterRequest>,
) -> Result<(CookieJar, (StatusCode, Json<MeResponse>)), AuthRouteError> {
    let email = req.email.trim().to_lowercase();
    if !looks_like_email(&email) {
        return Err(AuthRouteError::BadEmail);
    }
    if req.password.chars().count() < MIN_PASSWORD_LEN {
        return Err(AuthRouteError::WeakPassword);
    }

    let mut tx = state.pool.begin().await?;

    let existing: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM users WHERE email = $1")
            .bind(&email)
            .fetch_optional(&mut *tx)
            .await?;
    if existing.is_some() {
        return Err(AuthRouteError::AlreadyExists);
    }

    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
        .bind(user_id)
        .bind(&email)
        .execute(&mut *tx)
        .await?;

    let hash = hash_password(&req.password)?;
    let verified_at_sql = if state.auto_verify_email { "now()" } else { "NULL" };
    let q = format!(
        "INSERT INTO email_credentials (user_id, password_hash, verified_at) \
         VALUES ($1, $2, {verified_at_sql})"
    );
    sqlx::query(&q)
        .bind(user_id)
        .bind(&hash)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    let (jar, _resp_session) = open_session(jar, &state, user_id, Some(email.clone())).await?;

    Ok((
        jar,
        (
            StatusCode::CREATED,
            Json(MeResponse {
                user_id,
                email: Some(email),
                verified: state.auto_verify_email,
            }),
        ),
    ))
}

async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
) -> Result<(CookieJar, Json<MeResponse>), AuthRouteError> {
    let email = req.email.trim().to_lowercase();

    let row: Option<(Uuid, String, Option<chrono::DateTime<Utc>>)> = sqlx::query_as(
        "SELECT u.id, c.password_hash, c.verified_at \
         FROM users u JOIN email_credentials c ON c.user_id = u.id \
         WHERE u.email = $1",
    )
    .bind(&email)
    .fetch_optional(&state.pool)
    .await?;
    let (user_id, password_hash, verified_at) = row.ok_or(AuthRouteError::BadCreds)?;

    if !verify_password(&password_hash, &req.password) {
        return Err(AuthRouteError::BadCreds);
    }
    if verified_at.is_none() {
        return Err(AuthRouteError::Unverified);
    }

    let (jar, _) = open_session(jar, &state, user_id, Some(email.clone())).await?;

    Ok((
        jar,
        Json(MeResponse {
            user_id,
            email: Some(email),
            verified: true,
        }),
    ))
}

async fn me(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<MeResponse>, AuthRouteError> {
    let session = require_login(&state, &jar).await?;
    let verified: bool = match &session.email {
        Some(_) => sqlx::query_scalar::<_, Option<chrono::DateTime<Utc>>>(
            "SELECT verified_at FROM email_credentials WHERE user_id = $1",
        )
        .bind(session.user_id)
        .fetch_optional(&state.pool)
        .await?
        .flatten()
        .is_some(),
        None => true,
    };
    Ok(Json(MeResponse {
        user_id: session.user_id,
        email: session.email,
        verified,
    }))
}

async fn logout(State(state): State<AppState>, jar: CookieJar) -> (CookieJar, StatusCode) {
    if let Some(cookie) = jar.get(SESSION_COOKIE) {
        if let Some(key) = session::key_from_cookie(cookie.value()) {
            let mut kv = state.kv.clone();
            let _ = session::delete(&mut kv, &key).await;
        }
    }
    let cleared_sess = Cookie::build((SESSION_COOKIE, ""))
        .path("/")
        .max_age(Duration::ZERO)
        .build();
    let cleared_csrf = Cookie::build((CSRF_COOKIE_NAME, ""))
        .path("/")
        .max_age(Duration::ZERO)
        .build();
    (
        jar.add(cleared_sess).add(cleared_csrf),
        StatusCode::NO_CONTENT,
    )
}

/// Mint a session + CSRF cookie pair. Used by both register and login.
async fn open_session(
    jar: CookieJar,
    state: &AppState,
    user_id: Uuid,
    email: Option<String>,
) -> Result<(CookieJar, Session), AuthRouteError> {
    let sid = session::new();
    let key = sid.key();
    let session = Session {
        user_id,
        email,
        created_at: Utc::now(),
    };
    let mut kv = state.kv.clone();
    session::store(&mut kv, &key, &session).await?;

    let session_cookie = Cookie::build((SESSION_COOKIE, sid.cookie_value()))
        .http_only(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(Duration::seconds(SESSION_TTL_SECS as i64))
        .build();

    let mut csrf_raw = [0u8; 32];
    gnet_rand::fill(&mut csrf_raw);
    let csrf_token = gnet_hex::encode(&csrf_raw);
    let csrf_cookie = Cookie::build((CSRF_COOKIE_NAME, csrf_token))
        .http_only(false)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(Duration::seconds(SESSION_TTL_SECS as i64))
        .build();

    Ok((jar.add(session_cookie).add(csrf_cookie), session))
}

pub async fn require_login(
    state: &AppState,
    jar: &CookieJar,
) -> Result<Session, AuthRouteError> {
    let cookie = jar.get(SESSION_COOKIE).ok_or(AuthRouteError::NotLoggedIn)?;
    let key = session::key_from_cookie(cookie.value()).ok_or(AuthRouteError::NotLoggedIn)?;
    let mut kv = state.kv.clone();
    let session = session::fetch(&mut kv, &key)
        .await?
        .ok_or(AuthRouteError::NotLoggedIn)?;
    Ok(session)
}
