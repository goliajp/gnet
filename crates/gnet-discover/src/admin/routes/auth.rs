use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use time::Duration;
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

/// Whether the operator is fronting this dispatcher with HTTPS —
/// controls the `Secure` attribute on session + CSRF cookies and
/// the HSTS header in `routes::headers`. Default `false` because
/// the self-host bundle (plan §11) defaults to plain HTTP. Operators
/// who put a TLS reverse proxy in front set
/// `GNET_DISCOVER_SECURE_COOKIES=1`.
pub(super) fn secure_cookies() -> bool {
    std::env::var("GNET_DISCOVER_SECURE_COOKIES")
        .map(|v| v != "0" && !v.is_empty())
        .unwrap_or(false)
}

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
    /// Brute-force throttle tripped. Surfaces as 429 + Retry-After
    /// (plan §17.12).
    #[error("too many login attempts; retry in {retry_after_secs}s")]
    Throttled { retry_after_secs: u64 },
    #[error("session store: {0}")]
    Session(#[from] crate::admin::session::SessionError),
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    #[error("cache: {0}")]
    Cache(#[from] redis::RedisError),
}

impl IntoResponse for AuthRouteError {
    fn into_response(self) -> Response {
        if let AuthRouteError::Throttled { retry_after_secs } = &self {
            let secs = *retry_after_secs;
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(axum::http::header::RETRY_AFTER, secs.to_string())],
                self.to_string(),
            )
                .into_response();
        }
        let code = match self {
            AuthRouteError::BadCreds | AuthRouteError::NotLoggedIn => StatusCode::UNAUTHORIZED,
            AuthRouteError::Throttled { .. } => StatusCode::TOO_MANY_REQUESTS,
            AuthRouteError::Session(_) | AuthRouteError::Db(_) | AuthRouteError::Cache(_) => {
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
    // Brute-force throttle BEFORE the expensive password verify +
    // DB round-trip. Bucket keyed on `network_id:username` so a
    // multi-tenant dispatcher doesn't let traffic against one
    // tenant burn another tenant's bucket (plan §17.12).
    let throttle_key = format!("{}:{}", state.network_id, req.username);
    {
        let mut kv = state.kv.clone();
        match crate::admin::ratelimit::account_attempt(&mut kv, &throttle_key).await? {
            crate::admin::ratelimit::Decision::Allow => {}
            crate::admin::ratelimit::Decision::Throttle { retry_after_secs } => {
                return Err(AuthRouteError::Throttled { retry_after_secs });
            }
        }
    }

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

    // Successful login — clear the bucket so a typo-then-correct
    // session doesn't trap the user behind cooldown. Best-effort.
    {
        let mut kv = state.kv.clone();
        let _ = crate::admin::ratelimit::account_clear(&mut kv, &throttle_key).await;
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

    let secure = secure_cookies();
    let session_cookie = Cookie::build((COOKIE_NAME, sid.cookie_value()))
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(secure)
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
        .secure(secure)
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
    if let Some(cookie) = jar.get(COOKIE_NAME)
        && let Some(key) = session::key_from_cookie(state.network_id, cookie.value())
    {
        // Best-effort: a delete failure shouldn't keep the user
        // logged in client-side, so we still clear the cookie below.
        let mut kv = state.kv.clone();
        let _ = session::delete(&mut kv, &key).await;
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
    headers: HeaderMap,
) -> Result<Json<MeResponse>, AuthRouteError> {
    let session = require_login(&state, &jar, &headers).await?;
    Ok(Json(MeResponse {
        user_id: session.user_id,
        username: session.username,
        role: session.role,
    }))
}

/// Shared helper for any handler that needs the current session.
///
/// Tries two auth methods in order:
///
/// 1. `gnet_sess` cookie → Valkey session (the SPA / local admin path).
/// 2. `Authorization: Bearer <token>` matched against
///    `federation_trust.token_hash` (the SaaS-console-proxied path,
///    plan §6.3).
///
/// Returns `NotLoggedIn` only when neither method authenticates. The
/// federation-bearer fallback synthesises a `Session` whose `user_id`
/// is the `federation_trust` row id and whose `username` carries the
/// trusted `console_origin` for audit attribution.
pub async fn require_login(
    state: &AdminState,
    jar: &CookieJar,
    headers: &HeaderMap,
) -> Result<Session, AuthRouteError> {
    if let Some(cookie) = jar.get(COOKIE_NAME)
        && let Some(key) = session::key_from_cookie(state.network_id, cookie.value())
    {
        let mut kv = state.kv.clone();
        if let Some(s) = session::fetch(&mut kv, &key).await? {
            return Ok(s);
        }
    }

    if let Some(token) = bearer_from_headers(headers) {
        // Match the hashing the federation/register handler does: decode
        // the 64-char hex bearer back to its 32 raw bytes and hash *those*.
        // Hashing the hex ASCII directly would silently never match.
        if let Some(token_raw) = gnet_hex::decode_32(token) {
            let token_hash = gnet_crypto::sha3::sha3_256(&token_raw);
            let row: Option<(Uuid, Option<chrono::DateTime<Utc>>, String)> = sqlx::query_as(
                "SELECT id, revoked_at, console_origin FROM federation_trust \
                 WHERE network_id = $1 AND token_hash = $2",
            )
            .bind(state.network_id)
            .bind(&token_hash[..])
            .fetch_optional(&state.pool)
            .await?;
            if let Some((fed_id, None, origin)) = row {
                return Ok(Session {
                    user_id: fed_id,
                    network_id: state.network_id,
                    username: format!("federation:{origin}"),
                    role: "owner".to_string(),
                    created_at: Utc::now(),
                });
            }
        }
    }

    Err(AuthRouteError::NotLoggedIn)
}

fn bearer_from_headers(headers: &HeaderMap) -> Option<&str> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let rest = v
        .strip_prefix("Bearer ")
        .or_else(|| v.strip_prefix("bearer "))?
        .trim();
    if rest.is_empty() { None } else { Some(rest) }
}
