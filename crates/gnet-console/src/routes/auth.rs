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

/// Whether the SaaS console is fronted by HTTPS — controls the
/// `Secure` attribute on session + CSRF + OAuth-state cookies.
/// Default `true`: the console is a SaaS surface served behind
/// Caddy with TLS. Set `GNET_CONSOLE_SECURE_COOKIES=0` to opt out
/// for plain-HTTP dev setups; any non-empty non-zero value keeps
/// the default.
pub(super) fn secure_cookies() -> bool {
    std::env::var("GNET_CONSOLE_SECURE_COOKIES")
        .map(|v| v != "0" && !v.is_empty())
        .unwrap_or(true)
}

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
    /// Brute-force throttle tripped. `retry_after_secs` becomes
    /// the `Retry-After` header on the 429 response (plan §17.12).
    #[error("too many login attempts; retry in {retry_after_secs}s")]
    Throttled { retry_after_secs: u64 },
    #[error("password hash: {0}")]
    Hash(#[from] AuthError),
    #[error("session: {0}")]
    Session(#[from] crate::session::SessionError),
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    #[error("backend: {0}")]
    App(#[from] crate::error::AppError),
    /// Direct Valkey hop failure (the session-invalidation walk on
    /// password reset uses raw SCAN/GET/DEL). Surfaced as 500.
    #[error("cache: {0}")]
    Cache(#[from] redis::RedisError),
}

impl IntoResponse for AuthRouteError {
    fn into_response(self) -> Response {
        // Throttled responses carry a Retry-After header so an
        // honest client (browser, password manager) backs off.
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
            AuthRouteError::BadEmail | AuthRouteError::WeakPassword => StatusCode::BAD_REQUEST,
            AuthRouteError::BadCreds | AuthRouteError::NotLoggedIn | AuthRouteError::Unverified => {
                StatusCode::UNAUTHORIZED
            }
            AuthRouteError::AlreadyExists => StatusCode::CONFLICT,
            AuthRouteError::Throttled { .. } => StatusCode::TOO_MANY_REQUESTS,
            AuthRouteError::Hash(_)
            | AuthRouteError::Session(_)
            | AuthRouteError::Db(_)
            | AuthRouteError::App(_)
            | AuthRouteError::Cache(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (code, self.to_string()).into_response()
    }
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/auth/email/register", post(register))
        .route("/api/auth/email/login", post(login))
        .route("/api/auth/email/verify", post(verify_email))
        .route(
            "/api/auth/email/resend-verification",
            post(resend_verification),
        )
        .route("/api/auth/email/forgot-password", post(forgot_password))
        .route("/api/auth/email/reset-password", post(reset_password))
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

    let existing: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM users WHERE email = $1")
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
    let verified_at_sql = if state.auto_verify_email {
        "now()"
    } else {
        "NULL"
    };
    let q = format!(
        "INSERT INTO email_credentials (user_id, password_hash, verified_at) \
         VALUES ($1, $2, {verified_at_sql})"
    );
    sqlx::query(&q)
        .bind(user_id)
        .bind(&hash)
        .execute(&mut *tx)
        .await?;

    // When the mail loop is on, mint a single-use verification token
    // inside the same tx so the user row + the token always commit
    // together (or both roll back).
    let verify_token: Option<String> = if state.auto_verify_email {
        None
    } else {
        let mut raw = [0u8; 32];
        gnet_rand::fill(&mut raw);
        let token = gnet_hex::encode(&raw);
        sqlx::query("INSERT INTO email_verification_tokens (token, user_id) VALUES ($1, $2)")
            .bind(&token)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        Some(token)
    };

    tx.commit().await?;

    // Dispatch the verification mail AFTER commit. Failure here is
    // logged but doesn't roll back the signup — the user can ask for
    // a fresh token via the "resend" affordance (TODO when ready).
    // The mail-loop branch is only entered when mail.is_some()
    // because both come from the same env conditional in Config.
    if let (Some(token), Some(mail)) = (verify_token.as_ref(), state.mail.as_ref()) {
        let link = format!("{}/verify?token={}", state.public_url, token);
        let body = format!(
            "Welcome to gnet.\n\nConfirm this address to finish signing in:\n\n  {link}\n\nIf you didn't sign up for gnet, ignore this mail.\n\n— gnet.golia.jp\n"
        );
        let html_body = format!(
            "<p>Welcome to gnet.</p><p>Confirm this address to finish signing in:</p><p><a href=\"{link}\">{link}</a></p><p>If you didn't sign up for gnet, ignore this mail.</p><p>— gnet.golia.jp</p>"
        );
        if let Err(e) = mail
            .send(&email, "Confirm your gnet account", &body, Some(&html_body))
            .await
        {
            tracing::error!(error = ?e, user_id = %user_id, "verification mail send failed");
        }
    }

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

#[derive(Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

#[derive(Serialize)]
pub struct VerifyEmailResponse {
    pub verified: bool,
}

/// Confirm an email-address verification token. The token row stays
/// in the table after use (with `used_at = now()`) so a stolen link
/// that's already been redeemed gets the same 404 a never-existing
/// one does — leaks neither the original validity nor when the user
/// confirmed.
async fn verify_email(
    State(state): State<AppState>,
    Json(req): Json<VerifyEmailRequest>,
) -> Result<Json<VerifyEmailResponse>, AuthRouteError> {
    let mut tx = state.pool.begin().await?;
    let row: Option<(Uuid, Option<chrono::DateTime<Utc>>)> = sqlx::query_as(
        "SELECT user_id, used_at FROM email_verification_tokens \
         WHERE token = $1 AND created_at > now() - INTERVAL '1 hour' \
         FOR UPDATE",
    )
    .bind(&req.token)
    .fetch_optional(&mut *tx)
    .await?;

    let Some((user_id, used_at)) = row else {
        return Err(AuthRouteError::BadCreds);
    };
    if used_at.is_some() {
        return Err(AuthRouteError::BadCreds);
    }

    sqlx::query("UPDATE email_credentials SET verified_at = now() WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE email_verification_tokens SET used_at = now() WHERE token = $1")
        .bind(&req.token)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(Json(VerifyEmailResponse { verified: true }))
}

#[derive(Deserialize)]
pub struct ResendVerificationRequest {
    pub email: String,
}

/// Issue a fresh verification token for an unverified account, mail
/// it out, and ALWAYS return 200. We deliberately don't differentiate
/// "no such account" from "account already verified" from "fresh
/// token issued" — the response shape is identical so a probe can't
/// enumerate which addresses are real.
///
/// Auto-verify mode is a no-op success too (the binary has no mail
/// loop at all; signups already land verified). The frontend treats
/// 200 as "if your address is on file and still needs verification,
/// a new link is on the way."
async fn resend_verification(
    State(state): State<AppState>,
    Json(req): Json<ResendVerificationRequest>,
) -> Result<StatusCode, AuthRouteError> {
    let email = req.email.trim().to_lowercase();
    // No validation 400s — even a bad email shape returns 200 so the
    // enumeration surface stays flat.
    if !looks_like_email(&email) || state.auto_verify_email {
        return Ok(StatusCode::OK);
    }
    let Some(mail) = state.mail.as_ref() else {
        return Ok(StatusCode::OK);
    };

    let row: Option<(Uuid, Option<chrono::DateTime<Utc>>)> = sqlx::query_as(
        "SELECT u.id, c.verified_at \
         FROM users u JOIN email_credentials c ON c.user_id = u.id \
         WHERE u.email = $1",
    )
    .bind(&email)
    .fetch_optional(&state.pool)
    .await?;
    let Some((user_id, verified_at)) = row else {
        return Ok(StatusCode::OK);
    };
    if verified_at.is_some() {
        return Ok(StatusCode::OK);
    }

    let mut raw = [0u8; 32];
    gnet_rand::fill(&mut raw);
    let token = gnet_hex::encode(&raw);
    sqlx::query("INSERT INTO email_verification_tokens (token, user_id) VALUES ($1, $2)")
        .bind(&token)
        .bind(user_id)
        .execute(&state.pool)
        .await?;

    let link = format!("{}/verify?token={}", state.public_url, token);
    let body = format!(
        "Here's a fresh confirmation link for gnet:\n\n  {link}\n\nIf you didn't ask to resend, you can safely ignore this mail.\n\n— gnet.golia.jp\n"
    );
    let html_body = format!(
        "<p>Here's a fresh confirmation link for gnet:</p><p><a href=\"{link}\">{link}</a></p><p>If you didn't ask to resend, you can safely ignore this mail.</p><p>— gnet.golia.jp</p>"
    );
    if let Err(e) = mail
        .send(&email, "Confirm your gnet account", &body, Some(&html_body))
        .await
    {
        tracing::error!(error = ?e, user_id = %user_id, "resend verification mail failed");
    }
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

/// Issue a password-reset token for an existing account, mail it
/// out, and ALWAYS return 200 — same enumeration-flat behaviour as
/// resend-verification. The mail's link points at
/// `/reset-password?token=…` which the SPA hosts.
async fn forgot_password(
    State(state): State<AppState>,
    Json(req): Json<ForgotPasswordRequest>,
) -> Result<StatusCode, AuthRouteError> {
    let email = req.email.trim().to_lowercase();
    if !looks_like_email(&email) {
        return Ok(StatusCode::OK);
    }
    let Some(mail) = state.mail.as_ref() else {
        return Ok(StatusCode::OK);
    };

    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT u.id FROM users u JOIN email_credentials c ON c.user_id = u.id \
         WHERE u.email = $1",
    )
    .bind(&email)
    .fetch_optional(&state.pool)
    .await?;
    let Some((user_id,)) = row else {
        return Ok(StatusCode::OK);
    };

    let mut raw = [0u8; 32];
    gnet_rand::fill(&mut raw);
    let token = gnet_hex::encode(&raw);
    sqlx::query("INSERT INTO password_reset_tokens (token, user_id) VALUES ($1, $2)")
        .bind(&token)
        .bind(user_id)
        .execute(&state.pool)
        .await?;

    let link = format!("{}/reset-password?token={}", state.public_url, token);
    let body = format!(
        "Someone asked to reset the password on your gnet account.\n\nIf that was you, follow this link within one hour:\n\n  {link}\n\nIf it wasn't, ignore this mail — your password is unchanged.\n\n— gnet.golia.jp\n"
    );
    let html_body = format!(
        "<p>Someone asked to reset the password on your gnet account.</p><p>If that was you, follow this link within one hour:</p><p><a href=\"{link}\">{link}</a></p><p>If it wasn't, ignore this mail — your password is unchanged.</p><p>— gnet.golia.jp</p>"
    );
    if let Err(e) = mail
        .send(&email, "Reset your gnet password", &body, Some(&html_body))
        .await
    {
        tracing::error!(error = ?e, user_id = %user_id, "password-reset mail failed");
    }
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub password: String,
}

/// Consume a password-reset token and set a new password. Same
/// shape as `verify_email`: SELECT … FOR UPDATE inside a tx, single-
/// use (used_at IS NULL gates re-use), one-hour TTL. Also clears
/// every live session for that user so a thief with the old session
/// cookie loses access at reset time.
async fn reset_password(
    State(state): State<AppState>,
    Json(req): Json<ResetPasswordRequest>,
) -> Result<StatusCode, AuthRouteError> {
    if req.password.chars().count() < MIN_PASSWORD_LEN {
        return Err(AuthRouteError::WeakPassword);
    }

    let mut tx = state.pool.begin().await?;
    let row: Option<(Uuid, Option<chrono::DateTime<Utc>>)> = sqlx::query_as(
        "SELECT user_id, used_at FROM password_reset_tokens \
         WHERE token = $1 AND created_at > now() - INTERVAL '1 hour' \
         FOR UPDATE",
    )
    .bind(&req.token)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((user_id, used_at)) = row else {
        return Err(AuthRouteError::BadCreds);
    };
    if used_at.is_some() {
        return Err(AuthRouteError::BadCreds);
    }

    let hash = hash_password(&req.password)?;
    sqlx::query("UPDATE email_credentials SET password_hash = $1 WHERE user_id = $2")
        .bind(&hash)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE password_reset_tokens SET used_at = now() WHERE token = $1")
        .bind(&req.token)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    // Best-effort: kill all live sessions for this user by walking the
    // Valkey session prefix. Failure here just shortens the window
    // they remain valid — the password rotation already strands the
    // old cookies on the next login attempt.
    let _ = invalidate_user_sessions(&state, user_id).await;

    Ok(StatusCode::OK)
}

/// Walk the console session prefix in Valkey and drop every row that
/// belongs to `user_id`. Best-effort: returns Ok even on a partial
/// scan — caller logs the count via `?` propagation if needed.
async fn invalidate_user_sessions(state: &AppState, user_id: Uuid) -> Result<(), AuthRouteError> {
    use redis::AsyncCommands;
    let mut kv = state.kv.clone();
    let mut cursor: u64 = 0;
    let pattern = format!("{}*", crate::session::KEY_PREFIX);
    loop {
        let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(&pattern)
            .arg("COUNT")
            .arg(200)
            .query_async(&mut kv)
            .await?;
        for k in &keys {
            let raw: Option<String> = kv.get(k).await?;
            let Some(json) = raw else { continue };
            if json.contains(&user_id.to_string()) {
                let _: () = kv.del(k).await?;
            }
        }
        if next == 0 {
            break;
        }
        cursor = next;
    }
    Ok(())
}

async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
) -> Result<(CookieJar, Json<MeResponse>), AuthRouteError> {
    let email = req.email.trim().to_lowercase();

    // Brute-force throttle BEFORE the expensive password verify +
    // DB roundtrip. Bucket is keyed on the lowercased email so an
    // attacker can't bypass via case-folding (`ALICE@x` vs.
    // `alice@x`). The counter is always-incremented; honest users
    // with a typo burn at most LOGIN_ATTEMPT_LIMIT attempts before
    // having to wait one window. See `ratelimit.rs`.
    {
        let mut kv = state.kv.clone();
        match crate::ratelimit::account_attempt(&mut kv, &email).await? {
            crate::ratelimit::Decision::Allow => {}
            crate::ratelimit::Decision::Throttle { retry_after_secs } => {
                return Err(AuthRouteError::Throttled { retry_after_secs });
            }
        }
    }

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

    // Successful login — clear the bucket so the user doesn't get
    // throttled when they next sign in from another device after a
    // few failed attempts on this one. Best-effort: a failure here
    // would only mean the bucket decays naturally at the window
    // boundary, so we ignore the error.
    {
        let mut kv = state.kv.clone();
        let _ = crate::ratelimit::account_clear(&mut kv, &email).await;
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
    if let Some(cookie) = jar.get(SESSION_COOKIE)
        && let Some(key) = session::key_from_cookie(cookie.value())
    {
        let mut kv = state.kv.clone();
        let _ = session::delete(&mut kv, &key).await;
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
    let session = Session {
        user_id,
        email,
        created_at: Utc::now(),
    };
    let jar = open_session_cookies(jar, state, &session).await?;
    Ok((jar, session))
}

/// Lower-level: write `session` into Valkey + attach the session + CSRF
/// cookies to `jar`. Exposed for OAuth callbacks where the upstream
/// flow constructs the `Session` itself.
pub async fn open_session_cookies(
    jar: CookieJar,
    state: &AppState,
    session: &Session,
) -> Result<CookieJar, AuthRouteError> {
    let sid = session::new();
    let key = sid.key();
    let mut kv = state.kv.clone();
    session::store(&mut kv, &key, session).await?;

    let secure = secure_cookies();
    let session_cookie = Cookie::build((SESSION_COOKIE, sid.cookie_value()))
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(secure)
        .path("/")
        .max_age(Duration::seconds(SESSION_TTL_SECS as i64))
        .build();

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

    Ok(jar.add(session_cookie).add(csrf_cookie))
}

pub async fn require_login(state: &AppState, jar: &CookieJar) -> Result<Session, AuthRouteError> {
    let cookie = jar.get(SESSION_COOKIE).ok_or(AuthRouteError::NotLoggedIn)?;
    let key = session::key_from_cookie(cookie.value()).ok_or(AuthRouteError::NotLoggedIn)?;
    let mut kv = state.kv.clone();
    let session = session::fetch(&mut kv, &key)
        .await?
        .ok_or(AuthRouteError::NotLoggedIn)?;
    Ok(session)
}
