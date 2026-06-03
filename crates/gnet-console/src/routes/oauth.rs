//! OAuth start + callback handlers.
//!
//! GET /api/auth/oauth/{provider}/start
//!   - mint nonce, store in Valkey scoped to provider (TTL 10 min),
//!   - set HttpOnly state cookie carrying the same nonce,
//!   - 303 redirect to the provider's authorize URL.
//!
//! GET /api/auth/oauth/{provider}/callback
//!   - require state cookie == ?state query == Valkey value,
//!   - exchange code, fetch external user,
//!   - upsert users + oauth_identities,
//!   - open a session, clear state cookie, 303 redirect to "/".

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::Utc;
use redis::AsyncCommands;
use serde::Deserialize;
use time::Duration;
use uuid::Uuid;

use crate::oauth::OAuthError;
use crate::routes::auth::{AuthRouteError, open_session_cookies};
use crate::session::Session;
use crate::state::AppState;

const STATE_COOKIE: &str = "gnet_oauth_state";
const STATE_TTL_SECS: u64 = 600;

#[derive(Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum OAuthRouteError {
    #[error("{0}")]
    OAuth(#[from] OAuthError),
    #[error("missing `code` in callback")]
    MissingCode,
    #[error("missing `state` in callback")]
    MissingState,
    #[error("missing state cookie")]
    NoStateCookie,
    #[error("auth: {0}")]
    Auth(#[from] AuthRouteError),
    #[error("session: {0}")]
    Session(#[from] crate::session::SessionError),
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
}

impl IntoResponse for OAuthRouteError {
    fn into_response(self) -> Response {
        let code = match &self {
            OAuthRouteError::OAuth(OAuthError::NotConfigured(_))
            | OAuthRouteError::OAuth(OAuthError::Unknown(_)) => StatusCode::NOT_FOUND,
            OAuthRouteError::OAuth(OAuthError::StateMismatch)
            | OAuthRouteError::OAuth(OAuthError::StateExpired)
            | OAuthRouteError::NoStateCookie
            | OAuthRouteError::MissingState => StatusCode::UNAUTHORIZED,
            OAuthRouteError::MissingCode
            | OAuthRouteError::OAuth(OAuthError::Provider(_))
            | OAuthRouteError::OAuth(OAuthError::MissingEmail) => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (code, self.to_string()).into_response()
    }
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/auth/oauth/{provider}/start", get(start))
        .route("/api/auth/oauth/{provider}/callback", get(callback))
}

async fn start(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(provider): Path<String>,
) -> Result<(CookieJar, Redirect), OAuthRouteError> {
    let p = state
        .oauth
        .get(provider.as_str())
        .ok_or_else(|| OAuthError::NotConfigured(provider.clone()))?;

    let mut raw = [0u8; 32];
    gnet_rand::fill(&mut raw);
    let nonce = gnet_hex::encode(&raw);

    let mut kv = state.kv.clone();
    let key = format!("gnet:console:oauth:state:{nonce}");
    let _: () = kv
        .set_ex(&key, p.name(), STATE_TTL_SECS)
        .await
        .map_err(OAuthError::Redis)?;

    let redirect_uri = format!(
        "{}/api/auth/oauth/{}/callback",
        state.public_url,
        p.name()
    );
    let url = p.authorize_url(&nonce, &redirect_uri);

    let cookie = Cookie::build((STATE_COOKIE, nonce))
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(super::auth::secure_cookies())
        .path("/")
        .max_age(Duration::seconds(STATE_TTL_SECS as i64))
        .build();

    Ok((jar.add(cookie), Redirect::to(&url)))
}

async fn callback(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(provider): Path<String>,
    Query(q): Query<CallbackQuery>,
) -> Result<(CookieJar, Redirect), OAuthRouteError> {
    if let Some(err) = q.error {
        return Err(OAuthError::Provider(err).into());
    }
    let code = q.code.ok_or(OAuthRouteError::MissingCode)?;
    let qstate = q.state.ok_or(OAuthRouteError::MissingState)?;

    let cookie_state = jar
        .get(STATE_COOKIE)
        .map(|c| c.value().to_string())
        .ok_or(OAuthRouteError::NoStateCookie)?;
    if cookie_state != qstate {
        return Err(OAuthError::StateMismatch.into());
    }

    let mut kv = state.kv.clone();
    let key = format!("gnet:console:oauth:state:{qstate}");
    let stored: Option<String> = kv.get(&key).await.map_err(OAuthError::Redis)?;
    match stored.as_deref() {
        Some(name) if name == provider => {}
        _ => return Err(OAuthError::StateExpired.into()),
    }
    let _: () = kv.del(&key).await.map_err(OAuthError::Redis)?;

    let p = state
        .oauth
        .get(provider.as_str())
        .ok_or_else(|| OAuthError::NotConfigured(provider.clone()))?;
    let redirect_uri = format!(
        "{}/api/auth/oauth/{}/callback",
        state.public_url,
        p.name()
    );
    let mut kv = state.kv.clone();
    let ext = p
        .identify(&state.http, &mut kv, &code, &redirect_uri)
        .await?;

    let mut tx = state.pool.begin().await?;
    let existing: Option<(Uuid,)> = sqlx::query_as(
        "SELECT user_id FROM oauth_identities \
         WHERE provider = $1 AND provider_subject = $2",
    )
    .bind(ext.provider)
    .bind(&ext.provider_subject)
    .fetch_optional(&mut *tx)
    .await?;

    let user_id = match existing {
        Some((id,)) => id,
        None => {
            // First sign-in for this provider identity. We accept the
            // email if the provider returned one — duplicate email
            // collision (same person clicked Google then GitHub) is left
            // for the dedicated "link identities" UI; here we silently
            // store NULL on collision rather than crash, so the user can
            // resolve from inside the SPA.
            let new_id = Uuid::new_v4();
            let email = match ext.email.clone() {
                Some(e) => {
                    let dup: Option<(Uuid,)> = sqlx::query_as(
                        "SELECT id FROM users WHERE email = $1",
                    )
                    .bind(&e)
                    .fetch_optional(&mut *tx)
                    .await?;
                    if dup.is_some() { None } else { Some(e) }
                }
                None => None,
            };
            sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
                .bind(new_id)
                .bind(email.as_deref())
                .execute(&mut *tx)
                .await?;
            sqlx::query(
                "INSERT INTO oauth_identities (id, user_id, provider, provider_subject, email_snapshot) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(Uuid::new_v4())
            .bind(new_id)
            .bind(ext.provider)
            .bind(&ext.provider_subject)
            .bind(ext.email.as_deref())
            .execute(&mut *tx)
            .await?;
            new_id
        }
    };
    tx.commit().await?;

    let session = Session {
        user_id,
        email: ext.email.clone(),
        created_at: Utc::now(),
    };
    let jar_after = open_session_cookies(jar, &state, &session).await?;

    // Drop the now-spent state cookie.
    let cleared = Cookie::build((STATE_COOKIE, ""))
        .path("/")
        .max_age(Duration::ZERO)
        .build();
    Ok((jar_after.add(cleared), Redirect::to("/")))
}
