//! `user_networks` — the console-side mapping the user sees as "my
//! networks". Each row maps a friendly label + dispatcher endpoint to
//! the federated dispatcher; the bearer token used against that
//! dispatcher is re-derived on demand (see `crate::federation`).

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum_extra::extract::cookie::CookieJar;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::federation::derive_token;
use crate::routes::auth::{AuthRouteError, require_login};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub network_label: String,
    pub dispatcher_endpoint: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub id: Uuid,
    pub network_label: String,
    pub dispatcher_endpoint: String,
    pub mode: &'static str,
    /// Plaintext federation token — shown to the user **exactly once**
    /// so they can paste it into the dispatcher's admin UI. The console
    /// neither stores nor caches this; subsequent uses are re-derived
    /// from the master + network identity.
    pub federation_token: String,
}

#[derive(Serialize, FromRow)]
pub struct NetworkRow {
    pub id: Uuid,
    pub network_label: String,
    pub dispatcher_endpoint: String,
    pub mode: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("not logged in")]
    NotLoggedIn,
    #[error("network_label must be 3-32 chars of [a-z0-9_-]")]
    BadLabel,
    #[error("dispatcher_endpoint must be http(s)://… 1024 chars max")]
    BadEndpoint,
    #[error("network_label already in use")]
    LabelConflict,
    #[error("session: {0}")]
    Session(#[from] crate::session::SessionError),
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
}

impl From<AuthRouteError> for NetworkError {
    fn from(e: AuthRouteError) -> Self {
        match e {
            AuthRouteError::NotLoggedIn => NetworkError::NotLoggedIn,
            AuthRouteError::BadCreds => NetworkError::NotLoggedIn,
            AuthRouteError::Session(s) => NetworkError::Session(s),
            AuthRouteError::Db(d) => NetworkError::Db(d),
            // Other AuthRouteError variants never originate from
            // require_login() but the conversion has to be total.
            _ => NetworkError::NotLoggedIn,
        }
    }
}

impl IntoResponse for NetworkError {
    fn into_response(self) -> Response {
        let code = match self {
            NetworkError::NotLoggedIn => StatusCode::UNAUTHORIZED,
            NetworkError::BadLabel | NetworkError::BadEndpoint => StatusCode::BAD_REQUEST,
            NetworkError::LabelConflict => StatusCode::CONFLICT,
            NetworkError::Session(_) | NetworkError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (code, self.to_string()).into_response()
    }
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/networks", get(list).post(register))
}

fn valid_label(s: &str) -> bool {
    let len = s.len();
    (3..=32).contains(&len)
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

fn valid_endpoint(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 1024
        && (s.starts_with("http://") || s.starts_with("https://"))
}

async fn list(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Vec<NetworkRow>>, NetworkError> {
    let session = require_login(&state, &jar).await?;
    let rows: Vec<NetworkRow> = sqlx::query_as(
        "SELECT id, network_label, dispatcher_endpoint, mode, role, created_at \
         FROM user_networks WHERE user_id = $1 ORDER BY created_at DESC",
    )
    .bind(session.user_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

async fn register(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), NetworkError> {
    let session = require_login(&state, &jar).await?;
    let label = req.network_label.trim().to_string();
    let endpoint = req.dispatcher_endpoint.trim().trim_end_matches('/').to_string();
    if !valid_label(&label) {
        return Err(NetworkError::BadLabel);
    }
    if !valid_endpoint(&endpoint) {
        return Err(NetworkError::BadEndpoint);
    }

    let id = Uuid::new_v4();
    let token = derive_token(
        &state.federation_secret,
        session.user_id,
        &label,
        &endpoint,
    );

    let insert = sqlx::query(
        "INSERT INTO user_networks \
            (id, user_id, network_label, mode, dispatcher_endpoint) \
         VALUES ($1, $2, $3, 'self_host', $4)",
    )
    .bind(id)
    .bind(session.user_id)
    .bind(&label)
    .bind(&endpoint)
    .execute(&state.pool)
    .await;
    match insert {
        Ok(_) => {}
        Err(sqlx::Error::Database(db_err)) if db_err.code().as_deref() == Some("23505") => {
            return Err(NetworkError::LabelConflict);
        }
        Err(other) => return Err(other.into()),
    }

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            id,
            network_label: label,
            dispatcher_endpoint: endpoint,
            mode: "self_host",
            federation_token: token,
        }),
    ))
}
