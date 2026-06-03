//! Reverse-proxy route — forward `/api/networks/{id}/proxy/<path>` to
//! the federated dispatcher's `/<path>` with a freshly derived Bearer
//! token attached.
//!
//! The console is the federation translation layer (plan §2): the SPA
//! talks only to the console; the dispatcher accepts only its own
//! shape of auth (cookie session for the local admin path, federation
//! bearer for the SaaS path). This handler bridges them by re-deriving
//! the federation token from `(master, user_id, network_label,
//! dispatcher_endpoint)` and stamping it on the outbound request.
//!
//! The plaintext token never sits at rest in the console.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum_extra::extract::cookie::CookieJar;
use uuid::Uuid;

use crate::federation::derive_token;
use crate::routes::auth::{AuthRouteError, require_login};
use crate::state::AppState;

const MAX_BODY: usize = 10 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("not logged in")]
    NotLoggedIn,
    #[error("network not found")]
    NotFound,
    #[error("auth: {0}")]
    Auth(#[from] AuthRouteError),
    #[error("db: {0}")]
    Db(#[from] sqlx::Error),
    #[error("upstream: {0}")]
    Upstream(#[from] reqwest::Error),
    #[error("body: {0}")]
    Body(axum::Error),
    #[error("bad method")]
    BadMethod,
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        let code = match self {
            ProxyError::NotLoggedIn | ProxyError::Auth(_) => StatusCode::UNAUTHORIZED,
            ProxyError::NotFound => StatusCode::NOT_FOUND,
            ProxyError::BadMethod => StatusCode::BAD_REQUEST,
            ProxyError::Db(_) | ProxyError::Upstream(_) | ProxyError::Body(_) => {
                StatusCode::BAD_GATEWAY
            }
        };
        (code, self.to_string()).into_response()
    }
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/api/networks/{id}/proxy/{*rest}", any(proxy))
}

async fn proxy(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, rest)): Path<(Uuid, String)>,
    req: Request,
) -> Result<Response, ProxyError> {
    let session = require_login(&state, &jar).await?;

    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT network_label, dispatcher_endpoint FROM user_networks \
         WHERE id = $1 AND user_id = $2",
    )
    .bind(id)
    .bind(session.user_id)
    .fetch_optional(&state.pool)
    .await?;
    let (label, endpoint) = row.ok_or(ProxyError::NotFound)?;

    let token = derive_token(&state.federation_secret, session.user_id, &label, &endpoint);

    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let target = format!("{endpoint}/{rest}{query}");

    let method = req.method().clone();
    let req_content_type = req
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let body = axum::body::to_bytes(req.into_body(), MAX_BODY)
        .await
        .map_err(ProxyError::Body)?;

    let rq_method = reqwest::Method::from_bytes(method.as_str().as_bytes())
        .map_err(|_| ProxyError::BadMethod)?;

    let mut upstream_req = state
        .http
        .request(rq_method, &target)
        .bearer_auth(&token)
        .body(Bytes::from(body));
    if let Some(ct) = req_content_type {
        upstream_req = upstream_req.header(reqwest::header::CONTENT_TYPE, ct);
    }
    let upstream = upstream_req.send().await?;

    let status = StatusCode::from_u16(upstream.status().as_u16())
        .unwrap_or(StatusCode::BAD_GATEWAY);
    let resp_ct = upstream
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let resp_body = upstream.bytes().await?;

    let mut resp = (status, resp_body).into_response();
    if let Some(ct) = resp_ct {
        if let Ok(v) = axum::http::HeaderValue::from_str(&ct) {
            resp.headers_mut().insert(axum::http::header::CONTENT_TYPE, v);
        }
    }
    Ok(resp)
}
