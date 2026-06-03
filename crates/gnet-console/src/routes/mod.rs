use axum::Router;
use axum::middleware;

use crate::state::AppState;

pub mod auth;
pub mod banner;
pub mod csrf;
pub mod headers;
pub mod health;
pub mod host_role;
pub mod networks;
pub mod oauth;
pub mod proxy;
pub mod spa;

pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(banner::routes())
        .merge(health::routes())
        .merge(host_role::routes())
        .merge(auth::routes())
        .merge(oauth::routes())
        .merge(networks::routes())
        .merge(proxy::routes())
        // SPA fallback must merge last so the API routes above win
        // their exact-match paths first. Any path not matched falls
        // through to spa::serve which returns a real asset or the
        // SPA shell (plan §3.4).
        .merge(spa::routes())
        .with_state(state)
        .layer(middleware::from_fn(csrf::guard))
        // Defensive HTTP headers ride on every response. Outermost
        // so they wrap CSRF rejections too (plan §17.12 hardening).
        .layer(middleware::from_fn(headers::add_headers))
}
