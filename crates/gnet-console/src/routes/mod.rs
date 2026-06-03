use axum::Router;
use axum::middleware;

use crate::state::AppState;

pub mod auth;
pub mod banner;
pub mod csrf;
pub mod health;
pub mod host_role;

pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(banner::routes())
        .merge(health::routes())
        .merge(host_role::routes())
        .merge(auth::routes())
        .with_state(state)
        .layer(middleware::from_fn(csrf::guard))
}
