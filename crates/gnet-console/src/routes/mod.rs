use axum::Router;

use crate::state::AppState;

pub mod banner;
pub mod health;

pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(banner::routes())
        .merge(health::routes())
        .with_state(state)
}
