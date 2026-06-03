use axum::Router;
use axum::middleware;

use crate::admin::AdminState;

pub mod auth;
pub mod csrf;
pub mod devices;
pub mod host_role;
pub mod internal;
pub mod network;
pub mod setup;

pub fn router(state: AdminState) -> Router {
    Router::new()
        .merge(host_role::routes())
        .merge(setup::routes())
        .merge(auth::routes())
        .merge(network::routes())
        .merge(devices::routes())
        .merge(internal::routes())
        .with_state(state)
        // CSRF guard wraps the whole router. The guard itself filters by
        // method + path, so safe methods and pre-auth endpoints sail
        // through; write endpoints (when they land) get protection for
        // free. `/api/internal/*` is also exempt (bearer-auth path).
        .layer(middleware::from_fn(csrf::guard))
}
