use axum::Router;
use axum::middleware;

use crate::admin::AdminState;

pub mod auth;
pub mod csrf;
pub mod device_writes;
pub mod devices;
pub mod federation;
pub mod host_role;
pub mod internal;
pub mod network;
pub mod setup;
pub mod spa;

pub fn router(state: AdminState) -> Router {
    Router::new()
        .merge(host_role::routes())
        .merge(setup::routes())
        .merge(auth::routes())
        .merge(network::routes())
        .merge(devices::routes())
        .merge(device_writes::routes())
        .merge(internal::routes())
        .merge(federation::routes())
        // SPA fallback last — API routes above win on their exact-match
        // paths; everything else falls through to spa::serve, which
        // returns a real asset under `console/dist/*` or the SPA shell
        // for deep links (plan §3.4).
        .merge(spa::routes())
        .with_state(state)
        // CSRF guard wraps the whole router. The guard itself filters by
        // method + path, so safe methods and pre-auth endpoints sail
        // through; write endpoints (when they land) get protection for
        // free. `/api/internal/*` is also exempt (bearer-auth path).
        .layer(middleware::from_fn(csrf::guard))
}
