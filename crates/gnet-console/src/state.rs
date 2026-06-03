use redis::aio::ConnectionManager;
use sqlx::PgPool;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub kv: ConnectionManager,
    /// Mirrored from [`crate::config::Config::auto_verify_email`].
    pub auto_verify_email: bool,
}
