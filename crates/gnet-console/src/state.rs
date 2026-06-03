use std::collections::HashMap;
use std::sync::Arc;

use redis::aio::ConnectionManager;
use sqlx::PgPool;

use crate::oauth::Provider;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub kv: ConnectionManager,
    pub http: reqwest::Client,
    pub public_url: String,
    pub oauth: Arc<HashMap<&'static str, Provider>>,
    /// Mirrored from [`crate::config::Config::auto_verify_email`].
    pub auto_verify_email: bool,
}
