use std::collections::HashMap;
use std::sync::Arc;

use redis::aio::ConnectionManager;
use sqlx::PgPool;

use crate::mail::MailClient;
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
    pub federation_secret: [u8; 32],
    /// mailrs transport. `Some` when the four `MAILRS_*` env vars are
    /// set; `None` matches the auto-verify mode in `auto_verify_email`.
    /// The two are kept consistent in `Config::from_env`.
    pub mail: Option<MailClient>,
}
