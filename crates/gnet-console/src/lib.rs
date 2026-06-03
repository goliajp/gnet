//! gnet v1.1 control-plane backend (axum + PG18 + Valkey).
//!
//! Separate binary, separate host. The daemon's data-plane keeps working
//! when this process is down — once a device is registered, day-to-day
//! overlay traffic uses only the cached coord roster and direct/relay paths
//! (see ROADMAP "Architectural ground rules").

pub mod auth;
pub mod config;
pub mod error;
pub mod oauth;
pub mod routes;
pub mod session;
pub mod state;

use std::collections::HashMap;
use std::sync::Arc;

use config::Config;
use state::AppState;

pub async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = Config::from_env()?;
    tracing::info!(bind = %config.bind, "gnet-console starting");

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(16)
        .connect(&config.database_url)
        .await?;

    tracing::info!("running migrations");
    gnet_console_schema::MIGRATOR.run(&pool).await?;

    let redis_client = redis::Client::open(config.valkey_url.as_str())?;
    let kv = redis::aio::ConnectionManager::new(redis_client).await?;
    tracing::info!(valkey = %config.valkey_url, "valkey connected");

    if config.auto_verify_email {
        tracing::warn!(
            "auto_verify_email=true (no MAILRS_SMTP_HOST configured) — signups go live without email verification"
        );
    }

    let http = reqwest::Client::builder()
        .user_agent("gnet-console")
        .build()?;

    let mut oauth: HashMap<&'static str, oauth::Provider> = HashMap::new();
    if let Some(g) = oauth::google::Google::from_env() {
        oauth.insert("google", oauth::Provider::Google(g));
        tracing::info!("oauth provider configured: google");
    }
    if let Some(g) = oauth::github::GitHub::from_env() {
        oauth.insert("github", oauth::Provider::GitHub(g));
        tracing::info!("oauth provider configured: github");
    }
    if oauth.is_empty() {
        tracing::warn!(
            "no OAuth providers configured (set GOOGLE_OAUTH_CLIENT_ID/SECRET, GITHUB_OAUTH_CLIENT_ID/SECRET in .env.local)"
        );
    }

    let state = AppState {
        pool,
        kv,
        http,
        public_url: config.public_url.clone(),
        oauth: Arc::new(oauth),
        auto_verify_email: config.auto_verify_email,
    };
    let app = routes::router(state);

    let listener = tokio::net::TcpListener::bind(&config.bind).await?;
    tracing::info!(addr = %listener.local_addr()?, "listening");
    axum::serve(listener, app).await?;
    Ok(())
}
