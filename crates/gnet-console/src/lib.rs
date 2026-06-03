//! gnet v1.1 control-plane backend (axum + PG18 + Valkey).
//!
//! Separate binary, separate host. The daemon's data-plane keeps working
//! when this process is down — once a device is registered, day-to-day
//! overlay traffic uses only the cached coord roster and direct/relay paths
//! (see ROADMAP "Architectural ground rules").

pub mod auth;
pub mod config;
pub mod error;
pub mod routes;
pub mod session;
pub mod state;

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

    let state = AppState {
        pool,
        kv,
        auto_verify_email: config.auto_verify_email,
    };
    let app = routes::router(state);

    let listener = tokio::net::TcpListener::bind(&config.bind).await?;
    tracing::info!(addr = %listener.local_addr()?, "listening");
    axum::serve(listener, app).await?;
    Ok(())
}
