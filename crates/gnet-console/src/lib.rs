//! gnet v1.1 control-plane backend (axum + PG18 + Valkey).
//!
//! Separate binary, separate host. The daemon's data-plane keeps working
//! when this process is down — once a device is registered, day-to-day
//! overlay traffic uses only the cached coord roster and direct/relay paths
//! (see ROADMAP "Architectural ground rules").

pub mod config;
pub mod error;
pub mod routes;
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

    let state = AppState { pool };
    let app = routes::router(state);

    let listener = tokio::net::TcpListener::bind(&config.bind).await?;
    tracing::info!(addr = %listener.local_addr()?, "listening");
    axum::serve(listener, app).await?;
    Ok(())
}
