//! Dispatcher admin HTTP server.
//!
//! Runs alongside the v1.0 coord listener inside the same `gnet-discover`
//! binary. Listens on its own TCP port (default 0.0.0.0:8765 per
//! `docs/v1.1-plan.md` §16.1) and serves the admin API the console (Mode A
//! / C) and the self-host SPA (Mode B) both consume.
//!
//! Opt-in: enabled when `GNET_DISCOVER_DATABASE_URL` is set. Otherwise the
//! binary keeps behaving as a pure v1.0 coord — the v1.0→v1.1 transition
//! is a config flip, not a code rebuild.
//!
//! This file owns the admin server's startup path:
//!
//! - connect to PG, run dispatcher-side migrations
//! - resolve (or create) the single `networks` row this admin instance
//!   serves (self-host single-network case; SaaS multi-tenant arrives
//!   when the federation layer lands)
//! - mount the axum router and start serving

pub mod auth;
pub mod bootstrap;
pub mod config;
pub mod routes;
pub mod session;
pub mod state;

pub use config::{AdminConfig, AdminConfigError};
pub use state::AdminState;

use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum AdminServeError {
    #[error("config: {0}")]
    Config(#[from] AdminConfigError),
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    #[error("migrate: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("valkey: {0}")]
    Valkey(#[from] redis::RedisError),
    #[error("bind {bind}: {source}")]
    Bind {
        bind: std::net::SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("serve: {0}")]
    Serve(std::io::Error),
    #[error("{0}")]
    Init(String),
}

/// Start the admin server. Blocks until shutdown.
pub async fn serve(config: AdminConfig) -> Result<(), AdminServeError> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(16)
        .connect(&config.database_url)
        .await?;

    gnet_discover_schema::MIGRATOR.run(&pool).await?;

    let (network_id, network_name) = resolve_network(&pool, &config).await?;
    eprintln!(
        "gnet-discover admin: network = {network_name} ({network_id})"
    );

    let redis_client = redis::Client::open(config.valkey_url.as_str())?;
    let kv = redis::aio::ConnectionManager::new(redis_client).await?;
    eprintln!("gnet-discover admin: valkey connected ({})", config.valkey_url);

    bootstrap::ensure_first_admin_setup(&pool, network_id, &network_name, config.admin_bind)
        .await?;

    let state = AdminState {
        pool,
        kv,
        network_id,
        network_name,
    };

    let app = routes::router(state);

    let listener = tokio::net::TcpListener::bind(config.admin_bind)
        .await
        .map_err(|source| AdminServeError::Bind {
            bind: config.admin_bind,
            source,
        })?;

    let local = listener.local_addr().unwrap_or(config.admin_bind);
    eprintln!("gnet-discover admin: listening on {local}");

    // §16.1: 0.0.0.0 default is deliberate. Print a loud warning so the
    // operator who didn't want LAN exposure has one chance to notice
    // before walking away from the box.
    if local.ip().is_unspecified() {
        eprintln!(
            "gnet-discover admin: WARNING — admin port is reachable from the LAN. \
             Set GNET_DISCOVER_ADMIN_BIND=127.0.0.1:{} to bind loopback-only.",
            local.port()
        );
    }

    axum::serve(listener, app).await.map_err(AdminServeError::Serve)?;
    Ok(())
}

/// Resolve the network this admin instance is serving. Three cases:
///
/// 1. `GNET_DISCOVER_NETWORK_ID` set → look it up; fail if missing.
/// 2. No hint, exactly one row in `networks` → use it (self-host steady).
/// 3. No hint, zero rows in `networks` → create one with the configured
///    name + the hard-coded overlay prefixes (self-host first-boot).
///
/// More than one row with no hint is an ambiguity we refuse, not a silent
/// pick — the operator must point. The SaaS multi-tenant path doesn't go
/// through this function; it goes through the console-driven minting
/// surface that ships with the federation layer.
async fn resolve_network(
    pool: &PgPool,
    config: &AdminConfig,
) -> Result<(Uuid, String), AdminServeError> {
    if let Some(hint) = config.network_id_hint {
        let row: Option<(String,)> = sqlx::query_as("SELECT name FROM networks WHERE id = $1")
            .bind(hint)
            .fetch_optional(pool)
            .await?;
        return row
            .map(|(name,)| (hint, name))
            .ok_or_else(|| {
                AdminServeError::Init(format!(
                    "GNET_DISCOVER_NETWORK_ID {hint} not found in PG"
                ))
            });
    }

    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*)::bigint FROM networks")
        .fetch_one(pool)
        .await?;

    match count {
        0 => create_default_network(pool, config).await,
        1 => Ok(sqlx::query_as::<_, (Uuid, String)>(
            "SELECT id, name FROM networks LIMIT 1",
        )
        .fetch_one(pool)
        .await?),
        _ => Err(AdminServeError::Init(format!(
            "{count} networks present; set GNET_DISCOVER_NETWORK_ID to disambiguate"
        ))),
    }
}

async fn create_default_network(
    pool: &PgPool,
    config: &AdminConfig,
) -> Result<(Uuid, String), AdminServeError> {
    let id = Uuid::new_v4();
    let name = config.network_name.clone();
    // Defaults consistent with `crate::config::Config::from_env` — until
    // the operator-facing overlay-prefix config lands, dispatcher and
    // coord must agree, and coord still hard-codes these.
    let v4_prefix = vec![10u8, 42, 42];
    let v6_prefix: Vec<u8> = [0xfd8d_u16, 0xf090, 0x2ebb, 0x0000]
        .iter()
        .flat_map(|w| w.to_be_bytes())
        .collect();

    sqlx::query(
        "INSERT INTO networks (id, name, overlay_v4_prefix, overlay_v6_prefix) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(&name)
    .bind(&v4_prefix)
    .bind(&v6_prefix)
    .execute(pool)
    .await?;

    eprintln!(
        "gnet-discover admin: created default network {name} ({id}) on empty PG"
    );
    Ok((id, name))
}
