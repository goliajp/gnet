use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use gnet_discover::api::{AppState, handler};
use gnet_discover::auth::JoinTokenStore;
use gnet_discover::config::Config;
use gnet_discover::http::serve;
use gnet_discover::import::{ImportInput, import_state};
use gnet_discover::state::Store;

#[tokio::main]
async fn main() -> ExitCode {
    init_log();
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--validate-state") => match validate_state().await {
            Ok(devices) => {
                println!("ok: state.json loads cleanly ({devices} devices)");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("gnet-discover --validate-state: {e}");
                ExitCode::FAILURE
            }
        },
        Some("--import-state") => match import_cmd().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("gnet-discover --import-state: {e}");
                ExitCode::FAILURE
            }
        },
        Some("--help") | Some("-h") => {
            eprintln!("usage:");
            eprintln!("  gnet-discover                  serve the coordinator (config from env)");
            eprintln!(
                "  gnet-discover --validate-state load state.json + exit 0/1 (failover check)"
            );
            eprintln!(
                "  gnet-discover --import-state   one-shot v1.0 state.json -> v1.1 PG migration"
            );
            eprintln!();
            eprintln!("env (--import-state):");
            eprintln!("  GNET_DISCOVER_STATE_PATH               path to state.json");
            eprintln!("  GNET_DISCOVER_DATABASE_URL             postgres://user:pass@host/db");
            eprintln!(
                "  GNET_DISCOVER_RELAYS                   comma-separated host:port (optional)"
            );
            eprintln!(
                "  GNET_DISPATCHER_IMPORT_NETWORK_NAME    network name (default: imported-from-v1.0)"
            );
            ExitCode::SUCCESS
        }
        _ => match run().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("gnet-discover: {e}");
                ExitCode::FAILURE
            }
        },
    }
}

/// Smoke-test that the configured state.json path loads + parses + matches the
/// current `Device` schema. Operators run this on a warm-standby host against
/// the latest scp'd backup to verify it's restoreable BEFORE the primary
/// coordinator goes down. Returns the device count on success.
async fn validate_state() -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let config = Config::from_env()?;
    let store = Store::load(&config.state_path).await?;
    let snapshot = store.snapshot().await;
    Ok(snapshot.devices.len())
}

/// One-shot v1.0 -> v1.1 importer (see `import.rs` and v1.1-plan §12).
/// Deliberately decoupled from `Config::from_env` — the importer doesn't
/// need the admin token, the bind address, or the warm-standby config; it
/// only needs state.json, PG, and the overlay prefixes / relay list. Keeps
/// the import path runnable on a fresh box with no serve-time env at all.
async fn import_cmd() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state_path: PathBuf = std::env::var("GNET_DISCOVER_STATE_PATH")
        .unwrap_or_else(|_| "/var/lib/gnet-discover/state.json".to_string())
        .into();
    let db_url = std::env::var("GNET_DISCOVER_DATABASE_URL").map_err(
        |_| "GNET_DISCOVER_DATABASE_URL not set (e.g. postgres://user:pass@127.0.0.1/gnet)",
    )?;
    let network_name = std::env::var("GNET_DISPATCHER_IMPORT_NETWORK_NAME")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "imported-from-v1.0".to_string());
    let relays = parse_relays_env()?;

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&db_url)
        .await?;
    gnet_discover_schema::MIGRATOR.run(&pool).await?;

    let input = ImportInput {
        state_path: &state_path,
        network_name,
        // Same hard-coded prefixes Config::from_env uses today; surfacing
        // them as importer env is a follow-up if anyone needs a non-default.
        overlay_v4_prefix: [10, 42, 42],
        overlay_v6_prefix: [0xfd8d, 0xf090, 0x2ebb, 0],
        relays: &relays,
    };

    let summary = import_state(&input, &pool).await?;

    println!(
        "imported network: {} ({})",
        summary.network_name, summary.network_id
    );
    println!("  devices:           {}", summary.devices_imported);
    println!("  relays:            {}", summary.relays_imported);
    println!("  state.json -> {}", summary.imported_marker.display());
    Ok(())
}

/// Local copy of `Config::from_env`'s relay-list parsing, kept here so the
/// import CLI can avoid pulling in the rest of the serve-time env contract.
fn parse_relays_env() -> Result<Vec<SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
    match std::env::var("GNET_DISCOVER_RELAYS") {
        Ok(raw) => raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.parse::<SocketAddr>()
                    .map_err(|e| format!("GNET_DISCOVER_RELAYS: {s:?} -> {e}").into())
            })
            .collect(),
        Err(_) => Ok(Vec::new()),
    }
}

fn init_log() {
    // tracing's facade is in the allow-list; tracing-subscriber is not. Wire a
    // tiny eprintln-based subscriber via `tracing::dispatcher` would still pull
    // dependencies, so leave the global subscriber unset — `tracing::warn!` /
    // `info!` calls become no-ops, but errors that matter are surfaced via
    // explicit `eprintln!` in main + `Display` on `Error`.
}

async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = Config::from_env()?;
    let store = Store::load(&config.state_path).await?;
    let bind = config.bind;

    // Warm-standby: if a primary is configured, mirror its state on an interval.
    // Pulled out before `config` moves into `AppState`.
    let standby = config
        .primary
        .clone()
        .map(|primary| (primary, config.sync_interval, config.admin_token.clone()));

    let state = Arc::new(AppState {
        config,
        store,
        join_tokens: JoinTokenStore::new(),
    });

    if let Some((primary, interval, admin_token)) = standby {
        eprintln!(
            "gnet-discover: warm-standby, mirroring {primary} every {}s",
            interval.as_secs()
        );
        let store = state.store.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                match gnet_discover::sync::fetch_state(&primary, &admin_token).await {
                    Ok(new) => {
                        // Overwrite the whole table — the primary is authoritative.
                        // Reuses the store's atomic persist so a standby's on-disk
                        // state.json is always a valid restore point.
                        if let Err(e) = store.mutate(move |st| *st = new).await {
                            eprintln!("event=state_sync_persist_failed error=\"{e}\"");
                        }
                    }
                    // Keep serving the last good snapshot on transient failure.
                    Err(e) => eprintln!("event=state_sync_failed primary={primary} error=\"{e}\""),
                }
            }
        });
    }

    // v1.1 admin server — opt-in via GNET_DISCOVER_DATABASE_URL. The
    // existing coord listener below is unchanged; this just adds a sibling
    // task in the same process. Failure of admin serve logs and stays
    // contained — coord traffic must keep flowing through a v1.1
    // dispatcher just like it did through a v1.0 coord.
    match gnet_discover::admin::AdminConfig::from_env() {
        Ok(Some(admin_cfg)) => {
            eprintln!(
                "gnet-discover admin: enabled (bind {}), startup may take a moment for migrations",
                admin_cfg.admin_bind
            );
            tokio::spawn(async move {
                if let Err(e) = gnet_discover::admin::serve(admin_cfg).await {
                    eprintln!("event=admin_serve_failed error=\"{e}\"");
                }
            });
        }
        Ok(None) => {
            // v1.0 coord-only fallthrough.
        }
        Err(e) => return Err(Box::new(e)),
    }

    let listener = tokio::net::TcpListener::bind(bind).await?;
    eprintln!("gnet-discover: listening on {bind}");
    serve(listener, state, handler()).await?;
    Ok(())
}
