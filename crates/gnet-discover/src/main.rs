use std::process::ExitCode;
use std::sync::Arc;

use gnet_discover::api::{AppState, handler};
use gnet_discover::auth::JoinTokenStore;
use gnet_discover::config::Config;
use gnet_discover::http::serve;
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
        Some("--help") | Some("-h") => {
            eprintln!("usage:");
            eprintln!("  gnet-discover                  serve the coordinator (config from env)");
            eprintln!("  gnet-discover --validate-state load state.json + exit 0/1 (failover check)");
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

    let state = Arc::new(AppState {
        config,
        store,
        join_tokens: JoinTokenStore::new(),
    });
    let listener = tokio::net::TcpListener::bind(bind).await?;
    eprintln!("gnet-discover: listening on {bind}");
    serve(listener, state, handler()).await?;
    Ok(())
}
