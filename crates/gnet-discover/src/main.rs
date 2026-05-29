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

    // Warm-standby: if a primary is configured, mirror its state on an interval.
    // Pulled out before `config` moves into `AppState`.
    let standby = config.primary.clone().map(|primary| {
        (primary, config.sync_interval, config.admin_token.clone())
    });

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

    let listener = tokio::net::TcpListener::bind(bind).await?;
    eprintln!("gnet-discover: listening on {bind}");
    serve(listener, state, handler()).await?;
    Ok(())
}
