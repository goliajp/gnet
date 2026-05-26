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
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("gnet-discover: {e}");
            ExitCode::FAILURE
        }
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
