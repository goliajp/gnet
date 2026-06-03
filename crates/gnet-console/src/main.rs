use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    init_log();
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--help") | Some("-h") => {
            eprintln!("usage:");
            eprintln!("  gnet-console   serve the v1.1 control plane (config from env)");
            eprintln!();
            eprintln!("env vars:");
            eprintln!("  GNET_CONSOLE_BIND          default 127.0.0.1:8765");
            eprintln!("  GNET_CONSOLE_DATABASE_URL  required, postgres://user:pass@host/db");
            eprintln!("  RUST_LOG                   default info");
            ExitCode::SUCCESS
        }
        _ => match gnet_console::run().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("gnet-console: {e}");
                ExitCode::FAILURE
            }
        },
    }
}

fn init_log() {
    use tracing_subscriber::EnvFilter;
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
}
