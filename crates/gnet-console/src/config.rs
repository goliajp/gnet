use std::net::{AddrParseError, SocketAddr};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("env var {0} not set")]
    Missing(&'static str),
    #[error("env var {var} invalid: {source}")]
    BadAddr {
        var: &'static str,
        #[source]
        source: AddrParseError,
    },
}

#[derive(Clone, Debug)]
pub struct Config {
    pub bind: SocketAddr,
    pub database_url: String,
    pub valkey_url: String,
    /// When true, the console treats newly registered email accounts as
    /// verified immediately. Set automatically when no SMTP transport is
    /// configured (per plan §6.6 — self-host without mailrs is a
    /// supported mode). When mailrs is configured the binary flips this
    /// off so the verification link gates first sign-in.
    pub auto_verify_email: bool,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind: SocketAddr = std::env::var("GNET_CONSOLE_BIND")
            .unwrap_or_else(|_| "127.0.0.1:8765".to_string())
            .parse()
            .map_err(|source| ConfigError::BadAddr {
                var: "GNET_CONSOLE_BIND",
                source,
            })?;

        let database_url = std::env::var("GNET_CONSOLE_DATABASE_URL")
            .map_err(|_| ConfigError::Missing("GNET_CONSOLE_DATABASE_URL"))?;

        let valkey_url = std::env::var("GNET_CONSOLE_VALKEY_URL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "redis://127.0.0.1:6379".to_string());

        // Auto-verify ON when no mailrs SMTP host is configured. The
        // binary still boots either way; this flag just decides whether
        // a fresh signup can sign in immediately or has to clear a
        // verification step the operator hasn't wired yet.
        let auto_verify_email = std::env::var("MAILRS_SMTP_HOST")
            .map(|s| s.trim().is_empty())
            .unwrap_or(true);

        Ok(Self {
            bind,
            database_url,
            valkey_url,
            auto_verify_email,
        })
    }
}
