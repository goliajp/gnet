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

        Ok(Self { bind, database_url })
    }
}
