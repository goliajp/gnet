use std::net::{AddrParseError, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

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
    #[error("GNET_DISCOVER_ADMIN_TOKEN must be at least 16 chars")]
    WeakToken,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub bind: SocketAddr,
    pub state_path: PathBuf,
    pub admin_token: String,
    pub overlay_v4_prefix: [u8; 3],
    pub overlay_v6_prefix: [u16; 4],
    /// Dedicated relay servers (gnet-relay-server) this coordinator advertises
    /// to its devices via `/peers`. Static config — relay servers hold no gnet
    /// identity, so they cannot be modelled as devices. Empty = no relay
    /// advertised (nodes fall back to relay_eligible peers).
    pub relays: Vec<SocketAddr>,
    /// Base URL (`http://host:port`) of the primary coordinator this instance
    /// mirrors. `Some` ⇒ this is a warm-standby that periodically pulls
    /// `GET /admin/state` from the primary and overwrites its own state.
    /// `None` ⇒ this is itself a primary (the default).
    pub primary: Option<String>,
    /// How often a standby pulls the primary's state. Ignored when `primary`
    /// is `None`.
    pub sync_interval: Duration,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind: SocketAddr = std::env::var("GNET_DISCOVER_BIND")
            .unwrap_or_else(|_| "0.0.0.0:65432".to_string())
            .parse()
            .map_err(|source| ConfigError::BadAddr {
                var: "GNET_DISCOVER_BIND",
                source,
            })?;

        let state_path: PathBuf = std::env::var("GNET_DISCOVER_STATE_PATH")
            .unwrap_or_else(|_| "/var/lib/gnet-discover/state.json".to_string())
            .into();

        let admin_token = std::env::var("GNET_DISCOVER_ADMIN_TOKEN")
            .map_err(|_| ConfigError::Missing("GNET_DISCOVER_ADMIN_TOKEN"))?;
        if admin_token.len() < 16 {
            return Err(ConfigError::WeakToken);
        }

        // Comma-separated `host:port` list; empty/unset means no relay servers.
        // Whitespace around entries is tolerated; a blank entry is skipped.
        let relays: Vec<SocketAddr> = match std::env::var("GNET_DISCOVER_RELAYS") {
            Ok(raw) => raw
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| {
                    s.parse().map_err(|source| ConfigError::BadAddr {
                        var: "GNET_DISCOVER_RELAYS",
                        source,
                    })
                })
                .collect::<Result<_, _>>()?,
            Err(_) => Vec::new(),
        };

        // Warm-standby config. `GNET_DISCOVER_PRIMARY` unset ⇒ this is a
        // primary (no pull-sync loop). When set, it's the base URL of the
        // coordinator to mirror, e.g. `http://10.0.0.1:65432`.
        let primary = match std::env::var("GNET_DISCOVER_PRIMARY") {
            Ok(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
            _ => None,
        };
        let sync_interval = Duration::from_secs(
            std::env::var("GNET_DISCOVER_SYNC_INTERVAL_SECS")
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(10),
        );

        Ok(Self {
            bind,
            state_path,
            admin_token,
            overlay_v4_prefix: [10, 42, 42],
            overlay_v6_prefix: [0xfd8d, 0xf090, 0x2ebb, 0],
            relays,
            primary,
            sync_interval,
        })
    }
}
