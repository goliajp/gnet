use std::net::{AddrParseError, SocketAddr};

#[derive(Debug, thiserror::Error)]
pub enum AdminConfigError {
    #[error("env var {var} invalid: {source}")]
    BadAddr {
        var: &'static str,
        #[source]
        source: AddrParseError,
    },
    #[error("env var {var} invalid: {source}")]
    BadUuid {
        var: &'static str,
        #[source]
        source: uuid::Error,
    },
}

/// Configuration the dispatcher admin server reads at startup.
///
/// Deliberately separate from `crate::config::Config` (the v1.0 coord's
/// env). v1.1 keeps the coord surface unchanged; the admin server is an
/// additive opt-in (gated by `GNET_DISCOVER_DATABASE_URL`).
#[derive(Clone, Debug)]
pub struct AdminConfig {
    pub admin_bind: SocketAddr,
    pub database_url: String,
    /// Valkey URL for session storage (and, later, federation-token
    /// verify cache). Plan §6.1 — sessions live in the binary's own
    /// Valkey instance.
    pub valkey_url: String,
    /// Operator-specified network UUID. When set, dispatcher requires the
    /// row to exist. When unset, dispatcher auto-resolves: one row → use
    /// it, zero rows → create a default named [`AdminConfig::network_name`].
    pub network_id_hint: Option<uuid::Uuid>,
    /// Human-facing label for the default-network case. Ignored when an
    /// existing network is found.
    pub network_name: String,
}

impl AdminConfig {
    /// Try to read an admin config from env. Returns `Ok(None)` when
    /// `GNET_DISCOVER_DATABASE_URL` is unset / blank — that's the v1.0
    /// coord-only fallthrough, not an error.
    pub fn from_env() -> Result<Option<Self>, AdminConfigError> {
        let database_url = match std::env::var("GNET_DISCOVER_DATABASE_URL") {
            Ok(s) if !s.trim().is_empty() => s,
            _ => return Ok(None),
        };

        let admin_bind: SocketAddr = std::env::var("GNET_DISCOVER_ADMIN_BIND")
            .unwrap_or_else(|_| "0.0.0.0:8765".to_string())
            .parse()
            .map_err(|source| AdminConfigError::BadAddr {
                var: "GNET_DISCOVER_ADMIN_BIND",
                source,
            })?;

        let network_id_hint = match std::env::var("GNET_DISCOVER_NETWORK_ID") {
            Ok(s) if !s.trim().is_empty() => {
                Some(uuid::Uuid::parse_str(s.trim()).map_err(|source| {
                    AdminConfigError::BadUuid {
                        var: "GNET_DISCOVER_NETWORK_ID",
                        source,
                    }
                })?)
            }
            _ => None,
        };

        let network_name = std::env::var("GNET_DISCOVER_NETWORK_NAME")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "default".to_string());

        let valkey_url = std::env::var("GNET_DISCOVER_VALKEY_URL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "redis://127.0.0.1:6379".to_string());

        Ok(Some(Self {
            admin_bind,
            database_url,
            valkey_url,
            network_id_hint,
            network_name,
        }))
    }
}
