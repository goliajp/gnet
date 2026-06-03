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
    /// Externally-visible base URL of this console. OAuth callbacks are
    /// constructed against this — e.g. `<public_url>/api/auth/oauth/google/callback`.
    /// Defaults to the `bind` address in dev (`http://127.0.0.1:6015`).
    pub public_url: String,
    /// 32-byte master from which per-network federation tokens are
    /// derived (§17.6). Required in production; falls back to all
    /// zeros in dev with a loud warning so a fresh checkout boots.
    pub federation_secret: [u8; 32],
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

        // Auto-verify ON when no mailrs HTTP transport is configured.
        // The transport is wired in lib.rs (`MailClient::from_env`)
        // and requires `MAILRS_API_BASE` + `_LOGIN_ADDRESS` +
        // `_LOGIN_PASSWORD` + `_FROM_ADDRESS`. Whether the client
        // ends up `Some` is the source of truth for the flag — but
        // re-deriving the same conditional here keeps the config
        // decision out of lib.rs's boot path.
        let mail_configured = ["MAILRS_API_BASE", "MAILRS_LOGIN_ADDRESS",
            "MAILRS_LOGIN_PASSWORD", "MAILRS_FROM_ADDRESS"]
            .iter()
            .all(|v| std::env::var(v).map(|s| !s.trim().is_empty()).unwrap_or(false));
        let auto_verify_email = !mail_configured;

        let public_url = std::env::var("GNET_CONSOLE_PUBLIC_URL")
            .ok()
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("http://{bind}"));

        let federation_secret = match std::env::var("GNET_CONSOLE_FEDERATION_SECRET") {
            Ok(raw) => {
                let trimmed = raw.trim();
                gnet_hex::decode_32(trimmed).ok_or(ConfigError::Missing(
                    "GNET_CONSOLE_FEDERATION_SECRET (must be 64-char hex)",
                ))?
            }
            Err(_) => {
                // Dev fallback. Production should never see this branch —
                // the warning shows up on every boot until set.
                eprintln!(
                    "WARNING: GNET_CONSOLE_FEDERATION_SECRET unset — using zero secret (dev only)"
                );
                [0u8; 32]
            }
        };

        Ok(Self {
            bind,
            database_url,
            valkey_url,
            auto_verify_email,
            public_url,
            federation_secret,
        })
    }
}
