//! Valkey-backed session store for the console (SaaS) binary.
//!
//! Same discipline as the dispatcher's `admin/session.rs`: bearer
//! plaintext lives only in the HttpOnly cookie; Valkey only ever sees
//! `SHA3_256(raw)` in the key. Key prefix is `gnet:console:sess:` so a
//! shared Valkey across binaries doesn't collide.

use chrono::{DateTime, Utc};
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const SESSION_TTL_SECS: u64 = 12 * 3600;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("valkey: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("session encode/decode: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Session {
    pub user_id: Uuid,
    pub email: Option<String>,
    pub created_at: DateTime<Utc>,
}

pub struct SessionId {
    raw: [u8; 32],
}

pub fn new() -> SessionId {
    let mut raw = [0u8; 32];
    gnet_rand::fill(&mut raw);
    SessionId { raw }
}

impl SessionId {
    pub fn cookie_value(&self) -> String {
        gnet_hex::encode(&self.raw)
    }
    pub fn key(&self) -> String {
        format_key(&gnet_crypto::sha3::sha3_256(&self.raw))
    }
}

pub fn key_from_cookie(cookie: &str) -> Option<String> {
    let raw = gnet_hex::decode_32(cookie)?;
    Some(format_key(&gnet_crypto::sha3::sha3_256(&raw)))
}

/// Valkey key prefix shared by every console session row. Used both
/// here (to format individual keys) and by `routes/auth.rs` to walk
/// the prefix on password reset (every session for the user dies).
pub const KEY_PREFIX: &str = "gnet:console:sess:";

fn format_key(hash: &[u8; 32]) -> String {
    format!("{}{}", KEY_PREFIX, gnet_hex::encode(hash))
}

pub async fn store(
    kv: &mut ConnectionManager,
    key: &str,
    session: &Session,
) -> Result<(), SessionError> {
    let value = serde_json::to_string(session)?;
    let _: () = kv.set_ex(key, value, SESSION_TTL_SECS).await?;
    Ok(())
}

pub async fn fetch(
    kv: &mut ConnectionManager,
    key: &str,
) -> Result<Option<Session>, SessionError> {
    let raw: Option<String> = kv.get(key).await?;
    match raw {
        Some(v) => Ok(Some(serde_json::from_str(&v)?)),
        None => Ok(None),
    }
}

pub async fn delete(kv: &mut ConnectionManager, key: &str) -> Result<(), SessionError> {
    let _: () = kv.del(key).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_roundtrip() {
        let s = new();
        let cookie = s.cookie_value();
        assert_eq!(s.key(), key_from_cookie(&cookie).unwrap());
    }

    #[test]
    fn malformed_cookie_is_none() {
        assert!(key_from_cookie("nope").is_none());
        assert!(key_from_cookie(&"z".repeat(64)).is_none());
    }
}
