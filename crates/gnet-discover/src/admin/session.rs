//! Session storage on Valkey.
//!
//! The bearer plaintext is 32 random bytes hex-encoded (64 chars). The
//! plaintext lives in the `gnet_sess` cookie — the only place it ever
//! appears outside the client's machine. Valkey only ever sees
//! `SHA3_256(raw)` as part of the storage key — same discipline as setup
//! tokens (§17.2b) and federation tokens (planned §6.3).
//!
//! Key shape: `gnet:disp:<network_id>:sess:<hash_hex>`. The network_id
//! namespace lets a multi-network dispatcher (Mode A) share one Valkey
//! without cross-network session collisions.

use chrono::{DateTime, Utc};
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// How long a fresh session lives without reauth. 12 hours — long enough
/// for a normal admin sitting / typical "open the tab in the morning"
/// flow, short enough that a stolen cookie self-destructs within a day.
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
    pub network_id: Uuid,
    pub username: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

/// A freshly minted session id. Holds the raw 32-byte secret; the caller
/// pulls (a) the hex plaintext to put in the cookie, and (b) the Valkey
/// storage key derived from the SHA-3-256 hash of the raw bytes.
pub struct SessionId {
    raw: [u8; 32],
    network_id: Uuid,
}

pub fn new(network_id: Uuid) -> SessionId {
    let mut raw = [0u8; 32];
    gnet_rand::fill(&mut raw);
    SessionId { raw, network_id }
}

impl SessionId {
    pub fn cookie_value(&self) -> String {
        gnet_hex::encode(&self.raw)
    }

    pub fn key(&self) -> String {
        key_for(self.network_id, &gnet_crypto::sha3::sha3_256(&self.raw))
    }
}

/// Parse a cookie value back into the Valkey key it would be stored
/// under, scoped to `network_id`. Returns `None` on hex-format errors —
/// callers map that to "not logged in".
pub fn key_from_cookie(network_id: Uuid, cookie: &str) -> Option<String> {
    let raw = gnet_hex::decode_32(cookie)?;
    let hash = gnet_crypto::sha3::sha3_256(&raw);
    Some(key_for(network_id, &hash))
}

fn key_for(network_id: Uuid, hash: &[u8; 32]) -> String {
    format!("gnet:disp:{network_id}:sess:{}", gnet_hex::encode(hash))
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

pub async fn fetch(kv: &mut ConnectionManager, key: &str) -> Result<Option<Session>, SessionError> {
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
    fn cookie_roundtrip_resolves_to_same_key() {
        let nid = Uuid::new_v4();
        let sid = new(nid);
        let cookie = sid.cookie_value();
        let key_from_id = sid.key();
        let key_from_jar = key_from_cookie(nid, &cookie).unwrap();
        assert_eq!(key_from_id, key_from_jar);
    }

    #[test]
    fn cookie_with_wrong_network_id_yields_different_key() {
        let nid_a = Uuid::new_v4();
        let nid_b = Uuid::new_v4();
        let sid = new(nid_a);
        let cookie = sid.cookie_value();
        assert_ne!(
            key_from_cookie(nid_a, &cookie),
            key_from_cookie(nid_b, &cookie)
        );
    }

    #[test]
    fn malformed_cookie_is_none() {
        let nid = Uuid::new_v4();
        assert!(key_from_cookie(nid, "not-hex").is_none());
        assert!(key_from_cookie(nid, &"z".repeat(64)).is_none());
    }
}
