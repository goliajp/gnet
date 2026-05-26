//! Auth tokens.
//!
//! Two layers:
//! 1. **Admin token** — pre-shared, loaded from env. Authorises `POST /admin/enrol`.
//! 2. **Join token** — short-lived (10 min), one-shot. Minted by admin during
//!    enrol; the device presents it to `POST /join` and it is consumed.
//!
//! Join tokens live in memory only; a restart invalidates outstanding ones.
//! That is intentional — an enrol that has not been picked up by the target
//! device before a restart should be reissued.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

const JOIN_TOKEN_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Clone, Debug)]
pub struct PendingEnrol {
    pub alias: String,
    pub overlay_v4: String,
    pub overlay_v6: String,
    pub issued_at: Instant,
}

#[derive(Clone, Default)]
pub struct JoinTokenStore {
    inner: Arc<Mutex<HashMap<String, PendingEnrol>>>,
}

impl JoinTokenStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn issue(&self, alias: String, overlay_v4: String, overlay_v6: String) -> String {
        let token = mint_token();
        let mut guard = self.inner.lock().await;
        prune(&mut guard);
        guard.insert(
            token.clone(),
            PendingEnrol {
                alias,
                overlay_v4,
                overlay_v6,
                issued_at: Instant::now(),
            },
        );
        token
    }

    /// Consume a token: succeeds at most once, returns the pending enrol.
    pub async fn consume(&self, token: &str) -> Option<PendingEnrol> {
        let mut guard = self.inner.lock().await;
        prune(&mut guard);
        guard.remove(token)
    }
}

fn prune(map: &mut HashMap<String, PendingEnrol>) {
    let now = Instant::now();
    map.retain(|_, p| now.duration_since(p.issued_at) < JOIN_TOKEN_TTL);
}

fn mint_token() -> String {
    let mut bytes = [0u8; 24];
    gnet_rand::fill(&mut bytes);
    gnet_hex::encode(&bytes)
}

/// Constant-time compare for admin token check.
pub fn admin_token_matches(expected: &str, provided: &str) -> bool {
    if expected.len() != provided.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.bytes().zip(provided.bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn join_token_one_shot() {
        let s = JoinTokenStore::new();
        let t = s
            .issue("alpha".into(), "10.42.42.2".into(), "fd8d::2".into())
            .await;
        assert!(s.consume(&t).await.is_some());
        assert!(s.consume(&t).await.is_none(), "second consume must miss");
    }

    #[tokio::test]
    async fn join_token_carries_overlay_assignment() {
        let s = JoinTokenStore::new();
        let t = s
            .issue("beta".into(), "10.42.42.7".into(), "fd8d::7".into())
            .await;
        let p = s.consume(&t).await.unwrap();
        assert_eq!(p.alias, "beta");
        assert_eq!(p.overlay_v4, "10.42.42.7");
    }

    #[test]
    fn mint_token_is_48_hex_chars() {
        let t = mint_token();
        assert_eq!(t.len(), 48);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit() && (c.is_ascii_digit() || c.is_lowercase())));
    }

    #[test]
    fn admin_token_compare() {
        assert!(admin_token_matches("abc123def456ghi7", "abc123def456ghi7"));
        assert!(!admin_token_matches("abc123def456ghi7", "abc123def456ghi8"));
        assert!(!admin_token_matches("short", "shorter1"));
    }
}
