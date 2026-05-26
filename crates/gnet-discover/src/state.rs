//! On-disk state — single JSON file, atomic rename, in-memory `RwLock` cache.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, StateError>;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct State {
    pub devices: Vec<Device>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Device {
    pub alias: String,
    pub x25519_pubkey: String,
    pub mlkem_ek: String,
    pub overlay_v4: String,
    pub overlay_v6: String,
    pub endpoint: Option<String>,
    /// RFC 3339 UTC string, second resolution. See [`crate::time`].
    pub created_at: String,
}

#[derive(Clone)]
pub struct Store {
    inner: Arc<RwLock<State>>,
    path: PathBuf,
}

impl Store {
    pub async fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let state = match tokio::fs::read(&path).await {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            inner: Arc::new(RwLock::new(state)),
            path,
        })
    }

    pub async fn snapshot(&self) -> State {
        self.inner.read().await.clone()
    }

    /// Mutate under write lock, then persist atomically. Caller's closure can
    /// return any value; the value is returned to the caller after persist.
    pub async fn mutate<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut State) -> R,
    {
        let mut guard = self.inner.write().await;
        let out = f(&mut guard);
        persist(&self.path, &guard).await?;
        Ok(out)
    }
}

async fn persist(path: &Path, state: &State) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let bytes = serde_json::to_vec_pretty(state)?;
    let tmp = path.with_extension("json.tmp");
    tokio::fs::write(&tmp, &bytes).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

// ── allocator helpers ────────────────────────────────────────

/// Allocate the lowest unused last octet in 10.X.Y.0/24 (offset 2..=254 — skips
/// 0 (network), 1 (gateway convention), 255 (broadcast)).
pub fn allocate_v4_octet(state: &State) -> Option<u8> {
    let used: std::collections::HashSet<u8> = state
        .devices
        .iter()
        .filter_map(|d| d.overlay_v4.rsplit('.').next())
        .filter_map(|s| s.parse().ok())
        .collect();
    (2u8..=254u8).find(|n| !used.contains(n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::now_rfc3339;

    fn make_device(alias: &str, last_octet: u8) -> Device {
        Device {
            alias: alias.to_string(),
            x25519_pubkey: format!("pk-{alias}"),
            mlkem_ek: format!("ek-{alias}"),
            overlay_v4: format!("10.42.42.{last_octet}"),
            overlay_v6: format!("fd8d:f090:2ebb::{last_octet:x}"),
            endpoint: None,
            created_at: now_rfc3339(),
        }
    }

    fn tmp_path(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let mut r = [0u8; 8];
        gnet_rand::fill(&mut r);
        p.push(format!("gnet-discover-test-{}-{}.json", suffix, gnet_hex::encode(&r)));
        p
    }

    #[tokio::test]
    async fn load_missing_returns_empty() {
        let path = tmp_path("load_missing");
        let store = Store::load(&path).await.unwrap();
        assert!(store.snapshot().await.devices.is_empty());
    }

    #[tokio::test]
    async fn mutate_persists_and_roundtrips() {
        let path = tmp_path("roundtrip");
        let store = Store::load(&path).await.unwrap();
        store
            .mutate(|s| s.devices.push(make_device("alpha", 2)))
            .await
            .unwrap();

        let reloaded = Store::load(&path).await.unwrap();
        let devices = reloaded.snapshot().await.devices;
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].alias, "alpha");
        assert_eq!(devices[0].overlay_v4, "10.42.42.2");
        let _ = tokio::fs::remove_file(&path).await;
    }

    #[test]
    fn allocator_finds_lowest_unused() {
        let mut state = State::default();
        assert_eq!(allocate_v4_octet(&state), Some(2));
        state.devices.push(make_device("alpha", 2));
        assert_eq!(allocate_v4_octet(&state), Some(3));
        state.devices.push(make_device("beta", 3));
        state.devices.push(make_device("gamma", 5));
        assert_eq!(allocate_v4_octet(&state), Some(4));
    }

    #[test]
    fn allocator_exhausts_at_255() {
        let mut state = State::default();
        for n in 2..=254 {
            state.devices.push(make_device(&format!("d{n}"), n));
        }
        assert_eq!(allocate_v4_octet(&state), None);
    }

    #[tokio::test]
    async fn atomic_persist_no_partial_writes() {
        let path = tmp_path("atomic");
        let store = Store::load(&path).await.unwrap();
        for i in 2..10 {
            store
                .mutate(|s| s.devices.push(make_device(&format!("d{i}"), i)))
                .await
                .unwrap();
        }
        let reloaded = Store::load(&path).await.unwrap();
        assert_eq!(reloaded.snapshot().await.devices.len(), 8);
        assert!(!path.with_extension("json.tmp").exists());
        let _ = tokio::fs::remove_file(&path).await;
    }
}
