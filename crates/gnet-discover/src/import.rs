//! One-shot v1.0 → v1.1 state migration.
//!
//! Reads the on-disk `state.json` produced by a v1.0 coord, writes it into
//! the v1.1 dispatcher PG schema, and renames the file to
//! `state.json.imported` so a second boot is a no-op.
//!
//! Invariants we keep:
//!
//! - The import is **transactional**. Either every device lands in PG or
//!   none do; we never see a half-migrated network.
//! - The import is **idempotent in the safe direction**: if `networks` is
//!   already non-empty we refuse the import and return an error, so
//!   running the importer twice on the same DB cannot duplicate rows.
//!   The state.json rename to `.imported` is the operator-visible
//!   "already done" signal for repeated boots.
//! - The data-plane contract is preserved. `device_token` in state.json is
//!   v1.0's plaintext bearer that a daemon presents on `/endpoint-report`.
//!   v1.1 stores `SHA3_256(token)` in `devices.device_token_hash`; the
//!   verify path on the dispatcher hashes incoming tokens and
//!   constant-time compares against this column. No v1.0 daemon needs to
//!   re-key, no wire change.
//! - SHA-3-256 (not SHA-2) because gnet-crypto already provides it, it's
//!   NIST FIPS 202, and the rest of the gnet stack (ML-KEM, Noise) is on
//!   the SHA-3 / Keccak family already. One hash family, zero new deps.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use sqlx::{PgPool, Postgres};
use uuid::Uuid;

use crate::state::{Device, State};

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("read state.json at {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parse state.json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    #[error("decode hex for device alias='{alias}', field={field}")]
    BadHex {
        alias: String,
        field: &'static str,
    },
    #[error("dispatcher PG already populated (networks table non-empty); refusing import")]
    AlreadyPopulated,
    #[error("rename {from} -> {to}: {source}")]
    Rename {
        from: PathBuf,
        to: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug)]
pub struct ImportSummary {
    pub network_id: Uuid,
    pub network_name: String,
    pub devices_imported: usize,
    pub relays_imported: usize,
    pub imported_marker: PathBuf,
}

/// Everything the importer reads from the operator. Deliberately decoupled
/// from [`crate::config::Config`] — the importer is an ops tool, it has no
/// reason to require `GNET_DISCOVER_ADMIN_TOKEN` (which gates the serve
/// path) just to migrate a file into PG.
pub struct ImportInput<'a> {
    pub state_path: &'a Path,
    pub network_name: String,
    pub overlay_v4_prefix: [u8; 3],
    pub overlay_v6_prefix: [u16; 4],
    pub relays: &'a [SocketAddr],
}

/// Read `input.state_path`, write it into `pool` under a fresh `networks`
/// row, then rename `state_path` to `<state>.imported`.
///
/// Returns an [`ImportSummary`] on success. Returns
/// [`ImportError::AlreadyPopulated`] if `networks` is non-empty — the
/// importer never overwrites; the operator must clear PG manually if they
/// want to re-import.
pub async fn import_state(
    input: &ImportInput<'_>,
    pool: &PgPool,
) -> Result<ImportSummary, ImportError> {
    let bytes = tokio::fs::read(input.state_path).await.map_err(|source| ImportError::Read {
        path: input.state_path.to_path_buf(),
        source,
    })?;
    let state: State = serde_json::from_slice(&bytes)?;

    let mut tx = pool.begin().await?;

    let (existing,): (i64,) = sqlx::query_as("SELECT COUNT(*)::bigint FROM networks")
        .fetch_one(&mut *tx)
        .await?;
    if existing > 0 {
        return Err(ImportError::AlreadyPopulated);
    }

    let network_id = Uuid::new_v4();
    let v4_prefix = input.overlay_v4_prefix.to_vec();
    let v6_prefix = pack_v6_prefix(&input.overlay_v6_prefix);

    sqlx::query(
        "INSERT INTO networks (id, name, overlay_v4_prefix, overlay_v6_prefix) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(network_id)
    .bind(&input.network_name)
    .bind(&v4_prefix)
    .bind(&v6_prefix)
    .execute(&mut *tx)
    .await?;

    let mut devices_imported = 0usize;
    for dev in &state.devices {
        insert_device(&mut *tx, network_id, dev).await?;
        devices_imported += 1;
    }

    let mut relays_imported = 0usize;
    for relay in input.relays {
        let relay_id = Uuid::new_v4();
        let inserted = sqlx::query(
            "INSERT INTO relays (id, network_id, endpoint) \
             VALUES ($1, $2, $3) ON CONFLICT (network_id, endpoint) DO NOTHING",
        )
        .bind(relay_id)
        .bind(network_id)
        .bind(relay.to_string())
        .execute(&mut *tx)
        .await?;
        if inserted.rows_affected() > 0 {
            relays_imported += 1;
        }
    }

    tx.commit().await?;

    let imported_marker = with_imported_suffix(input.state_path);
    tokio::fs::rename(input.state_path, &imported_marker)
        .await
        .map_err(|source| ImportError::Rename {
            from: input.state_path.to_path_buf(),
            to: imported_marker.clone(),
            source,
        })?;

    Ok(ImportSummary {
        network_id,
        network_name: input.network_name.clone(),
        devices_imported,
        relays_imported,
        imported_marker,
    })
}

async fn insert_device<'a, E>(
    conn: E,
    network_id: Uuid,
    dev: &Device,
) -> Result<(), ImportError>
where
    E: sqlx::Executor<'a, Database = Postgres>,
{
    let x25519 = gnet_hex::decode(&dev.x25519_pubkey).ok_or_else(|| ImportError::BadHex {
        alias: dev.alias.clone(),
        field: "x25519_pubkey",
    })?;
    let mlkem = gnet_hex::decode(&dev.mlkem_ek).ok_or_else(|| ImportError::BadHex {
        alias: dev.alias.clone(),
        field: "mlkem_ek",
    })?;
    let token_hash: [u8; 32] = gnet_crypto::sha3::sha3_256(dev.device_token.as_bytes());
    let id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO devices ( \
            id, network_id, x25519_pubkey, mlkem_ek, alias, \
            vip_v4, vip_v6, device_token_hash, relay_eligible, \
            last_reflexive, created_at \
         ) VALUES ( \
            $1, $2, $3, $4, $5, \
            $6::inet, $7::inet, $8, $9, \
            $10, $11::timestamptz \
         )",
    )
    .bind(id)
    .bind(network_id)
    .bind(&x25519)
    .bind(&mlkem)
    .bind(&dev.alias)
    .bind(&dev.overlay_v4)
    .bind(&dev.overlay_v6)
    .bind(&token_hash[..])
    .bind(dev.relay_eligible)
    .bind(dev.endpoint.as_deref())
    .bind(&dev.created_at)
    .execute(conn)
    .await?;

    Ok(())
}

fn pack_v6_prefix(prefix: &[u16; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    for &word in prefix {
        out.extend_from_slice(&word.to_be_bytes());
    }
    out
}

fn with_imported_suffix(path: &Path) -> PathBuf {
    // `Path::with_extension` would replace `.json` with `.imported`; we want
    // to *append* so the original extension stays visible (state.json.imported).
    let mut name = path.file_name().map(|s| s.to_os_string()).unwrap_or_default();
    name.push(".imported");
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v6_prefix_packs_big_endian() {
        let packed = pack_v6_prefix(&[0xfd8d, 0xf090, 0x2ebb, 0]);
        assert_eq!(
            packed,
            vec![0xfd, 0x8d, 0xf0, 0x90, 0x2e, 0xbb, 0x00, 0x00]
        );
    }

    #[test]
    fn imported_suffix_appends_not_replaces() {
        let p = Path::new("/var/lib/gnet/state.json");
        assert_eq!(
            with_imported_suffix(p),
            PathBuf::from("/var/lib/gnet/state.json.imported")
        );
    }

    #[test]
    fn token_hash_is_sha3_256() {
        // Deterministic: same plaintext token in state.json + dispatcher
        // verify path must yield the same 32-byte hash. Anchoring to a
        // known SHA-3-256 vector (NIST FIPS 202 §B.1: empty message).
        let h: [u8; 32] = gnet_crypto::sha3::sha3_256(b"");
        let expected: [u8; 32] = [
            0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
            0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
            0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
            0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a,
        ];
        assert_eq!(h, expected);
    }
}
