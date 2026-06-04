//! First-boot setup-token issuance.
//!
//! Run once at admin-server startup, after the network row is resolved
//! and *before* the listener accepts traffic. Three cases:
//!
//! 1. `admin_users` already has at least one row for this network → no
//!    setup needed, return.
//! 2. No admins, but an unconsumed and not-expired `setup_tokens` row
//!    exists → print a notice (we cannot reveal the plaintext, since we
//!    only stored its hash). Operator who lost it can delete the row to
//!    re-issue.
//! 3. No admins, no outstanding token → mint one, store its hash, print
//!    a setup URL the operator can click.

use std::net::SocketAddr;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use super::AdminServeError;
use super::auth::generate_setup_token;

/// How long the first-admin setup token stays valid. One hour — short
/// enough that a token leaked into shell history / logs is unlikely to
/// outlive its operator, long enough for the typical "spin up + walk to
/// browser + paste" flow.
const SETUP_TOKEN_TTL_HOURS: i64 = 1;

pub async fn ensure_first_admin_setup(
    pool: &PgPool,
    network_id: Uuid,
    network_name: &str,
    admin_bind: SocketAddr,
) -> Result<(), AdminServeError> {
    let (admin_count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*)::bigint FROM admin_users WHERE network_id = $1")
            .bind(network_id)
            .fetch_one(pool)
            .await?;
    if admin_count > 0 {
        return Ok(());
    }

    let outstanding: Option<(DateTime<Utc>,)> = sqlx::query_as(
        "SELECT expires_at FROM setup_tokens \
         WHERE network_id = $1 AND consumed_at IS NULL AND expires_at > now() \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(network_id)
    .fetch_optional(pool)
    .await?;

    if let Some((expires_at,)) = outstanding {
        eprintln!(
            "gnet-discover admin: outstanding setup token exists (expires {expires_at}). \
             If lost, run `DELETE FROM setup_tokens WHERE network_id = '{network_id}';` \
             and restart to re-issue."
        );
        return Ok(());
    }

    let token = generate_setup_token();
    let token_hash = token.hash();
    let id = Uuid::new_v4();
    let expires_at: DateTime<Utc> = Utc::now() + chrono::Duration::hours(SETUP_TOKEN_TTL_HOURS);

    sqlx::query(
        "INSERT INTO setup_tokens (id, network_id, token_hash, expires_at) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(network_id)
    .bind(&token_hash[..])
    .bind(expires_at)
    .execute(pool)
    .await?;

    let token_hex = token.plaintext_hex();
    let banner = "═".repeat(72);
    eprintln!();
    eprintln!("{banner}");
    eprintln!("  gnet-discover admin: FIRST-BOOT SETUP for network {network_name}");
    eprintln!();
    eprintln!("  Visit (Mode B / self-host):");
    eprintln!("    http://{admin_bind}/setup?token={token_hex}");
    eprintln!();
    eprintln!("  Or POST JSON to /api/auth/setup :");
    eprintln!(r#"    {{"token":"{token_hex}", "username":"...", "password":"..."}}"#);
    eprintln!();
    eprintln!("  Token expires at {expires_at}");
    eprintln!("{banner}");
    eprintln!();

    Ok(())
}
