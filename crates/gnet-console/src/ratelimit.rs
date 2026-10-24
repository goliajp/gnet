//! Valkey-backed fixed-limit counters: login brute-force, and the
//! endpoints that send mail (signup, resend verification, forgot
//! password) so they cannot be used to mail arbitrary addresses.
//!
//! Pattern: `INCR <key>` + `EXPIRE <key> <window_secs>` in one atomic
//! pipeline. Keys are per account, per recipient address, or per
//! client IP; the client IP comes from [`crate::routes::client_ip`].

use redis::AsyncCommands;
use redis::aio::ConnectionManager;

use crate::error::AppError;

/// How many login attempts a single account may make in `WINDOW_SECS`
/// before further attempts are throttled to 429. Five is a usability /
/// security balance — covers honest typos and password-manager
/// retries while still slamming the door on automated dictionary
/// runs (60 / 12 = 5 attempts per minute → 7,200 attempts/day at the
/// throttle limit, vs. unlimited without it).
pub const LOGIN_ATTEMPT_LIMIT: u32 = 5;
pub const LOGIN_ATTEMPT_WINDOW_SECS: u64 = 60;

/// Outcome of an attempt registration. `Allow` carries no payload;
/// `Throttle` carries the number of seconds the client should wait
/// before its next attempt (the `Retry-After` value).
pub enum Decision {
    Allow,
    Throttle { retry_after_secs: u64 },
}

/// Register a login attempt for `account_id` (lowercased email or
/// user UUID), returning whether the attempt is allowed under the
/// rolling window. Always counts — does NOT differentiate by
/// success / failure. The TTL is one window, so the counter
/// auto-resets after a cool-down.
pub async fn account_attempt(
    kv: &mut ConnectionManager,
    account_id: &str,
) -> Result<Decision, AppError> {
    let key = format!("login_rl:account:{account_id}");
    hit(kv, &key, LOGIN_ATTEMPT_LIMIT, LOGIN_ATTEMPT_WINDOW_SECS).await
}

/// Signups one client IP may start per window.
pub const REGISTER_PER_IP: (u32, u64) = (5, 3600);
/// Mail-triggering requests (resend verification, forgot password)
/// one client IP may make per window.
pub const MAIL_REQUEST_PER_IP: (u32, u64) = (10, 3600);
/// Mail-triggering requests naming one recipient address per window,
/// across signup, resend and reset. Charged before the account lookup,
/// so it counts whether or not a mail actually goes out.
pub const MAIL_PER_RECIPIENT: (u32, u64) = (3, 3600);

/// Count one hit on `key` and decide against `limit` per `window_secs`.
/// Every hit refreshes the TTL, so a client that keeps hammering stays
/// throttled until it backs off for a full window.
pub async fn hit(
    kv: &mut ConnectionManager,
    key: &str,
    limit: u32,
    window_secs: u64,
) -> Result<Decision, AppError> {
    let (count, _): (u64, i64) = redis::pipe()
        .atomic()
        .incr(key, 1u32)
        .expire(key, window_secs as i64)
        .query_async(kv)
        .await?;
    if count > limit as u64 {
        Ok(Decision::Throttle {
            retry_after_secs: window_secs,
        })
    } else {
        Ok(Decision::Allow)
    }
}

/// Clear the counter on a confirmed-good login. Optional — callers
/// who don't bother will just have the entry decay naturally at
/// the next window boundary.
pub async fn account_clear(kv: &mut ConnectionManager, account_id: &str) -> Result<(), AppError> {
    let key = format!("login_rl:account:{account_id}");
    let _: () = kv.del(&key).await?;
    Ok(())
}
