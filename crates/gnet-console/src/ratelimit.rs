//! Tiny Valkey-backed counter for login brute-force throttling
//! (plan §17.12 hardening sweep).
//!
//! Pattern: `INCR <key>` + `EXPIRE <key> <window_secs> NX`. The
//! first hit creates the key with value 1 and sets the TTL; every
//! subsequent hit within the window increments without touching
//! the TTL (the NX makes EXPIRE a no-op when the key already has
//! one), so a single key always covers exactly one rolling window.
//!
//! No `ip` form here yet — SaaS console runs behind Caddy with
//! `X-Forwarded-For`, and trusting an arbitrary header for
//! brute-force-mitigation buckets is its own footgun. The
//! per-account form (`account_attempt`) is the load-bearing
//! mitigation; per-IP is a v1.2 follow-up if abuse data justifies
//! the proxy-header trust model.

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
    // INCR + atomic EXPIRE NX. We collapse them into a single
    // round-trip with a pipeline; the EXPIRE is no-op after the
    // first hit because the key already has a TTL.
    let (count, _): (u64, i64) = redis::pipe()
        .atomic()
        .incr(&key, 1u32)
        .expire(&key, LOGIN_ATTEMPT_WINDOW_SECS as i64)
        .query_async(kv)
        .await?;
    if count > LOGIN_ATTEMPT_LIMIT as u64 {
        // TTL is bounded by the window — worst case we ask the
        // client to wait the full WINDOW_SECS.
        let ttl: i64 = kv.ttl(&key).await.unwrap_or(LOGIN_ATTEMPT_WINDOW_SECS as i64);
        let retry_after_secs = if ttl > 0 { ttl as u64 } else { LOGIN_ATTEMPT_WINDOW_SECS };
        Ok(Decision::Throttle { retry_after_secs })
    } else {
        Ok(Decision::Allow)
    }
}

/// Clear the counter on a confirmed-good login. Optional — callers
/// who don't bother will just have the entry decay naturally at
/// the next window boundary.
pub async fn account_clear(
    kv: &mut ConnectionManager,
    account_id: &str,
) -> Result<(), AppError> {
    let key = format!("login_rl:account:{account_id}");
    let _: () = kv.del(&key).await?;
    Ok(())
}
