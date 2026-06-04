//! Login brute-force throttle — parallel-copy of the console-side
//! `ratelimit` module (plan §17.12). The dispatcher's local-admin
//! login is the only credential gate that benefits from this; the
//! daemon-facing `/api/internal/*` and federation endpoints already
//! rely on per-token bearer auth and don't need additional
//! throttling.
//!
//! Pattern: `INCR <key>` + `EXPIRE <key> <window_secs> NX`. The
//! first hit creates the key with value 1 and sets the TTL; every
//! subsequent hit within the window increments without touching
//! the TTL.

use redis::AsyncCommands;
use redis::aio::ConnectionManager;

pub const LOGIN_ATTEMPT_LIMIT: u32 = 5;
pub const LOGIN_ATTEMPT_WINDOW_SECS: u64 = 60;

pub enum Decision {
    Allow,
    Throttle { retry_after_secs: u64 },
}

pub async fn account_attempt(
    kv: &mut ConnectionManager,
    username: &str,
) -> Result<Decision, redis::RedisError> {
    let key = format!("login_rl:account:{username}");
    let (count, _): (u64, i64) = redis::pipe()
        .atomic()
        .incr(&key, 1u32)
        .expire(&key, LOGIN_ATTEMPT_WINDOW_SECS as i64)
        .query_async(kv)
        .await?;
    if count > LOGIN_ATTEMPT_LIMIT as u64 {
        let ttl: i64 = kv
            .ttl(&key)
            .await
            .unwrap_or(LOGIN_ATTEMPT_WINDOW_SECS as i64);
        let retry_after_secs = if ttl > 0 {
            ttl as u64
        } else {
            LOGIN_ATTEMPT_WINDOW_SECS
        };
        Ok(Decision::Throttle { retry_after_secs })
    } else {
        Ok(Decision::Allow)
    }
}

pub async fn account_clear(
    kv: &mut ConnectionManager,
    username: &str,
) -> Result<(), redis::RedisError> {
    let key = format!("login_rl:account:{username}");
    let _: () = kv.del(&key).await?;
    Ok(())
}
