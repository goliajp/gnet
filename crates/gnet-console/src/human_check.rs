//! Proof-of-work human check (ALTCHA) for the endpoints that send mail.
//!
//! The SPA fetches a signed challenge on page load, solves it in the
//! background, and submits the solution with the form. Challenges are
//! deterministic (the server picks the counter and signs the derived
//! key), so verification is one HMAC, not a PBKDF2 re-run. The scope
//! is part of the signed data, so a solution for one form cannot be
//! spent on another; a Valkey `SET NX` on the challenge nonce makes
//! every solution single-use.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use altcha::{CreateChallengeOptions, Payload, VerifySolutionOptions};
use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use serde::Deserialize;

use crate::ratelimit::{self, Decision};
use crate::routes::auth::AuthRouteError;
use crate::routes::client_ip::ClientIp;
use crate::state::AppState;

/// PBKDF2 iterations per counter step.
const COST: u32 = 5_000;
/// Range the secret counter is drawn from; the client walks up from 0,
/// so the expected work is about the midpoint times `COST`.
const COUNTER_MIN: u32 = 5_000;
const COUNTER_MAX: u32 = 10_000;
const TTL_SECS: i64 = 600;
/// Challenges one client IP may fetch per hour.
const ISSUE_PER_IP: (u32, u64) = (60, 3600);
/// Issued-per-minute thresholds (per scope) above which the counter
/// range is multiplied, so a flood makes every solve slower.
const SURGE: [(u64, u32); 2] = [(120, 8), (30, 4)];

pub struct Secrets {
    challenge: String,
    key: String,
}

impl Secrets {
    pub fn derive(master: &[u8; 32]) -> Self {
        let prk = gnet_crypto::hkdf::extract(b"gnet-console human-check v1", master);
        let sub = |info: &[u8]| gnet_hex::encode(&gnet_crypto::hkdf::expand(&prk, info, 32));
        Self {
            challenge: sub(b"altcha-challenge"),
            key: sub(b"altcha-key"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Register,
    Resend,
    Forgot,
}

impl Scope {
    fn as_str(self) -> &'static str {
        match self {
            Scope::Register => "register",
            Scope::Resend => "resend",
            Scope::Forgot => "forgot",
        }
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs() as i64
}

fn random_in(min: u32, max: u32) -> u32 {
    min + gnet_rand::random_u32() % (max - min + 1)
}

/// Sign a fresh challenge for `scope`. `multiplier` scales the counter
/// range (1 in normal operation).
pub fn issue(secrets: &Secrets, scope: Scope, multiplier: u32) -> altcha::Challenge {
    let counter = random_in(COUNTER_MIN * multiplier, COUNTER_MAX * multiplier);
    issue_with(secrets, scope, COST, counter)
}

fn issue_with(secrets: &Secrets, scope: Scope, cost: u32, counter: u32) -> altcha::Challenge {
    let mut data = BTreeMap::new();
    data.insert("scope".to_string(), scope.as_str().into());
    altcha::create_challenge(CreateChallengeOptions {
        cost,
        counter: Some(counter),
        expires_at: Some(now_secs() + TTL_SECS),
        data: Some(data),
        hmac_signature_secret: Some(secrets.challenge.clone()),
        hmac_key_signature_secret: Some(secrets.key.clone()),
        ..Default::default()
    })
    .expect("pbkdf2/sha-256 challenge with fixed parameters")
}

/// Check a widget payload (base64 JSON) without touching Valkey.
/// Returns the challenge nonce and expiry for the replay guard.
pub fn check(secrets: &Secrets, scope: Scope, raw: &str) -> Option<(String, i64)> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .ok()?;
    let payload: Payload = serde_json::from_slice(&bytes).ok()?;
    let result = altcha::verify_solution(VerifySolutionOptions {
        hmac_key_signature_secret: Some(secrets.key.clone()),
        ..VerifySolutionOptions::new(&payload.challenge, &payload.solution, &secrets.challenge)
    })
    .ok()?;
    let params = &payload.challenge.parameters;
    // only signed deterministic challenges: without a key signature the
    // crate falls back to re-deriving the key, which costs a full pbkdf2
    let scoped = params.key_signature.is_some()
        && params
            .data
            .as_ref()
            .and_then(|d| d.get("scope"))
            .and_then(|v| v.as_str())
            == Some(scope.as_str());
    (result.verified && scoped).then(|| (params.nonce.clone(), params.expires_at.unwrap_or(0)))
}

/// Enforce the human check for `scope`. A no-op when the check is
/// disabled by config.
pub async fn require(
    state: &AppState,
    scope: Scope,
    payload: Option<&str>,
) -> Result<(), AuthRouteError> {
    let Some(secrets) = state.human_check.as_deref() else {
        return Ok(());
    };
    let (nonce, expires_at) = payload
        .and_then(|p| check(secrets, scope, p))
        .ok_or(AuthRouteError::HumanCheckFailed)?;
    let ttl = (expires_at - now_secs()).max(1) as u64;
    let mut kv = state.kv.clone();
    let fresh: bool = redis::cmd("SET")
        .arg(format!("hc:used:{nonce}"))
        .arg(1)
        .arg("NX")
        .arg("EX")
        .arg(ttl)
        .query_async::<Option<String>>(&mut kv)
        .await
        .map_err(crate::error::AppError::from)?
        .is_some();
    if !fresh {
        return Err(AuthRouteError::HumanCheckFailed);
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct ChallengeQuery {
    scope: Scope,
}

/// `GET /api/auth/challenge?scope=register|resend|forgot`
pub async fn challenge(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Query(q): Query<ChallengeQuery>,
) -> Result<Response, AuthRouteError> {
    let Some(secrets) = state.human_check.as_deref() else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    let mut kv = state.kv.clone();
    let (limit, window) = ISSUE_PER_IP;
    if let Decision::Throttle { retry_after_secs } =
        ratelimit::hit(&mut kv, &format!("hc_rl:ip:{ip}"), limit, window).await?
    {
        return Err(AuthRouteError::Throttled { retry_after_secs });
    }
    let minute = now_secs() / 60;
    let key = format!("hc:issued:{}:{minute}", q.scope.as_str());
    let (issued, _): (u64, i64) = redis::pipe()
        .atomic()
        .incr(&key, 1u32)
        .expire(&key, 120)
        .query_async(&mut kv)
        .await
        .map_err(crate::error::AppError::from)?;
    let multiplier = SURGE
        .iter()
        .find(|(threshold, _)| issued > *threshold)
        .map_or(1, |(_, m)| *m);
    if multiplier > 1 {
        tracing::warn!(
            scope = q.scope.as_str(),
            issued,
            multiplier,
            "human-check surge"
        );
    }
    let mut resp = Json(issue(secrets, q.scope, multiplier)).into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use altcha::{SolveChallengeOptions, solve_challenge};

    fn solved(secrets: &Secrets, scope: Scope) -> String {
        // production cost takes minutes to solve in a debug build
        let challenge = issue_with(secrets, scope, 10, 50);
        let solution = solve_challenge(SolveChallengeOptions::new(&challenge))
            .unwrap()
            .unwrap();
        let payload = Payload {
            challenge,
            solution,
        };
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&payload).unwrap())
    }

    #[test]
    fn solved_challenge_verifies_for_its_scope_only() {
        let s = Secrets::derive(&[7u8; 32]);
        let p = solved(&s, Scope::Forgot);
        assert!(check(&s, Scope::Forgot, &p).is_some());
        assert!(check(&s, Scope::Register, &p).is_none());
    }

    #[test]
    fn other_secret_or_garbage_is_rejected() {
        let s = Secrets::derive(&[7u8; 32]);
        let p = solved(&s, Scope::Register);
        assert!(check(&Secrets::derive(&[8u8; 32]), Scope::Register, &p).is_none());
        assert!(check(&s, Scope::Register, "not base64!").is_none());
        assert!(check(&s, Scope::Register, "e30=").is_none());
    }

    #[test]
    fn tampered_counter_or_expiry_is_rejected() {
        let s = Secrets::derive(&[7u8; 32]);
        let raw = solved(&s, Scope::Register);
        let mut payload: Payload = serde_json::from_slice(
            &base64::engine::general_purpose::STANDARD
                .decode(&raw)
                .unwrap(),
        )
        .unwrap();
        payload.challenge.parameters.expires_at = Some(now_secs() + 86_400);
        let p =
            base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&payload).unwrap());
        assert!(check(&s, Scope::Register, &p).is_none());
    }
}
