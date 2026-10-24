//! Email-link flows: confirm address, resend confirmation, forgot /
//! reset password.
//!
//! Every endpoint here that sends mail is rate-limited per client IP
//! and per recipient address. Over a limit the request still gets the
//! same 204 as a real send, so neither the limit nor account existence
//! is observable, and the console cannot be used to mail arbitrary
//! addresses.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::auth::{AuthRouteError, MIN_PASSWORD_LEN};
use super::client_ip::ClientIp;
use crate::auth::{hash_password, looks_like_email};
use crate::human_check::{self, Scope};
use crate::ratelimit::{self, Decision};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

#[derive(Serialize)]
pub struct VerifyEmailResponse {
    pub verified: bool,
}

/// Confirm an email-address verification token. The token row stays
/// in the table after use (with `used_at = now()`) so a stolen link
/// that's already been redeemed gets the same 404 a never-existing
/// one does — leaks neither the original validity nor when the user
/// confirmed.
async fn verify_email(
    State(state): State<AppState>,
    Json(req): Json<VerifyEmailRequest>,
) -> Result<Json<VerifyEmailResponse>, AuthRouteError> {
    let mut tx = state.pool.begin().await?;
    let row: Option<(Uuid, Option<chrono::DateTime<Utc>>)> = sqlx::query_as(
        "SELECT user_id, used_at FROM email_verification_tokens \
         WHERE token = $1 AND created_at > now() - INTERVAL '1 hour' \
         FOR UPDATE",
    )
    .bind(&req.token)
    .fetch_optional(&mut *tx)
    .await?;

    let Some((user_id, used_at)) = row else {
        return Err(AuthRouteError::BadCreds);
    };
    if used_at.is_some() {
        return Err(AuthRouteError::BadCreds);
    }

    sqlx::query("UPDATE email_credentials SET verified_at = now() WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE email_verification_tokens SET used_at = now() WHERE token = $1")
        .bind(&req.token)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(Json(VerifyEmailResponse { verified: true }))
}

pub fn routes() -> axum::Router<AppState> {
    use axum::routing::post;
    axum::Router::new()
        .route("/api/auth/email/verify", post(verify_email))
        .route(
            "/api/auth/email/resend-verification",
            post(resend_verification),
        )
        .route("/api/auth/email/forgot-password", post(forgot_password))
        .route("/api/auth/email/reset-password", post(reset_password))
}

/// Charge one mail-triggering request to the client IP and one mail to
/// the recipient. `false` means skip the send but answer as if sent.
pub(super) async fn may_send(
    state: &AppState,
    ip: Option<std::net::IpAddr>,
    recipient: &str,
) -> Result<bool, AuthRouteError> {
    let mut kv = state.kv.clone();
    if let Some(ip) = ip {
        let (limit, window) = ratelimit::MAIL_REQUEST_PER_IP;
        let key = format!("mail_rl:ip:{ip}");
        if let Decision::Throttle { .. } = ratelimit::hit(&mut kv, &key, limit, window).await? {
            tracing::warn!(%ip, "auth mail request throttled per ip");
            return Ok(false);
        }
    }
    let (limit, window) = ratelimit::MAIL_PER_RECIPIENT;
    let key = format!("mail_rl:to:{recipient}");
    if let Decision::Throttle { .. } = ratelimit::hit(&mut kv, &key, limit, window).await? {
        tracing::warn!(recipient, "auth mail throttled per recipient");
        return Ok(false);
    }
    Ok(true)
}

fn new_token() -> String {
    let mut raw = [0u8; 32];
    gnet_rand::fill(&mut raw);
    gnet_hex::encode(&raw)
}

/// Mail a confirmation link. Send failures are logged, not returned:
/// the account row is already committed and the user can ask again.
pub(super) async fn send_verification(state: &AppState, email: &str, token: &str, fresh: bool) {
    let Some(mail) = state.mail.as_ref() else {
        return;
    };
    let link = format!("{}/verify?token={}", state.public_url, token);
    let (intro, outro) = if fresh {
        (
            "Here's a fresh confirmation link for gnet:",
            "If you didn't ask to resend, you can safely ignore this mail.",
        )
    } else {
        (
            "Welcome to gnet.\n\nConfirm this address to finish signing in:",
            "If you didn't sign up for gnet, ignore this mail.",
        )
    };
    let body = format!("{intro}\n\n  {link}\n\n{outro}\n\n— gnet.golia.jp\n");
    let html_intro = intro.replace("\n\n", "</p><p>");
    let html_body = format!(
        "<p>{html_intro}</p><p><a href=\"{link}\">{link}</a></p><p>{outro}</p><p>— gnet.golia.jp</p>"
    );
    if let Err(e) = mail
        .send(email, "Confirm your gnet account", &body, Some(&html_body))
        .await
    {
        tracing::error!(error = ?e, "verification mail send failed");
    }
}

#[derive(Deserialize)]
pub struct ResendVerificationRequest {
    pub email: String,
    #[serde(default)]
    pub altcha: Option<String>,
}

/// Issue a fresh verification token for an unverified account, mail
/// it out, and ALWAYS return 204. We deliberately don't differentiate
/// "no such account" from "account already verified" from "fresh
/// token issued" — the response shape is identical so a probe can't
/// enumerate which addresses are real.
///
/// Auto-verify mode is a no-op success too (the binary has no mail
/// loop at all; signups already land verified). The frontend treats
/// 204 as "if your address is on file and still needs verification,
/// a new link is on the way."
async fn resend_verification(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<ResendVerificationRequest>,
) -> Result<StatusCode, AuthRouteError> {
    human_check::require(&state, Scope::Resend, req.altcha.as_deref()).await?;
    let email = req.email.trim().to_lowercase();
    // No validation 400s — even a bad email shape returns 204 so the
    // enumeration surface stays flat.
    if !looks_like_email(&email) || state.mail.is_none() {
        return Ok(StatusCode::NO_CONTENT);
    }
    if !may_send(&state, Some(ip), &email).await? {
        return Ok(StatusCode::NO_CONTENT);
    }

    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT u.id FROM users u JOIN email_credentials c ON c.user_id = u.id \
         WHERE u.email = $1 AND c.verified_at IS NULL",
    )
    .bind(&email)
    .fetch_optional(&state.pool)
    .await?;
    let Some((user_id,)) = row else {
        return Ok(StatusCode::NO_CONTENT);
    };

    let token = new_token();
    sqlx::query("INSERT INTO email_verification_tokens (token, user_id) VALUES ($1, $2)")
        .bind(&token)
        .bind(user_id)
        .execute(&state.pool)
        .await?;
    send_verification(&state, &email, &token, true).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
    #[serde(default)]
    pub altcha: Option<String>,
}

/// Issue a password-reset token for a confirmed account, mail it out,
/// and ALWAYS return 204 — same enumeration-flat behaviour as
/// resend-verification. Unconfirmed accounts get no mail: their
/// address was never proven to belong to whoever signed up. The
/// mail's link points at `/reset-password?token=…` which the SPA hosts.
async fn forgot_password(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<ForgotPasswordRequest>,
) -> Result<StatusCode, AuthRouteError> {
    human_check::require(&state, Scope::Forgot, req.altcha.as_deref()).await?;
    let email = req.email.trim().to_lowercase();
    if !looks_like_email(&email) {
        return Ok(StatusCode::NO_CONTENT);
    }
    let Some(mail) = state.mail.as_ref() else {
        return Ok(StatusCode::NO_CONTENT);
    };
    if !may_send(&state, Some(ip), &email).await? {
        return Ok(StatusCode::NO_CONTENT);
    }

    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT u.id FROM users u JOIN email_credentials c ON c.user_id = u.id \
         WHERE u.email = $1 AND c.verified_at IS NOT NULL",
    )
    .bind(&email)
    .fetch_optional(&state.pool)
    .await?;
    let Some((user_id,)) = row else {
        return Ok(StatusCode::NO_CONTENT);
    };

    let token = new_token();
    sqlx::query("INSERT INTO password_reset_tokens (token, user_id) VALUES ($1, $2)")
        .bind(&token)
        .bind(user_id)
        .execute(&state.pool)
        .await?;

    let link = format!("{}/reset-password?token={}", state.public_url, token);
    let body = format!(
        "Someone asked to reset the password on your gnet account.\n\nIf that was you, follow this link within one hour:\n\n  {link}\n\nIf it wasn't, ignore this mail — your password is unchanged.\n\n— gnet.golia.jp\n"
    );
    let html_body = format!(
        "<p>Someone asked to reset the password on your gnet account.</p><p>If that was you, follow this link within one hour:</p><p><a href=\"{link}\">{link}</a></p><p>If it wasn't, ignore this mail — your password is unchanged.</p><p>— gnet.golia.jp</p>"
    );
    if let Err(e) = mail
        .send(&email, "Reset your gnet password", &body, Some(&html_body))
        .await
    {
        tracing::error!(error = ?e, user_id = %user_id, "password-reset mail failed");
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub password: String,
}

/// Consume a password-reset token and set a new password. Same
/// shape as `verify_email`: SELECT … FOR UPDATE inside a tx, single-
/// use (used_at IS NULL gates re-use), one-hour TTL. Also clears
/// every live session for that user so a thief with the old session
/// cookie loses access at reset time.
async fn reset_password(
    State(state): State<AppState>,
    Json(req): Json<ResetPasswordRequest>,
) -> Result<StatusCode, AuthRouteError> {
    if req.password.chars().count() < MIN_PASSWORD_LEN {
        return Err(AuthRouteError::WeakPassword);
    }

    let mut tx = state.pool.begin().await?;
    let row: Option<(Uuid, Option<chrono::DateTime<Utc>>)> = sqlx::query_as(
        "SELECT user_id, used_at FROM password_reset_tokens \
         WHERE token = $1 AND created_at > now() - INTERVAL '1 hour' \
         FOR UPDATE",
    )
    .bind(&req.token)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((user_id, used_at)) = row else {
        return Err(AuthRouteError::BadCreds);
    };
    if used_at.is_some() {
        return Err(AuthRouteError::BadCreds);
    }

    let hash = hash_password(&req.password)?;
    sqlx::query("UPDATE email_credentials SET password_hash = $1 WHERE user_id = $2")
        .bind(&hash)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE password_reset_tokens SET used_at = now() WHERE token = $1")
        .bind(&req.token)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    // Best-effort: kill all live sessions for this user by walking the
    // Valkey session prefix. Failure here just shortens the window
    // they remain valid — the password rotation already strands the
    // old cookies on the next login attempt.
    let _ = invalidate_user_sessions(&state, user_id).await;

    Ok(StatusCode::NO_CONTENT)
}

/// Walk the console session prefix in Valkey and drop every row that
/// belongs to `user_id`. Best-effort: returns Ok even on a partial
/// scan — caller logs the count via `?` propagation if needed.
async fn invalidate_user_sessions(state: &AppState, user_id: Uuid) -> Result<(), AuthRouteError> {
    use redis::AsyncCommands;
    let mut kv = state.kv.clone();
    let mut cursor: u64 = 0;
    let pattern = format!("{}*", crate::session::KEY_PREFIX);
    loop {
        let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(&pattern)
            .arg("COUNT")
            .arg(200)
            .query_async(&mut kv)
            .await?;
        for k in &keys {
            let raw: Option<String> = kv.get(k).await?;
            let Some(json) = raw else { continue };
            if json.contains(&user_id.to_string()) {
                let _: () = kv.del(k).await?;
            }
        }
        if next == 0 {
            break;
        }
        cursor = next;
    }
    Ok(())
}
