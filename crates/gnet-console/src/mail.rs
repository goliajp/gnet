//! mailrs HTTP-API client (plan §6.6).
//!
//! The console talks to a mailrs instance over its REST API: log in
//! once with a service-account address + password, cache the bearer
//! the response carries, send transactional mail with
//! `POST /api/mail/send`. Tokens are refreshed on 401 (a
//! mailrs session is short-lived; the cache holds it until the
//! server rejects it, then we re-login and retry once).
//!
//! What the operator configures (plan §6.6, .env.example):
//!
//!   MAILRS_API_BASE         the mailrs HTTP base, e.g.
//!                           `https://mail.golia.ai` — no path,
//!                           no trailing slash. UNSET → console runs
//!                           in auto-verify mode (no mail loop).
//!   MAILRS_LOGIN_ADDRESS    account used to log in to mailrs
//!   MAILRS_LOGIN_PASSWORD   password for that account
//!   MAILRS_FROM_ADDRESS     `from:` on outbound mail. mailrs does
//!                           NOT enforce that this match LOGIN_ADDRESS
//!                           or appear in its send_as list — superadmin
//!                           tokens can send from any address, existing
//!                           or not. Operators typically point this at
//!                           `noreply@<domain>` for transactional mail.
//!
//! All three must be set together; absence of any one falls the
//! console back to `auto_verify_email = true`.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct MailClient {
    inner: Arc<MailInner>,
}

struct MailInner {
    http: reqwest::Client,
    base: String,
    login_address: String,
    login_password: String,
    from_address: String,
    /// Cached session bearer. `None` until the first send; then
    /// rewritten on every successful login.
    cached: RwLock<Option<String>>,
}

#[derive(Debug, thiserror::Error)]
pub enum MailError {
    #[error("login refused: {0}")]
    LoginRefused(String),
    #[error("send refused: {0}")]
    SendRefused(String),
    #[error("transport: {0}")]
    Transport(#[from] reqwest::Error),
}

#[derive(Serialize)]
struct LoginRequest<'a> {
    address: &'a str,
    password: &'a str,
}

#[derive(Deserialize)]
struct LoginResponse {
    token: String,
}

#[derive(Serialize)]
struct SendRequest<'a> {
    from: &'a str,
    to: Vec<&'a str>,
    subject: &'a str,
    body: &'a str,
    html_body: Option<&'a str>,
}

impl MailClient {
    /// Build a client when all three env vars are present, otherwise
    /// `None` — the caller flips `auto_verify_email` on accordingly.
    pub fn from_env(http: reqwest::Client) -> Option<Self> {
        let base = std::env::var("MAILRS_API_BASE").ok().filter(|s| !s.is_empty())?;
        let login_address = std::env::var("MAILRS_LOGIN_ADDRESS").ok().filter(|s| !s.is_empty())?;
        let login_password = std::env::var("MAILRS_LOGIN_PASSWORD").ok().filter(|s| !s.is_empty())?;
        let from_address = std::env::var("MAILRS_FROM_ADDRESS").ok().filter(|s| !s.is_empty())?;
        let base = base.trim_end_matches('/').to_string();
        Some(MailClient {
            inner: Arc::new(MailInner {
                http,
                base,
                login_address,
                login_password,
                from_address,
                cached: RwLock::new(None),
            }),
        })
    }

    /// Send one transactional message. Loads the cached bearer
    /// (logging in on first use), retries once on 401 with a fresh
    /// login — every other failure surfaces directly.
    pub async fn send(
        &self,
        to: &str,
        subject: &str,
        body: &str,
        html_body: Option<&str>,
    ) -> Result<(), MailError> {
        let token = self.cached_or_login().await?;
        match self
            .send_with_token(&token, to, subject, body, html_body)
            .await
        {
            Ok(()) => Ok(()),
            Err(MailError::SendRefused(msg)) if msg.starts_with("401") => {
                // bearer expired — clear, re-login, retry.
                *self.inner.cached.write().await = None;
                let token = self.cached_or_login().await?;
                self.send_with_token(&token, to, subject, body, html_body)
                    .await
            }
            Err(e) => Err(e),
        }
    }

    async fn cached_or_login(&self) -> Result<String, MailError> {
        if let Some(t) = self.inner.cached.read().await.as_ref() {
            return Ok(t.clone());
        }
        let mut guard = self.inner.cached.write().await;
        if let Some(t) = guard.as_ref() {
            return Ok(t.clone());
        }
        let resp = self
            .inner
            .http
            .post(format!("{}/api/auth/login", self.inner.base))
            .json(&LoginRequest {
                address: &self.inner.login_address,
                password: &self.inner.login_password,
            })
            .send()
            .await?;
        if !resp.status().is_success() {
            let code = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(MailError::LoginRefused(format!("{code}: {body}")));
        }
        let lr: LoginResponse = resp.json().await?;
        *guard = Some(lr.token.clone());
        Ok(lr.token)
    }

    async fn send_with_token(
        &self,
        token: &str,
        to: &str,
        subject: &str,
        body: &str,
        html_body: Option<&str>,
    ) -> Result<(), MailError> {
        let req = SendRequest {
            from: &self.inner.from_address,
            to: vec![to],
            subject,
            body,
            html_body,
        };
        let resp = self
            .inner
            .http
            .post(format!("{}/api/mail/send", self.inner.base))
            .bearer_auth(token)
            .json(&req)
            .send()
            .await?;
        if resp.status().is_success() {
            return Ok(());
        }
        let code = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        Err(MailError::SendRefused(format!("{code}: {body}")))
    }
}
