//! OAuth 2 / OpenID Connect — provider configuration + flow primitives.
//!
//! v1.1 lands Google + GitHub here (§17.5b); Apple (ES256 ID-token verify
//! against `https://appleid.apple.com/auth/keys`) lands in §17.5d after
//! the JWKS cache piece is built.
//!
//! Providers are an `enum` (not a `dyn Trait`) so handlers can take a
//! plain reference and async methods compose without `Box<dyn ...>`.

pub mod github;
pub mod google;

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    #[error("provider {0:?} not configured")]
    NotConfigured(String),
    #[error("unknown provider: {0:?}")]
    Unknown(String),
    #[error("oauth state mismatch")]
    StateMismatch,
    #[error("oauth state expired or replayed")]
    StateExpired,
    #[error("provider returned no email")]
    MissingEmail,
    #[error("provider error: {0}")]
    Provider(String),
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("valkey: {0}")]
    Redis(#[from] redis::RedisError),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ExternalUser {
    pub provider: &'static str,
    pub provider_subject: String,
    pub email: Option<String>,
}

#[derive(Clone)]
pub enum Provider {
    Google(google::Google),
    GitHub(github::GitHub),
}

impl Provider {
    pub fn name(&self) -> &'static str {
        match self {
            Provider::Google(_) => "google",
            Provider::GitHub(_) => "github",
        }
    }

    pub fn authorize_url(&self, state: &str, redirect_uri: &str) -> String {
        match self {
            Provider::Google(g) => g.authorize_url(state, redirect_uri),
            Provider::GitHub(g) => g.authorize_url(state, redirect_uri),
        }
    }

    pub async fn exchange(
        &self,
        http: &reqwest::Client,
        code: &str,
        redirect_uri: &str,
    ) -> Result<String, OAuthError> {
        match self {
            Provider::Google(g) => g.exchange(http, code, redirect_uri).await,
            Provider::GitHub(g) => g.exchange(http, code, redirect_uri).await,
        }
    }

    pub async fn fetch_userinfo(
        &self,
        http: &reqwest::Client,
        access_token: &str,
    ) -> Result<ExternalUser, OAuthError> {
        match self {
            Provider::Google(g) => g.userinfo(http, access_token).await,
            Provider::GitHub(g) => g.userinfo(http, access_token).await,
        }
    }
}

/// `application/x-www-form-urlencoded` minimal percent-encoder.
/// RFC 3986 unreserved set (A-Z a-z 0-9 - _ . ~) passes through; every
/// other byte becomes %HH. Used for building both the authorize URL and
/// the token-exchange form. We don't reach for the `url` crate just for
/// this — the surface is tiny and we want zero ambiguity over encoding.
pub fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
}

#[derive(Deserialize)]
pub(crate) struct TokenResponse {
    pub access_token: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencode_preserves_unreserved_and_escapes_rest() {
        assert_eq!(urlencode("abcXYZ-_.~012"), "abcXYZ-_.~012");
        assert_eq!(urlencode("a b/c?d=e&f"), "a%20b%2Fc%3Fd%3De%26f");
        assert_eq!(urlencode("öl"), "%C3%B6l");
    }
}
