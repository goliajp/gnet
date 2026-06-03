//! Apple Sign-In.
//!
//! Two pieces of complexity Google / GitHub don't carry:
//!
//! - **`client_secret` is a self-signed JWT** (ES256 / P-256). Apple
//!   doesn't issue a static client_secret string; the relying party
//!   mints a short-lived JWT per token exchange, signed with a P-256
//!   private key downloaded from the Apple Developer portal.
//!
//! - **No userinfo endpoint** — identity comes from the `id_token`
//!   that Apple returns alongside the access_token, again ES256.
//!   We must verify the signature against Apple's JWKS at
//!   `https://appleid.apple.com/auth/keys`, then read `sub` (the
//!   provider subject) and `email` from the claims.

use chrono::Utc;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use serde::Deserialize;

use super::{ExternalUser, OAuthError, urlencode};

const AUTHORIZE: &str = "https://appleid.apple.com/auth/authorize";
const TOKEN: &str = "https://appleid.apple.com/auth/token";
const JWKS_URL: &str = "https://appleid.apple.com/auth/keys";
const ISSUER: &str = "https://appleid.apple.com";

#[derive(Clone)]
pub struct Apple {
    pub client_id: String,
    pub team_id: String,
    pub key_id: String,
    /// PEM-encoded ECDSA P-256 private key for client_secret signing.
    pub private_key_pem: String,
}

impl Apple {
    pub fn from_env() -> Option<Self> {
        let client_id = env_nonempty("APPLE_OAUTH_CLIENT_ID")?;
        let team_id = env_nonempty("APPLE_OAUTH_TEAM_ID")?;
        let key_id = env_nonempty("APPLE_OAUTH_KEY_ID")?;
        let pem = match (
            env_nonempty("APPLE_OAUTH_PRIVATE_KEY_PATH"),
            env_nonempty("APPLE_OAUTH_PRIVATE_KEY_PEM"),
        ) {
            // PATH wins: a path on disk is the supported deploy story;
            // the inline PEM is for dev convenience (mind shell quoting
            // around the multi-line value).
            (Some(path), _) => std::fs::read_to_string(&path).ok()?,
            (None, Some(inline)) => inline,
            (None, None) => return None,
        };
        Some(Self {
            client_id,
            team_id,
            key_id,
            private_key_pem: pem,
        })
    }

    pub fn authorize_url(&self, state: &str, redirect_uri: &str) -> String {
        // `response_mode=query` keeps the callback handler shape the
        // same as Google / GitHub (a GET with query params). The
        // alternative (`form_post`) needs a POST callback; not worth
        // the divergence for v1.1.
        format!(
            "{AUTHORIZE}?response_type=code&response_mode=query&scope=email\
             &client_id={cid}&redirect_uri={ru}&state={st}",
            cid = urlencode(&self.client_id),
            ru = urlencode(redirect_uri),
            st = urlencode(state),
        )
    }

    /// Apple folds exchange + identity into one round-trip because the
    /// identity payload arrives as an ID token in the same response. We
    /// expose a single method instead of `exchange()` + `userinfo()`.
    pub async fn exchange_and_identify(
        &self,
        http: &reqwest::Client,
        kv: &mut ConnectionManager,
        code: &str,
        redirect_uri: &str,
    ) -> Result<ExternalUser, OAuthError> {
        let client_secret = self.client_secret_jwt()?;

        #[derive(Deserialize)]
        struct TokenResp {
            id_token: String,
        }
        let res: TokenResp = http
            .post(TOKEN)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("client_id", &self.client_id),
                ("client_secret", &client_secret),
                ("redirect_uri", redirect_uri),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let header =
            decode_header(&res.id_token).map_err(|e| OAuthError::Provider(format!("jwt header: {e}")))?;
        let kid = header
            .kid
            .ok_or_else(|| OAuthError::Provider("apple id_token has no `kid`".into()))?;

        let jwk = fetch_jwk(http, kv, &kid).await?;
        let dec_key = DecodingKey::from_jwk(&jwk)
            .map_err(|e| OAuthError::Provider(format!("apple jwk decode: {e}")))?;

        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&[&self.client_id]);
        validation.set_issuer(&[ISSUER]);

        #[derive(Deserialize)]
        struct Claims {
            sub: String,
            email: Option<String>,
        }
        let token = decode::<Claims>(&res.id_token, &dec_key, &validation)
            .map_err(|e| OAuthError::Provider(format!("apple id_token verify: {e}")))?;

        Ok(ExternalUser {
            provider: "apple",
            provider_subject: token.claims.sub,
            email: token.claims.email,
        })
    }

    fn client_secret_jwt(&self) -> Result<String, OAuthError> {
        // Apple wants the relying party to sign a short-lived JWT and
        // present it as `client_secret`. iss=team_id, sub=client_id,
        // aud=Apple issuer, iat=now, exp=now + N (max 6 months; we
        // use 1 hour — plenty for a single token exchange and shrinks
        // the blast radius of a leaked secret).
        let now = Utc::now().timestamp();
        let claims = serde_json::json!({
            "iss": self.team_id,
            "iat": now,
            "exp": now + 60 * 60,
            "aud": ISSUER,
            "sub": self.client_id,
        });
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());
        let key = EncodingKey::from_ec_pem(self.private_key_pem.as_bytes())
            .map_err(|e| OAuthError::Provider(format!("apple private key: {e}")))?;
        encode(&header, &claims, &key)
            .map_err(|e| OAuthError::Provider(format!("apple client_secret jwt: {e}")))
    }
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Fetch a JWK by `kid` for Apple's keys endpoint, with a 24h Valkey
/// cache keyed by kid. Apple rotates keys infrequently and publishes
/// the full set; we cache each key independently so an Apple-side
/// rotation that adds a new kid doesn't invalidate keys we already
/// have, and a JWKS fetch failure on rotation degrades gracefully to
/// "key not in cache" rather than a wholesale outage.
async fn fetch_jwk(
    http: &reqwest::Client,
    kv: &mut ConnectionManager,
    kid: &str,
) -> Result<Jwk, OAuthError> {
    let cache_key = format!("gnet:console:oauth:apple:jwk:{kid}");
    let cached: Option<String> = kv.get(&cache_key).await?;
    if let Some(s) = cached {
        if let Ok(jwk) = serde_json::from_str::<Jwk>(&s) {
            return Ok(jwk);
        }
        // Cache hit but couldn't parse — treat as miss; we don't want
        // a stale-format entry to keep us from refetching.
    }

    #[derive(Deserialize)]
    struct Doc {
        keys: Vec<Jwk>,
    }
    let doc: Doc = http
        .get(JWKS_URL)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let jwk = doc
        .keys
        .into_iter()
        .find(|k| k.common.key_id.as_deref() == Some(kid))
        .ok_or_else(|| OAuthError::Provider(format!("no apple jwk for kid={kid}")))?;

    let serialised = serde_json::to_string(&jwk)
        .map_err(|e| OAuthError::Provider(format!("apple jwk reserialise: {e}")))?;
    let _: () = kv.set_ex(&cache_key, &serialised, 24 * 3600).await?;
    Ok(jwk)
}
