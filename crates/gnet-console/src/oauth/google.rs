use serde::Deserialize;

use super::{ExternalUser, OAuthError, TokenResponse, urlencode};

const AUTHORIZE: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN: &str = "https://oauth2.googleapis.com/token";
const USERINFO: &str = "https://openidconnect.googleapis.com/v1/userinfo";

#[derive(Clone)]
pub struct Google {
    pub client_id: String,
    pub client_secret: String,
}

impl Google {
    pub fn from_env() -> Option<Self> {
        let id = std::env::var("GOOGLE_OAUTH_CLIENT_ID").ok()?;
        let secret = std::env::var("GOOGLE_OAUTH_CLIENT_SECRET").ok()?;
        if id.trim().is_empty() || secret.trim().is_empty() {
            return None;
        }
        Some(Self {
            client_id: id,
            client_secret: secret,
        })
    }

    pub fn authorize_url(&self, state: &str, redirect_uri: &str) -> String {
        format!(
            "{AUTHORIZE}?response_type=code&scope=openid+email&prompt=select_account\
             &client_id={cid}&redirect_uri={ru}&state={st}",
            cid = urlencode(&self.client_id),
            ru = urlencode(redirect_uri),
            st = urlencode(state),
        )
    }

    pub async fn exchange(
        &self,
        http: &reqwest::Client,
        code: &str,
        redirect_uri: &str,
    ) -> Result<String, OAuthError> {
        let res: TokenResponse = http
            .post(TOKEN)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("redirect_uri", redirect_uri),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(res.access_token)
    }

    pub async fn userinfo(
        &self,
        http: &reqwest::Client,
        access_token: &str,
    ) -> Result<ExternalUser, OAuthError> {
        #[derive(Deserialize)]
        struct Body {
            sub: String,
            email: Option<String>,
        }
        let res: Body = http
            .get(USERINFO)
            .bearer_auth(access_token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(ExternalUser {
            provider: "google",
            provider_subject: res.sub,
            email: res.email,
        })
    }
}
