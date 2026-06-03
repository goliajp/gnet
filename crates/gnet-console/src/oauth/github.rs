use serde::Deserialize;

use super::{ExternalUser, OAuthError, TokenResponse, urlencode};

const AUTHORIZE: &str = "https://github.com/login/oauth/authorize";
const TOKEN: &str = "https://github.com/login/oauth/access_token";
const USER: &str = "https://api.github.com/user";
const USER_EMAILS: &str = "https://api.github.com/user/emails";

#[derive(Clone)]
pub struct GitHub {
    pub client_id: String,
    pub client_secret: String,
}

impl GitHub {
    pub fn from_env() -> Option<Self> {
        let id = std::env::var("GITHUB_OAUTH_CLIENT_ID").ok()?;
        let secret = std::env::var("GITHUB_OAUTH_CLIENT_SECRET").ok()?;
        if id.trim().is_empty() || secret.trim().is_empty() {
            return None;
        }
        Some(Self {
            client_id: id,
            client_secret: secret,
        })
    }

    pub fn authorize_url(&self, state: &str, redirect_uri: &str) -> String {
        // GitHub doesn't honour `prompt`; we ask for `user:email` so we
        // can fall back to the /user/emails endpoint when the primary
        // address is hidden in the public profile.
        format!(
            "{AUTHORIZE}?scope=user%3Aemail&client_id={cid}\
             &redirect_uri={ru}&state={st}",
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
            .header("Accept", "application/json")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("code", code),
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
        struct UserBody {
            id: i64,
            email: Option<String>,
        }
        let user: UserBody = http
            .get(USER)
            .bearer_auth(access_token)
            .header("User-Agent", "gnet-console")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        // The /user response withholds email when the user hides it from
        // the public profile; /user/emails returns every verified
        // address, and we pick the primary.
        let email = match user.email {
            Some(e) => Some(e),
            None => {
                #[derive(Deserialize)]
                struct Addr {
                    email: String,
                    primary: bool,
                    verified: bool,
                }
                let emails: Vec<Addr> = http
                    .get(USER_EMAILS)
                    .bearer_auth(access_token)
                    .header("User-Agent", "gnet-console")
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?;
                emails
                    .into_iter()
                    .find(|a| a.primary && a.verified)
                    .map(|a| a.email)
            }
        };

        Ok(ExternalUser {
            provider: "github",
            provider_subject: user.id.to_string(),
            email,
        })
    }
}
