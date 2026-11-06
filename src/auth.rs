use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use reqwest::{Client, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{info, warn};

use crate::{
    config::AuthConfig,
    utils::{hash::server_hash, time::now},
};

const DEVICE_CODE_URL: &str = "https://login.live.com/oauth20_connect.srf";
const TOKEN_URL: &str = "https://login.live.com/oauth20_token.srf";
const XBL_URL: &str = "https://user.auth.xboxlive.com/user/authenticate";
const XSTS_URL: &str = "https://xsts.auth.xboxlive.com/xsts/authorize";
const MC_LOGIN_URL: &str = "https://api.minecraftservices.com/authentication/login_with_xbox";
const MC_PROFILE_URL: &str = "https://api.minecraftservices.com/minecraft/profile";
const SESSION_JOIN_URL: &str = "https://sessionserver.mojang.com/session/minecraft/join";
const SCOPE: &str = "service::user.auth.xboxlive.com::MBI_SSL";
const EXPIRY_MARGIN_SECS: u64 = 300;

#[derive(Serialize, Deserialize, Default)]
struct TokenCache {
    ms_refresh_token: Option<String>,
    mc_access_token: Option<String>,
    mc_expires_at: u64,
    uuid: String,
    name: String,
}

#[derive(Deserialize)]
struct DeviceCode {
    user_code: String,
    device_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: u64,
}

#[derive(Deserialize)]
struct MsToken {
    access_token: String,
    refresh_token: String,
}

#[derive(Deserialize)]
struct OAuthError {
    error: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct XboxToken {
    token: String,
    display_claims: DisplayClaims,
}

#[derive(Deserialize)]
struct DisplayClaims {
    xui: Vec<XboxUser>,
}

#[derive(Deserialize)]
struct XboxUser {
    uhs: String,
}

#[derive(Deserialize)]
struct McToken {
    access_token: String,
    expires_in: u64,
}

#[derive(Deserialize)]
struct McProfile {
    id: String,
    name: String,
}

pub struct Auth {
    http: Client,
    client_id: String,
    cache_path: PathBuf,
    cache: TokenCache,
}

impl Auth {
    pub fn new(config: &AuthConfig) -> Result<Self> {
        let cache = match fs::read(&config.cache_path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|err| {
                warn!("ignoring unreadable token cache {}: {err}",config.cache_path.display());
                TokenCache::default()
            }),
            Err(_) => TokenCache::default(),
        };
        let http = Client::builder()
            .user_agent(concat!("rafk/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(20))
            .build()?;

        Ok(Self {
            http,
            client_id: config.client_id.clone(),
            cache_path: config.cache_path.clone(),
            cache
        })
    }

    pub fn name(&self) -> &str { &self.cache.name }

    pub async fn login(&mut self) -> Result<()> {
        if self.cache.mc_access_token.is_some() && self.cache.mc_expires_at > now() + EXPIRY_MARGIN_SECS { return Ok(()) }

        let ms_token = match self.cache.ms_refresh_token.clone() {
            Some(refresh_token) => match self.refresh(&refresh_token).await {
                Ok(token) => token,
                Err(err) => {
                    warn!("refresh token rejected ({err:#}), starting device code login");
                    self.device_flow().await?
                }
            },
            None => self.device_flow().await?,
        };
        self.cache.ms_refresh_token = Some(ms_token.refresh_token);

        let mc_token = self.minecraft_token(&ms_token.access_token).await?;
        let profile = self.profile(&mc_token.access_token).await?;
        info!(name = %profile.name, uuid = %profile.id, "authenticated");

        self.cache.mc_access_token = Some(mc_token.access_token);
        self.cache.mc_expires_at = now() + mc_token.expires_in;
        self.cache.uuid = profile.id;
        self.cache.name = profile.name;
        self.save()
    }

    pub async fn join_server(&mut self, server_id: &str, secret: &[u8], public_key: &[u8]) -> Result<()> {
        let hash = server_hash(server_id, secret, public_key);

        self.login().await?;
        let status = self.post_join(&hash).await?;
        if status.is_success() { return Ok(()) }
        if status != StatusCode::UNAUTHORIZED && status != StatusCode::FORBIDDEN { bail!("session join failed: {status}") }

        warn!("session server rejected token ({status}), re-authenticating");
        self.cache.mc_access_token = None;
        self.login().await?;
        let status = self.post_join(&hash).await?;
        if !status.is_success() { bail!("session join failed after re-authenticating: {status}") }
        Ok(())
    }

    async fn post_join(&self, hash: &str) -> Result<StatusCode> {
        let body = json!({
            "accessToken": self.cache.mc_access_token,
            "selectedProfile": self.cache.uuid,
            "serverId": hash,
        });
        
        Ok(self.http.post(SESSION_JOIN_URL).json(&body).send().await?.status())
    }

    async fn device_flow(&self) -> Result<MsToken> {
        let code: DeviceCode = self.http.post(DEVICE_CODE_URL).form(&[
            ("client_id", self.client_id.as_str()),
            ("scope", SCOPE),
            ("response_type", "device_code"),
        ]).send().await?.error_for_status()?.json().await?;

        warn!("Microsoft login required: open {} and enter code {}", code.verification_uri, code.user_code);

        let deadline = now() + code.expires_in;
        let mut interval = code.interval.max(1);
        while now() < deadline {
            tokio::time::sleep(Duration::from_secs(interval)).await;

            let response = self.http.post(TOKEN_URL).form(&[
                ("client_id", self.client_id.as_str()),
                ("device_code", code.device_code.as_str()),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ]).send().await?;
            
            if response.status().is_success() { return Ok(response.json().await?) }

            let error: OAuthError = response.json().await?;
            match error.error.as_str() {
                "authorization_pending" => {}
                "slow_down" => interval += 5,
                other => bail!("device code login failed: {other}"),
            }
        }
        
        bail!("device code expired before login was completed")
    }

    async fn refresh(&self, refresh_token: &str) -> Result<MsToken> {
        Ok(self.http.post(TOKEN_URL).form(&[
            ("client_id", self.client_id.as_str()),
            ("refresh_token", refresh_token),
            ("grant_type", "refresh_token"),
            ("scope", SCOPE),
        ]).send().await?.error_for_status()?.json().await?)
    }

    async fn minecraft_token(&self, ms_access_token: &str) -> Result<McToken> {
        let xbl: XboxToken = self.post_json(XBL_URL, &json!({
            "Properties": {
                "AuthMethod": "RPS",
                "SiteName": "user.auth.xboxlive.com",
                "RpsTicket": ms_access_token,
            },
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT",
        })).await.context("Xbox Live authentication failed")?;

        let xsts = self.xsts(&xbl.token).await?;
        let user_hash = &xsts.display_claims.xui.first().context("XSTS response has no user hash")?.uhs;

        self.post_json(MC_LOGIN_URL, &json!({ 
            "identityToken": format!("XBL3.0 x={user_hash};{}", xsts.token)
        })).await.context("Minecraft login failed")
    }

    async fn xsts(&self, xbl_token: &str) -> Result<XboxToken> {
        let response = self.http.post(XSTS_URL).header("Accept", "application/json").json(&json!({
            "Properties": { "SandboxId": "RETAIL", "UserTokens": [xbl_token] },
            "RelyingParty": "rp://api.minecraftservices.com/",
            "TokenType": "JWT",
        })).send().await?;
        
        if response.status().is_success() { return Ok(response.json().await?) }

        let status = response.status();
        let body: Value = response.json().await.unwrap_or_default();
        match body["XErr"].as_u64() {
            Some(2148916233) => bail!("this Microsoft account has no Xbox profile; sign in on minecraft.net once"),
            Some(2148916235) => bail!("Xbox Live is not available in this account's country"),
            Some(2148916238) => bail!("child account: it must be added to a Microsoft Family by an adult"),
            Some(code) => bail!("XSTS authorization failed: XErr {code}"),
            None => bail!("XSTS authorization failed: {status}")
        }
    }

    async fn profile(&self, mc_access_token: &str) -> Result<McProfile> {
        let response = self.http.get(MC_PROFILE_URL).bearer_auth(mc_access_token).send().await?;
        if response.status() == StatusCode::NOT_FOUND { bail!("this account does not own Minecraft Java Edition") }
        Ok(response.error_for_status()?.json().await?)
    }

    async fn post_json<T: DeserializeOwned>(&self, url: &str, body: &Value) -> Result<T> {
        Ok(self.http.post(url).header("Accept", "application/json").json(body).send().await?.error_for_status()?.json().await?)
    }

    fn save(&self) -> Result<()> {
        let tmp = self.cache_path.with_extension("tmp");
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        options.open(&tmp).and_then(|mut file| file.write_all(&serde_json::to_vec_pretty(&self.cache)?)).with_context(|| format!("failed to write token cache {}", tmp.display()))?;
        fs::rename(&tmp, &self.cache_path).with_context(|| format!("failed to write token cache {}", self.cache_path.display()))
    }
}