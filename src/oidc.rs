// use always_cell::AlwaysCell;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use log::warn;
use openid::{
    error::ClientError, Bearer, Client, DiscoveredClient, OAuth2Error, OAuth2ErrorCode, Options,
    StandardClaims, Token, Userinfo,
};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use tokio::sync::RwLock;
use url::Url;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OidcConfig {
    pub name: String,
    pub client_id: String,
    pub client_secret: String,
    pub issuer: Url,
    pub redirect: Url,
    pub refresh_cycle: Duration,
}

pub struct OidcController {
    handlers: IndexMap<String, OidcHandler>,
}

impl OidcController {
    pub async fn new(configs: &[OidcConfig]) -> Self {
        let mut handlers = IndexMap::new();
        for config in configs {
            handlers.insert(config.name.clone(), OidcHandler::new(config).await);
        }
        Self { handlers }
    }

    pub fn handler(&self, name: &str) -> Option<&OidcHandler> {
        self.handlers.get(name)
    }

    pub fn handlers(&self) -> impl Iterator<Item = &String> {
        self.handlers.keys()
    }
}

#[derive(Clone)]
pub struct OidcHandler {
    client: Arc<RwLock<(DateTime<Utc>, Client)>>,
    config: OidcConfig,
}

impl OidcHandler {
    pub async fn new(config: &OidcConfig) -> Self {
        let client = loop {
            match DiscoveredClient::discover(
                config.client_id.to_string(),
                config.client_secret.to_string(),
                Some(config.redirect.to_string()),
                config.issuer.clone(),
            )
            .await
            {
                Ok(x) => break x,
                Err(e) => {
                    warn!("failed to discover OIDC: {e:?}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        };
        Self {
            client: Arc::new(RwLock::new((
                Utc::now() + chrono::Duration::from_std(config.refresh_cycle).unwrap(),
                client,
            ))),
            config: config.clone(),
        }
    }

    async fn recreate(&self) -> Client {
        loop {
            match DiscoveredClient::discover(
                self.config.client_id.clone(),
                self.config.client_secret.clone(),
                Some(self.config.redirect.to_string()),
                self.config.issuer.clone(),
            )
            .await
            {
                Ok(x) => break x,
                Err(e) => {
                    warn!("failed to rediscover OIDC: {e:?}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    pub async fn auth_url(&self, redirect: Option<&Url>) -> Url {
        let client = self.client.read().await;
        let mut tclient;
        let client = if let Some(redirect) = redirect {
            tclient = client.1.clone();
            tclient.redirect_uri = Some(redirect.to_string());
            &tclient
        } else {
            &client.1
        };
        client.auth_url(&Options {
            scope: Some("openid email profile".into()),
            state: None,
            ..Default::default()
        })
    }

    pub async fn validate_code(
        &self,
        code: &str,
        redirect: Option<&Url>,
    ) -> Result<Option<(Bearer, StandardClaims, Userinfo)>> {
        let mut client = self.client.read().await;
        let now = Utc::now();
        if client.0 < now {
            drop(client);
            let mut old_client = self.client.write().await;
            if old_client.0 < now {
                let new_client = self.recreate().await;
                *old_client = (
                    now + chrono::Duration::from_std(self.config.refresh_cycle).unwrap(),
                    new_client,
                )
            }
            drop(old_client);
            client = self.client.read().await;
        }
        let mut tclient;
        let client = if let Some(redirect) = redirect {
            tclient = client.1.clone();
            tclient.redirect_uri = Some(redirect.to_string());
            &tclient
        } else {
            &client.1
        };
        let mut token: Token = match client.request_token(code).await {
            Ok(x) => x.into(),
            Err(ClientError::OAuth2(OAuth2Error {
                error: OAuth2ErrorCode::InvalidGrant,
                ..
            })) => {
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        };

        if let Some(id_token) = &mut token.id_token {
            client
                .decode_token(id_token)
                .context("failed to decode token")?;
            client
                .validate_token(id_token, None, None)
                .context("failed to validate token")?;
        } else {
            return Ok(None);
        };

        let info = client.request_userinfo(&token).await?;

        Ok(Some((
            token.bearer,
            token.id_token.unwrap().unwrap_decoded().1,
            info,
        )))
    }
}
