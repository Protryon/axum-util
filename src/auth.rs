use std::{marker::PhantomData, sync::Arc};

use axum::extract::FromRequestParts;
use hmac::{Hmac, Mac};
use http::request::Parts;
use jwt::{FromBase64, SignWithKey, VerifyWithKey};
use serde::{de::DeserializeOwned, Serialize};
use sha2::Sha256;

use crate::errors::{ApiError, ApiResult};

pub struct AuthConfig<T: Serialize + DeserializeOwned + FromBase64> {
    key: Hmac<Sha256>,
    prefix: String,
    _t: PhantomData<T>,
}

impl<T: Serialize + DeserializeOwned + FromBase64> AuthConfig<T> {
    pub fn new(key: &[u8]) -> Self {
        AuthConfig {
            key: Hmac::new_from_slice(key).unwrap(),
            prefix: "Token ".to_string(),
            _t: PhantomData,
        }
    }

    pub fn with_prefix(mut self, mut prefix: String) -> Self {
        if !prefix.is_empty() {
            prefix.push(' ');
        }
        self.prefix = prefix;
        self
    }

    pub fn sign(&self, value: &T) -> ApiResult<String> {
        Ok(value.sign_with_key(&self.key)?)
    }

    pub fn validate(&self, value: &str) -> ApiResult<T> {
        let out = value
            .verify_with_key(&self.key)
            .map_err(|_| ApiError::Unauthorized("malformed auth token".to_string()))?;

        Ok(out)
    }
}

#[async_trait::async_trait]
pub trait AuthParam<T: Serialize + DeserializeOwned + FromBase64> {
    fn config() -> Arc<AuthConfig<T>>;

    async fn authenticated(req: &mut Parts, arg: &T) -> ApiResult<()>;
}

pub struct Auth<T: Serialize + DeserializeOwned + FromBase64, P: AuthParam<T>>(
    pub T,
    pub PhantomData<P>,
);

#[async_trait::async_trait]
impl<
        T: Serialize + DeserializeOwned + FromBase64 + Send + Sync,
        P: AuthParam<T>,
        S: Send + Sync,
    > FromRequestParts<S> for Auth<T, P>
{
    type Rejection = ApiError;

    async fn from_request_parts(req: &mut Parts, _state: &S) -> ApiResult<Self> {
        let Some(auth) = req.headers.get("Authorization") else {
            return Err(ApiError::Unauthorized("missing auth token".to_string()));
        };
        let config = P::config();
        let auth = auth.to_str()?;
        let Some(auth) = auth.strip_prefix(&config.prefix).map(|x| x.trim()) else {
            return Err(ApiError::Unauthorized("malformed auth token".to_string()));
        };

        let out = P::config().validate(auth)?;
        P::authenticated(req, &out).await?;
        Ok(Self(out, PhantomData))
    }
}
