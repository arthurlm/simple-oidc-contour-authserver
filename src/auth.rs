use async_trait::async_trait;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Duration;

use crate::token_validation::*;

static KEY_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Deserialize)]
pub struct ValidationConfig {
    /// If it contains a value, the validation will check that the `iss` field is the same as the
    /// one provided and will error otherwise.
    #[serde(default)]
    iss: Option<String>,

    /// If it contains a value, the validation will check that the `aud` field is a member of the
    /// audience provided and will error otherwise.
    #[serde(default)]
    aud: Option<String>,

    /// Add some leeway (in seconds) to the `exp`, `iat` and `nbf` validation to
    /// account for clock skew.
    #[serde(default)]
    leeway: u64,
}

impl Into<Validation> for ValidationConfig {
    fn into(self) -> Validation {
        let mut validation = Validation {
            leeway: self.leeway,
            validate_exp: true,
            validate_nbf: false,
            iss: self.iss,
            algorithms: vec![Algorithm::RS256],
            ..Default::default()
        };

        if let Some(aud) = self.aud {
            validation.set_audience(&[aud]);
        }

        validation
    }
}

#[derive(Debug, Deserialize)]
pub struct AuthenticationServiceConfig {
    /// JWK url to get public key
    /// Exemple: https://login.microsoftonline.com/common/discovery/v2.0/keys
    /// You can easily found this in '.well-known' configs
    jwk_url: String,
}

#[derive(Debug)]
pub struct AuthenticationService<'a> {
    /// Service configuration
    config: AuthenticationServiceConfig,

    /// Validation object to match token with
    validation: Validation,

    /// Already in cache keys
    keys: RwLock<HashMap<String, DecodingKey<'a>>>,

    /// Reqwest client
    client: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct JwkItem {
    kid: String,
    kty: String,
    e: String,
    n: String,
}

#[derive(Debug, Deserialize)]
struct JwkEnveloppe {
    keys: Vec<JwkItem>,
}

impl<'a> From<JwkItem> for DecodingKey<'a> {
    fn from(item: JwkItem) -> DecodingKey<'a> {
        DecodingKey::from_rsa_components(&item.n, &item.e).into_static()
    }
}

impl<'a> AuthenticationService<'a> {
    pub fn new(config: AuthenticationServiceConfig, validation: Validation) -> Self {
        let keys = RwLock::new(HashMap::new());
        let client = reqwest::Client::new();
        Self {
            config,
            validation,
            keys,
            client,
        }
    }

    pub fn from_env() -> envy::Result<Self> {
        let config = envy::prefixed("AUTH_").from_env()?;
        let validation_config: ValidationConfig = envy::prefixed("AUTH_VALIDATE_").from_env()?;
        Ok(Self::new(config, validation_config.into()))
    }

    async fn refresh_token(&self) -> reqwest::Result<()> {
        log::info!("Refreshing token");
        let enveloppe: JwkEnveloppe = self
            .client
            .get(&self.config.jwk_url)
            .timeout(KEY_REQUEST_TIMEOUT)
            .send()
            .await?
            .json()
            .await?;

        let mut keys = self.keys.write().unwrap();
        for key in enveloppe.keys {
            keys.insert(key.kid.clone(), key.into());
        }

        Ok(())
    }
}

#[async_trait]
impl<'a> TokenValidator for AuthenticationService<'a> {
    async fn validate(&self, token: &str) -> Result<TokenContent, TokenError> {
        let header = jsonwebtoken::decode_header(token).map_err(|_e| TokenError::InvalidHeader)?;
        let kid = header.kid.ok_or(TokenError::MissingKid)?;

        // Check if kid is in cache and refresh keys if not
        if !self.keys.read().unwrap().contains_key(&kid) {
            if let Err(e) = self.refresh_token().await {
                log::error!("Fail to refresh token: {:?}", e);
            }
        }

        // Get key from cache
        let keys = self.keys.read().unwrap();
        let key = keys.get(&kid).ok_or(TokenError::InvalidKid)?;

        // Decode and check token
        let payload = jsonwebtoken::decode(token, key, &self.validation)
            .map_err(|_e| TokenError::InvalidToken)?;

        Ok(payload.claims)
    }
}
