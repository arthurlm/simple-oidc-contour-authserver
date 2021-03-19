use async_trait::async_trait;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Duration;

use crate::authentication::*;
use crate::helpers::read_auth_param;

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
pub struct BearerAuthConfig {
    /// JWK url to get public key
    /// Exemple: https://login.microsoftonline.com/common/discovery/v2.0/keys
    /// You can easily found this in '.well-known' configs
    jwk_url: String,
}

#[derive(Debug)]
pub struct BearerAuth<'a> {
    /// Service configuration
    config: BearerAuthConfig,

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

impl<'a> BearerAuth<'a> {
    pub fn new(config: BearerAuthConfig, validation: Validation) -> Self {
        log::info!(
            "bearer auth config: {:?}, validation: {:?}",
            config,
            validation,
        );

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

    pub async fn refresh_token(&self) -> reqwest::Result<()> {
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
impl<'a> AuthValidator for BearerAuth<'a> {
    async fn validate(&self, authorization: &str) -> Result<AuthContent, AuthError> {
        let token = read_auth_param("Bearer", authorization)?;

        let header = jsonwebtoken::decode_header(token).map_err(|_e| AuthError::InvalidHeader)?;
        let kid = header.kid.ok_or(AuthError::MissingKid)?;

        // Check if kid is in cache and refresh keys if not
        if !self.keys.read().unwrap().contains_key(&kid) {
            if let Err(e) = self.refresh_token().await {
                log::error!("Fail to refresh token: {:?}", e);
            }
        }

        // Get key from cache
        let keys = self.keys.read().unwrap();
        let key = keys.get(&kid).ok_or(AuthError::InvalidKid)?;

        // Decode and check token
        let payload = jsonwebtoken::decode(token, key, &self.validation).map_err(|e| {
            log::warn!("Token validation failed: {:?}", e);
            AuthError::InvalidToken
        })?;

        Ok(payload.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    static TOKEN_SECRET: &[u8] = &[4, 8, 15, 16, 23, 42];

    macro_rules! config {
        () => {
            BearerAuthConfig {
                jwk_url: "https://login.microsoftonline.com/common/discovery/v2.0/keys".into(),
            }
        };
    }

    #[test]
    fn test_new_does_not_panic() {
        let config = config!();
        let validation: ValidationConfig = serde_json::from_str("{}").unwrap();
        BearerAuth::new(config, validation.into());
    }

    macro_rules! auth {
        () => {{
            let config = config!();
            let validation = Validation {
                validate_exp: false,
                ..Default::default()
            };
            BearerAuth::new(config, validation.into())
        }};
    }

    #[tokio::test]
    async fn test_refresh_token() {
        let auth = auth!();
        assert_eq!(auth.keys.read().unwrap().len(), 0);

        auth.refresh_token().await.unwrap();
        assert_ne!(auth.keys.read().unwrap().len(), 0);
    }

    macro_rules! token {
        () => {
            token!(
                json!({"typ": "JWT", "alg": "HS256", "kid": "test"}),
                json!({"sub": "Arthur"})
            )
        };
        ($header:expr, $payload:expr) => {{
            use jsonwebtoken::{crypto::sign, EncodingKey};

            let message = format!(
                "{}.{}",
                base64::encode(serde_json::to_string(&$header).unwrap()),
                base64::encode(serde_json::to_string(&$payload).unwrap())
            );
            let key = EncodingKey::from_secret(TOKEN_SECRET);
            let signature = sign(&message, &key, Algorithm::HS256).unwrap();

            format!("Bearer   {}.{}", message, signature)
        }};
    }

    #[tokio::test]
    async fn test_no_headers() {
        let auth = auth!();
        assert_eq!(
            auth.validate("Bearer foo").await,
            Err(AuthError::InvalidHeader)
        );
        assert_eq!(
            auth.validate("Bearer .foo.bar").await,
            Err(AuthError::InvalidHeader)
        );
        assert_eq!(
            auth.validate("Bearer baz.foo.bar").await,
            Err(AuthError::InvalidHeader)
        );
    }

    #[tokio::test]
    async fn test_no_kid() {
        let token = token!(
            json!({
                "typ": "JWT",
                "alg": "HS256",
            }),
            json!({})
        );

        let auth = auth!();
        assert_eq!(auth.validate(&token).await, Err(AuthError::MissingKid));
    }

    #[tokio::test]
    async fn test_trigger_refresh() {
        let auth = auth!();
        assert_eq!(auth.keys.read().unwrap().len(), 0);

        let token = token!();
        let _ = auth.validate(&token).await;
        assert_ne!(auth.keys.read().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_invalid_signature() {
        let auth = auth!();
        auth.keys
            .write()
            .unwrap()
            .insert("test".into(), DecodingKey::from_secret(&[10, 31]));
        assert_eq!(auth.keys.read().unwrap().len(), 1);

        let token = token!();
        assert_eq!(auth.validate(&token).await, Err(AuthError::InvalidToken));
        assert_eq!(auth.keys.read().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_valid_signature() {
        let auth = auth!();
        auth.keys
            .write()
            .unwrap()
            .insert("test".into(), DecodingKey::from_secret(TOKEN_SECRET));
        assert_eq!(auth.keys.read().unwrap().len(), 1);

        let token = token!();
        assert_eq!(
            auth.validate(&token).await,
            Ok(AuthContent {
                sub: Some("Arthur".to_string()),
                email: None,
                name: None,
            })
        );
        assert_eq!(auth.keys.read().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_authorization_empty() {
        let auth = auth!();
        assert_eq!(
            auth.validate("").await,
            Err(AuthError::MissingAuthorizationParam)
        );
        assert_eq!(
            auth.validate("   ").await,
            Err(AuthError::MissingAuthorizationParam)
        );
    }

    #[tokio::test]
    async fn test_authorization_invalid_type() {
        let auth = auth!();
        assert_eq!(
            auth.validate("Basic    YWxhZGRpbjpvcGVuc2VzYW1l").await,
            Err(AuthError::InvalidAuthorizationType {
                expected: "Bearer".into(),
                current: "Basic".into(),
            })
        );
    }
}
