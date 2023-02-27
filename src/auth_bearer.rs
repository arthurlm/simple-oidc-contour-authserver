use async_trait::async_trait;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use std::time::Duration;
use thiserror::Error;

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

impl From<ValidationConfig> for Validation {
    fn from(config: ValidationConfig) -> Self {
        let mut validation = Self::new(Algorithm::RS256);
        validation.leeway = config.leeway;
        validation.validate_exp = true;
        validation.validate_nbf = false;

        if let Some(value) = config.iss {
            let mut iss = HashSet::new();
            iss.insert(value);
            validation.iss = Some(iss);
        }

        if let Some(aud) = config.aud {
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

    /// Add some extra constraints to allow / disallow user.
    /// For example 'required roles', ...
    #[serde(flatten, default)]
    constraints: AuthConstraint,
}

#[derive(Debug, PartialEq)]
pub enum KeyInfo {
    RsaComponents {
        e: String,
        n: String,
    },
    #[cfg(test)]
    Secret(Vec<u8>),
}

#[derive(Debug, Error)]
enum BearerAuthError {
    #[error("missing JWT header")]
    InvalidHeader,

    #[error("missing kid")]
    MissingKid,

    #[error("invalid kid")]
    InvalidKid,

    #[error("invalid JWT token: {0}")]
    InvalidToken(String),
}

impl From<BearerAuthError> for AuthError {
    fn from(error: BearerAuthError) -> Self {
        Self::PayloadValidationFail {
            reason: format!("{}", error),
        }
    }
}

#[derive(Debug)]
pub struct BearerAuth {
    /// Service configuration
    config: BearerAuthConfig,

    /// Validation object to match token with
    validation: Validation,

    /// Already in cache keys
    keys: RwLock<HashMap<String, KeyInfo>>,

    /// Reqwest client
    client: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct JwkItem {
    kid: String,
    e: String,
    n: String,
    // We do not read this field directly but wants to be sure it exists
    #[allow(dead_code)]
    kty: String,
}

#[derive(Debug, Deserialize)]
struct JwkEnveloppe {
    keys: Vec<JwkItem>,
}

impl From<JwkItem> for KeyInfo {
    fn from(item: JwkItem) -> Self {
        Self::RsaComponents {
            e: item.e,
            n: item.n,
        }
    }
}

impl BearerAuth {
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
impl AuthValidator for BearerAuth {
    const AUTHENTICATION_SCHEME: &'static str = "Bearer";

    async fn validate(&self, request: AuthRequest) -> Result<AuthContent, AuthError> {
        let authorization = request
            .authorization
            .ok_or(AuthError::MissingAuthorizationHeader)?;
        let token = read_auth_param(Self::AUTHENTICATION_SCHEME, &authorization)?;

        let header =
            jsonwebtoken::decode_header(token).map_err(|_e| BearerAuthError::InvalidHeader)?;
        let kid = header.kid.ok_or(BearerAuthError::MissingKid)?;

        // Check if kid is in cache and refresh keys if not
        if !self.keys.read().unwrap().contains_key(&kid) {
            if let Err(e) = self.refresh_token().await {
                log::error!("Fail to refresh token: {:?}", e);
            }
        }

        // Get key from cache
        let keys = self.keys.read().unwrap();
        let key_info = keys.get(&kid).ok_or(BearerAuthError::InvalidKid)?;
        let key = match key_info {
            KeyInfo::RsaComponents { n, e } => {
                DecodingKey::from_rsa_components(n, e).map_err(|err| {
                    AuthError::PayloadValidationFail {
                        reason: err.to_string(),
                    }
                })?
            }
            #[cfg(test)]
            KeyInfo::Secret(s) => DecodingKey::from_secret(s),
        };

        // Decode and check token
        let payload =
            jsonwebtoken::decode::<AuthContent>(token, &key, &self.validation).map_err(|e| {
                log::warn!("Token validation failed: {:?}", e);
                BearerAuthError::InvalidToken(e.to_string())
            })?;

        payload.claims.is_authorized(&self.config.constraints)?;

        Ok(payload.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use serde_json::json;

    static TOKEN_SECRET: &[u8] = &[4, 8, 15, 16, 23, 42];

    macro_rules! config {
        () => {
            BearerAuthConfig {
                jwk_url: "https://login.microsoftonline.com/common/discovery/v2.0/keys".into(),
                constraints: AuthConstraint::default(),
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
            auth!(config)
        }};
        ($config:expr) => {{
            let mut validation = Validation::default();
            validation.validate_exp = false;
            BearerAuth::new($config, validation.into())
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
                json!({"sub": "Arthur", "exp": 1648381980})
            )
        };
        ($header:expr, $payload:expr) => {{
            use jsonwebtoken::{crypto::sign, EncodingKey};

            let message = format!(
                "{}.{}",
                base64::engine::general_purpose::STANDARD.encode(serde_json::to_string(&$header).unwrap()),
                base64::engine::general_purpose::STANDARD.encode(serde_json::to_string(&$payload).unwrap())
            );
            let key = EncodingKey::from_secret(TOKEN_SECRET);
            let signature = sign(message.as_bytes(), &key, Algorithm::HS256).unwrap();

            format!("Bearer   {}.{}", message, signature)
        }};
    }

    macro_rules! bearer_auth_error {
        ($error:expr) => {
            Err(AuthError::PayloadValidationFail {
                reason: format!("{}", $error),
            })
        };
    }

    macro_rules! auth_req {
        ($req:expr) => {
            AuthRequest {
                authorization: Some($req.into()),
                ..Default::default()
            }
        };
    }

    #[tokio::test]
    async fn test_no_headers() {
        let auth = auth!();

        assert_eq!(
            auth.validate(AuthRequest::default()).await,
            Err(AuthError::MissingAuthorizationHeader)
        );
        assert_eq!(
            auth.validate(auth_req!("Bearer foo")).await,
            bearer_auth_error!(BearerAuthError::InvalidHeader)
        );
        assert_eq!(
            auth.validate(auth_req!("Bearer .foo.bar")).await,
            bearer_auth_error!(BearerAuthError::InvalidHeader)
        );
        assert_eq!(
            auth.validate(auth_req!("Bearer baz.foo.bar")).await,
            bearer_auth_error!(BearerAuthError::InvalidHeader)
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
        assert_eq!(
            auth.validate(auth_req!(token)).await,
            bearer_auth_error!(BearerAuthError::MissingKid)
        );
    }

    #[tokio::test]
    async fn test_trigger_refresh() {
        let auth = auth!();
        assert_eq!(auth.keys.read().unwrap().len(), 0);

        let token = token!();
        let _ = auth.validate(auth_req!(token)).await;
        assert_ne!(auth.keys.read().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_invalid_signature() {
        let auth = auth!();
        auth.keys
            .write()
            .unwrap()
            .insert("test".into(), KeyInfo::Secret(vec![10, 31]));
        assert_eq!(auth.keys.read().unwrap().len(), 1);

        let token = token!();
        assert_eq!(
            auth.validate(auth_req!(token)).await,
            bearer_auth_error!(BearerAuthError::InvalidToken(
                "InvalidSignature".to_string()
            ))
        );
        assert_eq!(auth.keys.read().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_valid_signature() {
        let auth = auth!();
        auth.keys
            .write()
            .unwrap()
            .insert("test".into(), KeyInfo::Secret(TOKEN_SECRET.to_vec()));
        assert_eq!(auth.keys.read().unwrap().len(), 1);

        let token = token!();
        assert_eq!(
            auth.validate(auth_req!(token)).await,
            Ok(AuthContent {
                sub: Some("Arthur".to_string()),
                ..Default::default()
            })
        );
        assert_eq!(auth.keys.read().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_authorization_empty() {
        let auth = auth!();
        assert_eq!(
            auth.validate(auth_req!("")).await,
            Err(AuthError::MissingAuthorizationParam)
        );
        assert_eq!(
            auth.validate(auth_req!("   ")).await,
            Err(AuthError::MissingAuthorizationParam)
        );
    }

    #[tokio::test]
    async fn test_authorization_invalid_type() {
        let auth = auth!();
        assert_eq!(
            auth.validate(auth_req!("Basic    YWxhZGRpbjpvcGVuc2VzYW1l"))
                .await,
            Err(AuthError::InvalidAuthorizationType {
                expected: "Bearer".into(),
                current: "Basic".into(),
            })
        );
    }

    #[tokio::test]
    async fn test_constraints() {
        let config = BearerAuthConfig {
            jwk_url: "https://login.microsoftonline.com/common/discovery/v2.0/keys".into(),
            constraints: AuthConstraint {
                required_role: Some("r1".to_string()),
                roles_contraint: None,
            },
        };
        let auth = auth!(config);
        auth.keys
            .write()
            .unwrap()
            .insert("test".into(), KeyInfo::Secret(TOKEN_SECRET.to_vec()));
        assert_eq!(auth.keys.read().unwrap().len(), 1);

        // Test missing roles
        let token = token!(
            json!({"typ": "JWT", "alg": "HS256", "kid": "test"}),
            json!({"sub": "Arthur", "exp": 1648381980})
        );
        assert_eq!(
            auth.validate(auth_req!(token)).await,
            Err(AuthError::AccessDenied)
        );

        // Test bad roles
        let token = token!(
            json!({"typ": "JWT", "alg": "HS256", "kid": "test"}),
            json!({"sub": "Arthur", "roles": ["r2"], "exp": 1648381980})
        );
        assert_eq!(
            auth.validate(auth_req!(token)).await,
            Err(AuthError::AccessDenied)
        );

        // Test valid token
        let token = token!(
            json!({"typ": "JWT", "alg": "HS256", "kid": "test"}),
            json!({"sub": "Arthur", "roles": ["r1"], "exp": 1648381980})
        );
        assert_eq!(
            auth.validate(auth_req!(token)).await,
            Ok(AuthContent {
                sub: Some("Arthur".to_string()),
                roles: Some(vec!["r1".to_string()]),
                ..Default::default()
            })
        );
    }
}
