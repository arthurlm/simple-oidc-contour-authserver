use async_trait::async_trait;
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum AuthError {
    #[error("missing HTTP attribute")]
    MissingHttpAttribute,

    #[error("missing Authorization HTTP header")]
    MissingAuthorizationHeader,

    #[error("invalid authentication type (expected: {expected}, current: {current})")]
    InvalidAuthenticationType { expected: String, current: String },

    #[error("missing authentication param")]
    MissingAuthenticationParam,

    #[error("missing JWT header")]
    InvalidHeader,

    #[error("missing kid")]
    MissingKid,

    #[error("invalid kid")]
    InvalidKid,

    #[error("invalid JWT token")]
    InvalidToken,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct AuthContent {
    pub sub: String,

    #[serde(default)]
    pub email: Option<String>,

    #[serde(default)]
    pub name: Option<String>,
}

#[async_trait]
pub trait AuthValidator {
    async fn validate(&self, authorization: &str) -> Result<AuthContent, AuthError>;
}
