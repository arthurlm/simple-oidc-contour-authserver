use async_trait::async_trait;
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum TokenError {
    #[error("missing HTTP attribute")]
    MissingHttpAttribute,

    #[error("missing Authorization HTTP header")]
    MissingAuthorizationHeader,

    #[error("invalid authentication type")]
    InvalidAuthenticationType,

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
pub struct TokenContent {
    pub sub: String,
}

#[async_trait]
pub trait TokenValidator {
    async fn validate(&self, authorization: &str) -> Result<TokenContent, TokenError>;
}
