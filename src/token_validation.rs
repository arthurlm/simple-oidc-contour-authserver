use async_trait::async_trait;
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("missing JWT header")]
    InvalidHeader,

    #[error("missing kid")]
    MissingKid,

    #[error("invalid kid")]
    InvalidKid,

    #[error("invalid JWT token")]
    InvalidToken,
}

#[derive(Debug, Deserialize)]
pub struct TokenContent {
    sub: String,
}

#[async_trait]
pub trait TokenValidator {
    async fn validate(&self, token: &str) -> Result<TokenContent, TokenError>;
}
