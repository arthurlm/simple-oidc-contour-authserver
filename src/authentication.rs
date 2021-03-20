use async_trait::async_trait;
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum AuthError {
    #[error("missing HTTP attribute")]
    MissingHttpAttribute,

    #[error("missing authorization HTTP header")]
    MissingAuthorizationHeader,

    #[error("invalid authorization type (expected: {expected}, current: {current})")]
    InvalidAuthorizationType { expected: String, current: String },

    #[error("missing authorization param")]
    MissingAuthorizationParam,

    #[error("missing JWT header")]
    InvalidHeader,

    #[error("missing kid")]
    MissingKid,

    #[error("invalid kid")]
    InvalidKid,

    #[error("invalid JWT token")]
    InvalidToken,
}

#[derive(Debug, Deserialize, PartialEq, Default)]
pub struct AuthContent {
    /// Auth subject (JWT standard fields)
    #[serde(default)]
    pub sub: Option<String>,

    /// Auth issuer (JWT standard fields)
    #[serde(default)]
    pub iss: Option<String>,

    /// Auth audience (JWT standard fields)
    #[serde(default)]
    pub aud: Option<String>,

    /// Auth subject email
    #[serde(default)]
    pub email: Option<String>,

    /// Auth pretty name
    #[serde(default)]
    pub name: Option<String>,

    /// Auth subject unique name
    #[serde(default)]
    pub unique_name: Option<String>,
}

pub type AuthItem = (String, Option<String>);

impl AuthContent {
    pub fn into_header_vec(self) -> Vec<AuthItem> {
        vec![
            ("Auth-Jwt-Sub".to_string(), self.sub),
            ("Auth-Jwt-Aud".to_string(), self.aud),
            ("Auth-Jwt-Iss".to_string(), self.iss),
            ("Auth-Email".to_string(), self.email),
            ("Auth-Name".to_string(), self.name),
            ("Auth-Unique-Name".to_string(), self.unique_name),
        ]
    }
}

#[async_trait]
pub trait AuthValidator {
    const AUTHENTICATION_SCHEME: &'static str;

    async fn validate(&self, authorization: &str) -> Result<AuthContent, AuthError>;
}
