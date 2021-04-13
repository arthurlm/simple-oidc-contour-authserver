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

    #[error("payload validation failed: {reason}")]
    PayloadValidationFail { reason: String },

    #[error("access denied")]
    AccessDenied,
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

    /// Roles associated to user
    #[serde(default)]
    pub roles: Option<Vec<String>>,
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
            ("Auth-Roles".to_string(), self.roles.map(|x| x.join(","))),
        ]
    }
}

#[async_trait]
pub trait AuthValidator {
    const AUTHENTICATION_SCHEME: &'static str;

    async fn validate(&self, authorization: &str) -> Result<AuthContent, AuthError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! http_header {
        ($k:expr) => {
            ($k.into(), None)
        };
        ($k:expr, $v:expr) => {
            ($k.into(), Some($v.into()))
        };
    }

    #[test]
    fn test_headers_empty() {
        let data: AuthContent = Default::default();

        assert_eq!(
            data.into_header_vec(),
            vec![
                http_header!("Auth-Jwt-Sub"),
                http_header!("Auth-Jwt-Aud"),
                http_header!("Auth-Jwt-Iss"),
                http_header!("Auth-Email"),
                http_header!("Auth-Name"),
                http_header!("Auth-Unique-Name"),
                http_header!("Auth-Roles"),
            ]
        );
    }
    #[test]
    fn test_headers_with_data() {
        let data = AuthContent {
            sub: Some("sub".to_string()),
            iss: Some("iss".to_string()),
            aud: Some("aud".to_string()),
            email: Some("email".to_string()),
            name: Some("name".to_string()),
            unique_name: Some("unique_name".to_string()),
            roles: Some(vec!["r1".to_string(), "r2".to_string()]),
        };

        assert_eq!(
            data.into_header_vec(),
            vec![
                http_header!("Auth-Jwt-Sub", "sub"),
                http_header!("Auth-Jwt-Aud", "aud"),
                http_header!("Auth-Jwt-Iss", "iss"),
                http_header!("Auth-Email", "email"),
                http_header!("Auth-Name", "name"),
                http_header!("Auth-Unique-Name", "unique_name"),
                http_header!("Auth-Roles", "r1,r2"),
            ]
        );
    }
}
