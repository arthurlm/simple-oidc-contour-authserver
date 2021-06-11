use async_trait::async_trait;
use serde::Deserialize;
use std::path::Path;
use std::{fs, io};
use thiserror::Error;

use crate::authentication::*;

#[derive(Debug, Deserialize)]
pub struct IpAuthEntry {
    /// Ip to allow.
    ///
    /// Possible improvment: use socket object instead.
    ip: String,

    /// information associated with this IP.
    #[serde(flatten)]
    content: AuthContent,
}

#[derive(Debug, Deserialize)]
pub struct IpAuthConfig {
    allow_list: Vec<IpAuthEntry>,
}

#[derive(Debug, Error)]
pub enum IpAuthError {
    #[error("invalid file: {0}")]
    InvalidFile(#[from] io::Error),

    #[error("invalid config: {0}")]
    InvalidConfig(#[from] serde_json::Error),
}

#[derive(Debug)]
pub struct IpAuth {
    config: IpAuthConfig,
}

impl IpAuth {
    pub fn new(config: IpAuthConfig) -> Self {
        log::info!("IP Auth config: {:?}", config);
        Self { config }
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, IpAuthError> {
        let content = fs::read_to_string(path)?;
        let config = serde_json::from_str(&content)?;
        Ok(Self::new(config))
    }
}

#[async_trait]
impl AuthValidator for IpAuth {
    const AUTHENTICATION_SCHEME: &'static str = "IP_ALLOWED_LIST";

    async fn validate(&self, request: AuthRequest) -> Result<AuthContent, AuthError> {
        let source_ip_addr = request
            .source_ip_addr
            .ok_or(AuthError::MissingAuthorizationParam)?;

        let entry = self
            .config
            .allow_list
            .iter()
            .find(|entry| entry.ip == source_ip_addr)
            .ok_or(AuthError::AccessDenied)?;

        Ok(entry.content.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! auth {
        () => {
            IpAuth::from_file("demo/ip_config.json")
        };
    }

    #[test]
    fn test_read_invalid_config() {
        assert_eq!(
            IpAuth::from_file("invalid.json").unwrap_err().to_string(),
            "invalid file: No such file or directory (os error 2)"
        );
        assert_eq!(
            IpAuth::from_file("README.md").unwrap_err().to_string(),
            "invalid config: expected value at line 1 column 1"
        );
    }

    #[test]
    fn test_read_valid_config() {
        assert!(auth!().is_ok());
    }

    macro_rules! req {
        ($ip:expr) => {
            AuthRequest {
                source_ip_addr: Some($ip.into()),
                ..Default::default()
            }
        };
    }

    #[tokio::test]
    async fn test_auth_validate() {
        let auth = auth!().unwrap();

        // Invalid
        assert_eq!(
            auth.validate(AuthRequest::default()).await,
            Err(AuthError::MissingAuthorizationParam)
        );
        assert_eq!(auth.validate(req!("")).await, Err(AuthError::AccessDenied));
        assert_eq!(
            auth.validate(req!("127.0.0.1")).await,
            Err(AuthError::AccessDenied)
        );

        // Valid
        assert_eq!(
            auth.validate(req!("192.168.1.158")).await,
            Ok(AuthContent {
                email: Some("foo@example.com".to_string()),
                roles: Some(vec!["User".to_string(), "Test".to_string()]),
                ..Default::default()
            })
        );
    }
}
