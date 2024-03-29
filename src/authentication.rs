use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashSet;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum AuthError {
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

#[derive(Debug, Clone, Deserialize, PartialEq, Default)]
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

    pub fn is_authorized(&self, auth_constraint: &AuthConstraint) -> Result<(), AuthError> {
        if let Some(required_role) = &auth_constraint.required_role {
            let roles = self.roles.as_ref().ok_or(AuthError::AccessDenied)?;

            if !roles.contains(required_role) {
                return Err(AuthError::AccessDenied);
            };
        }

        if let Some(roles_constraint) = &auth_constraint.roles_constraint {
            let user_roles: HashSet<String> = self
                .roles
                .clone()
                .ok_or(AuthError::AccessDenied)?
                .into_iter()
                .collect();

            let allowed = roles_constraint.allowed();
            let forbidden = roles_constraint.forbidden();

            // Check for forbidden
            if !(&user_roles & &forbidden).is_empty() {
                return Err(AuthError::AccessDenied);
            }

            // Check for allowed
            if !allowed.is_empty() && (&user_roles & &allowed).is_empty() {
                return Err(AuthError::AccessDenied);
            }
        }

        Ok(())
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct AuthRolesConstraint {
    /// User need to have any of this roles
    allowed: Vec<String>,

    /// If user has one of this roles, then it is rejected
    forbidden: Vec<String>,
}

impl AuthRolesConstraint {
    pub fn allowed(&self) -> HashSet<String> {
        self.allowed.clone().into_iter().collect()
    }

    pub fn forbidden(&self) -> HashSet<String> {
        self.forbidden.clone().into_iter().collect()
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct AuthConstraint {
    /// Role user need to have
    #[serde(default)]
    pub required_role: Option<String>,

    /// Advanced roles configuration
    #[serde(default)]
    pub roles_constraint: Option<AuthRolesConstraint>,
}

/// Represent standardized information about user request.
///
/// It is a common structure between request V2 and V3.
#[derive(Debug, Default)]
pub struct AuthRequest {
    pub authorization: Option<String>,
    pub source_ip_addr: Option<String>,
}

#[async_trait]
pub trait AuthValidator {
    const AUTHENTICATION_SCHEME: &'static str;

    async fn validate(&self, request: AuthRequest) -> Result<AuthContent, AuthError>;
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

    fn auth_content(roles: &[&str]) -> AuthContent {
        AuthContent {
            roles: Some(roles.iter().map(|x| x.to_string()).collect()),
            ..Default::default()
        }
    }

    #[test]
    fn test_auth_no_requirement() {
        let constraint = AuthConstraint {
            required_role: None,
            roles_constraint: None,
        };

        let content = AuthContent::default();
        assert_eq!(content.is_authorized(&constraint), Ok(()));

        let content = auth_content(&["r1", "r2"]);
        assert_eq!(content.is_authorized(&constraint), Ok(()));
    }

    #[test]
    fn test_auth_role_required() {
        let constraint = AuthConstraint {
            required_role: Some("r1".to_string()),
            roles_constraint: None,
        };

        // No roles
        let content = AuthContent::default();
        assert_eq!(
            content.is_authorized(&constraint),
            Err(AuthError::AccessDenied)
        );

        // Bad roles
        let content = auth_content(&["r2"]);
        assert_eq!(
            content.is_authorized(&constraint),
            Err(AuthError::AccessDenied)
        );

        // Good roles
        let content = auth_content(&["r1", "r2"]);
        assert_eq!(content.is_authorized(&constraint), Ok(()));
    }

    fn advanced_config(allowed: &[&str], forbidden: &[&str]) -> AuthConstraint {
        AuthConstraint {
            required_role: None,
            roles_constraint: Some(AuthRolesConstraint {
                allowed: allowed.iter().map(|x| x.to_string()).collect(),
                forbidden: forbidden.iter().map(|x| x.to_string()).collect(),
            }),
        }
    }

    macro_rules! assert_allowed {
        ($r:expr) => {
            assert_eq!($r, Ok(()))
        };
    }

    macro_rules! assert_deny {
        ($r:expr) => {
            assert_eq!($r, Err(AuthError::AccessDenied))
        };
    }

    #[test]
    fn test_auth_advanced_config() {
        // No info + no constraint
        let empty_config = advanced_config(&[], &[]);
        assert_allowed!(auth_content(&[]).is_authorized(&empty_config));
        assert_allowed!(auth_content(&["a1"]).is_authorized(&empty_config));

        // Check for allowed config
        let config = advanced_config(&["a1", "a3"], &[]);
        assert_deny!(auth_content(&[]).is_authorized(&config));
        assert_deny!(auth_content(&["a2"]).is_authorized(&config));

        assert_allowed!(auth_content(&["a1", "a2"]).is_authorized(&config));
        assert_allowed!(auth_content(&["a2", "a3"]).is_authorized(&config));

        // Check for forbidden config
        let config = advanced_config(&[], &["f1", "f3"]);
        assert_allowed!(auth_content(&[]).is_authorized(&config));
        assert_allowed!(auth_content(&["f2"]).is_authorized(&config));

        assert_deny!(auth_content(&["f1", "f2"]).is_authorized(&config));
        assert_deny!(auth_content(&["f2", "f3"]).is_authorized(&config));

        // Check for mixed config
        let config = advanced_config(&["a1", "a3"], &["f1", "f3"]);
        assert_allowed!(auth_content(&["a1", "f2"]).is_authorized(&config));

        assert_deny!(auth_content(&["a1", "f1"]).is_authorized(&config)); // Has forbidden
        assert_deny!(auth_content(&["a2", "f2"]).is_authorized(&config)); // Missing allowed
    }
}
