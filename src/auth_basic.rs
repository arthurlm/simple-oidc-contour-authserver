use async_trait::async_trait;
use base64::Engine;
use thiserror::Error;

use crate::authentication::*;
use crate::helpers::read_auth_param;

pub struct BasicAuth {
    // TODO: improve this using Htpasswd instead of its
    // config. For now I have issue with 'static lifetime
    // so doing this hack to make it works
    htpasswd_config: String,
}

impl BasicAuth {
    pub fn new(data: &str) -> Self {
        log::info!("Loading htpasswd");
        Self {
            htpasswd_config: data.into(),
        }
    }
}

struct AuthInfo {
    username: String,
    password: String,
}

#[derive(Debug, PartialEq, Error)]
enum BasicAuthError {
    #[error("bad auth payload")]
    BadPayload(#[from] base64::DecodeError),

    #[error("invalid char")]
    InvalidChar(#[from] std::string::FromUtf8Error),

    #[error("missing auth elements")]
    MissingAuthElements,
}

impl From<BasicAuthError> for AuthError {
    fn from(error: BasicAuthError) -> Self {
        Self::PayloadValidationFail {
            reason: format!("{}", error),
        }
    }
}

fn payload_to_user_pass(payload_bin: &str) -> Result<AuthInfo, BasicAuthError> {
    let payload_str =
        String::from_utf8(base64::engine::general_purpose::STANDARD.decode(payload_bin)?)?;

    let items: Vec<_> = payload_str.splitn(2, ':').collect();

    match items[..] {
        [username, password] => Ok(AuthInfo {
            username: username.into(),
            password: password.into(),
        }),
        _ => Err(BasicAuthError::MissingAuthElements),
    }
}

#[async_trait]
impl AuthValidator for BasicAuth {
    const AUTHENTICATION_SCHEME: &'static str = "Basic";

    async fn validate(&self, request: AuthRequest) -> Result<AuthContent, AuthError> {
        let authorization = request
            .authorization
            .ok_or(AuthError::MissingAuthorizationHeader)?;
        let payload = read_auth_param(Self::AUTHENTICATION_SCHEME, &authorization)?;
        let auth_info = payload_to_user_pass(payload)?;

        let htpasswd = htpasswd_verify::Htpasswd::new_borrowed(&self.htpasswd_config);
        if htpasswd.check(&auth_info.username, &auth_info.password) {
            Ok(AuthContent {
                sub: Some(auth_info.username),
                ..Default::default()
            })
        } else {
            Err(AuthError::AccessDenied)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! auth {
        () => {
            BasicAuth::new(
                r#"arthurlm:$apr1$Ric4YLNa$LqMiMreIwpMEfAnHwRXDm1
                   jbond:$apr1$5MRZMXUI$/jRU5NmdzGaIlB2fWm/mz.
                   "#,
            )
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
    async fn test_invalid_scheme() {
        let auth = auth!();

        assert_eq!(
            auth.validate(AuthRequest::default()).await,
            Err(AuthError::MissingAuthorizationHeader)
        );
        assert_eq!(
            auth.validate(auth_req!("")).await,
            Err(AuthError::MissingAuthorizationParam)
        );
        assert_eq!(
            auth.validate(auth_req!("toto")).await,
            Err(AuthError::MissingAuthorizationParam)
        );
        assert_eq!(
            auth.validate(auth_req!("bearer 123456")).await,
            Err(AuthError::InvalidAuthorizationType {
                expected: "Basic".into(),
                current: "bearer".into(),
            })
        );
    }

    macro_rules! basic_auth_err {
        ($error:expr) => {
            Err(AuthError::PayloadValidationFail {
                reason: format!("{}", $error),
            })
        };
    }

    #[tokio::test]
    async fn test_invalid_payload() {
        let auth = auth!();

        assert_eq!(
            auth.validate(auth_req!("Basic ❤")).await,
            basic_auth_err!("bad auth payload"),
        );
        assert_eq!(
            auth.validate(auth_req!("Basic XXXX")).await,
            basic_auth_err!("invalid char"),
        );
        assert_eq!(
            auth.validate(auth_req!("Basic YXJ0aHVybG0=")).await,
            basic_auth_err!(BasicAuthError::MissingAuthElements),
        );
    }

    #[tokio::test]
    async fn test_access_denied() {
        let auth = auth!();

        assert_eq!(
            auth.validate(auth_req!("Basic YXJ0aHVybG06")).await,
            Err(AuthError::AccessDenied)
        );
        assert_eq!(
            auth.validate(auth_req!("Basic YXJ0aHVybG06dGVzdDEyMzQ="))
                .await,
            Err(AuthError::AccessDenied)
        );
    }

    #[tokio::test]
    async fn test_access_granted() {
        let auth = auth!();

        assert_eq!(
            auth.validate(auth_req!("Basic YXJ0aHVybG06dG9wc2VjcmV0"))
                .await,
            Ok(AuthContent {
                sub: Some("arthurlm".to_string()),
                ..Default::default()
            })
        );
    }
}
