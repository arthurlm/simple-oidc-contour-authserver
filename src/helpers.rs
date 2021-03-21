use crate::authentication::*;

pub fn read_auth_param<'a>(
    expected_auth_type: &str,
    authorization: &'a str,
) -> Result<&'a str, AuthError> {
    let authorization_items: Vec<_> = authorization.trim_start().splitn(2, ' ').collect();

    match authorization_items[..] {
        [auth_type, auth_param]
            if auth_type.to_lowercase() == expected_auth_type.to_lowercase() =>
        {
            Ok(auth_param.trim_start())
        }
        [auth_type, _auth_param] => Err(AuthError::InvalidAuthorizationType {
            expected: expected_auth_type.into(),
            current: auth_type.into(),
        }),
        _ => Err(AuthError::MissingAuthorizationParam),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_empty() {
        assert_eq!(
            read_auth_param("Basic", ""),
            Err(AuthError::MissingAuthorizationParam)
        );
        assert_eq!(
            read_auth_param("Basic", "   "),
            Err(AuthError::MissingAuthorizationParam)
        );
    }

    #[test]
    fn test_auth_bad_type() {
        assert_eq!(
            read_auth_param("Basic", "Bearer XXXX"),
            Err(AuthError::InvalidAuthorizationType {
                expected: "Basic".into(),
                current: "Bearer".into(),
            })
        );
    }

    #[test]
    fn test_auth_valid() {
        assert_eq!(
            read_auth_param("Basic", "Basic    YYYY    "),
            Ok("YYYY    ")
        );
    }
}
