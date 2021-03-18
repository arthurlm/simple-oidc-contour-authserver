use crate::token_validation::*;

pub fn read_auth_param<'a>(
    expected_auth_type: &str,
    authorization: &'a str,
) -> Result<&'a str, TokenError> {
    let authorization_items: Vec<_> = authorization.trim_start().splitn(2, " ").collect();

    if let [auth_type, auth_param] = authorization_items[..] {
        if auth_type.to_lowercase() != expected_auth_type.to_lowercase() {
            return Err(TokenError::InvalidAuthenticationType);
        }
        return Ok(auth_param.trim_start());
    }

    return Err(TokenError::MissingAuthenticationParam);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_empty() {
        assert_eq!(
            read_auth_param("Basic", ""),
            Err(TokenError::MissingAuthenticationParam)
        );
        assert_eq!(
            read_auth_param("Basic", "   "),
            Err(TokenError::MissingAuthenticationParam)
        );
    }

    #[test]
    fn test_auth_bad_type() {
        assert_eq!(
            read_auth_param("Basic", "Bearer XXXX"),
            Err(TokenError::InvalidAuthenticationType)
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
