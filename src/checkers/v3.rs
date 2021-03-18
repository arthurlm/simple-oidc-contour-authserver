use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tonic::{Request, Response, Status};

use crate::envoy::config::core::v3::{HeaderValue, HeaderValueOption};
use crate::envoy::r#type::v3::HttpStatus;
use crate::envoy::service::auth::v3::authorization_server::Authorization;
use crate::envoy::service::auth::v3::check_response::HttpResponse;
use crate::envoy::service::auth::v3::{
    CheckRequest, CheckResponse, DeniedHttpResponse, OkHttpResponse,
};

use crate::token_validation::*;

pub fn build_http_header(key: &str, value: &str) -> HeaderValueOption {
    HeaderValueOption {
        header: Some(HeaderValue {
            key: key.into(),
            value: value.into(),
        }),
        ..Default::default()
    }
}

fn extract_http_headers(check_request: CheckRequest) -> Option<HashMap<String, String>> {
    let attributes = check_request.attributes?;
    let request = attributes.request?;
    let req_http = request.http?;
    Some(req_http.headers)
}

async fn process_request<T>(
    validator: &Arc<T>,
    check_request: CheckRequest,
) -> Result<TokenContent, TokenError>
where
    T: TokenValidator + Send + Sync + 'static,
{
    let headers = extract_http_headers(check_request).ok_or(TokenError::MissingHttpAttribute)?;
    let authorization = headers
        .get(http::header::AUTHORIZATION.as_str())
        .ok_or(TokenError::MissingAuthorizationHeader)?;

    validator.validate(authorization).await
}

#[derive(Debug)]
pub struct AuthorizationV3<T>
where
    T: TokenValidator + Send + Sync + 'static,
{
    validator: Arc<T>,
}

impl<T> AuthorizationV3<T>
where
    T: TokenValidator + Send + Sync + 'static,
{
    pub fn new(validator: Arc<T>) -> Self {
        Self { validator }
    }
}

#[async_trait]
impl<T> Authorization for AuthorizationV3<T>
where
    T: TokenValidator + Send + Sync + 'static,
{
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        log::debug!("Processing v3 request: {:?}", request);

        let http_response = match process_request(&self.validator, request.into_inner()).await {
            Ok(user_data) => HttpResponse::OkResponse(OkHttpResponse {
                headers: vec![build_http_header("Auth-Username", &user_data.sub)],
                headers_to_remove: vec![http::header::AUTHORIZATION.as_str().to_string()],
                ..Default::default()
            }),
            Err(e) => HttpResponse::DeniedResponse(DeniedHttpResponse {
                status: Some(HttpStatus {
                    code: http::status::StatusCode::UNAUTHORIZED.as_u16() as i32,
                }),
                headers: vec![build_http_header(
                    http::header::WWW_AUTHENTICATE.as_str(),
                    "Bearer",
                )],
                body: format!("Error: {}", e),
            }),
        };

        log::debug!("Auth v3 response: {:?}", http_response);

        Ok(Response::new(CheckResponse {
            http_response: Some(http_response),
            ..Default::default()
        }))
    }
}
