use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tonic::{Request, Response, Status};

use crate::envoy::api::v2::core::{HeaderValue, HeaderValueOption};
use crate::envoy::r#type::HttpStatus;
use crate::envoy::service::auth::v2::authorization_server::Authorization;
use crate::envoy::service::auth::v2::check_response::HttpResponse;
use crate::envoy::service::auth::v2::{
    CheckRequest, CheckResponse, DeniedHttpResponse, OkHttpResponse,
};
use crate::google::rpc;

use crate::authentication::*;

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
) -> Result<AuthContent, AuthError>
where
    T: AuthValidator + Send + Sync + 'static,
{
    let headers = extract_http_headers(check_request).ok_or(AuthError::MissingHttpAttribute)?;
    let authorization = headers
        .get(http::header::AUTHORIZATION.as_str())
        .ok_or(AuthError::MissingAuthorizationHeader)?;

    validator.validate(authorization).await
}

#[derive(Debug)]
pub struct AuthorizationV2<T>
where
    T: AuthValidator + Send + Sync + 'static,
{
    validator: Arc<T>,
}

impl<T> AuthorizationV2<T>
where
    T: AuthValidator + Send + Sync + 'static,
{
    pub fn new(validator: Arc<T>) -> Self {
        Self { validator }
    }
}

#[async_trait]
impl<T> Authorization for AuthorizationV2<T>
where
    T: AuthValidator + Send + Sync + 'static,
{
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        log::debug!("Processing v2 request: {:?}", request);

        let response = process_request(&self.validator, request.into_inner()).await;
        log::info!("Auth v2 response: {:?}", response);

        Ok(Response::new(match response {
            Ok(user_data) => CheckResponse {
                http_response: Some(HttpResponse::OkResponse(OkHttpResponse {
                    headers: vec![
                        build_http_header("Auth-Sub", &user_data.sub.unwrap_or("".into())),
                        build_http_header("Auth-Email", &user_data.email.unwrap_or("".into())),
                        build_http_header("Auth-Name", &user_data.name.unwrap_or("".into())),
                    ],
                })),
                ..Default::default()
            },
            Err(e) => CheckResponse {
                http_response: Some(HttpResponse::DeniedResponse(DeniedHttpResponse {
                    status: Some(HttpStatus {
                        code: http::status::StatusCode::UNAUTHORIZED.as_u16() as i32,
                    }),
                    headers: vec![build_http_header(
                        http::header::WWW_AUTHENTICATE.as_str(),
                        "Bearer",
                    )],
                    body: format!("Error: {}", e),
                })),
                status: Some(rpc::Status {
                    code: rpc::Code::Unauthenticated as i32,
                    message: format!("Error: {}", e),
                    details: vec![],
                }),
                ..Default::default()
            },
        }))
    }
}
