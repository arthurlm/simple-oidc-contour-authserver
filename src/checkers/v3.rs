use async_trait::async_trait;
use std::sync::Arc;
use tonic::{Request, Response, Status};

use crate::envoy::config::core::v3::{address::Address, HeaderValue, HeaderValueOption};
use crate::envoy::r#type::v3::HttpStatus;
use crate::envoy::service::auth::v3::authorization_server::Authorization;
use crate::envoy::service::auth::v3::check_response::HttpResponse;
use crate::envoy::service::auth::v3::{
    CheckRequest, CheckResponse, DeniedHttpResponse, OkHttpResponse,
};
use crate::google::rpc;

use crate::authentication::*;

fn build_http_header(key: &str, value: &str) -> HeaderValueOption {
    (key.to_string(), Some(value.to_string())).into()
}

impl From<AuthItem> for HeaderValueOption {
    fn from(header_value: AuthItem) -> Self {
        let (key, value) = header_value;
        let value = value.unwrap_or_else(|| "".into());
        Self {
            header: Some(HeaderValue { key, value }),
            ..Default::default()
        }
    }
}

fn extract_http_headers_authorization(check_request: &CheckRequest) -> Option<String> {
    let attributes = check_request.attributes.as_ref()?;
    let request = attributes.request.as_ref()?;
    let req_http = request.http.as_ref()?;
    req_http
        .headers
        .get(http::header::AUTHORIZATION.as_str())
        .cloned()
}

fn extract_source_ip_addr(check_request: &CheckRequest) -> Option<String> {
    let attributes = check_request.attributes.as_ref()?;
    let source = attributes.source.as_ref()?;
    let address = source.address.as_ref()?;
    let core_address = address.address.as_ref()?;
    match core_address {
        Address::SocketAddress(sock) => Some(sock.address.clone()),
        _ => None,
    }
}

async fn process_request<T>(
    validator: &Arc<T>,
    check_request: CheckRequest,
) -> Result<AuthContent, AuthError>
where
    T: AuthValidator,
{
    let request = AuthRequest {
        authorization: extract_http_headers_authorization(&check_request),
        source_ip_addr: extract_source_ip_addr(&check_request),
    };

    validator.validate(request).await
}

#[derive(Debug)]
pub struct AuthorizationV3<T> {
    validator: Arc<T>,
}

impl<T> AuthorizationV3<T> {
    pub fn new(validator: Arc<T>) -> Self {
        Self { validator }
    }
}

#[async_trait]
impl<T> Authorization for AuthorizationV3<T>
where
    T: AuthValidator + Send + Sync + 'static,
{
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        log::debug!("Processing v3 request: {:?}", request);

        let response = process_request(&self.validator, request.into_inner()).await;
        log::info!("Auth v3 response: {:?}", response);

        Ok(Response::new(match response {
            Ok(user_data) => CheckResponse {
                http_response: Some(HttpResponse::OkResponse(OkHttpResponse {
                    headers: user_data
                        .into_header_vec()
                        .into_iter()
                        .map(|x| x.into())
                        .collect(),
                    headers_to_remove: vec![http::header::AUTHORIZATION.as_str().to_string()],
                    ..Default::default()
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
                        T::AUTHENTICATION_SCHEME,
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
