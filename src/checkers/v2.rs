use async_trait::async_trait;
use tonic::{Request, Response, Status};

use crate::envoy::api::v2::core::{HeaderValue, HeaderValueOption};
use crate::envoy::service::auth::v2::authorization_server::Authorization;
use crate::envoy::service::auth::v2::check_response::HttpResponse;
use crate::envoy::service::auth::v2::{CheckRequest, CheckResponse, OkHttpResponse};

pub fn build_http_header(key: &str, value: &str) -> HeaderValueOption {
    HeaderValueOption {
        header: Some(HeaderValue {
            key: key.into(),
            value: value.into(),
        }),
        ..Default::default()
    }
}

#[derive(Debug, Default)]
pub struct AuthorizationV2 {}

#[async_trait]
impl Authorization for AuthorizationV2 {
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        log::info!("Processing v2 request: {:?}", request);

        Ok(Response::new(CheckResponse {
            http_response: Some(HttpResponse::OkResponse(OkHttpResponse {
                headers: vec![build_http_header("X-USER", "Arthur")],
            })),
            ..Default::default()
        }))
    }
}