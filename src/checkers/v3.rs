use async_trait::async_trait;
use std::sync::Arc;
use tonic::{Request, Response, Status};

use crate::envoy::config::core::v3::{HeaderValue, HeaderValueOption};
use crate::envoy::service::auth::v3::authorization_server::Authorization;
use crate::envoy::service::auth::v3::check_response::HttpResponse;
use crate::envoy::service::auth::v3::{CheckRequest, CheckResponse, OkHttpResponse};

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
        log::info!("Processing v3 request: {:?}", request);

        Ok(Response::new(CheckResponse {
            http_response: Some(HttpResponse::OkResponse(OkHttpResponse {
                headers: vec![build_http_header("X-USER", "Arthur")],
                headers_to_remove: vec!["Authorization".to_string()],
                ..Default::default()
            })),
            ..Default::default()
        }))
    }
}
