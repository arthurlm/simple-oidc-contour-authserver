use async_trait::async_trait;
use tonic::{Request, Response, Status};

use crate::envoy::service::auth::v2::authorization_server::Authorization;
use crate::envoy::service::auth::v2::{CheckRequest, CheckResponse};

#[derive(Debug, Default)]
pub struct AuthorizationV2 {}

#[async_trait]
impl Authorization for AuthorizationV2 {
    async fn check(
        &self,
        _request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        unimplemented!();
    }
}
