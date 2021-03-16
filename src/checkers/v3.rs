use async_trait::async_trait;
use tonic::{Request, Response, Status};

use crate::envoy::service::auth::v3::authorization_server::Authorization;
use crate::envoy::service::auth::v3::{CheckRequest, CheckResponse};

#[derive(Debug, Default)]
pub struct AuthorizationV3 {}

#[async_trait]
impl Authorization for AuthorizationV3 {
    async fn check(
        &self,
        _request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        unimplemented!();
    }
}
