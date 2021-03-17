pub mod google {
    pub mod rpc {
        tonic::include_proto!("google.rpc");
    }
}

pub mod envoy {
    pub mod api {
        pub mod v2 {
            pub mod core {
                tonic::include_proto!("envoy.api.v2.core");
            }
        }
    }

    pub mod config {
        pub mod core {
            pub mod v3 {
                tonic::include_proto!("envoy.config.core.v3");
            }
        }
    }

    pub mod r#type {
        tonic::include_proto!("envoy.r#type");

        pub mod v3 {
            tonic::include_proto!("envoy.r#type.v3");
        }
    }

    pub mod service {
        pub mod auth {
            pub mod v2 {
                tonic::include_proto!("envoy.service.auth.v2");
            }

            pub mod v3 {
                tonic::include_proto!("envoy.service.auth.v3");
            }
        }
    }
}

pub mod xds {
    pub mod core {
        pub mod v3 {
            tonic::include_proto!("xds.core.v3");
        }
    }
}

mod auth;
mod checkers;
mod token_validation;

use std::sync::Arc;
use tonic::transport::Server;

use crate::envoy::service::auth::v2::authorization_server::AuthorizationServer as AuthorizationServerV2;
use crate::envoy::service::auth::v3::authorization_server::AuthorizationServer as AuthorizationServerV3;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let auth_service = Arc::new(auth::AuthenticationService::from_env().unwrap());

    let addr = "0.0.0.0:50051".parse()?;
    let auth_v2 = checkers::v2::AuthorizationV2::new(auth_service.clone());
    let auth_v3 = checkers::v3::AuthorizationV3::new(auth_service);

    log::info!("gRPC server will listen at: {:?}", addr);
    Server::builder()
        .add_service(AuthorizationServerV2::new(auth_v2))
        .add_service(AuthorizationServerV3::new(auth_v3))
        .serve(addr)
        .await?;

    Ok(())
}
