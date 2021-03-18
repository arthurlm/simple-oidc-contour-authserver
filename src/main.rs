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
mod helpers;
mod token_validation;

use clap::Clap;
use futures::try_join;
use std::sync::Arc;
use tonic::transport::{Identity, Server, ServerTlsConfig};

use crate::envoy::service::auth::v2::authorization_server::AuthorizationServer as AuthorizationServerV2;
use crate::envoy::service::auth::v3::authorization_server::AuthorizationServer as AuthorizationServerV3;

#[derive(Clap)]
#[clap(version = "1.0", author = "Arthur LE MOIGNE. <me@alemoigne.com>")]
struct Opts {
    /// Addr to bind on
    #[clap(short, long, default_value = "0.0.0.0:50051")]
    addr: String,

    /// TLS key file to read
    #[clap(long, default_value = "tls.key")]
    tls_key: String,

    /// TLS cert file to read
    #[clap(long, default_value = "tls.crt")]
    tls_cert: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Parse CLI
    let opts = Opts::parse();
    let addr = opts.addr.parse()?;

    // Read TLS data
    let (cert, key) = try_join!(
        tokio::fs::read(opts.tls_cert),
        tokio::fs::read(opts.tls_key)
    )?;

    let identity = Identity::from_pem(cert, key);

    // Create auth services
    let auth_service = Arc::new(auth::AuthenticationService::from_env()?);
    let _ = auth_service.refresh_token().await;

    let auth_v2 = checkers::v2::AuthorizationV2::new(auth_service.clone());
    let auth_v3 = checkers::v3::AuthorizationV3::new(auth_service);

    log::info!("gRPC server will listen at: {:?}", addr);
    Server::builder()
        .tls_config(ServerTlsConfig::new().identity(identity))?
        .add_service(AuthorizationServerV2::new(auth_v2))
        .add_service(AuthorizationServerV3::new(auth_v3))
        .serve(addr)
        .await?;

    Ok(())
}
