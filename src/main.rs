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

mod auth_basic;
mod auth_bearer;
mod auth_ip;
mod authentication;
mod checkers {
    pub mod v2;
    pub mod v3;
}
mod helpers;

use regex::Regex;
use std::{fs, sync::Arc, time::Duration};
use structopt::StructOpt;
use tokio::try_join;
use tonic::transport::{Identity, Server, ServerTlsConfig};

use crate::{
    authentication::AuthValidator,
    envoy::service::auth::{
        v2::authorization_server::AuthorizationServer as AuthorizationServerV2,
        v3::authorization_server::AuthorizationServer as AuthorizationServerV3,
    },
};

static INTERVAL_KEEPALIVE_HTTP2: Duration = Duration::from_secs(60);
static INTERVAL_KEEPALIVE_TCP: Duration = Duration::from_secs(60);

#[derive(Debug, StructOpt)]
#[structopt(version = "1.0", author = "Arthur LE MOIGNE. <me@alemoigne.com>")]
struct Opts {
    /// Addr to bind on
    #[structopt(short, long, default_value = "0.0.0.0:50051")]
    addr: String,

    /// TLS key file to read
    #[structopt(long, default_value = "tls.key")]
    tls_key: String,

    /// TLS cert file to read
    #[structopt(long, default_value = "tls.crt")]
    tls_cert: String,

    /// Max number of concurrent requests per connection
    #[structopt(long, default_value = "32")]
    concurrency_limit_per_connection: usize,

    /// Auth type to use
    #[structopt(subcommand)]
    auth_type: AuthType,

    /// Regexp to ignore request checking based on URL path.
    #[structopt(long)]
    ignore_path_regexp: Option<String>,
}

impl Opts {
    fn ignore_path_regexp(&self) -> Option<Regex> {
        self.ignore_path_regexp.as_ref().and_then(|input| {
            let output = Regex::new(input);
            if output.is_err() {
                log::warn!("Fail to compile ignore path regex: {output:?}");
            }
            output.ok()
        })
    }
}

#[derive(Debug, StructOpt)]
enum AuthType {
    /// Bearer JWT auth type
    Bearer,

    /// Basic auth type
    Basic(BasicParam),

    /// Ip allow list
    IpAllowList(IpAllowListParam),
}

#[derive(Debug, StructOpt)]
struct BasicParam {
    /// Filename to read htpasswd data from
    filename: String,
}

#[derive(Debug, StructOpt)]
struct IpAllowListParam {
    /// Filename to read config from
    filename: String,
}

async fn run_server<T>(opts: Opts, svc: T) -> anyhow::Result<()>
where
    T: AuthValidator + Send + Sync + 'static,
{
    // Parse CLI addr
    let addr = opts.addr.parse()?;
    let regexp = opts.ignore_path_regexp();

    // Read TLS data
    let (cert, key) = try_join!(
        tokio::fs::read(opts.tls_cert),
        tokio::fs::read(opts.tls_key)
    )?;

    let identity = Identity::from_pem(cert, key);

    // Init gRPC impl
    let svc = Arc::new(svc);
    let auth_v2 = checkers::v2::AuthorizationV2::new(svc.clone(), regexp.clone());
    let auth_v3 = checkers::v3::AuthorizationV3::new(svc, regexp);

    log::info!("gRPC server will listen at: {:?}", addr);
    Server::builder()
        .tls_config(ServerTlsConfig::new().identity(identity))?
        .concurrency_limit_per_connection(opts.concurrency_limit_per_connection)
        .http2_keepalive_interval(Some(INTERVAL_KEEPALIVE_HTTP2))
        .tcp_keepalive(Some(INTERVAL_KEEPALIVE_TCP))
        .add_service(AuthorizationServerV2::new(auth_v2))
        .add_service(AuthorizationServerV3::new(auth_v3))
        .serve(addr)
        .await?;

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let opts = Opts::from_args();

    match &opts.auth_type {
        AuthType::Bearer => {
            let bearer_service = auth_bearer::BearerAuth::from_env()?;
            let _ = bearer_service.refresh_token().await;

            run_server(opts, bearer_service).await
        }
        AuthType::Basic(param) => {
            let data = fs::read_to_string(&param.filename)?;
            let basic_svc = auth_basic::BasicAuth::new(&data);

            run_server(opts, basic_svc).await
        }
        AuthType::IpAllowList(param) => {
            let svc = auth_ip::IpAuth::from_file(&param.filename)?;

            run_server(opts, svc).await
        }
    }
}
