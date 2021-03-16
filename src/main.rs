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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    Ok(())
}
