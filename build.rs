fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_client(false)
        .build_server(true)
        .compile(
            &[
                "proto/envoy/api/envoy/service/auth/v2/external_auth.proto",
                "proto/envoy/api/envoy/service/auth/v3/external_auth.proto",
            ],
            &[
                "proto/envoy/api",
                "proto/googleapis",
                "proto/udpa",
                "proto/protoc-gen-validate",
            ],
        )?;
    Ok(())
}
