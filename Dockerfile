FROM rust:1.72 AS builder
WORKDIR /usr/src/app
RUN rustup component add rustfmt
RUN apt-get update && \
    apt-get install -y protobuf-compiler
COPY . .
RUN git submodule update --init --recursive
RUN cargo install --locked --path .

FROM ubuntu:22.04
RUN apt-get update && \
    apt-get install -y ca-certificates && update-ca-certificates
COPY --from=builder /usr/local/cargo/bin/simple-oidc-contour-authserver /usr/local/bin/simple-oidc-contour-authserver
ENTRYPOINT ["simple-oidc-contour-authserver", "bearer"]
