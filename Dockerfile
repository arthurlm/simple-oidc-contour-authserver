FROM rust:1.51 AS builder
WORKDIR /usr/src/app
RUN rustup component add rustfmt
COPY . .
RUN git submodule update --init --recursive
RUN cargo install --locked --path .

FROM ubuntu:20.04
RUN apt update && apt install -y libssl1.1 ca-certificates && update-ca-certificates
COPY --from=builder /usr/local/cargo/bin/simple-oidc-contour-authserver /usr/local/bin/simple-oidc-contour-authserver
ENTRYPOINT ["simple-oidc-contour-authserver", "bearer"]
