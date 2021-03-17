FROM rust:1.50 AS builder
WORKDIR /usr/src/app
RUN rustup component add rustfmt
COPY . .
RUN git submodule update --init --recursive
RUN cargo install --path .

FROM ubuntu:20.04
RUN apt update && apt install -y libssl1.1
COPY --from=builder /usr/local/cargo/bin/simple-oidc-contour-authserver /usr/local/bin/simple-oidc-contour-authserver
CMD ["simple-oidc-contour-authserver"]

