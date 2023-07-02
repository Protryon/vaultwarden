FROM lukemathwalker/cargo-chef:0.1.61-rust-1.70-slim-buster AS planner
WORKDIR /plan

COPY ./src ./src
COPY ./migrations ./migrations
COPY ./build.rs ./
COPY ./Cargo.lock .
COPY ./Cargo.toml .

RUN cargo chef prepare --recipe-path recipe.json

FROM lukemathwalker/cargo-chef:0.1.61-rust-1.70-buster AS builder

WORKDIR /build
RUN apt-get update && apt-get install cmake -y

COPY --from=planner /plan/recipe.json recipe.json

RUN cargo chef cook --release --recipe-path recipe.json -p vaultwarden

COPY ./src ./src
COPY ./migrations ./migrations
COPY ./build.rs ./
COPY ./Cargo.lock .
COPY ./Cargo.toml .

RUN cargo build --release -p vaultwarden && mv /build/target/release/vaultwarden /build/target/vaultwarden

FROM debian:buster-slim
WORKDIR /runtime

COPY --from=builder /build/target/vaultwarden /runtime/vaultwarden

RUN apt-get update && apt-get install libssl1.1 ca-certificates -y && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/runtime/vaultwarden"]