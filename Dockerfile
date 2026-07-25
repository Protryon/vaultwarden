# web-vault v2026.6.2 (at parity with upstream dani-garcia/vaultwarden).
# To resolve/refresh this digest:
#   docker pull docker.io/vaultwarden/web-vault:v2026.6.2
#   docker image inspect --format "{{.RepoDigests}}" docker.io/vaultwarden/web-vault:v2026.6.2
# NOTE: this client is newer than the API surface this fork fully implements. In particular
# the 2FA userVerificationToken setup flow (UPSTREAM.md T5/T6) and Duo Universal Prompt
# (T1/T2) are not yet ported, so verify 2FA enable/disable in the bundled UI before shipping.
FROM docker.io/vaultwarden/web-vault@sha256:f004f72a5d357b87483839500a517da3d1b4ea0a57b9731989d298cccea7d02a as vault

FROM lukemathwalker/cargo-chef:0.1.73-rust-1.91.1-slim-bookworm AS planner
WORKDIR /plan

COPY ./src ./src
COPY ./migrations ./migrations
COPY ./build.rs ./
COPY ./Cargo.lock .
COPY ./Cargo.toml .

RUN cargo chef prepare --recipe-path recipe.json

FROM lukemathwalker/cargo-chef:0.1.73-rust-1.91.1-bookworm AS builder

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

FROM debian:bookworm-slim
WORKDIR /runtime

COPY --from=builder /build/target/vaultwarden /runtime/vaultwarden
COPY --from=vault /web-vault /web-vault

RUN apt-get update && apt-get install libssl3 ca-certificates -y && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/runtime/vaultwarden"]