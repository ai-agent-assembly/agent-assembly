# syntax=docker/dockerfile:1.7

# AAASM-4480: container image for the aa-gateway daemon (the policy/registry
# "brain"). Published to ghcr.io/ai-agent-assembly/aa-gateway so the
# `live-core-enforcement` docker-compose scenario (and the AAASM-4475 live CI
# lane) can pull it. Structure mirrors aa-runtime/Dockerfile — cargo-chef +
# BuildKit cache mounts reuse the dependency build layer across PRs as long as
# Cargo.lock is unchanged, and persist the cargo registry / git / target dirs.

FROM rust:alpine AS chef
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo install cargo-chef --locked
WORKDIR /app

# Planner: emit recipe.json describing the dependency graph. This layer's
# output only changes when Cargo.toml / Cargo.lock change.
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json --bin aa-gateway

# Builder: install system deps, pick the musl target for TARGETARCH,
# cook (compile) dependencies from recipe.json, then compile app code.
# The cook step is layer-cached on Cargo.lock; the final cargo build only
# rebuilds workspace crates.
FROM chef AS builder
RUN apk add --no-cache \
    musl-dev \
    protobuf-dev \
    openssl-dev \
    pkgconfig

ARG TARGETARCH
RUN case "$TARGETARCH" in \
      amd64) TARGET=x86_64-unknown-linux-musl ;; \
      arm64) TARGET=aarch64-unknown-linux-musl ;; \
      *) echo "Unsupported arch: $TARGETARCH" && exit 1 ;; \
    esac && \
    rustup target add "$TARGET" && \
    echo "$TARGET" > /tmp/rust_target

COPY --from=planner /app/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target,id=aa-gateway-target-${TARGETARCH} \
    TARGET=$(cat /tmp/rust_target) && \
    cargo chef cook --release --target "$TARGET" --recipe-path recipe.json --bin aa-gateway

COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target,id=aa-gateway-target-${TARGETARCH} \
    TARGET=$(cat /tmp/rust_target) && \
    cargo build --release --target "$TARGET" -p aa-gateway && \
    strip "target/$TARGET/release/aa-gateway" && \
    cp "target/$TARGET/release/aa-gateway" /aa-gateway-bin

# Final stage: minimal distroless image running as non-root.
FROM gcr.io/distroless/static:nonroot AS runtime

COPY --from=builder /aa-gateway-bin /aa-gateway

LABEL org.opencontainers.image.source="https://github.com/ai-agent-assembly/agent-assembly" \
      org.opencontainers.image.description="aa-gateway daemon — AI agent assembly policy/registry gateway" \
      org.opencontainers.image.licenses="Apache-2.0"

ENTRYPOINT ["/aa-gateway"]
