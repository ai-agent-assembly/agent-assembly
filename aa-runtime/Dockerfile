# syntax=docker/dockerfile:1.7

# cargo-chef + BuildKit cache mounts let us reuse the dependency build
# layer across PRs as long as Cargo.lock is unchanged, and persist the
# cargo registry / git / target directories across builds.

FROM rust:alpine AS chef
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo install cargo-chef --locked
WORKDIR /app

# Planner: emit recipe.json describing the dependency graph. This layer's
# output only changes when Cargo.toml / Cargo.lock change.
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json --bin aa-runtime

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
    --mount=type=cache,target=/app/target,id=aa-runtime-target-${TARGETARCH} \
    TARGET=$(cat /tmp/rust_target) && \
    cargo chef cook --release --target "$TARGET" --recipe-path recipe.json --bin aa-runtime

COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target,id=aa-runtime-target-${TARGETARCH} \
    TARGET=$(cat /tmp/rust_target) && \
    cargo build --release --target "$TARGET" -p aa-runtime && \
    strip "target/$TARGET/release/aa-runtime" && \
    cp "target/$TARGET/release/aa-runtime" /app/aa-runtime

# Final stage: minimal distroless image running as non-root.
FROM gcr.io/distroless/static:nonroot AS runtime

COPY --from=builder /app/aa-runtime /aa-runtime

LABEL org.opencontainers.image.source="https://github.com/AI-agent-assembly/agent-assembly" \
      org.opencontainers.image.description="aa-runtime sidecar — AI agent assembly runtime" \
      org.opencontainers.image.licenses="Apache-2.0"

ENTRYPOINT ["/aa-runtime"]
