# syntax=docker/dockerfile:1.7

FROM rust:1-bookworm AS chef
WORKDIR /app
RUN cargo install cargo-chef --locked

FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY webui ./webui
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json

# Keep release builds within lower memory limits by reducing parallel codegen.
ARG CARGO_BUILD_JOBS=2
ARG CARGO_PROFILE=release

RUN CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS}" cargo chef cook --release --locked --features s3

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY webui ./webui

RUN if [ "${CARGO_PROFILE}" = "release" ]; then \
      cargo build --release --locked --features s3 -j "${CARGO_BUILD_JOBS}" && \
      cp target/release/rustaccio /tmp/rustaccio-bin; \
    else \
      cargo build --profile "${CARGO_PROFILE}" --locked --features s3 -j "${CARGO_BUILD_JOBS}" && \
      cp "target/${CARGO_PROFILE}/rustaccio" /tmp/rustaccio-bin; \
    fi

RUN mkdir -p /tmp/rustaccio-root/data

FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

WORKDIR /var/lib/rustaccio

COPY --from=builder --chown=65532:65532 /tmp/rustaccio-root/ /var/lib/rustaccio/
COPY --from=builder /tmp/rustaccio-bin /usr/local/bin/rustaccio
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENV RUSTACCIO_BIND=0.0.0.0:4873
ENV RUSTACCIO_DATA_DIR=/var/lib/rustaccio/data

EXPOSE 4873
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/rustaccio"]
