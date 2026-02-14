# syntax=docker/dockerfile:1.7

FROM rust:1-bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY webui ./webui

# Keep release builds within lower memory limits by reducing parallel codegen.
ARG CARGO_BUILD_JOBS=2

RUN cargo build --release --locked --features s3 -j "${CARGO_BUILD_JOBS}"

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
  && apt-get install -y --no-install-recommends tini \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --system --create-home --uid 10001 --home-dir /var/lib/rustaccio rustaccio

WORKDIR /var/lib/rustaccio

COPY --from=builder /app/target/release/rustaccio /usr/local/bin/rustaccio
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENV RUSTACCIO_BIND=0.0.0.0:4873
ENV RUSTACCIO_DATA_DIR=/var/lib/rustaccio/data

EXPOSE 4873
USER rustaccio

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["rustaccio"]
