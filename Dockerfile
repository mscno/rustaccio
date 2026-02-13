# syntax=docker/dockerfile:1.7

FROM rust:1-bookworm AS builder
WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates pkg-config libssl-dev \
  && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY webui ./webui
COPY config.example.yml ./config.example.yml

RUN cargo build --release --locked

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates tini \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --system --create-home --uid 10001 --home-dir /var/lib/rustaccio rustaccio

WORKDIR /var/lib/rustaccio

COPY --from=builder /app/target/release/rustaccio /usr/local/bin/rustaccio
COPY --from=builder /app/config.example.yml /etc/rustaccio/config.example.yml

ENV RUSTACCIO_BIND=0.0.0.0:4873
ENV RUSTACCIO_DATA_DIR=/var/lib/rustaccio/data

EXPOSE 4873
USER rustaccio

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["rustaccio"]
