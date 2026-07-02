FROM rust:1-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim AS runtime

RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin mirage \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/mirage-server /usr/local/bin/mirage-server

USER mirage:mirage
EXPOSE 4020

ENV ABYSSAL_BIND_ADDR=0.0.0.0:4020

ENTRYPOINT ["/usr/local/bin/mirage-server"]
