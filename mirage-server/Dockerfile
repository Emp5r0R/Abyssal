FROM node:22-bookworm-slim AS web-builder

WORKDIR /repo
COPY package.json package-lock.json ./
COPY apps/web/package.json ./apps/web/package.json
RUN npm ci --workspace @abyssal/web
COPY apps/web ./apps/web
RUN npm run build --workspace @abyssal/web

FROM rust:1-bookworm AS rust-builder

WORKDIR /repo
COPY Cargo.toml Cargo.lock ./
COPY mirage-server ./mirage-server
COPY rust-core ./rust-core
RUN cargo build --release --locked --package mirage-server

FROM debian:bookworm-slim AS runtime

RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin mirage \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=rust-builder /repo/target/release/mirage-server /usr/local/bin/mirage-server
COPY --from=web-builder /repo/apps/web/dist /opt/abyssal/web

USER mirage:mirage
EXPOSE 4020

ENV ABYSSAL_BIND_ADDR=0.0.0.0:4020
ENV ABYSSAL_WEB_ROOT=/opt/abyssal/web

ENTRYPOINT ["/usr/local/bin/mirage-server"]
