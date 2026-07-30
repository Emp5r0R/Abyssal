# syntax=docker/dockerfile:1.7

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
RUN --mount=type=cache,id=abyssal-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=abyssal-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=abyssal-rust-target,target=/repo/target,sharing=locked \
    cargo build --release --locked --package mirage-server \
    && mkdir -p /out \
    && cp /repo/target/release/mirage-server /out/mirage-server

FROM debian:bookworm-slim AS runtime

RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin mirage \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=rust-builder /out/mirage-server /usr/local/bin/mirage-server
COPY --from=web-builder /repo/apps/web/dist /opt/abyssal/web

USER mirage:mirage
EXPOSE 4020

ENV ABYSSAL_BIND_ADDR=0.0.0.0:4020
ENV ABYSSAL_WEB_ROOT=/opt/abyssal/web

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["curl", "--fail", "--silent", "http://127.0.0.1:4020/health"]

ENTRYPOINT ["/usr/local/bin/mirage-server"]
