# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM node:22.23.2-bookworm-slim@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436 AS web-builder

WORKDIR /repo
COPY package.json package-lock.json ./
COPY apps/web/package.json ./apps/web/package.json
RUN npm ci --ignore-scripts --workspace @abyssal/web
COPY apps/web ./apps/web
RUN npm run build --workspace @abyssal/web

FROM rust:1.97.1-bookworm@sha256:14bc9c5966e7b3a385794b3d5389a8765668342025fbcc7b2e3d2866ac4bd8c3 AS rust-builder

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

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241 AS runtime

RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin mirage

COPY --from=rust-builder /out/mirage-server /usr/local/bin/mirage-server
COPY --from=web-builder /repo/apps/web/dist /opt/abyssal/web

USER mirage:mirage
EXPOSE 4020

ENV ABYSSAL_BIND_ADDR=0.0.0.0:4020
ENV ABYSSAL_WEB_ROOT=/opt/abyssal/web

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/mirage-server", "--healthcheck"]

ENTRYPOINT ["/usr/local/bin/mirage-server"]
