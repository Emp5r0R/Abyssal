# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS rust-builder

WORKDIR /repo
COPY Cargo.toml Cargo.lock ./
COPY mirage-server ./mirage-server
COPY rust-core ./rust-core
COPY tools/release-tool ./tools/release-tool
RUN --mount=type=cache,id=abyssal-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=abyssal-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=abyssal-rust-target,target=/repo/target,sharing=locked \
    cargo build --release --locked --package mirage-server \
    && mkdir -p /out \
    && cp /repo/target/release/mirage-server /out/mirage-server

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241 AS web-runtime

ADD .web-release/abyssal-web-*.tar.gz /opt/abyssal/web/
RUN set -eux; \
    test -f /opt/abyssal/web/index.html; \
    test ! -L /opt/abyssal/web/index.html; \
    test -f /opt/abyssal/web/build-id.json; \
    test ! -L /opt/abyssal/web/build-id.json; \
    test -z "$(find /opt/abyssal/web -type l -print -quit)"

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241 AS runtime

RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin mirage

COPY --from=rust-builder /out/mirage-server /usr/local/bin/mirage-server
COPY --from=web-runtime /opt/abyssal/web /opt/abyssal/web

USER mirage:mirage
EXPOSE 4020

ENV ABYSSAL_BIND_ADDR=0.0.0.0:4020
ENV ABYSSAL_WEB_ROOT=/opt/abyssal/web

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/mirage-server", "--healthcheck"]

ENTRYPOINT ["/usr/local/bin/mirage-server"]
