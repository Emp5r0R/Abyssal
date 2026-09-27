# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS rust-builder

WORKDIR /repo
COPY Cargo.toml Cargo.lock ./
COPY abyssal-invite ./abyssal-invite
COPY mirage-server ./mirage-server
COPY rust-core ./rust-core
COPY tools/release-tool ./tools/release-tool
RUN --mount=type=cache,id=abyssal-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=abyssal-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=abyssal-rust-target,target=/repo/target,sharing=locked \
    cargo build --release --locked --package mirage-server \
    && mkdir -p /out \
    && cp /repo/target/release/mirage-server /out/mirage-server

FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS web-runtime

ADD .web-release/abyssal-web-*.tar.gz /opt/abyssal/web/
RUN set -eux; \
    test -f /opt/abyssal/web/index.html; \
    test ! -L /opt/abyssal/web/index.html; \
    test -f /opt/abyssal/web/build-id.json; \
    test ! -L /opt/abyssal/web/build-id.json; \
    test -z "$(find /opt/abyssal/web -type l -print -quit)"

FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS runtime

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
