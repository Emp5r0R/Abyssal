#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT_DIR"
{
  printf '%s\0' \
    Cargo.lock \
    Cargo.toml \
    rust-toolchain.toml \
    abyssal-invite/Cargo.toml \
    rust-core/Cargo.toml \
    scripts/crypto-source-digest.sh \
    scripts/build-crypto-bindings.sh \
    uniffi-bindgen.toml
  find abyssal-invite/src rust-core/src -type f -print0
} | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}'
