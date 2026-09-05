#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/abyssal-crypto-digest.XXXXXX")"
trap 'rm -rf -- "$FIXTURE"' EXIT
mkdir -p "$FIXTURE/scripts" "$FIXTURE/rust-core/src" "$FIXTURE/abyssal-invite/src"
cp "$ROOT_DIR/scripts/crypto-source-digest.sh" "$FIXTURE/scripts/crypto-source-digest.sh"

inputs=(
  Cargo.lock Cargo.toml rust-toolchain.toml uniffi-bindgen.toml
  scripts/build-crypto-bindings.sh rust-core/Cargo.toml
  rust-core/src/lib.rs abyssal-invite/Cargo.toml abyssal-invite/src/locator.rs
)
for input in "${inputs[@]}"; do
  printf 'fixture\n' > "$FIXTURE/$input"
done
digest() { bash "$FIXTURE/scripts/crypto-source-digest.sh"; }
baseline="$(digest)"
[[ "$baseline" =~ ^[0-9a-f]{64}$ && "$(digest)" == "$baseline" ]]
for input in "${inputs[@]}"; do
  printf 'changed\n' >> "$FIXTURE/$input"
  [[ "$(digest)" != "$baseline" ]] || {
    printf 'Crypto freshness digest omitted %s\n' "$input" >&2
    exit 1
  }
  printf 'fixture\n' > "$FIXTURE/$input"
  [[ "$(digest)" == "$baseline" ]]
done

printf '\n# fixture mutation\n' >> "$FIXTURE/scripts/crypto-source-digest.sh"
[[ "$(digest)" != "$baseline" ]]
cp "$ROOT_DIR/scripts/crypto-source-digest.sh" "$FIXTURE/scripts/crypto-source-digest.sh"
mkdir -p "$FIXTURE/abyssal-invite/src/nested" "$FIXTURE/rust-core/src/nested"
for input in abyssal-invite/src/nested/new.rs rust-core/src/nested/new.rs; do
  touch "$FIXTURE/$input"
  [[ "$(digest)" != "$baseline" ]]
  rm -- "$FIXTURE/$input"
done
printf 'unrelated\n' > "$FIXTURE/README.md"
[[ "$(digest)" == "$baseline" ]]
mv "$FIXTURE/abyssal-invite/src/locator.rs" "$FIXTURE/abyssal-invite/src/renamed.rs"
[[ "$(digest)" != "$baseline" ]]
printf 'Crypto source digest coverage checks passed.\n'
