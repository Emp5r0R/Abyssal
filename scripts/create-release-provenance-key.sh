#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TOOL="${ABYSSAL_RELEASE_TOOL:-$ROOT_DIR/target/release/abyssal-release-tool}"
PRIVATE_KEY="${ABYSSAL_RELEASE_SIGNING_KEY_FILE:-$ROOT_DIR/.secrets/abyssal-release-ed25519.key}"
PUBLIC_KEY="${ABYSSAL_RELEASE_PUBLIC_KEY_FILE:-$ROOT_DIR/.secrets/abyssal-release-ed25519.pub}"
ROOT_SOURCE="${ABYSSAL_RELEASE_ROOT_SOURCE:-$ROOT_DIR/.secrets/release_root.rs}"

[[ -x "$TOOL" ]] || {
  printf 'Release tool not found: %s\n' "$TOOL" >&2
  printf 'Before disconnecting the ceremony machine, run: cargo build --release --locked --package abyssal-release-tool\n' >&2
  exit 1
}

umask 077
mkdir -p "$(dirname "$PRIVATE_KEY")" "$(dirname "$PUBLIC_KEY")" "$(dirname "$ROOT_SOURCE")"
chmod 0700 "$(dirname "$PRIVATE_KEY")"

"$TOOL" generate-key \
  --private-key "$PRIVATE_KEY" \
  --public-key "$PUBLIC_KEY"
"$TOOL" render-root \
  --public-key "$PUBLIC_KEY" \
  --output "$ROOT_SOURCE"

FINGERPRINT="$("$TOOL" fingerprint-public --public-key "$PUBLIC_KEY")"
printf 'Release public-key fingerprint: %s\n' "$FINGERPRINT"
printf 'Private key: %s\n' "$PRIVATE_KEY"
printf 'Public key: %s\n' "$PUBLIC_KEY"
printf 'Generated root source: %s\n' "$ROOT_SOURCE"
printf 'Back up the private key offline. Use it only on the isolated release host; never copy it to a relay, container, repository, or ordinary development host.\n'
