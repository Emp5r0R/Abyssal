#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TOOL="${ABYSSAL_RELEASE_TOOL:-$ROOT_DIR/target/release/abyssal-release-tool}"
PUBLIC_KEY="${1:-}"
EXPECTED_FINGERPRINT="${ABYSSAL_RELEASE_ROOT_FINGERPRINT:-}"

[[ -x "$TOOL" ]] || { printf 'Release tool not found: %s\n' "$TOOL" >&2; exit 1; }
[[ -n "$PUBLIC_KEY" && -f "$PUBLIC_KEY" && ! -L "$PUBLIC_KEY" ]] || {
  printf 'Usage: ABYSSAL_RELEASE_ROOT_FINGERPRINT=<sha256> %s <public-key-file>\n' "$0" >&2
  exit 2
}
[[ "$EXPECTED_FINGERPRINT" =~ ^[0-9a-f]{64}$ ]] || {
  printf 'ABYSSAL_RELEASE_ROOT_FINGERPRINT must be the separately verified 64-character fingerprint.\n' >&2
  exit 1
}

ACTUAL_FINGERPRINT="$("$TOOL" fingerprint-public --public-key "$PUBLIC_KEY")"
[[ "$ACTUAL_FINGERPRINT" == "$EXPECTED_FINGERPRINT" ]] || {
  printf 'Release public-key fingerprint mismatch.\n' >&2
  exit 1
}

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/abyssal-release-root.XXXXXX")"
trap 'rm -rf -- "$TEMP_DIR"' EXIT
"$TOOL" render-root --public-key "$PUBLIC_KEY" --output "$TEMP_DIR/release_root.rs"
install -m 0644 "$TEMP_DIR/release_root.rs" "$ROOT_DIR/rust-core/src/release_root.rs"

printf 'Installed release public key with fingerprint %s\n' "$ACTUAL_FINGERPRINT"
printf 'Run ./scripts/test-all.sh crypto, then ./scripts/test-all.sh all before committing the root.\n'
