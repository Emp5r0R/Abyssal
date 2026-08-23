#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
RELEASE_TOOL="$ROOT_DIR/target/release/abyssal-release-tool"
RELEASE_KEY="${ABYSSAL_RELEASE_SIGNING_KEY_FILE:-}"
SEQUENCE="${ABYSSAL_RELEASE_SEQUENCE:-}"
NOT_BEFORE_MS="${ABYSSAL_RELEASE_NOT_BEFORE_MS:-}"
EXPIRES_AT_MS="${ABYSSAL_RELEASE_EXPIRES_AT_MS:-}"
ANDROID_RECORD="${1:-}"
WEB_RECORD="${2:-}"
REVOCATIONS="${3:-}"
OUTPUT_DIR="${ABYSSAL_RELEASE_OUTPUT_DIR:-$ROOT_DIR/build-outputs}"

[[ -n "$RELEASE_KEY" && -f "$RELEASE_KEY" && ! -L "$RELEASE_KEY" ]] || {
  printf 'ABYSSAL_RELEASE_SIGNING_KEY_FILE must name a regular non-symlink file.\n' >&2
  exit 1
}
[[ "$SEQUENCE" =~ ^[1-9][0-9]*$ ]] || {
  printf 'ABYSSAL_RELEASE_SEQUENCE must be a positive canonical decimal.\n' >&2
  exit 1
}
[[ "$NOT_BEFORE_MS" =~ ^(0|[1-9][0-9]*)$ && "$EXPIRES_AT_MS" =~ ^(0|[1-9][0-9]*)$ ]] || {
  printf 'ABYSSAL_RELEASE_NOT_BEFORE_MS and ABYSSAL_RELEASE_EXPIRES_AT_MS are required canonical decimals.\n' >&2
  exit 1
}
for input in "$ANDROID_RECORD" "$WEB_RECORD" "$REVOCATIONS"; do
  [[ -f "$input" && ! -L "$input" ]] || {
    printf 'Usage: %s <android-build-record> <web-build-record> <revocations-file>\n' "$0" >&2
    exit 2
  }
done

cargo build --manifest-path "$ROOT_DIR/Cargo.toml" \
  --package abyssal-release-tool --release --locked
"$RELEASE_TOOL" check-root --private-key "$RELEASE_KEY"
ISSUED_AT_MS="$(date +%s%3N)"
mkdir -p "$OUTPUT_DIR"
MANIFEST="$OUTPUT_DIR/release-manifest-v1.json"
SIGNATURE="$OUTPUT_DIR/release-manifest-v1.sig"
for output in "$MANIFEST" "$SIGNATURE"; do
  [[ ! -e "$output" ]] || { printf 'Release output already exists: %s\n' "$output" >&2; exit 1; }
done

"$RELEASE_TOOL" assemble-manifest \
  --private-key "$RELEASE_KEY" \
  --sequence "$SEQUENCE" \
  --issued-at-ms "$ISSUED_AT_MS" \
  --not-before-ms "$NOT_BEFORE_MS" \
  --expires-at-ms "$EXPIRES_AT_MS" \
  --android-record "$ANDROID_RECORD" \
  --web-record "$WEB_RECORD" \
  --revocations "$REVOCATIONS" \
  --manifest-output "$MANIFEST" \
  --signature-output "$SIGNATURE"

printf 'Release manifest: %s\n' "$MANIFEST"
printf 'Detached signature: %s\n' "$SIGNATURE"
