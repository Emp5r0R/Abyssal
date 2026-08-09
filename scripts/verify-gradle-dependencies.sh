#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
METADATA="$ROOT_DIR/android/gradle/verification-metadata.xml"

if [[ ! -s "$METADATA" ]]; then
  printf 'Missing Gradle dependency verification metadata: %s\n' "$METADATA" >&2
  exit 1
fi

# Gradle performs the authoritative XML parse and hash verification during the
# Android gate. Keep this lightweight preflight focused on rejecting policy
# bypasses that would silently trust or ignore an unverified artifact.
grep -Fqx '<?xml version="1.0" encoding="UTF-8"?>' <(head -n 1 "$METADATA") || {
  echo 'Gradle verification metadata must be UTF-8 XML.' >&2
  exit 1
}
grep -Fq '<verification-metadata ' "$METADATA" || {
  echo 'Gradle verification metadata has no verification-metadata root.' >&2
  exit 1
}
grep -Fq '<verify-metadata>true</verify-metadata>' "$METADATA" || {
  echo 'Gradle metadata verification must be enabled.' >&2
  exit 1
}
grep -Fq '<verify-signatures>false</verify-signatures>' "$METADATA" || {
  echo 'Gradle verification must use the recorded SHA-256 checksums.' >&2
  exit 1
}

for bypass in trusted-artifacts ignored-artifacts ignored-key trusted-key; do
  if grep -Fq "<$bypass" "$METADATA"; then
    printf 'Gradle verification metadata contains forbidden bypass: <%s>\n' "$bypass" >&2
    exit 1
  fi
done

sha_count="$(grep -Ec '<sha256 value="[0-9a-f]{64}"' "$METADATA")"
if [[ "$sha_count" -lt 1 ]]; then
  echo 'Gradle verification metadata contains no SHA-256 artifact checksums.' >&2
  exit 1
fi

if grep -En '<sha256 value="[^"]+"' "$METADATA" | grep -Ev '<sha256 value="[0-9a-f]{64}"'; then
  echo 'Gradle verification metadata contains a malformed SHA-256 checksum.' >&2
  exit 1
fi

printf 'Gradle dependency verification metadata OK (%s SHA-256 checksums).\n' "$sha_count"
