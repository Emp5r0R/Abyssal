#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WRAPPER_DIR="$ROOT_DIR/android/gradle/wrapper"
WRAPPER_JAR="$WRAPPER_DIR/gradle-wrapper.jar"
PROPERTIES="$WRAPPER_DIR/gradle-wrapper.properties"

# Keep these values aligned with the checked-in Gradle wrapper. Updating Gradle
# is a deliberate supply-chain change: update both hashes from the official
# release, then review the resulting wrapper diff.
EXPECTED_GRADLE_VERSION="8.7"
EXPECTED_DISTRIBUTION_SHA256="544c35d6bd849ae8a5ed0bcea39ba677dc40f49df7d1835561582da2009b961d"
EXPECTED_WRAPPER_JAR_SHA256="cb0da6751c2b753a16ac168bb354870ebb1e162e9083f116729cec9c781156b8"

[[ -f "$WRAPPER_JAR" ]] || { printf 'Missing Gradle wrapper JAR: %s\n' "$WRAPPER_JAR" >&2; exit 1; }
[[ -f "$PROPERTIES" ]] || { printf 'Missing Gradle wrapper properties: %s\n' "$PROPERTIES" >&2; exit 1; }

actual_wrapper_jar_sha256="$(sha256sum "$WRAPPER_JAR" | awk '{print $1}')"
[[ "$actual_wrapper_jar_sha256" == "$EXPECTED_WRAPPER_JAR_SHA256" ]] || {
  printf 'Gradle wrapper JAR checksum mismatch: expected %s, got %s\n' \
    "$EXPECTED_WRAPPER_JAR_SHA256" "$actual_wrapper_jar_sha256" >&2
  exit 1
}

distribution_url="$(sed -n 's/^distributionUrl=.*gradle-\([0-9][^/]*\)-bin\.zip$/\1/p' "$PROPERTIES")"
distribution_sha256="$(sed -n 's/^distributionSha256Sum=\([0-9a-f]\{64\}\)$/\1/p' "$PROPERTIES")"
[[ "$distribution_url" == "$EXPECTED_GRADLE_VERSION" ]] || {
  printf 'Unexpected Gradle wrapper version: expected %s, got %s\n' \
    "$EXPECTED_GRADLE_VERSION" "${distribution_url:-missing}" >&2
  exit 1
}
[[ "$distribution_sha256" == "$EXPECTED_DISTRIBUTION_SHA256" ]] || {
  printf 'Gradle distribution checksum mismatch: expected %s, got %s\n' \
    "$EXPECTED_DISTRIBUTION_SHA256" "${distribution_sha256:-missing}" >&2
  exit 1
}

printf 'Gradle wrapper verified: %s (JAR %s)\n' "$EXPECTED_GRADLE_VERSION" "$actual_wrapper_jar_sha256"
