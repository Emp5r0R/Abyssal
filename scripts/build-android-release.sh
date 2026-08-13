#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ABYSSAL_RELEASE_ENV:-$ROOT_DIR/deploy/release.env}"
GRADLE_HOME="${ABYSSAL_GRADLE_HOME:-$ROOT_DIR/.gradle-local}"
OUTPUT_DIR="${ABYSSAL_RELEASE_OUTPUT_DIR:-$ROOT_DIR/build-outputs}"

# Packaging is deliberately downstream of the complete non-packaging gate.
# This keeps a release build from being used to bypass supply-chain, crypto,
# Rust, web, Android, integration, or advisory checks.
"$ROOT_DIR/check.sh" all

if [[ ! -f "$ENV_FILE" ]]; then
  printf 'Signing environment not found: %s\n' "$ENV_FILE" >&2
  printf 'Run ./scripts/create-android-release-key.sh once, then back up its outputs.\n' >&2
  exit 1
fi

# The signing file is a data-only format. Never source it: passwords and paths
# may contain shell metacharacters and must remain literal data.
mapfile -t RELEASE_ENV_VALUES < <("$ROOT_DIR/scripts/parse-android-release-env.sh" "$ENV_FILE")
[[ "${#RELEASE_ENV_VALUES[@]}" -eq 4 ]] || {
  printf 'Signing environment parser returned an invalid record count.\n' >&2
  exit 1
}
decode_release_value() {
  printf '%s' "$1" | base64 --decode
}
ABYSSAL_KEYSTORE_PATH="$(decode_release_value "${RELEASE_ENV_VALUES[0]}")"
ABYSSAL_KEYSTORE_PASSWORD="$(decode_release_value "${RELEASE_ENV_VALUES[1]}")"
ABYSSAL_KEY_ALIAS="$(decode_release_value "${RELEASE_ENV_VALUES[2]}")"
ABYSSAL_KEY_PASSWORD="$(decode_release_value "${RELEASE_ENV_VALUES[3]}")"
unset RELEASE_ENV_VALUES
export ABYSSAL_KEYSTORE_PATH ABYSSAL_KEYSTORE_PASSWORD ABYSSAL_KEY_ALIAS ABYSSAL_KEY_PASSWORD

RECORDED_CRYPTO_DIGEST="$(tr -d '[:space:]' < "$ROOT_DIR/rust-core/generated-bindings.sha256")"
CURRENT_CRYPTO_DIGEST="$("$ROOT_DIR/scripts/crypto-source-digest.sh")"
if [[ ! "$RECORDED_CRYPTO_DIGEST" =~ ^[0-9a-f]{64}$ ]] || \
  [[ "$RECORDED_CRYPTO_DIGEST" != "$CURRENT_CRYPTO_DIGEST" ]]; then
  printf 'Generated crypto bindings are stale; run ./scripts/test-all.sh crypto first.\n' >&2
  exit 1
fi
unset RECORDED_CRYPTO_DIGEST CURRENT_CRYPTO_DIGEST

VERSION="$(sed -n 's/.*versionName = "\([^"]*\)".*/\1/p' "$ROOT_DIR/android/app/build.gradle.kts" | head -1)"
[[ -n "$VERSION" ]] || { printf 'Unable to read Android versionName.\n' >&2; exit 1; }

(
  cd "$ROOT_DIR/android"
  GRADLE_USER_HOME="$GRADLE_HOME" ./gradlew \
    --no-daemon \
    --max-workers=1 \
    --console=plain \
    :app:testDebugUnitTest \
    :app:lintRelease \
    :app:assembleRelease \
    :app:bundleRelease
)

APK_SOURCE="$ROOT_DIR/android/app/build/outputs/apk/release/app-release.apk"
AAB_SOURCE="$ROOT_DIR/android/app/build/outputs/bundle/release/app-release.aab"
[[ -f "$APK_SOURCE" && -f "$AAB_SOURCE" ]] || { printf 'Expected release artifacts were not produced.\n' >&2; exit 1; }

for abi in arm64-v8a armeabi-v7a x86 x86_64; do
  NATIVE_LIBRARY="$ROOT_DIR/android/app/src/main/jniLibs/$abi/libabyssal_core.so"
  [[ -s "$NATIVE_LIBRARY" ]] || {
    printf 'Missing native crypto library for %s: %s\n' "$abi" "$NATIVE_LIBRARY" >&2
    exit 1
  }
  grep -aFq 'ABYSSAL_E2EE_PAYLOAD_V8' "$NATIVE_LIBRARY" || {
    printf 'Native crypto library is not protocol v8 for %s: %s\n' "$abi" "$NATIVE_LIBRARY" >&2
    exit 1
  }
done

APKSIGNER="${ABYSSAL_APKSIGNER:-}"
if [[ -z "$APKSIGNER" && -n "${ANDROID_SDK_ROOT:-}" ]]; then
  APKSIGNER="$(find "$ANDROID_SDK_ROOT/build-tools" -type f -name apksigner -print 2>/dev/null | sort -V | tail -1)"
fi
if [[ -z "$APKSIGNER" && -n "${ANDROID_HOME:-}" ]]; then
  APKSIGNER="$(find "$ANDROID_HOME/build-tools" -type f -name apksigner -print 2>/dev/null | sort -V | tail -1)"
fi
if [[ -z "$APKSIGNER" ]]; then
  APKSIGNER="$(command -v apksigner || true)"
fi
[[ -x "$APKSIGNER" ]] || { printf 'apksigner was not found. Set ANDROID_SDK_ROOT or ABYSSAL_APKSIGNER.\n' >&2; exit 1; }

JARSIGNER="${ABYSSAL_JARSIGNER:-$(command -v jarsigner || true)}"
[[ -x "$JARSIGNER" ]] || { printf 'jarsigner was not found. Set ABYSSAL_JARSIGNER.\n' >&2; exit 1; }

"$APKSIGNER" verify --verbose --print-certs "$APK_SOURCE"
AAB_VERIFY_OUTPUT="$(LC_ALL=C "$JARSIGNER" -verify -verbose "$AAB_SOURCE" 2>&1)"
if ! printf '%s\n' "$AAB_VERIFY_OUTPUT" | grep -Fq 'jar verified.'; then
  printf 'AAB signature verification did not confirm a signed bundle: %s\n' "$AAB_SOURCE" >&2
  exit 1
fi
unset AAB_VERIFY_OUTPUT

mkdir -p "$OUTPUT_DIR"
APK_OUTPUT="$OUTPUT_DIR/abyssal-android-$VERSION-universal-release.apk"
AAB_OUTPUT="$OUTPUT_DIR/abyssal-android-$VERSION-release.aab"
cp "$APK_SOURCE" "$APK_OUTPUT"
cp "$AAB_SOURCE" "$AAB_OUTPUT"
(
  cd "$OUTPUT_DIR"
  sha256sum "$(basename "$APK_OUTPUT")" "$(basename "$AAB_OUTPUT")" \
    >"abyssal-android-$VERSION-SHA256SUMS.txt"
)

printf 'Release APK: %s\n' "$APK_OUTPUT"
printf 'Release AAB: %s\n' "$AAB_OUTPUT"
printf 'Checksums: %s\n' "$OUTPUT_DIR/abyssal-android-$VERSION-SHA256SUMS.txt"
