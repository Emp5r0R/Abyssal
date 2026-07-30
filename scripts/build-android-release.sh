#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ABYSSAL_RELEASE_ENV:-$ROOT_DIR/deploy/release.env}"
GRADLE_HOME="${ABYSSAL_GRADLE_HOME:-$ROOT_DIR/.gradle-local}"
OUTPUT_DIR="${ABYSSAL_RELEASE_OUTPUT_DIR:-$ROOT_DIR/build-outputs}"

if [[ ! -f "$ENV_FILE" ]]; then
  printf 'Signing environment not found: %s\n' "$ENV_FILE" >&2
  printf 'Run ./scripts/create-android-release-key.sh once, then back up its outputs.\n' >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"
: "${ABYSSAL_KEYSTORE_PATH:?Missing ABYSSAL_KEYSTORE_PATH}"
: "${ABYSSAL_KEYSTORE_PASSWORD:?Missing ABYSSAL_KEYSTORE_PASSWORD}"
: "${ABYSSAL_KEY_ALIAS:?Missing ABYSSAL_KEY_ALIAS}"
: "${ABYSSAL_KEY_PASSWORD:?Missing ABYSSAL_KEY_PASSWORD}"
export ABYSSAL_KEYSTORE_PATH ABYSSAL_KEYSTORE_PASSWORD ABYSSAL_KEY_ALIAS ABYSSAL_KEY_PASSWORD

[[ -f "$ABYSSAL_KEYSTORE_PATH" ]] || { printf 'Keystore not found: %s\n' "$ABYSSAL_KEYSTORE_PATH" >&2; exit 1; }

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

"$APKSIGNER" verify --verbose --print-certs "$APK_SOURCE"

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
