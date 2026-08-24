#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$ROOT_DIR/rust-core/generated-artifacts.sha256"

[[ -f "$MANIFEST" ]] || {
  printf 'Missing generated crypto artifact manifest: %s\n' "$MANIFEST" >&2
  exit 1
}

expected_paths=(
  apps/web/src/generated/abyssal_core/abyssal_core.js
  apps/web/src/generated/abyssal_core/abyssal_core_bg.wasm
)
while IFS= read -r -d '' snippet; do
  expected_paths+=("${snippet#"$ROOT_DIR/"}")
done < <(
  find "$ROOT_DIR/apps/web/src/generated/abyssal_core/snippets" \
    -type f -name '*.js' -print0 2>/dev/null | sort -z
)
expected_paths+=(
  android/app/src/main/jniLibs/arm64-v8a/libabyssal_core.so
  android/app/src/main/jniLibs/armeabi-v7a/libabyssal_core.so
  android/app/src/main/jniLibs/x86/libabyssal_core.so
  android/app/src/main/jniLibs/x86_64/libabyssal_core.so
)

mapfile -t manifest_paths < <(
  sed -n 's/^[0-9a-f]\{64\}[[:space:]][[:space:]]*//p' "$MANIFEST"
)
if [[ "${#manifest_paths[@]}" -ne "${#expected_paths[@]}" ]]; then
  printf 'Generated crypto artifact manifest has the wrong entry count.\n' >&2
  exit 1
fi
for index in "${!expected_paths[@]}"; do
  [[ "${manifest_paths[$index]}" == "${expected_paths[$index]}" ]] || {
    printf 'Unexpected generated crypto artifact at manifest entry %s.\n' "$((index + 1))" >&2
    exit 1
  }
done

(cd "$ROOT_DIR" && sha256sum --check --strict "$MANIFEST")

for artifact in \
  "$ROOT_DIR/apps/web/src/generated/abyssal_core/abyssal_core_bg.wasm" \
  "$ROOT_DIR/android/app/src/main/jniLibs/arm64-v8a/libabyssal_core.so" \
  "$ROOT_DIR/android/app/src/main/jniLibs/armeabi-v7a/libabyssal_core.so" \
  "$ROOT_DIR/android/app/src/main/jniLibs/x86/libabyssal_core.so" \
  "$ROOT_DIR/android/app/src/main/jniLibs/x86_64/libabyssal_core.so"; do
  grep -aFq "ABYSSAL_E2EE_PAYLOAD_V9" "$artifact" || {
    printf 'Generated crypto artifact does not contain protocol v9: %s\n' "$artifact" >&2
    exit 1
  }
  grep -aFq "ABYSSAL-MLS-STATE-V10" "$artifact" || {
    printf 'Generated crypto artifact does not contain MLS protocol v10: %s\n' "$artifact" >&2
    exit 1
  }
  grep -aFq "ABYSSAL_ATTACHMENT_CHUNK_AEAD_V2" "$artifact" || {
    printf 'Generated crypto artifact does not contain attachment cipher v2: %s\n' "$artifact" >&2
    exit 1
  }
done
