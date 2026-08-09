#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$ROOT_DIR/rust-core/generated-artifacts.sha256"

[[ -f "$MANIFEST" ]] || {
  printf 'Missing generated crypto artifact manifest: %s\n' "$MANIFEST" >&2
  exit 1
}

expected_paths=(
  apps/web/src/generated/abyssal_core/abyssal_core_bg.wasm
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
