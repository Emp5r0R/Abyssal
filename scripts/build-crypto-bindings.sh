#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
WASM_BINDGEN_BIN="${WASM_BINDGEN_BIN:-$(command -v wasm-bindgen || true)}"
ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ROOT_DIR/android-sdk/ndk/27.3.13750724}"
LLVM_STRIP="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip"
EXPECTED_RUST_VERSION="1.97.1"
EXPECTED_WASM_BINDGEN_VERSION="0.2.126"
EXPECTED_CARGO_NDK_VERSION="4.1.2"
EXPECTED_NDK_REVISION="27.3.13750724"

# Rust embeds source paths in panic/backtrace metadata.  The checked-in WASM
# and native libraries must be identical when generated on a developer host
# and on a clean CI runner, so intentionally replace all ambient Rust flags
# with a fixed, path-independent set of remapping flags.
resolve_path() {
  local path="$1"
  local base="$2"
  if [[ "$path" != /* ]]; then
    path="$base/$path"
  fi
  if [[ -d "$path" ]]; then
    (cd -- "$path" && pwd -P)
  else
    realpath -m -- "$path"
  fi
}

INVOCATION_DIR="$(pwd -P)"
EFFECTIVE_CARGO_HOME="$(resolve_path "${CARGO_HOME:-${HOME:-$ROOT_DIR}/.cargo}" "$INVOCATION_DIR")"
EFFECTIVE_RUSTUP_HOME="$(resolve_path "${RUSTUP_HOME:-${HOME:-$ROOT_DIR}/.rustup}" "$INVOCATION_DIR")"
ANDROID_NDK_HOME="$(resolve_path "$ANDROID_NDK_HOME" "$ROOT_DIR")"

remap_flags=(
  "--remap-path-prefix=${ROOT_DIR}=/abyssal/src"
  "--remap-path-prefix=${EFFECTIVE_CARGO_HOME}=/abyssal/cargo"
  "--remap-path-prefix=${EFFECTIVE_RUSTUP_HOME}=/abyssal/rustup"
  "--remap-path-prefix=${ANDROID_NDK_HOME}=/abyssal/android-ndk"
)
CARGO_ENCODED_RUSTFLAGS="${remap_flags[0]}"
for ((flag_index = 1; flag_index < ${#remap_flags[@]}; flag_index++)); do
  CARGO_ENCODED_RUSTFLAGS+=$'\x1f'"${remap_flags[$flag_index]}"
done
export CARGO_ENCODED_RUSTFLAGS
unset RUSTFLAGS

if [[ -z "$WASM_BINDGEN_BIN" && -x "${HOME:-}/.cargo/bin/wasm-bindgen" ]]; then
  WASM_BINDGEN_BIN="$HOME/.cargo/bin/wasm-bindgen"
fi
if [[ -z "$WASM_BINDGEN_BIN" ]]; then
  echo "wasm-bindgen $EXPECTED_WASM_BINDGEN_VERSION is required (set WASM_BINDGEN_BIN)." >&2
  exit 1
fi
if ! cargo ndk --version >/dev/null 2>&1; then
  echo "cargo-ndk $EXPECTED_CARGO_NDK_VERSION is required." >&2
  exit 1
fi
if [[ ! -d "$ANDROID_NDK_HOME" ]]; then
  echo "Android NDK not found: $ANDROID_NDK_HOME" >&2
  exit 1
fi
if [[ ! -x "$LLVM_STRIP" ]]; then
  echo "Android NDK llvm-strip not found: $LLVM_STRIP" >&2
  exit 1
fi

actual_rust_version="$(rustc --version | awk '{print $2}')"
actual_wasm_bindgen_version="$("$WASM_BINDGEN_BIN" --version | awk '{print $2}')"
actual_cargo_ndk_version="$(cargo ndk --version | awk '{print $2}')"
actual_ndk_revision="$(sed -n 's/^Pkg.Revision = //p' "$ANDROID_NDK_HOME/source.properties")"
[[ "$actual_rust_version" == "$EXPECTED_RUST_VERSION" ]] || {
  printf 'Rust %s is required; found %s.\n' "$EXPECTED_RUST_VERSION" "$actual_rust_version" >&2
  exit 1
}
[[ "$actual_wasm_bindgen_version" == "$EXPECTED_WASM_BINDGEN_VERSION" ]] || {
  printf 'wasm-bindgen %s is required; found %s.\n' \
    "$EXPECTED_WASM_BINDGEN_VERSION" "$actual_wasm_bindgen_version" >&2
  exit 1
}
[[ "$actual_cargo_ndk_version" == "$EXPECTED_CARGO_NDK_VERSION" ]] || {
  printf 'cargo-ndk %s is required; found %s.\n' \
    "$EXPECTED_CARGO_NDK_VERSION" "$actual_cargo_ndk_version" >&2
  exit 1
}
[[ "$actual_ndk_revision" == "$EXPECTED_NDK_REVISION" ]] || {
  printf 'Android NDK %s is required; found %s.\n' \
    "$EXPECTED_NDK_REVISION" "${actual_ndk_revision:-unknown}" >&2
  exit 1
}

rustup target add \
  wasm32-unknown-unknown \
  aarch64-linux-android \
  armv7-linux-androideabi \
  i686-linux-android \
  x86_64-linux-android

cargo build \
  --manifest-path "$ROOT_DIR/Cargo.toml" \
  --package abyssal-core \
  --release \
  --locked \
  --bin uniffi-bindgen \
  --features bindgen-cli
cargo build \
  --manifest-path "$ROOT_DIR/Cargo.toml" \
  --package abyssal-core \
  --release \
  --locked \
  --lib
"$ROOT_DIR/target/release/uniffi-bindgen" generate \
  "$ROOT_DIR/target/release/libabyssal_core.so" \
  --library \
  --crate abyssal_core \
  --metadata-no-deps \
  --language kotlin \
  --config "$ROOT_DIR/uniffi-bindgen.toml" \
  --out-dir "$ROOT_DIR/android/app/src/main/java" \
  --no-format
perl -0pi -e 's/[ \t]+(?=\n)//g; s/\n+\z/\n/' \
  "$ROOT_DIR/android/app/src/main/java/uniffi/abyssal_core/abyssal_core.kt"

cargo build \
  --manifest-path "$ROOT_DIR/Cargo.toml" \
  --package abyssal-core \
  --release \
  --locked \
  --target wasm32-unknown-unknown
"$WASM_BINDGEN_BIN" \
  --target web \
  --typescript \
  --out-dir "$ROOT_DIR/apps/web/src/generated/abyssal_core" \
  "$ROOT_DIR/target/wasm32-unknown-unknown/release/abyssal_core.wasm"
chmod 0644 "$ROOT_DIR"/apps/web/src/generated/abyssal_core/*

ANDROID_NDK_HOME="$ANDROID_NDK_HOME" cargo ndk \
  --manifest-path "$ROOT_DIR/Cargo.toml" \
  -t arm64-v8a \
  -t armeabi-v7a \
  -t x86 \
  -t x86_64 \
  -o "$ROOT_DIR/android/app/src/main/jniLibs" \
  build --package abyssal-core --release --locked --lib
for library in "$ROOT_DIR"/android/app/src/main/jniLibs/*/libabyssal_core.so; do
  "$LLVM_STRIP" --strip-unneeded "$library"
done
chmod 0644 "$ROOT_DIR"/android/app/src/main/jniLibs/*/libabyssal_core.so

for artifact in \
  "$ROOT_DIR"/apps/web/src/generated/abyssal_core/abyssal_core_bg.wasm \
  "$ROOT_DIR"/android/app/src/main/jniLibs/*/libabyssal_core.so; do
  if ! grep -aFq "ABYSSAL_E2EE_PAYLOAD_V7" "$artifact"; then
    echo "Generated crypto artifact does not contain protocol v7: $artifact" >&2
    exit 1
  fi
done

for build_path in \
  "$ROOT_DIR" \
  "$EFFECTIVE_CARGO_HOME" \
  "$EFFECTIVE_RUSTUP_HOME" \
  "$ANDROID_NDK_HOME"; do
  # A path of / would match every artifact byte and is not a useful remap
  # target; the configured project/toolchain paths are always more specific.
  [[ -n "$build_path" && "$build_path" != "/" ]] || continue
  for artifact in \
    "$ROOT_DIR"/apps/web/src/generated/abyssal_core/abyssal_core_bg.wasm \
    "$ROOT_DIR"/android/app/src/main/jniLibs/*/libabyssal_core.so; do
    if grep -aFq -- "$build_path" "$artifact"; then
      printf 'Generated crypto artifact leaks build path %s: %s\n' \
        "$build_path" "$artifact" >&2
      exit 1
    fi
  done
done

(
  cd "$ROOT_DIR"
  sha256sum \
    apps/web/src/generated/abyssal_core/abyssal_core_bg.wasm \
    android/app/src/main/jniLibs/arm64-v8a/libabyssal_core.so \
    android/app/src/main/jniLibs/armeabi-v7a/libabyssal_core.so \
    android/app/src/main/jniLibs/x86/libabyssal_core.so \
    android/app/src/main/jniLibs/x86_64/libabyssal_core.so \
    > rust-core/generated-artifacts.sha256
)

"$ROOT_DIR/scripts/crypto-source-digest.sh" > \
  "$ROOT_DIR/rust-core/generated-bindings.sha256"

echo "Shared crypto bindings rebuilt for web and Android."
