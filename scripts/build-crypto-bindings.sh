#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WASM_BINDGEN_BIN="${WASM_BINDGEN_BIN:-$(command -v wasm-bindgen || true)}"
ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ROOT_DIR/android-sdk/ndk/27.3.13750724}"
LLVM_STRIP="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip"

if [[ -z "$WASM_BINDGEN_BIN" && -x "${HOME:-}/.cargo/bin/wasm-bindgen" ]]; then
  WASM_BINDGEN_BIN="$HOME/.cargo/bin/wasm-bindgen"
fi
if [[ -z "$WASM_BINDGEN_BIN" ]]; then
  echo "wasm-bindgen 0.2.126 is required (set WASM_BINDGEN_BIN)." >&2
  exit 1
fi
if ! cargo ndk --version >/dev/null 2>&1; then
  echo "cargo-ndk is required (run cargo install cargo-ndk)." >&2
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
  --bin uniffi-bindgen \
  --features bindgen-cli
cargo build --manifest-path "$ROOT_DIR/Cargo.toml" --package abyssal-core --release --lib
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
  build --package abyssal-core --release --lib
for library in "$ROOT_DIR"/android/app/src/main/jniLibs/*/libabyssal_core.so; do
  "$LLVM_STRIP" --strip-unneeded "$library"
done
chmod 0644 "$ROOT_DIR"/android/app/src/main/jniLibs/*/libabyssal_core.so

for artifact in \
  "$ROOT_DIR"/apps/web/src/generated/abyssal_core/abyssal_core_bg.wasm \
  "$ROOT_DIR"/android/app/src/main/jniLibs/*/libabyssal_core.so; do
  if ! grep -aFq "ABYSSAL_E2EE_PAYLOAD_V6" "$artifact"; then
    echo "Generated crypto artifact does not contain protocol v6: $artifact" >&2
    exit 1
  fi
done

"$ROOT_DIR/scripts/crypto-source-digest.sh" > \
  "$ROOT_DIR/rust-core/generated-bindings.sha256"

echo "Shared crypto bindings rebuilt for web and Android."
