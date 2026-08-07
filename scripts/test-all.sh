#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-all}"
GRADLE_HOME="${ABYSSAL_GRADLE_HOME:-$ROOT_DIR/.gradle-local}"

usage() {
  cat <<'EOF'
Usage: ./scripts/test-all.sh [all|quick|web|rust|android|integration|crypto|audit|shell]

  all          Run every repository check, including the live relay test.
  quick        Run formatting, web, and Rust checks without Android or integration.
  web          Run TypeScript lint, unit/component tests, and production build.
  rust         Run rustfmt, all Rust tests, and clippy with warnings denied.
  android      Run Android JVM tests, release lint, debug APK, and release bundles.
  integration  Start a disposable relay and verify account, DM, and access control flows.
  crypto       Regenerate the shared WASM, Kotlin, and Android native bindings.
  audit        Check npm and Rust dependencies against current advisories.
  shell        Parse every tracked Bash script and check patch whitespace.
EOF
}

run_shell() {
  echo "==> Repository and shell checks"
  git -C "$ROOT_DIR" diff --check
  while IFS= read -r script; do
    bash -n "$script"
  done < <(find "$ROOT_DIR" -path "$ROOT_DIR/.git" -prune -o -type f -name '*.sh' -print | sort)

  for artifact in \
    "$ROOT_DIR"/apps/web/src/generated/abyssal_core/abyssal_core_bg.wasm \
    "$ROOT_DIR"/android/app/src/main/jniLibs/*/libabyssal_core.so; do
    if ! grep -aFq "ABYSSAL_E2EE_PAYLOAD_V5" "$artifact"; then
      echo "Stale crypto artifact: $artifact" >&2
      exit 1
    fi
  done
}

run_audit() {
  echo "==> Dependency advisory checks"
  command -v cargo-audit >/dev/null 2>&1 || cargo audit --version >/dev/null 2>&1 || {
    echo "cargo-audit is required (run cargo install cargo-audit --locked)." >&2
    exit 1
  }
  npm --prefix "$ROOT_DIR" audit --audit-level=moderate
  cargo audit --file "$ROOT_DIR/Cargo.lock"
}

run_web() {
  echo "==> Web checks"
  npm --prefix "$ROOT_DIR" run web:check
}

run_rust() {
  echo "==> Rust checks"
  cargo fmt --manifest-path "$ROOT_DIR/Cargo.toml" --all -- --check
  cargo test --manifest-path "$ROOT_DIR/Cargo.toml" --workspace --all-targets --locked
  cargo clippy --manifest-path "$ROOT_DIR/Cargo.toml" --workspace --all-targets --locked -- -D warnings
}

run_android() {
  echo "==> Android checks"
  cargo build \
    --manifest-path "$ROOT_DIR/Cargo.toml" \
    --package abyssal-core \
    --release \
    --locked
  (
    cd "$ROOT_DIR/android"
    GRADLE_USER_HOME="$GRADLE_HOME" ./gradlew \
      --no-daemon \
      --max-workers=1 \
      --console=plain \
      :app:testDebugUnitTest \
      :app:lintRelease \
      :app:assembleDebug \
      :app:assembleRelease \
      :app:bundleRelease
  )
}

run_integration() {
  echo "==> Live relay integration checks"
  "$ROOT_DIR/scripts/test-relay-integration.sh"
}

case "$MODE" in
  all)
    run_shell
    run_web
    run_rust
    run_android
    run_integration
    run_audit
    ;;
  quick)
    run_shell
    run_web
    run_rust
    ;;
  web) run_web ;;
  rust) run_rust ;;
  android) run_android ;;
  integration) run_integration ;;
  crypto) "$ROOT_DIR/scripts/build-crypto-bindings.sh" ;;
  audit) run_audit ;;
  shell) run_shell ;;
  -h|--help) usage ;;
  *)
    usage >&2
    exit 2
    ;;
esac

echo "==> Abyssal $MODE checks passed"
