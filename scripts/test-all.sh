#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-all}"
GRADLE_HOME="${ABYSSAL_GRADLE_HOME:-$ROOT_DIR/.gradle-local}"

usage() {
  cat <<'EOF'
Usage: ./scripts/test-all.sh [all|quick|web|rust|android|integration|shell]

  all          Run every repository check, including the live relay test.
  quick        Run formatting, web, and Rust checks without Android or integration.
  web          Run TypeScript lint, unit/component tests, and production build.
  rust         Run rustfmt, all Rust tests, and clippy with warnings denied.
  android      Run Android JVM tests, release lint, debug APK, and release bundles.
  integration  Start a disposable relay and verify account, DM, and access control flows.
  shell        Parse every tracked Bash script and check patch whitespace.
EOF
}

run_shell() {
  echo "==> Repository and shell checks"
  git -C "$ROOT_DIR" diff --check
  while IFS= read -r script; do
    bash -n "$script"
  done < <(find "$ROOT_DIR" -path "$ROOT_DIR/.git" -prune -o -type f -name '*.sh' -print | sort)
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
  shell) run_shell ;;
  -h|--help) usage ;;
  *)
    usage >&2
    exit 2
    ;;
esac

echo "==> Abyssal $MODE checks passed"
