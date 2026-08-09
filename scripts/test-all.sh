#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-all}"
GRADLE_HOME="${ABYSSAL_GRADLE_HOME:-$ROOT_DIR/.gradle-local}"

usage() {
  cat <<'EOF'
Usage: ./scripts/test-all.sh [all|quick|web|rust|android|android-package|integration|crypto|audit|shell]

  all          Run every repository check, including the live relay test.
  quick        Run formatting, web, and Rust checks without Android or integration.
  web          Run TypeScript lint, unit/component tests, and production build.
  rust         Run rustfmt, all Rust tests, and clippy with warnings denied.
  android      Run Android JVM tests, release lint, and Kotlin compilation without packaging.
  android-package
               Explicitly build unsigned debug/release APK and AAB packages.
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
    bash -n "$ROOT_DIR/$script"
  done < <(git -C "$ROOT_DIR" ls-files '*.sh' | sort)

  "$ROOT_DIR/scripts/verify-gradle-wrapper.sh"
  "$ROOT_DIR/scripts/verify-gradle-dependencies.sh"
  "$ROOT_DIR/scripts/verify-crypto-artifacts.sh"
  "$ROOT_DIR/scripts/test-release-env-parser.sh"
  "$ROOT_DIR/scripts/test-deployment-inputs.sh"

  for sensitive_context_path in \
    .git .gradle-local .rustup-local .secrets .npmrc \
    deploy deploy/deploy.env deploy/release.env .env '.env.*'; do
    grep -Fxq "$sensitive_context_path" "$ROOT_DIR/.dockerignore" || {
      printf 'Docker context must exclude sensitive/local path: %s\n' \
        "$sensitive_context_path" >&2
      exit 1
    }
  done

  if grep -RhE '^[[:space:]]*-[[:space:]]+uses:' "$ROOT_DIR/.github/workflows" | \
    grep -Ev 'uses:[[:space:]]+[^@[:space:]]+@[0-9a-f]{40}([[:space:]]+#.*)?$'; then
    echo "GitHub Actions must use immutable 40-character commit SHAs." >&2
    exit 1
  fi

  if grep -RhE '^FROM[[:space:]]+' "$ROOT_DIR"/*/Dockerfile | \
    grep -Ev '@sha256:[0-9a-f]{64}([[:space:]]+AS[[:space:]]+[A-Za-z0-9_-]+)?$'; then
    echo "Docker base images must use immutable SHA-256 digests." >&2
    exit 1
  fi

  if grep -RhE '^#[[:space:]]*syntax=' "$ROOT_DIR"/*/Dockerfile | \
    grep -Ev '^#[[:space:]]*syntax=[^@[:space:]]+@sha256:[0-9a-f]{64}$'; then
    echo "Dockerfile frontends must use immutable SHA-256 digests." >&2
    exit 1
  fi

  local recorded_crypto_digest current_crypto_digest
  recorded_crypto_digest="$(tr -d '[:space:]' < "$ROOT_DIR/rust-core/generated-bindings.sha256")"
  current_crypto_digest="$("$ROOT_DIR/scripts/crypto-source-digest.sh")"
  if [[ ! "$recorded_crypto_digest" =~ ^[0-9a-f]{64}$ ]] || \
    [[ "$recorded_crypto_digest" != "$current_crypto_digest" ]]; then
    echo "Stale generated crypto bindings; run ./scripts/test-all.sh crypto." >&2
    exit 1
  fi

  for artifact in \
    "$ROOT_DIR"/apps/web/src/generated/abyssal_core/abyssal_core_bg.wasm \
    "$ROOT_DIR"/android/app/src/main/jniLibs/*/libabyssal_core.so; do
    if ! grep -aFq "ABYSSAL_E2EE_PAYLOAD_V6" "$artifact"; then
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
  echo "==> Android checks (no APK/AAB packaging)"
  # Keep direct `android` invocations subject to the same supply-chain and
  # generated-artifact checks as the full suite and CI workflow.
  run_shell
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
      :app:compileDebugKotlin \
      :app:compileReleaseKotlin
  )
}

run_android_package() {
  echo "==> Explicit Android package build"
  # Packaging is never a shortcut around the complete non-packaging gate.
  "$ROOT_DIR/check.sh" all
  (
    cd "$ROOT_DIR/android"
    GRADLE_USER_HOME="$GRADLE_HOME" ./gradlew \
      --no-daemon \
      --max-workers=1 \
      --console=plain \
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
  android-package) run_android_package ;;
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
