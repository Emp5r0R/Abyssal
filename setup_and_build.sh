#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="${ABYSSAL_WORKSPACE_DIR:-$ROOT_DIR}"
SDK_DIR="$WORKSPACE_DIR/android-sdk"
OUTPUT_DIR="$WORKSPACE_DIR/build-outputs"
CMDLINE_TOOLS_VERSION="15859902"
CMDLINE_TOOLS_URL="https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS_VERSION}_latest.zip"
CMDLINE_TOOLS_SHA256="4e4c464f145a7512b57d088ac6c278c03c9eea610886b35a5e0804e74eedf583"
CMDLINE_TOOLS_STAMP="$SDK_DIR/.abyssal-commandline-tools-${CMDLINE_TOOLS_VERSION}.verified-archive.sha256"
PACKAGE_DEBUG=false

usage() {
  cat <<'EOF'
Usage: ./setup_and_build.sh [--package-debug]

Sets up the local Android SDK and runs the non-packaging Android verification
by default. Use --package-debug only when an explicit debug APK is required.
EOF
}

case "${1:-}" in
  "") ;;
  --package-debug) PACKAGE_DEBUG=true ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac
[[ $# -le 1 ]] || { usage >&2; exit 2; }

require_commands() {
  local command_name
  for command_name in curl sha256sum unzip; do
    command -v "$command_name" >/dev/null 2>&1 || {
      printf 'Required command is missing: %s\n' "$command_name" >&2
      exit 1
    }
  done
}

install_commandline_tools() {
  local archive extract_dir
  archive="$(mktemp "$WORKSPACE_DIR/cmdline-tools.XXXXXX.zip")"
  extract_dir="$(mktemp -d "$WORKSPACE_DIR/cmdline-tools.XXXXXX")"
  trap 'rm -f "$archive"; rm -rf "$extract_dir"' RETURN

  printf '[+] Downloading Android command-line tools %s...\n' "$CMDLINE_TOOLS_VERSION"
  curl --fail --location --proto '=https' --tlsv1.2 --retry 3 --output "$archive" "$CMDLINE_TOOLS_URL"
  printf '%s  %s\n' "$CMDLINE_TOOLS_SHA256" "$archive" | sha256sum --check --status

  unzip -q "$archive" -d "$extract_dir"
  [[ -d "$extract_dir/cmdline-tools" ]] || {
    printf 'Android command-line tools archive has an unexpected layout.\n' >&2
    exit 1
  }
  rm -rf "$SDK_DIR/cmdline-tools/latest"
  mkdir -p "$SDK_DIR/cmdline-tools/latest"
  cp -a "$extract_dir/cmdline-tools/." "$SDK_DIR/cmdline-tools/latest/"
  # This records that the downloaded archive was verified before extraction;
  # it is not a persistent integrity monitor for the extracted tool tree.
  printf '%s\n' "$CMDLINE_TOOLS_SHA256" > "$CMDLINE_TOOLS_STAMP"
  chmod 0644 "$CMDLINE_TOOLS_STAMP"
  trap - RETURN
  rm -f "$archive"
  rm -rf "$extract_dir"
}

verify_commandline_tools() {
  [[ -x "$SDK_DIR/cmdline-tools/latest/bin/sdkmanager" ]] || {
    printf 'Android command-line tools are incomplete: %s\n' "$SDK_DIR/cmdline-tools/latest" >&2
    exit 1
  }
  [[ -f "$CMDLINE_TOOLS_STAMP" ]] || {
    printf 'Android command-line tools lack an installation checksum stamp: %s\n' "$CMDLINE_TOOLS_STAMP" >&2
    printf 'Remove %s and rerun this script to reinstall verified tools.\n' "$SDK_DIR" >&2
    exit 1
  }
  [[ "$(tr -d '[:space:]' < "$CMDLINE_TOOLS_STAMP")" == "$CMDLINE_TOOLS_SHA256" ]] || {
    printf 'Android command-line tools checksum stamp mismatch.\n' >&2
    exit 1
  }
}

require_commands
mkdir -p "$WORKSPACE_DIR"
cd "$WORKSPACE_DIR"

if [[ ! -x "$SDK_DIR/cmdline-tools/latest/bin/sdkmanager" || \
  ! -f "$CMDLINE_TOOLS_STAMP" || \
  "$(tr -d '[:space:]' < "$CMDLINE_TOOLS_STAMP")" != "$CMDLINE_TOOLS_SHA256" ]]; then
  install_commandline_tools
fi
verify_commandline_tools

printf '[+] Auto-accepting Android SDK licenses...\n'
yes | "$SDK_DIR/cmdline-tools/latest/bin/sdkmanager" --sdk_root="$SDK_DIR" --licenses >/dev/null || {
  status=$?
  [[ "$status" -eq 141 ]] || exit "$status"
}

printf '[+] Installing pinned Android SDK components...\n'
"$SDK_DIR/cmdline-tools/latest/bin/sdkmanager" --sdk_root="$SDK_DIR" \
  "platforms;android-34" "build-tools;34.0.0" "platform-tools"

printf 'sdk.dir=%s\n' "$SDK_DIR" > "$ROOT_DIR/android/local.properties"
"$ROOT_DIR/scripts/verify-gradle-wrapper.sh"

if [[ "$PACKAGE_DEBUG" == true ]]; then
  printf '[+] Explicit debug APK package requested...\n'
  "$ROOT_DIR/check.sh" all
  (
    cd "$ROOT_DIR/android"
    GRADLE_USER_HOME="${ABYSSAL_GRADLE_HOME:-$ROOT_DIR/.gradle-local}" ./gradlew \
      --no-daemon --max-workers=1 --console=plain :app:assembleDebug
  )
  mkdir -p "$OUTPUT_DIR"
  cp "$ROOT_DIR/android/app/build/outputs/apk/debug/app-debug.apk" \
    "$OUTPUT_DIR/abyssal-chat-debug.apk"
  printf 'Debug APK: %s\n' "$OUTPUT_DIR/abyssal-chat-debug.apk"
else
  printf '[+] Running non-packaging Android verification...\n'
  ABYSSAL_GRADLE_HOME="${ABYSSAL_GRADLE_HOME:-$ROOT_DIR/.gradle-local}" \
    "$ROOT_DIR/scripts/test-all.sh" android
fi

printf 'Abyssal setup and verification complete.\n'
