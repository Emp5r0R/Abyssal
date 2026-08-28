#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

source "$SCRIPT_DIR/remote-env.sh"

RELEASE_OUTPUT_DIR="${ABYSSAL_RELEASE_OUTPUT_DIR:-$ROOT_DIR/build-outputs}"
RELEASE_MANIFEST="${ABYSSAL_WEB_RELEASE_MANIFEST:-${ABYSSAL_RELEASE_MANIFEST:-$RELEASE_OUTPUT_DIR/release-manifest-v1.json}}"
RELEASE_SIGNATURE="${ABYSSAL_WEB_RELEASE_SIGNATURE:-${ABYSSAL_RELEASE_SIGNATURE:-$RELEASE_OUTPUT_DIR/release-manifest-v1.sig}}"
WEB_ARCHIVE="${ABYSSAL_WEB_RELEASE_ARCHIVE:-${ABYSSAL_WEB_ARCHIVE:-}}"

if [[ -n "${ABYSSAL_RELEASE_TOOL:-}" ]]; then
  RELEASE_TOOL_COMMAND=("$ABYSSAL_RELEASE_TOOL")
  [[ -x "$ABYSSAL_RELEASE_TOOL" && ! -L "$ABYSSAL_RELEASE_TOOL" ]] || {
    printf 'Configured release verifier must be an executable regular non-symlink file: %s\n' \
      "$ABYSSAL_RELEASE_TOOL" >&2
    exit 1
  }
else
  command -v cargo >/dev/null 2>&1 || {
    printf 'No release verifier configured. Install the pinned Rust toolchain from rust-toolchain.toml or set ABYSSAL_RELEASE_TOOL to a reviewed verifier binary.\n' >&2
    exit 1
  }
  [[ -f "$ROOT_DIR/rust-toolchain.toml" && -f "$ROOT_DIR/Cargo.lock" ]] || {
    printf 'No release verifier configured and the pinned Rust source prerequisites are missing (rust-toolchain.toml/Cargo.lock).\n' >&2
    exit 1
  }
  RELEASE_TOOL_COMMAND=(
    cargo run --quiet --locked --release
    --manifest-path "$ROOT_DIR/Cargo.toml"
    --package abyssal-release-tool --
  )
fi

run_release_tool() {
  "${RELEASE_TOOL_COMMAND[@]}" "$@"
}

[[ -f "$RELEASE_MANIFEST" && ! -L "$RELEASE_MANIFEST" ]] || {
  printf 'Signed release manifest must be a regular non-symlink file: %s\n' \
    "$RELEASE_MANIFEST" >&2
  exit 1
}
[[ -f "$RELEASE_SIGNATURE" && ! -L "$RELEASE_SIGNATURE" ]] || {
  printf 'Signed release signature must be a regular non-symlink file: %s\n' \
    "$RELEASE_SIGNATURE" >&2
  exit 1
}

if [[ -z "$WEB_ARCHIVE" ]]; then
  mapfile -t web_archives < <(
    find "$RELEASE_OUTPUT_DIR" -maxdepth 1 -type f -name 'abyssal-web-*.tar.gz' -print
  )
  [[ ${#web_archives[@]} -eq 1 ]] || {
    printf 'Expected exactly one signed web archive in %s; set ABYSSAL_WEB_RELEASE_ARCHIVE explicitly.\n' \
      "$RELEASE_OUTPUT_DIR" >&2
    exit 1
  }
  WEB_ARCHIVE="${web_archives[0]}"
fi
[[ -f "$WEB_ARCHIVE" && ! -L "$WEB_ARCHIVE" ]] || {
  printf 'Signed web archive must be a regular non-symlink file: %s\n' "$WEB_ARCHIVE" >&2
  exit 1
}

SOURCE_COMMIT="$(git -C "$ROOT_DIR" rev-parse --verify HEAD^{commit})"
ARCHIVE_NAME="$(basename -- "$WEB_ARCHIVE")"
run_release_tool verify-web-archive \
  --manifest "$RELEASE_MANIFEST" \
  --signature "$RELEASE_SIGNATURE" \
  --archive "$WEB_ARCHIVE" \
  --source-commit "$SOURCE_COMMIT"

printf -v REMOTE_RSYNC_PATH \
  'mkdir -p -- %q && rsync' \
  "$ABYSSAL_REMOTE_DIR"

SYNC_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$SYNC_DIR"
}
trap cleanup EXIT INT TERM

git -C "$ROOT_DIR" archive --format=tar "$SOURCE_COMMIT" | tar -xf - --no-same-owner -C "$SYNC_DIR"

WEB_STAGE_DIR="$SYNC_DIR/.web-release"
mkdir -p "$WEB_STAGE_DIR"
STAGED_ARCHIVE="$WEB_STAGE_DIR/$ARCHIVE_NAME"
cp --reflink=auto -- "$WEB_ARCHIVE" "$STAGED_ARCHIVE"
run_release_tool verify-web-archive \
  --manifest "$RELEASE_MANIFEST" \
  --signature "$RELEASE_SIGNATURE" \
  --archive "$STAGED_ARCHIVE" \
  --source-commit "$SOURCE_COMMIT"

rsync -az --checksum --delete --partial --human-readable --info=progress2,stats2 \
  -e "$ABYSSAL_SSH_COMMAND" \
  --rsync-path="$REMOTE_RSYNC_PATH" \
  --exclude '.git/' \
  --exclude '.secrets/' \
  --exclude 'README.local.md' \
  --exclude 'deploy/deploy.env' \
  --exclude 'deploy/release.env' \
  --exclude 'mirage-server/.env' \
  "$SYNC_DIR/" \
  "$ABYSSAL_SSH_HOST:$ABYSSAL_REMOTE_DIR/"

echo "Synced committed Abyssal snapshot to $ABYSSAL_SSH_HOST:$ABYSSAL_REMOTE_DIR"
