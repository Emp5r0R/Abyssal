#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

source "$SCRIPT_DIR/remote-env.sh"

printf -v REMOTE_RSYNC_PATH \
  'mkdir -p -- %q && rsync' \
  "$ABYSSAL_REMOTE_DIR"

SYNC_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$SYNC_DIR"
}
trap cleanup EXIT INT TERM

git -C "$ROOT_DIR" archive --format=tar HEAD | tar -xf - -C "$SYNC_DIR"

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
