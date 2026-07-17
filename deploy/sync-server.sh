#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

source "$SCRIPT_DIR/remote-env.sh"

rsync -az --delete --partial --human-readable --info=progress2,stats2 \
  -e "ssh -o StrictHostKeyChecking=accept-new -i $ABYSSAL_SSH_KEY" \
  --rsync-path="mkdir -p '$ABYSSAL_REMOTE_DIR' && rsync" \
  --exclude '.git/' \
  --exclude '.gradle/' \
  --exclude '.idea/' \
  --exclude 'README.local.md' \
  --exclude 'deploy/deploy.env' \
  --exclude 'node_modules/' \
  --exclude 'target/' \
  --include '.env.example' \
  --exclude '.env' \
  --exclude '.env.*' \
  --exclude 'android/.gradle/' \
  --exclude 'android/app/build/' \
  --exclude 'android/build/' \
  --exclude 'build-outputs/' \
  --exclude 'apps/web/dist/' \
  --exclude 'apps/web/coverage/' \
  --exclude 'mirage-server/target/' \
  --exclude 'rust-core/target/' \
  "$ROOT_DIR/" \
  "$ABYSSAL_SSH_HOST:$ABYSSAL_REMOTE_DIR/"

echo "Synced Abyssal to $ABYSSAL_SSH_HOST:$ABYSSAL_REMOTE_DIR"
