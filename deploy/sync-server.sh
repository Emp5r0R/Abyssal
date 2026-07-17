#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ABYSSAL_SSH_HOST="${ABYSSAL_SSH_HOST:-ubuntu@161.118.195.126}"
ABYSSAL_SSH_KEY="${ABYSSAL_SSH_KEY:-/home/Emp5r0R/Documents/ssh_key.key}"
ABYSSAL_REMOTE_DIR="${ABYSSAL_REMOTE_DIR:-/home/ubuntu/abyssal}"

rsync -az --delete --partial --human-readable --info=progress2,stats2 \
  -e "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i $ABYSSAL_SSH_KEY" \
  --rsync-path="mkdir -p '$ABYSSAL_REMOTE_DIR' && rsync" \
  --exclude '.git/' \
  --exclude '.gradle/' \
  --exclude '.idea/' \
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
