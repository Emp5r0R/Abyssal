#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source "$SCRIPT_DIR/remote-env.sh"

ssh \
  -o StrictHostKeyChecking=accept-new \
  -i "$ABYSSAL_SSH_KEY" \
  "$ABYSSAL_SSH_HOST" \
  "cd '$ABYSSAL_REMOTE_DIR' && docker compose -f deploy/docker-compose.yml down"
