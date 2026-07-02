#!/usr/bin/env bash
set -euo pipefail

ABYSSAL_SSH_HOST="${ABYSSAL_SSH_HOST:-ubuntu@161.118.195.126}"
ABYSSAL_SSH_KEY="${ABYSSAL_SSH_KEY:-/home/Emp5r0R/Documents/ssh_key.key}"
ABYSSAL_REMOTE_DIR="${ABYSSAL_REMOTE_DIR:-/home/ubuntu/abyssal}"

ssh \
  -o UserKnownHostsFile=/dev/null \
  -o StrictHostKeyChecking=no \
  -i "$ABYSSAL_SSH_KEY" \
  "$ABYSSAL_SSH_HOST" \
  "cd '$ABYSSAL_REMOTE_DIR' && docker compose -f deploy/docker-compose.yml up -d --build --remove-orphans && docker compose -f deploy/docker-compose.yml ps && docker compose -f deploy/docker-compose.yml logs --tail=120 mirage-server"
