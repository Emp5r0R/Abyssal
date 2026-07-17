#!/usr/bin/env bash

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ABYSSAL_DEPLOY_ENV="${ABYSSAL_DEPLOY_ENV:-$DEPLOY_DIR/deploy.env}"

override_ssh_host="${ABYSSAL_SSH_HOST:-}"
override_ssh_key="${ABYSSAL_SSH_KEY:-}"
override_remote_dir="${ABYSSAL_REMOTE_DIR:-}"

if [[ -f "$ABYSSAL_DEPLOY_ENV" ]]; then
  # shellcheck disable=SC1090
  source "$ABYSSAL_DEPLOY_ENV"
fi

[[ -n "$override_ssh_host" ]] && ABYSSAL_SSH_HOST="$override_ssh_host"
[[ -n "$override_ssh_key" ]] && ABYSSAL_SSH_KEY="$override_ssh_key"
[[ -n "$override_remote_dir" ]] && ABYSSAL_REMOTE_DIR="$override_remote_dir"

: "${ABYSSAL_SSH_HOST:?Set ABYSSAL_SSH_HOST or create deploy/deploy.env}"
: "${ABYSSAL_SSH_KEY:?Set ABYSSAL_SSH_KEY or create deploy/deploy.env}"
ABYSSAL_REMOTE_DIR="${ABYSSAL_REMOTE_DIR:-/home/ubuntu/abyssal}"

if [[ ! -f "$ABYSSAL_SSH_KEY" ]]; then
  printf 'SSH key does not exist: %s\n' "$ABYSSAL_SSH_KEY" >&2
  exit 1
fi

export ABYSSAL_SSH_HOST ABYSSAL_SSH_KEY ABYSSAL_REMOTE_DIR

unset override_ssh_host override_ssh_key override_remote_dir
