#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source "$SCRIPT_DIR/remote-env.sh"

printf -v REMOTE_COMMAND 'cd %q && bash deploy/server-stop.sh' \
  "$ABYSSAL_REMOTE_DIR"

ssh "${ABYSSAL_SSH_OPTIONS[@]}" \
  "$ABYSSAL_SSH_HOST" \
  "$REMOTE_COMMAND"
