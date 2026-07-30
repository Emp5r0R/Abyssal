#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/mirage-server/.env"
ENV_TEMPLATE="$ROOT_DIR/mirage-server/.env.example"

if [[ ! -f "$ENV_FILE" ]]; then
  install -m 600 "$ENV_TEMPLATE" "$ENV_FILE"
  printf 'Created relay environment from %s. Review it before public use.\n' "$ENV_TEMPLATE"
else
  chmod 600 "$ENV_FILE"
fi
