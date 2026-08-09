#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

printf 'Docker log persistence is disabled; reporting status and health instead.\n'
exec "$SCRIPT_DIR/server-status.sh"
