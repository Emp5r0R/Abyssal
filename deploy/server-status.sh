#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE=(docker compose -f "$ROOT_DIR/deploy/docker-compose.yml")

cd "$ROOT_DIR"
"${COMPOSE[@]}" ps --all

container_id="$("${COMPOSE[@]}" ps -aq mirage-server)"
if [[ -z "$container_id" ]]; then
  printf 'Abyssal container is not created.\n' >&2
  exit 1
fi

container_state="$(docker inspect --format '{{.State.Status}}' "$container_id")"
health_state="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}unconfigured{{end}}' "$container_id")"
printf 'Container state: %s\nHealth state: %s\n' "$container_state" "$health_state"

if [[ "$container_state" != running || "$health_state" != healthy ]]; then
  printf 'Abyssal is not healthy. Docker log persistence is disabled; inspect the attached startup output.\n' >&2
  exit 1
fi
