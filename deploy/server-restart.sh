#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT_DIR"
bash deploy/prepare-runtime-env.sh
docker compose -f deploy/docker-compose.yml create --build --force-recreate --remove-orphans mirage-server
container_id="$(docker compose -f deploy/docker-compose.yml ps -aq mirage-server)"
[[ -n "$container_id" ]] || { echo "Abyssal container was not created." >&2; exit 1; }
echo "Invite codes print once below. Previous RAM state and codes are gone."
timeout --signal=KILL 9s docker start --attach "$container_id" || status=$?
if [[ ${status:-0} -ne 0 && ${status:-0} -ne 137 ]]; then
  exit "$status"
fi
docker compose -f deploy/docker-compose.yml ps
curl --fail --silent http://127.0.0.1:4020/health
echo
