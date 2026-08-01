#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT_DIR"
bash deploy/prepare-runtime-env.sh
docker compose -f deploy/docker-compose.yml up -d --build --force-recreate --remove-orphans
docker compose -f deploy/docker-compose.yml ps
container_id="$(docker compose -f deploy/docker-compose.yml ps -q mirage-server)"
echo "Invite codes print once below. Previous RAM state and codes are gone."
timeout 9s docker attach --sig-proxy=false "$container_id" || status=$?
if [[ ${status:-0} -ne 0 && ${status:-0} -ne 124 ]]; then
  exit "$status"
fi
curl --fail --silent http://127.0.0.1:4020/health
echo
