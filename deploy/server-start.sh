#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT_DIR"
bash deploy/prepare-runtime-env.sh
if [[ -n "$(docker compose -f deploy/docker-compose.yml ps -q mirage-server)" ]]; then
  echo "Abyssal is already running; startup codes cannot be recovered."
  docker compose -f deploy/docker-compose.yml ps
  curl --fail --silent http://127.0.0.1:4020/health
  echo
  exit 0
fi
docker compose -f deploy/docker-compose.yml create --build --remove-orphans mirage-server
container_id="$(docker compose -f deploy/docker-compose.yml ps -aq mirage-server)"
[[ -n "$container_id" ]] || { echo "Abyssal container was not created." >&2; exit 1; }
echo "Invite codes print once below. They cannot be retrieved after this attachment closes."
timeout --signal=KILL 9s docker start --attach "$container_id" || status=$?
if [[ ${status:-0} -ne 0 && ${status:-0} -ne 137 ]]; then
  exit "$status"
fi
docker compose -f deploy/docker-compose.yml ps
curl --fail --silent http://127.0.0.1:4020/health
echo
