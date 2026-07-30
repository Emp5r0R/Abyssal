#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT_DIR"
bash deploy/prepare-runtime-env.sh
docker compose -f deploy/docker-compose.yml up -d --build --force-recreate --remove-orphans
docker compose -f deploy/docker-compose.yml ps
docker compose -f deploy/docker-compose.yml logs --tail=120 mirage-server
