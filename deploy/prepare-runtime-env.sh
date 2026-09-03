#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/mirage-server/.env"
ENV_TEMPLATE="$ROOT_DIR/mirage-server/.env.example"
NODE_KEY="$ROOT_DIR/.secrets/node-signing.key"
SECRET_DIR="$ROOT_DIR/.secrets"

if [[ -L "$ENV_FILE" ]]; then
  printf 'Refusing a symlinked relay environment: %s\n' "$ENV_FILE" >&2
  exit 1
fi
if [[ ! -f "$ENV_FILE" ]]; then
  install -m 600 "$ENV_TEMPLATE" "$ENV_FILE"
  printf 'Created relay environment from %s. Review it before public use.\n' "$ENV_TEMPLATE"
else
  chmod 600 "$ENV_FILE"
fi

if [[ ! -e "$SECRET_DIR" ]]; then
  printf 'Stable node signing key is missing. Run: ./deploy/generate-node-key.sh\n' >&2
  exit 1
fi
if [[ ! -d "$SECRET_DIR" || -L "$SECRET_DIR" ]]; then
  printf 'Secret directory must be a real directory: %s\n' "$SECRET_DIR" >&2
  exit 1
fi
secret_mode="$(stat -c '%a' -- "$SECRET_DIR")"
secret_owner="$(stat -c '%u' -- "$SECRET_DIR")"
[[ "$secret_mode" == 700 && "$secret_owner" == "$(id -u)" ]] || {
  printf 'Secret directory must be owned by the deployment user with mode 700: %s\n' "$SECRET_DIR" >&2
  exit 1
}
if [[ ! -f "$NODE_KEY" || -L "$NODE_KEY" ]]; then
  printf 'Stable node signing key is missing. Run: ./deploy/generate-node-key.sh\n' >&2
  exit 1
fi
[[ "$(stat -c '%s' -- "$NODE_KEY")" == 32 ]] || {
  printf 'Node signing key must contain exactly 32 raw bytes: %s\n' "$NODE_KEY" >&2
  exit 1
}
key_mode="$(stat -c '%a' -- "$NODE_KEY")"
key_owner="$(stat -c '%u' -- "$NODE_KEY")"
[[ "$key_mode" == 600 && "$key_owner" == "$(id -u)" ]] || {
  printf 'Node signing key must be owned by the deployment user with mode 600: %s\n' "$NODE_KEY" >&2
  exit 1
}

public_url_count="$(grep -c '^ABYSSAL_PUBLIC_URL=' "$ENV_FILE" || true)"
public_url="$(sed -n 's/^ABYSSAL_PUBLIC_URL=//p' "$ENV_FILE")"
if [[ "$public_url_count" != 1 || -z "$public_url" || "$public_url" == "https://chat.example.com" ]]; then
  printf 'Set exactly one real ABYSSAL_PUBLIC_URL in %s before startup.\n' "$ENV_FILE" >&2
  exit 1
fi
