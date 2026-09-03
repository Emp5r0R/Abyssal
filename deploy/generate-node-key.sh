#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRET_DIR="$ROOT_DIR/.secrets"
NODE_KEY="$SECRET_DIR/node-signing.key"

command -v openssl >/dev/null 2>&1 || {
  printf 'OpenSSL is required to generate the node signing key.\n' >&2
  exit 1
}
[[ ! -L "$SECRET_DIR" ]] || {
  printf 'Refusing a symlinked secret directory: %s\n' "$SECRET_DIR" >&2
  exit 1
}
if [[ -e "$NODE_KEY" || -L "$NODE_KEY" ]]; then
  printf 'Node signing key already exists; refusing to rotate it: %s\n' "$NODE_KEY" >&2
  exit 1
fi

umask 077
mkdir -p -- "$SECRET_DIR"
chmod 700 -- "$SECRET_DIR"
temporary="$SECRET_DIR/.node-signing.key.$$"
cleanup() { rm -f -- "$temporary"; }
trap cleanup EXIT INT TERM
openssl rand -out "$temporary" 32
[[ "$(stat -c '%s' -- "$temporary")" == 32 ]] || {
  printf 'Generated node signing key has an invalid size.\n' >&2
  exit 1
}
chmod 600 -- "$temporary"
ln -- "$temporary" "$NODE_KEY"
rm -f -- "$temporary"
trap - EXIT INT TERM
printf 'Created stable node signing key: %s\n' "$NODE_KEY"
printf 'Back it up securely. Never commit, print, or copy it into a container image.\n'
printf 'The relay prints only its public node fingerprint during startup.\n'
