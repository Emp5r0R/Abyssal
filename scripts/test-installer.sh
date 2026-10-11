#!/usr/bin/env bash
# Unit checks for deploy/install.sh: argument validation and every rendered file,
# without touching the host. The installer is sourced with main() disabled.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT INT TERM

fail() { printf 'installer check failed: %s\n' "$1" >&2; exit 1; }

bash -n "$ROOT_DIR/deploy/install.sh" || fail 'syntax'

# Each case runs in a subshell because parse_args exits on invalid input.
accepts() { ( ABYSSAL_INSTALL_SOURCED=1; source "$ROOT_DIR/deploy/install.sh"; parse_args "$@" ) >/dev/null 2>&1; }
rejects() { if accepts "$@"; then fail "accepted: $*"; fi; }

accepts install --domain chat.example.com || fail 'plain install'
accepts --domain Chat.Example.COM --version v3.4.0 --proxy none --port 4021 --invites 0 -y || fail 'full options'
accepts upgrade --version 3.4.1 || fail 'upgrade'
accepts status || fail 'status'
accepts --help || fail 'help'
rejects --domain 'chat.example.com;rm -rf /'
rejects --domain localhost
rejects --domain '-bad.example.com'
rejects --domain "$(printf 'a%.0s' {1..64}).example.com"
rejects --email 'not an email'
rejects --version 3.4
rejects --version '3.4.0; true'
rejects --repo 'owner/name/extra'
rejects --proxy nginx
rejects --port 0
rejects --port 70000
rejects --invites 257
rejects --unknown
rejects destroy

(
  ABYSSAL_INSTALL_SOURCED=1
  # shellcheck source=../deploy/install.sh
  source "$ROOT_DIR/deploy/install.sh"

  template="$ROOT_DIR/mirage-server/.env.example"
  fresh="$(render_env "$template" "$TEMP_DIR/missing.env" chat.example.com 12)"
  grep -Fxq 'ABYSSAL_PUBLIC_URL=https://chat.example.com' <<<"$fresh" || fail 'fresh env sets the public URL'
  grep -Fxq 'ABYSSAL_INVITE_COUNT=12' <<<"$fresh" || fail 'fresh env sets the invite count'
  grep -Fxq 'ABYSSAL_INVITE_TEXT_ENABLED=true' <<<"$fresh" || fail 'fresh env prints invite codes'
  ! grep -q '^ABYSSAL_BIND_ADDR=\|^ABYSSAL_NODE_SIGNING_KEY_FILE=' <<<"$fresh" || fail 'compose owns bind address and key path'
  [[ "$(grep -c '^ABYSSAL_PUBLIC_URL=' <<<"$fresh")" == 1 ]] || fail 'exactly one public URL'

  printf 'ABYSSAL_PUBLIC_URL=https://old.example.com\nABYSSAL_INVITE_COUNT=3\nABYSSAL_MAX_ROOMS_PER_USER=9\n' > "$TEMP_DIR/existing.env"
  kept="$(render_env "$template" "$TEMP_DIR/existing.env" '' '')"
  grep -Fxq 'ABYSSAL_PUBLIC_URL=https://old.example.com' <<<"$kept" || fail 'upgrade keeps the public URL'
  grep -Fxq 'ABYSSAL_INVITE_COUNT=3' <<<"$kept" || fail 'upgrade keeps the invite count'
  grep -Fxq 'ABYSSAL_MAX_ROOMS_PER_USER=9' <<<"$kept" || fail 'upgrade keeps operator settings'
  grep -Fxq 'ABYSSAL_INVITE_TEXT_ENABLED=true' <<<"$kept" || fail 'upgrade adds invite codes to old settings'
  moved="$(render_env "$template" "$TEMP_DIR/existing.env" new.example.com '')"
  grep -Fxq 'ABYSSAL_PUBLIC_URL=https://new.example.com' <<<"$moved" || fail 'explicit domain replaces the URL'
  [[ "$(env_public_url "$TEMP_DIR/existing.env")" == https://old.example.com ]] || fail 'reads the public URL'

  with_caddy="$(render_compose /opt/abyssal/releases/3.4.0 3.4.0 999 998 4020 caddy 1536m)"
  for expected in \
    'image: abyssal-relay:3.4.0' 'user: "999:998"' 'restart: "no"' 'read_only: true' 'driver: none' \
    '"127.0.0.1:4020:4020"' 'no-new-privileges:true' 'mem_limit: 1536m' "$CADDY_IMAGE" '"443:443"' \
    'context: /opt/abyssal/releases/3.4.0' 'node-signing.key:/run/secrets/abyssal-node-signing-key:ro'; do
    grep -Fq -- "$expected" <<<"$with_caddy" || fail "compose lacks: $expected"
  done
  [[ "$CADDY_IMAGE" == *@sha256:* ]] || fail 'caddy image is pinned by digest'
  without_caddy="$(render_compose /opt/abyssal/releases/3.4.0 3.4.0 999 998 4021 none 2048m)"
  ! grep -q 'caddy' <<<"$without_caddy" || fail 'proxy none adds no caddy service'
  grep -Fq '"127.0.0.1:4021:4020"' <<<"$without_caddy" || fail 'custom port stays on loopback'
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    printf '%s\n' "$with_caddy" > "$TEMP_DIR/compose.yml"
    docker compose -f "$TEMP_DIR/compose.yml" config --quiet 2>/dev/null || {
      # env_file must exist for config validation; create placeholders and retry.
      mkdir -p "$TEMP_DIR/etc"
      sed "s#$CONFIG_DIR#$TEMP_DIR/etc#g" "$TEMP_DIR/compose.yml" > "$TEMP_DIR/compose-local.yml"
      : > "$TEMP_DIR/etc/relay.env"
      docker compose -f "$TEMP_DIR/compose-local.yml" config --quiet || fail 'compose file is valid'
    }
  fi

  caddy="$(render_caddyfile chat.example.com ops@example.com)"
  grep -Fq 'email ops@example.com' <<<"$caddy" || fail 'caddy contact email'
  grep -Fq 'chat.example.com {' <<<"$caddy" || fail 'caddy site'
  grep -Fq 'reverse_proxy relay:4020' <<<"$caddy" || fail 'caddy upstream'
  ! grep -q 'encode' <<<"$caddy" || fail 'caddy must not transform responses'
  ! grep -q 'email' <<<"$(render_caddyfile chat.example.com '')" || fail 'no email block without an email'

  [[ "$(relay_memory_limit 16000000)" == 2048m ]] || fail 'memory cap'
  [[ "$(relay_memory_limit 1000000)" == 768m ]] || fail 'memory floor'
  [[ "$(relay_memory_limit 2000000)" == 1464m ]] || fail 'memory share'

  [[ "$(decide_proxy auto 0 0)" == caddy ]] || fail 'auto picks caddy on free ports'
  [[ "$(decide_proxy auto 1 0)" == none ]] || fail 'auto backs off when 80 is busy'
  [[ "$(decide_proxy auto 0 1)" == none ]] || fail 'auto backs off when 443 is busy'
  [[ "$(decide_proxy none 0 0)" == none ]] || fail 'explicit none'
  [[ "$(decide_proxy caddy 1 1)" == caddy ]] || fail 'explicit caddy is kept for the caller to reject'

  printf 'bundle' > "$TEMP_DIR/bundle.tar.gz"
  good="$(sha256sum "$TEMP_DIR/bundle.tar.gz")"
  verify_sha256 "$TEMP_DIR/bundle.tar.gz" "${good%% *}  abyssal-server-3.4.0.tar.gz" || fail 'accepts the right checksum'
  ! verify_sha256 "$TEMP_DIR/bundle.tar.gz" "$(printf '0%.0s' {1..64})  x" || fail 'rejects a wrong checksum'
  ! verify_sha256 "$TEMP_DIR/bundle.tar.gz" 'not-a-checksum' || fail 'rejects a malformed checksum'
)

printf 'Installer checks passed.\n'
