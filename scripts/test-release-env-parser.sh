#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PARSER="$ROOT_DIR/scripts/parse-android-release-env.sh"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
  printf 'release env parser test failed: %s\n' "$1" >&2
  exit 1
}

[[ -x "$PARSER" ]] || fail 'parser is not executable'

KEYSTORE="$TMP_DIR/keystore with spaces.jks"
printf 'test keystore\n' >"$KEYSTORE"
chmod 600 "$KEYSTORE"

ENV_FILE="$TMP_DIR/release.env"
MARKER="$TMP_DIR/should-not-exist"
HOSTILE_VALUE="\$(touch '$MARKER'); \`touch '$MARKER'\`=literal"

write_valid_env() {
  printf '%s\n' \
    '# Literal data only.' \
    "ABYSSAL_KEYSTORE_PATH=$KEYSTORE" \
    "ABYSSAL_KEYSTORE_PASSWORD=$HOSTILE_VALUE" \
    'ABYSSAL_KEY_ALIAS=alias with spaces' \
    "ABYSSAL_KEY_PASSWORD=$HOSTILE_VALUE" >"$ENV_FILE"
  chmod 600 "$ENV_FILE"
}

decode() {
  printf '%s' "$1" | base64 --decode
}

assert_valid_values() {
  local output
  output=$("$PARSER" "$ENV_FILE") || fail 'valid data-only file rejected'
  mapfile -t records <<<"$output"
  [[ "${#records[@]}" -eq 4 ]] || fail 'valid file did not produce four records'
  [[ "$(decode "${records[0]}")" == "$KEYSTORE" ]] || fail 'path was not preserved'
  [[ "$(decode "${records[1]}")" == "$HOSTILE_VALUE" ]] || fail 'password was not preserved'
  [[ "$(decode "${records[2]}")" == 'alias with spaces' ]] || fail 'alias was not preserved'
  [[ "$(decode "${records[3]}")" == "$HOSTILE_VALUE" ]] || fail 'key password was not preserved'
  [[ ! -e "$MARKER" ]] || fail 'shell metacharacters were executed'
}

assert_rejected() {
  local description=$1
  if "$PARSER" "$ENV_FILE" >/dev/null 2>&1; then
    fail "$description was accepted"
  fi
  [[ ! -e "$MARKER" ]] || fail "$description executed shell metacharacters"
}

write_valid_env
assert_valid_values

printf '%s\n' \
  "ABYSSAL_KEYSTORE_PATH=$KEYSTORE" \
  "ABYSSAL_KEYSTORE_PASSWORD=$HOSTILE_VALUE" \
  'ABYSSAL_KEY_ALIAS=alias with spaces' \
  "ABYSSAL_KEY_PASSWORD=$HOSTILE_VALUE" \
  'UNKNOWN=value' >"$ENV_FILE"
chmod 600 "$ENV_FILE"
assert_rejected 'unknown assignment'

write_valid_env
printf 'ABYSSAL_KEY_ALIAS=duplicate\n' >>"$ENV_FILE"
assert_rejected 'duplicate assignment'

write_valid_env
printf 'MALFORMED\n' >>"$ENV_FILE"
assert_rejected 'malformed assignment'

write_valid_env
printf 'ABYSSAL_KEY_ALIAS=bad\tvalue\n' >>"$ENV_FILE"
assert_rejected 'control character'

write_valid_env
chmod 640 "$ENV_FILE"
assert_rejected 'insecure environment mode'

write_valid_env
chmod 600 "$KEYSTORE"
ln -s "$ENV_FILE" "$TMP_DIR/release-env-link"
ENV_FILE="$TMP_DIR/release-env-link"
assert_rejected 'environment symlink'

ENV_FILE="$TMP_DIR/release.env"
write_valid_env
chmod 640 "$KEYSTORE"
assert_rejected 'insecure keystore mode'

printf 'release env parser tests passed\n'
