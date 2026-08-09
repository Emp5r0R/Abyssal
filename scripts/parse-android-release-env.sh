#!/usr/bin/env bash
set -euo pipefail

# Parse the signing file as data. This script must never source or eval it.
# Successful output is four base64 records, in the fixed order below. Base64
# keeps the subprocess interface newline-safe while the input values reject
# control characters, including newlines.

usage() {
  printf 'Usage: %s RELEASE_ENV_FILE\n' "$(basename "$0")" >&2
  exit 2
}

fail() {
  printf 'Invalid Android release signing environment: %s\n' "$1" >&2
  exit 1
}

[[ $# -eq 1 ]] || usage
ENV_FILE=$1

[[ -f "$ENV_FILE" && ! -L "$ENV_FILE" ]] || fail 'environment file must be a regular file'
[[ "$(stat -c '%u' -- "$ENV_FILE")" == "$(id -u)" ]] || fail 'environment file owner must be the current user'
ENV_MODE=$(stat -c '%a' -- "$ENV_FILE")
[[ "$ENV_MODE" =~ ^[0-7]{3,4}$ ]] || fail 'environment file mode is invalid'
(( (0$ENV_MODE & 077) == 0 )) || fail 'environment file is group/world accessible'

declare -A VALUES=()
declare -A SEEN=()
KNOWN_KEYS=(
  ABYSSAL_KEYSTORE_PATH
  ABYSSAL_KEYSTORE_PASSWORD
  ABYSSAL_KEY_ALIAS
  ABYSSAL_KEY_PASSWORD
)

while IFS= read -r line || [[ -n "$line" ]]; do
  case "$line" in
    ''|\#*) continue ;;
  esac

  [[ "$line" == *=* ]] || fail 'each assignment must contain an equals sign'
  key=${line%%=*}
  value=${line#*=}

  case "$key" in
    ABYSSAL_KEYSTORE_PATH|ABYSSAL_KEYSTORE_PASSWORD|ABYSSAL_KEY_ALIAS|ABYSSAL_KEY_PASSWORD) ;;
    *) fail "unknown assignment: $key" ;;
  esac

  [[ -z "${SEEN[$key]+x}" ]] || fail "duplicate assignment: $key"
  [[ -n "$value" ]] || fail "empty assignment: $key"
  [[ ! "$value" =~ [[:cntrl:]] ]] || fail "control character in assignment: $key"

  SEEN[$key]=1
  VALUES[$key]=$value
done < "$ENV_FILE"

for key in "${KNOWN_KEYS[@]}"; do
  [[ -n "${SEEN[$key]+x}" ]] || fail "missing assignment: $key"
done

keystore=${VALUES[ABYSSAL_KEYSTORE_PATH]}
[[ -f "$keystore" && ! -L "$keystore" ]] || fail 'keystore must be a regular file'
[[ -s "$keystore" ]] || fail 'keystore must not be empty'
[[ "$(stat -c '%u' -- "$keystore")" == "$(id -u)" ]] || fail 'keystore owner must be the current user'
KEYSTORE_MODE=$(stat -c '%a' -- "$keystore")
[[ "$KEYSTORE_MODE" =~ ^[0-7]{3,4}$ ]] || fail 'keystore mode is invalid'
(( (0$KEYSTORE_MODE & 077) == 0 )) || fail 'keystore is group/world accessible'

for key in "${KNOWN_KEYS[@]}"; do
  printf '%s' "${VALUES[$key]}" | base64 | tr -d '\n'
  printf '\n'
done
