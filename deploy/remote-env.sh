#!/usr/bin/env bash

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ABYSSAL_DEPLOY_ENV="${ABYSSAL_DEPLOY_ENV:-$DEPLOY_DIR/deploy.env}"

override_ssh_host="${ABYSSAL_SSH_HOST:-}"
override_ssh_key="${ABYSSAL_SSH_KEY:-}"
override_remote_dir="${ABYSSAL_REMOTE_DIR:-}"
override_ssh_known_hosts="${ABYSSAL_SSH_KNOWN_HOSTS:-}"

if [[ -f "$ABYSSAL_DEPLOY_ENV" ]]; then
  # Parse the tiny deployment configuration as data. Sourcing this file would
  # execute shell metacharacters from a mistaken or compromised local config.
  while IFS= read -r config_line || [[ -n "$config_line" ]]; do
    config_line="${config_line%$'\r'}"
    [[ "$config_line" =~ ^[[:space:]]*$ || "$config_line" =~ ^[[:space:]]*# ]] && continue
    if [[ ! "$config_line" =~ ^[[:space:]]*(ABYSSAL_SSH_HOST|ABYSSAL_SSH_KEY|ABYSSAL_SSH_KNOWN_HOSTS|ABYSSAL_REMOTE_DIR)[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]]; then
      printf 'Unsupported or malformed deployment setting in %s.\n' "$ABYSSAL_DEPLOY_ENV" >&2
      exit 1
    fi
    setting_name="${BASH_REMATCH[1]}"
    setting_value="${BASH_REMATCH[2]}"
    if [[ "$setting_value" == \"*\" || "$setting_value" == \'*\' ]]; then
      [[ "${setting_value: -1}" == "${setting_value:0:1}" ]] || {
        printf 'Unterminated quoted deployment setting in %s.\n' "$ABYSSAL_DEPLOY_ENV" >&2
        exit 1
      }
      setting_value="${setting_value:1:${#setting_value}-2}"
    fi
    [[ "$setting_value" != *'$('* && "$setting_value" != *'`'* && \
      "$setting_value" != *';'* && "$setting_value" != *'|'* && \
      "$setting_value" != *'&'* && "$setting_value" != *'<'* && \
      "$setting_value" != *'>'* && "$setting_value" != *'\\'* ]] || {
      printf 'Unsafe deployment setting in %s.\n' "$ABYSSAL_DEPLOY_ENV" >&2
      exit 1
    }
    setting_value="${setting_value//\$HOME/$HOME}"
    printf -v "$setting_name" '%s' "$setting_value"
  done < "$ABYSSAL_DEPLOY_ENV"
fi

[[ -n "$override_ssh_host" ]] && ABYSSAL_SSH_HOST="$override_ssh_host"
[[ -n "$override_ssh_key" ]] && ABYSSAL_SSH_KEY="$override_ssh_key"
[[ -n "$override_ssh_known_hosts" ]] && ABYSSAL_SSH_KNOWN_HOSTS="$override_ssh_known_hosts"
[[ -n "$override_remote_dir" ]] && ABYSSAL_REMOTE_DIR="$override_remote_dir"

validate_ssh_host() {
  local value="$1"
  if [[ ! "$value" =~ ^[A-Za-z_][A-Za-z0-9._-]*@([A-Za-z0-9._-]+|\[[A-Fa-f0-9:]+\])$ ]]; then
    printf 'Unsafe SSH target; expected user@host: %s\n' "$value" >&2
    return 1
  fi
}

validate_remote_dir() {
  local value="$1"
  if [[ ! "$value" =~ ^/([A-Za-z0-9._~+-]+/)*[A-Za-z0-9._~+-]+$ ]] ||
    [[ "$value" == *//* || "$value" == */./* || "$value" == */../* ||
      "$value" == */. || "$value" == */.. ]]; then
    printf 'Unsafe remote directory; expected a canonical non-root absolute path: %s\n' \
      "$value" >&2
    return 1
  fi
}

validate_ssh_key() {
  local value="$1"
  if [[ "$value" == *$'\n'* || "$value" == *$'\r'* || "$value" == *$'\t'* ]]; then
    printf 'Unsafe SSH key path; control characters are not allowed.\n' >&2
    return 1
  fi
  if [[ ! -f "$value" ]]; then
    printf 'SSH key does not exist: %s\n' "$value" >&2
    return 1
  fi
}

validate_ssh_known_hosts() {
  local value="$1"
  if [[ -z "$value" || "$value" =~ [[:cntrl:]] ]]; then
    printf 'Unsafe SSH known-hosts path; control characters are not allowed.\n' >&2
    return 1
  fi
  if [[ ! -f "$value" || ! -r "$value" ]]; then
    printf 'SSH known-hosts file must be a readable regular file: %s\n' "$value" >&2
    return 1
  fi
}

: "${ABYSSAL_SSH_HOST:?Set ABYSSAL_SSH_HOST or create deploy/deploy.env}"
: "${ABYSSAL_SSH_KEY:?Set ABYSSAL_SSH_KEY or create deploy/deploy.env}"
ABYSSAL_SSH_KNOWN_HOSTS="${ABYSSAL_SSH_KNOWN_HOSTS:-$HOME/.ssh/known_hosts}"
ABYSSAL_REMOTE_DIR="${ABYSSAL_REMOTE_DIR:-/home/ubuntu/abyssal}"

validate_ssh_host "$ABYSSAL_SSH_HOST" || exit 1
validate_ssh_key "$ABYSSAL_SSH_KEY" || exit 1
validate_ssh_known_hosts "$ABYSSAL_SSH_KNOWN_HOSTS" || exit 1
validate_remote_dir "$ABYSSAL_REMOTE_DIR" || exit 1

ABYSSAL_SSH_OPTIONS=(
  -o BatchMode=yes
  -o IdentitiesOnly=yes
  -o StrictHostKeyChecking=yes
  -o "UserKnownHostsFile=$ABYSSAL_SSH_KNOWN_HOSTS"
  -i "$ABYSSAL_SSH_KEY"
)
printf -v ABYSSAL_SSH_COMMAND \
  'ssh -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=%q -i %q' \
  "$ABYSSAL_SSH_KNOWN_HOSTS" "$ABYSSAL_SSH_KEY"

export ABYSSAL_SSH_HOST ABYSSAL_SSH_KEY ABYSSAL_SSH_KNOWN_HOSTS \
  ABYSSAL_REMOTE_DIR ABYSSAL_SSH_COMMAND

unset override_ssh_host override_ssh_key override_ssh_known_hosts override_remote_dir
unset setting_name setting_value config_line
