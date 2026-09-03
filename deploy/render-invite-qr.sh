#!/usr/bin/env bash
set -euo pipefail

command -v qrencode >/dev/null 2>&1 || {
  printf 'Install qrencode to render an invite QR in the terminal.\n' >&2
  exit 1
}

IFS= read -r invite
[[ -n "$invite" && ${#invite} -le 2048 ]] || {
  printf 'Expected one bounded invite on standard input.\n' >&2
  exit 1
}
[[ "$invite" == abyssal:invite:* || "$invite" == ABY1-* || "$invite" == aby1-* ]] || {
  printf 'Input is not an Abyssal Invite Capsule text form.\n' >&2
  exit 1
}

printf '%s' "$invite" | qrencode -t ANSIUTF8
unset invite
