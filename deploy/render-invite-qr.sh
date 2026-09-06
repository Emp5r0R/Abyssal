#!/usr/bin/env bash
set -euo pipefail

[[ $# -le 1 ]] || { printf 'Usage: render-invite-qr.sh [terminal|png]\n' >&2; exit 1; }
case "${1:-terminal}" in
  terminal) format=ANSIUTF8 ;;
  png) format=PNG ;;
  *) printf 'Usage: render-invite-qr.sh [terminal|png]\n' >&2; exit 1 ;;
esac

command -v qrencode >/dev/null 2>&1 || {
  printf 'Install qrencode to render an invite QR in the terminal.\n' >&2
  exit 1
}

export LC_ALL=C
IFS= read -r -n 2049 invite || true
[[ -n "$invite" && ${#invite} -le 2048 ]] || {
  printf 'Expected one bounded invite on standard input.\n' >&2
  exit 1
}
[[ "$invite" == abyssal:invite:* || "$invite" == ABY1-* || "$invite" == aby1-* ]] || {
  printf 'Input is not an Abyssal Invite Capsule text form.\n' >&2
  exit 1
}

printf '%s' "$invite" | qrencode -t "$format" -l M -s 8 -m 4 -o -
unset invite
