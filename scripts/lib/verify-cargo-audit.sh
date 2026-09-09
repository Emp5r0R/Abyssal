#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'Usage: %s <exit-status> <report-file> <stderr-file>\n' \
    "${BASH_SOURCE[0]}" >&2
}

if [[ $# -ne 3 ]]; then
  usage
  exit 2
fi

exit_status="$1"
report_file="$2"
stderr_file="$3"

if [[ ! "$exit_status" =~ ^[0-9]+$ ]] || (( exit_status > 255 )); then
  printf 'Invalid cargo audit exit status: %s\n' "$exit_status" >&2
  exit 2
fi

if (( exit_status != 0 )); then
  printf 'cargo audit failed with exit status %s.\n' "$exit_status" >&2
  exit "$exit_status"
fi

if [[ ! -f "$report_file" ]] || [[ ! -s "$report_file" ]]; then
  printf 'cargo audit returned success without a report: %s\n' \
    "$report_file" >&2
  exit 1
fi

if [[ ! -f "$stderr_file" ]]; then
  printf 'cargo audit stderr capture is missing: %s\n' "$stderr_file" >&2
  exit 1
fi

if [[ -s "$stderr_file" ]]; then
  printf 'cargo audit emitted diagnostics; refusing to accept an incomplete report:\n' >&2
  cat -- "$stderr_file" >&2
  exit 1
fi

if ! jq -e -s '
  if length != 1 then
    false
  else
    .[0]
    | type == "object"
    and (.database | type == "object")
    and (.database["advisory-count"] | type == "number" and floor == . and . > 0)
    and (.database | has("last-commit") and has("last-updated"))
    and (.database["last-commit"] | . == null or type == "string")
    and (.database["last-updated"] | . == null or type == "string")
    and (.lockfile | type == "object")
    and (.lockfile["dependency-count"] | type == "number" and floor == . and . > 0)
    and (.settings | type == "object")
    and (.settings.target_arch | type == "array" and length == 0)
    and (.settings.target_os | type == "array" and length == 0)
    and (.settings | has("severity"))
    and (.settings.severity == null)
    and (.settings.ignore | type == "array" and length == 0)
    and (.settings.informational_warnings | type == "array")
    and (.settings.informational_warnings | index("unmaintained") != null)
    and (.settings.informational_warnings | index("unsound") != null)
    and (.settings.informational_warnings | index("notice") != null)
    and (.vulnerabilities | type == "object")
    and (.vulnerabilities.found | type == "boolean" and . == false)
    and (.vulnerabilities.count | type == "number" and floor == . and . == 0)
    and (.vulnerabilities.list | type == "array" and length == 0)
    and (.warnings | type == "object" and length == 0)
  end
' "$report_file" >/dev/null 2>&1; then
  printf 'cargo audit returned an invalid or non-clean JSON report: %s\n' \
    "$report_file" >&2
  exit 1
fi
