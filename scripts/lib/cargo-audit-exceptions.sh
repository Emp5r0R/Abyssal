#!/usr/bin/env bash
# Prints the reviewed RustSec exception IDs, sorted, one per line.
# Fails on a malformed, duplicate or expired entry so an exception cannot
# outlive its review date or silently widen.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  printf 'Usage: %s <exceptions.tsv> [today YYYY-MM-DD]\n' "${BASH_SOURCE[0]}" >&2
  exit 2
fi

exceptions_file="$1"
today="${2:-$(date -u +%Y-%m-%d)}"
max_entries=8

if [[ ! "$today" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
  printf 'Invalid date: %s\n' "$today" >&2
  exit 2
fi
if [[ ! -f "$exceptions_file" || -L "$exceptions_file" ]]; then
  printf 'Missing cargo audit exceptions file: %s\n' "$exceptions_file" >&2
  exit 1
fi

declare -A seen=()
ids=()
line_number=0
while IFS= read -r line || [[ -n "$line" ]]; do
  line_number=$((line_number + 1))
  [[ -z "$line" || "$line" == \#* ]] && continue
  IFS=$'\t' read -r id review_by reason extra <<<"$line"
  if [[ -n "${extra:-}" || ! "${id:-}" =~ ^RUSTSEC-[0-9]{4}-[0-9]{4}$ ||
        ! "${review_by:-}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ || ${#reason} -lt 20 ]]; then
    printf 'Malformed cargo audit exception on line %d.\n' "$line_number" >&2
    exit 1
  fi
  if [[ -n "${seen[$id]:-}" ]]; then
    printf 'Duplicate cargo audit exception: %s\n' "$id" >&2
    exit 1
  fi
  if [[ "$review_by" < "$today" ]]; then
    printf 'Cargo audit exception %s expired on %s; review it or remove it.\n' "$id" "$review_by" >&2
    exit 1
  fi
  seen[$id]=1
  ids+=("$id")
done <"$exceptions_file"

if (( ${#ids[@]} > max_entries )); then
  printf 'Too many cargo audit exceptions (%d > %d).\n' "${#ids[@]}" "$max_entries" >&2
  exit 1
fi
if (( ${#ids[@]} > 0 )); then
  printf '%s\n' "${ids[@]}" | LC_ALL=C sort
fi
