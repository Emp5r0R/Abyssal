#!/usr/bin/env bash

create_web_release_archive() (
  set -euo pipefail
  local source="$1" archive="$2" epoch="$3"
  [[ -d "$source" && ! -L "$source" && "$epoch" =~ ^[0-9]+$ ]] || return 1
  [[ ! -e "$archive" && ! -L "$archive" ]] || return 1
  [[ -z "$(find "$source" ! -type f ! -type d -print -quit)" ]] || return 1
  # Public bundle files must remain readable by the unprivileged relay even
  # when the signing host uses umask 077. No source permissions are changed.
  set -o noclobber
  tar --sort=name --mode='u=rwX,go=rX' --mtime="@$epoch" \
    --owner=0 --group=0 --numeric-owner --pax-option=delete=atime,delete=ctime \
    -C "$source" -cf - . | gzip -n -9 > "$archive"
  gzip -t "$archive"
)
