#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
source "$ROOT_DIR/scripts/lib/web-release-archive.sh"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TEMP_DIR"' EXIT
umask 077
mkdir -p "$TEMP_DIR/source/assets" "$TEMP_DIR/extracted"
printf 'fixture\n' > "$TEMP_DIR/source/assets/app.js"
create_web_release_archive "$TEMP_DIR/source" "$TEMP_DIR/one.tar.gz" 1700000000
tar -xzf "$TEMP_DIR/one.tar.gz" --same-permissions --no-same-owner -C "$TEMP_DIR/extracted"
[[ "$(stat -c %a "$TEMP_DIR/extracted/assets")" == 755 ]]
[[ "$(stat -c %a "$TEMP_DIR/extracted/assets/app.js")" == 644 ]]
cmp "$TEMP_DIR/source/assets/app.js" "$TEMP_DIR/extracted/assets/app.js"
chmod 755 "$TEMP_DIR/source" "$TEMP_DIR/source/assets"
chmod 644 "$TEMP_DIR/source/assets/app.js"
create_web_release_archive "$TEMP_DIR/source" "$TEMP_DIR/two.tar.gz" 1700000000
cmp "$TEMP_DIR/one.tar.gz" "$TEMP_DIR/two.tar.gz"
if create_web_release_archive "$TEMP_DIR/source" "$TEMP_DIR/one.tar.gz" 1700000000; then exit 1; fi
ln -s /does-not-exist "$TEMP_DIR/output-link"
if create_web_release_archive "$TEMP_DIR/source" "$TEMP_DIR/output-link" 1700000000; then exit 1; fi
ln -s /etc/passwd "$TEMP_DIR/source/forbidden-link"
if create_web_release_archive "$TEMP_DIR/source" "$TEMP_DIR/three.tar.gz" 1700000000; then exit 1; fi
[[ ! -e "$TEMP_DIR/three.tar.gz" ]]
printf 'Web release archive checks passed\n'
