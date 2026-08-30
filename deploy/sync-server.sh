#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

source "$SCRIPT_DIR/remote-env.sh"

RELEASE_OUTPUT_DIR="${ABYSSAL_RELEASE_OUTPUT_DIR:-$ROOT_DIR/build-outputs}"
RELEASE_MANIFEST="${ABYSSAL_WEB_RELEASE_MANIFEST:-${ABYSSAL_RELEASE_MANIFEST:-$RELEASE_OUTPUT_DIR/release-manifest-v1.json}}"
RELEASE_SIGNATURE="${ABYSSAL_WEB_RELEASE_SIGNATURE:-${ABYSSAL_RELEASE_SIGNATURE:-$RELEASE_OUTPUT_DIR/release-manifest-v1.sig}}"
WEB_ARCHIVE="${ABYSSAL_WEB_RELEASE_ARCHIVE:-${ABYSSAL_WEB_ARCHIVE:-}}"
RELEASE_REPOSITORY="${ABYSSAL_RELEASE_REPOSITORY:-${ABYSSAL_RELEASE_REPO:-Emp5r0R/Abyssal}}"

MAX_REMOTE_MANIFEST_BYTES=262144
MAX_REMOTE_SIGNATURE_BYTES=64
MAX_REMOTE_ARCHIVE_BYTES=$((512 * 1024 * 1024))
REMOTE_CONNECT_TIMEOUT_SECONDS=10
REMOTE_DOWNLOAD_TIMEOUT_SECONDS=180

die() {
  printf '%s\n' "$1" >&2
  exit 1
}

require_clean_tracked_source() {
  git -C "$ROOT_DIR" diff --quiet --ignore-submodules -- || die \
    'Deployment requires a clean tracked worktree.'
  git -C "$ROOT_DIR" diff --cached --quiet --ignore-submodules -- || die \
    'Deployment requires a clean tracked index.'
}

path_exists() {
  [[ -e "$1" || -L "$1" ]]
}

validate_release_repository() {
  [[ "$RELEASE_REPOSITORY" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] || die \
    "Configured GitHub release repository must be owner/name: $RELEASE_REPOSITORY"
}

resolve_published_tag() {
  local source_commit="$1"
  local tag_output tag
  local -a candidate_tags=()

  tag_output="$(git -C "$ROOT_DIR" tag --points-at "$source_commit")" || die \
    'Unable to enumerate Git tags at the committed source.'
  while IFS= read -r tag; do
    [[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || continue
    candidate_tags+=("$tag")
  done <<< "$tag_output"

  [[ ${#candidate_tags[@]} -eq 1 ]] || die \
    'Expected exactly one canonical vMAJOR.MINOR.PATCH tag pointing at committed HEAD.'
  printf '%s\n' "${candidate_tags[0]}"
}

download_release_asset() {
  local url="$1"
  local destination="$2"
  local maximum_bytes="$3"
  local actual_size

  env -u GITHUB_TOKEN -u GH_TOKEN -u GITHUB_OAUTH_TOKEN -u GITHUB_API_TOKEN \
    curl -q --fail --silent --show-error --location \
    --max-redirs 3 \
    --proto '=https' --proto-redir '=https' \
    --connect-timeout "$REMOTE_CONNECT_TIMEOUT_SECONDS" \
    --max-time "$REMOTE_DOWNLOAD_TIMEOUT_SECONDS" \
    --max-filesize "$maximum_bytes" \
    --netrc-file /dev/null \
    --output "$destination" \
    "$url" || die "Unable to download signed release asset: $url"

  [[ -f "$destination" && ! -L "$destination" ]] || die \
    "Downloaded release asset is not a regular file: $destination"
  actual_size="$(stat -c '%s' -- "$destination")" || die \
    "Unable to inspect downloaded release asset: $destination"
  [[ "$actual_size" =~ ^[0-9]+$ && "$actual_size" -gt 0 && "$actual_size" -le "$maximum_bytes" ]] || die \
    "Downloaded release asset exceeds its bounded size: $destination"
}

fetch_published_release() {
  local source_commit="$1"
  local tag version base_url

  validate_release_repository

  tag="$(resolve_published_tag "$source_commit")"
  version="${tag#v}"
  FETCH_DIR="$(mktemp -d "${TMPDIR:-/tmp}/abyssal-release-fetch.XXXXXX")" || die \
    'Unable to create private temporary storage for signed release assets.'
  chmod 700 "$FETCH_DIR" || die 'Unable to restrict temporary release storage.'
  base_url="https://github.com/$RELEASE_REPOSITORY/releases/download/$tag"

  RELEASE_MANIFEST="$FETCH_DIR/release-manifest-v1.json"
  RELEASE_SIGNATURE="$FETCH_DIR/release-manifest-v1.sig"
  WEB_ARCHIVE="$FETCH_DIR/abyssal-web-$version.tar.gz"
  download_release_asset \
    "$base_url/release-manifest-v1.json" "$RELEASE_MANIFEST" "$MAX_REMOTE_MANIFEST_BYTES"
  download_release_asset \
    "$base_url/release-manifest-v1.sig" "$RELEASE_SIGNATURE" "$MAX_REMOTE_SIGNATURE_BYTES"
  download_release_asset \
    "$base_url/abyssal-web-$version.tar.gz" "$WEB_ARCHIVE" "$MAX_REMOTE_ARCHIVE_BYTES"
}

if [[ -n "${ABYSSAL_RELEASE_TOOL:-}" ]]; then
  RELEASE_TOOL_COMMAND=("$ABYSSAL_RELEASE_TOOL")
  [[ -x "$ABYSSAL_RELEASE_TOOL" && ! -L "$ABYSSAL_RELEASE_TOOL" ]] || {
    printf 'Configured release verifier must be an executable regular non-symlink file: %s\n' \
      "$ABYSSAL_RELEASE_TOOL" >&2
    exit 1
  }
else
  command -v cargo >/dev/null 2>&1 || {
    printf 'No release verifier configured. Install the pinned Rust toolchain from rust-toolchain.toml or set ABYSSAL_RELEASE_TOOL to a reviewed verifier binary.\n' >&2
    exit 1
  }
  [[ -f "$ROOT_DIR/rust-toolchain.toml" && -f "$ROOT_DIR/Cargo.lock" ]] || {
    printf 'No release verifier configured and the pinned Rust source prerequisites are missing (rust-toolchain.toml/Cargo.lock).\n' >&2
    exit 1
  }
  RELEASE_TOOL_COMMAND=(
    cargo run --quiet --locked --release
    --manifest-path "$ROOT_DIR/Cargo.toml"
    --package abyssal-release-tool --
  )
fi

run_release_tool() {
  "${RELEASE_TOOL_COMMAND[@]}" "$@"
}

FETCH_DIR=''
SYNC_DIR=''
cleanup() {
  [[ -z "${SYNC_DIR:-}" ]] || rm -rf -- "$SYNC_DIR"
  [[ -z "${FETCH_DIR:-}" ]] || rm -rf -- "$FETCH_DIR"
}
trap cleanup EXIT INT TERM

SOURCE_COMMIT="$(git -C "$ROOT_DIR" rev-parse --verify HEAD^{commit})" || die \
  'Unable to resolve committed source HEAD.'
require_clean_tracked_source

default_archive_count=0
default_archive_path=''
if [[ -d "$RELEASE_OUTPUT_DIR" ]]; then
  mapfile -t default_web_archives < <(
    find "$RELEASE_OUTPUT_DIR" -maxdepth 1 \( -type f -o -type l \) \
      -name 'abyssal-web-*.tar.gz' -print
  )
  default_archive_count="${#default_web_archives[@]}"
  if [[ "$default_archive_count" -eq 1 ]]; then
    default_archive_path="${default_web_archives[0]}"
  fi
fi

if [[ -z "$WEB_ARCHIVE" && "$default_archive_count" -eq 1 ]]; then
  WEB_ARCHIVE="$default_archive_path"
fi

explicit_release_input=0
[[ -n "${ABYSSAL_WEB_RELEASE_MANIFEST:-}" || -n "${ABYSSAL_RELEASE_MANIFEST:-}" ]] && explicit_release_input=1
[[ -n "${ABYSSAL_WEB_RELEASE_SIGNATURE:-}" || -n "${ABYSSAL_RELEASE_SIGNATURE:-}" ]] && explicit_release_input=1
[[ -n "${ABYSSAL_WEB_RELEASE_ARCHIVE:-}" || -n "${ABYSSAL_WEB_ARCHIVE:-}" ]] && explicit_release_input=1

default_manifest_present=0
default_signature_present=0
path_exists "$RELEASE_OUTPUT_DIR/release-manifest-v1.json" && default_manifest_present=1
path_exists "$RELEASE_OUTPUT_DIR/release-manifest-v1.sig" && default_signature_present=1

if [[ "$explicit_release_input" -eq 0 && "$default_manifest_present" -eq 0 && \
  "$default_signature_present" -eq 0 && "$default_archive_count" -eq 0 ]]; then
  fetch_published_release "$SOURCE_COMMIT"
fi

[[ -f "$RELEASE_MANIFEST" && ! -L "$RELEASE_MANIFEST" ]] || {
  printf 'Signed release manifest must be a regular non-symlink file: %s\n' \
    "$RELEASE_MANIFEST" >&2
  exit 1
}
[[ -f "$RELEASE_SIGNATURE" && ! -L "$RELEASE_SIGNATURE" ]] || {
  printf 'Signed release signature must be a regular non-symlink file: %s\n' \
    "$RELEASE_SIGNATURE" >&2
  exit 1
}

if [[ -z "$WEB_ARCHIVE" ]]; then
  mapfile -t web_archives < <(
    find "$RELEASE_OUTPUT_DIR" -maxdepth 1 \( -type f -o -type l \) \
      -name 'abyssal-web-*.tar.gz' -print
  )
  [[ ${#web_archives[@]} -eq 1 ]] || {
    printf 'Expected exactly one signed web archive in %s; set ABYSSAL_WEB_RELEASE_ARCHIVE explicitly.\n' \
      "$RELEASE_OUTPUT_DIR" >&2
    exit 1
  }
  WEB_ARCHIVE="${web_archives[0]}"
fi
[[ -f "$WEB_ARCHIVE" && ! -L "$WEB_ARCHIVE" ]] || {
  printf 'Signed web archive must be a regular non-symlink file: %s\n' "$WEB_ARCHIVE" >&2
  exit 1
}

ARCHIVE_NAME="$(basename -- "$WEB_ARCHIVE")"
run_release_tool verify-web-archive \
  --manifest "$RELEASE_MANIFEST" \
  --signature "$RELEASE_SIGNATURE" \
  --archive "$WEB_ARCHIVE" \
  --source-commit "$SOURCE_COMMIT"

printf -v REMOTE_RSYNC_PATH \
  'mkdir -p -- %q && rsync' \
  "$ABYSSAL_REMOTE_DIR"

SYNC_DIR="$(mktemp -d)"

git -C "$ROOT_DIR" archive --format=tar "$SOURCE_COMMIT" | tar -xf - --no-same-owner -C "$SYNC_DIR"

WEB_STAGE_DIR="$SYNC_DIR/.web-release"
mkdir -p "$WEB_STAGE_DIR"
STAGED_ARCHIVE="$WEB_STAGE_DIR/$ARCHIVE_NAME"
cp --reflink=auto -- "$WEB_ARCHIVE" "$STAGED_ARCHIVE"
run_release_tool verify-web-archive \
  --manifest "$RELEASE_MANIFEST" \
  --signature "$RELEASE_SIGNATURE" \
  --archive "$STAGED_ARCHIVE" \
  --source-commit "$SOURCE_COMMIT"

rsync -az --checksum --delete --partial --human-readable --info=progress2,stats2 \
  -e "$ABYSSAL_SSH_COMMAND" \
  --rsync-path="$REMOTE_RSYNC_PATH" \
  --exclude '.git/' \
  --exclude '.secrets/' \
  --exclude 'README.local.md' \
  --exclude 'deploy/deploy.env' \
  --exclude 'deploy/release.env' \
  --exclude 'mirage-server/.env' \
  "$SYNC_DIR/" \
  "$ABYSSAL_SSH_HOST:$ABYSSAL_REMOTE_DIR/"

echo "Synced committed Abyssal snapshot to $ABYSSAL_SSH_HOST:$ABYSSAL_REMOTE_DIR"
