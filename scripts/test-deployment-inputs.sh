#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT INT TERM

KEY_FILE="$TEMP_DIR/test key"
KNOWN_HOSTS="$TEMP_DIR/known_hosts"
ENV_FILE="$TEMP_DIR/deploy.env"
SENTINEL="$TEMP_DIR/executed"
FAKE_BIN="$TEMP_DIR/bin"
FAKE_LOG="$TEMP_DIR/fake.log"
: > "$KEY_FILE"
: > "$KNOWN_HOSTS"
mkdir -p "$FAKE_BIN"

cat > "$FAKE_BIN/ssh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'ssh\n' >> "$FAKE_LOG"
printf '%s\n' "$@" >> "$FAKE_LOG"
EOF

cat > "$FAKE_BIN/rsync" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
  printf 'rsync\n' >> "$FAKE_LOG"
  printf '%s\n' "$@" >> "$FAKE_LOG"
  for argument in "$@"; do
    if [[ "$argument" == */ ]]; then
      source_dir="${argument%/}"
      if [[ -n "${EXPECTED_ARCHIVE_NAME:-}" && -d "$source_dir/.web-release" ]]; then
        [[ -f "$source_dir/.web-release/.gitignore" ]] || exit 1
        [[ -f "$source_dir/.web-release/$EXPECTED_ARCHIVE_NAME" ]] || exit 1
        [[ -z "$(find "$source_dir/.web-release" -mindepth 1 -maxdepth 1 \
          ! -name .gitignore ! -name "$EXPECTED_ARCHIVE_NAME" -print -quit)" ]] || exit 1
        [[ -z "$(find "$source_dir" -mindepth 2 -type d -name .web-release -print -quit)" ]] || exit 1
      fi
    fi
  done
EOF

cat > "$FAKE_BIN/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == compose ]]; then
  if [[ " $* " == *' ps -aq '* ]]; then
    printf 'fake-container-id\n'
  else
    printf 'NAME IMAGE COMMAND SERVICE CREATED STATUS PORTS\nfake-container\n'
  fi
  exit 0
fi
if [[ "${1:-}" == inspect ]]; then
  if [[ " $* " == *'.State.Status'* ]]; then
    printf 'running\n'
  else
    printf 'healthy\n'
  fi
  exit 0
fi
printf 'unexpected fake docker invocation\n' >&2
exit 1
EOF

chmod 0755 "$FAKE_BIN/ssh" "$FAKE_BIN/rsync" "$FAKE_BIN/docker"

cat > "$FAKE_BIN/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" >> "$FAKE_CURL_LOG"
[[ "${FAKE_CURL_FAIL:-0}" != 1 ]] || exit 22
destination=''
for ((index = 1; index <= $#; index++)); do
  if [[ "${!index}" == --output ]]; then
    next=$((index + 1))
    destination="${!next}"
  fi
done
url="${!#}"
[[ "$url" == https://github.com/*/releases/download/v*/* ]] || exit 1
[[ -n "$destination" ]] || exit 1
mkdir -p "$(dirname -- "$destination")"
if [[ "$url" == */release-manifest-v1.json ]]; then
  if [[ "${FAKE_CURL_OVERSIZE:-0}" == manifest ]]; then
    head -c 262145 /dev/zero > "$destination"
  else
    cp -- "$EXPECTED_MANIFEST_SOURCE" "$destination"
  fi
elif [[ "$url" == */release-manifest-v1.sig ]]; then
  cp -- "$EXPECTED_SIGNATURE_SOURCE" "$destination"
elif [[ "$url" == */abyssal-web-*.tar.gz ]]; then
  if [[ "${FAKE_CURL_TAMPER:-0}" == 1 ]]; then
    printf '%s' 'tampered downloaded archive' > "$destination"
  else
    cp -- "$EXPECTED_ARCHIVE_SOURCE" "$destination"
  fi
else
  exit 1
fi
EOF

cat > "$FAKE_BIN/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == -C && "${3:-}" == diff ]]; then
  [[ "${FAKE_GIT_DIRTY:-0}" != 1 ]] || exit 1
  exit 0
fi
if [[ "${1:-}" == -C && "${3:-}" == tag ]]; then
  printf '%s\n' "${FAKE_GIT_TAGS-v2.2.5}"
  exit 0
fi
exec /usr/bin/git "$@"
EOF

chmod 0755 "$FAKE_BIN/curl" "$FAKE_BIN/git"

RELEASE_OUTPUT_DIR="$TEMP_DIR/releases"
RELEASE_MANIFEST="$RELEASE_OUTPUT_DIR/release-manifest-v1.json"
RELEASE_SIGNATURE="$RELEASE_OUTPUT_DIR/release-manifest-v1.sig"
WEB_ARCHIVE="$RELEASE_OUTPUT_DIR/abyssal-web-2.2.0.tar.gz"
mkdir -p "$RELEASE_OUTPUT_DIR"
printf '%s' '{"signed":true}' > "$RELEASE_MANIFEST"
printf '%064d' 0 > "$RELEASE_SIGNATURE"
printf '%s' 'signed web archive' > "$WEB_ARCHIVE"
EXPECTED_ARCHIVE_SHA="$(sha256sum -- "$WEB_ARCHIVE")"
EXPECTED_ARCHIVE_SHA="${EXPECTED_ARCHIVE_SHA%% *}"
EXPECTED_ARCHIVE_NAME="$(basename -- "$WEB_ARCHIVE")"
EXPECTED_ARCHIVE_SIZE="$(stat -c '%s' -- "$WEB_ARCHIVE")"
EXPECTED_MANIFEST_SHA="$(sha256sum -- "$RELEASE_MANIFEST")"
EXPECTED_MANIFEST_SHA="${EXPECTED_MANIFEST_SHA%% *}"
EXPECTED_SIGNATURE_SHA="$(sha256sum -- "$RELEASE_SIGNATURE")"
EXPECTED_SIGNATURE_SHA="${EXPECTED_SIGNATURE_SHA%% *}"
EXPECTED_SOURCE_COMMIT="$(git -C "$ROOT_DIR" rev-parse --verify HEAD^{commit})"

cat > "$FAKE_BIN/abyssal-release-tool" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == verify-web-archive || "${1:-}" == verify-web-release ]] || exit 1
shift
manifest=''
signature=''
archive=''
source_commit=''
while (($#)); do
  [[ $# -ge 2 ]] || exit 1
  case "$1" in
    --manifest) manifest="$2" ;;
    --signature) signature="$2" ;;
    --archive) archive="$2" ;;
    --source-commit) source_commit="$2" ;;
    *) exit 1 ;;
  esac
  shift 2
done
[[ -f "$manifest" && ! -L "$manifest" ]]
[[ -f "$signature" && ! -L "$signature" ]]
[[ -f "$archive" && ! -L "$archive" ]]
[[ "$source_commit" == "$EXPECTED_SOURCE_COMMIT" ]]
[[ "$(basename -- "$archive")" == "$EXPECTED_ARCHIVE_NAME" ]]
manifest_sha="$(sha256sum -- "$manifest")"
manifest_sha="${manifest_sha%% *}"
[[ "$manifest_sha" == "$EXPECTED_MANIFEST_SHA" ]]
signature_sha="$(sha256sum -- "$signature")"
signature_sha="${signature_sha%% *}"
[[ "$signature_sha" == "$EXPECTED_SIGNATURE_SHA" ]]
[[ "$(stat -c '%s' -- "$archive")" == "$EXPECTED_ARCHIVE_SIZE" ]]
actual_sha="$(sha256sum -- "$archive")"
actual_sha="${actual_sha%% *}"
[[ "$actual_sha" == "$EXPECTED_ARCHIVE_SHA" ]]
EOF
chmod 0755 "$FAKE_BIN/abyssal-release-tool"

expect_failure() {
  if "$@" >/dev/null 2>&1; then
    printf 'Expected command to reject unsafe deployment input: %q\n' "$*" >&2
    exit 1
  fi
}

cat > "$ENV_FILE" <<EOF
ABYSSAL_SSH_HOST=ubuntu@example.invalid
ABYSSAL_SSH_KEY="$KEY_FILE"
ABYSSAL_SSH_KNOWN_HOSTS="$KNOWN_HOSTS"
ABYSSAL_REMOTE_DIR=/home/ubuntu/abyssal
EOF
ABYSSAL_DEPLOY_ENV="$ENV_FILE" bash -c \
  'source "$1"; [[ "$ABYSSAL_SSH_HOST" == ubuntu@example.invalid ]]; [[ "$ABYSSAL_SSH_KEY" == "$2" ]]; [[ "$ABYSSAL_SSH_KNOWN_HOSTS" == "$3" ]]; [[ "$ABYSSAL_REMOTE_DIR" == /home/ubuntu/abyssal ]]; [[ "${ABYSSAL_SSH_OPTIONS[*]}" == *"StrictHostKeyChecking=yes"* ]]' \
  bash "$ROOT_DIR/deploy/remote-env.sh" "$KEY_FILE" "$KNOWN_HOSTS"

cat > "$ENV_FILE" <<EOF
ABYSSAL_SSH_HOST=ubuntu@example.invalid
ABYSSAL_SSH_KEY="$KEY_FILE"
ABYSSAL_REMOTE_DIR=\$(touch "$SENTINEL")
EOF
expect_failure env ABYSSAL_DEPLOY_ENV="$ENV_FILE" bash "$ROOT_DIR/deploy/remote-env.sh"
[[ ! -e "$SENTINEL" ]] || {
  echo 'Deployment configuration executed shell input.' >&2
  exit 1
}

cat > "$ENV_FILE" <<EOF
UNEXPECTED_SETTING=value
EOF
expect_failure env ABYSSAL_DEPLOY_ENV="$ENV_FILE" bash "$ROOT_DIR/deploy/remote-env.sh"

for unsafe_path in \
  /home/ubuntu/../root \
  /home//ubuntu/abyssal \
  /home/./ubuntu/abyssal; do
  expect_failure env \
    ABYSSAL_DEPLOY_ENV="$TEMP_DIR/missing.env" \
    ABYSSAL_SSH_HOST=ubuntu@example.invalid \
    ABYSSAL_SSH_KEY="$KEY_FILE" \
    ABYSSAL_SSH_KNOWN_HOSTS="$KNOWN_HOSTS" \
    ABYSSAL_REMOTE_DIR="$unsafe_path" \
    bash "$ROOT_DIR/deploy/sync-server.sh"
done

expect_failure env \
  ABYSSAL_DEPLOY_ENV="$TEMP_DIR/missing.env" \
  'ABYSSAL_SSH_HOST=ubuntu@example.invalid;touch /tmp/abyssal-invalid' \
  ABYSSAL_SSH_KEY="$KEY_FILE" \
  ABYSSAL_SSH_KNOWN_HOSTS="$KNOWN_HOSTS" \
  ABYSSAL_REMOTE_DIR=/home/ubuntu/abyssal \
  bash "$ROOT_DIR/deploy/sync-server.sh"

for helper in \
  restart-docker.sh \
  stop-docker.sh \
  logs-docker.sh \
  sync-server.sh \
  deploy-server.sh; do
  expect_failure env \
    ABYSSAL_DEPLOY_ENV="$TEMP_DIR/missing.env" \
    'ABYSSAL_SSH_HOST=ubuntu@example.invalid;touch /tmp/abyssal-invalid' \
    ABYSSAL_SSH_KEY="$KEY_FILE" \
    ABYSSAL_SSH_KNOWN_HOSTS="$KNOWN_HOSTS" \
    ABYSSAL_REMOTE_DIR=/home/ubuntu/abyssal \
    bash "$ROOT_DIR/deploy/$helper"

  expect_failure env \
    ABYSSAL_DEPLOY_ENV="$TEMP_DIR/missing.env" \
    ABYSSAL_SSH_HOST=ubuntu@example.invalid \
    "ABYSSAL_SSH_KEY=$TEMP_DIR/missing;touch $SENTINEL" \
    ABYSSAL_SSH_KNOWN_HOSTS="$KNOWN_HOSTS" \
    ABYSSAL_REMOTE_DIR=/home/ubuntu/abyssal \
    bash "$ROOT_DIR/deploy/$helper"

  expect_failure env \
    ABYSSAL_DEPLOY_ENV="$TEMP_DIR/missing.env" \
    ABYSSAL_SSH_HOST=ubuntu@example.invalid \
    ABYSSAL_SSH_KEY="$KEY_FILE" \
    ABYSSAL_SSH_KNOWN_HOSTS="$KNOWN_HOSTS" \
    "ABYSSAL_REMOTE_DIR=/home/ubuntu/abyssal;touch $SENTINEL" \
    bash "$ROOT_DIR/deploy/$helper"
done

for invalid_known_hosts in \
  "$TEMP_DIR/missing-known-hosts" \
  "$TEMP_DIR"; do
  expect_failure env \
    ABYSSAL_DEPLOY_ENV="$TEMP_DIR/missing.env" \
    ABYSSAL_SSH_HOST=ubuntu@example.invalid \
    ABYSSAL_SSH_KEY="$KEY_FILE" \
    ABYSSAL_SSH_KNOWN_HOSTS="$invalid_known_hosts" \
    ABYSSAL_REMOTE_DIR=/home/ubuntu/abyssal \
    bash "$ROOT_DIR/deploy/remote-env.sh"
done

expect_failure env \
  ABYSSAL_DEPLOY_ENV="$TEMP_DIR/missing.env" \
  ABYSSAL_SSH_HOST=ubuntu@example.invalid \
  ABYSSAL_SSH_KEY="$KEY_FILE" \
  "ABYSSAL_SSH_KNOWN_HOSTS=$KNOWN_HOSTS"$'\n'poison \
  ABYSSAL_REMOTE_DIR=/home/ubuntu/abyssal \
  bash "$ROOT_DIR/deploy/remote-env.sh"

run_fake_helper() {
  PATH="$FAKE_BIN:$PATH" \
    FAKE_LOG="$FAKE_LOG" \
    ABYSSAL_DEPLOY_ENV="$TEMP_DIR/missing.env" \
    ABYSSAL_SSH_HOST=ubuntu@example.invalid \
    ABYSSAL_SSH_KEY="$KEY_FILE" \
    ABYSSAL_SSH_KNOWN_HOSTS="$KNOWN_HOSTS" \
    ABYSSAL_REMOTE_DIR=/home/ubuntu/abyssal \
    ABYSSAL_RELEASE_OUTPUT_DIR="$RELEASE_OUTPUT_DIR" \
    ABYSSAL_RELEASE_TOOL="$FAKE_BIN/abyssal-release-tool" \
    ABYSSAL_WEB_RELEASE_MANIFEST="$RELEASE_MANIFEST" \
    ABYSSAL_WEB_RELEASE_SIGNATURE="$RELEASE_SIGNATURE" \
    ABYSSAL_WEB_RELEASE_ARCHIVE="$WEB_ARCHIVE" \
    EXPECTED_ARCHIVE_SHA="$EXPECTED_ARCHIVE_SHA" \
    EXPECTED_ARCHIVE_NAME="$EXPECTED_ARCHIVE_NAME" \
    EXPECTED_ARCHIVE_SIZE="$EXPECTED_ARCHIVE_SIZE" \
    EXPECTED_MANIFEST_SHA="$EXPECTED_MANIFEST_SHA" \
    EXPECTED_SIGNATURE_SHA="$EXPECTED_SIGNATURE_SHA" \
    EXPECTED_SOURCE_COMMIT="$EXPECTED_SOURCE_COMMIT" \
    bash "$ROOT_DIR/deploy/$1"
}

for helper in restart-docker.sh stop-docker.sh logs-docker.sh sync-server.sh deploy-server.sh; do
  run_fake_helper "$helper"
done

AUTO_RELEASE_OUTPUT_DIR="$TEMP_DIR/auto-releases"
FAKE_CURL_LOG="$TEMP_DIR/fake-curl.log"
EXPECTED_MANIFEST_SOURCE="$RELEASE_MANIFEST"
EXPECTED_SIGNATURE_SOURCE="$RELEASE_SIGNATURE"
EXPECTED_ARCHIVE_SOURCE="$WEB_ARCHIVE"
run_fake_auto_sync() {
  PATH="$FAKE_BIN:$PATH" \
    FAKE_LOG="$FAKE_LOG" \
    FAKE_CURL_LOG="$FAKE_CURL_LOG" \
    EXPECTED_MANIFEST_SOURCE="$EXPECTED_MANIFEST_SOURCE" \
    EXPECTED_SIGNATURE_SOURCE="$EXPECTED_SIGNATURE_SOURCE" \
    EXPECTED_ARCHIVE_SOURCE="$EXPECTED_ARCHIVE_SOURCE" \
    FAKE_GIT_TAGS="v2.2.0" \
    ABYSSAL_DEPLOY_ENV="$TEMP_DIR/missing.env" \
    ABYSSAL_SSH_HOST=ubuntu@example.invalid \
    ABYSSAL_SSH_KEY="$KEY_FILE" \
    ABYSSAL_SSH_KNOWN_HOSTS="$KNOWN_HOSTS" \
    ABYSSAL_REMOTE_DIR=/home/ubuntu/abyssal \
    ABYSSAL_RELEASE_OUTPUT_DIR="$AUTO_RELEASE_OUTPUT_DIR" \
    ABYSSAL_RELEASE_REPOSITORY=fixture/Abyssal \
    ABYSSAL_RELEASE_TOOL="$FAKE_BIN/abyssal-release-tool" \
    EXPECTED_ARCHIVE_SHA="$EXPECTED_ARCHIVE_SHA" \
    EXPECTED_ARCHIVE_NAME="$EXPECTED_ARCHIVE_NAME" \
    EXPECTED_ARCHIVE_SIZE="$EXPECTED_ARCHIVE_SIZE" \
    EXPECTED_MANIFEST_SHA="$EXPECTED_MANIFEST_SHA" \
    EXPECTED_SIGNATURE_SHA="$EXPECTED_SIGNATURE_SHA" \
    EXPECTED_SOURCE_COMMIT="$EXPECTED_SOURCE_COMMIT" \
    bash "$ROOT_DIR/deploy/sync-server.sh"
}

run_fake_auto_case() {
  env \
    PATH="$FAKE_BIN:$PATH" \
    FAKE_LOG="$FAKE_LOG" \
    FAKE_CURL_LOG="$FAKE_CURL_LOG" \
    EXPECTED_MANIFEST_SOURCE="$EXPECTED_MANIFEST_SOURCE" \
    EXPECTED_SIGNATURE_SOURCE="$EXPECTED_SIGNATURE_SOURCE" \
    EXPECTED_ARCHIVE_SOURCE="$EXPECTED_ARCHIVE_SOURCE" \
    EXPECTED_ARCHIVE_SHA="$EXPECTED_ARCHIVE_SHA" \
    EXPECTED_ARCHIVE_NAME="$EXPECTED_ARCHIVE_NAME" \
    EXPECTED_ARCHIVE_SIZE="$EXPECTED_ARCHIVE_SIZE" \
    EXPECTED_MANIFEST_SHA="$EXPECTED_MANIFEST_SHA" \
    EXPECTED_SIGNATURE_SHA="$EXPECTED_SIGNATURE_SHA" \
    EXPECTED_SOURCE_COMMIT="$EXPECTED_SOURCE_COMMIT" \
    ABYSSAL_DEPLOY_ENV="$TEMP_DIR/missing.env" \
    ABYSSAL_SSH_HOST=ubuntu@example.invalid \
    ABYSSAL_SSH_KEY="$KEY_FILE" \
    ABYSSAL_SSH_KNOWN_HOSTS="$KNOWN_HOSTS" \
    ABYSSAL_REMOTE_DIR=/home/ubuntu/abyssal \
    ABYSSAL_RELEASE_TOOL="$FAKE_BIN/abyssal-release-tool" \
    "$@" \
    bash "$ROOT_DIR/deploy/sync-server.sh"
}

expect_auto_failure() {
  local before after
  before="$(grep -c '^rsync$' "$FAKE_LOG" || true)"
  if run_fake_auto_case "$@" >/dev/null 2>&1; then
    echo 'Expected automatic release resolution to reject its input.' >&2
    exit 1
  fi
  after="$(grep -c '^rsync$' "$FAKE_LOG" || true)"
  [[ "$before" == "$after" ]] || {
    echo 'Automatic release resolution invoked rsync after rejecting input.' >&2
    exit 1
  }
}

before_auto_rsync="$(grep -c '^rsync$' "$FAKE_LOG" || true)"
run_fake_auto_sync
after_auto_rsync="$(grep -c '^rsync$' "$FAKE_LOG" || true)"
[[ "$after_auto_rsync" -eq $((before_auto_rsync + 1)) ]] || {
  echo 'Automatic release download did not reach the existing verified rsync path.' >&2
  exit 1
}
grep -Fq -- 'https://github.com/fixture/Abyssal/releases/download/v2.2.0/release-manifest-v1.json' "$FAKE_CURL_LOG" || {
  echo 'Automatic release download did not use the canonical HTTPS manifest URL.' >&2
  exit 1
}
grep -Fq -- 'https://github.com/fixture/Abyssal/releases/download/v2.2.0/release-manifest-v1.sig' "$FAKE_CURL_LOG" || {
  echo 'Automatic release download did not use the canonical HTTPS signature URL.' >&2
  exit 1
}
grep -Fq -- 'https://github.com/fixture/Abyssal/releases/download/v2.2.0/abyssal-web-2.2.0.tar.gz' "$FAKE_CURL_LOG" || {
  echo 'Automatic release download did not use the tag-matched archive URL.' >&2
  exit 1
}
grep -Fq -- '--max-filesize' "$FAKE_CURL_LOG" || {
  echo 'Automatic release download did not bound response sizes.' >&2
  exit 1
}
grep -Fq -- '--max-time' "$FAKE_CURL_LOG" || {
  echo 'Automatic release download did not bound response time.' >&2
  exit 1
}
grep -Fq -- '--max-redirs' "$FAKE_CURL_LOG" || {
  echo 'Automatic release download did not bound redirects.' >&2
  exit 1
}
grep -Fq -- '--proto-redir' "$FAKE_CURL_LOG" || {
  echo 'Automatic release download did not restrict redirects to HTTPS.' >&2
  exit 1
}
grep -Fq -- '--netrc-file' "$FAKE_CURL_LOG" || {
  echo 'Automatic release download did not disable credential forwarding.' >&2
  exit 1
}

expect_auto_failure \
  FAKE_GIT_DIRTY=1 \
  ABYSSAL_RELEASE_OUTPUT_DIR="$TEMP_DIR/dirty-releases"
expect_auto_failure \
  FAKE_GIT_TAGS= \
  ABYSSAL_RELEASE_OUTPUT_DIR="$TEMP_DIR/untagged-releases"
expect_auto_failure \
  FAKE_GIT_TAGS=$'v2.2.0\nv2.2.1' \
  ABYSSAL_RELEASE_OUTPUT_DIR="$TEMP_DIR/ambiguous-releases"
expect_auto_failure \
  FAKE_CURL_FAIL=1 \
  FAKE_GIT_TAGS=v2.2.0 \
  ABYSSAL_RELEASE_OUTPUT_DIR="$TEMP_DIR/failed-download-releases"
expect_auto_failure \
  FAKE_CURL_OVERSIZE=manifest \
  FAKE_GIT_TAGS=v2.2.0 \
  ABYSSAL_RELEASE_OUTPUT_DIR="$TEMP_DIR/oversize-releases"
expect_auto_failure \
  FAKE_CURL_TAMPER=1 \
  FAKE_GIT_TAGS=v2.2.0 \
  ABYSSAL_RELEASE_OUTPUT_DIR="$TEMP_DIR/tampered-releases"

run_fake_sync() {
  local archive="${1-}"
  local manifest="${2:-$RELEASE_MANIFEST}"
  local signature="${3:-$RELEASE_SIGNATURE}"
  local expected_source_commit="${4:-$EXPECTED_SOURCE_COMMIT}"
  local expected_archive_size="${5:-$EXPECTED_ARCHIVE_SIZE}"
  PATH="$FAKE_BIN:$PATH" \
    FAKE_LOG="$FAKE_LOG" \
    FAKE_GIT_DIRTY="${FAKE_GIT_DIRTY:-0}" \
    ABYSSAL_DEPLOY_ENV="$TEMP_DIR/missing.env" \
    ABYSSAL_SSH_HOST=ubuntu@example.invalid \
    ABYSSAL_SSH_KEY="$KEY_FILE" \
    ABYSSAL_SSH_KNOWN_HOSTS="$KNOWN_HOSTS" \
    ABYSSAL_REMOTE_DIR=/home/ubuntu/abyssal \
    ABYSSAL_RELEASE_TOOL="$FAKE_BIN/abyssal-release-tool" \
    ABYSSAL_WEB_RELEASE_MANIFEST="$manifest" \
    ABYSSAL_WEB_RELEASE_SIGNATURE="$signature" \
    ABYSSAL_WEB_RELEASE_ARCHIVE="$archive" \
    EXPECTED_ARCHIVE_SHA="$EXPECTED_ARCHIVE_SHA" \
    EXPECTED_ARCHIVE_NAME="$EXPECTED_ARCHIVE_NAME" \
    EXPECTED_ARCHIVE_SIZE="$expected_archive_size" \
    EXPECTED_MANIFEST_SHA="$EXPECTED_MANIFEST_SHA" \
    EXPECTED_SIGNATURE_SHA="$EXPECTED_SIGNATURE_SHA" \
    EXPECTED_SOURCE_COMMIT="$expected_source_commit" \
    bash "$ROOT_DIR/deploy/sync-server.sh"
}

expect_no_rsync() {
  local before after
  before="$(grep -c '^rsync$' "$FAKE_LOG" || true)"
  expect_failure "$@"
  after="$(grep -c '^rsync$' "$FAKE_LOG" || true)"
  [[ "$before" == "$after" ]] || {
    echo 'sync helper invoked rsync after rejecting release input.' >&2
    exit 1
  }
}

run_fake_dirty_sync() {
  FAKE_GIT_DIRTY=1 run_fake_sync "$@"
}

expect_no_rsync run_fake_dirty_sync "$WEB_ARCHIVE"

expect_no_rsync run_fake_sync "$TEMP_DIR/missing-archive.tar.gz"
ln -s "$WEB_ARCHIVE" "$TEMP_DIR/archive-link.tar.gz"
expect_no_rsync run_fake_sync "$TEMP_DIR/archive-link.tar.gz"
ln -s "$RELEASE_MANIFEST" "$TEMP_DIR/manifest-link.json"
expect_no_rsync run_fake_sync "$WEB_ARCHIVE" "$TEMP_DIR/manifest-link.json"
ln -s "$RELEASE_SIGNATURE" "$TEMP_DIR/signature-link.sig"
expect_no_rsync run_fake_sync "$WEB_ARCHIVE" "$RELEASE_MANIFEST" "$TEMP_DIR/signature-link.sig"
printf '%s' 'tampered web archive' > "$WEB_ARCHIVE"
expect_no_rsync run_fake_sync
printf '%s' 'signed web archive' > "$WEB_ARCHIVE"
printf '%s' 'tampered manifest' > "$RELEASE_MANIFEST"
expect_no_rsync run_fake_sync
printf '%s' '{"signed":true}' > "$RELEASE_MANIFEST"
printf '%064d' 1 > "$RELEASE_SIGNATURE"
expect_no_rsync run_fake_sync
printf '%064d' 0 > "$RELEASE_SIGNATURE"
printf '%s' 'mismatched web archive' > "$TEMP_DIR/other-web-2.2.0.tar.gz"
expect_no_rsync run_fake_sync "$TEMP_DIR/other-web-2.2.0.tar.gz"
expect_no_rsync run_fake_sync "$WEB_ARCHIVE" "$RELEASE_MANIFEST" "$RELEASE_SIGNATURE" \
  89abcdef0123456789abcdef0123456789abcdef
expect_no_rsync run_fake_sync "$WEB_ARCHIVE" "$RELEASE_MANIFEST" "$RELEASE_SIGNATURE" \
  "$EXPECTED_SOURCE_COMMIT" "$((EXPECTED_ARCHIVE_SIZE + 1))"
expect_no_rsync run_fake_sync "$WEB_ARCHIVE" "$TEMP_DIR/missing-manifest.json"
expect_no_rsync run_fake_sync "$WEB_ARCHIVE" "$RELEASE_MANIFEST" "$TEMP_DIR/missing-signature.sig"
cp -- "$WEB_ARCHIVE" "$RELEASE_OUTPUT_DIR/abyssal-web-2.2.1.tar.gz"
expect_no_rsync run_fake_sync
rm -- "$RELEASE_OUTPUT_DIR/abyssal-web-2.2.1.tar.gz"

PATH="$FAKE_BIN:$PATH" bash "$ROOT_DIR/deploy/server-logs.sh" >/dev/null

grep -Fq 'bash deploy/server-restart.sh' "$FAKE_LOG" || {
  echo 'restart helper did not use the server restart entrypoint.' >&2
  exit 1
}
grep -Fq 'bash deploy/server-stop.sh' "$FAKE_LOG" || {
  echo 'stop helper did not use the server stop entrypoint.' >&2
  exit 1
}
grep -Fq 'bash deploy/server-status.sh' "$FAKE_LOG" || {
  echo 'status helper did not use the server status entrypoint.' >&2
  exit 1
}
grep -Fq 'mkdir -p -- /home/ubuntu/abyssal && rsync' "$FAKE_LOG" || {
  echo 'sync helper did not use the constrained remote rsync command.' >&2
  exit 1
}
grep -Fq -- 'BatchMode=yes' "$FAKE_LOG" || {
  echo 'remote helper did not require non-interactive SSH authentication.' >&2
  exit 1
}
grep -Fq -- 'IdentitiesOnly=yes' "$FAKE_LOG" || {
  echo 'remote helper did not constrain SSH identities.' >&2
  exit 1
}
grep -Fq -- 'StrictHostKeyChecking=yes' "$FAKE_LOG" || {
  echo 'remote helper did not require strict host-key verification.' >&2
  exit 1
}
grep -Fq -- "UserKnownHostsFile=$KNOWN_HOSTS" "$FAKE_LOG" || {
  echo 'remote helper did not use the validated known-hosts file.' >&2
  exit 1
}
if grep -Fq -- 'StrictHostKeyChecking=accept-new' "$ROOT_DIR/deploy"/*.sh; then
  echo 'deployment helper still permits unverified host-key acceptance.' >&2
  exit 1
fi

PATH="$FAKE_BIN:$PATH" FAKE_LOG="$FAKE_LOG" bash "$ROOT_DIR/deploy/server-status.sh"

cat > "$FAKE_BIN/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == compose ]]; then
  if [[ " $* " == *' ps -aq '* ]]; then
    printf 'fake-container-id\n'
  else
    printf 'fake-container\n'
  fi
  exit 0
fi
if [[ "${1:-}" == inspect ]]; then
  if [[ " $* " == *'.State.Status'* ]]; then
    printf 'exited\n'
  else
    printf 'unhealthy\n'
  fi
  exit 0
fi
exit 1
EOF
chmod 0755 "$FAKE_BIN/docker"
if PATH="$FAKE_BIN:$PATH" bash "$ROOT_DIR/deploy/server-status.sh" >/dev/null 2>&1; then
  echo 'server-status accepted an unhealthy container.' >&2
  exit 1
fi

DOCKERFILE="$ROOT_DIR/mirage-server/Dockerfile"
grep -Fq 'COPY tools/release-tool ./tools/release-tool' "$DOCKERFILE" || {
  echo 'Docker rust workspace is missing the release-tool member.' >&2
  exit 1
}
grep -Fq 'ADD .web-release/abyssal-web-*.tar.gz /opt/abyssal/web/' "$DOCKERFILE" || {
  echo 'Docker build does not consume the staged web archive.' >&2
  exit 1
}
if grep -Eq 'deploy/scripts/\.web-release|(^|[[:space:]])(tar|gzip)([[:space:]]|$)' "$DOCKERFILE"; then
  echo 'Dockerfile relies on the excluded deployment tree or a runtime archive tool.' >&2
  exit 1
fi
if grep -Fxq '.web-release' "$ROOT_DIR/.dockerignore"; then
  echo 'Docker context excludes the staged web archive.' >&2
  exit 1
fi
grep -Fq 'test -f /opt/abyssal/web/index.html' "$DOCKERFILE" || {
  echo 'Docker build does not require a web index.' >&2
  exit 1
}
grep -Fq 'test -f /opt/abyssal/web/build-id.json' "$DOCKERFILE" || {
  echo 'Docker build does not require web build identity.' >&2
  exit 1
}
if grep -Eq '(^|[[:space:]])(FROM node|npm (ci|run)|COPY apps/web)' "$DOCKERFILE"; then
  echo 'Dockerfile still builds or copies the web source.' >&2
  exit 1
fi

[[ ! -e "$SENTINEL" ]] || {
  echo 'Hostile helper override executed shell input.' >&2
  exit 1
}

echo 'Deployment input checks passed.'
