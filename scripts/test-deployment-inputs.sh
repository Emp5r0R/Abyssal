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
    bash "$ROOT_DIR/deploy/$1"
}

for helper in restart-docker.sh stop-docker.sh logs-docker.sh sync-server.sh deploy-server.sh; do
  run_fake_helper "$helper"
done

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

[[ ! -e "$SENTINEL" ]] || {
  echo 'Hostile helper override executed shell input.' >&2
  exit 1
}

echo 'Deployment input checks passed.'
