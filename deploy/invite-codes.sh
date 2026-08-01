#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'EOF'
Invite codes are deliberately unrecoverable after startup output closes.
Run ./deploy/restart-docker.sh to wipe all RAM state and generate new codes.
EOF
exit 1
