#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'EOF'
Invite Capsules are deliberately unrecoverable after startup output closes.
Run ./deploy/restart-docker.sh to wipe all RAM state and generate new capabilities.
EOF
exit 1
