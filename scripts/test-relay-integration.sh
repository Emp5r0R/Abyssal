#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="$(node -e "const n=require('node:net').createServer();n.listen(0,'127.0.0.1',()=>{console.log(n.address().port);n.close()})")"
TMP_DIR="$(mktemp -d)"
RELAY_LOG="$TMP_DIR/relay.log"
RELAY_PID=""

cleanup() {
  if [[ -n "$RELAY_PID" ]] && kill -0 "$RELAY_PID" 2>/dev/null; then
    kill "$RELAY_PID" 2>/dev/null || true
    wait "$RELAY_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

cargo build --manifest-path "$ROOT_DIR/Cargo.toml" --locked --package mirage-server

ABYSSAL_BIND_ADDR="127.0.0.1:$PORT" \
ABYSSAL_NODE_ID="abyssal-integration-node" \
ABYSSAL_CODE_COUNT=0 \
ABYSSAL_INVITE_CODES="ABYS-ALICE-0001,ABYS-BOB-000002" \
ABYSSAL_SESSION_INACTIVITY_MINUTES=5 \
ABYSSAL_WEB_ROOT="$TMP_DIR/no-web" \
RUST_LOG=mirage_server=warn \
  "$ROOT_DIR/target/debug/mirage-server" >"$RELAY_LOG" 2>&1 &
RELAY_PID=$!

for _ in {1..80}; do
  if curl --fail --silent "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$RELAY_PID" 2>/dev/null; then
    cat "$RELAY_LOG" >&2
    exit 1
  fi
  sleep 0.1
done

curl --fail --silent --show-error "http://127.0.0.1:$PORT/health" >/dev/null
ABYSSAL_TEST_BASE_URL="http://127.0.0.1:$PORT" node "$ROOT_DIR/scripts/relay-integration.mjs"
