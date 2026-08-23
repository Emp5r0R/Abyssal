#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="$(node -e "const n=require('node:net').createServer();n.listen(0,'127.0.0.1',()=>{console.log(n.address().port);n.close()})")"
TMP_DIR="$(mktemp -d)"
RELAY_PID=""

cleanup() {
  if [[ -n "$RELAY_PID" ]] && kill -0 "$RELAY_PID" 2>/dev/null; then
    kill "$RELAY_PID" 2>/dev/null || true
    wait "$RELAY_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

RELEASE_TOOL="$ROOT_DIR/target/debug/abyssal-release-tool"
RELEASE_KEY="$TMP_DIR/integration-release.key"
ANDROID_SIGNATURE="$TMP_DIR/android-build-signature.b64"
WEB_SIGNATURE="$TMP_DIR/web-build-signature.b64"
ANDROID_ASSET="$TMP_DIR/integration.apk"
WEB_ASSET="$TMP_DIR/integration-web.tar.gz"
ANDROID_RECORD="$TMP_DIR/android-build-record.json"
WEB_RECORD="$TMP_DIR/web-build-record.json"
REVOCATIONS="$TMP_DIR/revocations.txt"
MANIFEST="$TMP_DIR/release-manifest-v1.json"
MANIFEST_SIGNATURE="$TMP_DIR/release-manifest-v1.sig"
SOURCE_COMMIT="$(git -C "$ROOT_DIR" rev-parse --verify HEAD)"
NOW_MS="$(node -e 'process.stdout.write(String(Date.now()))')"
EXPIRES_AT_MS="$((NOW_MS + 10 * 60 * 1000))"

cargo build --manifest-path "$ROOT_DIR/Cargo.toml" --locked --package abyssal-release-tool
node -e '
  const fs = require("node:fs");
  const [key, android, web, revocations] = process.argv.slice(1);
  fs.writeFileSync(key, Buffer.alloc(32, 7), { flag: "wx", mode: 0o600 });
  fs.writeFileSync(android, "integration android asset\n", { flag: "wx" });
  fs.writeFileSync(web, "integration web asset\n", { flag: "wx" });
  fs.writeFileSync(revocations, "", { flag: "wx" });
' "$RELEASE_KEY" "$ANDROID_ASSET" "$WEB_ASSET" "$REVOCATIONS"

"$RELEASE_TOOL" sign-build \
  --private-key "$RELEASE_KEY" \
  --build-id "android@2.1.0" \
  --source-commit "$SOURCE_COMMIT" \
  --output "$ANDROID_SIGNATURE"
"$RELEASE_TOOL" sign-build \
  --private-key "$RELEASE_KEY" \
  --build-id "web@2.1.0" \
  --source-commit "$SOURCE_COMMIT" \
  --output "$WEB_SIGNATURE"
"$RELEASE_TOOL" create-build-record \
  --private-key "$RELEASE_KEY" \
  --build-id "android@2.1.0" \
  --source-commit "$SOURCE_COMMIT" \
  --expected-signature "$ANDROID_SIGNATURE" \
  --output "$ANDROID_RECORD" \
  --asset "integration.apk" "$ANDROID_ASSET"
"$RELEASE_TOOL" create-build-record \
  --private-key "$RELEASE_KEY" \
  --build-id "web@2.1.0" \
  --source-commit "$SOURCE_COMMIT" \
  --expected-signature "$WEB_SIGNATURE" \
  --output "$WEB_RECORD" \
  --asset "integration-web.tar.gz" "$WEB_ASSET"
"$RELEASE_TOOL" assemble-manifest \
  --private-key "$RELEASE_KEY" \
  --sequence 1 \
  --issued-at-ms "$NOW_MS" \
  --not-before-ms "$NOW_MS" \
  --expires-at-ms "$EXPIRES_AT_MS" \
  --android-record "$ANDROID_RECORD" \
  --web-record "$WEB_RECORD" \
  --revocations "$REVOCATIONS" \
  --manifest-output "$MANIFEST" \
  --signature-output "$MANIFEST_SIGNATURE"
WEB_BUILD_SIGNATURE_B64="$(tr -d '\n' < "$WEB_SIGNATURE")"

cargo build --manifest-path "$ROOT_DIR/Cargo.toml" --locked \
  --package mirage-server --features integration-release-root

coproc RELAY_PROCESS {
  ABYSSAL_BIND_ADDR="127.0.0.1:$PORT" \
  ABYSSAL_INTEGRATION_TEST=1 \
  ABYSSAL_INTEGRATION_RELEASE_MANIFEST="$MANIFEST" \
  ABYSSAL_INTEGRATION_RELEASE_SIGNATURE="$MANIFEST_SIGNATURE" \
  ABYSSAL_NODE_ID="abyssal-integration-node" \
  ABYSSAL_CODE_COUNT=2 \
  ABYSSAL_CODE_MIN_LEN=16 \
  ABYSSAL_CODE_MAX_LEN=17 \
  ABYSSAL_SESSION_INACTIVITY_MINUTES=5 \
  ABYSSAL_WEB_ROOT="$TMP_DIR/no-web" \
  RUST_LOG="${RUST_LOG:-mirage_server=warn}" \
    "$ROOT_DIR/target/debug/mirage-server" 2>&1
}
RELAY_PID="$RELAY_PROCESS_PID"
RELAY_FD="${RELAY_PROCESS[0]}"

codes=()
for _ in {1..20}; do
  if read -r -t 0.5 -u "$RELAY_FD" line; then
    if [[ "$line" == "ABYSSAL_CODE code="* ]]; then
      codes+=("${line#ABYSSAL_CODE code=}")
      if [[ ${#codes[@]} -eq 2 ]]; then
        break
      fi
    fi
  elif ! kill -0 "$RELAY_PID" 2>/dev/null; then
    echo "Relay exited before printing test invite codes." >&2
    exit 1
  fi
done

if [[ ${#codes[@]} -ne 2 ]]; then
  echo "Relay did not print two one-time test invite codes." >&2
  exit 1
fi

# Drain non-secret relay diagnostics after capturing the one-time invite lines.
# Duplicating the coprocess descriptor keeps it available to the background job.
exec 3<&"$RELAY_FD"
{
  while IFS= read -r -u 3 line; do
    if [[ "$line" != "ABYSSAL_CODE code="* ]]; then
      printf '%s\n' "$line" >&2
    fi
  done
} &

for _ in {1..80}; do
  if curl --fail --silent "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$RELAY_PID" 2>/dev/null; then
    echo "Relay exited before health check passed." >&2
    exit 1
  fi
  sleep 0.1
done

curl --fail --silent --show-error "http://127.0.0.1:$PORT/health" >/dev/null
ABYSSAL_TEST_BASE_URL="http://127.0.0.1:$PORT" \
ABYSSAL_TEST_CODE_A="${codes[0]}" \
ABYSSAL_TEST_CODE_B="${codes[1]}" \
ABYSSAL_TEST_BUILD_SIGNATURE_B64="$WEB_BUILD_SIGNATURE_B64" \
  node --trace-uncaught "$ROOT_DIR/scripts/relay-integration.mjs"
