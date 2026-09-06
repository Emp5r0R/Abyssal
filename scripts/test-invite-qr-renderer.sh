#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TEMP_DIR"' EXIT
mkdir "$TEMP_DIR/bin"
cat > "$TEMP_DIR/bin/qrencode" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ $# == 10 && "$1" == -t && "$3" == -l && "$4" == M && "$5" == -s && "$6" == 8 && "$7" == -m && "$8" == 4 && "$9" == -o && "${10}" == - ]]
[[ "$2" == ANSIUTF8 || "$2" == PNG ]]
printf '%s\n' "$2" > "$QR_TEST_FORMAT"
cat > "$QR_TEST_INPUT"
SH
chmod 755 "$TEMP_DIR/bin/qrencode"
export PATH="$TEMP_DIR/bin:$PATH" QR_TEST_FORMAT="$TEMP_DIR/format" QR_TEST_INPUT="$TEMP_DIR/input"

# The renderer is deliberately not a signature verifier. It passes bounded
# data through stdin, never as options or a shell expression.
invite='abyssal:invite:nonproduction-test;$(touch forbidden)'
for mode in terminal png; do
  printf '%s\n' "$invite" | bash "$ROOT_DIR/deploy/render-invite-qr.sh" "$mode"
  [[ "$(<"$QR_TEST_INPUT")" == "$invite" ]]
  if [[ "$mode" == png ]]; then [[ "$(<"$QR_TEST_FORMAT")" == PNG ]];
  else [[ "$(<"$QR_TEST_FORMAT")" == ANSIUTF8 ]]; fi
done
for bad in '' 'file:///etc/passwd' 'https://example.com/qr' '-o /tmp/forbidden'; do
  if printf '%s\n' "$bad" | bash "$ROOT_DIR/deploy/render-invite-qr.sh" 2>/dev/null; then exit 1; fi
done
if printf '%s' "$invite" | bash "$ROOT_DIR/deploy/render-invite-qr.sh" --help 2>/dev/null; then exit 1; fi
printf -v oversized '%02049d' 0
if printf '%s\n' "abyssal:invite:$oversized" | bash "$ROOT_DIR/deploy/render-invite-qr.sh" 2>/dev/null; then exit 1; fi
printf 'Invite QR renderer checks passed\n'
