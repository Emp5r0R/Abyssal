#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
VALIDATOR="$ROOT_DIR/scripts/lib/verify-cargo-audit.sh"
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/abyssal-cargo-audit-test.XXXXXX")"
trap 'rm -rf -- "$TEMP_DIR"' EXIT INT TERM

REPORT="$TEMP_DIR/report.json"
STDERR="$TEMP_DIR/stderr"
FAKE_BIN="$TEMP_DIR/bin"
mkdir -p "$FAKE_BIN"

write_valid_report() {
  cat > "$1" <<'EOF'
{
  "database": {"advisory-count": 1242, "last-commit": null, "last-updated": null},
  "lockfile": {"dependency-count": 358},
  "settings": {
    "target_arch": [],
    "target_os": [],
    "severity": null,
    "ignore": [],
    "informational_warnings": ["unmaintained", "unsound", "notice"]
  },
  "vulnerabilities": {"found": false, "count": 0, "list": []},
  "warnings": {}
}
EOF
}

write_valid_report "$REPORT"
: > "$STDERR"

expect_success() {
  "$VALIDATOR" 0 "$REPORT" "$STDERR"
}

expect_failure() {
  if "$@" >/dev/null 2>&1; then
    printf 'Expected cargo audit validation to fail: %s\n' "$*" >&2
    exit 1
  fi
}

expect_success
expect_failure "$VALIDATOR" 17 "$REPORT" "$STDERR"
expect_failure "$VALIDATOR" 0 "$TEMP_DIR/missing.json" "$STDERR"
: > "$REPORT"
expect_failure "$VALIDATOR" 0 "$REPORT" "$STDERR"
printf '%s\n' 'malformed' > "$REPORT"
expect_failure "$VALIDATOR" 0 "$REPORT" "$STDERR"
printf '%s' '{"database":' > "$REPORT"
expect_failure "$VALIDATOR" 0 "$REPORT" "$STDERR"
printf '%s\n' '{"unexpected":true}' >> "$REPORT"
expect_failure "$VALIDATOR" 0 "$REPORT" "$STDERR"
write_valid_report "$REPORT"
cp -- "$REPORT" "$TEMP_DIR/valid-report.json"
cat -- "$TEMP_DIR/valid-report.json" >> "$REPORT"
expect_failure "$VALIDATOR" 0 "$REPORT" "$STDERR"
printf '%s' '{"database":' > "$REPORT"
cat -- "$TEMP_DIR/valid-report.json" >> "$REPORT"
expect_failure "$VALIDATOR" 0 "$REPORT" "$STDERR"

write_valid_report "$REPORT"
sed -i 's/, "last-commit": null//' "$REPORT"
expect_failure "$VALIDATOR" 0 "$REPORT" "$STDERR"
write_valid_report "$REPORT"
sed -i 's/, "last-updated": null//' "$REPORT"
expect_failure "$VALIDATOR" 0 "$REPORT" "$STDERR"
write_valid_report "$REPORT"
sed -i '/"severity": null,/d' "$REPORT"
expect_failure "$VALIDATOR" 0 "$REPORT" "$STDERR"

write_valid_report "$REPORT"
sed -i 's/"ignore": \[\]/"ignore": ["RUSTSEC-0000-0000"]/' "$REPORT"
expect_failure "$VALIDATOR" 0 "$REPORT" "$STDERR"
write_valid_report "$REPORT"
sed -i 's/"target_arch": \[\]/"target_arch": ["x86_64"]/' "$REPORT"
expect_failure "$VALIDATOR" 0 "$REPORT" "$STDERR"
write_valid_report "$REPORT"
sed -i 's/"severity": null/"severity": "high"/' "$REPORT"
expect_failure "$VALIDATOR" 0 "$REPORT" "$STDERR"
write_valid_report "$REPORT"
sed -i 's/"informational_warnings": \["unmaintained", "unsound", "notice"\]/"informational_warnings": []/' "$REPORT"
expect_failure "$VALIDATOR" 0 "$REPORT" "$STDERR"

cat > "$REPORT" <<'EOF'
{"vulnerabilities":{"found":false,"count":0,"list":[]},"warnings":{}}
EOF
expect_failure "$VALIDATOR" 0 "$REPORT" "$STDERR"

write_valid_report "$REPORT"
sed -i 's/"warnings": {}/"warnings": {"yanked": [{"name": "example"}]}/' "$REPORT"
expect_failure "$VALIDATOR" 0 "$REPORT" "$STDERR"

write_valid_report "$REPORT"
printf '%s\n' "warning: couldn't check if the package is yanked: registry: request could not be completed in the allotted timeframe" > "$STDERR"
expect_failure "$VALIDATOR" 0 "$REPORT" "$STDERR"
printf '%s\n' 'warning: registry request timed out after 30 seconds' > "$STDERR"
expect_failure "$VALIDATOR" 0 "$REPORT" "$STDERR"
printf '%s\n' 'error: registry request failed' > "$STDERR"
expect_failure "$VALIDATOR" 0 "$REPORT" "$STDERR"
: > "$STDERR"

cat > "$FAKE_BIN/npm" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat > "$FAKE_BIN/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == audit && "${2:-}" == --version ]]; then
  printf 'cargo-audit-audit 0.22.2\n'
  exit 0
fi
[[ "${1:-}" == audit ]] || exit 2
[[ "$*" == *"--deny warnings"* ]] || exit 3
[[ "$*" == *"--format json"* ]] || exit 3
if [[ "${FAKE_CARGO_AUDIT_MODE:-success}" == success ]]; then
  cat "$FAKE_CARGO_AUDIT_REPORT"
  exit 0
fi
if [[ "${FAKE_CARGO_AUDIT_MODE:-}" == incomplete ]]; then
  cat "$FAKE_CARGO_AUDIT_REPORT"
  printf '%s\n' 'warning: registry request could not be completed in the allotted timeframe' >&2
  exit 0
fi
exit 19
EOF
chmod 0755 "$FAKE_BIN/npm" "$FAKE_BIN/cargo"
export FAKE_CARGO_AUDIT_REPORT="$REPORT"
AUDIT_TEMP_DIR="$TEMP_DIR/audit-tmp"
mkdir -p "$AUDIT_TEMP_DIR"
assert_audit_tempdir_clean() {
  [[ -z "$(find "$AUDIT_TEMP_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
    printf 'cargo audit temporary directory was not cleaned: %s\n' \
      "$AUDIT_TEMP_DIR" >&2
    exit 1
  }
}

TMPDIR="$AUDIT_TEMP_DIR" PATH="$FAKE_BIN:$PATH" FAKE_CARGO_AUDIT_MODE=success \
  bash "$ROOT_DIR/scripts/test-all.sh" audit >/dev/null
assert_audit_tempdir_clean
expect_failure env TMPDIR="$AUDIT_TEMP_DIR" PATH="$FAKE_BIN:$PATH" \
  FAKE_CARGO_AUDIT_MODE=incomplete \
  bash "$ROOT_DIR/scripts/test-all.sh" audit
assert_audit_tempdir_clean
expect_failure env TMPDIR="$AUDIT_TEMP_DIR" PATH="$FAKE_BIN:$PATH" \
  FAKE_CARGO_AUDIT_MODE=nonzero \
  bash "$ROOT_DIR/scripts/test-all.sh" audit
assert_audit_tempdir_clean

sed -i 's/"found": false, "count": 0/"found": true, "count": 1/' "$REPORT"
expect_failure "$VALIDATOR" 0 "$REPORT" "$STDERR"

printf 'Cargo audit validation checks passed.\n'
