#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
OUTPUT_DIR="${ABYSSAL_RELEASE_OUTPUT_DIR:-$ROOT_DIR/build-outputs}"
RELEASE_KEY="${ABYSSAL_RELEASE_SIGNING_KEY_FILE:-}"
RELEASE_TOOL="$ROOT_DIR/target/release/abyssal-release-tool"

[[ -n "$RELEASE_KEY" ]] || {
  printf 'ABYSSAL_RELEASE_SIGNING_KEY_FILE is required. Environment key material is not accepted.\n' >&2
  exit 1
}
[[ -f "$RELEASE_KEY" && ! -L "$RELEASE_KEY" ]] || {
  printf 'Release signing key must be a regular non-symlink file.\n' >&2
  exit 1
}
git -C "$ROOT_DIR" diff --quiet --ignore-submodules -- && \
  git -C "$ROOT_DIR" diff --cached --quiet --ignore-submodules -- || {
  printf 'Release builds require a clean tracked worktree and index.\n' >&2
  exit 1
}

cargo build --manifest-path "$ROOT_DIR/Cargo.toml" \
  --package abyssal-release-tool --release --locked
"$RELEASE_TOOL" check-root --private-key "$RELEASE_KEY"
"$ROOT_DIR/check.sh" all

VERSION="$(node -p "require('$ROOT_DIR/apps/web/package.json').version")"
ANDROID_VERSION="$(sed -n 's/.*versionName = "\([^"]*\)".*/\1/p' "$ROOT_DIR/android/app/build.gradle.kts" | head -1)"
[[ "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
  printf 'Web release version is invalid.\n' >&2
  exit 1
}
[[ "$VERSION" == "$ANDROID_VERSION" ]] || {
  printf 'Android and web release versions must match: android=%s web=%s\n' "$ANDROID_VERSION" "$VERSION" >&2
  exit 1
}
SOURCE_COMMIT="$(git -C "$ROOT_DIR" rev-parse --verify HEAD)"
SOURCE_EPOCH="$(git -C "$ROOT_DIR" show -s --format=%ct HEAD)"
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ && "$SOURCE_EPOCH" =~ ^[0-9]+$ ]] || {
  printf 'Release source identity is invalid.\n' >&2
  exit 1
}

BUILD_ID="web@$VERSION"
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/abyssal-web-release.XXXXXX")"
trap 'rm -rf -- "$TEMP_DIR"' EXIT
BUILD_SIGNATURE_FILE="$TEMP_DIR/web-build-signature.b64"
"$RELEASE_TOOL" sign-build \
  --private-key "$RELEASE_KEY" \
  --build-id "$BUILD_ID" \
  --source-commit "$SOURCE_COMMIT" \
  --output "$BUILD_SIGNATURE_FILE"
ABYSSAL_BUILD_SIGNATURE_B64="$(tr -d '\n' < "$BUILD_SIGNATURE_FILE")"
export ABYSSAL_BUILD_ID="$BUILD_ID" ABYSSAL_BUILD_SIGNATURE_B64 ABYSSAL_SOURCE_COMMIT="$SOURCE_COMMIT"

npm --prefix "$ROOT_DIR" run web:build
DIST_DIR="$ROOT_DIR/apps/web/dist"
[[ -f "$DIST_DIR/build-id.json" && ! -L "$DIST_DIR/build-id.json" ]] || {
  printf 'Web build identity was not emitted.\n' >&2
  exit 1
}
node -e '
  const fs = require("fs");
  const [path, buildId, sourceCommit, signature] = process.argv.slice(1);
  const raw = fs.readFileSync(path, "utf8");
  const expected = JSON.stringify({
    schema: "abyssal-build-identity-v1",
    build_id: buildId,
    source_commit: sourceCommit,
    build_signature_b64: signature,
  });
  if (raw !== expected) process.exit(1);
' "$DIST_DIR/build-id.json" "$BUILD_ID" "$SOURCE_COMMIT" "$ABYSSAL_BUILD_SIGNATURE_B64" || {
  printf 'Web build identity does not match release metadata.\n' >&2
  exit 1
}
[[ -z "$(find "$DIST_DIR" -type l -print -quit)" ]] || {
  printf 'Web release output must not contain symlinks.\n' >&2
  exit 1
}

mkdir -p "$OUTPUT_DIR"
ARCHIVE="$OUTPUT_DIR/abyssal-web-$VERSION.tar.gz"
BUILD_RECORD="$OUTPUT_DIR/abyssal-web-$VERSION-build-record.json"
for output in "$ARCHIVE" "$BUILD_RECORD"; do
  [[ ! -e "$output" ]] || { printf 'Release output already exists: %s\n' "$output" >&2; exit 1; }
done
tar --sort=name \
  --mtime="@$SOURCE_EPOCH" \
  --owner=0 --group=0 --numeric-owner \
  --pax-option=delete=atime,delete=ctime \
  -C "$DIST_DIR" -cf - . | gzip -n -9 > "$ARCHIVE"
gzip -t "$ARCHIVE"

RECORD_ARGUMENTS=(
  create-build-record
  --private-key "$RELEASE_KEY"
  --build-id "$BUILD_ID"
  --source-commit "$SOURCE_COMMIT"
  --expected-signature "$BUILD_SIGNATURE_FILE"
  --output "$BUILD_RECORD"
  --asset "$(basename "$ARCHIVE")" "$ARCHIVE"
)
while IFS= read -r -d '' asset; do
  RECORD_ARGUMENTS+=(--asset "${asset#"$DIST_DIR/"}" "$asset")
done < <(find "$DIST_DIR" -type f -print0 | sort -z)
"$RELEASE_TOOL" "${RECORD_ARGUMENTS[@]}"

printf 'Web archive: %s\n' "$ARCHIVE"
printf 'Build record: %s\n' "$BUILD_RECORD"
