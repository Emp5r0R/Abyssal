#!/usr/bin/env bash
# Packages a VPS server release: the relay's Rust sources at the committed HEAD,
# the signed web release staged for the image build, and the one-command installer.
#
#   ABYSSAL_RELEASE_OUTPUT_DIR=build-outputs ./scripts/build-server-bundle.sh
#
# Writes abyssal-server-VERSION.tar.gz, its .sha256 and abyssal-install.sh next to
# the web release. The image build verifies the web archive against the signed
# manifest again with the release root compiled into the relay's release tool.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
OUTPUT_DIR="${ABYSSAL_RELEASE_OUTPUT_DIR:-$ROOT_DIR/build-outputs}"
RELEASE_TOOL="${ABYSSAL_RELEASE_TOOL:-}"

die() { printf '%s\n' "$1" >&2; exit 1; }

# Everything the relay image build reads, plus licences and the installer.
BUNDLE_PATHS=(
  .dockerignore Cargo.toml Cargo.lock rust-toolchain.toml uniffi-bindgen.toml
  LICENSE README.md SECURITY.md THIRD_PARTY_NOTICES.md
  abyssal-invite abyssal-transport mirage-server rust-core tools/release-tool
  deploy/install.sh
)

git -C "$ROOT_DIR" diff --quiet --ignore-submodules -- && git -C "$ROOT_DIR" diff --cached --quiet --ignore-submodules -- ||
  die 'Server bundles require a clean tracked worktree.'
SOURCE_COMMIT="$(git -C "$ROOT_DIR" rev-parse --verify HEAD^{commit})"
VERSION="$(sed -n 's/^  "version": "\([0-9]*\.[0-9]*\.[0-9]*\)",$/\1/p' "$ROOT_DIR/apps/web/package.json" | head -n 1)"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die 'Cannot read the release version from apps/web/package.json.'

WEB_ARCHIVE="$OUTPUT_DIR/abyssal-web-$VERSION.tar.gz"
MANIFEST="$OUTPUT_DIR/release-manifest-v1.json"
SIGNATURE="$OUTPUT_DIR/release-manifest-v1.sig"
for input in "$WEB_ARCHIVE" "$MANIFEST" "$SIGNATURE"; do
  [[ -f "$input" && ! -L "$input" ]] || die "Missing signed release input: $input"
done
BUNDLE="$OUTPUT_DIR/abyssal-server-$VERSION.tar.gz"
INSTALLER="$OUTPUT_DIR/abyssal-install.sh"
for output in "$BUNDLE" "$BUNDLE.sha256" "$INSTALLER"; do
  [[ ! -e "$output" ]] || die "Release output already exists: $output"
done

if [[ -z "$RELEASE_TOOL" ]]; then
  cargo build --quiet --manifest-path "$ROOT_DIR/Cargo.toml" --package abyssal-release-tool --release --locked
  RELEASE_TOOL="$ROOT_DIR/target/release/abyssal-release-tool"
fi
"$RELEASE_TOOL" verify-web-archive \
  --manifest "$MANIFEST" \
  --signature "$SIGNATURE" \
  --archive "$WEB_ARCHIVE" \
  --source-commit "$SOURCE_COMMIT"

STAGE="$(mktemp -d)"
trap 'rm -rf -- "$STAGE"' EXIT INT TERM
TOP="$STAGE/abyssal-server-$VERSION"
mkdir -p "$TOP/.web-release"
git -C "$ROOT_DIR" archive --format=tar "$SOURCE_COMMIT" -- "${BUNDLE_PATHS[@]}" | tar -xf - --no-same-owner -C "$TOP"
cp -- "$WEB_ARCHIVE" "$TOP/.web-release/"
cp -- "$MANIFEST" "$TOP/.web-release/release-manifest-v1.json"
cp -- "$SIGNATURE" "$TOP/.web-release/release-manifest-v1.sig"
printf '%s\n' "$SOURCE_COMMIT" > "$TOP/.web-release/source-commit"

# Reproducible archive: sorted names, fixed owners, commit time, no gzip timestamp.
COMMIT_TIME="$(git -C "$ROOT_DIR" log -1 --format=%ct "$SOURCE_COMMIT")"
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$COMMIT_TIME" \
  -C "$STAGE" -cf - "abyssal-server-$VERSION" | gzip -n -9 > "$BUNDLE"
(cd "$OUTPUT_DIR" && sha256sum -- "abyssal-server-$VERSION.tar.gz" > "abyssal-server-$VERSION.tar.gz.sha256")
git -C "$ROOT_DIR" show "$SOURCE_COMMIT:deploy/install.sh" > "$INSTALLER"
chmod 0755 "$INSTALLER"

printf 'Server bundle: %s\n' "$BUNDLE"
printf 'Checksum: %s\n' "$BUNDLE.sha256"
printf 'Installer: %s\n' "$INSTALLER"
