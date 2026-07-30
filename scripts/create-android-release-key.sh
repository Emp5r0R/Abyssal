#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ABYSSAL_RELEASE_ENV:-$ROOT_DIR/deploy/release.env}"
KEYSTORE_PATH="${ABYSSAL_KEYSTORE_PATH:-$ROOT_DIR/.secrets/abyssal-release.jks}"
KEY_ALIAS="${ABYSSAL_KEY_ALIAS:-abyssal-release}"

if [[ -e "$KEYSTORE_PATH" || -e "$ENV_FILE" ]]; then
  printf 'Refusing to overwrite an existing release key or environment file.\n' >&2
  printf 'Keystore: %s\nEnvironment: %s\n' "$KEYSTORE_PATH" "$ENV_FILE" >&2
  exit 1
fi

command -v keytool >/dev/null || { printf 'keytool is required.\n' >&2; exit 1; }
command -v openssl >/dev/null || { printf 'openssl is required.\n' >&2; exit 1; }

mkdir -p "$(dirname "$KEYSTORE_PATH")" "$(dirname "$ENV_FILE")"
umask 077
STORE_PASSWORD="${ABYSSAL_KEYSTORE_PASSWORD:-$(openssl rand -hex 32)}"
KEY_PASSWORD="${ABYSSAL_KEY_PASSWORD:-$STORE_PASSWORD}"

keytool -genkeypair \
  -keystore "$KEYSTORE_PATH" \
  -storetype PKCS12 \
  -storepass "$STORE_PASSWORD" \
  -keypass "$KEY_PASSWORD" \
  -alias "$KEY_ALIAS" \
  -keyalg RSA \
  -keysize 4096 \
  -sigalg SHA256withRSA \
  -validity 10000 \
  -dname "CN=Abyssal Android Release, OU=Abyssal, O=Abyssal"

{
  printf 'ABYSSAL_KEYSTORE_PATH=%q\n' "$KEYSTORE_PATH"
  printf 'ABYSSAL_KEYSTORE_PASSWORD=%q\n' "$STORE_PASSWORD"
  printf 'ABYSSAL_KEY_ALIAS=%q\n' "$KEY_ALIAS"
  printf 'ABYSSAL_KEY_PASSWORD=%q\n' "$KEY_PASSWORD"
} >"$ENV_FILE"

chmod 600 "$KEYSTORE_PATH" "$ENV_FILE"
printf 'Created release keystore: %s\n' "$KEYSTORE_PATH"
printf 'Created ignored signing environment: %s\n' "$ENV_FILE"
printf 'Back up both files securely. Losing this key prevents signing compatible updates.\n'
