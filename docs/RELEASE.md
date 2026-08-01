# Release Procedure

Abyssal releases require a clean full test run, a stable Android signing key, verified artifacts, a Git tag, and a relay health check after deployment.

## One-time Android signing setup

```bash
./scripts/create-android-release-key.sh
```

This creates an ignored keystore under `.secrets/` and an ignored `deploy/release.env`. Back up both in an encrypted offline location. Never commit either file. Android updates must use the same signing key.

## Verification

```bash
./check.sh all
```

The command checks shell syntax and repository whitespace, then runs web lint/tests/build, Rust formatting/tests/clippy, Android JVM tests/lint/debug and release builds, and a live disposable-relay integration test.

## Signed Android artifacts

```bash
ANDROID_SDK_ROOT="$HOME/Android/Sdk" ./scripts/build-android-release.sh
```

The script requires `deploy/release.env`, verifies the APK signature with `apksigner`, and writes the universal APK, AAB, and SHA-256 manifest to ignored `build-outputs/`.

## Publish

1. Review `git diff`, `SECURITY.md`, version code, and version name.
2. Commit and push `main`.
3. Create a signed Git tag matching the Android version.
4. Upload only the release APK, AAB, and checksum manifest from `build-outputs/`.
5. Publish stable product releases only with the known cryptographic limits copied into release notes. Never describe Abyssal as Signal-grade, independently audited, or high-assurance until that work exists.

## Deploy relay

```bash
./deploy/deploy-server.sh
curl --fail https://chat.example.com/health
```

Confirm the container is healthy, the public endpoint is HTTPS, port `4020` is not publicly exposed, and fresh startup codes appeared once in the attached deployment terminal. Codes must not exist in Docker logs, relay files, or environment configuration. After startup, inspect only counts through health data; there is deliberately no code-retrieval workflow. A restart intentionally destroys all prior accounts, sessions, rooms, pending frames, and attachments.

The sync helper transfers a clean archive of committed `HEAD` only. It explicitly protects the remote relay `.env` and excludes local signing credentials even if future ignore rules change. If the relay environment is missing on a first deployment, the restart helper installs the tracked template with mode `600`; review that file before distributing its generated invite codes.
