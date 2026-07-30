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
5. Mark the release as a prerelease while the documented E2EE and PAKE gaps remain.

## Deploy relay

```bash
./deploy/deploy-server.sh
curl --fail https://chat.example.com/health
```

Confirm the container is healthy, the public endpoint is HTTPS, port `4020` is not publicly exposed, and fresh startup codes appear only in restricted logs. A restart intentionally destroys all prior accounts, sessions, rooms, pending frames, and attachments.

The sync helper transfers a clean archive of committed `HEAD` only. It explicitly protects the remote relay `.env` and excludes local signing credentials even if future ignore rules change.
