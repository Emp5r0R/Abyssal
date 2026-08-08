# Release Procedure

Abyssal releases require a clean full test run, a stable Android signing key, verified artifacts, an annotated Git tag, and a relay health check after deployment. Sign the tag when a maintained Git signing identity is configured; do not create an untrusted one-off signing key merely for a release.

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

The script requires `deploy/release.env`, rejects generated crypto bindings that do not match the recorded Rust-source digest, verifies the APK signature with `apksigner`, and writes the universal APK, AAB, and SHA-256 manifest to ignored `build-outputs/`.

## Publish

1. Review `git diff`, `SECURITY.md`, version code, and version name. The current protocol-v6 release is Android `versionCode 16`, `versionName 2.0.0`.
2. Commit and push `main`.
3. Create an annotated Git tag matching the Android version. Sign it with the project's established Git signing identity when one is configured.
4. Upload only the release APK, AAB, and checksum manifest from `build-outputs/`. Keep the build script's exact `abyssal-android-VERSION-universal-release.apk` name: Android update discovery intentionally rejects alternate filenames, hosts, repository paths, prereleases, and drafts.
5. Publish stable product releases only with the known cryptographic limits copied into release notes. Never describe Abyssal as Signal-grade, independently audited, or high-assurance until that work exists. Protocol-v6 releases must call out that text/read receipts/control metadata use ChaCha20-Poly1305 over pairwise Olm Double Ratchet sessions, each recipient envelope carries exactly one Ed25519 signature, and attachment keys travel in ratcheted metadata while bulk attachments use stateless XChaCha20-Poly1305 blobs with exactly 41 bytes of wire overhead. Release notes must also cover transactional ratchet rollback on failed payload authentication, queued-lifetime one-time-prekey claims, bounded login and attachment resources, single-session enforcement, and directory-checkpoint limits.
6. State the attachment lifecycle precisely: destructive DM downloads are scoped to the intended recipient, destructive room uploads snapshot eligible recipients, and the owner can preview without consuming a claim. Transport EOF does not consume a claim. The client must validate the exact non-empty body, authenticate and decrypt it, then explicitly complete its recipient-bound claim before exposing plaintext. Failed or interrupted transfers release their claims for retry, and deletion/quota release happens only after every eligible recipient completes or the retention policy expires the record. One-time viewing cannot prevent a malicious recipient from recording decrypted content.
7. State the remaining security limits: there is no MLS group protocol, key-transparency witness, multi-device coordination, persistent rollback anchor, or independent cryptographic audit. The web client remains dependent on its origin and JavaScript/WASM delivery, relay and network metadata remain visible, and any authenticated account can trigger the global wipe as an intentional availability risk.

## Deploy relay

```bash
./deploy/deploy-server.sh
curl --fail https://chat.example.com/health
```

Confirm the container is healthy, the public endpoint is HTTPS, port `4020` is not publicly exposed, and fresh startup codes appeared once in the attached deployment terminal. Codes must not exist in Docker logs, relay files, or environment configuration. The public health response exposes only liveness, node identity, and the RAM-only storage label; there is deliberately no code-retrieval workflow. A restart intentionally destroys all prior accounts, sessions, rooms, pending frames, and attachments. Docker automatic restart must remain disabled because an unattended restart rotates the unrecoverable one-time code set.

The sync helper transfers a clean archive of committed `HEAD` only. It explicitly protects the remote relay `.env` and excludes local signing credentials even if future ignore rules change. If the relay environment is missing on a first deployment, the restart helper installs the tracked template with mode `600`; review that file before distributing its generated invite codes.
