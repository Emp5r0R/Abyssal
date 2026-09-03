# Release Procedure

Abyssal releases require a clean full test run, a stable Android signing key, verified artifacts, an annotated Git tag, and a relay health check after deployment. Sign the tag when a maintained Git signing identity is configured; do not create an untrusted one-off signing key merely for a release.

## One-time provenance trust-root ceremony

Do this on an isolated machine. Build the release tool from reviewed source, generate the key, and back up the private key offline:

```bash
cargo build --release --locked --package abyssal-release-tool
./scripts/create-release-provenance-key.sh
```

Verify the printed SHA-256 public-key fingerprint through a separate channel. On the reviewed source machine, install only the public key, regenerate shared artifacts, and run the full gate:

```bash
ABYSSAL_RELEASE_ROOT_FINGERPRINT=<separately-verified-fingerprint> \
  ./scripts/install-release-public-key.sh /secure/path/abyssal-release-ed25519.pub
./scripts/test-all.sh crypto
./check.sh all
```

Commit the reviewed public root and regenerated artifacts. Never commit the private key or copy it to a relay or container. The source sentinel is deliberately unusable before this ceremony. The fixed integration key is restricted to debug loopback tests and cannot compile in release mode.

## One-time Android signing setup

```bash
./scripts/create-android-release-key.sh
```

This creates an ignored keystore under `.secrets/` and an ignored `deploy/release.env`. The environment file is a strict data-only file with exactly four literal assignments; it is never sourced or executed. Back up both in an encrypted offline location. Never commit either file. Android updates must use the same signing key.

## Verification

```bash
./check.sh all
```

The command checks shell syntax and repository whitespace, then runs web lint/tests/build, Rust formatting/tests/clippy, Android JVM tests/lint/Kotlin compilation without invoking Android packaging, and a live disposable-relay integration test. Android packaging remains an explicit release-only step. The 2026-08-28 integrated local gate ran 352 web tests across 31 files, 68 Rust-core tests, 20 release-tool tests, 232 relay tests, and 241 Android JVM tests; the forbidden integration-root release compile check, release lint, debug/release compilation, protocol-v9 direct/protocol-v10 MLS integration with strict build admission, deterministic generated-artifact/deployment checks, and npm/RustSec audits also passed. All applicable tests had zero skips, failures, or errors; no Android packaging task was invoked. CodeQL must pass remotely after push.

## Signed Android artifacts

```bash
ABYSSAL_RELEASE_SIGNING_KEY_FILE=/secure/offline/abyssal-release-ed25519.key \
  ANDROID_SDK_ROOT="$HOME/Android/Sdk" \
  ./scripts/build-android-release.sh
```

The script requires `deploy/release.env`, validates that the environment and keystore are regular files owned by the current user with no group/world permissions, rejects stale crypto bindings, and parses signing values without shell evaluation. It also requires the provenance private-key file to match the compiled public root, binds `android@VERSION` and the exact source commit into the app, refuses existing outputs, verifies APK/AAB signatures, and emits a build record containing exact artifact sizes and SHA-256 digests.

## Signed web artifact and release manifest

On the same clean commit and isolated release host:

```bash
ABYSSAL_RELEASE_SIGNING_KEY_FILE=/secure/offline/abyssal-release-ed25519.key \
  ./scripts/build-web-release.sh

: > /secure/work/revocations.txt
ABYSSAL_RELEASE_SIGNING_KEY_FILE=/secure/offline/abyssal-release-ed25519.key \
ABYSSAL_RELEASE_SEQUENCE=<strictly-increasing-sequence> \
ABYSSAL_RELEASE_NOT_BEFORE_MS=<activation-unix-ms> \
ABYSSAL_RELEASE_EXPIRES_AT_MS=<expiry-unix-ms-within-35-days> \
  ./scripts/assemble-release-manifest.sh \
  build-outputs/abyssal-android-VERSION-build-record.json \
  build-outputs/abyssal-web-VERSION-build-record.json \
  /secure/work/revocations.txt
```

The web builder bakes the signed build identity into JavaScript and `/build-id.json`, records every served asset plus the deterministic web archive, and requires the Android/web version and source commit to agree. Each platform build is bounded to 128 authenticated assets; exceeding that limit fails before manifest creation. Manifest assembly is canonical, refuses overwrite, signs with the offline root, and supports one revoked build ID per line. At runtime the web startup audit has a 30-second aggregate deadline, a 12-second request cap, and at most four concurrent served-asset checks; the WASM core uses a same-origin `no-store` load and aborts after 30 seconds. Keep each validity window operationally short; the verifier enforces a maximum of 35 days.

## Publish

1. Review `git diff`, `SECURITY.md`, version code, and version name. Current source retains protocol-v9 OPAQUE/Olm direct chats and introduces protocol-v10 MLS rooms. Protocol-v9 room clients have no pairwise compatibility fallback and fail closed. Advance the Android version before any package release, regenerate matching native/WASM bindings, and keep the canonical padded direct-message envelope mandatory.
2. Commit and push `main`.
3. Create an annotated Git tag matching the Android version. Sign it with the project's established Git signing identity when one is configured.
4. Upload the exact universal APK, AAB, checksum file, deterministic web archive, `release-manifest-v1.json`, and `release-manifest-v1.sig` from `build-outputs/`. Keep the generated names unchanged. Android and the relay require the two manifest assets; Android also requires the exact universal APK name/path/size. Extract the verified web archive for deployment rather than rebuilding it on the relay.
5. Publish stable product releases only with the current constructions and limits summarized from [SECURITY.md](../SECURITY.md). State that account entry uses OPAQUE plus registration proof-of-possession; direct protocol v9 uses signed pairwise Olm Double Ratchet envelopes and authenticated prekey leases; rooms use protocol-v10 RFC 9420 MLS; attachment cipher v2 uses fixed authenticated 256 KiB plaintext records; and every WebSocket application/control frame uses canonical transport padding. Describe Android account admission as local baked build ID/source/signature verification through the compiled offline Ed25519 root; GitHub update discovery is separate, bounded, advisory, and its availability failure cannot demote a valid local admission. State that relay messaging remains gated by the exact current signed manifest before bearer or WebSocket access. Include the web audit's 30-second aggregate, 12-second request, four-worker, same-origin/no-store WASM limits. State the build-attested platform interoperability defaults and any deployment overrides. Never describe Abyssal as hardware/TEE-attested, Signal-grade, independently audited, anonymous, metadata-free, or high-assurance. Include the remaining external-transparency, multi-device, persistent rollback-anchor, web-runtime/origin, traffic-metadata, malicious-relay, offline-wipe, recipient-recording, and experimental-MLS-provider limits.
   Release notes must also state that `ack_result` is emitted only after exactly one matching pending recipient frame and, for a leased first-contact frame, its matching lease, plus the signed state mutation/removal; post-native-decrypt wrapper/schema/state-install failures clear identity and fail closed while pre-return authentication failures are drops; Android inbound ciphertext and room/direct queues are bounded and generation-tagged, overflow closes and requires reconnect/resync, and invalidation drains/wipes them; commands, sends, and ACKs are connection-generation-bound; a carried global wipe survives same-account reconnect while explicit logout drains pending wipe/work; duress is account-stamped; every attachment operation uses its captured `NodeSession`; Android accepted attachment publication is connection-generation/repository-epoch guarded; cancellation, failure, and late responses release destructive claims exactly once and wipe buffers; and abnormal socket invalidation clears socket-scoped joins, catalogs, and identity authorization before reconnect.
6. State attachment lifecycle precisely. The upload carries the encrypted message ID and is staged as non-downloadable encrypted cipher-v2 records until exact authenticated owner/chat/message admission publishes it. Every published record retains the uploader's attested platform and an exact eligible-recipient snapshot; non-owners need both membership and an allowed platform direction even for non-destructive files. Staged records consume quotas and expire after the bounded staging deadline. Duplicate bindings, invalid record order/length/authentication, unauthorized downloads, and failed message admission fail closed. Destructive completion remains recipient-bound and explicit; owner preview does not consume a claim. Clients wipe transfer buffers and release claims on failure or cancellation. Relay/UI deletion cannot recall bytes already handed to an operating-system, kernel, or hostile recipient.
7. State the remaining security limits: there is protocol-v10 MLS, but no external key-transparency witness, multi-device coordination, persistent rollback anchor, or independent cryptographic audit. Pairwise Olm Double Ratchet exists, but it is not a claim of Signal-grade security. The web client remains dependent on its origin and JavaScript/WASM delivery and cannot guarantee physical RAM-only behavior or physical zeroization. First-contact relay key substitution still requires out-of-band safety-number verification. Relay and network metadata, including timing, routing, packet sizes, and bucket selection, remain visible; current padding is not cover traffic. Offline or uncooperative clients cannot receive a purge, and bytes already handed to the kernel cannot be recalled. Any authenticated account can trigger the global wipe as an intentional availability risk.

8. For protocol-v10 room releases, document RFC 9420 MLS through exact `mls-rs 0.55.4` and RustCrypto provider `0.22.1`; random group identifiers; owner-approved key-package joins, Welcome, additions, and removals; exact epoch/digest/roster relay validation; and encrypted per-member RAM-only recovery snapshots. Document transactional sender state commit only after exact accepted `mls_room_result`, transactional recipient application/control commit only after exact accepted `mls_snapshot_result`, fail-closed ambiguity, the `synchronized` outbound gate, bounded replay/delivery/state resources, the 1,024-generation back-history limit, and loss of undecryptable expired tails until a membership epoch refresh. Do not claim an independently audited MLS implementation: the RustCrypto provider is experimental, external key transparency and multi-device coordination remain absent, and RAM-only clients have no persistent rollback anchor.

## Deploy relay

Provision the relay's stable node identity once on the deployment host, then
set its advertised HTTPS locator. This key is separate from release provenance
and Android signing keys; it remains on the relay host and must be backed up
through a separate secure path:

```bash
cd /home/ubuntu/abyssal
./deploy/generate-node-key.sh
cp mirage-server/.env.example mirage-server/.env
$EDITOR mirage-server/.env  # set ABYSSAL_PUBLIC_URL=https://exact-origin
chmod 600 mirage-server/.env .secrets/node-signing.key
```

The generator refuses to replace an existing key. Source synchronization
excludes and preserves both `.secrets/` and `mirage-server/.env`.

From a clean checkout whose `HEAD` has exactly one canonical
`vMAJOR.MINOR.PATCH` tag, the default deployment path needs no local artifact
paths:

```bash
./deploy/deploy-server.sh
```

With no artifact overrides (and no complete local release set),
`sync-server.sh` downloads the public `release-manifest-v1.json`, detached
signature, and tag-matching web archive from the configured canonical GitHub
repository into private mode-700 temporary storage. It removes GitHub
credential variables and netrc access, requires HTTPS-only redirects, bounds
redirects/time/size, verifies the signed archive/source-commit contract before
rsync, verifies the staged copy, and cleans temporary files. Dirty, untagged,
multiply tagged, partial, or otherwise ambiguous inputs fail before rsync. The
release signing key is not downloaded or required on the deployment host.

Explicit artifact overrides remain supported when all required paths are
provided and match the committed source:

```bash
ABYSSAL_RELEASE_OUTPUT_DIR=/secure/release-output \
ABYSSAL_WEB_RELEASE_MANIFEST=/secure/release-output/release-manifest-v1.json \
ABYSSAL_WEB_RELEASE_SIGNATURE=/secure/release-output/release-manifest-v1.sig \
ABYSSAL_WEB_RELEASE_ARCHIVE=/secure/release-output/abyssal-web-VERSION.tar.gz \
  ./deploy/deploy-server.sh
curl --fail https://chat.example.com/health
```

Confirm the container is healthy, the public endpoint is HTTPS, port `4020` is not publicly exposed, and fresh signed Invite Capsules appeared once in the attached deployment terminal. Capsules and capabilities must not exist in Docker logs, relay files, or environment configuration. Fetch `/v1/node` and confirm that its node ID/fingerprint matches the expected persistent node identity. Confirm public responses preserve both `no-store` and `no-transform`; CDN analytics or challenge injection changes signed HTML and must remain disabled. The public health response exposes only liveness, node identity, and the RAM-only storage label; there is deliberately no capsule-retrieval workflow. A restart intentionally destroys all prior accounts, sessions, rooms, pending frames, and attachments while the separately mounted key preserves node identity. Docker automatic restart must remain disabled because an unattended restart rotates the unrecoverable one-time capability set.

Before any rsync, the sync helper verifies the offline-root signature, canonical
manifest validity window, current web build and revocation state, exact
committed `HEAD`, and archive filename, size, and SHA-256 digest. It transfers a
clean archive of that commit plus only the verified web archive. The Docker
build extracts those exact web bytes and never rebuilds the browser bundle from
source. The helper explicitly protects the remote relay `.env` and excludes
local signing credentials even if future ignore rules change. If the relay
environment is missing on a first deployment, the restart helper installs the
tracked template with mode `600`; startup deliberately fails until a real
`ABYSSAL_PUBLIC_URL` and the owner-only node key exist. Review both before
distributing generated Invite Capsules.

`restart-docker.sh` is a separate remote rebuild/restart operation. It never
downloads release assets and has no signing-key dependency; it recreates the
container from the already staged verified archive. Restarting the relay
intentionally destroys its RAM-only accounts, sessions, rooms, pending frames,
attachments, and capability set while retaining the configured node identity.
