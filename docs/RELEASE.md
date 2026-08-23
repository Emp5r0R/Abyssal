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

The command checks shell syntax and repository whitespace, then runs web lint/tests/build, Rust formatting/tests/clippy, Android JVM tests/lint/Kotlin compilation without invoking Android packaging, and a live disposable-relay integration test. Android packaging remains an explicit release-only step. The 2026-08-23 integrated local gate ran 332 web tests across 24 files, 63 Rust-core tests, 15 release-tool tests, 215 relay tests, and 234 Android JVM tests; the forbidden integration-root release compile check, release lint, debug/release compilation, protocol-v9 direct/protocol-v10 MLS integration with strict build admission, deterministic generated-artifact/deployment checks, and npm/RustSec audits also passed. All applicable tests had zero skips, failures, or errors; no Android packaging task was invoked. CodeQL must pass remotely after push.

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

The web builder bakes the signed build identity into JavaScript and `/build-id.json`, records every served asset plus the deterministic web archive, and requires the Android/web version and source commit to agree. Manifest assembly is canonical, refuses overwrite, signs with the offline root, and supports one revoked build ID per line. Keep each validity window operationally short; the verifier enforces a maximum of 35 days.

## Publish

1. Review `git diff`, `SECURITY.md`, version code, and version name. Current source retains protocol-v9 OPAQUE/Olm direct chats and introduces protocol-v10 MLS rooms. Protocol-v9 room clients have no pairwise compatibility fallback and fail closed. Advance the Android version before any package release, regenerate matching native/WASM bindings, and keep the canonical padded direct-message envelope mandatory.
2. Commit and push `main`.
3. Create an annotated Git tag matching the Android version. Sign it with the project's established Git signing identity when one is configured.
4. Upload the exact universal APK, AAB, checksum file, deterministic web archive, `release-manifest-v1.json`, and `release-manifest-v1.sig` from `build-outputs/`. Keep the generated names unchanged. Android and the relay require the two manifest assets; Android also requires the exact universal APK name/path/size. Extract the verified web archive for deployment rather than rebuilding it on the relay.
5. Publish stable product releases only with the known cryptographic limits copied into release notes. Never describe Abyssal as Signal-grade, independently audited, or high-assurance until that work exists. Direct protocol-v9 releases must call out OPAQUE registration proof-of-possession over a fresh server challenge; direct text/read receipts/control metadata use ChaCha20-Poly1305 over pairwise Olm Double Ratchet sessions; each recipient envelope carries exactly one Ed25519 signature; and successful state snapshots are Ed25519-signed with bounded revisions. Document the exact 608-byte public bundle (stable 64-byte identity portion, 16 canonical 32-byte one-time keys covered by the signed identity bundle, and 32-byte fallback), authenticated prekey leases bound to sender/chat/recipient/message/prekey before first-contact encryption, 30-second idle TTL, global 4,096 and per-recipient 16 capacities, accepted pending-frame lease pinning, and generation-bound client release only for definitely unused leases. Document mandatory authenticated 256-byte plaintext-length buckets and the mandatory outer encrypted-message frame buckets (`4096`, `16384`, `65536`, `262144`, `1048576`) with random URL-safe filler; the outer envelope applies only to text/read-receipt/attachment-metadata application frames, not WebSocket control frames or HTTP attachment bodies, and full padded bytes count toward relay budgets. Missing, malformed, wrong-smallest-bucket, truncated, and oversized frames fail closed; clients strip transport fields before domain state. This reduces exact encrypted-message application-frame length leakage to bucket boundaries but does not hide timing, count, routing, participants, attachment sizes, relay/Cloudflare visibility, control-frame sizes, or bucket selection, and it is not cover traffic. Continue documenting staged outbound ratchets, strict `message_result` acceptance only after atomic all-recipient fanout admission, rollback only for explicit rejection/not-sent results, fail-closed session closure on ambiguity, and dedicated result-sink confirmation (a sink failure invalidates the session). Document the receiver `ack_result` transaction: exact matching message ID, signed recipient state update and pending removal before emission, recipient publication only after exact acceptance, consumed-lease removal with one-for-one replacement and preservation of other live leases, fail-closed rejected/not-sent/timeout/disconnect/malformed/unknown/duplicate outcomes, and separate Android 64/web 256 pending-ACK bounds. Also document single-use 30-second WebSocket tickets, attachment keys in ratcheted metadata, cipher-v1 XChaCha20-Poly1305 bulk blobs with exactly 41 bytes of wire overhead, the global attachment pool covering stored and in-flight references, independent attachment record quotas (16,384 global and 4,096 per account by default, configurable through `ABYSSAL_ATTACHMENT_RECORD_LIMIT` and `ABYSSAL_ATTACHMENT_ACCOUNT_RECORD_LIMIT`, clamped to 1-65,536 with the account value capped by global), 4 MiB/client and 64 MiB/global live outbound queue byte caps, the 1,024-room catalog cap, purge text plus close code `4001`/`purge`, and Android lifecycle/catalog/send bounds (generation-stamped shared 64-operation text/read-receipt bound, a drainable generation-tagged 1,152-event room/direct catalog channel, and repository-epoch-guarded mutations that reject stale work after synchronous purge). Release notes must also cover transactional decrypt rollback, bounded login and attachment resources, single-session enforcement, heap-aware Android attachment admission, directory-checkpoint limits, the tested envelope of at most 117 accounts and core peer cap 256, and protocol-v10 MLS room behavior, recovery, and limits. Protocol-v8 shapes/checkpoints fail closed. Preserve the historical note that Android 2.0.0 introduced deletion of the obsolete device-bound export key.
   Release notes must also state that `ack_result` is emitted only after exactly one matching pending recipient frame and, for a leased first-contact frame, its matching lease, plus the signed state mutation/removal; post-native-decrypt wrapper/schema/state-install failures clear identity and fail closed while pre-return authentication failures are drops; Android inbound ciphertext and room/direct queues are bounded and generation-tagged, overflow closes and requires reconnect/resync, and invalidation drains/wipes them; commands, sends, and ACKs are connection-generation-bound; a carried global wipe survives same-account reconnect while explicit logout drains pending wipe/work; duress is account-stamped; every attachment operation uses its captured `NodeSession`; Android accepted attachment publication is connection-generation/repository-epoch guarded; cancellation, failure, and late responses release destructive claims exactly once and wipe buffers; and abnormal socket invalidation clears socket-scoped joins, catalogs, and identity authorization before reconnect.
6. State the attachment publication and lifecycle precisely: each upload must carry the same generated message ID used by its encrypted metadata. The relay stages the encrypted blob in a record that is non-downloadable to every user; staged records count against byte and record quotas, expire after a 10-minute deadline clamped to final retention, and are swept every 30 seconds. After replay/state acceptance, exact authenticated owner/chat/message admission promotes the matching staged record server-side before fanout and result emission. Rejected, rolled-back, or never-sent messages do not publish; duplicate live bindings reject without replacing ciphertext; an accepted message whose result is lost still publishes. The upload API now requires `message_id`; attachment ciphertext, keys, and cipher-v1 bulk bytes are unchanged; direct metadata stays v9 while room metadata uses v10 MLS. Destructive DM downloads are scoped to the intended recipient, destructive room uploads snapshot eligible recipients, and the owner can preview without consuming a claim. Every upload, download, delete, complete, and release uses the captured `NodeSession`. Transport EOF does not consume a claim. If `Content-Length` is present, it must match the metadata-derived ciphertext length; if absent, the client accepts only an exact bounded body of that length. The client authenticates and decrypts it, then explicitly completes its recipient-bound claim before exposing plaintext. Failed, truncated, oversized, interrupted, cancelled, or unauthenticated transfers release their claims exactly once, including late responses, and wipe transfer buffers; deletion/quota release happens only after every eligible recipient completes or the retention policy expires the record. Operation cancellation invalidates lifecycle generations and revokes local media URLs. A pre-publication process or connection loss leaves only a non-downloadable staged record for at most about 10.5 minutes; an accepted encrypted message whose result is lost still publishes its attachment under normal retention. The relay and clients cannot recall in-flight or kernel-delivered bytes. One-time viewing cannot prevent a malicious recipient from recording decrypted content.
7. State the remaining security limits: there is protocol-v10 MLS, but no external key-transparency witness, multi-device coordination, persistent rollback anchor, or independent cryptographic audit. Pairwise Olm Double Ratchet exists, but it is not a claim of Signal-grade security. The web client remains dependent on its origin and JavaScript/WASM delivery and cannot guarantee physical RAM-only behavior or physical zeroization. First-contact relay key substitution still requires out-of-band safety-number verification. Relay and network metadata, including timing, routing, packet sizes, and bucket selection, remain visible; current padding is not cover traffic. Offline or uncooperative clients cannot receive a purge, and bytes already handed to the kernel cannot be recalled. Any authenticated account can trigger the global wipe as an intentional availability risk.

8. For protocol-v10 room releases, document RFC 9420 MLS through exact `mls-rs 0.55.4` and RustCrypto provider `0.22.1`; random group identifiers; owner-approved key-package joins, Welcome, additions, and removals; exact epoch/digest/roster relay validation; and encrypted per-member RAM-only recovery snapshots. Document transactional sender state commit only after exact accepted `mls_room_result`, transactional recipient application/control commit only after exact accepted `mls_snapshot_result`, fail-closed ambiguity, the `synchronized` outbound gate, bounded replay/delivery/state resources, the 1,024-generation back-history limit, and loss of undecryptable expired tails until a membership epoch refresh. Do not claim an independently audited MLS implementation: the RustCrypto provider is experimental, external key transparency and multi-device coordination remain absent, and RAM-only clients have no persistent rollback anchor.

## Deploy relay

```bash
./deploy/deploy-server.sh
curl --fail https://chat.example.com/health
```

Confirm the container is healthy, the public endpoint is HTTPS, port `4020` is not publicly exposed, and fresh startup codes appeared once in the attached deployment terminal. Codes must not exist in Docker logs, relay files, or environment configuration. The public health response exposes only liveness, node identity, and the RAM-only storage label; there is deliberately no code-retrieval workflow. A restart intentionally destroys all prior accounts, sessions, rooms, pending frames, and attachments. Docker automatic restart must remain disabled because an unattended restart rotates the unrecoverable one-time code set.

The sync helper transfers a clean archive of committed `HEAD` only. It explicitly protects the remote relay `.env` and excludes local signing credentials even if future ignore rules change. If the relay environment is missing on a first deployment, the restart helper installs the tracked template with mode `600`; review that file before distributing its generated invite codes.
