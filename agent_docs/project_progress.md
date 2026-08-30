# Project Progress

## Active Deployment: v2.3.0 Signed Release and Production Rollout

The original release-provenance key, Android keystore, and strict Android
credential file were recovered from the established owner-only external release
directory. This package publishes the completed relay modularization, inline
web admission, unified loading UX, and verified deployment recovery without
changing the existing trust roots.

### Bounded Plan

1. Verify the recovered Ed25519 key against the committed public fingerprint
   and the Android keystore against the existing release signer; advance all
   canonical version surfaces to `2.3.0` with the next Android version code.
2. Run the complete final-tree test and security gate, stage only intended
   project changes, commit, and push `main` while preserving unrelated local
   files.
3. Require CI and CodeQL success for the exact commit, create and push the
   annotated `v2.3.0` tag, and build signed Android/web artifacts plus the
   canonical manifest from a clean isolated worktree using the established
   external keys.
4. Verify artifact digests, signatures, manifest binding, and signer continuity;
   publish one stable GitHub release with complete notes and exact assets.
5. Deploy the exact published release through `deploy-server.sh`, verify relay
   and public health plus web admission, and record only observed results.

### Acceptance Gates

- No replacement release root or Android signer is generated.
- All applicable tests, security gates, CI, and CodeQL pass for the exact
  released commit.
- The APK/AAB, web archive, manifest, and detached signature bind the same
  version, source commit, and established signing identities.
- Production runs the exact published web archive and reports healthy after
  the intentional RAM-only restart.

## Completed Deployment: Verified Deploy Recovery and Unified Loading UX

### Delivered

- `deploy-server.sh` can acquire the exact published manifest, detached
  signature, and web archive when no local artifact inputs exist. It accepts
  only one canonical release tag at committed `HEAD`, uses bounded HTTPS-only
  downloads in a private temporary directory, verifies every artifact before
  transfer, and rejects dirty, untagged, ambiguous, partial, oversized, or
  tampered inputs before `rsync`.
- `restart-docker.sh` remains an explicit restart of the remotely staged,
  verified archive. It performs no release download and needs no offline
  signing key.
- Web startup verification is a fail-closed inline page state rather than a
  dialog. Account entry is absent until verification succeeds, authenticated
  attestation rejection hides the workspace, and every login submission runs
  a fresh bounded signed-manifest preflight before OPAQUE authentication.
- The web client reuses the login page's four-ring Abyssal mark for startup,
  runtime, and entry loading. Android now has a reusable Compose loader backed
  by its canonical `MirageLogo` drawing for entrance verification, connection,
  build/update verification, and video preparation. Fixed sizing,
  reduced-motion rendering, and loading-versus-terminal semantics are covered
  by deterministic tests; quantitative attachment progress remains unchanged.

### Verification

- Independent deployment tests passed release acquisition, explicit overrides,
  clean-source enforcement, artifact validation, and pre-transfer rejection.
- Independent web verification passed 34 files and 374 tests, lint, TypeScript,
  and the production build. Component tests cover the inline admission and
  loader states; the local Playwright attempt could not cross the signed
  attestation test boundary and is not counted as passed evidence.
- Independent Android verification passed focused loader-policy tests and
  debug Kotlin compilation, including static reduced-motion loading semantics.
- Final `./scripts/test-all.sh all` passed repository and shell checks, web
  tests/build, 321 Rust tests, Android unit/lint/release compilation, live
  OPAQUE/v9/v10 relay integration, and dependency advisory checks. A second
  final-tree run is required after this progress reconciliation.

### Operational Boundary

- No commit, push, tag, release, or production deployment was performed. The
  worktree is intentionally rejected by deployment while it contains
  uncommitted changes, and the matching offline release key, Android keystore,
  and release environment are not available in this checkout. Production
  packaging must use the original material matching the compiled release trust
  root and existing Android signer; generating replacements would break that
  trust chain.

## Completed Deployment: Web Admission UX and Relay Modularization

### Delivered

- Privacy-cover setup now exposes exact 6-12 digit validation state, matching
  confirmation, optional distinct duress-PIN validation, accessible guidance,
  and a generic enable-failure surface.
- The full signed startup origin/asset audit remains mandatory. Concurrent
  default startup calls share only their active flight, while every account
  submission performs a fresh lightweight manifest, revocation, and exact
  build-identity preflight before password encoding or OPAQUE authentication.
- The relay entrypoint delegates attachment, authentication/session,
  configuration, HTTP, transport, protocol-v9 message, and MLS responsibilities
  to dedicated modules. `RoomAuthority` remains the stable facade over focused
  model, policy, validation, membership, application, delivery, and snapshot
  modules.
- Protocol schemas, transactional delivery behavior, resource limits,
  zeroization, and RAM-only lifecycle remain unchanged.

### Verification

- Independent focused verification passed 368 web tests and 321 Rust tests,
  web lint/build, Rust formatting, and strict Clippy.
- Final `./scripts/test-all.sh all` passed repository and shell checks, 368 web
  tests plus production build, 321 Rust tests, Android unit/lint compilation,
  live OPAQUE/v9/v10 relay integration, and dependency advisory checks.
- The advisory scan reported zero vulnerabilities and one explicitly allowed
  yanked-crate warning for `chacha20 0.10.1`.
- No release was created for this package.

## Active Deployment: Attested Release Recovery

Production v2.2.0 serves the exact signed web archive, but browser account entry
is blocked because the web verifier follows GitHub release-download redirects
that do not provide a browser CORS contract. This package restores the
fail-closed attestation path and makes production deployment reproducible.

### Bounded Plan

1. Serve the relay's exact RAM-held, signature-verified release manifest and
   detached signature through fixed same-origin well-known endpoints; keep web
   verification of signature, validity, revocation, build identity, and every
   served asset.
2. Fix the tracked container build and deployment flow so production consumes
   an explicitly supplied, validated signed web archive instead of rebuilding
   an unattested bundle or relying on remote-only Dockerfile edits.
3. Add regression tests for manifest delivery, browser request origins,
   archive staging, and fail-closed deployment prerequisites; reconcile public
   release/security text with the implemented behavior.
4. Run the complete repository gate, require CI and CodeQL success on the exact
   commit, build v2.2.1 Android/web artifacts from a clean worktree, verify the
   existing Android signer, publish sequence 2, and deploy the exact web
   archive.
5. Verify production health, browser attestation/account-entry rendering,
   release digests/signatures, and the installed Android artifact.

## Completed Deployment: Sender-Client Origin Disclosure

This package makes the web-versus-Android security asymmetry visible per
message instead of only in documentation. Text and attachment-metadata
plaintexts now carry a sender-client tag validated strictly by both clients,
and each client renders a per-message origin badge for received messages.

### Delivered

- Direct protocol-v9 and protocol-v10 MLS text and attachment metadata carry a
  `sender_client` field (`android` or `web`) inside the authenticated
  encrypted payload. The relay never sees it and cannot forge or strip it.
- Both clients fail closed on missing, mistyped, or unknown tags: the frame is
  dropped before publication or read-receipt emission. This is
  wire-incompatible with older untagged builds per existing deployment rules;
  read receipts remain untagged control frames.
- Android shows a small amber warning icon beside every web-origin message
  (tap for the full screenshot/memory-limit explanation); the web client shows
  a warning badge for web-origin messages and an informational badge for
  Android-origin ones. Own composed messages are never badged.
- Domain-owned allowlist modules (`domain/senderClient.ts`,
  `SenderClient.kt`) are the single validation source for both directions,
  keeping parsing, transport, and presentation decoupled.

### Verification

- Final `./scripts/test-all.sh all`: passed on the integrated tree.
- Web: 327 tests in 22 files, zero-warning ESLint, TypeScript compilation, and
  the production Vite build passed.
- Rust: rustfmt, locked workspace tests (53 core, 210 relay), and
  warning-denied Clippy passed; core and relay behavior is unchanged.
- Android: 227 JVM unit tests with zero skips/failures/errors, release lint,
  and debug/release Kotlin compilation passed without packaging an APK or AAB.
- Live relay integration (OPAQUE, v9 E2EE DM, v10 MLS rooms, offline
  recovery/replay, access control), generated-artifact/deployment checks, and
  zero-vulnerability npm/RustSec audits passed.

### Remaining External Limits

The tag is self-reported inside the decrypted plaintext, not an attestation;
a maliciously modified client build can mislabel itself. It adds no cover
traffic, does not change ratchet or attachment semantics, and cannot prevent
a hostile recipient from recording content. All previously disclosed limits
(web origin trust, metadata visibility, no external transparency witness,
persistent rollback anchor, multi-device coordination, independent audit)
remain separate work in `SECURITY.md`.

## Active Deployment: Protocol-v10 MLS Rooms

This breaking package replaces pairwise room fanout with RFC 9420 MLS while
leaving direct-chat Olm sessions isolated behind their existing core boundary.
Protocol-v9 room clients will fail closed rather than receive a compatibility
fallback.

### Bounded Plan

1. Add a private Rust-core MLS adapter using exact `mls-rs 0.55.4` and
   `mls-rs-crypto-rustcrypto 0.22.1`, with account-bound credentials, bounded
   opaque FFI records, transactional state, sealed RAM-recovery snapshots, and
   native/WASM/Android tests.
2. Replace relay room access and all-account fanout with owner-approved,
   epoch-bound MLS membership; bounded join requests, control messages,
   encrypted per-member state snapshots, replay windows, and exact roster
   attachment authorization.
3. Add web and Android MLS room managers, strict protocol-v10 schemas,
   lifecycle invalidation, UI join/approval/removal flows, and no pairwise room
   fallback. Regenerate pinned reproducible WASM, UniFFI, and Android-native
   artifacts only after the core API stabilizes.
4. Cover create, join, Welcome, add, remove, leave, offline control, encrypted
   text and attachments, rollback, tamper, replay, restart, delete, and global
   wipe across focused and disposable-relay integration tests.
5. Update verified architecture and security disclosures, then run the complete
   non-packaging repository gate before commit or push. Do not build or release
   an Android package during this deployment.

### Provider Decision

OpenMLS `0.8.1` was rejected because its locked dependency graph contains
current high-severity RustSec findings. Exact `mls-rs 0.55.4` with RustCrypto
`0.22.1` passed create/add/Welcome/remove/application/reload behavior, native
Rust, `wasm32-unknown-unknown`, all four Android ABIs, RustSec, and license
checks. The provider is Apache-2.0 OR MIT and compatible with MPL-2.0. Its
RustCrypto backend is still marked experimental, and `mls-rs` has not received
an independent third-party security audit; those facts remain explicit
residual risks rather than being represented as solved.

## Completed Deployment: Canonical WebSocket Envelope Padding

This package reduces exact encrypted-message length leakage on the TLS path by
requiring every protocol-v9 `message` WebSocket frame to occupy the smallest
canonical wire bucket that can contain it. It does not claim sender anonymity,
cover traffic, attachment-size hiding, or protection from the relay or TLS
terminator.

### Delivered

- Sender-to-relay and relay-to-recipient `message` frames use exact 4 KiB,
  16 KiB, 64 KiB, 256 KiB, or 1 MiB serialized UTF-8 buckets with bounded
  random ASCII filler.
- Relay, web, and Android independently select and validate the smallest
  canonical bucket; missing, malformed, noncanonical, truncated, or oversized
  padding fails closed before message admission or publication.
- Padding is transport-only and does not alter protocol-v9 ciphertext,
  signatures, ratchet state, attachment cipher-v1 bytes, or generated crypto
  bindings.
- Existing inbound rate limits, per-client/global outbound byte reservations,
  transient fanout budgets, pending queues, session generations, and purge
  behavior account for the complete padded frame.
- Cohesive Rust, web, Android, and disposable-relay integration tests cover
  bucket boundaries, distinct plaintexts in the same bucket, tampering,
  overflow, accounting, and lifecycle invalidation.
- This outer envelope is mandatory for matching clients but remains separate
  from the protocol-v9 cryptographic payload. Older builds that omit the two
  transport fields are wire-incompatible.

### Verification

- Final `./scripts/test-all.sh all`: passed on the integrated tree.
- Web: 258 tests in 19 files, zero-warning lint, TypeScript compilation, and
  production Vite build passed.
- Rust: 25 core tests and 149 relay tests passed with rustfmt, locked workspace
  tests, and warning-denied workspace Clippy.
- Android: 197 JVM tests with zero skips/failures/errors, release lint, and
  debug/release Kotlin compilation passed without packaging an APK or AAB.
- Disposable-relay OPAQUE/E2EE integration covered first-contact prekeys,
  padded text and attachment metadata, read receipts, rollback, and offline
  replay. Generated-artifact, dependency-verification, deployment, shell,
  npm, and RustSec checks passed.

### Remaining External Limits

The buckets reduce exact encrypted-message application-frame length leakage,
not traffic analysis generally. Timing, counts, routing, participants, control
frames, attachment sizes, bucket selection, and relay/TLS-terminator visibility
remain exposed. Sealed sender, batching, private contact discovery, optional
cover traffic, MLS, multi-device coordination, an external transparency
witness, a persistent rollback anchor, and an independent audit remain separate
work. No Android package, release, or production deployment was performed.

## Completed Deployment: Transactional Attachment Publication

This package reduces the remaining encrypted-attachment orphan window without
adding disk state or weakening ambiguous-message handling. Each upload is bound
to its already-generated sender/chat/message identity and remains staged under a
short relay deadline until the relay atomically accepts that exact encrypted
message transaction.

### Delivered

- Upload admission now requires the valid message ID already generated for
  ratcheted metadata and rejects duplicate live owner/chat/message bindings
  without replacing ciphertext.
- Staged encrypted records consume existing byte and record quotas, are
  non-downloadable to every account, and require a live 10-minute deadline
  clamped to final retention. Missing or expired deadlines fail closed; the
  30-second sweeper bounds normal cleanup to about 10.5 minutes.
- After replay registration and signed state acceptance, the relay promotes
  only the matching authenticated owner's staged record before fanout and
  result emission. Rejected or rolled-back admission cannot publish it, while
  an accepted message whose result is lost still publishes it.
- Publication is serialized by the existing conversation/attachment locks and
  preserves quota, deletion, destructive claim, expiry, restart, and wipe
  semantics. The upload API requires `message_id`; attachment keys, cipher-v1
  blobs, and protocol-v9 encrypted-message shapes are unchanged.
- Web and Android pass the exact generated message ID to upload while retaining
  the existing captured-session, cancellation, cleanup, and ambiguous-result
  behavior.

### Verification

- Final `./scripts/test-all.sh all`: passed on the integrated tree.
- Web: 250 tests in 18 files, zero-warning lint, TypeScript compilation, and the
  production Vite build passed.
- Rust: 25 core tests and 143 relay tests passed with rustfmt, locked workspace
  tests, and warning-denied workspace Clippy.
- Android: 189 JVM tests with zero skips/failures/errors, release lint, and
  debug/release Kotlin compilation passed without invoking Android packaging.
- Disposable-relay OPAQUE/E2EE integration covered pre-admission `404`, exact
  publication, normal download, destructive completion/release, and access
  control. Generated-artifact/source, Gradle dependency, deployment, shell,
  npm, and RustSec checks also passed.

### Remaining External Limits

The pre-publication cleanup window is bounded rather than physically
instantaneous. In-flight or kernel-delivered bytes cannot be recalled, hostile
recipients can record decrypted content, and global wipe cannot reach offline
clients. MLS group state, multi-device coordination, an external transparency
witness, a persistent rollback anchor, metadata-obscuring transport, and an
independent audit remain separate disclosed work. No Android package, release,
or production deployment was performed.

## Completed Deployment: Direct Safety-Number Comparison Interlock

This deployment closes the repository-fixable direct-chat verification gap by
requiring a session-scoped, out-of-band safety-number comparison before either
client performs sensitive direct actions.

### Delivered

- Android and web direct chats remain `NOT COMPARED` until the user confirms an
  exact match for the displayed symmetric safety number. Direct text, GIF and
  media upload, attachment view/export/save, and network read receipts fail
  closed until that confirmation.
- Incoming unverified direct text may render and become locally read without
  emitting a receipt. Rooms retain their existing pairwise behavior and are
  unaffected by the direct-chat gate.
- Each client keeps at most 128 confirmations in RAM, bound to the exact direct
  context, both stable long-term identity prefixes, and the active session and
  connection generations. Rotating prekeys do not invalidate a confirmation;
  stable identity changes do.
- Reconnect, logout, wipe, inactivity expiry, teardown, and bounded-store
  eviction clear applicable confirmation state. Deferred send and attachment
  work rechecks the captured session and connection epochs before cryptography,
  upload, download, decrypt, save, or plaintext exposure.
- Adversarial tests cover wrong comparison values, unknown and stale chats,
  identity replacement, prekey-tail rotation, reconnect races, bounded-store
  eviction, suppressed untrusted receipts, and blocked attachment operations.

### Verification

- Final `./scripts/test-all.sh all`: passed on the integrated tree.
- Web: 249 tests in 18 files, zero-warning ESLint, TypeScript compilation, and
  the production Vite build passed.
- Rust: 25 core tests and 134 relay tests passed with rustfmt, locked workspace
  tests, and warning-denied workspace Clippy.
- Android: 188 JVM unit tests, release lint, and debug/release Kotlin
  compilation passed without packaging an APK or AAB.
- Live OPAQUE/E2EE relay integration, generated artifact/source verification,
  Gradle dependency verification, immutable workflow/container checks, shell
  syntax checks, npm audit with zero vulnerabilities, and the RustSec audit of
  239 locked dependencies passed.

### Remaining External Limits

The confirmation is a user assertion, not an external transparency witness or
proof that the peer compared the value. Process restart clears RAM-only trust.
An external transparency service, a persistent rollback anchor, multi-device
coordination, MLS group protocol, and independent audit remain separate work.
No package, release, or production deployment was performed.

## Completed Deployment: Directory Equivocation Detection

This deployment closed the next repository-fixable item in `SECURITY.md` after
protocol-v9 prekey leasing by adding authenticated, monotonic directory
evidence that clients can compare and gossip without persisting account or
message state to disk.

### Delivered

- The relay computes a canonical SHA-256 directory checkpoint over the node ID,
  bounded monotonic account revision, and sorted username-to-long-term-identity
  map. Presence broadcasts are serialized so an older snapshot cannot follow a
  newer one, and message admission requires the exact current checkpoint.
- Web and Android independently recompute checkpoints, retain a bounded
  32-entry RAM-only history, reject malformed, stale, conflicting, or
  cross-node evidence, and clear the history with the authenticated session.
- Text, attachment metadata, and read-receipt plaintext bind the same directory
  evidence as their encrypted outer frame. Exact mismatch fails before decrypt
  publication or acknowledgement, while unknown checkpoints evicted from the
  bounded history are dropped without acknowledgement.
- Direct peers carry the authenticated checkpoint through existing protocol-v9
  encryption, making conflicting views detectable whenever those views cross a
  communicating client boundary. Replay tracking binds each message ID to the
  exact directory evidence originally accepted.
- The disposable-relay integration recomputes the Rust transcript, covers text,
  attachment metadata, read receipts, and offline replay, and verifies that
  missing or stale evidence is rejected before fanout with ratchet rollback,
  prekey-lease release/reuse, and an exact-message-ID valid retry.

### Verification

- Final `./scripts/test-all.sh all`: passed after integration-harness migration.
- Rust: 25 core tests and 134 relay tests passed with rustfmt, locked workspace
  tests, and warning-denied workspace Clippy.
- Web: 241 tests in 17 files, zero-warning lint, TypeScript compilation, and the
  production Vite build passed.
- Android: 182 JVM unit tests, release lint, and debug/release Kotlin
  compilation passed without packaging an APK or AAB.
- Live OPAQUE/E2EE relay integration, generated artifact/source verification,
  Gradle dependency verification, immutable workflow/container checks, shell
  syntax checks, npm audit with zero vulnerabilities, and RustSec audit passed.

### Remaining External Limits

Client gossip is not an independent signed witness. A malicious relay that
permanently partitions inconsistent views can prevent the evidence from
crossing clients, process/session restart clears the RAM-only history, and the
32-entry bound can turn very old evidence into a safe availability drop. An
external transparency witness, persistent rollback anchor, multi-device
coordination, MLS group protocol, and independent audit remain separate work.
No package, release, or production deployment was performed.

## Completed Deployment: Protocol-v9 Initial Prekey Pool

Protocol v9 replaces the single advertised Olm one-time prekey with a bounded,
signed pool and an authenticated lease-before-encrypt transaction across the
Rust core, relay, web client, and Android client.

### Delivered

- Each identity publishes a canonical 16-key pool covered by its long-term
  Ed25519 identity signature, registration proof, and state transcript. The
  exact public bundle is 608 bytes and protocol-v8 bundles and checkpoints fail
  closed.
- The relay leases an exact unused prekey to the authenticated sender,
  conversation, recipient, and message ID before encryption. Exact retries are
  idempotent; leases expire after 30 seconds unless pinned by accepted pending
  ciphertext, and global/per-recipient bounds are 4,096/16.
- ACK handling locks and validates the account, pending frame, pending-byte
  accounting, and lease together. It removes exactly the consumed key, accepts
  exactly one replacement, and preserves every other live lease.
- Web and Android consult the native ratchet before leasing, bind asynchronous
  operations to the active session/connection generation, release only leases
  known to remain unused, roll back on explicit rejection or not-sent outcomes,
  and fail closed on ambiguous outcomes.
- Generated WASM, UniFFI, and four JNI artifacts were regenerated twice with
  pinned tools and byte-identical manifests. The disposable-relay integration
  exercises lease acquisition, deterministic release/reuse, first-contact
  encryption, delivery, and acknowledgement.

### Verification

- Rust: 25 core tests and 130 relay tests passed with rustfmt, wasm32 checking,
  warning-denied workspace Clippy, and locked workspace tests.
- Web: 229 tests, zero-warning lint, TypeScript compilation, and the production
  Vite build passed.
- Android: 179 unit tests, release lint, and debug/release Kotlin compilation
  passed without packaging an APK or AAB.
- Reproducible binding generation, artifact/source digests, path-leak scans,
  shell/Node syntax checks, live relay integration, npm audit, and RustSec audit
  passed. No package, release, or production deployment was performed.

### Remaining External Limits

Rooms remain bounded pairwise Olm fanout. The relay can create at most 117
accounts from its distinct invite-code lengths and the core caps fanout at 256;
replacing pairwise sessions with MLS is a separate protocol migration. Abyssal
still has no independent cryptographic/application audit, external
key-transparency witness, multi-device coordination protocol, or persistent
rollback anchor. These limits remain disclosed in `SECURITY.md`.

## Completed Deployment: Dependency Update Integration

Compatible Dependabot families were integrated together and independently
verified instead of force-merging eighteen isolated pull requests.

### Delivered

- Upgraded direct RustCrypto SHA-256/HKDF/HMAC, `base64`, and `futures-util`
  dependencies while preserving the `opaque-ke` SHA-512 digest boundary.
- Aligned React/react-dom 19.2.8 and compatible web tooling, retained TypeScript
  6.0.3, and pinned transitive `nanoid` 3.3.18 to clear the full npm audit.
- Upgraded AndroidX JUnit 1.3.0 and Espresso 3.7.0 with strict exact-hash Gradle
  verification metadata.
- Updated pinned checkout/setup-node actions and aligned CI and the immutable
  Docker builder on Node 26.7.0.

### Deferred

- OkHttp/MockWebServer 5.4.0 require Kotlin 2.1/2.2 metadata, so the app remains
  on 4.12.0 rather than bypassing compiler checks or excluding its runtime.
- The 2026 Compose BOM remains incompatible with the current Kotlin/compiler
  family, and TypeScript 7 exceeds `typescript-eslint`'s declared `<6.1` range.

### Verification

- Rust: 23 core and 127 relay tests, warning-denied Clippy, RustSec scan, and
  two byte-identical WASM/JNI generations passed.
- Web: clean locked install, 220 tests, lint/build, peer/engine inspection, and
  full npm audit with zero vulnerabilities passed independently.
- Android: 170 unit tests, debug/release compilation, release lint, strict
  dependency resolution, and verification-metadata inspection passed; no APK
  or AAB was built.
- CI/container: action/digest pin checks, cached and uncached Docker builds,
  hardened Compose runtime smoke, health endpoint, and served web UI passed.
- Final integrated `./scripts/test-all.sh all` passed after the dependency and
  progress-document changes, including live relay integration and both npm and
  RustSec advisory scans.

## Completed Deployment: Attachment Metadata Resource Hardening

The protocol-v8 security checkpoint was committed and pushed as `a11c0e5`.
The next repository-fixable package closes a relay denial-of-service gap where
minimum-size encrypted attachment records could exhaust heap through map and
record metadata while remaining under the ciphertext-byte quota.

### Delivered

- Added configurable, clamped global and per-account attachment-record limits,
  defaulting to 16,384 and 4,096 records respectively.
- Enforced authoritative count capacity before request-body allocation and
  again atomically with final insertion after expiry pruning and authorization
  revalidation. Existing byte quotas and attachment wire behavior are unchanged.
- Added deterministic boundary, concurrent admission, minimum-blob, expiry,
  deletion, destructive completion, room cleanup, and wipe capacity tests.
- Updated the example environment, operator configuration, security model, and
  release checklist.

### Verification

- Independent focused attachment suite: 37 passed.
- Full relay suite: 125 passed; warning-denied Clippy and rustfmt passed.
- Final `./scripts/test-all.sh all`: passed, covering web, Rust, Android without
  packaging, disposable-relay integration, supply-chain checks, and npm/RustSec
  advisory scans.
- No Android package, release, or production deployment was performed. The
  unrelated `.gitignore` edit, `.npm-cache/`, `.rustup-local/`, and `sum.sh`
  remain protected local state.

## Completed Deployment: Protocol-v8 Security Completion

The repository-fixable protocol-v8 security package is complete and ready for
its source checkpoint. No Android APK/AAB was packaged, no release was
published, and production was not deployed or restarted.

### Delivered

- Rust core: OPAQUE registration proof of possession, pairwise Olm Double
  Ratchet sessions, signed and revision-bounded state snapshots, staged
  outbound commit/rollback, transactional decrypt rollback, and authenticated
  256-byte plaintext-length buckets.
- Relay: atomic all-recipient fanout admission, sink-confirmed
  `message_result`, exact pending-recipient and claim preconditions for
  `ack_result`, bounded queues and replay windows, finite pending/attachment
  lifetimes, and priority purge handling.
- Web: registration proof, protocol-v8 transaction handling, strict catalog and
  sender binding, bounded attachment operations, lifecycle cleanup, and
  fail-closed ambiguous ratchet behavior.
- Android: connection-generation-bound commands, sends, ACKs, inbound payloads,
  catalog changes, purge handling, and repository publication; bounded queues
  close/resync on overflow and wipe queued ciphertext on invalidation.
- Android attachment operations use an explicitly captured `NodeSession` for
  upload, download, delete, claim completion, and claim release. Cancellation,
  failure, and late responses release destructive claims at most once and wipe
  owned buffers. Accepted publication is guarded by account, connection, and
  repository generations.
- Android duress work is stamped to the captured account and cannot broadcast
  or purge a replacement login.
- README, security model, release process, integration checks, and generated
  WASM/JNI bindings are protocol-v8 consistent.

### Verification

- Independent Android repair verification: 98 focused tests and 170 full unit
  tests, with zero skips, failures, or errors; debug Kotlin compilation passed.
- Final `./scripts/test-all.sh all`: passed.
  - Web: 17 files / 220 tests, zero-warning lint, production build.
  - Rust: 22 core tests and 119 relay tests, rustfmt, warning-denied Clippy.
  - Android: JVM tests, release lint, debug Kotlin compile, release Kotlin
    compile; no APK/AAB packaging.
  - Disposable relay integration: OPAQUE authentication, E2EE DM, offline
    replay, and access control.
  - Supply-chain/generated-artifact checks, shell checks, npm audit with zero
    vulnerabilities, and RustSec scan of 227 dependencies.

### Remaining External Limits

No repository change can replace an independent cryptographic/application
audit, an external key-transparency witness, a multi-device coordination
protocol, or a persistent rollback anchor. Pairwise Olm is not MLS, first
contact still needs out-of-band safety-number verification, metadata remains
visible, web security depends on origin delivery, and offline/uncooperative
clients cannot be remotely wiped. These limits remain documented in
`SECURITY.md` and release guidance.

### Preserved Local State

The unrelated `.gitignore` edit, `.npm-cache/`, `.rustup-local/`, and `sum.sh`
remain unstaged.
