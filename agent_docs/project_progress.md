# Project Progress

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
