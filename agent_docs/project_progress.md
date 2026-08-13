# Project Progress

## Completed Deployment: Attachment Metadata Resource Hardening

The protocol-v8 security checkpoint was committed and pushed as `a7450d3`.
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
