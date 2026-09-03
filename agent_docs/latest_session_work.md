# Latest Session Work

## 2026-09-03 - Unified Invite Capsule V1 source complete

Replaced the normal node-URL and access-code bootstrap with a signed,
self-contained Invite Capsule plus password flow. No package, tag, release, or
production deployment was performed in this source phase.

### Implemented

- Added the standalone `abyssal-invite` crate with canonical bounded CBOR,
  Ed25519 node identity/signatures, typed HTTPS and explicit loopback locators,
  a 256-bit account-bootstrap capability, expiry enforcement, deterministic
  URI/manual encodings, checksum validation, and stable vectors.
- Added separately provisioned relay node identity, signed `/v1/node`
  descriptors, one-time invite output, HMAC capability identifiers, exact
  one-winner registration, and node/capability-bound OPAQUE context.
- Web and Android now accept Invite + Password, parse through the shared Rust
  core, verify the connected node before authentication, reject redirects and
  unsafe locators, and keep decoded bootstrap material in process memory only.
- Added strict Android public-DNS policy, browser same-origin production policy,
  node-key and QR operator helpers, deployment preflight checks, protocol and
  security documentation, and cross-layer regression/integration coverage.
- Pinned `browserslist 4.28.8` after the full gate detected high-severity
  advisories affecting `4.28.6`.

### Verification

- `./scripts/test-all.sh crypto`: passed; checked-in WASM, UniFFI, and all four
  Android ABI libraries were regenerated and verified.
- Final `./scripts/test-all.sh all`: passed repository/deployment checks, web
  lint, 386 web tests and production build, 70 Rust-core tests, 14 invite tests,
  236 relay tests, rustfmt and warning-denied Clippy, Android JVM tests and
  release lint, live OPAQUE/v9/v10 relay integration, and dependency audits.
- npm audit reported zero vulnerabilities. RustSec reported no vulnerability
  and the existing allowed yanked transitive warning for `chacha20 0.10.1`.

### Next

- Create and push the fully verified source checkpoint without staging the
  user-owned `.gitignore` edit or local cache/helper files.
- Prepare one breaking release, require hosted CI/CodeQL success, verify every
  signed Android/web artifact and signer, then deploy that exact release with a
  persistent production node signing key and advertised HTTPS locator.

## 2026-08-25 - Release v2.2.0 published and production deployed

Released the first attested-distribution stable build and deployed it to
production. No repository source changes were made in this session.

### Released (GitHub v2.2.0, tag on `b8d1c74`)

- Rebuilt all release artifacts in a clean detached worktree at the green
  commit `b8d1c743dcf6f479b53d63623f29a87679d63b92` using the offline
  provenance key (`~/.abyssal-release/`) and the Android signing env; each
  build script re-ran the full non-packaging gate before packaging.
- Published `abyssal-android-2.2.0-universal-release.apk`,
  `abyssal-android-2.2.0-release.aab`, `abyssal-android-2.2.0-SHA256SUMS.txt`,
  `abyssal-web-2.2.0.tar.gz`, and signed `release-manifest-v1.json`/`.sig`
  (sequence 1, 30-day validity, no revocations). `releases/latest` serves them.
- Release notes follow the RELEASE.md disclosure requirements.

### Deployed (abyssal.nsa.tools)

- Synced committed HEAD, then restarted prod via tracked helpers. The running
  container serves the extracted verified web archive (image `/opt/abyssal/web`
  byte-identical to the published archive), loopback-only port 4020, health OK,
  CSP/HSTS present, interop defaults `android_to_web=false web_to_android=true`.
- Two ephemeral remote-only edits were required because HEAD's tracked
  Dockerfile cannot build HEAD as committed:
  1. `COPY tools ./tools` added to the rust-builder stage (root Cargo.toml
     declares the `tools/release-tool` workspace member but the Dockerfile never
     copied it). This is a latent repo bug to fix upstream.
  2. Final COPY switched from the web-builder stage output to the uploaded
     verified archive directory, per RELEASE.md "extract rather than rebuild".
  Both edits are wiped by the next `sync-server.sh`; fix item 1 in-tree before
  the next deployment and keep serving the verified archive.

### Operational deadlines / warnings

- Manifest expires ~2026-09-24 (30-day window): publish a successor release
  with a higher sequence before expiry or strict admission fails closed for
  every client.
- Fresh invite codes printed once into this session's transcript; treat as
  exposed if that transcript is shared and rotate via restart.
- Old clients (pre-2.2.0) are intentionally disconnected by current-only
  admission once this manifest is installed.

## 2026-08-23 - Sender-client origin disclosure (SECURITY.md residual limit)

Closed the next repository-fixable item from `SECURITY.md`: the browser
RAM/screenshot asymmetry was invisible at the message level.

### Implemented

- Added strict allowlist origin modules: `apps/web/src/domain/senderClient.ts`
  and `android/.../domain/model/SenderClient.kt` (single validation source).
- Outgoing text + attachment plaintexts in DM v9 and MLS v10 rooms are tagged
  with the sending platform (`messagePayload()` on web;
  `textMetadata`/`attachmentMetadataJson` on Android). Relay and Rust core
  untouched; the tag stays inside authenticated ciphertext.
- Inbound parsing fails closed on missing/unknown tags on both clients.
- Android `ChatScreen` shows an amber hazard badge on web-origin messages with
  a tap-to-explain Toast; web `ChatView` shows per-message warning
  (web-origin) or informational (Android-origin) badges with accessible labels.
- Updated `SECURITY.md` protections list and the "Browser RAM-only claims are
  limited" section, disclosing that the tag is self-reported, not attestation,
  and wire-incompatible with older builds.

### Verification

- Full integrated gate `./scripts/test-all.sh all` passed: web 327 tests/22
  files + zero-warning lint + production build; Android 227 JVM tests +
  release lint + debug/release compilation (no packaging); Rust rustfmt,
  locked tests (53 core, 210 relay), warning-denied Clippy; live relay
  integration; generated-artifact/deployment checks; npm audit 0
  vulnerabilities; RustSec audit of 272 locked dependencies clean.

### Unfinished / Handoff

- Nothing pending for this change. Pre-existing preserved local state
  (`.gitignore` edit adding `./AGENTS.md`, `sum.sh`, `.npm-cache/`,
  `.rustup-local/`) remains unstaged and untouched.
