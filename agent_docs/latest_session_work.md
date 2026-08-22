# Latest Session Work

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
