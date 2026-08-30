# Project Structure

## Web Client

- `apps/web/src/App.tsx` owns application lifecycle rendering and runs the full
  origin audit at startup. `Entrance` performs a fresh lightweight signed-release
  preflight immediately before each account submission.
- `apps/web/src/security/originAttestation.ts` contains the signed manifest,
  build-identity, and served-asset checks. Default concurrent startup calls are
  deduplicated only while the same audit is in flight.
- `apps/web/src/components/Privacy.tsx` owns privacy-cover PIN setup and the
  calculator cover. Setup validates the cover PIN, confirmation, and optional
  distinct duress PIN, with accessible live feedback and a vague enable failure.

## Mirage Relay

- `mirage-server/src/main.rs` owns process startup, shared application state,
  WebSocket/frame dispatch, and orchestration. Dedicated modules own the
  attachment, authentication/session, configuration, HTTP, transport,
  protocol-v9 message, and MLS concerns: `attachments.rs`, `auth.rs`,
  `config.rs`, `http.rs`, `messages.rs`, `transport.rs`, and `mls.rs`.
- `mirage-server/src/rooms.rs` is the protocol-v10 MLS `RoomAuthority` facade.
  Its focused implementations are in `rooms/model.rs`, `policy.rs`,
  `validation.rs`, `membership.rs`, `application.rs`, `delivery.rs`, and
  `snapshot.rs`.

## Deployment and Shared Loading UI

- `deploy/sync-server.sh` validates the clean source boundary and, on the
  published-release fallback, the exact canonical source tag; it fetches
  default public release assets into private temporary storage when no artifact
  overrides are supplied, verifies them before rsync, and stages the verified
  web archive. `deploy/deploy-server.sh` composes sync with the remote restart;
  `deploy/restart-docker.sh` only invokes the remote Docker rebuild/restart.
- `apps/web/src/components/Ui.tsx` owns the reusable web Abyssal mark loader.
  `apps/web/src/components/SecurityVerificationGate.tsx` owns the inline
  fail-closed release-admission surface, while `App.tsx` blocks account entry
  and workspace rendering and `Entrance.tsx` performs the submission preflight.
- `android/.../AbyssalMarkLoader.kt` owns the fixed-size Android loader,
  TalkBack semantics, and system-motion-scale policy. Web CSS and Android
  motion settings stop animation without removing the loading/status signal.
