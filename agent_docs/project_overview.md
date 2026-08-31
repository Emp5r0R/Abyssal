# Project Overview

Abyssal's web client performs a full signed release-origin audit during startup.
The audit verifies the same-origin manifest, signature, build identity, and
every served JS/CSS/WASM/HTML asset. It has a 30-second aggregate deadline, a
12-second cap per request, and at most four concurrent asset checks. Concurrent
default startup calls share one in-flight audit; a completed audit is not reused
for account entry. Each account submission runs a fresh lightweight signed-
release preflight before invoking authentication. The WASM core is loaded with
a same-origin `no-store` request and its initialization aborts after 30 seconds.

Android account access uses a separate local admission path: the baked build ID,
source commit, and signature are checked through the compiled offline Ed25519
root before account entry. Bounded GitHub signed-manifest update discovery is
advisory after this check, so update-service availability cannot demote a valid
local admission. The relay remains authoritative for messaging: it requires the
exact current signed-manifest platform, version, and signature before parsing a
bearer token or issuing a WebSocket ticket.

The web privacy-cover setup requires a 6-12 digit cover PIN, matching
confirmation, and an optional 6-12 digit duress PIN that differs from the cover
PIN. It exposes accessible live guidance for invalid state and uses a generic
failure message when enabling the cover fails.

The Mirage relay entrypoint is an orchestration and dispatch layer. Attachments,
authentication/session handling, configuration, HTTP, transport, protocol-v9
message routing, and MLS integration live in dedicated modules. The protocol-v10
MLS `RoomAuthority` remains the public facade over model, policy, validation,
membership, application, delivery, and snapshot modules.

The published-release deployment path accepts a clean tracked `HEAD` only when
exactly one canonical `vMAJOR.MINOR.PATCH` tag points at it. Without artifact
overrides, `deploy-server.sh` downloads the public signed manifest, signature,
and tag-matching web archive into private temporary storage, bounds the HTTPS
fetch, verifies the archive/source-commit contract before rsync, and cleans
temporary files. Explicit artifact overrides remain supported; dirty,
untagged, ambiguous, or partial fallback inputs fail before transfer.
`restart-docker.sh` only rebuilds/restarts the remote container from an already
staged verified archive; it does not download or use signing keys and the relay
restart wipes RAM state.

The web and Android clients reuse the animated Abyssal mark for loading states.
Web release admission stays inline and fail-closed before account entry and
workspace rendering, with a fresh preflight before each account submission.
Reduced-motion settings stop the mark animation while preserving accessible
status/loading semantics.
