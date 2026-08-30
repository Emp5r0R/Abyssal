# Project Diary

## 2026-08-30 - Web admission checks and relay ownership boundaries

The web startup path retains a full signed origin audit, including the served
asset set. Concurrent default startup calls share one in-flight audit and clear
that flight when it settles; a later call starts a new audit. Before every
account submission, the entrance runs a fresh lightweight signed-release
preflight for manifest validity, revocation, and build identity without
replacing the startup asset audit. Privacy-cover setup now validates a 6-12
digit cover PIN, matching confirmation, and an optional distinct 6-12 digit
duress PIN. Invalid state has accessible live guidance, while enable failures
use a generic message.

The relay entrypoint is now an orchestrator and frame-dispatch boundary. Its
attachment, authentication/session, configuration, HTTP, transport,
protocol-v9 message, and MLS responsibilities are delegated to dedicated
modules. `RoomAuthority` remains the MLS facade, with model, policy,
validation, membership, application, delivery, and snapshot implementations
behind it.

Remote deployment now has a published-release fallback. From a clean tracked
source commit with exactly one canonical version tag, the default sync fetches
the public manifest, signature, and matching web archive into private bounded
temporary storage, strips credential/netrc access, verifies the signed
archive/source-commit contract before transfer, and cleans the temporary files.
Explicit artifact paths remain available, while dirty, untagged, ambiguous, or
partial inputs stop before rsync. Docker restart is intentionally separate: it
does not download or use signing keys and recreates the remote container from
the already staged archive, so the relay restart still wipes RAM state.

The web and Android clients now share a reusable animated Abyssal mark loader.
Web release admission is an inline fail-closed surface before login/workspace
rendering, with a fresh lightweight preflight before account submission. Web
`prefers-reduced-motion` and Android `MotionDurationScale` disable motion while
keeping the corresponding accessible status/loading semantics.

## 2026-08-23 - Offline release provenance and strict build admission

Abyssal now has a separate Ed25519 release-provenance root shared through Rust core, WASM, JNI, relay, Android, and web. Canonical manifests bind exact Android/web build IDs to the same version/source commit, bounded asset digests, validity, sequence, and revocations. The relay mirrors only signed GitHub manifests into a monotonic RAM last-known-good store and checks exact build identity before bearer-session lookup or WebSocket ticket issuance. Web blocks account entry until its compiled identity, origin `build-id.json`, and all served bundle assets match the signed manifest. Android blocks account access until its baked identity matches, and user-approved updates are streamed to private cache with exact size/SHA-256 verification before a `FileProvider` installer handoff. Release tooling refuses unconfigured roots, dirty tracked trees, weak key files, or existing outputs. The integration key is fixed, debug/loopback-only, and forbidden at release compilation.

This is distribution hardening, not TEE attestation or a transparency log. Public build signatures can be replayed by patched clients; a malicious origin can remove its JavaScript self-check; a malicious relay can remove admission or deny service; RAM-only clients and relay restarts have no persistent sequence anchor; and GitHub becomes an availability dependency. The production root remains an unusable zero sentinel until the separately verified offline ceremony is completed. No Android APK/AAB may be released from that sentinel state.

## 2026-08-23 - Sender-client origin disclosure on message plaintexts

Text and attachment-metadata plaintexts in direct protocol-v9 chats and protocol-v10 MLS rooms now carry a `sender_client` tag (`android` or `web`) asserted by the sending build. The tag travels only inside the authenticated encrypted payload, so the relay cannot observe, strip, or forge it. Receivers validate it against a strict allowlist and fail closed on missing or unknown values, dropping the frame before publication or read-receipt emission. Android renders a small warning badge beside every web-origin sender name (tap for a full explanation) because that device may lack screenshot protection and any memory-wipe guarantee; the web client marks Android-origin messages informationally. Own locally composed messages are never badged. The change is wire-incompatible with older builds that omit the field, consistent with existing Deployment Rule 6 semantics; the relay-level acknowledgement still precedes plaintext validation, so dropped untagged frames consume their pending entry exactly like other malformed inner payloads.

This is per-message visibility into an already-disclosed residual limit, not new cryptography or attestation: the tag is as trustworthy as the rest of the decrypted plaintext, and a maliciously modified client build can mislabel itself. Read receipts remain untagged control frames. The integrated gate passed web 327 tests across 22 files with zero-warning lint and production build, 227 Android JVM tests plus release lint and debug/release compilation without packaging, rustfmt, locked workspace tests (53 core, 210 relay), warning-denied Clippy, live relay integration, generated-artifact and deployment checks, and zero-vulnerability npm and RustSec audits.

## 2026-08-16 - V2 directory equivocation detection

The relay now emits a V2 directory checkpoint in presence. Its SHA-256 transcript includes the authenticated node ID, the monotonic append-only account-map revision, and the sorted username-to-stable-64-byte-identity map. Account-map admission and encrypted fanout share the conversation transaction lock; presence snapshot computation and serialized fanout prevent concurrent broadcasts from publishing an older checkpoint after a newer one. The relay requires the exact current checkpoint before admission. Web and Android recompute the transcript and retain up to 32 stamps in RAM. Text, attachment metadata, and read receipts bind the checkpoint in both authenticated inner payload and outer frame; conflicts, cross-node/newer/altered replay evidence, or mismatches fail closed before ACK/publication, while evicted unknown-old frames drop without decryption or ACK.

This is bounded equivocation detection, not transparency. There is no signed append-only external witness or monitor; permanently partitioned/noncommunicating clients can evade gossip; logout, restart, or RAM-only lifecycle loss clears history; and the 32-stamp cap can turn an older valid frame into an availability drop.

## 2026-08-16 - Session-scoped direct safety-number interlock

Direct chats now display `NOT COMPARED` until the user explicitly confirms an exact safety-number match obtained through a separate channel. Android and web require that RAM-only confirmation for direct text, GIF/media upload, attachment view/export/save, and network read receipts. Incoming unverified text may render and become locally read without emitting a receipt. Records are bounded to 128 peers and keyed to the direct context, both stable identity prefixes (the first 64 bytes), and session/connection generations; prekey rotation is intentionally outside the key. Reconnect, identity change, logout, wipe, expiry, teardown, or eviction clears trust. This is a user assertion, not independent authentication or a Signal-grade claim; rooms remain pairwise, with no MLS or protocol-version change. Focused web checks (three affected files, 41 tests) and Android checks (39 tests) passed. The final integrated gate also passed with 249 web, 25 core, 134 relay, and 188 Android tests plus lint, production web build, live relay integration, and zero-vulnerability npm and RustSec audits.

## 2026-08-20 - Transactional attachment publication

Attachment uploads now require the same generated message ID used by encrypted metadata. The relay stages the encrypted blob under the authenticated owner/chat/message binding in a record that is non-downloadable to every user. Staged records count against existing byte and record quotas, expire after a 10-minute deadline clamped to final retention, and are swept every 30 seconds. After replay/state acceptance, exact authenticated admission promotes only the matching staged record server-side before fanout and result emission. Rejected, rolled-back, or never-sent messages do not publish; duplicate live bindings reject without replacing ciphertext; an accepted message whose result is lost still publishes. The upload API requires `message_id`; attachment ciphertext, keys, the cipher-v1 blob, and protocol-v9 encrypted-message shape are unchanged.

This closes the prior immediate-acceptance orphan gap without adding disk state. The tradeoff is a bounded pre-publication cleanup window of about 10.5 minutes, staged quota consumption, and fail-closed rejection of ambiguous bindings. The relay and clients still cannot recall in-flight or kernel-delivered bytes, and a hostile recipient can record decrypted content. This remains pairwise fanout rather than MLS, with no external key-transparency witness, persistent rollback anchor, or independent cryptographic audit; it is not a Signal-grade claim. The final integrated gate passed with 250 web, 25 Rust-core, 143 relay, and 189 Android tests plus lint, compilation/build, live relay integration, generated-artifact/deployment checks, and zero-vulnerability npm/RustSec audits. No Android packaging task was invoked.

## 2026-08-21 - Canonical encrypted message-frame buckets

Protocol-v9 encrypted application frames carrying text, read receipts, or attachment metadata now use a mandatory canonical outer transport envelope from sender to relay and relay to recipient. The complete UTF-8 application frame occupies the smallest bucket among 4,096, 16,384, 65,536, 262,144, and 1,048,576 bytes, with random URL-safe ASCII filler in `padding_bucket` and `padding`. Relay, web, and Android reject missing, malformed, noncanonical, truncated, and oversized frames; clients remove the transport fields before domain-state installation. Rate, transient-fanout, pending, and outbound queue budgets count the full padded bytes. The contract covers encrypted message frames only, not WebSocket control frames or HTTP attachment bodies, and JSON property order is not a security contract.

This reduces exact encrypted-message application-frame length leakage to bucket boundaries. It does not hide timing, counts, routing, participants, attachment sizes, relay or Cloudflare visibility, control-frame sizes, or bucket selection, and it does not add cover traffic. Older clients that omit the required padding are wire-incompatible even though the inner cryptographic payload remains protocol v9. The integrated gate passed web 258 tests across 19 files, Rust-core 25 tests, relay 149 tests, 197 Android JVM tests, Android lint/debug-release compilation, live integration, generated-artifact/deployment checks, and npm/RustSec audits; no Android packaging task was invoked.
