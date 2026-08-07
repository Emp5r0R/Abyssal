# Abyssal Security Model

No application has absolute security. Abyssal implements ratcheted end-to-end encryption and OPAQUE authentication, but it has not received an independent audit and must not be presented as Signal-equivalent.

## Current Protections

- Relay state is process memory only: keyed invite-code identifiers, OPAQUE password files, encrypted identity envelopes, sessions, room catalog, presence, recipient-specific pending ciphertext, and attachments have no database or volume. Plaintext invite codes exist only until their one-time startup print, then those buffers are zeroized.
- Android app-owned account, message, endpoint, PIN, password, token, and key state is process memory only. `FLAG_SECURE` blocks normal Android screenshots and recents snapshots.
- Web client uses no persistent browser storage, cookies, service worker, source maps, or third-party runtime scripts. Identity keys live in the shared Rust/WASM core; typed password, plaintext, and key buffers are overwritten on a best-effort basis after use.
- OPAQUE registration and login use the shared Rust `opaque-ke` implementation. Password bytes never appear in relay application requests. Identity and ratchet snapshots are encrypted with an OPAQUE export-key-derived key before leaving the client.
- Protocol-v5 text, attachment, and read-receipt payloads use a fresh content key and ChaCha20-Poly1305 with conversation/message/sender additional data. Each recipient's content key is wrapped through an authenticated `vodozemac` Olm Double Ratchet session configured for a full-length HMAC, and Ed25519 signatures bind the outer ciphertext. Initial asynchronous messages use a recipient-specific one-time prekey, which is rotated after successful decryption. Prekey IDs are deterministic commitments to their public keys; recipients verify relay metadata against the one-time key inside the Olm envelope before changing ratchet state. The relay records a bounded claim for the advertised prekey until acknowledgement, preventing concurrent deliveries from claiming the same prekey. The relay receives ciphertext, signatures, public identity bundles, prekey metadata, ratchet envelopes, and OPAQUE-encrypted state snapshots, not plaintext or ratchet secrets.
- Successful encryption and decryption advance a monotonic ratchet-state revision. The relay keeps only the latest encrypted snapshot in RAM, uses a 128-revision replay window to accept bounded network reordering without accepting a message revision twice, and never replaces newer state with an older snapshot. Recipient ciphertext remains queued until a sender-bound acknowledgement follows successful decryption.
- The relay authoritatively binds delivered sender usernames/public keys to authenticated accounts and rejects missing, duplicate, or unauthorized recipient envelope sets. Clients reject malformed, tampered, wrongly addressed, or misbound payloads before parsing plaintext.
- Direct conversations display a symmetric safety number derived from both identity public keys. Comparing it through a separate channel detects active relay key substitution for that conversation.
- TLS/WSS is required for remote web nodes loaded from HTTPS. Loopback HTTP remains available for development.
- WebSocket bearer tokens are sent as a WebSocket subprotocol value, not in request URLs. Browser WebSocket origins must match the node host or an exact `ABYSSAL_WEB_ORIGINS` entry.
- Relay responses set a restrictive CSP, no-store caching, frame denial, no-referrer, MIME sniffing denial, HSTS, permissions restrictions, and cross-origin headers.
- Account request bodies, WebSocket frame size/rate, attachment type size, total attachment RAM, session inactivity, and per-user room count are bounded.
- Account-entry attempts are rate-limited per code, and a code cannot create a concurrent bearer session while its existing session remains unexpired.
- Relay and clients maintain bounded RAM replay windows keyed by conversation, authenticated sender, and message ID. Ratchet message keys are consumed after use, so cryptographic replays also fail. Duplicate ciphertext and receipt frames are rejected without growing unbounded state.
- Clients pin each observed account identity key for the current RAM session and terminate/drop state if that key changes. First-contact authenticity still requires out-of-band safety-number comparison.
- Sender usernames on delivered frames come from the authenticated relay session, not user-controlled encrypted metadata.
- Room ownership and media-retention policy are enforced by the relay. Canonical DMs are visible only to their participants, and guessed chat IDs cannot be used to join a DM or transfer its attachments.
- Android and web attachment saves are explicit user actions. Clients authenticate and decrypt attachment ciphertext in memory, write the original bytes under a sanitized original filename, and best-effort wipe temporary byte arrays. One-time attachments have no save control. Saved files are plaintext by explicit user choice and inherit the destination provider's security. Android `1.7.2` and later also delete the obsolete device-bound export key created by older releases.

## Known High-Risk Gaps

### Initial prekey and group-key limits

Protocol v5 uses pairwise Olm Double Ratchet sessions. Deleted message keys provide the ratchet's forward-secrecy property, and reciprocal DH-ratchet steps provide recovery within an established session after key turnover. Initial asynchronous sessions consume a recipient-specific one-time prekey and rotate it after use. The relay enforces one live WebSocket session per account and a bounded prekey-claim window, but the design is still not MLS: rooms use pairwise fanout, prekey replenishment is one-at-a-time rather than a signed batch service, and multi-device session coordination is not implemented.

### Directory verification limits

Presence includes a deterministic directory checkpoint over usernames and stable long-term identity keys. Clients reject inconsistent checkpoints in one presence update and pin each peer's long-term identity across one-time-prekey rotation. This is a useful out-of-band comparison signal, not a signed append-only transparency log: the relay can still equivocate between clients, and there is no independent witness or monitor service yet.

Rooms encrypt the same content separately to every account through pairwise sessions. There is no MLS group epoch, membership transcript, efficient group rekey, or multi-device device list. Large rooms therefore have linear envelope cost and weaker membership-change semantics than a reviewed MLS design.

### State rollback and recovery limits

Encrypted ratchet snapshots and pending ciphertext exist only in relay RAM. This permits process-memory-only clients to recover a session after app-process death, but a malicious relay can withhold or replay an older encrypted snapshot. Because clients deliberately keep no persistent state, they have no independent monotonic counter with which to prove rollback after a fresh login. A relay restart destroys accounts, snapshots, pending messages, and replay windows together.

Delivery acknowledgements are authenticated by the WebSocket session and bound to conversation, recipient, original sender, and message ID. They are transport durability signals, not cryptographic proof to the sender that a human read the message.

### Active relay and web-delivery trust

An actively malicious relay can substitute recipient public keys before a sender has independently verified the direct safety number. Abyssal deliberately does not persist trust decisions because client account state is RAM-only, so verification must be repeated after process restart. For rooms there is no scalable key-transparency or participant-verification system yet.

The relay also serves the browser bundle. A compromised web origin can deliver modified JavaScript/WASM and capture plaintext before encryption. Signed native Android builds avoid this code-delivery dependency but still require release-key and device integrity.

### Browser RAM-only claims are limited

JavaScript cannot guarantee physical zeroization. Browser engines may copy immutable strings, page memory to swap, cache decoded media, retain back/forward state, or expose process data to privileged extensions and compromised devices. File pickers and Blob/media implementations may use temporary disk storage. OS screenshots, cameras, developer tools, and network inspection cannot be blocked reliably by a web page.

Web client therefore provides no local forensic guarantee. Use hardened native Android for threat models requiring screenshot controls and stronger OS integration.

### Metadata remains visible

Relay and TLS endpoint observe IP addresses, timing, packet sizes, account sessions, usernames, room membership, presence, attachment sizes, and routing. Cloudflare observes transport metadata and terminates public TLS when used as edge.

Required replacement depends on threat model: sealed sender, message padding, batching, private contact discovery, optional cover traffic, and a reviewed proxy or anonymity layer.

## Deployment Rules

1. Serve production web and API from one HTTPS origin. Leave `ABYSSAL_WEB_ORIGINS` empty unless a separate reviewed origin is required.
2. Keep port `4020` private behind TLS tunnel or reverse proxy. Do not expose plaintext relay HTTP to internet.
3. Use the supplied Docker read-only runtime, no volumes, non-root UID, dropped capabilities, bounded memory/PIDs, and `no-new-privileges`.
4. Startup codes appear once in attached process stdout. The supplied Compose deployment disables Docker log persistence and provides no retrieval file, API, fixed-code environment setting, or plaintext-code map. Lost codes require a destructive restart. Do not replace this with a disk-backed log driver.
5. Restart wipes all relay state. Verify terminal capture, host tracing, crash dumps, and swap are not configured to capture process/container memory.
6. Rebuild Android and web clients after protocol changes; protocol-v5 OPAQUE/ratcheted E2EE with one-time prekeys requires version `1.9.x` clients.
7. Keep the Android release keystore offline and backed up. Never commit `deploy/release.env`, `.secrets/`, APK signing credentials, or generated access codes.
8. Commission independent cryptographic and application security review before claiming Signal-grade, audited, or high-assurance security. Stable software releases must continue disclosing prekey, group key management, transparency, rollback, multi-device, and audit gaps.

Android update discovery requests only the configured official GitHub `releases/latest` API endpoint over HTTPS. The client disables redirects and caching for this request, accepts only stable semantic versions, and requires the APK asset name, repository path, HTTPS host, media type, and bounded size to match the expected release. Release metadata and reminder state remain in RAM. Pressing Update opens the official APK URL in the system browser; Android still requires normal user confirmation and a matching application signature before replacement.

A hostile host administrator can replace or instrument the relay binary, attach before startup output is zeroized, or capture incoming account requests. Software running on an administrator-controlled host cannot prevent that. This design removes recovery paths and plaintext retention after normal startup; it does not claim protection from a malicious root operator.

## Reporting

Do not include access codes, passwords, bearer tokens, decrypted messages, or attachment contents in an issue. Share minimal reproduction details privately with repository maintainers.
