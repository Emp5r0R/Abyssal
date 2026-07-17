# Abyssal Security Model

No application has absolute security. Abyssal currently remains a prototype and must not be presented as a Signal-equivalent system.

## Current Protections

- Relay state is process memory only: codes, password hashes, accounts, sessions, room catalog, presence, pending frames, and attachments have no database or volume.
- Android app-owned account, message, endpoint, PIN, password, token, and key state is process memory only. `FLAG_SECURE` blocks normal Android screenshots and recents snapshots.
- Web client uses no persistent browser storage, cookies, service worker, source maps, or third-party runtime scripts. Crypto keys are non-extractable Web Crypto keys. Typed plaintext and ciphertext buffers are overwritten on a best-effort basis after use.
- TLS/WSS is required for remote web nodes loaded from HTTPS. Loopback HTTP remains available for development.
- WebSocket bearer tokens are sent as a WebSocket subprotocol value, not in request URLs. Browser WebSocket origins must match the node host or an exact `ABYSSAL_WEB_ORIGINS` entry.
- Relay responses set a restrictive CSP, no-store caching, frame denial, no-referrer, MIME sniffing denial, HSTS, permissions restrictions, and cross-origin headers.
- Account request bodies, WebSocket frame size/rate, attachment type size, total attachment RAM, session inactivity, and per-user room count are bounded.
- Sender usernames on delivered frames come from the authenticated relay session, not user-controlled encrypted metadata.

## Known High-Risk Gaps

### Payload encryption is not E2EE

`InMemoryPayloadCipher` derives one AES-GCM key from `ABYSSAL_NODE_PAYLOAD_V1:<node-id>`. Node ID is public. Relay operators and participants can derive the key, decrypt room traffic, forge payloads, and read attachment bytes. AES-GCM itself is not the problem; key distribution is.

Required replacement: an audited, interoperable group and pairwise protocol such as Signal Protocol for direct sessions and MLS for groups. It needs authenticated identity keys, prekeys, forward secrecy, post-compromise recovery, replay protection, device changes, offline delivery, and key verification. Do not create a custom ratchet.

### Password authentication is not PAKE

Passwords reach the relay inside TLS and are Argon2-hashed in RAM. A malicious relay binary or compromised TLS endpoint can capture plaintext during entry.

Required replacement: audited OPAQUE registration and login shared by Android, web/WASM, and Rust. Passwords must never become application-level relay input.

### Browser RAM-only claims are limited

JavaScript cannot guarantee physical zeroization. Browser engines may copy immutable strings, page memory to swap, cache decoded media, retain back/forward state, or expose process data to privileged extensions and compromised devices. File pickers and Blob/media implementations may use temporary disk storage. OS screenshots, cameras, developer tools, and network inspection cannot be blocked reliably by a web page.

Web client therefore provides no local forensic guarantee. Use hardened native Android for threat models requiring screenshot controls and stronger OS integration.

### Metadata remains visible

Relay and TLS endpoint observe IP addresses, timing, packet sizes, account sessions, usernames, room membership, presence, attachment sizes, and routing. Cloudflare observes transport metadata and terminates public TLS when used as edge.

Required replacement depends on threat model: sealed sender, message padding, batching, private contact discovery, optional cover traffic, and a reviewed proxy or anonymity layer.

## Deployment Rules

1. Serve production web and API from one HTTPS origin. Leave `ABYSSAL_WEB_ORIGINS` empty unless a separate reviewed origin is required.
2. Keep port `4020` private behind TLS tunnel or reverse proxy. Do not expose plaintext relay HTTP to internet.
3. Use supplied Docker read-only runtime, no volumes, non-root UID, dropped capabilities, and `no-new-privileges`.
4. Restrict process logs. Startup access codes are credentials and intentionally appear in stdout.
5. Restart wipes all state. Verify backups are not configured for relay/container memory or logs.
6. Rebuild Android clients after protocol changes; version `1.4.0` removes WebSocket query-token authentication.
7. Commission independent cryptographic and application security review before real sensitive use.

## Reporting

Do not include access codes, passwords, bearer tokens, decrypted messages, or attachment contents in an issue. Share minimal reproduction details privately with repository maintainers.
