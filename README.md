# Abyssal Chat

Abyssal is an ephemeral chat monorepo containing a native Android client, a browser client, a Rust relay, and a native crypto crate. Neither client hardcodes a node URL: account entry takes a node URL, access code, and password every time a process starts.

## UI Preview

The web client and Android client share the same Abyssal visual language: dark relay surfaces, restrained cyan/green status signals, RAM-only account entry, encrypted rooms, mentions, replies, GIF reactions, and media controls.

![Abyssal web account entry](docs/assets/readme/web-entry.png)

Android uses `FLAG_SECURE`, so production device screenshots are intentionally blocked instead of being used as README media.

## Monorepo Layout

```text
apps/web/        React + TypeScript browser client
android/         Kotlin + Jetpack Compose Android client
mirage-server/   Rust Axum relay (legacy directory name)
rust-core/       Native Rust crypto crate
deploy/          Docker, rsync, and service scripts
```

Root `package.json` owns the npm workspace. Root `Cargo.toml` and `Cargo.lock` own the Rust workspace. Existing Android and relay paths remain stable for deployment scripts.

## Storage Policy

- Android keeps account sessions, node URLs, chat sessions, message buffers, camouflage secrets, passwords, and encryption material out of app-owned persistent storage. Authenticated state lives only in the application process.
- `Remember this session` keeps that RAM-only session alive across activity pause, stop, and activity recreation while the Android process remains alive. With calculator camouflage enabled, leaving the app shows the calculator cover without logging out. When unchecked, leaving the foreground ends the session.
- Every authenticated session has a strict node-provided inactivity deadline. User interaction refreshes it; background time and time spent behind the calculator cover do not. Expiry clears local RAM state, disconnects transport, and requires account entry again. Process death, explicit logout, wipe, or relay restart also clears session state.
- Explicit logout and client-side expiry also make a best-effort relay call to revoke the bearer token immediately. The relay independently rejects expired tokens and closes idle WebSockets, so client enforcement is not the only boundary.
- The calculator cover supports a normal unlock PIN and an optional duress PIN. The duress PIN silently purges local memory and attempts a relay wipe.
- Camouflage has no default PIN and is never recoverable from disk. Android resets the stale calculator launcher alias and the RAM-only PIN after process death; configure a new camouflage PIN after signing in to a fresh process.
- The relay stores generated codes, OPAQUE password records, encrypted identity envelopes, sessions, rooms, clients, presence, and pending recipient-specific ciphertext in RAM only. Pending frames are keyed by conversation and intended username so one participant cannot consume another participant's offline queue. Pending frames expire after a bounded configurable lifetime (default 24 hours, accepted range 1-168 hours; `0` is clamped, never unbounded), and expiration also releases any matching one-time-prekey claim. Restarting the relay, an authenticated user wipe, or the dead-man switch clears all relay account and chat state.
- Files, images, and videos may only be written to disk through an explicit user save flow. Android and web authenticate and decrypt attachments in memory, then save the original bytes under a sanitized original filename. One-time attachments remain view-only and expose no save control.
- Attachment plaintext limits are 20 MiB for images, 100 MiB for videos, and 200 MiB for other files. Protocol-v6 attachments are stateless binary XChaCha20-Poly1305 blobs: one version byte, a 24-byte nonce, ciphertext, and a 16-byte tag, so the wire body is the plaintext size plus exactly 41 bytes. The bulk key is delivered inside the encrypted, ratcheted message metadata; the relay stores and streams only the opaque blob. A default 320 MiB encrypted-RAM quota applies per account in addition to the global RAM limit, with bounded upload and download concurrency.
- `Delete after download` and one-time attachments are destructive only after the client receives the exact non-empty ciphertext, authenticates and decrypts it, then explicitly completes its recipient-bound claim. In a DM each intended recipient gets one completion; in a room the eligible recipients are snapshotted at upload and each can complete once. Failed, truncated, interrupted, cancelled, or unauthenticated transfers release the claim for retry; concurrent claims by the same recipient are rejected; and the owner can preview their upload without consuming a recipient claim. The relay removes the encrypted blob and releases quota only after every eligible recipient completes, or when the configured retention policy expires it.
- There is no Room, SQLite, DataStore, SharedPreferences, or app-owned message database.
- Bundled static UI assets, including GIF reactions, are packaged with the APK. They are not user messages or account/session state.
- The web client never calls `localStorage`, `sessionStorage`, IndexedDB, Cache Storage, cookies, or a service worker. Account state, messages, PINs, decrypted media URLs, and crypto keys live in the current JavaScript process only. Relay responses use `Cache-Control: no-store`.
- Browser engines may still page process memory to disk, retain implementation caches, expose data to privileged extensions, or allow OS capture. Web pages cannot provide Android `FLAG_SECURE` guarantees. Read [SECURITY.md](SECURITY.md) before treating Abyssal as a high-security system.

## Credits

The bundled GIF reaction pack came from ECA, [`EraseableChatApp`](https://github.com/i-vt/EraseableChatApp), by [@i-vt](https://github.com/i-vt). We adapted those assets for Abyssal's encrypted in-chat GIF picker.

Asset licensing details are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Android

Build a debug APK:

```bash
cd android
./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

The install command expects `adb` on `PATH`. Otherwise invoke `platform-tools/adb` from your Android SDK.

At the entrance screen enter:

- Node URL, for example `https://chat.example.com`. Plain HTTP is accepted only for loopback development addresses such as `127.0.0.1` and the Android emulator host `10.0.2.2`.
- Code printed by the relay process at startup.
- Password. Creating an account consumes the code; later logins use the same code and password while the relay process is still alive. A second login is rejected while that code still has an unexpired session.
- `Remember this session` is optional and never stores the code, password, URL, or token on disk. It only changes lifecycle behavior for the current process.

For an Android emulator talking to a server on the development machine, use `http://10.0.2.2:4020`.

### Chat behavior

- Text and media messages can reply to any message still present in the current RAM buffer. Tap the reply icon beside a bubble, then send text, a file, an image, a video, or a bundled GIF.
- Reply envelopes contain only the original message ID inside the encrypted payload. They do not copy the original plaintext, filename, or sender. If the original expires, the reply renders `Original message unavailable` instead of extending the original content's lifetime.
- Tapping an available reply preview scrolls to and briefly highlights the original message. The composer automatically cancels a reply if its target expires before send.
- Every bundled reaction has a `:filename:` shortcut, such as `:fire:`. Picker and shortcut sends use the same encrypted attachment path and render in equal-size inline frames on Android and web.
- Type `@` to complete a connected username, or tap a sender name to mention them. Mentions and replies to one of the current process's own message IDs receive recipient-only attention styling.
- The composer remains editable while reconnecting, but send and attachment actions stay disabled until the WebSocket is connected so a local bubble is not mistaken for a relayed message.
- The chat initially opens at the latest active message and follows new messages only while the user remains near the bottom.
- Direct messages appear under `DIRECT`. Select a peer in the live presence rail to ask the relay for a canonical private conversation; guessed DM identifiers are rejected by the relay.
- Direct headers display a symmetric safety number derived from both identity keys. Both participants see the same number and can compare it through a separate channel to detect relay key substitution.
- Direct composers choose retention for each text, GIF, or attachment: `Never`, `5s`, `10s`, `30s`, or `1m`. `Never` means retained only for the current client/relay RAM lifetime; restart, wipe, logout, or process loss still removes it.
- Room creators may set any after-read timer to `0` for no read-triggered expiry. Room policy is locked for participants, including text and media-specific timers; a sender cannot extend it from the composer.
- Android checks the latest stable GitHub release after launch without caching metadata to disk. A newer signed universal APK opens in the system browser only after explicit confirmation; users can cancel for the process lifetime or request an in-memory reminder two hours later. The prompt never appears over the calculator cover.

### Signed release build

Create and securely back up a signing key once:

```bash
./scripts/create-android-release-key.sh
```

Then build and verify the signed universal APK and AAB:

```bash
ANDROID_SDK_ROOT="$HOME/Android/Sdk" ./scripts/build-android-release.sh
```

The ignored `deploy/release.env` and `.secrets/abyssal-release.jks` are both required to sign future compatible updates. Full release steps are in [docs/RELEASE.md](docs/RELEASE.md).

## Web

Install and run the browser client:

```bash
npm ci
npm run web:dev
```

For local cross-origin development, start the relay from the repository root with the exact Vite origin:

```bash
ABYSSAL_WEB_ORIGINS=http://localhost:4173 cargo run --package mirage-server
```

Open `http://localhost:4173`, then enter `http://127.0.0.1:4020` as the node URL. Production Docker builds the web client and serves it from the relay root, so a URL such as `https://chat.example.com/` and the API use one origin. Leave `ABYSSAL_WEB_ORIGINS` empty for that deployment.

Web client behavior:

- Account entry automatically creates an account for an unused code or logs into its existing RAM account. Each account request body is capped at 16 KiB; OPAQUE handshakes expire after 60 seconds and code attempts are rate-limited to six per minute.
- Rooms, owner quotas, room media policy, live presence, encrypted messages, replies, read expiry, absolute expiry, GIFs, upload progress, images, videos, and explicit attachment downloads use the existing relay protocol. Dashboard room and DM entries never render message plaintext.
- Existing DMs are listed in the sidebar. Select any other account in `DIRECT` or the live presence rail to create/open the canonical pairwise conversation. The relay sends DM frames only to its two participants and rejects unauthorized joins and attachment requests.
- Every bundled reaction has a `:filename:` shortcut, such as `:fire:`. Picker reactions carry a validated shortcut inside encrypted attachment metadata and render in equal-size inline frames without exposing the selection to the relay.
- Type `@` to complete an active or offline username. Mentions and replies to one of the current process's own message IDs receive the same recipient-only attention treatment; other users do not see that highlight.
- Direct composers apply a per-message `Never`, `5s`, `10s`, `30s`, or `1m` timer to text, GIFs, and attachments. Room composers show the creator's locked room timer; room policy can also be configured as no read expiry.
- The calculator cover PIN and optional duress PIN exist only in the current tab. Reload, tab close, logout, wipe, session expiry, or process termination loses them.
- WebSocket bearer tokens use a negotiated subprotocol instead of a URL query string. Protocol-v6 E2EE with per-recipient signatures, one-time prekey claims, and ratcheted metadata requires Abyssal `2.0.0` clients; older protocol-v5/1.9.x builds are wire-incompatible.

Run web checks:

```bash
npm run web:check
```

## Verification

Run the complete repository suite from the root:

```bash
./check.sh all
```

Targeted modes are available for `quick`, `web`, `rust`, `android`, `integration`, `crypto`, `audit`, and `shell`. The full mode runs web lint/unit/component/build checks, Rust formatting/tests/clippy, Android JVM tests/release lint/debug and release builds, shell syntax checks, a live disposable-relay OPAQUE/ratcheted-E2EE DM/offline-replay/access-control integration test, and npm/RustSec dependency advisory scans. `crypto` regenerates the shared WASM, Kotlin, and four stripped Android ABI libraries, then records a deterministic digest of their Rust inputs. Normal, full, and signed-release checks reject non-v6 or stale generated artifacts.

## Rust Server

Run locally:

```bash
cd mirage-server
ABYSSAL_BIND_ADDR=0.0.0.0:4020 \
ABYSSAL_NODE_ID=abyssal-node-1 \
ABYSSAL_CODE_COUNT=8 \
ABYSSAL_ATTACHMENT_RAM_LIMIT_MB=512 \
ABYSSAL_ATTACHMENT_ACCOUNT_LIMIT_MB=320 \
ABYSSAL_ATTACHMENT_DOWNLOAD_CONCURRENCY=2 \
ABYSSAL_ATTACHMENT_UPLOAD_CONCURRENCY=2 \
ABYSSAL_MAX_ROOMS_PER_USER=5 \
ABYSSAL_PENDING_MESSAGE_TTL_HOURS=24 \
ABYSSAL_SESSION_INACTIVITY_MINUTES=15 \
ABYSSAL_INACTIVITY_LIMIT_HOURS=0 \
cargo run --release
```

Health check:

```bash
curl http://127.0.0.1:4020/health
```

The server prints generated access codes once to attached stdout during boot. Each code has a random variable length of at least 12 characters including dashes, can create exactly one RAM-only account, and is never written to a relay file or Docker log. After printing, plaintext code buffers are zeroized and the relay retains only per-process HMAC identifiers; account, session, client, rate-limit, and room-owner maps never retain plaintext codes. Fixed invite codes cannot be supplied through environment variables. There are no administrator roles or privileged codes. Only one unexpired bearer session may exist for a code at a time. If the operator loses terminal output, codes are deliberately unrecoverable through supported interfaces; restarting the relay destroys all RAM state and creates a new set.

Every authenticated user can create rooms and trigger a relay RAM wipe. Rooms are owned by their creator: only that account can update or delete them. `ABYSSAL_MAX_ROOMS_PER_USER` limits each account's active rooms, and deleting an owned room releases one slot.

This is an intentional availability tradeoff: a compromised account can wipe the relay and force destructive restart/code rotation. Keep active account sessions and the wipe confirmation protected.

Security-related relay knobs:

- `ABYSSAL_ATTACHMENT_RAM_LIMIT_MB`: total in-memory encrypted attachment budget. Default: `512`.
- `ABYSSAL_ATTACHMENT_ACCOUNT_LIMIT_MB`: per-account in-memory encrypted attachment quota, capped by the global RAM limit. Default: `320`.
- `ABYSSAL_ATTACHMENT_DOWNLOAD_CONCURRENCY`: maximum concurrent attachment responses across the relay. Default: `2`; accepted range: `1` to `16`.
- `ABYSSAL_ATTACHMENT_UPLOAD_CONCURRENCY`: maximum concurrent attachment request-body reads. Default: `2`; accepted range: `1` to `4`. This bounds large encrypted request allocations before the RAM quota check.
- `ABYSSAL_MAX_ROOMS_PER_USER`: active room quota for each account. Default: `5`; accepted range: `1` to `100`.
- `ABYSSAL_PENDING_MESSAGE_TTL_HOURS`: maximum RAM lifetime for an undelivered encrypted pending frame. Default: `24`; accepted range: `1` to `168` hours. `0` is clamped to the one-hour minimum and never means unbounded. Expired frames are removed, their byte budget is returned, and matching prekey claims are released together.
- `ABYSSAL_SESSION_INACTIVITY_MINUTES`: strict bearer-token and WebSocket inactivity limit. Default: `15`; accepted range: `1` to `1440`. The Android client displays the node policy and enforces the same deadline locally.
- `ABYSSAL_INACTIVITY_LIMIT_HOURS`: dead-man switch. `0` disables it. A positive value wipes relay RAM state and broadcasts `GLOBAL_WIPE` after that many idle hours.
- `ABYSSAL_WEB_ORIGINS`: comma-separated exact browser origins allowed to call the relay cross-origin and open WebSockets. Leave empty when web and relay share one origin.
- `ABYSSAL_WEB_ROOT`: optional built web directory containing `index.html`. Docker sets this to `/opt/abyssal/web`.

The relay accepts websocket dummy frames shaped like `{"type":"dummy","padding_b64":"..."}` and discards them before room routing. This supports future optional cover traffic without polluting message queues.

Android and web use the same Rust core. Account creation/login uses OPAQUE, so the password is not sent as relay application data. Protocol v6 encrypts text, read receipts, and control metadata with ChaCha20-Poly1305 and carries each recipient's content key through an authenticated `vodozemac` Olm Double Ratchet session. Every recipient envelope contains exactly one Ed25519 signature over the v6 version, authenticated context, common ciphertext, sender identity key, intended username, prekey metadata, and recipient-specific ratchet envelope; the relay validates envelope shape and forwards only the envelope selected for that recipient, while clients verify the signature before accepting plaintext. Initial asynchronous messages use a recipient-specific one-time prekey; its public key deterministically commits to the advertised prekey ID, and recipients verify that ID against the key embedded in the Olm envelope before decrypting. The recipient rotates that prekey after successful use. Attachment bulk data is separate stateless XChaCha20-Poly1305: a version byte, 24-byte nonce, ciphertext, and 16-byte tag. Its 32-byte key is delivered in encrypted ratcheted message metadata, so the relay never receives the attachment key or plaintext. A relay prekey claim lasts 10 minutes when idle, but a matching queued ciphertext keeps the claim until acknowledgement, eviction, or queue removal, so a delayed frame cannot race a later sender for the same prekey. Client decryption checkpoints ratchet/account/prekey metadata before processing and restores it when Olm succeeds but outer AEAD, signature, or content binding fails. Ratchet/account snapshots are encrypted by an OPAQUE export-key-derived key before the relay keeps the latest copy in RAM. Pending ciphertext remains queued until the recipient decrypts it and acknowledges the authenticated sender, message ID, and consumed prekey. Presence also carries a stable long-term identity directory checkpoint, while clients pin the long-term identity portion across prekey rotation. This is not Signal or MLS: rooms use pairwise fanout, there is no key-transparency witness, multi-device protocol, persistent rollback anchor, or independent Abyssal audit. Compare direct-chat safety numbers and directory checkpoints out of band. See [SECURITY.md](SECURITY.md).

## Docker

The relay can run cleanly in Docker. Build stages compile the web bundle and Rust relay. The runtime image contains only the static web bundle, compiled Rust binary, CA certificates, and the health-check client. It runs as a non-root user with a read-only filesystem, bounded memory/PIDs, disabled Docker log persistence, disabled core dumps, and no database volume. Compose binds `4020` to loopback so a local Cloudflare tunnel or reverse proxy can reach it without exposing plaintext HTTP publicly. The Compose memory default is `2g` to leave headroom for the 512 MiB global attachment pool, two roughly 200 MiB encrypted upload bodies, two downloads, and runtime overhead; set `ABYSSAL_CONTAINER_MEMORY_LIMIT` before `docker compose` when sizing a different host. Attachment uploads have a 30-second idle deadline and a 10-minute total deadline, while stalled download producers release their buffers and permits after 30 seconds. Automatic restart is deliberately disabled: a crash must remain visible, because restarting creates a new invite-code set that is only recoverable from the operator's attached stdout.

Docker is the supported launcher. A systemd unit is intentionally not shipped: journald would persist one-time startup codes and relay metadata, while a hidden restart could generate an unrecoverable fresh code set. Keep Docker's `none` log driver and disabled automatic restart unchanged.

```bash
cp mirage-server/.env.example mirage-server/.env
$EDITOR mirage-server/.env
./deploy/server-start.sh
curl http://127.0.0.1:4020/health
```

The public health response contains only liveness, node identity, and the RAM-only storage label; invite and account counts are not exposed.

Stop it:

```bash
docker compose -f deploy/docker-compose.yml down
```

Do not put production codes in the Dockerfile. Configure only counts and node settings in `.env` or your server secret manager. The process prints codes once to attached stdout. The supplied Compose file uses Docker's `none` log driver, so startup credentials are not retained in host container logs. Terminal scrollback is the operator's only copy and must be protected or cleared after distribution.

## Remote Docker Deploy

The remote helpers read SSH settings from environment variables or the ignored `deploy/deploy.env` file. Create a local configuration from the tracked template:

```bash
cp deploy/deploy.env.example deploy/deploy.env
$EDITOR deploy/deploy.env
```

Sync the repo and rebuild/restart Docker on the server:

```bash
./deploy/deploy-server.sh
```

The first deploy creates `mirage-server/.env` from the tracked template with mode `600`. Later syncs preserve that file and its node-specific settings. Review it on the server before issuing production invite codes.

Run that command from your local machine, not from inside the server shell. It uses SSH and rsync to reach the configured remote host.

If you are already SSH'd into the server at `/home/ubuntu/abyssal`, use the server-local scripts instead:

```bash
./deploy/server-start.sh
./deploy/server-restart.sh
./deploy/server-logs.sh
./deploy/server-stop.sh
```

Run only the sync:

```bash
./deploy/sync-server.sh
```

Run only the Docker rebuild/restart:

```bash
./deploy/restart-docker.sh
```

Check container health without persistent logs:

```bash
./deploy/logs-docker.sh
```

Invite codes cannot be retrieved after startup. This command explains the destructive recovery path and exits:

```bash
./deploy/invite-codes.sh
```

To generate new codes, restart the relay. This destroys all accounts, rooms, pending messages, attachments, and sessions:

```bash
./deploy/restart-docker.sh
```

Stop the server:

```bash
./deploy/stop-docker.sh
```

Equivalent raw `rsync` command:

```bash
SSH_HOST=ubuntu@chat.example.com
SSH_KEY="$HOME/.ssh/abyssal"
REMOTE_DIR=/home/ubuntu/abyssal
SYNC_DIR="$(mktemp -d)"
trap 'rm -rf "$SYNC_DIR"' EXIT

git archive --format=tar HEAD | tar -xf - -C "$SYNC_DIR"

rsync -az --delete \
  -e "ssh -o StrictHostKeyChecking=accept-new -i $SSH_KEY" \
  --exclude '.git/' --exclude '.secrets/' --exclude 'README.local.md' \
  --exclude 'deploy/deploy.env' --exclude 'deploy/release.env' \
  --exclude 'mirage-server/.env' \
  "$SYNC_DIR/" "$SSH_HOST:$REMOTE_DIR/"
```

Override the target without editing scripts:

```bash
ABYSSAL_SSH_HOST=ubuntu@chat.example.com \
ABYSSAL_SSH_KEY="$HOME/.ssh/abyssal" \
ABYSSAL_REMOTE_DIR=/home/ubuntu/abyssal \
./deploy/deploy-server.sh
```

Command-line environment values override `deploy/deploy.env`. Set `ABYSSAL_DEPLOY_ENV` to use a different local configuration file.

## ARM64 Server Deployment

On Ubuntu ARM64, including Oracle Ampere instances:

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
cd /opt/abyssal
npm ci
npm run web:build
cargo build --release --package mirage-server
```

For production, use the supplied Docker launcher and put Caddy or Nginx in front of port `4020` with HTTPS/WSS. The Android app will derive `wss://.../v1/ws` from a `https://...` node URL entered by the user.

## License

Abyssal's original source is licensed under the [Mozilla Public License 2.0](LICENSE). Bundled third-party assets retain their own licenses as described in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
