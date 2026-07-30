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
- The relay stores generated codes, OPAQUE password records, encrypted identity envelopes, sessions, rooms, clients, presence, and pending recipient-specific ciphertext in RAM only. Pending frames are keyed by conversation and intended username so one participant cannot consume another participant's offline queue. Restarting the relay, an authenticated user wipe, or the dead-man switch clears all relay account and chat state.
- Files, images, and videos may only be written to disk through an explicit user save/export flow. Android saves attachments as device-bound `.abyssal` AES-GCM export envelopes using Android Keystore, preferring StrongBox when the device supports it. There is not yet an in-app import flow, so these exports are archival ciphertext rather than portable files.
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

- Account entry automatically creates an account for an unused code or logs into its existing RAM account.
- Rooms, owner quotas, room media policy, live presence, encrypted messages, replies, read expiry, absolute expiry, GIFs, upload progress, images, videos, and explicit encrypted `.abyssal` exports use the existing relay protocol.
- Existing DMs are listed in the sidebar. Select any other account in `DIRECT` or the live presence rail to create/open the canonical pairwise conversation. The relay sends DM frames only to its two participants and rejects unauthorized joins and attachment requests.
- Every bundled reaction has a `:filename:` shortcut, such as `:fire:`. Picker reactions carry a validated shortcut inside encrypted attachment metadata and render in equal-size inline frames without exposing the selection to the relay.
- Type `@` to complete an active or offline username. Mentions and replies to one of the current process's own message IDs receive the same recipient-only attention treatment; other users do not see that highlight.
- The calculator cover PIN and optional duress PIN exist only in the current tab. Reload, tab close, logout, wipe, session expiry, or process termination loses them.
- WebSocket bearer tokens use a negotiated subprotocol instead of a URL query string. Protocol-v3 E2EE requires Abyssal `1.7.0` clients; older builds are incompatible.

Run web checks:

```bash
npm run web:check
```

## Verification

Run the complete repository suite from the root:

```bash
./check.sh all
```

Targeted modes are available for `quick`, `web`, `rust`, `android`, `integration`, `crypto`, and `shell`. The full mode runs web lint/unit/component/build checks, Rust formatting/tests/clippy, Android JVM tests/release lint/debug and release builds, shell syntax checks, and a live disposable-relay OPAQUE/E2EE DM/offline-replay/access-control integration test. `crypto` regenerates the shared WASM, Kotlin, and four Android ABI libraries.

## Rust Server

Run locally:

```bash
cd mirage-server
ABYSSAL_BIND_ADDR=0.0.0.0:4020 \
ABYSSAL_NODE_ID=abyssal-node-1 \
ABYSSAL_CODE_COUNT=8 \
ABYSSAL_ATTACHMENT_RAM_LIMIT_MB=512 \
ABYSSAL_MAX_ROOMS_PER_USER=5 \
ABYSSAL_SESSION_INACTIVITY_MINUTES=15 \
ABYSSAL_INACTIVITY_LIMIT_HOURS=0 \
cargo run --release
```

Health check:

```bash
curl http://127.0.0.1:4020/health
```

The server prints generated access codes to stdout during boot. Each code has a random variable length of at least 12 characters including dashes, can create exactly one RAM-only account, and is never written to disk by the relay. There are no administrator roles or privileged codes. Only one unexpired bearer session may exist for a code at a time.

Every authenticated user can create rooms and trigger a relay RAM wipe. Rooms are owned by their creator: only that account can update or delete them. `ABYSSAL_MAX_ROOMS_PER_USER` limits each account's active rooms, and deleting an owned room releases one slot.

Security-related relay knobs:

- `ABYSSAL_ATTACHMENT_RAM_LIMIT_MB`: total in-memory encrypted attachment budget. Default: `512`.
- `ABYSSAL_MAX_ROOMS_PER_USER`: active room quota for each account. Default: `5`; accepted range: `1` to `100`.
- `ABYSSAL_SESSION_INACTIVITY_MINUTES`: strict bearer-token and WebSocket inactivity limit. Default: `15`; accepted range: `1` to `1440`. The Android client displays the node policy and enforces the same deadline locally.
- `ABYSSAL_INACTIVITY_LIMIT_HOURS`: dead-man switch. `0` disables it. A positive value wipes relay RAM state and broadcasts `GLOBAL_WIPE` after that many idle hours.
- `ABYSSAL_WEB_ORIGINS`: comma-separated exact browser origins allowed to call the relay cross-origin and open WebSockets. Leave empty when web and relay share one origin.
- `ABYSSAL_WEB_ROOT`: optional built web directory containing `index.html`. Docker sets this to `/opt/abyssal/web`.

The relay accepts websocket dummy frames shaped like `{"type":"dummy","padding_b64":"..."}` and discards them before room routing. This supports future optional cover traffic without polluting message queues.

Android and web use the same Rust core. Account creation/login uses OPAQUE, so the password is not sent as relay application data. Messages, attachment bytes, and read receipts use recipient-specific X25519 key wrapping, ChaCha20-Poly1305, and Ed25519 signatures; the relay routes ciphertext and cannot passively decrypt or forge it. Identity secret keys are recovered from an envelope encrypted by the OPAQUE export key and remain client-side in process memory. This is real baseline E2EE, but it is not Signal-grade: the current protocol has no Double Ratchet/MLS forward secrecy or post-compromise recovery, and safety numbers must be compared out of band to detect an actively malicious relay substituting recipient keys. See [SECURITY.md](SECURITY.md).

## Docker

The relay can run cleanly in Docker. Build stages compile the web bundle and Rust relay. The runtime image contains only the static web bundle, compiled Rust binary, CA certificates, and the health-check client. It runs as a non-root user with a read-only filesystem, bounded memory/PIDs, disabled Docker log persistence, and no database volume. Compose binds `4020` to loopback so a local Cloudflare tunnel or reverse proxy can reach it without exposing plaintext HTTP publicly.

```bash
cp mirage-server/.env.example mirage-server/.env
$EDITOR mirage-server/.env
docker compose -f deploy/docker-compose.yml up -d --build
curl http://127.0.0.1:4020/health
```

Stop it:

```bash
docker compose -f deploy/docker-compose.yml down
```

Do not put production codes in the Dockerfile. Configure only counts and node settings in `.env`, systemd environment entries, or your server secret manager. The process prints codes to stdout and also writes them to `/tmp/abyssal-invite-codes`, which is backed by the container's bounded tmpfs. The supplied Compose file uses Docker's `none` log driver, so startup credentials are not retained in host container logs.

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

Print the current RAM-only invite codes:

```bash
./deploy/invite-codes.sh
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

Copy `deploy/mirage-server.service` to `/etc/systemd/system/mirage-server.service`, edit the environment values, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mirage-server
sudo systemctl status mirage-server
```

For production, put Caddy or Nginx in front of port `4020` and use HTTPS/WSS. The Android app will derive `wss://.../v1/ws` from a `https://...` node URL entered by the user.

## License

Abyssal's original source is licensed under the [Apache License 2.0](LICENSE). Bundled third-party assets retain their own licenses as described in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
