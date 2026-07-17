# Abyssal Chat

Abyssal is an ephemeral chat monorepo containing a native Android client, a browser client, a Rust relay, and a native crypto crate. Neither client hardcodes a node URL: account entry takes a node URL, access code, and password every time a process starts.

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
- The relay stores generated codes, accounts, password hashes, sessions, rooms, clients, presence, and pending encrypted frames in RAM only. Restarting the relay, an authenticated user wipe, or the dead-man switch clears all relay account and chat state.
- Files, images, and videos may only be written to disk through an explicit user save/export flow. Android saves attachments as `.abyssal` encrypted export blobs using Android Keystore AES-GCM, preferring StrongBox when the device supports it.
- There is no Room, SQLite, DataStore, SharedPreferences, or app-owned message database.
- Bundled static UI assets, including GIF reactions, are packaged with the APK. They are not user messages or account/session state.
- The web client never calls `localStorage`, `sessionStorage`, IndexedDB, Cache Storage, cookies, or a service worker. Account state, messages, PINs, decrypted media URLs, and crypto keys live in the current JavaScript process only. Relay responses use `Cache-Control: no-store`.
- Browser engines may still page process memory to disk, retain implementation caches, expose data to privileged extensions, or allow OS capture. Web pages cannot provide Android `FLAG_SECURE` guarantees. Read [SECURITY.md](SECURITY.md) before treating Abyssal as a high-security system.

## Credits

The bundled GIF reaction pack came from ECA, [`EraseableChatApp`](https://github.com/i-vt/EraseableChatApp), by [@i-vt](https://github.com/i-vt). We adapted those assets for Abyssal's encrypted in-chat GIF picker.

## Android

Build a debug APK:

```bash
cd android
./gradlew :app:assembleDebug
```

Install to a connected device:

```bash
/media/n_emperor/Aadhish/Projects/Abyssal/android-sdk/platform-tools/adb install -r /media/n_emperor/Aadhish/Projects/Abyssal/build-outputs/abyssal-chat-debug.apk
```

At the entrance screen enter:

- Node URL, for example `https://chat.example.com` or `http://SERVER_IP:4020`.
- Code printed by the relay process at startup.
- Password. Creating an account consumes the code; later logins use the same code and password while the relay process is still alive.
- `Remember this session` is optional and never stores the code, password, URL, or token on disk. It only changes lifecycle behavior for the current process.

For an Android emulator talking to a server on the development machine, use `http://10.0.2.2:4020`.

### Chat behavior

- Text and media messages can reply to any message still present in the current RAM buffer. Tap the reply icon beside a bubble, then send text, a file, an image, a video, or a bundled GIF.
- Reply envelopes contain only the original message ID inside the encrypted payload. They do not copy the original plaintext, filename, or sender. If the original expires, the reply renders `Original message unavailable` instead of extending the original content's lifetime.
- Tapping an available reply preview scrolls to and briefly highlights the original message. The composer automatically cancels a reply if its target expires before send.
- The composer remains editable while reconnecting, but send and attachment actions stay disabled until the WebSocket is connected so a local bubble is not mistaken for a relayed message.
- The chat initially opens at the latest active message and follows new messages only while the user remains near the bottom.

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

Open `http://localhost:4173`, then enter `http://127.0.0.1:4020` as the node URL. Production Docker builds the web client and serves it from the relay root, so `https://YOUR_NODE/` and the API use one origin. Leave `ABYSSAL_WEB_ORIGINS` empty for that deployment.

Web client behavior:

- Account entry automatically creates an account for an unused code or logs into its existing RAM account.
- Rooms, owner quotas, room media policy, live presence, encrypted messages, replies, read expiry, absolute expiry, GIFs, upload progress, images, videos, and explicit encrypted `.abyssal` exports use the existing relay protocol.
- The calculator cover PIN and optional duress PIN exist only in the current tab. Reload, tab close, logout, wipe, session expiry, or process termination loses them.
- WebSocket bearer tokens use a negotiated subprotocol instead of a URL query string. Old Android APKs using `?token=` must be replaced with Abyssal `1.4.0` or newer.

Run web checks:

```bash
npm run web:check
```

## Rust Server

Run locally:

```bash
cd mirage-server
ABYSSAL_BIND_ADDR=0.0.0.0:4020 \
ABYSSAL_NODE_ID=oracle-ampere-1 \
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

The server prints generated access codes to stdout during boot. Each code has a random variable length of at least 12 characters including dashes, can create exactly one RAM-only account, and is never written to disk by the relay. There are no administrator roles or privileged codes.

Every authenticated user can create rooms and trigger a relay RAM wipe. Rooms are owned by their creator: only that account can update or delete them. `ABYSSAL_MAX_ROOMS_PER_USER` limits each account's active rooms, and deleting an owned room releases one slot.

Security-related relay knobs:

- `ABYSSAL_ATTACHMENT_RAM_LIMIT_MB`: total in-memory encrypted attachment budget. Default: `512`.
- `ABYSSAL_MAX_ROOMS_PER_USER`: active room quota for each account. Default: `5`; accepted range: `1` to `100`.
- `ABYSSAL_SESSION_INACTIVITY_MINUTES`: strict bearer-token and WebSocket inactivity limit. Default: `15`; accepted range: `1` to `1440`. The Android client displays the node policy and enforces the same deadline locally.
- `ABYSSAL_INACTIVITY_LIMIT_HOURS`: dead-man switch. `0` disables it. A positive value wipes relay RAM state and broadcasts `GLOBAL_WIPE` after that many idle hours.
- `ABYSSAL_WEB_ORIGINS`: comma-separated exact browser origins allowed to call the relay cross-origin and open WebSockets. Leave empty when web and relay share one origin.
- `ABYSSAL_WEB_ROOT`: optional built web directory containing `index.html`. Docker sets this to `/opt/abyssal/web`.

The relay accepts websocket dummy frames shaped like `{"type":"dummy","padding_b64":"..."}` and discards them before room routing. This supports future optional cover traffic without polluting message queues.

Current crypto warning: Android and web use the same node-derived AES-GCM compatibility cipher. Because its input is the public node ID, a relay operator or any node participant can derive the payload key. This is authenticated payload encryption, but it is **not end-to-end encryption against the relay or other participants**. Passwords also reach the relay over TLS because OPAQUE is not implemented. Do not describe the current release as Signal-grade or absolutely secure. See [SECURITY.md](SECURITY.md).

## Docker

The relay can run cleanly in Docker. Build stages compile the web bundle and Rust relay. The runtime image contains only the static web bundle, compiled Rust binary, and CA certificates; it runs as a non-root user with a read-only filesystem and no database volume.

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

Do not put production codes in the Dockerfile. Configure only counts and node settings in `.env`, systemd environment entries, or your server secret manager. Read the generated codes from process logs.

## Oracle Docker Deploy

The helper scripts default to your Oracle host:

```bash
ubuntu@161.118.195.126
/home/Emp5r0R/Documents/ssh_key.key
/home/ubuntu/abyssal
```

Sync the repo and rebuild/restart Docker on the server:

```bash
./deploy/deploy-server.sh
```

Run that command from your local machine, not from inside the server shell. It uses SSH and rsync to reach the Oracle host.

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

Follow logs and copy the RAM-only access codes printed at boot:

```bash
./deploy/logs-docker.sh
```

Stop the server:

```bash
./deploy/stop-docker.sh
```

Equivalent raw `rsync` command:

```bash
rsync -az --delete \
  -e "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i /home/Emp5r0R/Documents/ssh_key.key" \
  --exclude '.git/' --exclude '.gradle/' --exclude '.idea/' \
  --exclude 'node_modules/' --exclude 'target/' \
  --include '.env.example' --exclude '.env' --exclude '.env.*' \
  --exclude 'android/.gradle/' --exclude 'android/app/build/' --exclude 'android/build/' \
  --exclude 'build-outputs/' --exclude 'mirage-server/target/' --exclude 'rust-core/target/' \
  --exclude 'apps/web/dist/' --exclude 'apps/web/coverage/' \
  ./ ubuntu@161.118.195.126:/home/ubuntu/abyssal/
```

Override the target without editing scripts:

```bash
ABYSSAL_SSH_HOST=ubuntu@YOUR_IP \
ABYSSAL_SSH_KEY=/path/to/key \
ABYSSAL_REMOTE_DIR=/home/ubuntu/abyssal \
./deploy/deploy-server.sh
```

## Oracle Ampere Deployment

On Ubuntu ARM64:

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
cd /opt/mirage
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
