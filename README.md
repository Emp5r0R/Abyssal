# Abyssal Chat

Abyssal is an Android-first ephemeral chat prototype with a RAM-only Rust relay. The Android app does not hardcode a node URL: every login requires a node URL, server code, and password.

## Storage Policy

- Android keeps account sessions, node URLs, chat sessions, message buffers, camouflage state, passwords, and encryption material in process memory only.
- Pausing/stopping the Android activity logs out and clears local chat state. If calculator camouflage is enabled, Abyssal shows the calculator cover first; passing it returns to the account login screen.
- The relay stores generated codes, accounts, password hashes, sessions, rooms, clients, presence, and pending encrypted frames in RAM only. Restarting the relay clears all account and chat state.
- Files, images, and videos may only be written to disk through an explicit user save/export flow. Those persisted artifacts must be encrypted before writing.
- There is no Room, SQLite, DataStore, SharedPreferences, or app-owned message database.

## Android

Build a debug APK:

```bash
cd android
./gradlew :app:assembleDebug
```

Install to a connected device:

```bash
/media/n_emperor/Aadhish/Projects/Abyssal/android-sdk/platform-tools/adb install -r /media/n_emperor/Aadhish/Projects/Abyssal/android/app/build/outputs/apk/debug/app-debug.apk
```

At the entrance screen enter:

- Node URL, for example `https://chat.example.com` or `http://SERVER_IP:8080`.
- Code printed by the relay process at startup.
- Password. Creating an account consumes the code; later logins use the same code and password while the relay process is still alive.

For an Android emulator talking to a server on the development machine, use `http://10.0.2.2:8080`.

## Rust Server

Run locally:

```bash
cd mirage-server
ABYSSAL_BIND_ADDR=0.0.0.0:8080 \
ABYSSAL_NODE_ID=oracle-ampere-1 \
ABYSSAL_CODE_COUNT=8 \
ABYSSAL_ADMIN_CODE_COUNT=1 \
cargo run --release
```

Health check:

```bash
curl http://127.0.0.1:8080/health
```

The server prints generated user/admin codes to stdout during boot. Each code has a random variable length of at least 12 characters including dashes, can create exactly one RAM-only account, and is never written to disk by the relay.

## Docker

The relay can run cleanly in Docker. The image contains only the compiled Rust binary and CA certificates, runs as a non-root user, and the compose service uses a read-only filesystem with no database volume.

```bash
cp mirage-server/.env.example mirage-server/.env
$EDITOR mirage-server/.env
docker compose -f deploy/docker-compose.yml up -d --build
curl http://127.0.0.1:8080/health
```

Stop it:

```bash
docker compose -f deploy/docker-compose.yml down
```

Do not put production codes in the Dockerfile. Configure only counts and node settings in `.env`, systemd environment entries, or your server secret manager. Read the generated codes from process logs.

## Oracle Ampere Deployment

On Ubuntu ARM64:

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
cd /opt/mirage/mirage-server
cargo build --release
```

Copy `deploy/mirage-server.service` to `/etc/systemd/system/mirage-server.service`, edit the environment values, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mirage-server
sudo systemctl status mirage-server
```

For production, put Caddy or Nginx in front of port `8080` and use HTTPS/WSS. The Android app will derive `wss://.../v1/ws` from a `https://...` node URL entered by the user.
