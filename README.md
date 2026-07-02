# Mirage Chat

Mirage is an Android-first ephemeral chat prototype with a RAM-only Rust relay. The Android app does not hardcode a node URL: every login requires an invite code and a user-entered node URL.

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

- Invite code, for example `MIRA-4729-ZX00` unless you change server env vars.
- Node URL, for example `https://chat.example.com` or `http://SERVER_IP:8080`.

For an Android emulator talking to a server on the development machine, use `http://10.0.2.2:8080`.

## Rust Server

Run locally:

```bash
cd mirage-server
MIRAGE_BIND_ADDR=0.0.0.0:8080 \
MIRAGE_NODE_ID=oracle-ampere-1 \
MIRAGE_INVITE_CODES=MIRA-4729-ZX00 \
MIRAGE_ADMIN_CODES=ROOT-0000-WIPE \
cargo run --release
```

Health check:

```bash
curl http://127.0.0.1:8080/health
```

The server keeps invite sessions, WebSocket clients, rooms, and pending encrypted frames in process memory only. Restarting the server clears all chat state.

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
