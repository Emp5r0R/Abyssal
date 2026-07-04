# Abyssal Chat

Abyssal is an Android-first ephemeral chat prototype with a RAM-only Rust relay. The Android app does not hardcode a node URL: every login requires a node URL, server code, and password.

## Storage Policy

- Android keeps account sessions, node URLs, chat sessions, message buffers, camouflage state, passwords, and encryption material in process memory only.
- Pausing/stopping the Android activity locks to the calculator cover when camouflage is enabled. Process death, explicit logout, wipe, or relay restart clears RAM-only session state and returns to account entry.
- The relay stores generated codes, accounts, password hashes, sessions, rooms, clients, presence, and pending encrypted frames in RAM only. Restarting the relay clears all account and chat state.
- Files, images, and videos may only be written to disk through an explicit user save/export flow. Those persisted artifacts must be encrypted before writing.
- There is no Room, SQLite, DataStore, SharedPreferences, or app-owned message database.
- Bundled static UI assets, including GIF reactions, are packaged with the APK. They are not user messages or account/session state.

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
/media/n_emperor/Aadhish/Projects/Abyssal/android-sdk/platform-tools/adb install -r /media/n_emperor/Aadhish/Projects/Abyssal/android/app/build/outputs/apk/debug/app-debug.apk
```

At the entrance screen enter:

- Node URL, for example `https://chat.example.com` or `http://SERVER_IP:4020`.
- Code printed by the relay process at startup.
- Password. Creating an account consumes the code; later logins use the same code and password while the relay process is still alive.

For an Android emulator talking to a server on the development machine, use `http://10.0.2.2:4020`.

## Rust Server

Run locally:

```bash
cd mirage-server
ABYSSAL_BIND_ADDR=0.0.0.0:4020 \
ABYSSAL_NODE_ID=oracle-ampere-1 \
ABYSSAL_CODE_COUNT=8 \
ABYSSAL_ADMIN_CODE_COUNT=1 \
cargo run --release
```

Health check:

```bash
curl http://127.0.0.1:4020/health
```

The server prints generated user/admin codes to stdout during boot. Each code has a random variable length of at least 12 characters including dashes, can create exactly one RAM-only account, and is never written to disk by the relay.

## Docker

The relay can run cleanly in Docker. The image contains only the compiled Rust binary and CA certificates, runs as a non-root user, and the compose service uses a read-only filesystem with no database volume.

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
  --include '.env.example' --exclude '.env' --exclude '.env.*' \
  --exclude 'android/.gradle/' --exclude 'android/app/build/' --exclude 'android/build/' \
  --exclude 'build-outputs/' --exclude 'mirage-server/target/' --exclude 'rust-core/target/' \
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
cd /opt/mirage/mirage-server
cargo build --release
```

Copy `deploy/mirage-server.service` to `/etc/systemd/system/mirage-server.service`, edit the environment values, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mirage-server
sudo systemctl status mirage-server
```

For production, put Caddy or Nginx in front of port `4020` and use HTTPS/WSS. The Android app will derive `wss://.../v1/ws` from a `https://...` node URL entered by the user.
