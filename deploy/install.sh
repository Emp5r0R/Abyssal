#!/usr/bin/env bash
# Abyssal relay + web installer for a Linux VPS, fresh or already in use.
#
#   curl -fsSLO https://github.com/Emp5r0R/Abyssal/releases/latest/download/abyssal-install.sh
#   sudo bash abyssal-install.sh --domain chat.example.com
#
# It installs Docker when missing, downloads the signed release bundle, builds the
# relay image (the build refuses a web bundle the release key did not sign), sets
# up HTTPS with Caddy when ports 80/443 are free, starts the relay and prints the
# one-time invites. Afterwards the same script is available as `sudo abyssal ...`.
set -euo pipefail

readonly ABYSSAL_DEFAULT_REPO="Emp5r0R/Abyssal"
readonly CADDY_IMAGE="caddy:2.10.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d"
readonly INSTALL_ROOT="${ABYSSAL_INSTALL_ROOT:-/opt/abyssal}"
readonly CONFIG_DIR="${ABYSSAL_CONFIG_DIR:-/etc/abyssal}"
readonly STATE_DIR="${ABYSSAL_STATE_DIR:-/var/lib/abyssal}"
readonly CLI_PATH="${ABYSSAL_CLI_PATH:-/usr/local/sbin/abyssal}"
readonly SERVICE_USER="abyssal"
readonly COMPOSE_PROJECT="abyssal"
readonly MAX_BUNDLE_BYTES=$((256 * 1024 * 1024))
readonly BUILD_SWAP_FILE="/abyssal-build.swap"

COMMAND="install"
DOMAIN=""
ACME_EMAIL=""
VERSION="latest"
REPO="$ABYSSAL_DEFAULT_REPO"
PROXY="auto"
RELAY_PORT="4020"
INVITE_COUNT=""
NODE_KEY_IMPORT=""
BUNDLE_FILE=""
ASSUME_YES=0
REPLACE_EXISTING=0
PURGE=0

log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: abyssal [command] [options]

Commands:
  install     Install or reinstall the relay and web app (default)
  upgrade     Switch to another release, rebuild and restart (wipes RAM, new invites)
  restart     Restart the relay: wipes all RAM state and prints new invites
  status      Show container state and health
  stop        Stop the relay (Caddy keeps serving a 502 until restart)
  uninstall   Remove containers, images and releases (add --purge for keys and config)

Options:
  --domain NAME        Public DNS name, e.g. chat.example.com (required on first install)
  --email ADDRESS      Contact address for Let's Encrypt (optional)
  --version X.Y.Z      Release to install (default: latest)
  --proxy MODE         auto | caddy | none (default: auto)
                         caddy  built-in HTTPS on ports 80/443 via Let's Encrypt
                         none   relay on 127.0.0.1:PORT for your own proxy or tunnel
                         auto   caddy when 80/443 are free, otherwise none
  --port N             Local relay port (default: 4020)
  --invites N          Invites printed at each start, 0-256 (default: 8)
  --node-key FILE      Import an existing 32-byte node signing key (keeps node identity)
  --bundle FILE        Install from a local abyssal-server-X.Y.Z.tar.gz instead of downloading
  --repo OWNER/NAME    GitHub repository with the releases (default: Emp5r0R/Abyssal)
  --replace-existing   Stop another container that already holds the relay port
  --purge              With uninstall: also delete the node key and configuration
  -y, --yes            Do not ask for confirmation
  -h, --help           Show this help
EOF
}

# ---------------------------------------------------------------------------
# Validation (pure; covered by scripts/test-installer.sh)
# ---------------------------------------------------------------------------

valid_domain() {
  local name="$1"
  [[ ${#name} -le 253 ]] || return 1
  [[ "$name" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]]
}

valid_version() { [[ "$1" == latest || "$1" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; }
valid_repo() { [[ "$1" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]]; }
valid_port() { [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && ((10#$1 <= 65535)); }
valid_invites() { [[ "$1" =~ ^(0|[1-9][0-9]{0,2})$ ]] && ((10#$1 <= 256)); }
valid_email() { [[ "$1" =~ ^[^[:space:]@\"\']+@[^[:space:]@\"\']+\.[^[:space:]@\"\']+$ ]]; }

parse_args() {
  if [[ $# -gt 0 && "$1" != -* ]]; then
    COMMAND="$1"
    shift
  fi
  case "$COMMAND" in
    install | upgrade | restart | status | stop | uninstall | help) ;;
    *) die "Unknown command: $COMMAND (see --help)" ;;
  esac
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --domain) DOMAIN="${2:-}"; shift 2 ;;
      --email) ACME_EMAIL="${2:-}"; shift 2 ;;
      --version) VERSION="${2:-}"; VERSION="${VERSION#v}"; shift 2 ;;
      --proxy) PROXY="${2:-}"; shift 2 ;;
      --port) RELAY_PORT="${2:-}"; shift 2 ;;
      --invites) INVITE_COUNT="${2:-}"; shift 2 ;;
      --node-key) NODE_KEY_IMPORT="${2:-}"; shift 2 ;;
      --bundle) BUNDLE_FILE="${2:-}"; shift 2 ;;
      --repo) REPO="${2:-}"; shift 2 ;;
      --replace-existing) REPLACE_EXISTING=1; shift ;;
      --purge) PURGE=1; shift ;;
      -y | --yes) ASSUME_YES=1; shift ;;
      -h | --help) COMMAND="help"; shift ;;
      *) die "Unknown option: $1 (see --help)" ;;
    esac
  done
  DOMAIN="${DOMAIN,,}"
  [[ -z "$DOMAIN" ]] || valid_domain "$DOMAIN" || die "Not a valid public DNS name: $DOMAIN"
  [[ -z "$ACME_EMAIL" ]] || valid_email "$ACME_EMAIL" || die "Not a valid email address: $ACME_EMAIL"
  valid_version "$VERSION" || die "Version must be latest or X.Y.Z: $VERSION"
  valid_repo "$REPO" || die "Repository must be OWNER/NAME: $REPO"
  [[ "$PROXY" =~ ^(auto|caddy|none)$ ]] || die "Proxy must be auto, caddy or none: $PROXY"
  valid_port "$RELAY_PORT" || die "Not a valid port: $RELAY_PORT"
  [[ -z "$INVITE_COUNT" ]] || valid_invites "$INVITE_COUNT" || die "Invites must be 0-256: $INVITE_COUNT"
  return 0
}

# ---------------------------------------------------------------------------
# Rendering (pure; covered by scripts/test-installer.sh)
# ---------------------------------------------------------------------------

# Prints the relay environment: an existing file keeps every setting except the
# public URL and invite count when those are given explicitly.
render_env() {
  local template="$1" existing="$2" domain="$3" invites="$4"
  local source_file="$template"
  [[ -f "$existing" ]] && source_file="$existing"
  local line key seen_url=0 seen_text=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    key="${line%%=*}"
    case "$key" in
      ABYSSAL_PUBLIC_URL)
        seen_url=1
        if [[ -n "$domain" ]]; then printf 'ABYSSAL_PUBLIC_URL=https://%s\n' "$domain"; else printf '%s\n' "$line"; fi ;;
      ABYSSAL_PUBLIC_LOCATORS)
        if [[ -n "$domain" ]]; then printf 'ABYSSAL_PUBLIC_LOCATORS=\n'; else printf '%s\n' "$line"; fi ;;
      ABYSSAL_INVITE_COUNT)
        if [[ -n "$invites" ]]; then printf 'ABYSSAL_INVITE_COUNT=%s\n' "$invites"; else printf '%s\n' "$line"; fi ;;
      ABYSSAL_INVITE_TEXT_ENABLED) seen_text=1; printf '%s\n' "$line" ;;
      ABYSSAL_BIND_ADDR | ABYSSAL_NODE_SIGNING_KEY_FILE) ;; # set by the compose file
      *) printf '%s\n' "$line" ;;
    esac
  done < "$source_file"
  if [[ $seen_url -eq 0 && -n "$domain" ]]; then printf 'ABYSSAL_PUBLIC_URL=https://%s\n' "$domain"; fi
  # Releases before 3.4 printed QR only; print the copyable code beside it too.
  if [[ $seen_text -eq 0 ]]; then printf 'ABYSSAL_INVITE_TEXT_ENABLED=true\n'; fi
  return 0
}

env_public_url() {
  sed -n 's/^ABYSSAL_PUBLIC_URL=//p' "$1" | tail -n 1
}

render_compose() {
  local release_dir="$1" version="$2" uid="$3" gid="$4" port="$5" proxy="$6" memory="$7"
  cat <<EOF
# Generated by the Abyssal installer. Re-run \`abyssal install\` to regenerate.
name: $COMPOSE_PROJECT
services:
  relay:
    build:
      context: $release_dir
      dockerfile: mirage-server/Dockerfile
    image: abyssal-relay:$version
    user: "$uid:$gid"
    # A crash stays visible: a silent restart would mint invites nobody sees.
    restart: "no"
    init: true
    stop_grace_period: 10s
    pids_limit: 128
    ulimits:
      core: 0
    mem_limit: $memory
    env_file:
      - $CONFIG_DIR/relay.env
    environment:
      ABYSSAL_BIND_ADDR: 0.0.0.0:4020
      ABYSSAL_NODE_SIGNING_KEY_FILE: /run/secrets/abyssal-node-signing-key
    volumes:
      - $STATE_DIR/node-signing.key:/run/secrets/abyssal-node-signing-key:ro
    ports:
      - "127.0.0.1:$port:4020"
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=16m,mode=1777
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    # Invites print once to the attached terminal; nothing is written to disk.
    logging:
      driver: none
EOF
  if [[ "$proxy" == caddy ]]; then
    cat <<EOF
  caddy:
    image: $CADDY_IMAGE
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
    volumes:
      - $CONFIG_DIR/Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    security_opt:
      - no-new-privileges:true
    logging:
      driver: local
      options:
        max-size: 1m
        max-file: "2"
volumes:
  caddy_data:
  caddy_config:
EOF
  fi
}

render_caddyfile() {
  local domain="$1" email="$2"
  printf '# Generated by the Abyssal installer.\n'
  if [[ -n "$email" ]]; then
    printf '{\n\temail %s\n}\n\n' "$email"
  fi
  # No `encode`: the relay sends Cache-Control: no-transform for signed assets.
  printf '%s {\n\treverse_proxy relay:4020\n}\n' "$domain"
}

# Container memory: 2 GiB normally, less on small hosts but never below 768 MiB.
relay_memory_limit() {
  local total_kib="$1"
  local mib=$((total_kib / 1024 * 3 / 4))
  ((mib > 2048)) && mib=2048
  ((mib < 768)) && mib=768
  printf '%sm\n' "$mib"
}

# auto picks Caddy only when both web ports are free; explicit choices stay as given.
decide_proxy() {
  local requested="$1" port80_busy="$2" port443_busy="$3"
  if [[ "$requested" != auto ]]; then
    printf '%s\n' "$requested"
  elif [[ "$port80_busy" == 0 && "$port443_busy" == 0 ]]; then
    printf 'caddy\n'
  else
    printf 'none\n'
  fi
}

verify_sha256() {
  local file="$1" expected_line="$2"
  local expected="${expected_line%% *}"
  [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || return 1
  local actual
  actual="$(sha256sum -- "$file")"
  [[ "${actual%% *}" == "$expected" ]]
}

# ---------------------------------------------------------------------------
# Host operations
# ---------------------------------------------------------------------------

require_root() {
  if [[ $EUID -ne 0 ]]; then
    command -v sudo >/dev/null 2>&1 || die "Run this as root."
    exec sudo -E bash "$0" "$@"
  fi
}

confirm() {
  [[ $ASSUME_YES -eq 1 ]] && return 0
  [[ -t 0 ]] || die "$1 Re-run with --yes to confirm non-interactively."
  local answer
  read -r -p "$1 [y/N] " answer
  [[ "$answer" =~ ^[Yy]([Ee][Ss])?$ ]]
}

detect_platform() {
  [[ "$(uname -s)" == Linux ]] || die "Abyssal's installer supports Linux only."
  case "$(uname -m)" in
    x86_64 | amd64 | aarch64 | arm64) ;;
    *) die "Unsupported CPU architecture: $(uname -m)" ;;
  esac
  [[ -r /etc/os-release ]] || die "Cannot identify this Linux distribution (/etc/os-release missing)."
}

package_manager() {
  local manager
  for manager in apt-get dnf yum zypper apk pacman; do
    if command -v "$manager" >/dev/null 2>&1; then
      printf '%s\n' "$manager"
      return 0
    fi
  done
  return 1
}

install_packages() {
  local manager
  manager="$(package_manager)" || die "No supported package manager found. Install: $*"
  case "$manager" in
    apt-get) DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" ;;
    dnf | yum) "$manager" install -y -q "$@" ;;
    zypper) zypper --non-interactive install "$@" ;;
    apk) apk add --no-cache "$@" ;;
    pacman) pacman -Sy --noconfirm --needed "$@" ;;
  esac
}

ensure_base_tools() {
  local missing=()
  local tool
  for tool in curl tar sha256sum getent; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    log "Installing base tools: ${missing[*]}"
    install_packages curl tar coreutils ca-certificates
  fi
  command -v ss >/dev/null 2>&1 || install_packages iproute2 >/dev/null 2>&1 || install_packages iproute >/dev/null 2>&1 || true
}

ensure_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    log "Installing Docker Engine (official convenience script from get.docker.com)"
    local script
    script="$(mktemp)"
    curl -fsSL --proto '=https' https://get.docker.com -o "$script"
    sh "$script"
    rm -f -- "$script"
  fi
  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now docker >/dev/null 2>&1 || true
  fi
  docker info >/dev/null 2>&1 || die "Docker is installed but not running. Start it and re-run."
  if ! docker compose version >/dev/null 2>&1; then
    log "Installing the Docker Compose plugin"
    install_packages docker-compose-plugin >/dev/null 2>&1 || install_packages docker-compose-v2 >/dev/null 2>&1 || true
    docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required. Install the docker-compose-plugin package and re-run."
  fi
  if ! docker buildx version >/dev/null 2>&1; then
    log "Installing the Docker Buildx plugin"
    install_packages docker-buildx-plugin >/dev/null 2>&1 || install_packages docker-buildx >/dev/null 2>&1 || true
    docker buildx version >/dev/null 2>&1 || die "Docker Buildx is required. Install the docker-buildx-plugin package and re-run."
  fi
}

ensure_service_user() {
  if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    log "Creating system user $SERVICE_USER"
    if command -v useradd >/dev/null 2>&1; then
      useradd --system --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    else
      adduser -S -D -H -h /nonexistent -s /sbin/nologin "$SERVICE_USER"
    fi
  fi
}

# True when this installation's container for SERVICE exists (running or not).
own_container() {
  docker ps -aq --filter "label=com.docker.compose.project=$COMPOSE_PROJECT" \
    --filter "label=com.docker.compose.service=$1" 2>/dev/null | grep -q .
}

own_container_running() {
  docker ps -q --filter "label=com.docker.compose.project=$COMPOSE_PROJECT" \
    --filter "label=com.docker.compose.service=$1" 2>/dev/null | grep -q .
}

port_in_use() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -Hltn "sport = :$port" 2>/dev/null | grep -q .
  else
    (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null
  fi
}

# A container from another project (for example an earlier manual deployment)
# holding the relay port is stopped only with --replace-existing.
handle_existing_relay_port() {
  local holders
  holders="$(docker ps --filter "publish=$RELAY_PORT" --format '{{.Names}} {{.Label "com.docker.compose.project"}}' 2>/dev/null |
    awk -v project="$COMPOSE_PROJECT" '$2 != project {print $1}')"
  if [[ -n "$holders" ]]; then
    if [[ $REPLACE_EXISTING -eq 1 ]]; then
      log "Stopping existing container(s) on port $RELAY_PORT: $holders"
      # shellcheck disable=SC2086
      docker stop $holders >/dev/null
    else
      die "Port $RELAY_PORT is used by container(s): $holders. Re-run with --replace-existing to stop them, or choose --port."
    fi
  elif port_in_use "$RELAY_PORT" && ! own_container_running relay; then
    die "Port $RELAY_PORT is already in use by another program. Choose a different --port."
  fi
}

resolve_version() {
  if [[ "$VERSION" != latest ]]; then
    printf '%s\n' "$VERSION"
    return 0
  fi
  local effective tag
  effective="$(curl -fsSLI --proto '=https' -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")" ||
    die "Cannot reach GitHub to find the latest release. Pass --version or --bundle."
  tag="${effective##*/}"
  tag="${tag#v}"
  valid_version "$tag" && [[ "$tag" != latest ]] || die "Could not determine the latest release (got: $effective)."
  printf '%s\n' "$tag"
}

download_bundle() {
  local version="$1" destination="$2"
  local base="https://github.com/$REPO/releases/download/v$version"
  local name="abyssal-server-$version.tar.gz"
  log "Downloading $name"
  curl -fSL --proto '=https' --proto-redir '=https' --max-filesize "$MAX_BUNDLE_BYTES" \
    --retry 3 --connect-timeout 15 -o "$destination" "$base/$name" ||
    die "Download failed: $base/$name"
  local checksum
  checksum="$(curl -fsSL --proto '=https' --proto-redir '=https' --max-filesize 4096 "$base/$name.sha256")" ||
    die "Download failed: $base/$name.sha256"
  verify_sha256 "$destination" "$checksum" || die "Checksum mismatch for $name; refusing to install it."
}

extract_bundle() {
  local bundle="$1" version="$2"
  local target="$INSTALL_ROOT/releases/$version"
  local staging
  staging="$(mktemp -d "$INSTALL_ROOT/.extract.XXXXXX")"
  tar -xzf "$bundle" -C "$staging" --no-same-owner --no-same-permissions
  local top="$staging/abyssal-server-$version"
  [[ -d "$top" && -f "$top/mirage-server/Dockerfile" && -f "$top/.web-release/source-commit" ]] ||
    { rm -rf -- "$staging"; die "The bundle does not contain an Abyssal $version server release."; }
  rm -rf -- "$target"
  mkdir -p "$INSTALL_ROOT/releases"
  mv -- "$top" "$target"
  rm -rf -- "$staging"
  ln -sfn "releases/$version" "$INSTALL_ROOT/current"
  printf '%s\n' "$version" > "$INSTALL_ROOT/VERSION"
}

ensure_node_key() {
  local key="$STATE_DIR/node-signing.key"
  local uid gid
  uid="$(id -u "$SERVICE_USER")"
  gid="$(id -g "$SERVICE_USER")"
  install -d -m 0700 -o "$uid" -g "$gid" "$STATE_DIR"
  if [[ -n "$NODE_KEY_IMPORT" ]]; then
    [[ -f "$NODE_KEY_IMPORT" && ! -L "$NODE_KEY_IMPORT" && "$(stat -c '%s' -- "$NODE_KEY_IMPORT")" == 32 ]] ||
      die "--node-key must be a regular 32-byte key file: $NODE_KEY_IMPORT"
    [[ ! -f "$key" ]] || cmp -s -- "$key" "$NODE_KEY_IMPORT" ||
      confirm "Replace this node's signing key? Existing invites and node identity change." || die "Kept the existing key."
    install -m 0600 -o "$uid" -g "$gid" -- "$NODE_KEY_IMPORT" "$key"
    log "Imported node signing key"
  elif [[ ! -f "$key" ]]; then
    log "Generating the node signing key (kept in $key; back it up privately)"
    (umask 077 && head -c 32 /dev/urandom > "$key")
    chown "$uid:$gid" "$key"
    chmod 0600 "$key"
  fi
  [[ "$(stat -c '%s' -- "$key")" == 32 ]] || die "Node signing key is not 32 bytes: $key"
}

write_config() {
  local release_dir="$1" version="$2" proxy="$3"
  install -d -m 0750 "$CONFIG_DIR"
  local env_file="$CONFIG_DIR/relay.env"
  local rendered
  rendered="$(mktemp)"
  render_env "$release_dir/mirage-server/.env.example" "$env_file" "$DOMAIN" "$INVITE_COUNT" > "$rendered"
  install -m 0600 -- "$rendered" "$env_file"
  rm -f -- "$rendered"
  local public_url
  public_url="$(env_public_url "$env_file")"
  [[ "$public_url" =~ ^https://[a-z0-9.-]+$ ]] || die "Set the public name with --domain chat.example.com."
  DOMAIN="${public_url#https://}"

  local uid gid total_kib memory
  uid="$(id -u "$SERVICE_USER")"
  gid="$(id -g "$SERVICE_USER")"
  total_kib="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
  memory="$(relay_memory_limit "$total_kib")"
  render_compose "$release_dir" "$version" "$uid" "$gid" "$RELAY_PORT" "$proxy" "$memory" > "$CONFIG_DIR/compose.yml"
  if [[ "$proxy" == caddy ]]; then
    render_caddyfile "$DOMAIN" "$ACME_EMAIL" > "$CONFIG_DIR/Caddyfile"
  else
    rm -f -- "$CONFIG_DIR/Caddyfile"
  fi
  printf 'PROXY=%s\nRELAY_PORT=%s\nREPO=%s\n' "$proxy" "$RELAY_PORT" "$REPO" > "$CONFIG_DIR/installer.conf"
}

load_saved_settings() {
  local file="$CONFIG_DIR/installer.conf"
  [[ -f "$file" ]] || return 0
  local saved_proxy saved_port saved_repo
  saved_proxy="$(sed -n 's/^PROXY=//p' "$file")"
  saved_port="$(sed -n 's/^RELAY_PORT=//p' "$file")"
  saved_repo="$(sed -n 's/^REPO=//p' "$file")"
  [[ "$PROXY" != auto || -z "$saved_proxy" ]] || PROXY="$saved_proxy"
  [[ "$RELAY_PORT" != 4020 || -z "$saved_port" ]] || RELAY_PORT="$saved_port"
  [[ "$REPO" != "$ABYSSAL_DEFAULT_REPO" || -z "$saved_repo" ]] || REPO="$saved_repo"
  valid_port "$RELAY_PORT" && valid_repo "$REPO" && [[ "$PROXY" =~ ^(auto|caddy|none)$ ]] ||
    die "Saved installer settings are invalid: $file"
}

open_firewall() {
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    log "Allowing ports 80 and 443 in ufw"
    ufw allow 80/tcp >/dev/null && ufw allow 443/tcp >/dev/null && ufw allow 443/udp >/dev/null
  elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    log "Allowing HTTP and HTTPS in firewalld"
    firewall-cmd --permanent --add-service=http --add-service=https >/dev/null && firewall-cmd --reload >/dev/null
  fi
}

check_dns() {
  local addresses
  addresses="$(getent ahosts "$DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')"
  if [[ -z "$addresses" ]]; then
    warn "$DOMAIN does not resolve yet. Point its A/AAAA record at this server; HTTPS starts once it does."
    return 0
  fi
  local local_addresses address
  local_addresses="$(ip -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | tr '\n' ' ')"
  for address in $addresses; do
    [[ " $local_addresses " == *" $address "* ]] && return 0
  done
  warn "$DOMAIN resolves to $addresses, not to an address on this server. That is fine behind a CDN or NAT; otherwise fix DNS before expecting HTTPS."
}

compose() {
  docker compose -p "$COMPOSE_PROJECT" -f "$CONFIG_DIR/compose.yml" "$@"
}

# Small VPSes cannot compile the relay in RAM alone. Swap exists only for the
# build and is removed before the relay starts, so relay memory never pages to disk.
with_build_swap() {
  local total_kib swap_kib added=0 status=0
  total_kib="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
  swap_kib="$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo)"
  if ((total_kib + swap_kib < 3 * 1024 * 1024)) && [[ ! -e "$BUILD_SWAP_FILE" ]]; then
    log "Adding 2 GiB of temporary swap for the build (removed afterwards)"
    if (fallocate -l 2G "$BUILD_SWAP_FILE" 2>/dev/null || dd if=/dev/zero of="$BUILD_SWAP_FILE" bs=1M count=2048 status=none) &&
      chmod 0600 "$BUILD_SWAP_FILE" && mkswap "$BUILD_SWAP_FILE" >/dev/null && swapon "$BUILD_SWAP_FILE"; then
      added=1
    else
      rm -f -- "$BUILD_SWAP_FILE"
      warn "Could not add temporary swap; the build may run out of memory."
    fi
  fi
  "$@" || status=$?
  if [[ $added -eq 1 ]]; then
    swapoff "$BUILD_SWAP_FILE" || warn "Could not turn off temporary swap $BUILD_SWAP_FILE"
    rm -f -- "$BUILD_SWAP_FILE"
  fi
  return "$status"
}

build_images() {
  log "Building the relay image (first build takes several minutes)"
  DOCKER_BUILDKIT=1 compose build relay
  if [[ "$(saved_proxy)" == caddy ]]; then
    compose pull --quiet caddy
  fi
}

saved_proxy() {
  sed -n 's/^PROXY=//p' "$CONFIG_DIR/installer.conf" 2>/dev/null
}

# Recreating the relay wipes every account, room and message held in RAM.
start_relay() {
  compose rm -sf relay >/dev/null 2>&1 || true
  compose create --force-recreate relay >/dev/null
  if [[ "$(saved_proxy)" == caddy ]]; then
    compose up -d caddy >/dev/null
  fi
  local container
  container="$(compose ps -aq relay)"
  [[ -n "$container" ]] || die "The relay container was not created."
  printf '\n'
  log "One-time invites follow. Copy or scan them now; they cannot be shown again."
  printf '\n'
  local status=0
  timeout --signal=KILL 12s docker start --attach "$container" || status=$?
  [[ $status -eq 0 || $status -eq 137 ]] || die "The relay stopped during startup (exit $status). Check the settings in $CONFIG_DIR/relay.env."
  wait_for_health
}

wait_for_health() {
  local attempt
  for attempt in $(seq 1 30); do
    if curl -fsS --max-time 2 "http://127.0.0.1:$RELAY_PORT/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  die "The relay did not become healthy on 127.0.0.1:$RELAY_PORT."
}

print_summary() {
  local proxy
  proxy="$(saved_proxy)"
  printf '\n'
  log "Abyssal $(cat "$INSTALL_ROOT/VERSION") is running."
  if [[ "$proxy" == caddy ]]; then
    printf '   Web app:  https://%s\n' "$DOMAIN"
    printf '   HTTPS certificates are issued automatically once DNS points here.\n'
  else
    printf '   The relay listens on 127.0.0.1:%s. Point your reverse proxy or tunnel for\n' "$RELAY_PORT"
    printf '   https://%s at it, keeping WebSocket upgrades. Example for nginx:\n\n' "$DOMAIN"
    printf '     location / {\n       proxy_pass http://127.0.0.1:%s;\n       proxy_http_version 1.1;\n' "$RELAY_PORT"
    printf '       proxy_set_header Upgrade $http_upgrade;\n       proxy_set_header Connection "upgrade";\n'
    printf '       proxy_set_header Host $host;\n       proxy_read_timeout 3600s;\n     }\n\n'
    printf '   Cloudflare Tunnel: cloudflared tunnel --url http://127.0.0.1:%s\n' "$RELAY_PORT"
  fi
  printf '   Node key: %s/node-signing.key (back it up privately)\n' "$STATE_DIR"
  printf '   Settings: %s/relay.env\n\n' "$CONFIG_DIR"
  printf '   sudo abyssal status | restart | upgrade | stop | uninstall\n'
}

install_cli() {
  local self
  self="$(readlink -f -- "${BASH_SOURCE[0]}")"
  if [[ "$self" != "$CLI_PATH" ]]; then
    install -m 0755 -- "$self" "$CLI_PATH"
  fi
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

cmd_install() {
  detect_platform
  ensure_base_tools
  ensure_docker
  ensure_service_user
  load_saved_settings
  install -d -m 0755 "$INSTALL_ROOT"

  if [[ -z "$DOMAIN" && ! -f "$CONFIG_DIR/relay.env" ]]; then
    [[ -t 0 ]] || die "Pass --domain chat.example.com on the first install."
    read -r -p "Public DNS name for this server (e.g. chat.example.com): " DOMAIN
    DOMAIN="${DOMAIN,,}"
    valid_domain "$DOMAIN" || die "Not a valid public DNS name: $DOMAIN"
  fi

  local busy80=0 busy443=0 proxy
  if ! own_container_running caddy; then
    port_in_use 80 && busy80=1
    port_in_use 443 && busy443=1
  fi
  proxy="$(decide_proxy "$PROXY" "$busy80" "$busy443")"
  if [[ "$proxy" == caddy && ( $busy80 -eq 1 || $busy443 -eq 1 ) ]]; then
    die "Ports 80/443 are in use by another web server. Use --proxy none and route the domain to 127.0.0.1:$RELAY_PORT."
  fi
  if [[ "$PROXY" == auto && "$proxy" == none ]]; then
    warn "Ports 80/443 are taken by another program, so HTTPS is left to it (--proxy none)."
  fi
  handle_existing_relay_port

  local version bundle cleanup_bundle=0
  if [[ -n "$BUNDLE_FILE" ]]; then
    [[ -f "$BUNDLE_FILE" ]] || die "Bundle not found: $BUNDLE_FILE"
    bundle="$BUNDLE_FILE"
    version="$(basename -- "$bundle")"
    version="${version#abyssal-server-}"
    version="${version%.tar.gz}"
    valid_version "$version" && [[ "$version" != latest ]] || die "Bundle name must be abyssal-server-X.Y.Z.tar.gz"
  else
    version="$(resolve_version)"
    bundle="$(mktemp)"
    cleanup_bundle=1
    download_bundle "$version" "$bundle"
  fi

  if own_container_running relay; then
    confirm "Abyssal is running. Reinstalling restarts it and wipes all accounts, rooms and messages in RAM. Continue?" ||
      die "Nothing changed."
  fi

  extract_bundle "$bundle" "$version"
  [[ $cleanup_bundle -eq 0 ]] || rm -f -- "$bundle"
  ensure_node_key
  write_config "$INSTALL_ROOT/releases/$version" "$version" "$proxy"
  [[ "$proxy" != caddy ]] || { open_firewall; check_dns; }
  with_build_swap build_images
  start_relay
  install_cli
  prune_old_releases "$version"
  print_summary
}

cmd_upgrade() {
  [[ -f "$CONFIG_DIR/compose.yml" ]] || die "Abyssal is not installed here. Run: abyssal install --domain NAME"
  REPLACE_EXISTING=1
  cmd_install
}

cmd_restart() {
  [[ -f "$CONFIG_DIR/compose.yml" ]] || die "Abyssal is not installed here."
  confirm "Restarting wipes all accounts, rooms and messages in RAM and prints new invites. Continue?" || die "Nothing changed."
  DOMAIN="$(env_public_url "$CONFIG_DIR/relay.env")"
  DOMAIN="${DOMAIN#https://}"
  RELAY_PORT="$(sed -n 's/^RELAY_PORT=//p' "$CONFIG_DIR/installer.conf")"
  start_relay
  print_summary
}

cmd_status() {
  [[ -f "$CONFIG_DIR/compose.yml" ]] || die "Abyssal is not installed here."
  RELAY_PORT="$(sed -n 's/^RELAY_PORT=//p' "$CONFIG_DIR/installer.conf")"
  printf 'Version: %s\n' "$(cat "$INSTALL_ROOT/VERSION" 2>/dev/null || echo unknown)"
  compose ps
  if curl -fsS --max-time 3 "http://127.0.0.1:$RELAY_PORT/health"; then
    printf '\n'
  else
    printf 'Relay health check failed.\n'
  fi
  local url
  url="$(env_public_url "$CONFIG_DIR/relay.env")"
  if [[ -n "$url" ]] && curl -fsS --max-time 8 "$url/health" >/dev/null 2>&1; then
    printf 'Public URL %s is reachable.\n' "$url"
  else
    printf 'Public URL %s is not reachable from this server (DNS, proxy or certificate).\n' "$url"
  fi
}

cmd_stop() {
  [[ -f "$CONFIG_DIR/compose.yml" ]] || die "Abyssal is not installed here."
  confirm "Stopping wipes all accounts, rooms and messages in RAM. Continue?" || die "Nothing changed."
  compose stop relay
}

cmd_uninstall() {
  confirm "Remove Abyssal containers, images and releases from this server?" || die "Nothing changed."
  if [[ -f "$CONFIG_DIR/compose.yml" ]]; then
    compose down --rmi all --volumes --remove-orphans || true
  fi
  rm -rf -- "$INSTALL_ROOT"
  rm -f -- "$CLI_PATH"
  if [[ $PURGE -eq 1 ]]; then
    rm -rf -- "$CONFIG_DIR" "$STATE_DIR"
    userdel "$SERVICE_USER" >/dev/null 2>&1 || true
    log "Removed Abyssal, its configuration and the node signing key."
  else
    log "Removed Abyssal. Kept $CONFIG_DIR and $STATE_DIR (node key); use --purge to delete them."
  fi
}

prune_old_releases() {
  local keep="$1" dir tag
  for dir in "$INSTALL_ROOT"/releases/*; do
    [[ -d "$dir" && "$(basename -- "$dir")" != "$keep" ]] && rm -rf -- "$dir"
  done
  for tag in $(docker images abyssal-relay --format '{{.Tag}}' 2>/dev/null); do
    [[ "$tag" == "$keep" ]] || docker image rm "abyssal-relay:$tag" >/dev/null 2>&1 || true
  done
  return 0
}

main() {
  parse_args "$@"
  if [[ "$COMMAND" == help ]]; then
    usage
    return 0
  fi
  require_root "$@"
  case "$COMMAND" in
    install) cmd_install ;;
    upgrade) cmd_upgrade ;;
    restart) cmd_restart ;;
    status) cmd_status ;;
    stop) cmd_stop ;;
    uninstall) cmd_uninstall ;;
  esac
}

if [[ "${ABYSSAL_INSTALL_SOURCED:-0}" != 1 ]]; then
  main "$@"
fi
