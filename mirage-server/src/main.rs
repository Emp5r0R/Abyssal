use std::{
    collections::{HashMap, HashSet},
    env,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use abyssal_core::secure_protocol::{
    opaque_server_finish_login, opaque_server_finish_registration,
    opaque_server_registration_response, opaque_server_setup, opaque_server_start_login,
    prekey_id_for_public,
};
use axum::{
    body::Bytes,
    extract::Request,
    extract::{
        ws::{Message, WebSocket},
        DefaultBodyLimit, Path, Query, State, WebSocketUpgrade,
    },
    http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, Mutex};
use tower_http::{
    cors::CorsLayer,
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use tracing::{error, info, warn};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const IMAGE_ATTACHMENT_LIMIT_BYTES: usize = 20 * 1024 * 1024;
const VIDEO_ATTACHMENT_LIMIT_BYTES: usize = 100 * 1024 * 1024;
const FILE_ATTACHMENT_LIMIT_BYTES: usize = 200 * 1024 * 1024;
const ENCRYPTION_OVERHEAD_BYTES: usize = 64 * 1024;
const WS_RATE_WINDOW_MS: u64 = 10_000;
const WS_MAX_FRAMES_PER_WINDOW: usize = 30;
const WS_MAX_BYTES_PER_WINDOW: usize = 4 * 1024 * 1024;
const WS_MAX_FRAME_BYTES: usize = 1024 * 1024;
const STATE_REVISION_WINDOW_BITS: u32 = u128::BITS;
const MAX_PENDING_FRAMES_PER_ROOM: usize = 500;
const CLIENT_OUTBOUND_QUEUE_CAPACITY: usize = 256;
const ACCOUNT_BODY_LIMIT_BYTES: usize = 16 * 1024;
const MAX_CHAT_ID_BYTES: usize = 128;
const MAX_USERNAME_BYTES: usize = 80;
const MAX_CODE_BYTES: usize = 128;
const LOGIN_RATE_WINDOW_MS: u64 = 60_000;
const LOGIN_MAX_ATTEMPTS_PER_WINDOW: usize = 6;
const WEB_SOCKET_PROTOCOL: &str = "abyssal-v1";
const OPAQUE_HANDSHAKE_TTL_MS: u64 = 60_000;
const IDENTITY_FINGERPRINT_BYTES: usize = 64;
const ONE_TIME_KEY_BYTES: usize = 32;
const ONE_TIME_KEY_OFFSET: usize = IDENTITY_FINGERPRINT_BYTES;
const FALLBACK_KEY_OFFSET: usize = ONE_TIME_KEY_OFFSET + ONE_TIME_KEY_BYTES;
const IDENTITY_PUBLIC_BYTES: usize = FALLBACK_KEY_OFFSET + 32;
const MAX_IDENTITY_ENVELOPE_BYTES: usize = 512 * 1024;
const MESSAGE_NONCE_BYTES: usize = 12;
const MESSAGE_SIGNATURE_BYTES: usize = 64;
const MAX_WRAPPED_KEY_BYTES: usize = 4096;
const E2EE_PROTOCOL_VERSION: u32 = 5;
const IDENTITY_ENVELOPE_VERSION: u8 = 4;
const REPLAY_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;
const MAX_REPLAY_IDS: usize = 50_000;
const PREKEY_CLAIM_TTL_MS: u64 = 10 * 60 * 1000;
const MAX_PREKEY_ID_BYTES: usize = 32;
const CODE_ID_DOMAIN: &[u8] = b"ABYSSAL_INVITE_CODE_ID_V1";

type CodeId = [u8; 32];
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
struct AppState {
    node_id: String,
    attachment_ram_limit_bytes: usize,
    max_rooms_per_user: usize,
    web_origins: Vec<String>,
    session_inactivity_ms: u64,
    inactivity_limit_ms: Option<u64>,
    last_activity_ms: Arc<Mutex<u64>>,
    account_ops: Arc<Mutex<()>>,
    opaque_setup: Arc<Vec<u8>>,
    opaque_handshakes: Arc<Mutex<HashMap<Uuid, OpaqueHandshake>>>,
    invite_code_pepper: Arc<CodeId>,
    boot_codes: Arc<Mutex<Option<Vec<String>>>>,
    available_codes: Arc<Mutex<HashSet<CodeId>>>,
    accounts: Arc<Mutex<HashMap<CodeId, Account>>>,
    sessions: Arc<Mutex<HashMap<String, AuthSession>>>,
    active_connections: Arc<Mutex<HashMap<CodeId, Uuid>>>,
    clients: Arc<Mutex<HashMap<Uuid, ClientHandle>>>,
    frame_limits: Arc<Mutex<HashMap<Uuid, RateState>>>,
    login_limits: Arc<Mutex<HashMap<CodeId, RateState>>>,
    replay_ids: Arc<Mutex<HashMap<ReplayKey, u64>>>,
    prekey_claims: Arc<Mutex<HashMap<PrekeyClaimKey, PrekeyClaim>>>,
    rooms: Arc<Mutex<HashMap<String, HashSet<Uuid>>>>,
    room_catalog: Arc<Mutex<HashMap<String, RoomEntry>>>,
    direct_catalog: Arc<Mutex<HashMap<String, DirectEntry>>>,
    pending: Arc<Mutex<HashMap<PendingKey, Vec<OutboundFrame>>>>,
    attachments: Arc<Mutex<HashMap<Uuid, AttachmentRecord>>>,
}

#[derive(Clone)]
struct Account {
    username: String,
    password_file: Vec<u8>,
    identity_public: Vec<u8>,
    identity_envelope: Vec<u8>,
    prekey_id: String,
    state_revision: u64,
    state_revision_window: u128,
    connected: bool,
}

enum OpaqueHandshake {
    Registration {
        code_id: CodeId,
        created_at_ms: u64,
    },
    Login {
        code_id: CodeId,
        username: String,
        server_state: Vec<u8>,
        created_at_ms: u64,
    },
}

#[derive(Clone)]
struct AuthSession {
    code_id: CodeId,
    username: String,
    last_activity_ms: u64,
}

#[derive(Clone)]
struct ClientHandle {
    code_id: CodeId,
    username: String,
    tx: mpsc::Sender<Message>,
}

#[derive(Clone)]
struct RoomEntry {
    room: RoomRecord,
    owner_code_id: CodeId,
}

#[derive(Clone)]
struct DirectEntry {
    id: String,
    user_a: String,
    user_b: String,
}

#[derive(Clone)]
struct RateState {
    window_start_ms: u64,
    count: usize,
    bytes: usize,
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct PendingKey {
    chat_id: String,
    recipient_username: String,
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct ReplayKey {
    chat_id: String,
    sender_username: String,
    message_id: String,
}

impl Drop for ReplayKey {
    fn drop(&mut self) {
        self.chat_id.zeroize();
        self.sender_username.zeroize();
        self.message_id.zeroize();
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct PrekeyClaimKey {
    code_id: CodeId,
    prekey_id: String,
}

struct PrekeyClaim {
    chat_id: String,
    message_id: String,
    sender_username: String,
    created_at_ms: u64,
}

impl Drop for PrekeyClaimKey {
    fn drop(&mut self) {
        self.code_id.zeroize();
        self.prekey_id.zeroize();
    }
}

impl Drop for PrekeyClaim {
    fn drop(&mut self) {
        self.chat_id.zeroize();
        self.message_id.zeroize();
        self.sender_username.zeroize();
    }
}

impl Drop for PendingKey {
    fn drop(&mut self) {
        self.chat_id.zeroize();
        self.recipient_username.zeroize();
    }
}

struct AttachmentRecord {
    encrypted_bytes: Vec<u8>,
    chat_id: String,
    media_type: String,
    one_time: bool,
    delete_after_download: bool,
    expires_at_ms: Option<u64>,
}

impl Drop for AttachmentRecord {
    fn drop(&mut self) {
        self.encrypted_bytes.zeroize();
        self.chat_id.zeroize();
        self.media_type.zeroize();
    }
}

impl Drop for Account {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password_file.zeroize();
        self.identity_public.zeroize();
        self.identity_envelope.zeroize();
        self.prekey_id.zeroize();
    }
}

impl Drop for OpaqueHandshake {
    fn drop(&mut self) {
        match self {
            Self::Registration { code_id, .. } => code_id.zeroize(),
            Self::Login {
                code_id,
                username,
                server_state,
                ..
            } => {
                code_id.zeroize();
                username.zeroize();
                server_state.zeroize();
            }
        }
    }
}

impl Drop for AuthSession {
    fn drop(&mut self) {
        self.code_id.zeroize();
        self.username.zeroize();
    }
}

impl Drop for DirectEntry {
    fn drop(&mut self) {
        self.id.zeroize();
        self.user_a.zeroize();
        self.user_b.zeroize();
    }
}

impl Drop for RoomEntry {
    fn drop(&mut self) {
        self.owner_code_id.zeroize();
    }
}

impl Drop for ClientHandle {
    fn drop(&mut self) {
        self.code_id.zeroize();
        self.username.zeroize();
    }
}

#[derive(Clone)]
enum ConversationAccess {
    Room(RoomRecord),
    Direct,
}

#[derive(Clone, Serialize, Deserialize)]
struct RoomRecord {
    id: String,
    name: String,
    #[serde(default)]
    owner_username: String,
    self_destruct_timer_sec: u64,
    overall_expiry_sec: u64,
    allow_images: bool,
    allow_videos: bool,
    allow_files: bool,
    enforce_text_absolute_expiry: bool,
    image_read_timer_sec: u64,
    image_overall_expiry_sec: u64,
    enforce_image_absolute_expiry: bool,
    video_read_timer_sec: u64,
    video_overall_expiry_sec: u64,
    enforce_video_absolute_expiry: bool,
    file_read_timer_sec: u64,
    file_overall_expiry_sec: u64,
    enforce_file_absolute_expiry: bool,
}

#[derive(Deserialize)]
struct OpaqueAccountStartRequest {
    code: String,
    registration_request_b64: String,
    credential_request_b64: String,
}

impl Drop for OpaqueAccountStartRequest {
    fn drop(&mut self) {
        self.code.zeroize();
        self.registration_request_b64.zeroize();
        self.credential_request_b64.zeroize();
    }
}

#[derive(Deserialize)]
struct OpaqueAccountFinishRequest {
    handshake_id: Uuid,
    registration_upload_b64: Option<String>,
    credential_finalization_b64: Option<String>,
    identity_public_b64: Option<String>,
    identity_prekey_id: Option<String>,
    identity_envelope_b64: Option<String>,
}

impl Drop for OpaqueAccountFinishRequest {
    fn drop(&mut self) {
        self.registration_upload_b64.zeroize();
        self.credential_finalization_b64.zeroize();
        self.identity_public_b64.zeroize();
        self.identity_prekey_id.zeroize();
        self.identity_envelope_b64.zeroize();
    }
}

#[derive(Deserialize)]
struct AttachmentQuery {
    chat_id: String,
    media_type: Option<String>,
    one_time: Option<bool>,
    delete_after_download: Option<bool>,
    ttl_sec: Option<u64>,
}

#[derive(Serialize)]
struct AccountResponse {
    accepted: bool,
    created: bool,
    token: Option<String>,
    node_id: String,
    username: Option<String>,
    max_rooms_per_user: usize,
    session_inactivity_sec: u64,
    identity_public_b64: Option<String>,
    identity_prekey_id: Option<String>,
    identity_envelope_b64: Option<String>,
    error: Option<String>,
}

#[derive(Serialize)]
struct OpaqueAccountStartResponse {
    accepted: bool,
    mode: Option<&'static str>,
    handshake_id: Option<Uuid>,
    response_b64: Option<String>,
    node_id: String,
    identity_public_b64: Option<String>,
    identity_prekey_id: Option<String>,
    identity_envelope_b64: Option<String>,
    error: Option<&'static str>,
}

#[derive(Serialize)]
struct HealthResponse {
    ok: bool,
    node_id: String,
    storage: &'static str,
    available_codes: usize,
    accounts: usize,
    max_rooms_per_user: usize,
    session_inactivity_sec: u64,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum InboundFrame {
    #[serde(rename = "activity")]
    Activity,
    #[serde(rename = "join")]
    Join { chat_id: String },
    #[serde(rename = "leave")]
    Leave { chat_id: String },
    #[serde(rename = "message")]
    Message {
        chat_id: String,
        version: u32,
        message_id: String,
        nonce_b64: String,
        ciphertext_b64: String,
        signature_b64: String,
        envelopes: Vec<InboundRecipientEnvelope>,
        state_revision: u64,
        identity_envelope_b64: String,
        identity_public_b64: String,
        prekey_id: String,
    },
    #[serde(rename = "message_ack")]
    MessageAck {
        chat_id: String,
        message_id: String,
        sender_username: String,
        state_revision: u64,
        identity_envelope_b64: String,
        identity_public_b64: String,
        prekey_id: String,
        used_prekey_id: String,
    },
    #[serde(rename = "identity_state")]
    IdentityState {
        state_revision: u64,
        identity_envelope_b64: String,
        identity_public_b64: String,
        prekey_id: String,
    },
    #[serde(rename = "global_wipe")]
    GlobalWipe,
    #[serde(rename = "create_room")]
    CreateRoom { room: RoomRecord },
    #[serde(rename = "delete_room")]
    DeleteRoom { chat_id: String },
    #[serde(rename = "open_direct")]
    OpenDirect { peer_username: String },
    #[serde(rename = "dummy")]
    Dummy {
        padding_b64: Option<String>,
        bytes: Option<usize>,
    },
}

#[derive(Deserialize)]
struct InboundRecipientEnvelope {
    recipient_username: String,
    wrapped_key_b64: String,
    prekey_id: String,
    is_prekey: bool,
}

#[derive(Clone, Serialize)]
#[serde(tag = "type")]
enum OutboundFrame {
    #[serde(rename = "message")]
    Message {
        chat_id: String,
        version: u32,
        message_id: String,
        nonce_b64: String,
        ciphertext_b64: String,
        signature_b64: String,
        wrapped_key_b64: String,
        prekey_id: String,
        is_prekey: bool,
        sender_username: String,
        sender_public_key_b64: String,
    },
    #[serde(rename = "presence")]
    Presence { users: Vec<PresenceUser> },
    #[serde(rename = "GLOBAL_WIPE")]
    GlobalWipe,
    #[serde(rename = "rooms")]
    Rooms { rooms: Vec<RoomRecord> },
    #[serde(rename = "room_created")]
    RoomCreated { room: RoomRecord },
    #[serde(rename = "room_deleted")]
    RoomDeleted { chat_id: String },
    #[serde(rename = "directs")]
    Directs { directs: Vec<DirectRecord> },
    #[serde(rename = "direct_opened")]
    DirectOpened { direct: DirectRecord },
}

impl OutboundFrame {
    fn zeroize_sensitive(&mut self) {
        if let Self::Message {
            chat_id,
            message_id,
            nonce_b64,
            ciphertext_b64,
            signature_b64,
            wrapped_key_b64,
            sender_username,
            sender_public_key_b64,
            ..
        } = self
        {
            chat_id.zeroize();
            message_id.zeroize();
            nonce_b64.zeroize();
            ciphertext_b64.zeroize();
            signature_b64.zeroize();
            wrapped_key_b64.zeroize();
            sender_username.zeroize();
            sender_public_key_b64.zeroize();
        }
    }
}

impl Drop for OutboundFrame {
    fn drop(&mut self) {
        self.zeroize_sensitive();
    }
}

#[derive(Clone, Serialize)]
struct PresenceUser {
    username: String,
    connected: bool,
    identity_public_b64: String,
    identity_prekey_id: String,
    directory_digest: String,
}

#[derive(Clone, Serialize)]
struct DirectRecord {
    id: String,
    peer_username: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mirage_server=info,tower_http=info".into()),
        )
        .init();

    let state = AppState::from_env();
    tokio::spawn(attachment_sweeper(state.clone()));
    tokio::spawn(session_sweeper(state.clone()));
    if state.inactivity_limit_ms.is_some() {
        tokio::spawn(inactivity_watcher(state.clone()));
    }

    let bind_addr: SocketAddr = env::var("ABYSSAL_BIND_ADDR")
        .or_else(|_| env::var("MIRAGE_BIND_ADDR"))
        .unwrap_or_else(|_| "0.0.0.0:4020".to_string())
        .parse()
        .expect("ABYSSAL_BIND_ADDR must be a valid socket address");

    let attachment_body_limit = FILE_ATTACHMENT_LIMIT_BYTES + ENCRYPTION_OVERHEAD_BYTES;
    let account_routes = Router::new()
        .route("/v2/account/start", post(start_opaque_account))
        .route("/v2/account/finish", post(finish_opaque_account))
        .route("/v1/account/logout", post(logout_account))
        .layer(DefaultBodyLimit::max(ACCOUNT_BODY_LIMIT_BYTES));
    let attachment_routes = Router::new()
        .route("/v1/attachment", post(upload_attachment))
        .route("/v1/attachment/:id", get(download_attachment))
        .layer(DefaultBodyLimit::max(attachment_body_limit));

    let web_origins = state.web_origins.clone();
    let mut app = Router::new()
        .route("/health", get(health))
        .merge(account_routes)
        .merge(attachment_routes)
        .route("/v1/ws", get(ws_handler))
        .route("/v1/*path", any(api_not_found))
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    if let Some(web_root) = resolve_web_root() {
        info!("serving Abyssal web client from {}", web_root.display());
        let index = web_root.join("index.html");
        app = app.fallback_service(
            ServeDir::new(web_root)
                .append_index_html_on_directories(true)
                .not_found_service(ServeFile::new(index)),
        );
    }

    let allowed_origins = web_origins
        .iter()
        .filter_map(|origin| HeaderValue::from_str(origin).ok())
        .collect::<Vec<_>>();
    if !allowed_origins.is_empty() {
        app = app.layer(
            CorsLayer::new()
                .allow_origin(allowed_origins)
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
                .max_age(std::time::Duration::from_secs(600)),
        );
    }
    app = app.layer(middleware::from_fn(security_headers));

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .expect("failed to bind ABYSSAL_BIND_ADDR");

    info!("abyssal relay listening on {bind_addr}");
    let code_print_delay_ms = read_usize_env("ABYSSAL_CODE_PRINT_DELAY_MS", 0).min(30_000) as u64;
    if code_print_delay_ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(code_print_delay_ms)).await;
    }
    state.print_boot_codes().await;
    axum::serve(listener, app).await.expect("server failed");
}

impl AppState {
    fn from_env() -> Self {
        let node_id = env::var("ABYSSAL_NODE_ID")
            .or_else(|_| env::var("MIRAGE_NODE_ID"))
            .unwrap_or_else(|_| format!("abyssal-{}", Uuid::new_v4().simple()));

        let min_len = read_usize_env("ABYSSAL_CODE_MIN_LEN", 12).clamp(12, MAX_CODE_BYTES);
        let max_distinct_lengths = MAX_CODE_BYTES - min_len + 1;
        let user_count = read_usize_env("ABYSSAL_CODE_COUNT", 5).min(max_distinct_lengths);
        let required_max_len = min_len.saturating_add(user_count.saturating_sub(1));
        let requested_max_len =
            read_usize_env("ABYSSAL_CODE_MAX_LEN", required_max_len).clamp(min_len, MAX_CODE_BYTES);
        let max_len = requested_max_len.max(required_max_len);
        let mut boot_code_set = HashSet::new();
        let mut generated_lengths = HashSet::new();
        let mut invite_code_pepper = [0_u8; 32];
        OsRng.fill_bytes(&mut invite_code_pepper);
        let attachment_ram_limit_bytes =
            read_usize_env("ABYSSAL_ATTACHMENT_RAM_LIMIT_MB", 512).saturating_mul(1024 * 1024);
        let max_rooms_per_user = read_usize_env("ABYSSAL_MAX_ROOMS_PER_USER", 5).clamp(1, 100);
        let web_origins = parse_origins_from_env("ABYSSAL_WEB_ORIGINS");
        let session_inactivity_minutes =
            read_usize_env("ABYSSAL_SESSION_INACTIVITY_MINUTES", 15).clamp(1, 24 * 60);
        let session_inactivity_ms = session_inactivity_minutes.saturating_mul(60 * 1000) as u64;
        let inactivity_limit_ms = read_usize_env("ABYSSAL_INACTIVITY_LIMIT_HOURS", 0)
            .checked_mul(60 * 60 * 1000)
            .filter(|limit| *limit > 0)
            .map(|limit| limit as u64);

        generate_codes(
            &mut boot_code_set,
            &mut generated_lengths,
            user_count,
            min_len,
            max_len,
        );
        let boot_codes = boot_code_set.into_iter().collect::<Vec<_>>();
        let available_codes = boot_codes
            .iter()
            .map(|code| derive_code_id(&invite_code_pepper, code))
            .collect::<HashSet<_>>();

        Self {
            node_id,
            attachment_ram_limit_bytes,
            max_rooms_per_user,
            web_origins,
            session_inactivity_ms,
            inactivity_limit_ms,
            last_activity_ms: Arc::new(Mutex::new(now_ms())),
            account_ops: Arc::new(Mutex::new(())),
            opaque_setup: Arc::new(opaque_server_setup()),
            opaque_handshakes: Arc::new(Mutex::new(HashMap::new())),
            invite_code_pepper: Arc::new(invite_code_pepper),
            boot_codes: Arc::new(Mutex::new(Some(boot_codes))),
            available_codes: Arc::new(Mutex::new(available_codes)),
            accounts: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            active_connections: Arc::new(Mutex::new(HashMap::new())),
            clients: Arc::new(Mutex::new(HashMap::new())),
            frame_limits: Arc::new(Mutex::new(HashMap::new())),
            login_limits: Arc::new(Mutex::new(HashMap::new())),
            replay_ids: Arc::new(Mutex::new(HashMap::new())),
            prekey_claims: Arc::new(Mutex::new(HashMap::new())),
            rooms: Arc::new(Mutex::new(HashMap::new())),
            room_catalog: Arc::new(Mutex::new(HashMap::new())),
            direct_catalog: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
            attachments: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn print_boot_codes(&self) {
        let Some(mut codes) = self.boot_codes.lock().await.take() else {
            return;
        };
        println!("ABYSSAL RAM-ONLY ACCESS CODES - copy these now; they are not written to disk");
        for code in codes.iter() {
            println!("ABYSSAL_CODE code={code}");
        }
        for code in &mut codes {
            code.zeroize();
        }
        drop(codes);
        info!(
            "ABYSSAL_ATTACHMENT_RAM_LIMIT bytes={}",
            self.attachment_ram_limit_bytes
        );
        info!(
            "ABYSSAL_ROOM_LIMIT max_rooms_per_user={}",
            self.max_rooms_per_user
        );
        info!(
            "ABYSSAL_SESSION_INACTIVITY inactivity_limit_ms={}",
            self.session_inactivity_ms
        );
        if !self.web_origins.is_empty() {
            info!("ABYSSAL_WEB_ORIGINS count={}", self.web_origins.len());
        }
        if let Some(limit_ms) = self.inactivity_limit_ms {
            info!("ABYSSAL_DEAD_MAN_SWITCH inactivity_limit_ms={limit_ms}");
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

fn read_usize_env(key: &str, fallback: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(fallback)
}

fn parse_origins_from_env(key: &str) -> Vec<String> {
    env::var(key)
        .unwrap_or_default()
        .split(',')
        .filter_map(|value| normalize_web_origin(value).ok())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect()
}

fn normalize_web_origin(value: &str) -> Result<String, String> {
    let trimmed = value.trim().trim_end_matches('/');
    let uri = trimmed
        .parse::<Uri>()
        .map_err(|_| "web origin rejected".to_string())?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| "web origin rejected".to_string())?;
    let authority = uri
        .authority()
        .ok_or_else(|| "web origin rejected".to_string())?;
    if !matches!(scheme, "http" | "https") || uri.path() != "/" || uri.query().is_some() {
        return Err("web origin rejected".to_string());
    }
    Ok(format!("{scheme}://{authority}"))
}

fn resolve_web_root() -> Option<PathBuf> {
    if let Ok(configured) = env::var("ABYSSAL_WEB_ROOT") {
        let path = PathBuf::from(configured);
        if path.join("index.html").is_file() {
            return Some(path);
        }
        warn!("ABYSSAL_WEB_ROOT has no index.html; web client disabled");
        return None;
    }

    ["apps/web/dist", "../apps/web/dist", "/opt/abyssal/web"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.join("index.html").is_file())
}

async fn api_not_found() -> StatusCode {
    StatusCode::NOT_FOUND
}

const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' blob: data:; media-src 'self' blob:; connect-src 'self' https: wss: http: ws:; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; worker-src 'none'; manifest-src 'none'";

async fn security_headers(request: Request, next: Next) -> Response {
    let clear_site_data = request.uri().path() == "/v1/account/logout";
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, max-age=0, must-revalidate"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(header::EXPIRES, HeaderValue::from_static("0"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(
            "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), interest-cohort=()",
        ),
    );
    headers.insert(
        header::HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        header::HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("cross-origin"),
    );
    headers.insert(
        header::HeaderName::from_static("x-permitted-cross-domain-policies"),
        HeaderValue::from_static("none"),
    );
    headers.insert(
        header::HeaderName::from_static("x-robots-tag"),
        HeaderValue::from_static("noindex, noarchive, nosnippet"),
    );
    if clear_site_data {
        headers.insert(
            header::HeaderName::from_static("clear-site-data"),
            HeaderValue::from_static("\"cache\", \"cookies\", \"storage\""),
        );
    }
    response
}

fn derive_code_id(pepper: &[u8], code: &str) -> CodeId {
    let mut mac = HmacSha256::new_from_slice(pepper).expect("HMAC accepts any key length");
    mac.update(CODE_ID_DOMAIN);
    mac.update(code.as_bytes());
    mac.finalize().into_bytes().into()
}

fn generate_codes(
    codes: &mut HashSet<String>,
    generated_lengths: &mut HashSet<usize>,
    count: usize,
    min_len: usize,
    max_len: usize,
) {
    let mut rng = OsRng;
    for _ in 0..count {
        loop {
            let len = next_unique_length(&mut rng, generated_lengths, min_len, max_len);
            let code = generate_code(&mut rng, len);
            if codes.insert(code) {
                break;
            }
        }
    }
}

fn next_unique_length(
    rng: &mut OsRng,
    generated_lengths: &mut HashSet<usize>,
    min_len: usize,
    max_len: usize,
) -> usize {
    let available = (min_len..=max_len)
        .filter(|len| !generated_lengths.contains(len))
        .collect::<Vec<_>>();
    let len = if available.is_empty() {
        max_len + generated_lengths.len() + 1
    } else {
        available[rng.gen_range(0..available.len())]
    };
    generated_lengths.insert(len);
    len
}

fn generate_code(rng: &mut OsRng, len: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let dash_count = if len >= 16 { 2 } else { 1 };
    let char_count = len - dash_count;
    let mut raw = String::with_capacity(char_count);
    for _ in 0..char_count {
        let idx = rng.gen_range(0..ALPHABET.len());
        raw.push(ALPHABET[idx] as char);
    }

    let first_dash = char_count / 3;
    let second_dash = (char_count * 2) / 3;
    let mut out = String::with_capacity(len);
    for (idx, ch) in raw.chars().enumerate() {
        if idx == first_dash || (dash_count == 2 && idx == second_dash) {
            out.push('-');
        }
        out.push(ch);
    }
    out
}

fn normalize_code(code: &str) -> Result<String, String> {
    let normalized = code.trim().to_ascii_uppercase();
    if !valid_code_shape(&normalized) {
        return Err(
            "Code must be at least 12 characters and contain only letters, numbers, and dashes."
                .to_string(),
        );
    }
    Ok(normalized)
}

fn valid_code_shape(code: &str) -> bool {
    code.len() >= 12
        && code.len() <= MAX_CODE_BYTES
        && !code.starts_with('-')
        && !code.ends_with('-')
        && code.chars().any(|ch| ch.is_ascii_alphanumeric())
        && code
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
}

fn record_rate_attempt(state: &mut RateState, now: u64, window_ms: u64, limit: usize) -> bool {
    if now.saturating_sub(state.window_start_ms) >= window_ms {
        state.window_start_ms = now;
        state.count = 0;
        state.bytes = 0;
    }
    state.count = state.count.saturating_add(1);
    state.count <= limit
}

async fn login_attempt_allowed(state: &AppState, code_id: &CodeId) -> bool {
    let now = now_ms();
    let mut limits = state.login_limits.lock().await;
    let rate = limits.entry(*code_id).or_insert(RateState {
        window_start_ms: now,
        count: 0,
        bytes: 0,
    });
    record_rate_attempt(
        rate,
        now,
        LOGIN_RATE_WINDOW_MS,
        LOGIN_MAX_ATTEMPTS_PER_WINDOW,
    )
}

async fn clear_login_limit(state: &AppState, code_id: &CodeId) {
    state.login_limits.lock().await.remove(code_id);
}

fn random_username() -> String {
    const PREFIXES: &[&str] = &[
        "Silent",
        "Nebula",
        "Quantum",
        "Vortex",
        "Solar",
        "Cosmic",
        "Lunar",
        "Alpha",
        "Shadow",
        "Ghost",
        "Starlight",
        "Obsidian",
        "Frozen",
        "Electric",
    ];
    const SUFFIXES: &[&str] = &[
        "Wolf", "Tiger", "Fox", "Eagle", "Falcon", "Leopard", "Spectre", "Titan", "Node", "Warp",
        "Core", "Entity", "Daemon", "Vector",
    ];
    let mut rng = OsRng;
    let prefix = PREFIXES[rng.gen_range(0..PREFIXES.len())];
    let suffix = SUFFIXES[rng.gen_range(0..SUFFIXES.len())];
    let number = rng.gen_range(100..1000);
    format!("{prefix}{suffix}{number}")
}

fn random_unique_username(accounts: &HashMap<CodeId, Account>) -> String {
    for _ in 0..128 {
        let candidate = random_username();
        if accounts
            .values()
            .all(|account| account.username != candidate)
        {
            return candidate;
        }
    }

    loop {
        let candidate = format!("Abyssal{}", Uuid::new_v4().simple());
        if accounts
            .values()
            .all(|account| account.username != candidate)
        {
            return candidate;
        }
    }
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        node_id: state.node_id.clone(),
        storage: "ram-only",
        available_codes: state.available_codes.lock().await.len(),
        accounts: state.accounts.lock().await.len(),
        max_rooms_per_user: state.max_rooms_per_user,
        session_inactivity_sec: state.session_inactivity_ms / 1000,
    })
}

async fn attachment_sweeper(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
    loop {
        interval.tick().await;
        prune_expired_attachments(&state).await;
    }
}

async fn prune_expired_attachments(state: &AppState) {
    let now = now_ms();
    let mut attachments = state.attachments.lock().await;
    let before = attachments.len();
    attachments.retain(|_, record| record.expires_at_ms.is_none_or(|expires| now < expires));
    let removed = before.saturating_sub(attachments.len());
    if removed > 0 {
        info!("expired_attachments_removed count={removed}");
    }
}

async fn session_sweeper(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let now = now_ms();
        let mut sessions = state.sessions.lock().await;
        let before = sessions.len();
        sessions
            .retain(|_, session| !session_is_expired(session, now, state.session_inactivity_ms));
        let removed = before.saturating_sub(sessions.len());
        if removed > 0 {
            info!("expired_sessions_removed count={removed}");
        }
        state
            .prekey_claims
            .lock()
            .await
            .retain(|_, claim| now.saturating_sub(claim.created_at_ms) < PREKEY_CLAIM_TTL_MS);
    }
}

fn session_is_expired(session: &AuthSession, now: u64, inactivity_limit_ms: u64) -> bool {
    now.saturating_sub(session.last_activity_ms) >= inactivity_limit_ms
}

async fn active_session(state: &AppState, token: &str, touch: bool) -> Option<AuthSession> {
    let now = now_ms();
    let mut sessions = state.sessions.lock().await;
    let expired = sessions
        .get(token)
        .is_some_and(|session| session_is_expired(session, now, state.session_inactivity_ms));
    if expired {
        sessions.remove(token);
        return None;
    }

    let session = sessions.get_mut(token)?;
    if touch {
        session.last_activity_ms = now;
    }
    Some(session.clone())
}

async fn code_has_active_session(state: &AppState, code_id: &CodeId) -> bool {
    let now = now_ms();
    let mut sessions = state.sessions.lock().await;
    sessions.retain(|_, session| !session_is_expired(session, now, state.session_inactivity_ms));
    sessions.values().any(|session| session.code_id == *code_id)
}

fn normalize_media_type(media_type: Option<&str>) -> String {
    match media_type
        .unwrap_or("FILE")
        .trim()
        .to_ascii_uppercase()
        .as_str()
    {
        "IMAGE" => "IMAGE".to_string(),
        "VIDEO" => "VIDEO".to_string(),
        _ => "FILE".to_string(),
    }
}

fn encrypted_attachment_limit_bytes(media_type: &str) -> usize {
    let plain_limit = match media_type {
        "IMAGE" => IMAGE_ATTACHMENT_LIMIT_BYTES,
        "VIDEO" => VIDEO_ATTACHMENT_LIMIT_BYTES,
        _ => FILE_ATTACHMENT_LIMIT_BYTES,
    };
    plain_limit + ENCRYPTION_OVERHEAD_BYTES
}

fn valid_chat_id(chat_id: &str) -> bool {
    !chat_id.is_empty()
        && chat_id.len() <= MAX_CHAT_ID_BYTES
        && chat_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

async fn conversation_access(
    state: &AppState,
    username: &str,
    chat_id: &str,
) -> Option<ConversationAccess> {
    if !valid_chat_id(chat_id) {
        return None;
    }
    if let Some(room) = state
        .room_catalog
        .lock()
        .await
        .get(chat_id)
        .map(|entry| entry.room.clone())
    {
        return Some(ConversationAccess::Room(room));
    }
    state
        .direct_catalog
        .lock()
        .await
        .get(chat_id)
        .filter(|direct| direct.user_a == username || direct.user_b == username)
        .map(|_| ConversationAccess::Direct)
}

fn room_allows_media(room: &RoomRecord, media_type: &str) -> bool {
    match media_type {
        "IMAGE" => room.allow_images,
        "VIDEO" => room.allow_videos,
        _ => room.allow_files,
    }
}

fn enforced_attachment_ttl_sec(room: &RoomRecord, media_type: &str) -> u64 {
    let room_ttl = room
        .enforce_text_absolute_expiry
        .then_some(room.overall_expiry_sec)
        .filter(|ttl| *ttl > 0);
    let media_ttl = match media_type {
        "IMAGE" if room.enforce_image_absolute_expiry => room.image_overall_expiry_sec,
        "VIDEO" if room.enforce_video_absolute_expiry => room.video_overall_expiry_sec,
        "FILE" if room.enforce_file_absolute_expiry => room.file_overall_expiry_sec,
        _ => 0,
    };
    room_ttl
        .into_iter()
        .chain((media_ttl > 0).then_some(media_ttl))
        .min()
        .unwrap_or(0)
}

fn effective_attachment_ttl_sec(
    requested: Option<u64>,
    access: &ConversationAccess,
    media_type: &str,
) -> u64 {
    let requested = requested.unwrap_or_default().min(86_400);
    let ConversationAccess::Room(room) = access else {
        return requested;
    };
    let enforced = enforced_attachment_ttl_sec(room, media_type);
    match (requested, enforced) {
        (0, enforced) => enforced,
        (requested, 0) => requested,
        (requested, enforced) => requested.min(enforced),
    }
}

fn current_attachment_bytes(attachments: &HashMap<Uuid, AttachmentRecord>) -> usize {
    attachments
        .values()
        .map(|record| record.encrypted_bytes.len())
        .sum()
}

async fn touch_activity(state: &AppState) {
    *state.last_activity_ms.lock().await = now_ms();
}

async fn inactivity_watcher(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        interval.tick().await;
        let Some(limit_ms) = state.inactivity_limit_ms else {
            return;
        };
        let last_activity = *state.last_activity_ms.lock().await;
        let idle_ms = now_ms().saturating_sub(last_activity);
        if idle_ms >= limit_ms {
            warn!(
                "dead_man_switch_triggered idle_ms={} limit_ms={}",
                idle_ms, limit_ms
            );
            wipe_relay_state(&state, true).await;
            touch_activity(&state).await;
        }
    }
}

async fn start_opaque_account(
    State(state): State<AppState>,
    Json(request): Json<OpaqueAccountStartRequest>,
) -> impl IntoResponse {
    touch_activity(&state).await;
    let _account_guard = state.account_ops.lock().await;
    prune_opaque_handshakes(&state).await;
    let code = match normalize_code(&request.code) {
        Ok(code) => Zeroizing::new(code),
        Err(_) => return opaque_start_error(StatusCode::BAD_REQUEST, &state),
    };
    let code_id = derive_code_id(&state.invite_code_pepper[..], &code);
    if !login_attempt_allowed(&state, &code_id).await {
        return opaque_start_error(StatusCode::TOO_MANY_REQUESTS, &state);
    }
    if code_has_active_session(&state, &code_id).await {
        return opaque_start_error(StatusCode::CONFLICT, &state);
    }

    let handshake_id = Uuid::new_v4();
    if let Some(account) = state.accounts.lock().await.get(&code_id).cloned() {
        let request_bytes =
            match decode_bounded(&request.credential_request_b64, ACCOUNT_BODY_LIMIT_BYTES) {
                Ok(bytes) => bytes,
                Err(_) => return opaque_start_error(StatusCode::BAD_REQUEST, &state),
            };
        let (server_state, response) = match opaque_server_start_login(
            &state.opaque_setup,
            &account.password_file,
            &request_bytes,
            code.as_bytes(),
        ) {
            Ok(result) => result,
            Err(_) => return opaque_start_error(StatusCode::UNAUTHORIZED, &state),
        };
        state.opaque_handshakes.lock().await.insert(
            handshake_id,
            OpaqueHandshake::Login {
                code_id,
                username: account.username.clone(),
                server_state,
                created_at_ms: now_ms(),
            },
        );
        return (
            StatusCode::OK,
            Json(OpaqueAccountStartResponse {
                accepted: true,
                mode: Some("login"),
                handshake_id: Some(handshake_id),
                response_b64: Some(URL_SAFE_NO_PAD.encode(response)),
                node_id: state.node_id.clone(),
                identity_public_b64: Some(URL_SAFE_NO_PAD.encode(&account.identity_public)),
                identity_prekey_id: Some(account.prekey_id.clone()),
                identity_envelope_b64: Some(URL_SAFE_NO_PAD.encode(&account.identity_envelope)),
                error: None,
            }),
        );
    }

    if !state.available_codes.lock().await.contains(&code_id) {
        return opaque_start_error(StatusCode::UNAUTHORIZED, &state);
    }
    let request_bytes =
        match decode_bounded(&request.registration_request_b64, ACCOUNT_BODY_LIMIT_BYTES) {
            Ok(bytes) => bytes,
            Err(_) => return opaque_start_error(StatusCode::BAD_REQUEST, &state),
        };
    let response = match opaque_server_registration_response(
        &state.opaque_setup,
        &request_bytes,
        code.as_bytes(),
    ) {
        Ok(response) => response,
        Err(_) => return opaque_start_error(StatusCode::UNAUTHORIZED, &state),
    };
    state.opaque_handshakes.lock().await.insert(
        handshake_id,
        OpaqueHandshake::Registration {
            code_id,
            created_at_ms: now_ms(),
        },
    );
    (
        StatusCode::OK,
        Json(OpaqueAccountStartResponse {
            accepted: true,
            mode: Some("registration"),
            handshake_id: Some(handshake_id),
            response_b64: Some(URL_SAFE_NO_PAD.encode(response)),
            node_id: state.node_id.clone(),
            identity_public_b64: None,
            identity_prekey_id: None,
            identity_envelope_b64: None,
            error: None,
        }),
    )
}

async fn finish_opaque_account(
    State(state): State<AppState>,
    Json(request): Json<OpaqueAccountFinishRequest>,
) -> impl IntoResponse {
    touch_activity(&state).await;
    let _account_guard = state.account_ops.lock().await;
    prune_opaque_handshakes(&state).await;
    let Some(handshake) = state
        .opaque_handshakes
        .lock()
        .await
        .remove(&request.handshake_id)
    else {
        return account_error(StatusCode::UNAUTHORIZED, &state, String::new()).await;
    };

    match &handshake {
        OpaqueHandshake::Registration { code_id, .. } => {
            if state.accounts.lock().await.contains_key(code_id)
                || !state.available_codes.lock().await.contains(code_id)
            {
                return account_error(StatusCode::CONFLICT, &state, String::new()).await;
            }
            let upload = match request
                .registration_upload_b64
                .as_deref()
                .ok_or(())
                .and_then(|value| decode_bounded(value, ACCOUNT_BODY_LIMIT_BYTES).map_err(|_| ()))
            {
                Ok(value) => value,
                Err(_) => {
                    return account_error(StatusCode::BAD_REQUEST, &state, String::new()).await
                }
            };
            let identity_public = match request
                .identity_public_b64
                .as_deref()
                .ok_or(())
                .and_then(|value| decode_exact(value, IDENTITY_PUBLIC_BYTES).map_err(|_| ()))
            {
                Ok(value) => value,
                Err(_) => {
                    return account_error(StatusCode::BAD_REQUEST, &state, String::new()).await
                }
            };
            let prekey_id = match request.identity_prekey_id.as_deref() {
                Some(value) if valid_prekey_id(value) => value.to_string(),
                _ => return account_error(StatusCode::BAD_REQUEST, &state, String::new()).await,
            };
            if !valid_identity_public_bundle(&identity_public, &prekey_id) {
                return account_error(StatusCode::BAD_REQUEST, &state, String::new()).await;
            }
            let identity_envelope = match request
                .identity_envelope_b64
                .as_deref()
                .ok_or(())
                .and_then(|value| {
                    decode_bounded(value, MAX_IDENTITY_ENVELOPE_BYTES).map_err(|_| ())
                }) {
                Ok(value) if !value.is_empty() => value,
                _ => return account_error(StatusCode::BAD_REQUEST, &state, String::new()).await,
            };
            let password_file = match opaque_server_finish_registration(&upload) {
                Ok(value) => value,
                Err(_) => {
                    return account_error(StatusCode::UNAUTHORIZED, &state, String::new()).await
                }
            };
            state.available_codes.lock().await.remove(code_id);
            let mut accounts = state.accounts.lock().await;
            let username = random_unique_username(&accounts);
            accounts.insert(
                *code_id,
                Account {
                    username: username.clone(),
                    password_file,
                    identity_public,
                    identity_envelope,
                    prekey_id,
                    state_revision: 0,
                    state_revision_window: 1,
                    connected: false,
                },
            );
            drop(accounts);
            clear_login_limit(&state, code_id).await;
            info!("opaque_account_created");
            issue_session(&state, *code_id, username, true).await
        }
        OpaqueHandshake::Login {
            code_id,
            username,
            server_state,
            ..
        } => {
            let finalization = match request
                .credential_finalization_b64
                .as_deref()
                .ok_or(())
                .and_then(|value| decode_bounded(value, ACCOUNT_BODY_LIMIT_BYTES).map_err(|_| ()))
            {
                Ok(value) => value,
                Err(_) => {
                    return account_error(StatusCode::BAD_REQUEST, &state, String::new()).await
                }
            };
            if opaque_server_finish_login(server_state, &finalization).is_err() {
                return account_error(StatusCode::UNAUTHORIZED, &state, String::new()).await;
            }
            if code_has_active_session(&state, code_id).await {
                return account_error(StatusCode::CONFLICT, &state, String::new()).await;
            }
            clear_login_limit(&state, code_id).await;
            info!("opaque_account_login");
            issue_session(&state, *code_id, username.clone(), false).await
        }
    }
}

fn opaque_start_error(
    status: StatusCode,
    state: &AppState,
) -> (StatusCode, Json<OpaqueAccountStartResponse>) {
    (
        status,
        Json(OpaqueAccountStartResponse {
            accepted: false,
            mode: None,
            handshake_id: None,
            response_b64: None,
            node_id: state.node_id.clone(),
            identity_public_b64: None,
            identity_prekey_id: None,
            identity_envelope_b64: None,
            error: Some("Wrong information."),
        }),
    )
}

async fn prune_opaque_handshakes(state: &AppState) {
    let now = now_ms();
    state.opaque_handshakes.lock().await.retain(|_, handshake| {
        let created_at_ms = match handshake {
            OpaqueHandshake::Registration { created_at_ms, .. }
            | OpaqueHandshake::Login { created_at_ms, .. } => *created_at_ms,
        };
        now.saturating_sub(created_at_ms) < OPAQUE_HANDSHAKE_TTL_MS
    });
}

fn decode_bounded(value: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
    if value.is_empty() || value.len() > max_bytes.saturating_mul(2) {
        return Err("Wrong information".to_string());
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "Wrong information".to_string())?;
    if bytes.is_empty() || bytes.len() > max_bytes {
        return Err("Wrong information".to_string());
    }
    Ok(bytes)
}

fn decode_exact(value: &str, expected_bytes: usize) -> Result<Vec<u8>, String> {
    let bytes = decode_bounded(value, expected_bytes)?;
    (bytes.len() == expected_bytes)
        .then_some(bytes)
        .ok_or_else(|| "Wrong information".to_string())
}

fn valid_prekey_id(value: &str) -> bool {
    value.len() <= MAX_PREKEY_ID_BYTES
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn valid_identity_public_bundle(public_key: &[u8], prekey_id: &str) -> bool {
    if public_key.len() != IDENTITY_PUBLIC_BYTES || !valid_prekey_id(prekey_id) {
        return false;
    }
    let long_term = &public_key[..IDENTITY_FINGERPRINT_BYTES];
    if long_term.iter().all(|byte| *byte == 0) {
        return false;
    }
    let one_time = &public_key[ONE_TIME_KEY_OFFSET..FALLBACK_KEY_OFFSET];
    if prekey_id.is_empty() {
        one_time.iter().all(|byte| *byte == 0)
    } else {
        one_time.iter().any(|byte| *byte != 0)
            && one_time
                .try_into()
                .map(|public| prekey_id_for_public(public) == prekey_id)
                .unwrap_or(false)
    }
}

async fn replace_connected_clients_for_code(state: &AppState, code_id: &CodeId) {
    let old_clients = state
        .clients
        .lock()
        .await
        .iter()
        .filter_map(|(client_id, client)| {
            if client.code_id == *code_id {
                Some((*client_id, client.tx.clone()))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    if old_clients.is_empty() {
        return;
    }

    for (_, tx) in &old_clients {
        let _ = tx.try_send(Message::Close(None));
    }

    let old_ids = old_clients
        .iter()
        .map(|(client_id, _)| *client_id)
        .collect::<HashSet<_>>();
    state
        .clients
        .lock()
        .await
        .retain(|client_id, _| !old_ids.contains(client_id));
    state
        .frame_limits
        .lock()
        .await
        .retain(|client_id, _| !old_ids.contains(client_id));
    for members in state.rooms.lock().await.values_mut() {
        members.retain(|client_id| !old_ids.contains(client_id));
    }
    if let Some(account) = state.accounts.lock().await.get_mut(code_id) {
        account.connected = false;
    }
    state.active_connections.lock().await.remove(code_id);
    broadcast_presence(state).await;
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(ToOwned::to_owned)
}

async fn auth_from_headers(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthSession, StatusCode> {
    let token = bearer_token(headers).ok_or(StatusCode::UNAUTHORIZED)?;
    active_session(state, &token, true)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)
}

async fn logout_account(State(state): State<AppState>, headers: HeaderMap) -> StatusCode {
    let Some(token) = bearer_token(&headers) else {
        return StatusCode::UNAUTHORIZED;
    };
    let session = state.sessions.lock().await.remove(&token);
    let Some(session) = session else {
        return StatusCode::UNAUTHORIZED;
    };

    replace_connected_clients_for_code(&state, &session.code_id).await;
    touch_activity(&state).await;
    StatusCode::NO_CONTENT
}

async fn upload_attachment(
    State(state): State<AppState>,
    Query(query): Query<AttachmentQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let auth = match auth_from_headers(&state, &headers).await {
        Ok(auth) => auth,
        Err(status) => return status.into_response(),
    };
    touch_activity(&state).await;
    let chat_id = query.chat_id.trim();
    if !valid_chat_id(chat_id) || body.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let media_type = normalize_media_type(query.media_type.as_deref());
    let Some(access) = conversation_access(&state, &auth.username, chat_id).await else {
        return StatusCode::FORBIDDEN.into_response();
    };
    if matches!(&access, ConversationAccess::Room(room) if !room_allows_media(room, &media_type)) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let max_bytes = encrypted_attachment_limit_bytes(&media_type);
    if body.len() > max_bytes {
        warn!(
            "attachment_upload_rejected chat_id={} media_type={} reason=size bytes={} max={}",
            chat_id,
            media_type,
            body.len(),
            max_bytes
        );
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }

    let id = Uuid::new_v4();
    let ttl_ms = effective_attachment_ttl_sec(query.ttl_sec, &access, &media_type);
    let ttl_ms = (ttl_ms > 0).then(|| now_ms().saturating_add(ttl_ms.saturating_mul(1000)));
    let one_time = query.one_time.unwrap_or(false);
    prune_expired_attachments(&state).await;
    let mut attachments = state.attachments.lock().await;
    let used_bytes = current_attachment_bytes(&attachments);
    if used_bytes.saturating_add(body.len()) > state.attachment_ram_limit_bytes {
        warn!(
            "attachment_upload_rejected chat_id={} media_type={} reason=ram_limit used={} incoming={} limit={}",
            chat_id,
            media_type,
            used_bytes,
            body.len(),
            state.attachment_ram_limit_bytes
        );
        return StatusCode::from_u16(507)
            .unwrap_or(StatusCode::SERVICE_UNAVAILABLE)
            .into_response();
    }
    attachments.insert(
        id,
        AttachmentRecord {
            encrypted_bytes: body.to_vec(),
            chat_id: chat_id.to_string(),
            media_type,
            one_time,
            delete_after_download: query.delete_after_download.unwrap_or(one_time),
            expires_at_ms: ttl_ms,
        },
    );
    drop(attachments);

    Json(serde_json::json!({
        "accepted": true,
        "attachment_id": id,
        "storage": "ram-only"
    }))
    .into_response()
}

async fn download_attachment(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = match auth_from_headers(&state, &headers).await {
        Ok(auth) => auth,
        Err(status) => return status.into_response(),
    };
    touch_activity(&state).await;

    let chat_id = {
        let attachments = state.attachments.lock().await;
        let Some(record) = attachments.get(&id) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        record.chat_id.clone()
    };
    if conversation_access(&state, &auth.username, &chat_id)
        .await
        .is_none()
    {
        return StatusCode::FORBIDDEN.into_response();
    }

    let mut attachments = state.attachments.lock().await;
    let Some(record) = attachments.get(&id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if record
        .expires_at_ms
        .is_some_and(|expires| now_ms() >= expires)
    {
        attachments.remove(&id);
        return StatusCode::NOT_FOUND.into_response();
    }

    let bytes = record.encrypted_bytes.clone();
    let media_type = record.media_type.clone();
    if record.one_time || record.delete_after_download {
        attachments.remove(&id);
    }
    info!(
        "attachment_downloaded id={} media_type={} bytes={}",
        id,
        media_type,
        bytes.len()
    );

    let mut response = bytes.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response
}

async fn account_error(
    status: StatusCode,
    state: &AppState,
    _error: String,
) -> (StatusCode, Json<AccountResponse>) {
    (
        status,
        Json(AccountResponse {
            accepted: false,
            created: false,
            token: None,
            node_id: state.node_id.clone(),
            username: None,
            max_rooms_per_user: state.max_rooms_per_user,
            session_inactivity_sec: state.session_inactivity_ms / 1000,
            identity_public_b64: None,
            identity_prekey_id: None,
            identity_envelope_b64: None,
            error: Some("Wrong information.".to_string()),
        }),
    )
}

async fn issue_session(
    state: &AppState,
    code_id: CodeId,
    username: String,
    created: bool,
) -> (StatusCode, Json<AccountResponse>) {
    let account_identity = state.accounts.lock().await.get(&code_id).map(|account| {
        (
            URL_SAFE_NO_PAD.encode(&account.identity_public),
            account.prekey_id.clone(),
            URL_SAFE_NO_PAD.encode(&account.identity_envelope),
        )
    });
    let Some((identity_public_b64, identity_prekey_id, identity_envelope_b64)) = account_identity
    else {
        return account_error(StatusCode::UNAUTHORIZED, state, String::new()).await;
    };
    let token = Uuid::new_v4().to_string();
    let now = now_ms();
    let mut sessions = state.sessions.lock().await;
    sessions.retain(|_, session| session.code_id != code_id);
    sessions.insert(
        token.clone(),
        AuthSession {
            code_id,
            username: username.clone(),
            last_activity_ms: now,
        },
    );
    drop(sessions);

    (
        StatusCode::OK,
        Json(AccountResponse {
            accepted: true,
            created,
            token: Some(token),
            node_id: state.node_id.clone(),
            username: Some(username),
            max_rooms_per_user: state.max_rooms_per_user,
            session_inactivity_sec: state.session_inactivity_ms / 1000,
            identity_public_b64: Some(identity_public_b64),
            identity_prekey_id: Some(identity_prekey_id),
            identity_envelope_b64: Some(identity_envelope_b64),
            error: None,
        }),
    )
}

async fn ws_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    if !websocket_origin_allowed(&headers, &state.web_origins) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(token) = websocket_protocol_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let auth = active_session(&state, &token, true).await;

    match auth {
        Some(session) => {
            let client_id = Uuid::new_v4();
            let code_id = session.code_id;
            if state
                .active_connections
                .lock()
                .await
                .insert(code_id, client_id)
                .is_some()
            {
                return StatusCode::CONFLICT.into_response();
            }
            let failed_state = state.clone();
            ws.protocols([WEB_SOCKET_PROTOCOL])
                .on_failed_upgrade(move |_| {
                    tokio::spawn(async move {
                        release_connection_reservation(&failed_state, &code_id, client_id).await;
                    });
                })
                .on_upgrade(move |socket| socket_loop(state, token, session, client_id, socket))
                .into_response()
        }
        None => StatusCode::UNAUTHORIZED.into_response(),
    }
}

fn websocket_protocol_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::SEC_WEBSOCKET_PROTOCOL)?
        .to_str()
        .ok()?
        .split(',')
        .map(str::trim)
        .find_map(|protocol| protocol.strip_prefix("bearer."))
        .filter(|token| !token.is_empty() && token.len() <= 128)
        .map(ToOwned::to_owned)
}

fn websocket_origin_allowed(headers: &HeaderMap, allowed_origins: &[String]) -> bool {
    let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return true;
    };
    let Ok(uri) = origin.parse::<Uri>() else {
        return false;
    };
    let Some(origin_authority) = uri.authority().map(|value| value.as_str()) else {
        return false;
    };
    let same_host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|host| host.eq_ignore_ascii_case(origin_authority));
    same_host
        || allowed_origins
            .iter()
            .any(|allowed| allowed == origin.trim_end_matches('/'))
}

async fn socket_loop(
    state: AppState,
    session_token: String,
    auth: AuthSession,
    client_id: Uuid,
    socket: WebSocket,
) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::channel::<Message>(CLIENT_OUTBOUND_QUEUE_CAPACITY);

    state.clients.lock().await.insert(
        client_id,
        ClientHandle {
            code_id: auth.code_id,
            username: auth.username.clone(),
            tx,
        },
    );
    if let Some(account) = state.accounts.lock().await.get_mut(&auth.code_id) {
        account.connected = true;
    }
    info!("client_connected id={client_id}");
    broadcast_presence(&state).await;
    send_room_catalog(&state, client_id).await;
    send_direct_catalog(&state, client_id, &auth.username).await;

    let writer = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            if sink.send(message).await.is_err() {
                break;
            }
        }
    });

    let mut session_watchdog = tokio::time::interval(std::time::Duration::from_secs(1));
    session_watchdog.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = session_watchdog.tick() => {
                if active_session(&state, &session_token, false).await.is_none() {
                    break;
                }
            }
            result = stream.next() => {
                match result {
                    Some(Ok(Message::Text(text))) => {
                        if active_session(&state, &session_token, true).await.is_none() {
                            break;
                        }
                        if let Err(err) = check_ws_frame_allowed(&state, client_id, text.len()).await {
                            warn!("dropping limited frame from {client_id}: {err}");
                            continue;
                        }
                        if let Err(err) = handle_frame(&state, client_id, &text).await {
                            warn!("dropping invalid frame from {client_id}: {err}");
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {}
                    Some(Err(err)) => {
                        warn!("websocket error from {client_id}: {err}");
                        break;
                    }
                }
            }
        }
    }

    cleanup_client(&state, client_id).await;
    writer.abort();
}

async fn check_ws_frame_allowed(
    state: &AppState,
    client_id: Uuid,
    frame_bytes: usize,
) -> Result<(), String> {
    if frame_bytes > WS_MAX_FRAME_BYTES {
        return Err(format!(
            "frame too large: bytes={} max={}",
            frame_bytes, WS_MAX_FRAME_BYTES
        ));
    }

    let now = now_ms();
    let mut limits = state.frame_limits.lock().await;
    let state = limits.entry(client_id).or_insert(RateState {
        window_start_ms: now,
        count: 0,
        bytes: 0,
    });
    if !record_rate_attempt(state, now, WS_RATE_WINDOW_MS, WS_MAX_FRAMES_PER_WINDOW) {
        return Err(format!(
            "rate limit exceeded: count={} window_ms={}",
            state.count, WS_RATE_WINDOW_MS
        ));
    }
    state.bytes = state
        .bytes
        .checked_add(frame_bytes)
        .ok_or_else(|| "frame byte rate rejected".to_string())?;
    if state.bytes > WS_MAX_BYTES_PER_WINDOW {
        return Err(format!(
            "byte rate limit exceeded: bytes={} window_ms={}",
            state.bytes, WS_RATE_WINDOW_MS
        ));
    }
    Ok(())
}

async fn handle_frame(state: &AppState, sender_id: Uuid, text: &str) -> Result<(), String> {
    let frame: InboundFrame = serde_json::from_str(text).map_err(|err| err.to_string())?;
    match frame {
        InboundFrame::Activity => {
            touch_activity(state).await;
            Ok(())
        }
        InboundFrame::Dummy { padding_b64, bytes } => {
            let _discarded_hint =
                padding_b64.as_deref().map(str::len).unwrap_or(0) + bytes.unwrap_or_default();
            Ok(())
        }
        InboundFrame::Join { chat_id } => {
            touch_activity(state).await;
            join_room(state, sender_id, chat_id).await
        }
        InboundFrame::Leave { chat_id } => {
            touch_activity(state).await;
            leave_room(state, sender_id, &chat_id).await
        }
        InboundFrame::Message {
            chat_id,
            version,
            message_id,
            nonce_b64,
            ciphertext_b64,
            signature_b64,
            envelopes,
            state_revision,
            identity_envelope_b64,
            identity_public_b64,
            prekey_id,
        } => {
            touch_activity(state).await;
            route_encrypted_message(
                state,
                sender_id,
                chat_id,
                version,
                message_id,
                nonce_b64,
                ciphertext_b64,
                signature_b64,
                envelopes,
                state_revision,
                identity_envelope_b64,
                identity_public_b64,
                prekey_id,
            )
            .await
        }
        InboundFrame::MessageAck {
            chat_id,
            message_id,
            sender_username,
            state_revision,
            identity_envelope_b64,
            identity_public_b64,
            prekey_id,
            used_prekey_id,
        } => {
            touch_activity(state).await;
            acknowledge_message(
                state,
                sender_id,
                &chat_id,
                &message_id,
                &sender_username,
                state_revision,
                &identity_envelope_b64,
                &identity_public_b64,
                &prekey_id,
                &used_prekey_id,
            )
            .await
        }
        InboundFrame::IdentityState {
            state_revision,
            identity_envelope_b64,
            identity_public_b64,
            prekey_id,
        } => {
            touch_activity(state).await;
            update_identity_state(
                state,
                sender_id,
                state_revision,
                &identity_envelope_b64,
                &identity_public_b64,
                &prekey_id,
            )
            .await
        }
        InboundFrame::GlobalWipe => {
            touch_activity(state).await;
            broadcast_wipe(state, sender_id).await
        }
        InboundFrame::CreateRoom { room } => {
            touch_activity(state).await;
            create_room(state, sender_id, room).await
        }
        InboundFrame::DeleteRoom { chat_id } => {
            touch_activity(state).await;
            delete_room(state, sender_id, &chat_id).await
        }
        InboundFrame::OpenDirect { peer_username } => {
            touch_activity(state).await;
            open_direct(state, sender_id, &peer_username).await
        }
    }
}

async fn join_room(state: &AppState, client_id: Uuid, chat_id: String) -> Result<(), String> {
    let (_, username) = client_identity(state, client_id).await?;
    if conversation_access(state, &username, &chat_id)
        .await
        .is_none()
    {
        return Err("conversation unavailable".to_string());
    }
    state
        .rooms
        .lock()
        .await
        .entry(chat_id.clone())
        .or_default()
        .insert(client_id);

    let pending = state
        .pending
        .lock()
        .await
        .get(&PendingKey {
            chat_id,
            recipient_username: username,
        })
        .cloned()
        .unwrap_or_default();
    for frame in pending {
        send_to_client(state, client_id, &frame).await;
    }
    Ok(())
}

async fn leave_room(state: &AppState, client_id: Uuid, chat_id: &str) -> Result<(), String> {
    if let Some(members) = state.rooms.lock().await.get_mut(chat_id) {
        members.remove(&client_id);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn route_encrypted_message(
    state: &AppState,
    sender_id: Uuid,
    chat_id: String,
    version: u32,
    message_id: String,
    nonce_b64: String,
    ciphertext_b64: String,
    signature_b64: String,
    envelopes: Vec<InboundRecipientEnvelope>,
    state_revision: u64,
    identity_envelope_b64: String,
    identity_public_b64: String,
    prekey_id: String,
) -> Result<(), String> {
    if version != E2EE_PROTOCOL_VERSION || !valid_chat_id(&chat_id) || !valid_chat_id(&message_id) {
        return Err("encrypted message rejected".to_string());
    }
    decode_exact(&nonce_b64, MESSAGE_NONCE_BYTES)?;
    decode_exact(&signature_b64, MESSAGE_SIGNATURE_BYTES)?;
    decode_bounded(&ciphertext_b64, WS_MAX_FRAME_BYTES)?;

    decode_bounded(&identity_envelope_b64, MAX_IDENTITY_ENVELOPE_BYTES)?;

    let (sender_code_id, sender_username) = client_identity(state, sender_id).await?;
    let access = conversation_access(state, &sender_username, &chat_id)
        .await
        .ok_or_else(|| "conversation unavailable".to_string())?;
    let expected_recipients = match access {
        ConversationAccess::Room(_) => state
            .accounts
            .lock()
            .await
            .values()
            .map(|account| account.username.clone())
            .filter(|username| username != &sender_username)
            .collect::<HashSet<_>>(),
        ConversationAccess::Direct => {
            let peer = state
                .direct_catalog
                .lock()
                .await
                .get(&chat_id)
                .and_then(|direct| direct.peer_for(&sender_username))
                .ok_or_else(|| "direct conversation unavailable".to_string())?;
            HashSet::from([peer])
        }
    };

    if envelopes.len() != expected_recipients.len() {
        return Err("recipient envelope set rejected".to_string());
    }
    let mut envelope_map = HashMap::with_capacity(envelopes.len());
    for envelope in envelopes {
        if !expected_recipients.contains(&envelope.recipient_username)
            || envelope_map.contains_key(&envelope.recipient_username)
        {
            return Err("recipient envelope rejected".to_string());
        }
        if !valid_prekey_id(&envelope.prekey_id) {
            return Err("recipient envelope rejected".to_string());
        }
        if envelope.is_prekey == envelope.prekey_id.is_empty() {
            return Err("recipient envelope rejected".to_string());
        }
        let wrapped = decode_bounded(&envelope.wrapped_key_b64, MAX_WRAPPED_KEY_BYTES)?;
        if wrapped.is_empty() {
            return Err("recipient envelope rejected".to_string());
        }
        let recipient_username = envelope.recipient_username.clone();
        envelope_map.insert(recipient_username, envelope);
    }
    if envelope_map.keys().collect::<HashSet<_>>()
        != expected_recipients.iter().collect::<HashSet<_>>()
    {
        return Err("recipient envelope set rejected".to_string());
    }

    apply_identity_state(
        state,
        &sender_code_id,
        state_revision,
        &identity_envelope_b64,
        &identity_public_b64,
        &prekey_id,
        false,
    )
    .await?;
    claim_prekeys(
        state,
        &expected_recipients,
        &envelope_map,
        &chat_id,
        &message_id,
        &sender_username,
    )
    .await?;
    if let Err(error) = register_message_id(state, &chat_id, &sender_username, &message_id).await {
        release_prekey_claims(state, &chat_id, &message_id, &sender_username).await;
        return Err(error);
    }
    let sender_public_key_b64 = state
        .accounts
        .lock()
        .await
        .get(&sender_code_id)
        .map(|account| URL_SAFE_NO_PAD.encode(&account.identity_public))
        .ok_or_else(|| "authenticated identity required".to_string())?;

    let joined = state
        .rooms
        .lock()
        .await
        .get(&chat_id)
        .cloned()
        .unwrap_or_default();
    let clients = state.clients.lock().await.clone();
    for recipient_username in expected_recipients {
        let envelope = envelope_map
            .remove(&recipient_username)
            .ok_or_else(|| "recipient envelope rejected".to_string())?;
        let frame = OutboundFrame::Message {
            chat_id: chat_id.clone(),
            version,
            message_id: message_id.clone(),
            nonce_b64: nonce_b64.clone(),
            ciphertext_b64: ciphertext_b64.clone(),
            signature_b64: signature_b64.clone(),
            wrapped_key_b64: envelope.wrapped_key_b64,
            prekey_id: envelope.prekey_id,
            is_prekey: envelope.is_prekey,
            sender_username: sender_username.clone(),
            sender_public_key_b64: sender_public_key_b64.clone(),
        };
        let recipient_ids = clients
            .iter()
            .filter_map(|(client_id, client)| {
                (client.username == recipient_username && joined.contains(client_id))
                    .then_some(*client_id)
            })
            .collect::<Vec<_>>();
        queue_pending_frame(state, &chat_id, recipient_username, frame.clone()).await;
        if !recipient_ids.is_empty() {
            for recipient_id in recipient_ids {
                send_to_client(state, recipient_id, &frame).await;
            }
        }
    }
    Ok(())
}

async fn register_message_id(
    state: &AppState,
    chat_id: &str,
    sender_username: &str,
    message_id: &str,
) -> Result<(), String> {
    let now = now_ms();
    let mut replay_ids = state.replay_ids.lock().await;
    replay_ids.retain(|_, seen_at| now.saturating_sub(*seen_at) < REPLAY_WINDOW_MS);
    let key = ReplayKey {
        chat_id: chat_id.to_string(),
        sender_username: sender_username.to_string(),
        message_id: message_id.to_string(),
    };
    if replay_ids.contains_key(&key) {
        return Err("message replay rejected".to_string());
    }
    if replay_ids.len() >= MAX_REPLAY_IDS {
        if let Some(oldest) = replay_ids
            .iter()
            .min_by_key(|(_, seen_at)| **seen_at)
            .map(|(key, _)| key.clone())
        {
            replay_ids.remove(&oldest);
        }
    }
    replay_ids.insert(key, now);
    Ok(())
}

async fn claim_prekeys(
    state: &AppState,
    expected_recipients: &HashSet<String>,
    envelopes: &HashMap<String, InboundRecipientEnvelope>,
    chat_id: &str,
    message_id: &str,
    sender_username: &str,
) -> Result<(), String> {
    let accounts = state.accounts.lock().await;
    let mut claims_to_add = Vec::new();
    for username in expected_recipients {
        let Some(envelope) = envelopes.get(username) else {
            return Err("recipient envelope rejected".to_string());
        };
        if !envelope.is_prekey || envelope.prekey_id.is_empty() {
            continue;
        }
        let Some((code_id, account)) = accounts
            .iter()
            .find(|(_, account)| account.username == *username)
        else {
            return Err("recipient envelope rejected".to_string());
        };
        if account.prekey_id != envelope.prekey_id {
            return Err("recipient prekey unavailable".to_string());
        }
        claims_to_add.push((
            PrekeyClaimKey {
                code_id: *code_id,
                prekey_id: envelope.prekey_id.clone(),
            },
            PrekeyClaim {
                chat_id: chat_id.to_string(),
                message_id: message_id.to_string(),
                sender_username: sender_username.to_string(),
                created_at_ms: now_ms(),
            },
        ));
    }
    drop(accounts);

    let now = now_ms();
    let mut claims = state.prekey_claims.lock().await;
    claims.retain(|_, claim| now.saturating_sub(claim.created_at_ms) < PREKEY_CLAIM_TTL_MS);
    if claims_to_add
        .iter()
        .any(|(key, _)| claims.contains_key(key))
    {
        return Err("recipient prekey unavailable".to_string());
    }
    for (key, claim) in claims_to_add {
        claims.insert(key, claim);
    }
    Ok(())
}

async fn release_prekey_claims(
    state: &AppState,
    chat_id: &str,
    message_id: &str,
    sender_username: &str,
) {
    state.prekey_claims.lock().await.retain(|_, claim| {
        claim.chat_id != chat_id
            || claim.message_id != message_id
            || claim.sender_username != sender_username
    });
}

async fn queue_pending_frame(
    state: &AppState,
    chat_id: &str,
    recipient_username: String,
    frame: OutboundFrame,
) {
    let mut pending = state.pending.lock().await;
    let queue = pending
        .entry(PendingKey {
            chat_id: chat_id.to_string(),
            recipient_username,
        })
        .or_default();
    if queue.len() >= MAX_PENDING_FRAMES_PER_ROOM {
        let mut evicted = queue.remove(0);
        evicted.zeroize_sensitive();
    }
    queue.push(frame);
}

async fn update_identity_state(
    state: &AppState,
    sender_id: Uuid,
    revision: u64,
    envelope_b64: &str,
    identity_public_b64: &str,
    prekey_id: &str,
) -> Result<(), String> {
    let (code_id, _) = client_identity(state, sender_id).await?;
    apply_identity_state(
        state,
        &code_id,
        revision,
        envelope_b64,
        identity_public_b64,
        prekey_id,
        true,
    )
    .await
}

async fn apply_identity_state(
    state: &AppState,
    code_id: &CodeId,
    revision: u64,
    envelope_b64: &str,
    identity_public_b64: &str,
    prekey_id: &str,
    allow_reuse: bool,
) -> Result<(), String> {
    let mut envelope = decode_bounded(envelope_b64, MAX_IDENTITY_ENVELOPE_BYTES)?;
    let mut identity_public = decode_exact(identity_public_b64, IDENTITY_PUBLIC_BYTES)?;
    if envelope.len() <= 1 + MESSAGE_NONCE_BYTES
        || envelope.first() != Some(&IDENTITY_ENVELOPE_VERSION)
        || !valid_identity_public_bundle(&identity_public, prekey_id)
    {
        envelope.zeroize();
        identity_public.zeroize();
        return Err("identity state rejected".to_string());
    }
    let mut accounts = state.accounts.lock().await;
    let account = accounts.get_mut(code_id).ok_or_else(|| {
        envelope.zeroize();
        identity_public.zeroize();
        "authenticated identity required".to_string()
    })?;
    if account.identity_public.len() != IDENTITY_PUBLIC_BYTES
        || account.identity_public[..IDENTITY_FINGERPRINT_BYTES]
            != identity_public[..IDENTITY_FINGERPRINT_BYTES]
    {
        envelope.zeroize();
        identity_public.zeroize();
        return Err("identity state rejected".to_string());
    }
    if revision > account.state_revision {
        let advance = revision - account.state_revision;
        account.state_revision_window = if advance >= u64::from(STATE_REVISION_WINDOW_BITS) {
            1
        } else {
            (account.state_revision_window << advance) | 1
        };
        let mut previous = std::mem::replace(&mut account.identity_envelope, envelope);
        previous.zeroize();
        let mut previous_public = std::mem::replace(&mut account.identity_public, identity_public);
        previous_public.zeroize();
        account.prekey_id = prekey_id.to_string();
        account.state_revision = revision;
        return Ok(());
    }

    let lag = account.state_revision - revision;
    if lag >= u64::from(STATE_REVISION_WINDOW_BITS) {
        envelope.zeroize();
        identity_public.zeroize();
        return if allow_reuse {
            Ok(())
        } else {
            Err("identity state rejected".to_string())
        };
    }
    let revision_bit = 1_u128 << lag;
    if account.state_revision_window & revision_bit != 0 && !allow_reuse {
        envelope.zeroize();
        identity_public.zeroize();
        return Err("identity state rejected".to_string());
    }
    if account.identity_public != identity_public || account.prekey_id != prekey_id {
        envelope.zeroize();
        identity_public.zeroize();
        return Err("identity state rejected".to_string());
    }
    account.state_revision_window |= revision_bit;
    envelope.zeroize();
    identity_public.zeroize();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn acknowledge_message(
    state: &AppState,
    sender_id: Uuid,
    chat_id: &str,
    message_id: &str,
    original_sender: &str,
    revision: u64,
    envelope_b64: &str,
    identity_public_b64: &str,
    current_prekey_id: &str,
    used_prekey_id: &str,
) -> Result<(), String> {
    if !valid_chat_id(chat_id)
        || !valid_chat_id(message_id)
        || original_sender.is_empty()
        || original_sender.len() > 80
        || !original_sender.is_ascii()
    {
        return Err("message acknowledgement rejected".to_string());
    }
    let (code_id, username) = client_identity(state, sender_id).await?;
    let access = conversation_access(state, &username, chat_id)
        .await
        .ok_or_else(|| "conversation unavailable".to_string())?;
    let valid_sender = match access {
        ConversationAccess::Room(_) => state
            .accounts
            .lock()
            .await
            .values()
            .any(|account| account.username == original_sender),
        ConversationAccess::Direct => state
            .direct_catalog
            .lock()
            .await
            .get(chat_id)
            .and_then(|direct| direct.peer_for(&username))
            .is_some_and(|peer| peer == original_sender),
    };
    if !valid_sender || original_sender == username {
        return Err("conversation unavailable".to_string());
    }
    apply_identity_state(
        state,
        &code_id,
        revision,
        envelope_b64,
        identity_public_b64,
        current_prekey_id,
        true,
    )
    .await?;

    if !used_prekey_id.is_empty() {
        let key = PrekeyClaimKey {
            code_id,
            prekey_id: used_prekey_id.to_string(),
        };
        let mut claims = state.prekey_claims.lock().await;
        if let Some(claim) = claims.get(&key) {
            if claim.chat_id != chat_id
                || claim.message_id != message_id
                || claim.sender_username != original_sender
            {
                return Err("message acknowledgement rejected".to_string());
            }
        }
        claims.remove(&key);
    }

    let key = PendingKey {
        chat_id: chat_id.to_string(),
        recipient_username: username,
    };
    let mut pending = state.pending.lock().await;
    if let Some(queue) = pending.get_mut(&key) {
        queue.retain(|frame| {
            !matches!(
                frame,
                OutboundFrame::Message {
                    message_id: pending_id,
                    sender_username: pending_sender,
                    ..
                } if pending_id == message_id && pending_sender == original_sender
            )
        });
        if queue.is_empty() {
            pending.remove(&key);
        }
    }
    Ok(())
}

async fn broadcast_wipe(state: &AppState, sender_id: Uuid) -> Result<(), String> {
    if !state.clients.lock().await.contains_key(&sender_id) {
        return Err("authenticated client required".to_string());
    }

    wipe_relay_state(state, true).await;
    Ok(())
}

async fn wipe_relay_state(state: &AppState, notify_clients: bool) {
    let clients = state
        .clients
        .lock()
        .await
        .keys()
        .copied()
        .collect::<Vec<_>>();
    if notify_clients {
        for client_id in &clients {
            send_to_client(state, *client_id, &OutboundFrame::GlobalWipe).await;
        }
    }

    let mut pending = state.pending.lock().await;
    for (_, mut frames) in pending.drain() {
        for frame in &mut frames {
            frame.zeroize_sensitive();
        }
    }
    drop(pending);
    state.attachments.lock().await.clear();
    state.room_catalog.lock().await.clear();
    state.direct_catalog.lock().await.clear();
    state.rooms.lock().await.clear();
    let mut sessions = state.sessions.lock().await;
    for (mut token, _) in sessions.drain() {
        token.zeroize();
    }
    drop(sessions);
    state.accounts.lock().await.clear();
    state.available_codes.lock().await.clear();
    if let Some(mut boot_codes) = state.boot_codes.lock().await.take() {
        for code in &mut boot_codes {
            code.zeroize();
        }
    }
    state.frame_limits.lock().await.clear();
    state.replay_ids.lock().await.clear();
    state.prekey_claims.lock().await.clear();
    state.opaque_handshakes.lock().await.clear();
    state.login_limits.lock().await.clear();
    state.clients.lock().await.clear();
    state.active_connections.lock().await.clear();
}

async fn create_room(
    state: &AppState,
    sender_id: Uuid,
    mut room: RoomRecord,
) -> Result<(), String> {
    let (owner_code_id, owner_username) = client_identity(state, sender_id).await?;
    room.owner_username = owner_username;
    normalize_room_record(&mut room)?;
    let mut catalog = state.room_catalog.lock().await;
    if let Some(existing) = catalog.get(&room.id) {
        if existing.owner_code_id != owner_code_id {
            return Err("room id rejected".to_string());
        }
    } else if !has_room_capacity(&catalog, &owner_code_id, state.max_rooms_per_user) {
        return Err("room limit reached".to_string());
    }
    catalog.insert(
        room.id.clone(),
        RoomEntry {
            room: room.clone(),
            owner_code_id,
        },
    );
    drop(catalog);
    broadcast_to_all(state, &OutboundFrame::RoomCreated { room }).await;
    Ok(())
}

async fn delete_room(state: &AppState, sender_id: Uuid, chat_id: &str) -> Result<(), String> {
    let (owner_code_id, _) = client_identity(state, sender_id).await?;
    let chat_id = chat_id.trim();
    if chat_id.is_empty() {
        return Err("room id is required".to_string());
    }
    let mut catalog = state.room_catalog.lock().await;
    let Some(entry) = catalog.get(chat_id) else {
        return Err("room unavailable".to_string());
    };
    if entry.owner_code_id != owner_code_id {
        return Err("room owner required".to_string());
    }
    catalog.remove(chat_id);
    drop(catalog);
    {
        let mut pending = state.pending.lock().await;
        let keys = pending
            .keys()
            .filter(|key| key.chat_id == chat_id)
            .cloned()
            .collect::<Vec<_>>();
        for key in keys {
            if let Some(mut frames) = pending.remove(&key) {
                for frame in &mut frames {
                    frame.zeroize_sensitive();
                }
            }
        }
    }
    state.rooms.lock().await.remove(chat_id);
    broadcast_to_all(
        state,
        &OutboundFrame::RoomDeleted {
            chat_id: chat_id.to_string(),
        },
    )
    .await;
    Ok(())
}

async fn send_room_catalog(state: &AppState, client_id: Uuid) {
    let rooms = state
        .room_catalog
        .lock()
        .await
        .values()
        .map(|entry| entry.room.clone())
        .collect::<Vec<_>>();
    send_to_client(state, client_id, &OutboundFrame::Rooms { rooms }).await;
}

impl DirectEntry {
    fn contains(&self, username: &str) -> bool {
        self.user_a == username || self.user_b == username
    }

    fn peer_for(&self, username: &str) -> Option<String> {
        if self.user_a == username {
            Some(self.user_b.clone())
        } else if self.user_b == username {
            Some(self.user_a.clone())
        } else {
            None
        }
    }

    fn record_for(&self, username: &str) -> Option<DirectRecord> {
        self.peer_for(username).map(|peer_username| DirectRecord {
            id: self.id.clone(),
            peer_username,
        })
    }
}

async fn open_direct(state: &AppState, sender_id: Uuid, peer_username: &str) -> Result<(), String> {
    let (_, sender_username) = client_identity(state, sender_id).await?;
    let requested = peer_username.trim();
    if requested.is_empty() || requested.len() > MAX_USERNAME_BYTES {
        return Err("direct recipient unavailable".to_string());
    }
    let peer_username = state
        .accounts
        .lock()
        .await
        .values()
        .find(|account| account.username.eq_ignore_ascii_case(requested))
        .map(|account| account.username.clone())
        .filter(|peer| peer != &sender_username)
        .ok_or_else(|| "direct recipient unavailable".to_string())?;

    let direct = {
        let mut catalog = state.direct_catalog.lock().await;
        if let Some(existing) = catalog
            .values()
            .find(|direct| direct.contains(&sender_username) && direct.contains(&peer_username))
            .cloned()
        {
            existing
        } else {
            let direct = DirectEntry {
                id: format!("dm_{}", Uuid::new_v4().simple()),
                user_a: sender_username.clone(),
                user_b: peer_username.clone(),
            };
            catalog.insert(direct.id.clone(), direct.clone());
            direct
        }
    };

    let clients = state
        .clients
        .lock()
        .await
        .iter()
        .filter_map(|(client_id, client)| {
            direct
                .record_for(&client.username)
                .map(|record| (*client_id, record))
        })
        .collect::<Vec<_>>();
    for (client_id, record) in clients {
        send_to_client(
            state,
            client_id,
            &OutboundFrame::DirectOpened { direct: record },
        )
        .await;
    }
    Ok(())
}

async fn send_direct_catalog(state: &AppState, client_id: Uuid, username: &str) {
    let directs = state
        .direct_catalog
        .lock()
        .await
        .values()
        .filter_map(|direct| direct.record_for(username))
        .collect::<Vec<_>>();
    send_to_client(state, client_id, &OutboundFrame::Directs { directs }).await;
}

async fn client_identity(state: &AppState, client_id: Uuid) -> Result<(CodeId, String), String> {
    state
        .clients
        .lock()
        .await
        .get(&client_id)
        .map(|client| (client.code_id, client.username.clone()))
        .ok_or_else(|| "authenticated client required".to_string())
}

fn owned_room_count(catalog: &HashMap<String, RoomEntry>, owner_code_id: &CodeId) -> usize {
    catalog
        .values()
        .filter(|entry| entry.owner_code_id == *owner_code_id)
        .count()
}

fn has_room_capacity(
    catalog: &HashMap<String, RoomEntry>,
    owner_code_id: &CodeId,
    max_rooms_per_user: usize,
) -> bool {
    owned_room_count(catalog, owner_code_id) < max_rooms_per_user
}

fn normalize_room_record(room: &mut RoomRecord) -> Result<(), String> {
    room.id = room.id.trim().to_string();
    room.name = room
        .name
        .trim()
        .chars()
        .filter(|character| !character.is_control())
        .take(36)
        .collect::<String>();
    if !room.id.starts_with("forum_") || !valid_chat_id(&room.id) {
        return Err("room id rejected".to_string());
    }
    if room.name.is_empty() {
        return Err("room name rejected".to_string());
    }
    room.self_destruct_timer_sec = room.self_destruct_timer_sec.min(86_400);
    room.overall_expiry_sec = room.overall_expiry_sec.min(86_400);
    room.image_read_timer_sec = room.image_read_timer_sec.min(86_400);
    room.image_overall_expiry_sec = room.image_overall_expiry_sec.min(86_400);
    room.video_read_timer_sec = room.video_read_timer_sec.min(86_400);
    room.video_overall_expiry_sec = room.video_overall_expiry_sec.min(86_400);
    room.file_read_timer_sec = room.file_read_timer_sec.min(86_400);
    room.file_overall_expiry_sec = room.file_overall_expiry_sec.min(86_400);
    Ok(())
}

async fn broadcast_presence(state: &AppState) {
    let accounts = state.accounts.lock().await;
    let directory_digest = identity_directory_digest(&accounts);
    let users = accounts
        .values()
        .map(|account| PresenceUser {
            username: account.username.clone(),
            connected: account.connected,
            identity_public_b64: URL_SAFE_NO_PAD.encode(&account.identity_public),
            identity_prekey_id: account.prekey_id.clone(),
            directory_digest: directory_digest.clone(),
        })
        .collect::<Vec<_>>();
    drop(accounts);
    let frame = OutboundFrame::Presence { users };
    let clients = state
        .clients
        .lock()
        .await
        .keys()
        .copied()
        .collect::<Vec<_>>();
    for client_id in clients {
        send_to_client(state, client_id, &frame).await;
    }
}

fn identity_directory_digest(accounts: &HashMap<CodeId, Account>) -> String {
    let mut entries = accounts
        .values()
        .filter(|account| account.identity_public.len() >= IDENTITY_FINGERPRINT_BYTES)
        .map(|account| {
            (
                account.username.clone(),
                account.identity_public[..IDENTITY_FINGERPRINT_BYTES].to_vec(),
            )
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let mut digest = Sha256::new();
    digest.update(b"ABYSSAL_DIRECTORY_CHECKPOINT_V1");
    for (username, identity_public) in entries {
        digest.update((username.len() as u32).to_be_bytes());
        digest.update(username.as_bytes());
        digest.update(&identity_public);
    }
    URL_SAFE_NO_PAD.encode(digest.finalize())
}

async fn broadcast_to_all(state: &AppState, frame: &OutboundFrame) {
    let clients = state
        .clients
        .lock()
        .await
        .keys()
        .copied()
        .collect::<Vec<_>>();
    for client_id in clients {
        send_to_client(state, client_id, frame).await;
    }
}

async fn send_to_client(state: &AppState, client_id: Uuid, frame: &OutboundFrame) {
    let serialized = match serde_json::to_string(frame) {
        Ok(serialized) => serialized,
        Err(err) => {
            error!("failed to serialize outbound frame: {err}");
            return;
        }
    };

    let tx = state
        .clients
        .lock()
        .await
        .get(&client_id)
        .map(|client| client.tx.clone());
    if let Some(tx) = tx {
        if tx.try_send(Message::Text(serialized)).is_err() {
            warn!("dropping frame for slow or closed client {client_id}");
        }
    }
}

async fn cleanup_client(state: &AppState, client_id: Uuid) {
    state.frame_limits.lock().await.remove(&client_id);
    let code_id = state
        .clients
        .lock()
        .await
        .remove(&client_id)
        .map(|client| client.code_id);
    for members in state.rooms.lock().await.values_mut() {
        members.remove(&client_id);
    }
    if let Some(code_id) = code_id {
        release_connection_reservation(state, &code_id, client_id).await;
        let still_connected = state
            .clients
            .lock()
            .await
            .values()
            .any(|client| client.code_id == code_id);
        if !still_connected {
            if let Some(account) = state.accounts.lock().await.get_mut(&code_id) {
                account.connected = false;
            }
        }
    }
    broadcast_presence(state).await;
}

async fn release_connection_reservation(state: &AppState, code_id: &CodeId, client_id: Uuid) {
    let mut active_connections = state.active_connections.lock().await;
    if active_connections.get(code_id) == Some(&client_id) {
        active_connections.remove(code_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_security_policy_allows_wasm_without_javascript_eval() {
        assert!(CONTENT_SECURITY_POLICY.contains("script-src 'self' 'wasm-unsafe-eval'"));
        assert!(!CONTENT_SECURITY_POLICY.contains("'unsafe-eval'"));
    }

    #[test]
    fn generated_codes_are_at_least_minimum_length() {
        let mut rng = OsRng;
        for len in 12..=20 {
            let code = generate_code(&mut rng, len);
            assert_eq!(len, code.len());
            assert!(valid_code_shape(&code));
        }
    }

    #[test]
    fn generated_code_lengths_are_unique() {
        let mut codes = HashSet::new();
        let mut lengths = HashSet::new();
        generate_codes(&mut codes, &mut lengths, 11, 12, 24);

        let unique_lengths = codes.iter().map(|code| code.len()).collect::<HashSet<_>>();
        assert_eq!(codes.len(), unique_lengths.len());
    }

    #[test]
    fn invite_code_ids_are_keyed_and_do_not_embed_plaintext() {
        let code = "ABYS-PRIVATE-0001";
        let first = derive_code_id(&[1_u8; 32], code);
        let repeated = derive_code_id(&[1_u8; 32], code);
        let different_process = derive_code_id(&[2_u8; 32], code);

        assert_eq!(first, repeated);
        assert_ne!(first, different_process);
        assert!(!first
            .windows(code.len())
            .any(|window| window == code.as_bytes()));
    }

    #[test]
    fn code_parser_accepts_variable_lengths() {
        assert!(valid_code_shape("ABCD-1234-WXYZ"));
        assert!(valid_code_shape("ABC-12345678"));
        assert!(!valid_code_shape("SHORT-1"));
        assert!(!valid_code_shape("-ABCD12345678"));
        assert!(!valid_code_shape("ABCD12345678-"));
        assert!(!valid_code_shape("ABCD_12345678"));
        assert!(!valid_code_shape(&"A".repeat(MAX_CODE_BYTES + 1)));
    }

    #[test]
    fn rate_windows_enforce_limit_and_reset_at_boundary() {
        let mut state = RateState {
            window_start_ms: 1_000,
            count: 0,
            bytes: 99,
        };
        assert!(record_rate_attempt(&mut state, 1_001, 100, 2));
        assert!(record_rate_attempt(&mut state, 1_002, 100, 2));
        assert!(!record_rate_attempt(&mut state, 1_003, 100, 2));
        assert!(record_rate_attempt(&mut state, 1_100, 100, 2));
        assert_eq!(state.count, 1);
        assert_eq!(state.bytes, 0);
    }

    #[test]
    fn protocol_base64_requires_exact_unpadded_lengths() {
        let encoded = URL_SAFE_NO_PAD.encode([7_u8; MESSAGE_NONCE_BYTES]);
        assert_eq!(
            decode_exact(&encoded, MESSAGE_NONCE_BYTES).unwrap(),
            vec![7; 12]
        );
        assert!(decode_exact(&encoded, MESSAGE_NONCE_BYTES + 1).is_err());
        assert!(decode_bounded("not base64!", 128).is_err());
    }

    #[test]
    fn session_expiration_uses_strict_boundary() {
        let session = AuthSession {
            code_id: test_code_id("ABCD-1234-WXYZ"),
            username: "SilentNode123".to_string(),
            last_activity_ms: 1_000,
        };

        assert!(!session_is_expired(&session, 5_999, 5_000));
        assert!(session_is_expired(&session, 6_000, 5_000));
    }

    #[test]
    fn room_quota_is_counted_per_owner() {
        let mut catalog = HashMap::new();
        for (id, owner_code) in [
            ("room-a", "code-a"),
            ("room-b", "code-a"),
            ("room-c", "code-b"),
        ] {
            catalog.insert(
                id.to_string(),
                RoomEntry {
                    room: test_room(id),
                    owner_code_id: test_code_id(owner_code),
                },
            );
        }

        assert_eq!(owned_room_count(&catalog, &test_code_id("code-a")), 2);
        assert!(!has_room_capacity(&catalog, &test_code_id("code-a"), 2));
        assert!(has_room_capacity(&catalog, &test_code_id("code-b"), 2));
    }

    #[test]
    fn websocket_token_uses_bearer_subprotocol() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static("abyssal-v1, bearer.12345678-abcd"),
        );

        assert_eq!(
            websocket_protocol_token(&headers).as_deref(),
            Some("12345678-abcd")
        );
    }

    #[test]
    fn websocket_origin_requires_same_host_or_allow_list() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("abyssal.example"));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://abyssal.example"),
        );
        assert!(websocket_origin_allowed(&headers, &[]));

        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://web.example"),
        );
        assert!(!websocket_origin_allowed(&headers, &[]));
        assert!(websocket_origin_allowed(
            &headers,
            &["https://web.example".to_string()]
        ));
    }

    #[test]
    fn web_origin_normalization_rejects_paths_and_non_http_schemes() {
        assert_eq!(
            normalize_web_origin("https://web.example/").as_deref(),
            Ok("https://web.example")
        );
        assert!(normalize_web_origin("https://web.example/path").is_err());
        assert!(normalize_web_origin("file://web.example").is_err());
    }

    #[test]
    fn chat_ids_and_room_metadata_are_strictly_normalized() {
        assert!(valid_chat_id("forum_alpha-1"));
        assert!(!valid_chat_id("forum/alpha"));
        assert!(!valid_chat_id("forum_alpha\nmessage"));
        assert!(!valid_chat_id(&"a".repeat(MAX_CHAT_ID_BYTES + 1)));

        let mut room = test_room("forum_safe");
        room.name = "  Ops\nRoom\u{0000}  ".to_string();
        normalize_room_record(&mut room).expect("room should normalize");
        assert_eq!(room.name, "OpsRoom");

        room.self_destruct_timer_sec = 0;
        room.image_read_timer_sec = 0;
        normalize_room_record(&mut room).expect("never-expire policy should normalize");
        assert_eq!(room.self_destruct_timer_sec, 0);
        assert_eq!(room.image_read_timer_sec, 0);

        room.id = "forum/unsafe".to_string();
        assert!(normalize_room_record(&mut room).is_err());
    }

    #[tokio::test]
    async fn replay_window_rejects_duplicate_sender_message_ids() {
        let state = test_state();
        register_message_id(&state, "forum_alpha", "Alice", "message-1")
            .await
            .expect("first message should register");
        assert!(
            register_message_id(&state, "forum_alpha", "Alice", "message-1")
                .await
                .is_err()
        );
        assert!(
            register_message_id(&state, "forum_alpha", "Bob", "message-1")
                .await
                .is_ok()
        );
        assert!(
            register_message_id(&state, "forum_beta", "Alice", "message-1")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn one_time_prekey_claims_are_single_use_and_bound_to_recipient_state() {
        let state = test_state();
        add_test_account(&state, "code-a", "Alice").await;
        add_test_account(&state, "code-b", "Bob").await;
        let expected = HashSet::from(["Bob".to_string()]);
        let envelope = InboundRecipientEnvelope {
            recipient_username: "Bob".to_string(),
            wrapped_key_b64: URL_SAFE_NO_PAD.encode([7_u8; 32]),
            prekey_id: test_prekey_id(b'B'),
            is_prekey: true,
        };
        let envelopes = HashMap::from([("Bob".to_string(), envelope)]);

        claim_prekeys(
            &state,
            &expected,
            &envelopes,
            "dm_alice_bob",
            "message-1",
            "Alice",
        )
        .await
        .expect("first claim");
        assert!(claim_prekeys(
            &state,
            &expected,
            &envelopes,
            "dm_alice_bob",
            "message-2",
            "Alice",
        )
        .await
        .is_err());

        let mut mismatched = envelopes;
        mismatched.get_mut("Bob").expect("Bob envelope").prekey_id = "other-key".to_string();
        state.prekey_claims.lock().await.clear();
        assert!(claim_prekeys(
            &state,
            &expected,
            &mismatched,
            "dm_alice_bob",
            "message-3",
            "Alice",
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn identity_directory_checkpoint_is_order_independent_and_long_term_bound() {
        let state = test_state();
        add_test_account(&state, "code-a", "Alice").await;
        add_test_account(&state, "code-b", "Bob").await;
        let first = {
            let accounts = state.accounts.lock().await;
            identity_directory_digest(&accounts)
        };
        {
            let mut accounts = state.accounts.lock().await;
            let bob_id = test_code_id("code-b");
            accounts.get_mut(&bob_id).expect("Bob").prekey_id = "rotated-key".to_string();
        }
        let after_prekey_rotation = {
            let accounts = state.accounts.lock().await;
            identity_directory_digest(&accounts)
        };
        assert_eq!(first, after_prekey_rotation);
        {
            let mut accounts = state.accounts.lock().await;
            let bob_id = test_code_id("code-b");
            accounts.get_mut(&bob_id).expect("Bob").identity_public[0] ^= 1;
        }
        let after_identity_change = {
            let accounts = state.accounts.lock().await;
            identity_directory_digest(&accounts)
        };
        assert_ne!(first, after_identity_change);
    }

    #[test]
    fn attachment_ttl_cannot_exceed_enforced_room_policy() {
        let mut room = test_room("forum_policy");
        room.enforce_text_absolute_expiry = true;
        room.overall_expiry_sec = 60;
        room.enforce_video_absolute_expiry = true;
        room.video_overall_expiry_sec = 20;
        let access = ConversationAccess::Room(room);

        assert_eq!(
            effective_attachment_ttl_sec(Some(100), &access, "VIDEO"),
            20
        );
        assert_eq!(effective_attachment_ttl_sec(None, &access, "VIDEO"), 20);
        assert_eq!(effective_attachment_ttl_sec(Some(10), &access, "VIDEO"), 10);
        assert_eq!(
            effective_attachment_ttl_sec(Some(u64::MAX), &ConversationAccess::Direct, "FILE"),
            86_400
        );
    }

    #[tokio::test]
    async fn direct_conversations_are_canonical_and_participant_restricted() {
        let state = test_state();
        add_test_account(&state, "code-a", "Alice").await;
        add_test_account(&state, "code-b", "Bob").await;
        add_test_account(&state, "code-e", "Eve").await;
        let (alice_id, mut alice_rx) = add_test_client(&state, "code-a", "Alice").await;
        let (bob_id, mut bob_rx) = add_test_client(&state, "code-b", "Bob").await;
        let (eve_id, mut eve_rx) = add_test_client(&state, "code-e", "Eve").await;

        open_direct(&state, alice_id, "Bob")
            .await
            .expect("direct should open");
        open_direct(&state, bob_id, "Alice")
            .await
            .expect("opening the same pair should be idempotent");

        let catalog = state.direct_catalog.lock().await;
        assert_eq!(catalog.len(), 1);
        let direct_id = catalog.values().next().expect("direct").id.clone();
        drop(catalog);
        assert!(join_room(&state, alice_id, direct_id.clone()).await.is_ok());
        assert!(join_room(&state, bob_id, direct_id.clone()).await.is_ok());
        assert!(join_room(&state, eve_id, direct_id.clone()).await.is_err());
        assert!(join_room(&state, eve_id, "dm_guessed".to_string())
            .await
            .is_err());

        while alice_rx.try_recv().is_ok() {}
        while bob_rx.try_recv().is_ok() {}
        while eve_rx.try_recv().is_ok() {}
        route_test_message(&state, alice_id, &direct_id, &["Bob"])
            .await
            .expect("participant message should route");

        let delivered = bob_rx.try_recv().expect("Bob receives the DM");
        assert!(
            matches!(delivered, Message::Text(text) if text.contains("ciphertext_b64") && text.contains("wrapped_key_b64"))
        );
        assert!(eve_rx.try_recv().is_err());
        assert!(conversation_access(&state, "Eve", &direct_id)
            .await
            .is_none());
        assert!(conversation_access(&state, "Alice", &direct_id)
            .await
            .is_some());
    }

    #[tokio::test]
    async fn direct_catalog_is_private_to_each_participant() {
        let state = test_state();
        state.direct_catalog.lock().await.insert(
            "dm_private".to_string(),
            DirectEntry {
                id: "dm_private".to_string(),
                user_a: "Alice".to_string(),
                user_b: "Bob".to_string(),
            },
        );
        let records_for_alice = state
            .direct_catalog
            .lock()
            .await
            .values()
            .filter_map(|direct| direct.record_for("Alice"))
            .collect::<Vec<_>>();
        let records_for_eve = state
            .direct_catalog
            .lock()
            .await
            .values()
            .filter_map(|direct| direct.record_for("Eve"))
            .collect::<Vec<_>>();

        assert_eq!(records_for_alice.len(), 1);
        assert_eq!(records_for_alice[0].peer_username, "Bob");
        assert!(records_for_eve.is_empty());
    }

    #[tokio::test]
    async fn relay_rejects_missing_duplicate_and_unauthorized_recipient_envelopes() {
        let state = test_state();
        add_test_account(&state, "code-a", "Alice").await;
        add_test_account(&state, "code-b", "Bob").await;
        add_test_account(&state, "code-e", "Eve").await;
        let (alice_id, _) = add_test_client(&state, "code-a", "Alice").await;
        open_direct(&state, alice_id, "Bob")
            .await
            .expect("direct should open");
        let direct_id = state
            .direct_catalog
            .lock()
            .await
            .values()
            .next()
            .expect("direct")
            .id
            .clone();

        assert!(route_test_message(&state, alice_id, &direct_id, &[])
            .await
            .is_err());
        assert!(
            route_test_message(&state, alice_id, &direct_id, &["Bob", "Bob"])
                .await
                .is_err()
        );
        assert!(route_test_message(&state, alice_id, &direct_id, &["Eve"])
            .await
            .is_err());
    }

    #[tokio::test]
    async fn offline_direct_frames_are_consumed_only_by_the_peer() {
        let state = test_state();
        add_test_account(&state, "code-a", "Alice").await;
        add_test_account(&state, "code-b", "Bob").await;
        let (alice_id, mut alice_rx) = add_test_client(&state, "code-a", "Alice").await;
        open_direct(&state, alice_id, "Bob")
            .await
            .expect("direct should open");
        while alice_rx.try_recv().is_ok() {}

        let direct_id = state
            .direct_catalog
            .lock()
            .await
            .values()
            .next()
            .expect("direct")
            .id
            .clone();
        route_test_message(&state, alice_id, &direct_id, &["Bob"])
            .await
            .expect("offline direct should queue");

        join_room(&state, alice_id, direct_id.clone())
            .await
            .expect("sender can join");
        assert!(alice_rx.try_recv().is_err());
        assert_eq!(state.pending.lock().await.len(), 1);

        let (bob_id, mut bob_rx) = add_test_client(&state, "code-b", "Bob").await;
        join_room(&state, bob_id, direct_id.clone())
            .await
            .expect("peer can join");
        let delivered = bob_rx.try_recv().expect("peer receives queued frame");
        let Message::Text(text) = delivered else {
            panic!("expected text frame")
        };
        let frame: serde_json::Value = serde_json::from_str(&text).expect("message frame");
        let message_id = frame["message_id"].as_str().expect("message id");
        assert!(text.contains("ciphertext_b64"));
        assert_eq!(state.pending.lock().await.len(), 1);
        acknowledge_message(
            &state,
            bob_id,
            &direct_id,
            message_id,
            "Alice",
            1,
            &URL_SAFE_NO_PAD.encode({
                let mut envelope = [0_u8; 256];
                envelope[0] = IDENTITY_ENVELOPE_VERSION;
                envelope
            }),
            &test_identity_public_b64(b'B'),
            &test_prekey_id(b'B'),
            "",
        )
        .await
        .expect("recipient acknowledgement");
        assert!(state.pending.lock().await.is_empty());
    }

    #[tokio::test]
    async fn room_frames_wait_for_each_existing_account_to_join() {
        let state = test_state();
        add_test_account(&state, "code-a", "Alice").await;
        add_test_account(&state, "code-b", "Bob").await;
        let (alice_id, mut alice_rx) = add_test_client(&state, "code-a", "Alice").await;
        let (bob_id, mut bob_rx) = add_test_client(&state, "code-b", "Bob").await;
        let room = test_room("forum_replay");
        state.room_catalog.lock().await.insert(
            room.id.clone(),
            RoomEntry {
                room: room.clone(),
                owner_code_id: test_code_id("code-a"),
            },
        );
        join_room(&state, alice_id, room.id.clone())
            .await
            .expect("owner joins room");

        route_test_message(&state, alice_id, &room.id, &["Bob"])
            .await
            .expect("room frame should queue");
        assert!(alice_rx.try_recv().is_err());
        assert!(bob_rx.try_recv().is_err());

        join_room(&state, bob_id, room.id.clone())
            .await
            .expect("peer joins room");
        let delivered = bob_rx.try_recv().expect("peer receives queued room frame");
        let Message::Text(text) = delivered else {
            panic!("expected text frame")
        };
        let frame: serde_json::Value = serde_json::from_str(&text).expect("message frame");
        let message_id = frame["message_id"].as_str().expect("message id");
        assert!(text.contains("ciphertext_b64"));
        assert_eq!(state.pending.lock().await.len(), 1);
        acknowledge_message(
            &state,
            bob_id,
            &room.id,
            message_id,
            "Alice",
            1,
            &URL_SAFE_NO_PAD.encode({
                let mut envelope = [0_u8; 256];
                envelope[0] = IDENTITY_ENVELOPE_VERSION;
                envelope
            }),
            &test_identity_public_b64(b'B'),
            &test_prekey_id(b'B'),
            "",
        )
        .await
        .expect("recipient acknowledgement");
        assert!(state.pending.lock().await.is_empty());
    }

    #[tokio::test]
    async fn acknowledgement_removes_only_matching_sender_and_message() {
        let state = test_state();
        add_test_account(&state, "code-a", "Alice").await;
        add_test_account(&state, "code-b", "Bob").await;
        add_test_account(&state, "code-e", "Eve").await;
        let (alice_id, _) = add_test_client(&state, "code-a", "Alice").await;
        let (bob_id, _) = add_test_client(&state, "code-b", "Bob").await;
        let (eve_id, _) = add_test_client(&state, "code-e", "Eve").await;
        let room = test_room("forum_ack_binding");
        state.room_catalog.lock().await.insert(
            room.id.clone(),
            RoomEntry {
                room: room.clone(),
                owner_code_id: test_code_id("code-a"),
            },
        );
        let shared_message_id = "shared-message-id";

        route_test_message_with_id(
            &state,
            alice_id,
            &room.id,
            &["Bob", "Eve"],
            shared_message_id,
        )
        .await
        .expect("Alice message should queue");
        route_test_message_with_id(
            &state,
            eve_id,
            &room.id,
            &["Alice", "Bob"],
            shared_message_id,
        )
        .await
        .expect("Eve message should queue");

        assert!(acknowledge_message(
            &state,
            bob_id,
            &room.id,
            shared_message_id,
            "Mallory",
            1,
            &URL_SAFE_NO_PAD.encode({
                let mut envelope = [0_u8; 256];
                envelope[0] = IDENTITY_ENVELOPE_VERSION;
                envelope
            }),
            &test_identity_public_b64(b'B'),
            &test_prekey_id(b'B'),
            "",
        )
        .await
        .is_err());

        acknowledge_message(
            &state,
            bob_id,
            &room.id,
            shared_message_id,
            "Alice",
            1,
            &URL_SAFE_NO_PAD.encode({
                let mut envelope = [0_u8; 256];
                envelope[0] = IDENTITY_ENVELOPE_VERSION;
                envelope
            }),
            &test_identity_public_b64(b'B'),
            &test_prekey_id(b'B'),
            "",
        )
        .await
        .expect("Bob should acknowledge Alice only");

        let pending = state.pending.lock().await;
        let bob_queue = pending
            .get(&PendingKey {
                chat_id: room.id.clone(),
                recipient_username: "Bob".to_string(),
            })
            .expect("Eve message must remain queued for Bob");
        assert_eq!(bob_queue.len(), 1);
        assert!(matches!(
            &bob_queue[0],
            OutboundFrame::Message {
                sender_username,
                message_id,
                ..
            } if sender_username == "Eve" && message_id == shared_message_id
        ));
        drop(pending);

        acknowledge_message(
            &state,
            bob_id,
            &room.id,
            shared_message_id,
            "Eve",
            1,
            &URL_SAFE_NO_PAD.encode({
                let mut envelope = [0_u8; 256];
                envelope[0] = IDENTITY_ENVELOPE_VERSION;
                envelope
            }),
            &test_identity_public_b64(b'B'),
            &test_prekey_id(b'B'),
            "",
        )
        .await
        .expect("retry with an older state revision must not roll state backward");
        assert!(!state.pending.lock().await.contains_key(&PendingKey {
            chat_id: room.id,
            recipient_username: "Bob".to_string(),
        }));
    }

    #[tokio::test]
    async fn identity_revision_window_accepts_reordering_once_without_rollback() {
        let state = test_state();
        add_test_account(&state, "code-a", "Alice").await;
        let code_id = test_code_id("code-a");
        let mut revision_two = [2_u8; 256];
        revision_two[0] = IDENTITY_ENVELOPE_VERSION;
        revision_two[1] = 22;
        let mut revision_one = [2_u8; 256];
        revision_one[0] = IDENTITY_ENVELOPE_VERSION;
        revision_one[1] = 11;

        apply_identity_state(
            &state,
            &code_id,
            2,
            &URL_SAFE_NO_PAD.encode(revision_two),
            &test_identity_public_b64(b'A'),
            &test_prekey_id(b'A'),
            false,
        )
        .await
        .expect("newer revision");
        apply_identity_state(
            &state,
            &code_id,
            1,
            &URL_SAFE_NO_PAD.encode(revision_one),
            &test_identity_public_b64(b'A'),
            &test_prekey_id(b'A'),
            false,
        )
        .await
        .expect("bounded out-of-order revision");
        assert!(apply_identity_state(
            &state,
            &code_id,
            1,
            &URL_SAFE_NO_PAD.encode(revision_one),
            &test_identity_public_b64(b'A'),
            &test_prekey_id(b'A'),
            false,
        )
        .await
        .is_err());

        let accounts = state.accounts.lock().await;
        let account = accounts.get(&code_id).expect("Alice account");
        assert_eq!(account.state_revision, 2);
        assert_eq!(account.identity_envelope, revision_two);
    }

    #[tokio::test]
    async fn account_code_allows_only_one_unexpired_session() {
        let state = test_state();
        let code = "ABYS-SESSION-0001";
        let code_id = test_code_id(code);
        state.sessions.lock().await.insert(
            "active-token".to_string(),
            AuthSession {
                code_id,
                username: "Alice".to_string(),
                last_activity_ms: now_ms(),
            },
        );
        assert!(code_has_active_session(&state, &code_id).await);

        state
            .sessions
            .lock()
            .await
            .get_mut("active-token")
            .expect("session")
            .last_activity_ms = 0;
        assert!(!code_has_active_session(&state, &code_id).await);
        assert!(state.sessions.lock().await.is_empty());
    }

    #[tokio::test]
    async fn stale_socket_cleanup_cannot_release_new_active_connection() {
        let state = test_state();
        add_test_account(&state, "code-a", "Alice").await;
        let (old_client, _) = add_test_client(&state, "code-a", "Alice").await;
        let code_id = test_code_id("code-a");
        state
            .active_connections
            .lock()
            .await
            .insert(code_id, old_client);

        replace_connected_clients_for_code(&state, &code_id).await;
        let (new_client, _) = add_test_client(&state, "code-a", "Alice").await;
        state
            .active_connections
            .lock()
            .await
            .insert(code_id, new_client);

        cleanup_client(&state, old_client).await;

        assert_eq!(
            state.active_connections.lock().await.get(&code_id).copied(),
            Some(new_client)
        );
    }

    fn test_state() -> AppState {
        AppState {
            node_id: "test-node".to_string(),
            attachment_ram_limit_bytes: 8 * 1024 * 1024,
            max_rooms_per_user: 2,
            web_origins: Vec::new(),
            session_inactivity_ms: 60_000,
            inactivity_limit_ms: None,
            last_activity_ms: Arc::new(Mutex::new(now_ms())),
            account_ops: Arc::new(Mutex::new(())),
            opaque_setup: Arc::new(opaque_server_setup()),
            opaque_handshakes: Arc::new(Mutex::new(HashMap::new())),
            invite_code_pepper: Arc::new([7_u8; 32]),
            boot_codes: Arc::new(Mutex::new(None)),
            available_codes: Arc::new(Mutex::new(HashSet::new())),
            accounts: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            clients: Arc::new(Mutex::new(HashMap::new())),
            active_connections: Arc::new(Mutex::new(HashMap::new())),
            frame_limits: Arc::new(Mutex::new(HashMap::new())),
            login_limits: Arc::new(Mutex::new(HashMap::new())),
            replay_ids: Arc::new(Mutex::new(HashMap::new())),
            rooms: Arc::new(Mutex::new(HashMap::new())),
            room_catalog: Arc::new(Mutex::new(HashMap::new())),
            direct_catalog: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
            attachments: Arc::new(Mutex::new(HashMap::new())),
            prekey_claims: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn add_test_account(state: &AppState, code: &str, username: &str) {
        let identity_fill = username.as_bytes()[0];
        let mut identity_envelope = vec![0; 256];
        identity_envelope[0] = IDENTITY_ENVELOPE_VERSION;
        state.accounts.lock().await.insert(
            test_code_id(code),
            Account {
                username: username.to_string(),
                password_file: vec![1; 192],
                identity_public: vec![identity_fill; IDENTITY_PUBLIC_BYTES],
                prekey_id: test_prekey_id(identity_fill),
                identity_envelope,
                state_revision: 0,
                state_revision_window: 1,
                connected: true,
            },
        );
    }

    async fn route_test_message(
        state: &AppState,
        sender_id: Uuid,
        chat_id: &str,
        recipients: &[&str],
    ) -> Result<(), String> {
        route_test_message_with_id(
            state,
            sender_id,
            chat_id,
            recipients,
            &Uuid::new_v4().to_string(),
        )
        .await
    }

    async fn route_test_message_with_id(
        state: &AppState,
        sender_id: Uuid,
        chat_id: &str,
        recipients: &[&str],
        message_id: &str,
    ) -> Result<(), String> {
        let (code_id, _) = client_identity(state, sender_id).await?;
        let state_revision = state
            .accounts
            .lock()
            .await
            .get(&code_id)
            .map(|account| account.state_revision + 1)
            .ok_or_else(|| "missing test account".to_string())?;
        let (identity_public_b64, prekey_id) = state
            .accounts
            .lock()
            .await
            .get(&code_id)
            .map(|account| {
                (
                    URL_SAFE_NO_PAD.encode(&account.identity_public),
                    account.prekey_id.clone(),
                )
            })
            .ok_or_else(|| "missing test account".to_string())?;
        route_encrypted_message(
            state,
            sender_id,
            chat_id.to_string(),
            E2EE_PROTOCOL_VERSION,
            message_id.to_string(),
            URL_SAFE_NO_PAD.encode([2_u8; MESSAGE_NONCE_BYTES]),
            URL_SAFE_NO_PAD.encode(b"ciphertext"),
            URL_SAFE_NO_PAD.encode([3_u8; MESSAGE_SIGNATURE_BYTES]),
            recipients
                .iter()
                .map(|username| InboundRecipientEnvelope {
                    recipient_username: (*username).to_string(),
                    wrapped_key_b64: URL_SAFE_NO_PAD.encode([4_u8; 256]),
                    prekey_id: String::new(),
                    is_prekey: false,
                })
                .collect(),
            state_revision,
            URL_SAFE_NO_PAD.encode({
                let mut envelope = [0_u8; 256];
                envelope[0] = IDENTITY_ENVELOPE_VERSION;
                envelope
            }),
            identity_public_b64,
            prekey_id,
        )
        .await
    }

    async fn add_test_client(
        state: &AppState,
        code: &str,
        username: &str,
    ) -> (Uuid, mpsc::Receiver<Message>) {
        let client_id = Uuid::new_v4();
        let (tx, rx) = mpsc::channel(CLIENT_OUTBOUND_QUEUE_CAPACITY);
        state.clients.lock().await.insert(
            client_id,
            ClientHandle {
                code_id: test_code_id(code),
                username: username.to_string(),
                tx,
            },
        );
        (client_id, rx)
    }

    fn test_code_id(code: &str) -> CodeId {
        derive_code_id(&[7_u8; 32], code)
    }

    fn test_identity_public_b64(fill: u8) -> String {
        URL_SAFE_NO_PAD.encode(vec![fill; IDENTITY_PUBLIC_BYTES])
    }

    fn test_prekey_id(fill: u8) -> String {
        prekey_id_for_public(&[fill; ONE_TIME_KEY_BYTES])
    }

    fn test_room(id: &str) -> RoomRecord {
        RoomRecord {
            id: id.to_string(),
            name: id.to_string(),
            owner_username: "SilentNode123".to_string(),
            self_destruct_timer_sec: 5,
            overall_expiry_sec: 0,
            allow_images: true,
            allow_videos: true,
            allow_files: true,
            enforce_text_absolute_expiry: false,
            image_read_timer_sec: 5,
            image_overall_expiry_sec: 0,
            enforce_image_absolute_expiry: false,
            video_read_timer_sec: 5,
            video_overall_expiry_sec: 0,
            enforce_video_absolute_expiry: false,
            file_read_timer_sec: 5,
            file_overall_expiry_sec: 0,
            enforce_file_absolute_expiry: false,
        }
    }
}
