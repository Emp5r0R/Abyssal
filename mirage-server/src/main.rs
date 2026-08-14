use std::{
    borrow::Borrow,
    collections::{HashMap, HashSet},
    convert::Infallible,
    env,
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use abyssal_core::secure_protocol::{
    opaque_server_finish_login, opaque_server_finish_registration,
    opaque_server_registration_response, opaque_server_setup, opaque_server_start_login,
    validate_identity_public_bundle as validate_core_identity_public_bundle,
    verify_ack_signature_v8, verify_identity_state_signature_v8, verify_message_signature_v8,
    verify_registration_identity_proof_v8, REGISTRATION_CHALLENGE_BYTES_V8,
};
use axum::{
    body::{Body, Bytes},
    extract::Request,
    extract::{
        ws::{CloseFrame, Message, WebSocket},
        DefaultBodyLimit, Path, Query, State, WebSocketUpgrade,
    },
    http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, delete, get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, KeyInit, Mac};
use rand::{rngs::OsRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot, watch, Mutex};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tower_http::{
    cors::CorsLayer,
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use tracing::{info, warn};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const IMAGE_ATTACHMENT_LIMIT_BYTES: usize = 20 * 1024 * 1024;
const VIDEO_ATTACHMENT_LIMIT_BYTES: usize = 100 * 1024 * 1024;
const FILE_ATTACHMENT_LIMIT_BYTES: usize = 200 * 1024 * 1024;
// Stateless attachment blobs contain a version byte, XChaCha nonce, and
// authentication tag in addition to the encrypted plaintext.
const ATTACHMENT_WIRE_OVERHEAD_BYTES: usize = 41;
const ATTACHMENT_BLOB_VERSION: u8 = 1;
const WS_RATE_WINDOW_MS: u64 = 10_000;
const WS_MAX_FRAMES_PER_WINDOW: usize = 30;
const WS_MAX_BYTES_PER_WINDOW: usize = 4 * 1024 * 1024;
const WS_MAX_FRAME_BYTES: usize = 1024 * 1024;
const STATE_REVISION_WINDOW_BITS: u32 = u128::BITS;
const MAX_PENDING_FRAMES_PER_ROOM: usize = 500;
const MAX_PENDING_BYTES: usize = 256 * 1024 * 1024;
const DEFAULT_PENDING_MESSAGE_TTL_HOURS: usize = 24;
const MIN_PENDING_MESSAGE_TTL_HOURS: usize = 1;
const MAX_PENDING_MESSAGE_TTL_HOURS: usize = 7 * 24;
const HOURS_TO_MILLISECONDS: u64 = 60 * 60 * 1000;
const CLIENT_OUTBOUND_QUEUE_CAPACITY: usize = 256;
const CLIENT_CONTROL_QUEUE_CAPACITY: usize = 1;
const CLIENT_RESULT_QUEUE_CAPACITY: usize = 2;
const CLIENT_OUTBOUND_BYTES: usize = 4 * 1024 * 1024;
const GLOBAL_OUTBOUND_BYTES: usize = 64 * 1024 * 1024;
// A fanout is assembled before its per-recipient frames enter either the
// live client queues or pending queues. Keep that temporary allocation
// bounded by the same global outbound budget.
const MAX_TRANSIENT_FANOUT_BYTES: usize = GLOBAL_OUTBOUND_BYTES;
const CLIENT_SINK_SEND_TIMEOUT: Duration = Duration::from_secs(5);
const CLIENT_WIPE_SEND_TIMEOUT: Duration = Duration::from_millis(500);
const CLIENT_RESULT_SEND_TIMEOUT: Duration = Duration::from_secs(5);
const PURGE_CLOSE_CODE: u16 = 4001;
const PURGE_CLOSE_REASON: &str = "purge";
const MAX_ROOM_CATALOG_ENTRIES: usize = 1_024;
const MAX_DIRECT_CATALOG_ENTRIES: usize = 8_192;
const MAX_DIRECT_CATALOG_PER_USER: usize = 128;
const ACCOUNT_BODY_LIMIT_BYTES: usize = 16 * 1024;
const MAX_CHAT_ID_BYTES: usize = 128;
const MAX_USERNAME_BYTES: usize = 80;
const MAX_CODE_BYTES: usize = 128;
const LOGIN_RATE_WINDOW_MS: u64 = 60_000;
const LOGIN_MAX_ATTEMPTS_PER_WINDOW: usize = 6;
const MAX_LOGIN_LIMIT_ENTRIES: usize = 4_096;
const WEB_SOCKET_PROTOCOL: &str = "abyssal-v1";
const WS_TICKET_BYTES: usize = 32;
const WS_TICKET_B64_LEN: usize = 43;
const WS_TICKET_TTL_MS: u64 = 30_000;
const MAX_WS_TICKETS: usize = 1_024;
const OPAQUE_HANDSHAKE_TTL_MS: u64 = 60_000;
const MAX_OPAQUE_HANDSHAKES: usize = 1_024;
const IDENTITY_FINGERPRINT_BYTES: usize = 64;
const ONE_TIME_KEY_BYTES: usize = 32;
const ONE_TIME_KEY_OFFSET: usize = IDENTITY_FINGERPRINT_BYTES;
const FALLBACK_KEY_OFFSET: usize = ONE_TIME_KEY_OFFSET + ONE_TIME_KEY_BYTES;
const IDENTITY_PUBLIC_BYTES: usize = FALLBACK_KEY_OFFSET + 32;
const MAX_IDENTITY_ENVELOPE_BYTES: usize = 512 * 1024;
const MESSAGE_NONCE_BYTES: usize = 12;
const MESSAGE_SIGNATURE_BYTES: usize = 64;
const MAX_WRAPPED_KEY_BYTES: usize = 4096;
const E2EE_PROTOCOL_VERSION: u32 = 8;
const MAX_STATE_REVISION_ADVANCE: u64 = 1_024;
const IDENTITY_ENVELOPE_VERSION: u8 = 4;
const REPLAY_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;
const MAX_REPLAY_IDS: usize = 50_000;
const MAX_REPLAY_IDS_PER_SENDER: usize = 2_048;
const PREKEY_CLAIM_TTL_MS: u64 = 10 * 60 * 1000;
const ATTACHMENT_CLAIM_TTL_MS: u64 = 10 * 60 * 1000;
const MAX_PREKEY_ID_BYTES: usize = 32;
const DEFAULT_ATTACHMENT_ACCOUNT_LIMIT_MB: usize = 320;
const DEFAULT_ATTACHMENT_RECORD_LIMIT: usize = 16 * 1024;
const DEFAULT_ATTACHMENT_ACCOUNT_RECORD_LIMIT: usize = 4 * 1024;
const MIN_ATTACHMENT_RECORD_LIMIT: usize = 1;
const MAX_ATTACHMENT_RECORD_LIMIT: usize = 65_536;
// A zero/omitted client TTL still receives this bounded relay-side lifetime.
// This prevents an orphaned encrypted blob from remaining in RAM forever.
const DEFAULT_ATTACHMENT_MAX_LIFETIME_HOURS: usize = 7 * 24;
const MIN_ATTACHMENT_MAX_LIFETIME_HOURS: usize = 1;
const MAX_ATTACHMENT_MAX_LIFETIME_HOURS: usize = 30 * 24;
const DEFAULT_ATTACHMENT_DOWNLOAD_CONCURRENCY: usize = 2;
const MAX_ATTACHMENT_DOWNLOAD_CONCURRENCY: usize = 16;
const DEFAULT_ATTACHMENT_UPLOAD_CONCURRENCY: usize = 2;
const MAX_ATTACHMENT_UPLOAD_CONCURRENCY: usize = 4;
// A single account may hold only one upload permit at a time.  The global
// upload semaphore remains configurable; this per-account bound prevents one
// authenticated client from monopolising it.
const MAX_ATTACHMENT_UPLOADS_PER_ACCOUNT: usize = 1;
const ATTACHMENT_DOWNLOAD_CHUNK_BYTES: usize = 64 * 1024;
const ATTACHMENT_UPLOAD_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
// A client may upload a maximum-size attachment over a slow but legitimate
// connection, but no single upload should retain an upload permit forever.
const ATTACHMENT_UPLOAD_TOTAL_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const ATTACHMENT_DOWNLOAD_STALL_TIMEOUT: Duration = Duration::from_secs(30);
const ATTACHMENT_CLAIM_HEADER: &str = "x-abyssal-attachment-claim";
const CODE_ID_DOMAIN: &[u8] = b"ABYSSAL_INVITE_CODE_ID_V1";

type CodeId = [u8; 32];
type WsTicketDigest = [u8; WS_TICKET_BYTES];
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
struct AppState {
    node_id: String,
    attachment_ram_limit_bytes: usize,
    attachment_account_limit_bytes: usize,
    attachment_record_limit: usize,
    attachment_account_record_limit: usize,
    attachment_max_lifetime_sec: u64,
    max_rooms_per_user: usize,
    conversation_ops: Arc<Mutex<()>>,
    pending_message_ttl_ms: u64,
    web_origins: Vec<String>,
    session_inactivity_ms: u64,
    inactivity_limit_ms: Option<u64>,
    last_activity_ms: Arc<Mutex<u64>>,
    // Account endpoints and global wipe use this before conversation_ops.
    // Keep this order whenever both guards are needed so a handshake cannot
    // finish after a wipe has cleared the account maps.
    account_ops: Arc<Mutex<()>>,
    opaque_setup: Arc<Zeroizing<Vec<u8>>>,
    opaque_handshakes: Arc<Mutex<HashMap<Uuid, OpaqueHandshake>>>,
    invite_code_pepper: Arc<Zeroizing<CodeId>>,
    boot_codes: Arc<Mutex<Option<Vec<String>>>>,
    available_codes: Arc<Mutex<HashSet<CodeId>>>,
    accounts: Arc<Mutex<HashMap<CodeId, Account>>>,
    sessions: Arc<Mutex<HashMap<SessionToken, AuthSession>>>,
    ws_tickets: Arc<Mutex<HashMap<WsTicketDigest, WsTicket>>>,
    active_connections: Arc<Mutex<HashMap<CodeId, Uuid>>>,
    clients: Arc<Mutex<HashMap<Uuid, ClientHandle>>>,
    purge_epoch: watch::Sender<u64>,
    outbound_bytes: Arc<AtomicUsize>,
    frame_limits: Arc<Mutex<HashMap<Uuid, RateState>>>,
    login_limits: Arc<Mutex<HashMap<CodeId, RateState>>>,
    replay_ids: Arc<Mutex<HashMap<ReplayKey, u64>>>,
    prekey_claims: Arc<Mutex<HashMap<PrekeyClaimKey, PrekeyClaim>>>,
    rooms: Arc<Mutex<HashMap<String, HashSet<Uuid>>>>,
    room_catalog: Arc<Mutex<HashMap<String, RoomEntry>>>,
    direct_catalog: Arc<Mutex<HashMap<String, DirectEntry>>>,
    pending: Arc<Mutex<HashMap<PendingKey, Vec<PendingFrame>>>>,
    pending_bytes: Arc<Mutex<usize>>,
    attachments: Arc<Mutex<HashMap<Uuid, AttachmentRecord>>>,
    attachment_bytes_by_code: Arc<Mutex<HashMap<CodeId, usize>>>,
    attachment_downloads: Arc<Semaphore>,
    attachment_uploads: Arc<Semaphore>,
    attachment_memory: Arc<Semaphore>,
    attachment_epoch: Arc<AtomicU64>,
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
    attachment_uploads: Arc<Semaphore>,
}

enum OpaqueHandshake {
    Registration {
        code_id: CodeId,
        challenge: Zeroizing<Vec<u8>>,
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

struct WsTicket {
    session_token: Zeroizing<String>,
    expires_at_ms: u64,
}

impl Drop for WsTicket {
    fn drop(&mut self) {
        self.session_token.zeroize();
    }
}

#[derive(Eq, Hash, PartialEq)]
struct SessionToken(String);

impl SessionToken {
    fn new(value: String) -> Self {
        Self(value)
    }
}

impl Borrow<str> for SessionToken {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl Drop for SessionToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone)]
struct ClientHandle {
    code_id: CodeId,
    username: String,
    tx: mpsc::Sender<OutboundFrame>,
    control_tx: mpsc::Sender<ClientControl>,
    result_tx: mpsc::Sender<ClientResult>,
    queued_bytes: Arc<AtomicUsize>,
}

struct ClientResult {
    frame: OutboundFrame,
    delivered: oneshot::Sender<bool>,
}

enum ClientControl {
    GlobalWipe,
    Close,
}

struct BootCodes(Vec<String>);

impl Drop for BootCodes {
    fn drop(&mut self) {
        for code in &mut self.0 {
            code.zeroize();
        }
    }
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

#[derive(Clone)]
struct PendingFrame {
    frame: OutboundFrame,
    enqueued_at_ms: u64,
}

impl PendingFrame {
    fn new(frame: OutboundFrame, enqueued_at_ms: u64) -> Self {
        Self {
            frame,
            enqueued_at_ms,
        }
    }

    fn zeroize_sensitive(&mut self) {
        self.frame.zeroize_sensitive();
    }
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
    recipient_username: String,
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
        self.recipient_username.zeroize();
    }
}

impl Drop for PendingKey {
    fn drop(&mut self) {
        self.chat_id.zeroize();
        self.recipient_username.zeroize();
    }
}

struct AttachmentBlob {
    bytes: Zeroizing<Vec<u8>>,
    _memory_permit: Option<OwnedSemaphorePermit>,
}

struct AttachmentRecord {
    blob: Arc<AttachmentBlob>,
    chat_id: String,
    media_type: String,
    owner_code_id: CodeId,
    one_time: bool,
    delete_after_download: bool,
    expires_at_ms: Option<u64>,
    eligible_recipient_code_ids: HashSet<CodeId>,
    download_claims: HashMap<Uuid, AttachmentDownloadClaim>,
    completed_recipient_code_ids: HashSet<CodeId>,
}

struct AttachmentDownloadClaim {
    recipient_code_id: CodeId,
    created_at_ms: u64,
}

impl Drop for AttachmentDownloadClaim {
    fn drop(&mut self) {
        self.recipient_code_id.zeroize();
    }
}

impl Drop for AttachmentRecord {
    fn drop(&mut self) {
        self.chat_id.zeroize();
        self.media_type.zeroize();
        self.owner_code_id.zeroize();
        for mut code_id in self.eligible_recipient_code_ids.drain() {
            code_id.zeroize();
        }
        for (_, mut claim) in self.download_claims.drain() {
            claim.recipient_code_id.zeroize();
        }
        for mut code_id in self.completed_recipient_code_ids.drain() {
            code_id.zeroize();
        }
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
            Self::Registration {
                code_id, challenge, ..
            } => {
                code_id.zeroize();
                challenge.zeroize();
            }
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
struct OpaqueAccountFinishRequest {
    handshake_id: Uuid,
    registration_upload_b64: Option<String>,
    credential_finalization_b64: Option<String>,
    identity_public_b64: Option<String>,
    identity_prekey_id: Option<String>,
    identity_envelope_b64: Option<String>,
    identity_proof_b64: Option<String>,
}

impl Drop for OpaqueAccountFinishRequest {
    fn drop(&mut self) {
        self.registration_upload_b64.zeroize();
        self.credential_finalization_b64.zeroize();
        self.identity_public_b64.zeroize();
        self.identity_prekey_id.zeroize();
        self.identity_envelope_b64.zeroize();
        self.identity_proof_b64.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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

#[derive(Deserialize, Serialize)]
struct WsTicketResponse {
    ticket: String,
    expires_in_sec: u64,
}

#[derive(Serialize)]
struct OpaqueAccountStartResponse {
    accepted: bool,
    mode: Option<&'static str>,
    handshake_id: Option<Uuid>,
    response_b64: Option<String>,
    challenge_b64: Option<String>,
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
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
        envelopes: Vec<InboundRecipientEnvelope>,
        state_revision: u64,
        identity_envelope_b64: String,
        identity_public_b64: String,
        prekey_id: String,
        state_signature_b64: String,
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
        state_signature_b64: String,
        ack_signature_b64: String,
        used_prekey_id: String,
    },
    #[serde(rename = "identity_state")]
    IdentityState {
        state_revision: u64,
        identity_envelope_b64: String,
        identity_public_b64: String,
        prekey_id: String,
        state_signature_b64: String,
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
#[serde(deny_unknown_fields)]
struct InboundRecipientEnvelope {
    recipient_username: String,
    wrapped_key_b64: String,
    prekey_id: String,
    is_prekey: bool,
    signature_b64: String,
}

impl Drop for InboundRecipientEnvelope {
    fn drop(&mut self) {
        self.recipient_username.zeroize();
        self.wrapped_key_b64.zeroize();
        self.prekey_id.zeroize();
        self.signature_b64.zeroize();
    }
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
        identity_public_b64: String,
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
    #[serde(rename = "message_result")]
    MessageResult { message_id: String, accepted: bool },
    #[serde(rename = "ack_result")]
    AckResult { message_id: String, accepted: bool },
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
            identity_public_b64,
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
            identity_public_b64.zeroize();
        }
        if let Self::MessageResult { message_id, .. } | Self::AckResult { message_id, .. } = self {
            message_id.zeroize();
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

fn configured_bind_addr() -> SocketAddr {
    env::var("ABYSSAL_BIND_ADDR")
        .or_else(|_| env::var("MIRAGE_BIND_ADDR"))
        .unwrap_or_else(|_| "0.0.0.0:4020".to_string())
        .parse()
        .expect("ABYSSAL_BIND_ADDR must be a valid socket address")
}

fn healthcheck_response_is_healthy(response: &[u8]) -> bool {
    response.starts_with(b"HTTP/1.1 200 ")
        && response
            .windows(b"\"ok\":true".len())
            .any(|window| window == b"\"ok\":true")
}

async fn healthcheck(bind_addr: SocketAddr) -> bool {
    let health_addr = env::var("ABYSSAL_HEALTHCHECK_ADDR")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bind_addr.port()));
    let Ok(Ok(mut stream)) =
        tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(health_addr)).await
    else {
        return false;
    };
    let request = b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    if tokio::time::timeout(Duration::from_secs(2), stream.write_all(request))
        .await
        .is_err()
    {
        return false;
    }
    let result = tokio::time::timeout(Duration::from_secs(2), async {
        let mut response = Vec::with_capacity(512);
        let mut buffer = [0_u8; 512];
        loop {
            let read = stream.read(&mut buffer).await?;
            if read == 0 {
                return Ok::<bool, io::Error>(healthcheck_response_is_healthy(&response));
            }
            response.extend_from_slice(&buffer[..read]);
            if healthcheck_response_is_healthy(&response) {
                return Ok::<bool, io::Error>(true);
            }
            if response.len() >= 4096 {
                return Ok::<bool, io::Error>(false);
            }
        }
    })
    .await;
    matches!(result, Ok(Ok(true)))
}

#[tokio::main]
async fn main() {
    let configured_bind_addr = configured_bind_addr();
    if env::args().nth(1).as_deref() == Some("--healthcheck") {
        let healthy = healthcheck(configured_bind_addr).await;
        std::process::exit(i32::from(!healthy));
    }
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

    let bind_addr = configured_bind_addr;

    let account_routes = Router::new()
        .route("/v2/account/start", post(start_opaque_account))
        .route("/v2/account/finish", post(finish_opaque_account))
        .route("/v1/ws-ticket", post(issue_ws_ticket))
        .route("/v1/account/logout", post(logout_account))
        .layer(DefaultBodyLimit::max(ACCOUNT_BODY_LIMIT_BYTES));
    let attachment_upload_routes = Router::new().route("/v1/attachment", post(upload_attachment));
    let attachment_download_routes = Router::new()
        .route(
            "/v1/attachment/:id",
            get(download_attachment).delete(delete_attachment),
        )
        .route(
            "/v1/attachment/:id/complete",
            post(complete_attachment_claim),
        )
        .route("/v1/attachment/:id/claim", delete(release_attachment_claim));
    let attachment_routes = attachment_upload_routes.merge(attachment_download_routes);

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
                .allow_methods([Method::DELETE, Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([
                    header::AUTHORIZATION,
                    header::CONTENT_TYPE,
                    header::HeaderName::from_static(ATTACHMENT_CLAIM_HEADER),
                ])
                .expose_headers([header::HeaderName::from_static(ATTACHMENT_CLAIM_HEADER)])
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
        let (purge_epoch, _) = watch::channel(0_u64);
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
        let attachment_ram_limit_bytes = read_usize_env("ABYSSAL_ATTACHMENT_RAM_LIMIT_MB", 512)
            .saturating_mul(1024 * 1024)
            .min(Semaphore::MAX_PERMITS);
        let attachment_account_limit_bytes = read_usize_env(
            "ABYSSAL_ATTACHMENT_ACCOUNT_LIMIT_MB",
            DEFAULT_ATTACHMENT_ACCOUNT_LIMIT_MB,
        )
        .saturating_mul(1024 * 1024)
        .min(attachment_ram_limit_bytes);
        let (attachment_record_limit, attachment_account_record_limit) =
            attachment_record_limits_from_values(
                env::var("ABYSSAL_ATTACHMENT_RECORD_LIMIT").ok().as_deref(),
                env::var("ABYSSAL_ATTACHMENT_ACCOUNT_RECORD_LIMIT")
                    .ok()
                    .as_deref(),
            );
        let attachment_max_lifetime_sec = read_usize_env(
            "ABYSSAL_ATTACHMENT_MAX_LIFETIME_HOURS",
            DEFAULT_ATTACHMENT_MAX_LIFETIME_HOURS,
        )
        .clamp(
            MIN_ATTACHMENT_MAX_LIFETIME_HOURS,
            MAX_ATTACHMENT_MAX_LIFETIME_HOURS,
        )
        .saturating_mul(60 * 60) as u64;
        let attachment_download_concurrency = read_usize_env(
            "ABYSSAL_ATTACHMENT_DOWNLOAD_CONCURRENCY",
            DEFAULT_ATTACHMENT_DOWNLOAD_CONCURRENCY,
        )
        .clamp(1, MAX_ATTACHMENT_DOWNLOAD_CONCURRENCY);
        let attachment_upload_concurrency = read_usize_env(
            "ABYSSAL_ATTACHMENT_UPLOAD_CONCURRENCY",
            DEFAULT_ATTACHMENT_UPLOAD_CONCURRENCY,
        )
        .clamp(1, MAX_ATTACHMENT_UPLOAD_CONCURRENCY);
        let max_rooms_per_user = read_usize_env("ABYSSAL_MAX_ROOMS_PER_USER", 5).clamp(1, 100);
        let pending_message_ttl_ms = pending_message_ttl_ms_from_env();
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
            attachment_account_limit_bytes,
            attachment_record_limit,
            attachment_account_record_limit,
            attachment_max_lifetime_sec,
            max_rooms_per_user,
            conversation_ops: Arc::new(Mutex::new(())),
            pending_message_ttl_ms,
            web_origins,
            session_inactivity_ms,
            inactivity_limit_ms,
            last_activity_ms: Arc::new(Mutex::new(now_ms())),
            account_ops: Arc::new(Mutex::new(())),
            opaque_setup: Arc::new(Zeroizing::new(opaque_server_setup())),
            opaque_handshakes: Arc::new(Mutex::new(HashMap::new())),
            invite_code_pepper: Arc::new(Zeroizing::new(invite_code_pepper)),
            boot_codes: Arc::new(Mutex::new(Some(boot_codes))),
            available_codes: Arc::new(Mutex::new(available_codes)),
            accounts: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            ws_tickets: Arc::new(Mutex::new(HashMap::new())),
            active_connections: Arc::new(Mutex::new(HashMap::new())),
            clients: Arc::new(Mutex::new(HashMap::new())),
            purge_epoch,
            outbound_bytes: Arc::new(AtomicUsize::new(0)),
            frame_limits: Arc::new(Mutex::new(HashMap::new())),
            login_limits: Arc::new(Mutex::new(HashMap::new())),
            replay_ids: Arc::new(Mutex::new(HashMap::new())),
            prekey_claims: Arc::new(Mutex::new(HashMap::new())),
            rooms: Arc::new(Mutex::new(HashMap::new())),
            room_catalog: Arc::new(Mutex::new(HashMap::new())),
            direct_catalog: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
            pending_bytes: Arc::new(Mutex::new(0)),
            attachments: Arc::new(Mutex::new(HashMap::new())),
            attachment_bytes_by_code: Arc::new(Mutex::new(HashMap::new())),
            attachment_downloads: Arc::new(Semaphore::new(attachment_download_concurrency)),
            attachment_uploads: Arc::new(Semaphore::new(attachment_upload_concurrency)),
            attachment_memory: Arc::new(Semaphore::new(attachment_ram_limit_bytes)),
            attachment_epoch: Arc::new(AtomicU64::new(0)),
        }
    }

    async fn print_boot_codes(&self) {
        let Some(codes) = self.boot_codes.lock().await.take() else {
            return;
        };
        let codes = BootCodes(codes);
        let print_result = {
            let stdout = io::stdout();
            let mut output = stdout.lock();
            write_boot_codes(&mut output, &codes.0)
        };
        if let Err(error) = print_result {
            drop(codes);
            panic!("failed to print Abyssal startup codes: {error}");
        }
        drop(codes);
        info!(
            "ABYSSAL_ATTACHMENT_RAM_LIMIT bytes={}",
            self.attachment_ram_limit_bytes
        );
        info!(
            "ABYSSAL_ATTACHMENT_ACCOUNT_LIMIT bytes={}",
            self.attachment_account_limit_bytes
        );
        info!(
            "ABYSSAL_ATTACHMENT_RECORD_LIMIT records={}",
            self.attachment_record_limit
        );
        info!(
            "ABYSSAL_ATTACHMENT_ACCOUNT_RECORD_LIMIT records={}",
            self.attachment_account_record_limit
        );
        info!(
            "ABYSSAL_ATTACHMENT_MAX_LIFETIME seconds={}",
            self.attachment_max_lifetime_sec
        );
        info!(
            "ABYSSAL_ATTACHMENT_UPLOAD_CONCURRENCY permits={}",
            self.attachment_uploads.available_permits()
        );
        info!(
            "ABYSSAL_ATTACHMENT_DOWNLOAD_CONCURRENCY permits={}",
            self.attachment_downloads.available_permits()
        );
        info!(
            "ABYSSAL_ROOM_LIMIT max_rooms_per_user={}",
            self.max_rooms_per_user
        );
        info!(
            "ABYSSAL_PENDING_MESSAGE_TTL pending_message_ttl_ms={}",
            self.pending_message_ttl_ms
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

fn write_boot_codes<W: Write>(output: &mut W, codes: &[String]) -> io::Result<()> {
    writeln!(
        output,
        "ABYSSAL RAM-ONLY ACCESS CODES - copy these now; they are not written to disk"
    )?;
    for code in codes {
        writeln!(output, "ABYSSAL_CODE code={code}")?;
    }
    output.flush()
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

fn attachment_record_limits_from_values(
    global: Option<&str>,
    account: Option<&str>,
) -> (usize, usize) {
    let global = global
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(DEFAULT_ATTACHMENT_RECORD_LIMIT)
        .clamp(MIN_ATTACHMENT_RECORD_LIMIT, MAX_ATTACHMENT_RECORD_LIMIT);
    let account = account
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(DEFAULT_ATTACHMENT_ACCOUNT_RECORD_LIMIT)
        .clamp(MIN_ATTACHMENT_RECORD_LIMIT, global);
    (global, account)
}

fn pending_message_ttl_ms_from_env() -> u64 {
    let configured = env::var("ABYSSAL_PENDING_MESSAGE_TTL_HOURS").ok();
    pending_message_ttl_ms_from_value(configured.as_deref())
}

fn pending_message_ttl_ms_from_value(value: Option<&str>) -> u64 {
    let hours = value
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(DEFAULT_PENDING_MESSAGE_TTL_HOURS)
        .clamp(MIN_PENDING_MESSAGE_TTL_HOURS, MAX_PENDING_MESSAGE_TTL_HOURS);
    (hours as u64).saturating_mul(HOURS_TO_MILLISECONDS)
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
    if !matches!(scheme, "http" | "https")
        || !matches!(uri.path(), "" | "/")
        || uri.query().is_some()
        || authority.as_str().contains('@')
        || authority.host().is_empty()
        || (scheme == "http"
            && !matches!(
                authority.host().to_ascii_lowercase().as_str(),
                "localhost" | "127.0.0.1" | "[::1]" | "::1"
            ))
    {
        return Err("web origin rejected".to_string());
    }
    Ok(format!(
        "{}://{}",
        scheme.to_ascii_lowercase(),
        authority.as_str().to_ascii_lowercase()
    ))
}

fn normalized_origin_authority(value: &str) -> Option<String> {
    let uri = value.trim().trim_end_matches('/').parse::<Uri>().ok()?;
    let authority = uri.authority()?;
    if authority.as_str().contains('@') || authority.host().is_empty() {
        return None;
    }
    Some(authority.as_str().to_ascii_lowercase())
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

const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' blob: data:; media-src 'self' blob:; connect-src 'self' https: wss: http://localhost:* http://127.0.0.1:* http://[::1]:* ws://localhost:* ws://127.0.0.1:* ws://[::1]:*; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; worker-src 'none'; manifest-src 'none'";

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

fn zeroize_code_id_set(set: &mut HashSet<CodeId>) {
    for mut code_id in set.drain() {
        code_id.zeroize();
    }
}

fn zeroize_code_id_map<V>(map: &mut HashMap<CodeId, V>) {
    for (mut code_id, value) in map.drain() {
        code_id.zeroize();
        drop(value);
    }
}

fn remove_code_id_map_entry<V>(map: &mut HashMap<CodeId, V>, code_id: &CodeId) {
    if let Some((mut removed_code_id, value)) = map.remove_entry(code_id) {
        removed_code_id.zeroize();
        drop(value);
    }
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
    let stale = limits
        .iter()
        .filter_map(|(candidate, rate)| {
            (now.saturating_sub(rate.window_start_ms) >= LOGIN_RATE_WINDOW_MS).then_some(*candidate)
        })
        .collect::<Vec<_>>();
    for candidate in stale {
        remove_code_id_map_entry(&mut limits, &candidate);
    }
    // Do not evict a live entry to make room for an attacker-controlled new
    // code.  Failing closed preserves every existing code's quota instead of
    // allowing unbounded churn to bypass the limiter.
    if !limits.contains_key(code_id) && limits.len() >= MAX_LOGIN_LIMIT_ENTRIES {
        return false;
    }
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
    let mut limits = state.login_limits.lock().await;
    remove_code_id_map_entry(&mut limits, code_id);
}

async fn known_code_id(state: &AppState, code_id: &CodeId) -> bool {
    if state.accounts.lock().await.contains_key(code_id) {
        return true;
    }
    state.available_codes.lock().await.contains(code_id)
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
    let mut usage = state.attachment_bytes_by_code.lock().await;
    let before = attachments.len();
    attachments.retain(|_, record| {
        record
            .download_claims
            .retain(|_, claim| now.saturating_sub(claim.created_at_ms) < ATTACHMENT_CLAIM_TTL_MS);
        if record.expires_at_ms.is_none_or(|expires| now < expires)
            || !record.download_claims.is_empty()
        {
            true
        } else {
            subtract_attachment_usage(&mut usage, &record.owner_code_id, record.blob.bytes.len());
            false
        }
    });
    let removed = before.saturating_sub(attachments.len());
    if removed > 0 {
        info!("expired_attachments_removed count={removed}");
    }
}

async fn remove_chat_attachments(state: &AppState, chat_id: &str) {
    let mut attachments = state.attachments.lock().await;
    let mut usage = state.attachment_bytes_by_code.lock().await;
    attachments.retain(|_, record| {
        if record.chat_id != chat_id {
            true
        } else {
            subtract_attachment_usage(&mut usage, &record.owner_code_id, record.blob.bytes.len());
            false
        }
    });
}

async fn session_sweeper(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let _conversation_guard = state.conversation_ops.lock().await;
        let now = now_ms();
        let mut sessions = state.sessions.lock().await;
        let before = sessions.len();
        sessions
            .retain(|_, session| !session_is_expired(session, now, state.session_inactivity_ms));
        let removed = before.saturating_sub(sessions.len());
        if removed > 0 {
            info!("expired_sessions_removed count={removed}");
        }
        drop(sessions);
        prune_ws_tickets(&state, now).await;
        prune_pending_queues(&state, now).await;
    }
}

async fn prune_pending_queues(state: &AppState, now: u64) {
    let mut pending = state.pending.lock().await;
    let mut pending_bytes = state.pending_bytes.lock().await;
    let mut claims = state.prekey_claims.lock().await;
    let removed = prune_pending_queues_locked(
        &mut pending,
        &mut pending_bytes,
        &mut claims,
        now,
        state.pending_message_ttl_ms,
    );
    drop(claims);
    drop(pending_bytes);
    drop(pending);
    if removed > 0 {
        info!("expired_pending_frames_removed count={removed}");
    }
}

fn prune_pending_queues_locked(
    pending: &mut HashMap<PendingKey, Vec<PendingFrame>>,
    pending_bytes: &mut usize,
    claims: &mut HashMap<PrekeyClaimKey, PrekeyClaim>,
    now: u64,
    pending_message_ttl_ms: u64,
) -> usize {
    let mut expired_claims = Vec::new();
    let mut removed = 0usize;
    for queue in pending.values_mut() {
        let mut retained = Vec::with_capacity(queue.len());
        for mut pending_frame in queue.drain(..) {
            if now.saturating_sub(pending_frame.enqueued_at_ms) >= pending_message_ttl_ms {
                *pending_bytes =
                    (*pending_bytes).saturating_sub(outbound_frame_bytes(&pending_frame.frame));
                if let Some(details) = prekey_claim_details(&pending_frame.frame) {
                    expired_claims.push(details);
                }
                pending_frame.zeroize_sensitive();
                removed = removed.saturating_add(1);
            } else {
                retained.push(pending_frame);
            }
        }
        *queue = retained;
    }
    pending.retain(|_, queue| !queue.is_empty());

    for mut details in expired_claims {
        release_prekey_claim_details_locked(claims, &mut details);
    }
    prune_prekey_claims(claims, pending, now);
    removed
}

fn release_prekey_claim_details_locked(
    claims: &mut HashMap<PrekeyClaimKey, PrekeyClaim>,
    details: &mut (String, String, String, String),
) {
    let (chat_id, message_id, sender_username, prekey_id) = details;
    claims.retain(|key, claim| {
        !(claim.chat_id == *chat_id
            && claim.message_id == *message_id
            && claim.sender_username == *sender_username
            && key.prekey_id == *prekey_id)
    });
    chat_id.zeroize();
    message_id.zeroize();
    sender_username.zeroize();
    prekey_id.zeroize();
}

fn pending_contains_prekey_frame(
    pending: &HashMap<PendingKey, Vec<PendingFrame>>,
    key: &PrekeyClaimKey,
    claim: &PrekeyClaim,
) -> bool {
    pending.iter().any(|(pending_key, frames)| {
        pending_key.recipient_username == claim.recipient_username
            && frames.iter().any(|pending_frame| {
                matches!(
                    &pending_frame.frame,
                    OutboundFrame::Message {
                        chat_id,
                        message_id,
                        prekey_id,
                        is_prekey: true,
                        sender_username,
                        ..
                    } if chat_id == &claim.chat_id
                        && message_id == &claim.message_id
                        && sender_username == &claim.sender_username
                        && prekey_id == &key.prekey_id
                )
            })
    })
}

fn prune_prekey_claims(
    claims: &mut HashMap<PrekeyClaimKey, PrekeyClaim>,
    pending: &HashMap<PendingKey, Vec<PendingFrame>>,
    now: u64,
) {
    claims.retain(|key, claim| {
        now.saturating_sub(claim.created_at_ms) < PREKEY_CLAIM_TTL_MS
            || pending_contains_prekey_frame(pending, key, claim)
    });
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

fn max_serialized_attachment_bytes(media_type: &str) -> usize {
    let plain_limit = match media_type {
        "IMAGE" => IMAGE_ATTACHMENT_LIMIT_BYTES,
        "VIDEO" => VIDEO_ATTACHMENT_LIMIT_BYTES,
        _ => FILE_ATTACHMENT_LIMIT_BYTES,
    };
    plain_limit.saturating_add(ATTACHMENT_WIRE_OVERHEAD_BYTES)
}

fn encrypted_attachment_limit_bytes(media_type: &str) -> usize {
    max_serialized_attachment_bytes(media_type)
}

fn valid_encrypted_attachment_body(body: &[u8]) -> bool {
    body.len() >= ATTACHMENT_WIRE_OVERHEAD_BYTES && body.first() == Some(&ATTACHMENT_BLOB_VERSION)
}

fn declared_attachment_length(headers: &HeaderMap, max_bytes: usize) -> Result<usize, StatusCode> {
    let value = headers
        .get(header::CONTENT_LENGTH)
        .ok_or(StatusCode::LENGTH_REQUIRED)?;
    let length = value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|length| *length > 0)
        .ok_or(StatusCode::LENGTH_REQUIRED)?;
    if length > max_bytes {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    Ok(length)
}

async fn read_bounded_attachment_body(
    body: Body,
    max_bytes: usize,
    declared_length: Option<usize>,
) -> Result<Zeroizing<Vec<u8>>, StatusCode> {
    read_bounded_attachment_body_with_timeout(
        body,
        max_bytes,
        declared_length,
        ATTACHMENT_UPLOAD_IDLE_TIMEOUT,
    )
    .await
}

async fn read_bounded_attachment_body_with_timeout(
    body: Body,
    max_bytes: usize,
    declared_length: Option<usize>,
    idle_timeout: Duration,
) -> Result<Zeroizing<Vec<u8>>, StatusCode> {
    read_bounded_attachment_body_with_timeouts(
        body,
        max_bytes,
        declared_length,
        idle_timeout,
        ATTACHMENT_UPLOAD_TOTAL_TIMEOUT,
    )
    .await
}

async fn read_bounded_attachment_body_with_timeouts(
    body: Body,
    max_bytes: usize,
    declared_length: Option<usize>,
    idle_timeout: Duration,
    total_timeout: Duration,
) -> Result<Zeroizing<Vec<u8>>, StatusCode> {
    tokio::time::timeout(total_timeout, async move {
        let initial_capacity = declared_length
            .unwrap_or(ATTACHMENT_DOWNLOAD_CHUNK_BYTES)
            .min(max_bytes);
        let mut encrypted_body = Zeroizing::new(Vec::with_capacity(initial_capacity));
        let mut stream = body.into_data_stream();
        loop {
            let next = tokio::time::timeout(idle_timeout, stream.next())
                .await
                .map_err(|_| StatusCode::REQUEST_TIMEOUT)?;
            let Some(chunk) = next else {
                break;
            };
            let chunk = chunk.map_err(|_| StatusCode::BAD_REQUEST)?;
            let next_len = encrypted_body
                .len()
                .checked_add(chunk.len())
                .ok_or(StatusCode::PAYLOAD_TOO_LARGE)?;
            if declared_length.is_some_and(|declared| next_len > declared) {
                return Err(StatusCode::BAD_REQUEST);
            }
            if next_len > max_bytes {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            let capacity = encrypted_body.capacity();
            if capacity < next_len {
                let target_capacity = capacity.saturating_mul(2).max(next_len).min(max_bytes);
                encrypted_body.reserve_exact(target_capacity - capacity);
            }
            encrypted_body.extend_from_slice(&chunk);
        }
        if encrypted_body.is_empty() {
            return Err(StatusCode::BAD_REQUEST);
        }
        if declared_length.is_some_and(|declared| declared != encrypted_body.len()) {
            return Err(StatusCode::BAD_REQUEST);
        }
        Ok(encrypted_body)
    })
    .await
    .map_err(|_| StatusCode::REQUEST_TIMEOUT)?
}

async fn attachment_conversation_access(
    state: &AppState,
    username: &str,
    chat_id: &str,
    media_type: &str,
) -> Result<ConversationAccess, StatusCode> {
    if !valid_chat_id(chat_id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let Some(access) = conversation_access(state, username, chat_id).await else {
        return Err(StatusCode::FORBIDDEN);
    };
    if matches!(&access, ConversationAccess::Room(room) if !room_allows_media(room, media_type)) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(access)
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

async fn snapshot_attachment_recipients(
    state: &AppState,
    access: &ConversationAccess,
    chat_id: &str,
    owner_username: &str,
    owner_code_id: &CodeId,
) -> HashSet<CodeId> {
    let peer_username = if matches!(access, ConversationAccess::Direct) {
        state
            .direct_catalog
            .lock()
            .await
            .get(chat_id)
            .and_then(|direct| direct.peer_for(owner_username))
    } else {
        None
    };
    state
        .accounts
        .lock()
        .await
        .iter()
        .filter(|(code_id, account)| {
            **code_id != *owner_code_id
                && match (&access, &peer_username) {
                    (ConversationAccess::Room(_), _) => true,
                    (ConversationAccess::Direct, Some(peer)) => account.username == *peer,
                    (ConversationAccess::Direct, None) => false,
                }
        })
        .map(|(code_id, _)| *code_id)
        .collect()
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
    max_lifetime_sec: u64,
) -> u64 {
    let requested = requested.unwrap_or_default().min(86_400);
    let effective = if let ConversationAccess::Room(room) = access {
        let enforced = enforced_attachment_ttl_sec(room, media_type);
        match (requested, enforced) {
            (0, enforced) => enforced,
            (requested, 0) => requested,
            (requested, enforced) => requested.min(enforced),
        }
    } else {
        requested
    };
    // Even an explicit zero/no-expiry request gets a finite relay-side
    // lifetime.  Room policy can still shorten this value, never extend it.
    if effective == 0 {
        max_lifetime_sec
    } else {
        effective.min(max_lifetime_sec)
    }
}

fn current_attachment_bytes(attachments: &HashMap<Uuid, AttachmentRecord>) -> usize {
    attachments
        .values()
        .map(|record| record.blob.bytes.len())
        .sum()
}

fn current_attachment_records_for_owner(
    attachments: &HashMap<Uuid, AttachmentRecord>,
    owner_code_id: &CodeId,
) -> usize {
    attachments
        .values()
        .filter(|record| record.owner_code_id == *owner_code_id)
        .count()
}

fn attachment_record_capacity_allows(
    used_total: usize,
    used_account: usize,
    total_limit: usize,
    account_limit: usize,
) -> bool {
    used_total < total_limit && used_account < account_limit
}

async fn attachment_record_capacity_available(state: &AppState, owner_code_id: &CodeId) -> bool {
    prune_expired_attachments(state).await;
    let attachments = state.attachments.lock().await;
    attachment_record_capacity_allows(
        attachments.len(),
        current_attachment_records_for_owner(&attachments, owner_code_id),
        state.attachment_record_limit,
        state.attachment_account_record_limit,
    )
}

fn subtract_attachment_usage(
    usage: &mut HashMap<CodeId, usize>,
    owner_code_id: &CodeId,
    bytes: usize,
) {
    let Some(current) = usage.get_mut(owner_code_id) else {
        return;
    };
    if *current <= bytes {
        if let Some((mut removed_code_id, _)) = usage.remove_entry(owner_code_id) {
            removed_code_id.zeroize();
        }
    } else {
        *current -= bytes;
    }
}

fn attachment_capacity_allows(
    used_total: usize,
    used_account: usize,
    incoming: usize,
    total_limit: usize,
    account_limit: usize,
) -> bool {
    used_total
        .checked_add(incoming)
        .is_some_and(|total| total <= total_limit)
        && used_account
            .checked_add(incoming)
            .is_some_and(|account| account <= account_limit)
}

fn acquire_attachment_download_permit(
    downloads: &Arc<Semaphore>,
) -> Result<OwnedSemaphorePermit, StatusCode> {
    downloads
        .clone()
        .try_acquire_owned()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)
}

fn acquire_attachment_upload_permit(
    uploads: &Arc<Semaphore>,
) -> Result<OwnedSemaphorePermit, StatusCode> {
    uploads
        .clone()
        .try_acquire_owned()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)
}

async fn acquire_account_attachment_upload_permit(
    state: &AppState,
    code_id: &CodeId,
) -> Result<OwnedSemaphorePermit, StatusCode> {
    let uploads = state
        .accounts
        .lock()
        .await
        .get(code_id)
        .map(|account| Arc::clone(&account.attachment_uploads))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    uploads
        .try_acquire_owned()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)
}

fn acquire_attachment_memory_permit(
    memory: &Arc<Semaphore>,
    bytes: usize,
) -> Result<OwnedSemaphorePermit, StatusCode> {
    if bytes == 0 || bytes > u32::MAX as usize {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    memory
        .clone()
        .try_acquire_many_owned(bytes as u32)
        .map_err(|_| StatusCode::from_u16(507).unwrap_or(StatusCode::SERVICE_UNAVAILABLE))
}

struct AttachmentDownloadReservation {
    blob: Arc<AttachmentBlob>,
    claim_id: Option<Uuid>,
    epoch: u64,
}

async fn reserve_attachment_download(
    state: &AppState,
    attachment_id: Uuid,
    requester_code_id: &CodeId,
) -> Result<AttachmentDownloadReservation, StatusCode> {
    prune_expired_attachments(state).await;
    let mut attachments = state.attachments.lock().await;
    let mut usage = state.attachment_bytes_by_code.lock().await;
    let Some(record) = attachments.get_mut(&attachment_id) else {
        return Err(StatusCode::NOT_FOUND);
    };
    if record
        .expires_at_ms
        .is_some_and(|expires| now_ms() >= expires)
    {
        if !record.download_claims.is_empty() {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        let owner_code_id = record.owner_code_id;
        let encrypted_len = record.blob.bytes.len();
        attachments.remove(&attachment_id);
        subtract_attachment_usage(&mut usage, &owner_code_id, encrypted_len);
        return Err(StatusCode::NOT_FOUND);
    }

    let destructive = record.one_time || record.delete_after_download;
    let claim_id = if !destructive || *requester_code_id == record.owner_code_id {
        None
    } else {
        if !record
            .eligible_recipient_code_ids
            .contains(requester_code_id)
        {
            return Err(StatusCode::FORBIDDEN);
        }
        if record
            .completed_recipient_code_ids
            .contains(requester_code_id)
        {
            return Err(StatusCode::NOT_FOUND);
        }
        if record
            .download_claims
            .values()
            .any(|claim| claim.recipient_code_id == *requester_code_id)
        {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        let claim_id = loop {
            let candidate = Uuid::new_v4();
            if !record.download_claims.contains_key(&candidate) {
                break candidate;
            }
        };
        record.download_claims.insert(
            claim_id,
            AttachmentDownloadClaim {
                recipient_code_id: *requester_code_id,
                created_at_ms: now_ms(),
            },
        );
        Some(claim_id)
    };
    Ok(AttachmentDownloadReservation {
        blob: Arc::clone(&record.blob),
        claim_id,
        epoch: state.attachment_epoch.load(Ordering::Acquire),
    })
}

async fn complete_attachment_download_claim(
    state: &AppState,
    attachment_id: Uuid,
    requester_code_id: &CodeId,
    claim_id: Uuid,
) -> Result<(), StatusCode> {
    let mut attachments = state.attachments.lock().await;
    let mut usage = state.attachment_bytes_by_code.lock().await;
    let Some(record) = attachments.get_mut(&attachment_id) else {
        return Err(StatusCode::NOT_FOUND);
    };
    let Some(claim) = record.download_claims.get(&claim_id) else {
        return Err(StatusCode::NOT_FOUND);
    };
    let claim_recipient_code_id = claim.recipient_code_id;
    if claim_recipient_code_id != *requester_code_id {
        return Err(StatusCode::FORBIDDEN);
    }
    if now_ms().saturating_sub(claim.created_at_ms) >= ATTACHMENT_CLAIM_TTL_MS {
        record.download_claims.remove(&claim_id);
        return Err(StatusCode::NOT_FOUND);
    }
    record.download_claims.remove(&claim_id);
    record
        .completed_recipient_code_ids
        .insert(claim_recipient_code_id);
    if record
        .eligible_recipient_code_ids
        .is_subset(&record.completed_recipient_code_ids)
    {
        let Some(record) = attachments.remove(&attachment_id) else {
            return Err(StatusCode::NOT_FOUND);
        };
        subtract_attachment_usage(&mut usage, &record.owner_code_id, record.blob.bytes.len());
    }
    Ok(())
}

async fn release_attachment_download_claim(
    state: &AppState,
    attachment_id: Uuid,
    requester_code_id: &CodeId,
    claim_id: Uuid,
) -> Result<(), StatusCode> {
    let mut attachments = state.attachments.lock().await;
    let Some(record) = attachments.get_mut(&attachment_id) else {
        return Err(StatusCode::NOT_FOUND);
    };
    let Some(claim) = record.download_claims.get(&claim_id) else {
        return Err(StatusCode::NOT_FOUND);
    };
    if claim.recipient_code_id != *requester_code_id {
        return Err(StatusCode::FORBIDDEN);
    }
    record.download_claims.remove(&claim_id);
    Ok(())
}

#[cfg(test)]
fn attachment_download_response(
    bytes: Vec<u8>,
    permit: OwnedSemaphorePermit,
    claim_id: Option<Uuid>,
) -> Response {
    attachment_download_response_with_timeout(
        bytes,
        permit,
        claim_id,
        ATTACHMENT_DOWNLOAD_STALL_TIMEOUT,
    )
}

#[cfg(test)]
fn attachment_download_response_with_timeout(
    bytes: Vec<u8>,
    permit: OwnedSemaphorePermit,
    claim_id: Option<Uuid>,
    stall_timeout: Duration,
) -> Response {
    attachment_download_response_with_epoch(
        Arc::new(AttachmentBlob {
            bytes: Zeroizing::new(bytes),
            _memory_permit: None,
        }),
        permit,
        claim_id,
        Arc::new(AtomicU64::new(0)),
        0,
        stall_timeout,
    )
}

fn attachment_download_response_with_epoch(
    blob: Arc<AttachmentBlob>,
    permit: OwnedSemaphorePermit,
    claim_id: Option<Uuid>,
    epoch: Arc<AtomicU64>,
    captured_epoch: u64,
    stall_timeout: Duration,
) -> Response {
    let content_length = blob.bytes.len().to_string();
    let (sender, receiver) = mpsc::channel(1);
    let stream_epoch = Arc::clone(&epoch);
    tokio::spawn(async move {
        let mut offset = 0usize;
        while offset < blob.bytes.len() {
            if epoch.load(Ordering::Acquire) != captured_epoch {
                return;
            }
            let end = offset
                .saturating_add(ATTACHMENT_DOWNLOAD_CHUNK_BYTES)
                .min(blob.bytes.len());
            let chunk = Bytes::copy_from_slice(&blob.bytes[offset..end]);
            let sent = tokio::time::timeout(stall_timeout, sender.send(chunk)).await;
            if !matches!(sent, Ok(Ok(()))) {
                return;
            }
            offset = end;
        }
        drop(sender);
        drop(permit);
    });
    let stream = futures_util::stream::unfold(
        (receiver, stream_epoch, captured_epoch),
        |(mut receiver, epoch, captured_epoch)| async move {
            let chunk = receiver.recv().await?;
            if epoch.load(Ordering::Acquire) != captured_epoch {
                return None;
            }
            Some((
                Ok::<Bytes, Infallible>(chunk),
                (receiver, epoch, captured_epoch),
            ))
        },
    );
    let mut response = Response::new(Body::from_stream(stream));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Ok(value) = HeaderValue::from_str(&content_length) {
        response.headers_mut().insert(header::CONTENT_LENGTH, value);
    }
    if let Some(claim_id) = claim_id {
        if let Ok(value) = HeaderValue::from_str(&claim_id.to_string()) {
            response.headers_mut().insert(
                header::HeaderName::from_static(ATTACHMENT_CLAIM_HEADER),
                value,
            );
        }
    }
    response
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
    let _account_guard = state.account_ops.lock().await;
    prune_opaque_handshakes(&state).await;
    let code = match normalize_code(&request.code) {
        Ok(code) => Zeroizing::new(code),
        Err(_) => return opaque_start_error(StatusCode::BAD_REQUEST, &state),
    };
    let code_id = derive_code_id(&state.invite_code_pepper[..], &code);
    // Unknown HMAC IDs must not allocate limiter entries. Otherwise an
    // attacker can fill the bounded map with random codes and deny real
    // invite holders even though every request is rejected.
    if !known_code_id(&state, &code_id).await {
        return opaque_start_error(StatusCode::UNAUTHORIZED, &state);
    }
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
                Ok(bytes) => Zeroizing::new(bytes),
                Err(_) => return opaque_start_error(StatusCode::BAD_REQUEST, &state),
            };
        let (server_state, response) = match opaque_server_start_login(
            &state.opaque_setup,
            &account.password_file,
            request_bytes.as_slice(),
            code.as_bytes(),
        ) {
            Ok(result) => result,
            Err(_) => return opaque_start_error(StatusCode::UNAUTHORIZED, &state),
        };
        let response = Zeroizing::new(response);
        if !store_opaque_handshake(
            &state,
            handshake_id,
            OpaqueHandshake::Login {
                code_id,
                username: account.username.clone(),
                server_state,
                created_at_ms: now_ms(),
            },
        )
        .await
        {
            return opaque_start_error(StatusCode::TOO_MANY_REQUESTS, &state);
        }
        touch_activity(&state).await;
        return (
            StatusCode::OK,
            Json(OpaqueAccountStartResponse {
                accepted: true,
                mode: Some("login"),
                handshake_id: Some(handshake_id),
                response_b64: Some(URL_SAFE_NO_PAD.encode(response.as_slice())),
                challenge_b64: None,
                node_id: state.node_id.clone(),
                identity_public_b64: Some(URL_SAFE_NO_PAD.encode(&account.identity_public)),
                identity_prekey_id: Some(account.prekey_id.clone()),
                identity_envelope_b64: Some(URL_SAFE_NO_PAD.encode(&account.identity_envelope)),
                error: None,
            }),
        );
    }

    let request_bytes =
        match decode_bounded(&request.registration_request_b64, ACCOUNT_BODY_LIMIT_BYTES) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(_) => return opaque_start_error(StatusCode::BAD_REQUEST, &state),
        };
    let response = match opaque_server_registration_response(
        &state.opaque_setup,
        request_bytes.as_slice(),
        code.as_bytes(),
    ) {
        Ok(response) => response,
        Err(_) => return opaque_start_error(StatusCode::UNAUTHORIZED, &state),
    };
    let response = Zeroizing::new(response);
    let mut challenge = Zeroizing::new(vec![0_u8; REGISTRATION_CHALLENGE_BYTES_V8]);
    OsRng.fill_bytes(&mut challenge);
    if !store_opaque_handshake(
        &state,
        handshake_id,
        OpaqueHandshake::Registration {
            code_id,
            challenge: challenge.clone(),
            created_at_ms: now_ms(),
        },
    )
    .await
    {
        return opaque_start_error(StatusCode::TOO_MANY_REQUESTS, &state);
    }
    touch_activity(&state).await;
    (
        StatusCode::OK,
        Json(OpaqueAccountStartResponse {
            accepted: true,
            mode: Some("registration"),
            handshake_id: Some(handshake_id),
            response_b64: Some(URL_SAFE_NO_PAD.encode(response.as_slice())),
            challenge_b64: Some(URL_SAFE_NO_PAD.encode(challenge.as_slice())),
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
        OpaqueHandshake::Registration {
            code_id, challenge, ..
        } => {
            if !opaque_finish_request_is_registration(&request) {
                return account_error(StatusCode::BAD_REQUEST, &state, String::new()).await;
            }
            if state.accounts.lock().await.contains_key(code_id)
                || !state.available_codes.lock().await.contains(code_id)
            {
                return account_error(StatusCode::CONFLICT, &state, String::new()).await;
            }
            let upload = match request
                .registration_upload_b64
                .as_deref()
                .ok_or(())
                .and_then(|value| {
                    decode_bounded(value, ACCOUNT_BODY_LIMIT_BYTES)
                        .map(Zeroizing::new)
                        .map_err(|_| ())
                }) {
                Ok(value) => value,
                Err(_) => {
                    return account_error(StatusCode::BAD_REQUEST, &state, String::new()).await
                }
            };
            let mut identity_public = match request
                .identity_public_b64
                .as_deref()
                .ok_or(())
                .and_then(|value| {
                    decode_exact(value, IDENTITY_PUBLIC_BYTES)
                        .map(Zeroizing::new)
                        .map_err(|_| ())
                }) {
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
            let mut identity_envelope = match request
                .identity_envelope_b64
                .as_deref()
                .ok_or(())
                .and_then(|value| {
                    decode_bounded(value, MAX_IDENTITY_ENVELOPE_BYTES)
                        .map(Zeroizing::new)
                        .map_err(|_| ())
                }) {
                Ok(value) if !value.is_empty() => value,
                _ => return account_error(StatusCode::BAD_REQUEST, &state, String::new()).await,
            };
            let proof = match request
                .identity_proof_b64
                .as_deref()
                .ok_or(())
                .and_then(|value| {
                    decode_exact(value, MESSAGE_SIGNATURE_BYTES)
                        .map(Zeroizing::new)
                        .map_err(|_| ())
                }) {
                Ok(value) => value,
                Err(_) => {
                    return account_error(StatusCode::BAD_REQUEST, &state, String::new()).await
                }
            };
            if verify_registration_identity_proof_v8(
                &state.node_id,
                &request.handshake_id.to_string(),
                challenge,
                upload.as_slice(),
                identity_public.as_slice(),
                &prekey_id,
                identity_envelope.as_slice(),
                proof.as_slice(),
            )
            .is_err()
            {
                return account_error(StatusCode::UNAUTHORIZED, &state, String::new()).await;
            }
            let password_file = match opaque_server_finish_registration(upload.as_slice()) {
                Ok(value) => value,
                Err(_) => {
                    return account_error(StatusCode::UNAUTHORIZED, &state, String::new()).await
                }
            };
            if let Some(mut removed_code_id) = state.available_codes.lock().await.take(code_id) {
                removed_code_id.zeroize();
            }
            let mut accounts = state.accounts.lock().await;
            let username = random_unique_username(&accounts);
            accounts.insert(
                *code_id,
                Account {
                    username: username.clone(),
                    password_file,
                    identity_public: std::mem::take(&mut *identity_public),
                    identity_envelope: std::mem::take(&mut *identity_envelope),
                    prekey_id,
                    state_revision: 0,
                    state_revision_window: 1,
                    connected: false,
                    attachment_uploads: Arc::new(Semaphore::new(
                        MAX_ATTACHMENT_UPLOADS_PER_ACCOUNT,
                    )),
                },
            );
            drop(accounts);
            clear_login_limit(&state, code_id).await;
            info!("opaque_account_created");
            let response = issue_session(&state, *code_id, username, true).await;
            if response.0.is_success() {
                touch_activity(&state).await;
            }
            response
        }
        OpaqueHandshake::Login {
            code_id,
            username,
            server_state,
            ..
        } => {
            if !opaque_finish_request_is_login(&request) {
                return account_error(StatusCode::BAD_REQUEST, &state, String::new()).await;
            }
            let finalization = match request
                .credential_finalization_b64
                .as_deref()
                .ok_or(())
                .and_then(|value| {
                    decode_bounded(value, ACCOUNT_BODY_LIMIT_BYTES)
                        .map(Zeroizing::new)
                        .map_err(|_| ())
                }) {
                Ok(value) => value,
                Err(_) => {
                    return account_error(StatusCode::BAD_REQUEST, &state, String::new()).await
                }
            };
            if opaque_server_finish_login(server_state, finalization.as_slice()).is_err() {
                return account_error(StatusCode::UNAUTHORIZED, &state, String::new()).await;
            }
            if code_has_active_session(&state, code_id).await {
                return account_error(StatusCode::CONFLICT, &state, String::new()).await;
            }
            clear_login_limit(&state, code_id).await;
            info!("opaque_account_login");
            let response = issue_session(&state, *code_id, username.clone(), false).await;
            if response.0.is_success() {
                touch_activity(&state).await;
            }
            response
        }
    }
}

fn opaque_finish_request_is_registration(request: &OpaqueAccountFinishRequest) -> bool {
    request.registration_upload_b64.is_some()
        && request.credential_finalization_b64.is_none()
        && request.identity_public_b64.is_some()
        && request.identity_prekey_id.is_some()
        && request.identity_envelope_b64.is_some()
        && request.identity_proof_b64.is_some()
}

fn opaque_finish_request_is_login(request: &OpaqueAccountFinishRequest) -> bool {
    request.registration_upload_b64.is_none()
        && request.credential_finalization_b64.is_some()
        && request.identity_public_b64.is_none()
        && request.identity_prekey_id.is_none()
        && request.identity_envelope_b64.is_none()
        && request.identity_proof_b64.is_none()
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
            challenge_b64: None,
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

async fn store_opaque_handshake(state: &AppState, id: Uuid, handshake: OpaqueHandshake) -> bool {
    let now = now_ms();
    let mut handshakes = state.opaque_handshakes.lock().await;
    handshakes.retain(|_, handshake| {
        let created_at_ms = match handshake {
            OpaqueHandshake::Registration { created_at_ms, .. }
            | OpaqueHandshake::Login { created_at_ms, .. } => *created_at_ms,
        };
        now.saturating_sub(created_at_ms) < OPAQUE_HANDSHAKE_TTL_MS
    });
    // A live handshake contains OPAQUE state.  Never evict it to accept an
    // attacker-controlled handshake; the caller returns a bounded failure and
    // dropping this value invokes its zeroizing Drop implementation.
    if handshakes.len() >= MAX_OPAQUE_HANDSHAKES {
        drop(handshake);
        return false;
    }
    handshakes.insert(id, handshake);
    true
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
    validate_core_identity_public_bundle(public_key, Some(prekey_id)).is_ok()
}

async fn replace_connected_clients_for_code(state: &AppState, code_id: &CodeId) {
    let old_clients = state
        .clients
        .lock()
        .await
        .iter()
        .filter_map(|(client_id, client)| {
            if client.code_id == *code_id {
                Some((*client_id, client.control_tx.clone()))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    if old_clients.is_empty() {
        // Logout invalidates the session even when its upgrade has not yet
        // installed a client handle. Do not leave that reservation blocking
        // the next login.
        if let Some((mut removed_code_id, _)) =
            state.active_connections.lock().await.remove_entry(code_id)
        {
            removed_code_id.zeroize();
        }
        return;
    }

    for (_, control_tx) in &old_clients {
        let _ = control_tx.try_send(ClientControl::Close);
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
    let mut active_connections = state.active_connections.lock().await;
    if active_connections
        .get(code_id)
        .is_some_and(|client_id| old_ids.contains(client_id))
    {
        if let Some((mut removed_code_id, _)) = active_connections.remove_entry(code_id) {
            removed_code_id.zeroize();
        }
    }
    drop(active_connections);
    broadcast_presence(state).await;
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|token| !token.is_empty() && token.len() <= 128)
        .map(ToOwned::to_owned)
}

async fn auth_from_headers(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthSession, StatusCode> {
    let token = Zeroizing::new(bearer_token(headers).ok_or(StatusCode::UNAUTHORIZED)?);
    active_session(state, token.as_str(), true)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)
}

fn ws_ticket_digest(value: &str) -> Option<WsTicketDigest> {
    if value.len() != WS_TICKET_B64_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return None;
    }
    let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(value).ok()?);
    if decoded.len() != WS_TICKET_BYTES {
        return None;
    }
    let digest = Sha256::digest(decoded.as_slice());
    let mut result = [0_u8; WS_TICKET_BYTES];
    result.copy_from_slice(&digest);
    Some(result)
}

fn prune_ws_tickets_locked(tickets: &mut HashMap<WsTicketDigest, WsTicket>, now: u64) -> usize {
    let expired = tickets
        .iter()
        .filter(|(_, ticket)| ticket.expires_at_ms <= now)
        .map(|(digest, _)| *digest)
        .collect::<Vec<_>>();
    let removed = expired.len();
    for mut digest in expired {
        if let Some((mut stored_digest, _)) = tickets.remove_entry(&digest) {
            stored_digest.zeroize();
        }
        digest.zeroize();
    }
    removed
}

fn clear_ws_tickets_locked(tickets: &mut HashMap<WsTicketDigest, WsTicket>) {
    for (mut digest, ticket) in tickets.drain() {
        digest.zeroize();
        drop(ticket);
    }
}

async fn clear_ws_tickets_for_session(state: &AppState, session_token: &str) {
    let mut tickets = state.ws_tickets.lock().await;
    let matching = tickets
        .iter()
        .filter(|(_, ticket)| ticket.session_token.as_str() == session_token)
        .map(|(digest, _)| *digest)
        .collect::<Vec<_>>();
    for mut digest in matching {
        if let Some((mut stored_digest, _)) = tickets.remove_entry(&digest) {
            stored_digest.zeroize();
        }
        digest.zeroize();
    }
}

async fn prune_ws_tickets(state: &AppState, now: u64) {
    let mut tickets = state.ws_tickets.lock().await;
    prune_ws_tickets_locked(&mut tickets, now);
}

async fn issue_ws_ticket(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(session_token) = bearer_token(&headers).map(Zeroizing::new) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let _account_guard = state.account_ops.lock().await;
    if active_session(&state, session_token.as_str(), false)
        .await
        .is_none()
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let now = now_ms();
    let mut tickets = state.ws_tickets.lock().await;
    prune_ws_tickets_locked(&mut tickets, now);

    // A session has at most one outstanding ticket. Rotating it also allows
    // an authenticated session to recover when the global cap is full.
    let matching = tickets
        .iter()
        .filter(|(_, ticket)| ticket.session_token.as_str() == session_token.as_str())
        .map(|(digest, _)| *digest)
        .collect::<Vec<_>>();
    for mut digest in matching {
        if let Some((mut stored_digest, _)) = tickets.remove_entry(&digest) {
            stored_digest.zeroize();
        }
        digest.zeroize();
    }
    if tickets.len() >= MAX_WS_TICKETS {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    let (ticket, digest) = loop {
        let mut random = [0_u8; WS_TICKET_BYTES];
        OsRng.fill_bytes(&mut random);
        let ticket = URL_SAFE_NO_PAD.encode(random);
        random.zeroize();
        let Some(digest) = ws_ticket_digest(&ticket) else {
            continue;
        };
        if !tickets.contains_key(&digest) {
            break (ticket, digest);
        }
    };
    tickets.insert(
        digest,
        WsTicket {
            session_token,
            expires_at_ms: now.saturating_add(WS_TICKET_TTL_MS),
        },
    );
    drop(tickets);
    touch_activity(&state).await;

    let mut response = Json(WsTicketResponse {
        ticket,
        expires_in_sec: WS_TICKET_TTL_MS / 1000,
    })
    .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn consume_ws_ticket(
    state: &AppState,
    ticket_value: &str,
) -> Option<(Zeroizing<String>, AuthSession)> {
    let mut digest = ws_ticket_digest(ticket_value)?;
    let ticket = {
        let mut tickets = state.ws_tickets.lock().await;
        prune_ws_tickets_locked(&mut tickets, now_ms());
        let (mut stored_digest, ticket) = tickets.remove_entry(&digest)?;
        stored_digest.zeroize();
        digest.zeroize();
        ticket
    };
    // Removal happens before session validation and before the websocket
    // upgrade, making this ticket single-use even when the upgrade fails.
    let session_token = Zeroizing::new(ticket.session_token.as_str().to_owned());
    drop(ticket);
    let session = active_session(state, session_token.as_str(), true).await?;
    touch_activity(state).await;
    Some((session_token, session))
}

async fn logout_account(State(state): State<AppState>, headers: HeaderMap) -> StatusCode {
    let Some(token) = bearer_token(&headers).map(Zeroizing::new) else {
        return StatusCode::UNAUTHORIZED;
    };
    let _account_guard = state.account_ops.lock().await;
    let session = state.sessions.lock().await.remove(token.as_str());
    let Some(session) = session else {
        return StatusCode::UNAUTHORIZED;
    };

    clear_ws_tickets_for_session(&state, token.as_str()).await;
    replace_connected_clients_for_code(&state, &session.code_id).await;
    touch_activity(&state).await;
    StatusCode::NO_CONTENT
}

async fn upload_attachment(
    State(state): State<AppState>,
    Query(query): Query<AttachmentQuery>,
    headers: HeaderMap,
    body: Body,
) -> impl IntoResponse {
    let upload_epoch = state.attachment_epoch.load(Ordering::Acquire);
    let initial_auth = match auth_from_headers(&state, &headers).await {
        Ok(auth) => auth,
        Err(status) => return status.into_response(),
    };
    let chat_id = query.chat_id.trim().to_string();
    let media_type = normalize_media_type(query.media_type.as_deref());
    let _initial_access =
        match attachment_conversation_access(&state, &initial_auth.username, &chat_id, &media_type)
            .await
        {
            Ok(access) => access,
            Err(status) => return status.into_response(),
        };
    let max_bytes = encrypted_attachment_limit_bytes(&media_type);
    let declared_length = match declared_attachment_length(&headers, max_bytes) {
        Ok(length) => length,
        Err(status) => return status.into_response(),
    };
    if !attachment_record_capacity_available(&state, &initial_auth.code_id).await {
        return StatusCode::from_u16(507)
            .unwrap_or(StatusCode::SERVICE_UNAVAILABLE)
            .into_response();
    }
    let _account_upload_permit =
        match acquire_account_attachment_upload_permit(&state, &initial_auth.code_id).await {
            Ok(permit) => permit,
            Err(status) => return status.into_response(),
        };
    let memory_permit =
        match acquire_attachment_memory_permit(&state.attachment_memory, declared_length) {
            Ok(permit) => permit,
            Err(status) => return status.into_response(),
        };
    let _upload_permit = match acquire_attachment_upload_permit(&state.attachment_uploads) {
        Ok(permit) => permit,
        Err(status) => return status.into_response(),
    };
    let mut encrypted_body =
        match read_bounded_attachment_body(body, max_bytes, Some(declared_length)).await {
            Ok(body) => body,
            Err(status) => return status.into_response(),
        };
    let _conversation_guard = state.conversation_ops.lock().await;
    if state.attachment_epoch.load(Ordering::Acquire) != upload_epoch {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let auth = match auth_from_headers(&state, &headers).await {
        Ok(auth) if auth.code_id == initial_auth.code_id => auth,
        Ok(_) | Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };
    if !valid_encrypted_attachment_body(&encrypted_body) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let access =
        match attachment_conversation_access(&state, &auth.username, &chat_id, &media_type).await {
            Ok(access) => access,
            Err(status) => return status.into_response(),
        };
    let ttl_ms = effective_attachment_ttl_sec(
        query.ttl_sec,
        &access,
        &media_type,
        state.attachment_max_lifetime_sec,
    );
    let ttl_ms = (ttl_ms > 0).then(|| now_ms().saturating_add(ttl_ms.saturating_mul(1000)));
    let one_time = query.one_time.unwrap_or(false);
    let delete_after_download = query.delete_after_download.unwrap_or(one_time);
    let destructive = one_time || delete_after_download;
    let eligible_recipient_code_ids = if destructive {
        snapshot_attachment_recipients(&state, &access, &chat_id, &auth.username, &auth.code_id)
            .await
    } else {
        HashSet::new()
    };
    if destructive && eligible_recipient_code_ids.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    prune_expired_attachments(&state).await;
    let mut attachments = state.attachments.lock().await;
    let mut usage = state.attachment_bytes_by_code.lock().await;
    let used_bytes = current_attachment_bytes(&attachments);
    let account_used = usage.get(&auth.code_id).copied().unwrap_or_default();
    let used_records = attachments.len();
    let account_records = current_attachment_records_for_owner(&attachments, &auth.code_id);
    let encrypted_len = encrypted_body.len();
    if !attachment_capacity_allows(
        used_bytes,
        account_used,
        encrypted_len,
        state.attachment_ram_limit_bytes,
        state.attachment_account_limit_bytes,
    ) {
        warn!(
            "attachment_upload_rejected reason=ram_limit used={} account_used={} incoming={} limit={} account_limit={}",
            used_bytes,
            account_used,
            encrypted_len,
            state.attachment_ram_limit_bytes,
            state.attachment_account_limit_bytes,
        );
        return StatusCode::from_u16(507)
            .unwrap_or(StatusCode::SERVICE_UNAVAILABLE)
            .into_response();
    }
    if !attachment_record_capacity_allows(
        used_records,
        account_records,
        state.attachment_record_limit,
        state.attachment_account_record_limit,
    ) {
        warn!(
            "attachment_upload_rejected reason=record_limit used={} account_used={} limit={} account_limit={}",
            used_records,
            account_records,
            state.attachment_record_limit,
            state.attachment_account_record_limit,
        );
        return StatusCode::from_u16(507)
            .unwrap_or(StatusCode::SERVICE_UNAVAILABLE)
            .into_response();
    }
    let id = Uuid::new_v4();
    attachments.insert(
        id,
        AttachmentRecord {
            blob: Arc::new(AttachmentBlob {
                bytes: std::mem::take(&mut encrypted_body),
                _memory_permit: Some(memory_permit),
            }),
            chat_id,
            media_type,
            owner_code_id: auth.code_id,
            one_time,
            delete_after_download,
            expires_at_ms: ttl_ms,
            eligible_recipient_code_ids,
            download_claims: HashMap::new(),
            completed_recipient_code_ids: HashSet::new(),
        },
    );
    usage.insert(auth.code_id, account_used.saturating_add(encrypted_len));
    drop(attachments);
    drop(usage);
    touch_activity(&state).await;

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
    let _conversation_guard = state.conversation_ops.lock().await;
    let download_permit = match acquire_attachment_download_permit(&state.attachment_downloads) {
        Ok(permit) => permit,
        Err(status) => return status.into_response(),
    };

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

    let reservation = match reserve_attachment_download(&state, id, &auth.code_id).await {
        Ok(reservation) => reservation,
        Err(status) => return status.into_response(),
    };
    info!(
        "attachment_downloaded bytes={}",
        reservation.blob.bytes.len()
    );
    touch_activity(&state).await;

    attachment_download_response_with_epoch(
        Arc::clone(&reservation.blob),
        download_permit,
        reservation.claim_id,
        Arc::clone(&state.attachment_epoch),
        reservation.epoch,
        ATTACHMENT_DOWNLOAD_STALL_TIMEOUT,
    )
}

fn attachment_claim_id(headers: &HeaderMap) -> Result<Uuid, StatusCode> {
    headers
        .get(ATTACHMENT_CLAIM_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value.trim()).ok())
        .ok_or(StatusCode::BAD_REQUEST)
}

async fn complete_attachment_claim(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> StatusCode {
    let auth = match auth_from_headers(&state, &headers).await {
        Ok(auth) => auth,
        Err(status) => return status,
    };
    let claim_id = match attachment_claim_id(&headers) {
        Ok(claim_id) => claim_id,
        Err(status) => return status,
    };
    let _conversation_guard = state.conversation_ops.lock().await;
    match complete_attachment_download_claim(&state, id, &auth.code_id, claim_id).await {
        Ok(()) => {
            touch_activity(&state).await;
            StatusCode::NO_CONTENT
        }
        Err(status) => status,
    }
}

async fn release_attachment_claim(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> StatusCode {
    let auth = match auth_from_headers(&state, &headers).await {
        Ok(auth) => auth,
        Err(status) => return status,
    };
    let claim_id = match attachment_claim_id(&headers) {
        Ok(claim_id) => claim_id,
        Err(status) => return status,
    };
    let _conversation_guard = state.conversation_ops.lock().await;
    match release_attachment_download_claim(&state, id, &auth.code_id, claim_id).await {
        Ok(()) => {
            touch_activity(&state).await;
            StatusCode::NO_CONTENT
        }
        Err(status) => status,
    }
}

async fn delete_attachment(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> StatusCode {
    let auth = match auth_from_headers(&state, &headers).await {
        Ok(auth) => auth,
        Err(status) => return status,
    };
    let _conversation_guard = state.conversation_ops.lock().await;
    let status = delete_owned_attachment(&state, id, &auth.code_id).await;
    if status == StatusCode::NO_CONTENT {
        touch_activity(&state).await;
    }
    status
}

async fn delete_owned_attachment(state: &AppState, id: Uuid, owner_code_id: &CodeId) -> StatusCode {
    let mut attachments = state.attachments.lock().await;
    let Some(record) = attachments.get(&id) else {
        return StatusCode::NOT_FOUND;
    };
    if record.owner_code_id != *owner_code_id {
        return StatusCode::FORBIDDEN;
    }
    let Some(record) = attachments.remove(&id) else {
        return StatusCode::NOT_FOUND;
    };
    drop(attachments);

    let mut usage = state.attachment_bytes_by_code.lock().await;
    subtract_attachment_usage(&mut usage, &record.owner_code_id, record.blob.bytes.len());
    StatusCode::NO_CONTENT
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
    let replaced_tokens = sessions
        .iter()
        .filter(|(_, session)| session.code_id == code_id)
        .map(|(token, _)| token.0.clone())
        .collect::<Vec<_>>();
    sessions.retain(|_, session| session.code_id != code_id);
    sessions.insert(
        SessionToken::new(token.clone()),
        AuthSession {
            code_id,
            username: username.clone(),
            last_activity_ms: now,
        },
    );
    drop(sessions);
    for mut replaced_token in replaced_tokens {
        clear_ws_tickets_for_session(state, &replaced_token).await;
        replaced_token.zeroize();
    }

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
    let Some(ticket) = websocket_ticket_header(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let auth = consume_ws_ticket(&state, ticket.as_str()).await;

    match auth {
        Some((token, session)) => {
            let client_id = Uuid::new_v4();
            let code_id = session.code_id;
            let mut active_connections = state.active_connections.lock().await;
            if !reserve_connection(&mut active_connections, code_id, client_id) {
                return StatusCode::CONFLICT.into_response();
            }
            drop(active_connections);
            let failed_state = state.clone();
            ws.max_frame_size(WS_MAX_FRAME_BYTES)
                .max_message_size(WS_MAX_FRAME_BYTES)
                .protocols([WEB_SOCKET_PROTOCOL])
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

fn websocket_ticket_header(headers: &HeaderMap) -> Option<Zeroizing<String>> {
    let protocols = headers.get(header::SEC_WEBSOCKET_PROTOCOL)?.to_str().ok()?;
    let mut has_protocol = false;
    let mut ticket = None;
    for protocol in protocols.split(',').map(str::trim) {
        if protocol == WEB_SOCKET_PROTOCOL {
            if has_protocol {
                return None;
            }
            has_protocol = true;
            continue;
        }
        if protocol.starts_with("bearer.") {
            return None;
        }
        let Some(value) = protocol.strip_prefix("ticket.") else {
            continue;
        };
        if ticket.is_some() || ws_ticket_digest(value).is_none() {
            return None;
        }
        ticket = Some(Zeroizing::new(value.to_string()));
    }
    if has_protocol {
        ticket
    } else {
        None
    }
}

fn websocket_origin_allowed(headers: &HeaderMap, allowed_origins: &[String]) -> bool {
    let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return true;
    };
    let Ok(normalized_origin) = normalize_web_origin(origin) else {
        return false;
    };
    let same_host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(|host| normalized_origin_authority(&format!("https://{host}")))
        .is_some_and(|host| {
            normalized_origin_authority(origin).is_some_and(|origin_host| origin_host == host)
        });
    same_host
        || allowed_origins
            .iter()
            .any(|allowed| allowed == &normalized_origin)
}

async fn socket_loop(
    state: AppState,
    session_token: Zeroizing<String>,
    auth: AuthSession,
    client_id: Uuid,
    socket: WebSocket,
) {
    let mut purge_rx = state.purge_epoch.subscribe();
    if active_session(&state, session_token.as_str(), false)
        .await
        .is_none()
    {
        release_connection_reservation(&state, &auth.code_id, client_id).await;
        return;
    }
    let (mut sink, mut stream) = socket.split();
    let (tx, rx) = mpsc::channel::<OutboundFrame>(CLIENT_OUTBOUND_QUEUE_CAPACITY);
    let (control_tx, control_rx) = mpsc::channel::<ClientControl>(CLIENT_CONTROL_QUEUE_CAPACITY);
    let (result_tx, result_rx) = mpsc::channel::<ClientResult>(CLIENT_RESULT_QUEUE_CAPACITY);
    let queued_bytes = Arc::new(AtomicUsize::new(0));

    state.clients.lock().await.insert(
        client_id,
        ClientHandle {
            code_id: auth.code_id,
            username: auth.username.clone(),
            tx,
            control_tx,
            result_tx,
            queued_bytes: Arc::clone(&queued_bytes),
        },
    );
    if let Some(account) = state.accounts.lock().await.get_mut(&auth.code_id) {
        account.connected = true;
    }
    info!("client_connected id={client_id}");
    broadcast_presence(&state).await;
    send_room_catalog(&state, client_id).await;
    send_direct_catalog(&state, client_id, &auth.username).await;

    let global_outbound_bytes = Arc::clone(&state.outbound_bytes);
    let writer = tokio::spawn(async move {
        let mut rx = rx;
        let mut control_rx = control_rx;
        let mut result_rx = result_rx;
        loop {
            tokio::select! {
                biased;
                changed = purge_rx.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    let serialized = serialize_outbound_frame(&OutboundFrame::GlobalWipe);
                    if let Some(serialized) = serialized {
                        let _ = tokio::time::timeout(
                            CLIENT_WIPE_SEND_TIMEOUT,
                            sink.send(Message::Text(serialized)),
                        ).await;
                    }
                    let _ = tokio::time::timeout(
                        CLIENT_WIPE_SEND_TIMEOUT,
                        sink.send(Message::Close(Some(CloseFrame {
                            code: PURGE_CLOSE_CODE,
                            reason: PURGE_CLOSE_REASON.into(),
                        }))),
                    ).await;
                    break;
                }
                result = result_rx.recv() => {
                    let Some(result) = result else {
                        break;
                    };
                    let delivered = serialize_outbound_frame(&result.frame)
                        .map(|serialized| async {
                            matches!(
                                tokio::time::timeout(
                                    CLIENT_RESULT_SEND_TIMEOUT,
                                    sink.send(Message::Text(serialized)),
                                ).await,
                                Ok(Ok(()))
                            )
                        });
                    let delivered = match delivered {
                        Some(future) => future.await,
                        None => false,
                    };
                    let _ = result.delivered.send(delivered);
                    if !delivered {
                        break;
                    }
                }
                control = control_rx.recv() => {
                    match control {
                        Some(ClientControl::GlobalWipe) => {
                            let Some(serialized) = serialize_outbound_frame(&OutboundFrame::GlobalWipe) else {
                                break;
                            };
                            let _ = tokio::time::timeout(
                                CLIENT_WIPE_SEND_TIMEOUT,
                                sink.send(Message::Text(serialized)),
                            ).await;
                            let _ = tokio::time::timeout(
                                CLIENT_WIPE_SEND_TIMEOUT,
                                sink.send(Message::Close(Some(CloseFrame {
                                    code: PURGE_CLOSE_CODE,
                                    reason: PURGE_CLOSE_REASON.into(),
                                }))),
                            ).await;
                        }
                        Some(ClientControl::Close) => {
                            let _ = tokio::time::timeout(
                                CLIENT_WIPE_SEND_TIMEOUT,
                                sink.send(Message::Close(None)),
                            ).await;
                        }
                        None => break,
                    }
                    break;
                }
                frame = rx.recv() => {
                    let Some(frame) = frame else {
                        break;
                    };
                    let Some(serialized) = serialize_outbound_frame(&frame) else {
                        warn!("dropping invalid or oversized outbound frame");
                        release_client_outbound_bytes(&global_outbound_bytes, &queued_bytes, &frame);
                        continue;
                    };
                    let sent = tokio::time::timeout(
                        CLIENT_SINK_SEND_TIMEOUT,
                        sink.send(Message::Text(serialized)),
                    ).await;
                    release_client_outbound_bytes(&global_outbound_bytes, &queued_bytes, &frame);
                    if !matches!(sent, Ok(Ok(()))) {
                        break;
                    }
                }
            }
        }
        while let Ok(frame) = rx.try_recv() {
            release_client_outbound_bytes(&global_outbound_bytes, &queued_bytes, &frame);
        }
        while let Ok(result) = result_rx.try_recv() {
            let _ = result.delivered.send(false);
        }
    });

    let mut session_watchdog = tokio::time::interval(std::time::Duration::from_secs(1));
    session_watchdog.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = session_watchdog.tick() => {
                if active_session(&state, session_token.as_str(), false).await.is_none() {
                    break;
                }
            }
            result = stream.next() => {
                match result {
                    Some(Ok(Message::Text(text))) => {
                        let text = Zeroizing::new(text);
                        // Validation and authorization happen in handle_frame;
                        // do not refresh the dead-man timer for rejected text.
                        if active_session(&state, session_token.as_str(), false).await.is_none() {
                            break;
                        }
                        if let Err(err) = check_ws_frame_allowed(&state, client_id, text.len()).await {
                            warn!("dropping limited frame from {client_id}: {err}");
                            continue;
                        }
                        if let Err(err) = handle_frame(&state, client_id, text.as_str()).await {
                            warn!("dropping invalid frame from {client_id}: {err}");
                        }
                    }
                    Some(Ok(Message::Binary(bytes))) => {
                        if let Err(err) = check_ws_frame_allowed(&state, client_id, bytes.len()).await {
                            warn!("dropping limited binary frame from {client_id}: {err}");
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
    // Dropping the client handle closes every writer input channel. Let the
    // writer drain and release its weighted queue accounting before falling
    // back to aborting a wedged sink.
    let _ = tokio::time::timeout(CLIENT_WIPE_SEND_TIMEOUT, writer).await;
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
            touch_activity_on_success(state, join_room(state, sender_id, chat_id).await).await
        }
        InboundFrame::Leave { chat_id } => {
            touch_activity_on_success(state, leave_room(state, sender_id, &chat_id).await).await
        }
        InboundFrame::Message {
            chat_id,
            version,
            message_id,
            nonce_b64,
            ciphertext_b64,
            envelopes,
            state_revision,
            identity_envelope_b64,
            identity_public_b64,
            prekey_id,
            state_signature_b64,
        } => {
            let message_id_is_safe = valid_chat_id(&message_id);
            let route_result = route_encrypted_message(
                state,
                sender_id,
                chat_id,
                version,
                message_id.clone(),
                nonce_b64,
                ciphertext_b64,
                envelopes,
                state_revision,
                identity_envelope_b64,
                identity_public_b64,
                prekey_id,
                state_signature_b64,
            )
            .await;
            if message_id_is_safe {
                let accepted = route_result.is_ok();
                send_message_result(state, sender_id, &message_id, accepted).await?;
            }
            if route_result.is_ok() {
                touch_activity(state).await;
            }
            route_result
        }
        InboundFrame::MessageAck {
            chat_id,
            message_id,
            sender_username,
            state_revision,
            identity_envelope_b64,
            identity_public_b64,
            prekey_id,
            state_signature_b64,
            ack_signature_b64,
            used_prekey_id,
        } => {
            let message_id_is_safe = valid_chat_id(&message_id);
            let acknowledgement_result = acknowledge_message(
                state,
                sender_id,
                &chat_id,
                &message_id,
                &sender_username,
                state_revision,
                &identity_envelope_b64,
                &identity_public_b64,
                &prekey_id,
                &state_signature_b64,
                &ack_signature_b64,
                &used_prekey_id,
            )
            .await;
            if message_id_is_safe {
                let accepted = acknowledgement_result.is_ok();
                send_ack_result(state, sender_id, &message_id, accepted).await?;
            }
            if acknowledgement_result.is_ok() {
                touch_activity(state).await;
            }
            acknowledgement_result
        }
        InboundFrame::IdentityState {
            state_revision,
            identity_envelope_b64,
            identity_public_b64,
            prekey_id,
            state_signature_b64,
        } => {
            touch_activity_on_success(
                state,
                update_identity_state(
                    state,
                    sender_id,
                    state_revision,
                    &identity_envelope_b64,
                    &identity_public_b64,
                    &prekey_id,
                    &state_signature_b64,
                )
                .await,
            )
            .await
        }
        InboundFrame::GlobalWipe => {
            touch_activity_on_success(state, broadcast_wipe(state, sender_id).await).await
        }
        InboundFrame::CreateRoom { room } => {
            touch_activity_on_success(state, create_room(state, sender_id, room).await).await
        }
        InboundFrame::DeleteRoom { chat_id } => {
            touch_activity_on_success(state, delete_room(state, sender_id, &chat_id).await).await
        }
        InboundFrame::OpenDirect { peer_username } => {
            touch_activity_on_success(state, open_direct(state, sender_id, &peer_username).await)
                .await
        }
    }
}

async fn touch_activity_on_success(
    state: &AppState,
    result: Result<(), String>,
) -> Result<(), String> {
    if result.is_ok() {
        touch_activity(state).await;
    }
    result
}

async fn join_room(state: &AppState, client_id: Uuid, chat_id: String) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
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

    prune_pending_queues(state, now_ms()).await;
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
    for mut pending_frame in pending {
        send_to_client(state, client_id, &pending_frame.frame).await;
        pending_frame.zeroize_sensitive();
    }
    Ok(())
}

async fn leave_room(state: &AppState, client_id: Uuid, chat_id: &str) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
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
    envelopes: Vec<InboundRecipientEnvelope>,
    state_revision: u64,
    identity_envelope_b64: String,
    identity_public_b64: String,
    prekey_id: String,
    state_signature_b64: String,
) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    if version != E2EE_PROTOCOL_VERSION || !valid_chat_id(&chat_id) || !valid_chat_id(&message_id) {
        return Err("encrypted message rejected".to_string());
    }
    let nonce = Zeroizing::new(decode_exact(&nonce_b64, MESSAGE_NONCE_BYTES)?);
    let ciphertext = Zeroizing::new(decode_bounded(&ciphertext_b64, WS_MAX_FRAME_BYTES)?);

    decode_bounded(&identity_envelope_b64, MAX_IDENTITY_ENVELOPE_BYTES)?;

    let (sender_code_id, sender_username) = client_identity(state, sender_id).await?;
    let sender_identity_public =
        Zeroizing::new(decode_exact(&identity_public_b64, IDENTITY_PUBLIC_BYTES)?);
    // Validate the complete bundle before any recipient fanout.  The relay
    // must not distribute a sender identity containing a low-order or
    // otherwise non-contributory X25519 key, even when its fingerprint looks
    // consistent with the authenticated account.
    if !valid_identity_public_bundle(&sender_identity_public, &prekey_id) {
        return Err("authenticated identity required".to_string());
    }
    let authenticated_identity_public = Zeroizing::new(
        state
            .accounts
            .lock()
            .await
            .get(&sender_code_id)
            .map(|account| account.identity_public.clone())
            .ok_or_else(|| "authenticated identity required".to_string())?,
    );
    if authenticated_identity_public.len() != IDENTITY_PUBLIC_BYTES
        || authenticated_identity_public[..IDENTITY_FINGERPRINT_BYTES]
            != sender_identity_public[..IDENTITY_FINGERPRINT_BYTES]
    {
        return Err("authenticated identity required".to_string());
    }
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
        let wrapped = Zeroizing::new(decode_bounded(
            &envelope.wrapped_key_b64,
            MAX_WRAPPED_KEY_BYTES,
        )?);
        if wrapped.is_empty() {
            return Err("recipient envelope rejected".to_string());
        }
        let signature = Zeroizing::new(decode_exact(
            &envelope.signature_b64,
            MESSAGE_SIGNATURE_BYTES,
        )?);
        verify_message_signature_v8(
            version,
            &chat_id,
            &message_id,
            &sender_username,
            &sender_identity_public,
            &nonce,
            &ciphertext,
            &envelope.recipient_username,
            &wrapped,
            &envelope.prekey_id,
            envelope.is_prekey,
            &signature,
        )?;
        let recipient_username = envelope.recipient_username.clone();
        envelope_map.insert(recipient_username, envelope);
    }
    if envelope_map.keys().collect::<HashSet<_>>()
        != expected_recipients.iter().collect::<HashSet<_>>()
    {
        return Err("recipient envelope set rejected".to_string());
    }

    let sender_public_key_b64 = state
        .accounts
        .lock()
        .await
        .get(&sender_code_id)
        .map(|account| URL_SAFE_NO_PAD.encode(&account.identity_public))
        .ok_or_else(|| "authenticated identity required".to_string())?;
    let mut prepared_frames = Vec::with_capacity(expected_recipients.len());
    let mut transient_fanout_bytes = 0usize;
    for recipient_username in &expected_recipients {
        let envelope = envelope_map
            .get(recipient_username)
            .ok_or_else(|| "recipient envelope rejected".to_string())?;
        let frame = OutboundFrame::Message {
            chat_id: chat_id.clone(),
            version,
            message_id: message_id.clone(),
            nonce_b64: nonce_b64.clone(),
            ciphertext_b64: ciphertext_b64.clone(),
            signature_b64: envelope.signature_b64.clone(),
            wrapped_key_b64: envelope.wrapped_key_b64.clone(),
            prekey_id: envelope.prekey_id.clone(),
            is_prekey: envelope.is_prekey,
            sender_username: sender_username.clone(),
            sender_public_key_b64: sender_public_key_b64.clone(),
            identity_public_b64: sender_public_key_b64.clone(),
        };
        let frame_bytes = outbound_frame_bytes(&frame);
        transient_fanout_bytes = transient_fanout_bytes
            .checked_add(frame_bytes.saturating_add(recipient_username.len()))
            .ok_or_else(|| "fanout preparation budget full".to_string())?;
        if transient_fanout_bytes > MAX_TRANSIENT_FANOUT_BYTES {
            return Err("fanout preparation budget full".to_string());
        }
        prepared_frames.push((recipient_username.clone(), frame));
    }
    let mut pending_plan = preflight_pending_frames(state, &prepared_frames).await?;
    commit_pending_frames(state, &prepared_frames, &mut pending_plan).await?;

    if let Err(error) = claim_prekeys(
        state,
        &expected_recipients,
        &envelope_map,
        &chat_id,
        &message_id,
        &sender_username,
    )
    .await
    {
        rollback_pending_frames(state, &prepared_frames, &mut pending_plan).await;
        return Err(error);
    }
    if let Err(error) = register_message_id(state, &chat_id, &sender_username, &message_id).await {
        release_prekey_claims(state, &chat_id, &message_id, &sender_username).await;
        rollback_pending_frames(state, &prepared_frames, &mut pending_plan).await;
        return Err(error);
    }
    if let Err(error) = apply_identity_state(
        state,
        &sender_code_id,
        state_revision,
        &identity_envelope_b64,
        &identity_public_b64,
        &prekey_id,
        &state_signature_b64,
        false,
    )
    .await
    {
        unregister_message_id(state, &chat_id, &sender_username, &message_id).await;
        release_prekey_claims(state, &chat_id, &message_id, &sender_username).await;
        rollback_pending_frames(state, &prepared_frames, &mut pending_plan).await;
        return Err(error);
    }

    let joined = state
        .rooms
        .lock()
        .await
        .get(&chat_id)
        .cloned()
        .unwrap_or_default();
    let clients = state.clients.lock().await.clone();
    for (recipient_username, frame) in prepared_frames {
        let recipient_ids = clients
            .iter()
            .filter_map(|(client_id, client)| {
                (client.username == recipient_username && joined.contains(client_id))
                    .then_some(*client_id)
            })
            .collect::<Vec<_>>();
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
    if replay_ids
        .keys()
        .filter(|candidate| candidate.sender_username == sender_username)
        .count()
        >= MAX_REPLAY_IDS_PER_SENDER
    {
        return Err("sender replay window full".to_string());
    }
    if replay_ids.len() >= MAX_REPLAY_IDS {
        // Never evict a live replay-window entry to admit new traffic. An
        // attacker could otherwise fill the map and replay an older message.
        return Err("replay window full".to_string());
    }
    replay_ids.insert(key, now);
    Ok(())
}

async fn unregister_message_id(
    state: &AppState,
    chat_id: &str,
    sender_username: &str,
    message_id: &str,
) {
    state.replay_ids.lock().await.remove(&ReplayKey {
        chat_id: chat_id.to_string(),
        sender_username: sender_username.to_string(),
        message_id: message_id.to_string(),
    });
}

async fn claim_prekeys(
    state: &AppState,
    expected_recipients: &HashSet<String>,
    envelopes: &HashMap<String, InboundRecipientEnvelope>,
    chat_id: &str,
    message_id: &str,
    sender_username: &str,
) -> Result<(), String> {
    // The caller holds conversation_ops. Prune frames and claims before
    // deciding whether an advertised one-time prekey is still reserved.
    prune_pending_queues(state, now_ms()).await;
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
                recipient_username: username.clone(),
                created_at_ms: now_ms(),
            },
        ));
    }
    drop(accounts);

    let now = now_ms();
    let pending = state.pending.lock().await;
    let mut claims = state.prekey_claims.lock().await;
    prune_prekey_claims(&mut claims, &pending, now);
    drop(pending);
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
    release_prekey_claim(state, chat_id, message_id, sender_username, None).await;
}

async fn release_prekey_claim(
    state: &AppState,
    chat_id: &str,
    message_id: &str,
    sender_username: &str,
    prekey_id: Option<&str>,
) {
    state.prekey_claims.lock().await.retain(|key, claim| {
        !(claim.chat_id == chat_id
            && claim.message_id == message_id
            && claim.sender_username == sender_username
            && prekey_id.is_none_or(|expected| key.prekey_id == expected))
    });
}

fn is_prekey_frame(frame: &OutboundFrame) -> bool {
    matches!(
        frame,
        OutboundFrame::Message {
            is_prekey: true,
            prekey_id,
            ..
        } if !prekey_id.is_empty()
    )
}

fn prekey_claim_details(frame: &OutboundFrame) -> Option<(String, String, String, String)> {
    match frame {
        OutboundFrame::Message {
            chat_id,
            message_id,
            prekey_id,
            is_prekey: true,
            sender_username,
            ..
        } if !prekey_id.is_empty() => Some((
            chat_id.clone(),
            message_id.clone(),
            sender_username.clone(),
            prekey_id.clone(),
        )),
        _ => None,
    }
}

fn outbound_frame_bytes(frame: &OutboundFrame) -> usize {
    match frame {
        OutboundFrame::Message {
            chat_id,
            message_id,
            nonce_b64,
            ciphertext_b64,
            signature_b64,
            wrapped_key_b64,
            sender_username,
            sender_public_key_b64,
            identity_public_b64,
            ..
        } => 256usize
            .saturating_add(chat_id.len())
            .saturating_add(message_id.len())
            .saturating_add(nonce_b64.len())
            .saturating_add(ciphertext_b64.len())
            .saturating_add(signature_b64.len())
            .saturating_add(wrapped_key_b64.len())
            .saturating_add(sender_username.len())
            .saturating_add(sender_public_key_b64.len())
            .saturating_add(identity_public_b64.len()),
        _ => 0,
    }
}

struct PendingQueuePlan {
    key: PendingKey,
    eviction_index: Option<usize>,
    evicted: Option<PendingFrame>,
}

impl Drop for PendingQueuePlan {
    fn drop(&mut self) {
        if let Some(evicted) = self.evicted.as_mut() {
            evicted.zeroize_sensitive();
        }
    }
}

async fn preflight_pending_frames(
    state: &AppState,
    frames: &[(String, OutboundFrame)],
) -> Result<Vec<PendingQueuePlan>, String> {
    // The caller holds conversation_ops. Prune before taking the snapshot so
    // expired frames and their prekey claims cannot consume admission budget.
    let transient_fanout_bytes = frames
        .iter()
        .try_fold(0usize, |total, (recipient, frame)| {
            total
                .checked_add(outbound_frame_bytes(frame).saturating_add(recipient.len()))
                .filter(|bytes| *bytes <= MAX_TRANSIENT_FANOUT_BYTES)
                .ok_or_else(|| "fanout preparation budget full".to_string())
        })?;
    let _ = transient_fanout_bytes;
    prune_pending_queues(state, now_ms()).await;
    let pending = state.pending.lock().await;
    let pending_bytes = state.pending_bytes.lock().await;
    let mut projected_bytes = *pending_bytes;
    let mut simulated = HashMap::<PendingKey, Vec<(usize, bool)>>::new();
    for (key, queue) in pending.iter() {
        simulated.insert(
            key.clone(),
            queue
                .iter()
                .map(|pending_frame| {
                    (
                        outbound_frame_bytes(&pending_frame.frame),
                        is_prekey_frame(&pending_frame.frame),
                    )
                })
                .collect(),
        );
    }
    let mut plan = Vec::with_capacity(frames.len());
    for (recipient_username, frame) in frames {
        let key = PendingKey {
            chat_id: match frame {
                OutboundFrame::Message { chat_id, .. } => chat_id.clone(),
                _ => return Err("pending frame rejected".to_string()),
            },
            recipient_username: recipient_username.clone(),
        };
        let queue = simulated.entry(key.clone()).or_default();
        let eviction_index = if queue.len() >= MAX_PENDING_FRAMES_PER_ROOM {
            let Some(index) = queue.iter().position(|(_, is_prekey)| !*is_prekey) else {
                return Err("recipient pending queue full".to_string());
            };
            let (evicted_bytes, _) = queue.remove(index);
            projected_bytes = projected_bytes.saturating_sub(evicted_bytes);
            Some(index)
        } else {
            None
        };
        let incoming_bytes = outbound_frame_bytes(frame);
        if projected_bytes.saturating_add(incoming_bytes) > MAX_PENDING_BYTES {
            return Err("pending message budget full".to_string());
        }
        projected_bytes = projected_bytes.saturating_add(incoming_bytes);
        queue.push((incoming_bytes, is_prekey_frame(frame)));
        plan.push(PendingQueuePlan {
            key,
            eviction_index,
            evicted: None,
        });
    }
    drop(pending_bytes);
    drop(pending);
    Ok(plan)
}

async fn commit_pending_frames(
    state: &AppState,
    frames: &[(String, OutboundFrame)],
    plan: &mut [PendingQueuePlan],
) -> Result<(), String> {
    if frames.len() != plan.len() {
        return Err("pending frame plan mismatch".to_string());
    }
    let mut pending = state.pending.lock().await;
    let mut pending_bytes = state.pending_bytes.lock().await;
    let now = now_ms();

    // Validate the complete plan against the live queues before mutating
    // anything. conversation_ops normally makes this snapshot stable, but
    // keeping the validation transactional also protects maintenance/tests
    // that call this helper directly.
    let mut projected_bytes = *pending_bytes;
    let mut simulated = HashMap::<PendingKey, Vec<(usize, bool)>>::new();
    for (key, queue) in pending.iter() {
        simulated.insert(
            key.clone(),
            queue
                .iter()
                .map(|pending_frame| {
                    (
                        outbound_frame_bytes(&pending_frame.frame),
                        is_prekey_frame(&pending_frame.frame),
                    )
                })
                .collect(),
        );
    }
    for ((_, frame), queue_plan) in frames.iter().zip(plan.iter()) {
        let queue = simulated.entry(queue_plan.key.clone()).or_default();
        let expected_eviction = if queue.len() >= MAX_PENDING_FRAMES_PER_ROOM {
            let Some(index) = queue.iter().position(|(_, is_prekey)| !*is_prekey) else {
                return Err("pending queue changed during commit".to_string());
            };
            let (evicted_bytes, _) = queue.remove(index);
            projected_bytes = projected_bytes.saturating_sub(evicted_bytes);
            Some(index)
        } else {
            None
        };
        if expected_eviction != queue_plan.eviction_index {
            return Err("pending queue changed during commit".to_string());
        }
        if queue_plan.evicted.is_some() {
            return Err("pending frame plan already committed".to_string());
        }
        let incoming_bytes = outbound_frame_bytes(frame);
        if projected_bytes.saturating_add(incoming_bytes) > MAX_PENDING_BYTES {
            return Err("pending message budget changed during commit".to_string());
        }
        projected_bytes = projected_bytes.saturating_add(incoming_bytes);
        queue.push((incoming_bytes, is_prekey_frame(frame)));
    }

    for ((_, frame), queue_plan) in frames.iter().zip(plan.iter_mut()) {
        let queue = pending.entry(queue_plan.key.clone()).or_default();
        if queue.len() >= MAX_PENDING_FRAMES_PER_ROOM {
            let Some(eviction_index) = queue_plan.eviction_index else {
                return Err("pending queue changed during commit".to_string());
            };
            if eviction_index >= queue.len() || is_prekey_frame(&queue[eviction_index].frame) {
                return Err("pending queue changed during commit".to_string());
            }
            let evicted = queue.remove(eviction_index);
            *pending_bytes = pending_bytes.saturating_sub(outbound_frame_bytes(&evicted.frame));
            queue_plan.evicted = Some(evicted);
        } else if queue_plan.eviction_index.is_some() {
            return Err("pending queue changed during commit".to_string());
        }
        let incoming_bytes = outbound_frame_bytes(frame);
        queue.push(PendingFrame::new(frame.clone(), now));
        *pending_bytes = pending_bytes.saturating_add(incoming_bytes);
    }
    Ok(())
}

async fn rollback_pending_frames(
    state: &AppState,
    frames: &[(String, OutboundFrame)],
    plan: &mut [PendingQueuePlan],
) {
    let mut pending = state.pending.lock().await;
    let mut pending_bytes = state.pending_bytes.lock().await;
    for ((_, frame), queue_plan) in frames.iter().zip(plan.iter_mut()) {
        let Some(queue) = pending.get_mut(&queue_plan.key) else {
            continue;
        };
        let Some((message_id, sender_username)) = (match frame {
            OutboundFrame::Message {
                message_id,
                sender_username,
                ..
            } => Some((message_id, sender_username)),
            _ => None,
        }) else {
            continue;
        };
        if let Some(index) = queue.iter().rposition(|pending_frame| {
            matches!(
                &pending_frame.frame,
                OutboundFrame::Message {
                    message_id: pending_id,
                    sender_username: pending_sender,
                    ..
                } if pending_id == message_id && pending_sender == sender_username
            )
        }) {
            let mut removed = queue.remove(index);
            *pending_bytes = pending_bytes.saturating_sub(outbound_frame_bytes(&removed.frame));
            removed.zeroize_sensitive();
        }
        if let Some(evicted) = queue_plan.evicted.take() {
            let insertion_index = queue_plan
                .eviction_index
                .unwrap_or(queue.len())
                .min(queue.len());
            *pending_bytes = pending_bytes.saturating_add(outbound_frame_bytes(&evicted.frame));
            queue.insert(insertion_index, evicted);
        }
    }
    pending.retain(|_, queue| !queue.is_empty());
}

#[cfg(test)]
async fn queue_pending_frame(
    state: &AppState,
    _chat_id: &str,
    recipient_username: String,
    frame: OutboundFrame,
) -> Result<(), String> {
    let frames = vec![(recipient_username, frame)];
    let mut plan = preflight_pending_frames(state, &frames).await?;
    commit_pending_frames(state, &frames, &mut plan).await
}

async fn update_identity_state(
    state: &AppState,
    sender_id: Uuid,
    revision: u64,
    envelope_b64: &str,
    identity_public_b64: &str,
    prekey_id: &str,
    state_signature_b64: &str,
) -> Result<(), String> {
    let (code_id, _) = client_identity(state, sender_id).await?;
    apply_identity_state(
        state,
        &code_id,
        revision,
        envelope_b64,
        identity_public_b64,
        prekey_id,
        state_signature_b64,
        true,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn apply_identity_state(
    state: &AppState,
    code_id: &CodeId,
    revision: u64,
    envelope_b64: &str,
    identity_public_b64: &str,
    prekey_id: &str,
    state_signature_b64: &str,
    allow_reuse: bool,
) -> Result<(), String> {
    let mut accounts = state.accounts.lock().await;
    apply_identity_state_locked(
        &mut accounts,
        code_id,
        revision,
        envelope_b64,
        identity_public_b64,
        prekey_id,
        state_signature_b64,
        allow_reuse,
    )
}

#[allow(clippy::too_many_arguments)]
fn apply_identity_state_locked(
    accounts: &mut HashMap<CodeId, Account>,
    code_id: &CodeId,
    revision: u64,
    envelope_b64: &str,
    identity_public_b64: &str,
    prekey_id: &str,
    state_signature_b64: &str,
    allow_reuse: bool,
) -> Result<(), String> {
    let mut envelope = decode_bounded(envelope_b64, MAX_IDENTITY_ENVELOPE_BYTES)?;
    let mut identity_public = decode_exact(identity_public_b64, IDENTITY_PUBLIC_BYTES)?;
    let state_signature =
        Zeroizing::new(decode_exact(state_signature_b64, MESSAGE_SIGNATURE_BYTES)?);
    if envelope.len() <= 1 + MESSAGE_NONCE_BYTES
        || envelope.first() != Some(&IDENTITY_ENVELOPE_VERSION)
        || !valid_identity_public_bundle(&identity_public, prekey_id)
    {
        envelope.zeroize();
        identity_public.zeroize();
        return Err("identity state rejected".to_string());
    }
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
    if verify_identity_state_signature_v8(
        E2EE_PROTOCOL_VERSION,
        revision,
        &envelope,
        &identity_public,
        prekey_id,
        &state_signature,
    )
    .is_err()
    {
        envelope.zeroize();
        identity_public.zeroize();
        return Err("identity state rejected".to_string());
    }
    if revision > account.state_revision {
        let Some(advance) = revision.checked_sub(account.state_revision) else {
            envelope.zeroize();
            identity_public.zeroize();
            return Err("identity state rejected".to_string());
        };
        if advance > MAX_STATE_REVISION_ADVANCE {
            envelope.zeroize();
            identity_public.zeroize();
            return Err("identity state rejected".to_string());
        }
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

    // A reusable stale snapshot must still describe the exact current public
    // bundle and prekey. The fingerprint check above only binds the long-term
    // signing key; without this full comparison, a lagged ACK could carry a
    // signed but stale prekey bundle and be accepted without validation.
    if account.identity_public != identity_public || account.prekey_id != prekey_id {
        envelope.zeroize();
        identity_public.zeroize();
        return Err("identity state rejected".to_string());
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
    account.state_revision_window |= revision_bit;
    envelope.zeroize();
    identity_public.zeroize();
    Ok(())
}

fn pending_frame_matches_ack(
    frame: &OutboundFrame,
    chat_id: &str,
    message_id: &str,
    original_sender: &str,
    used_prekey_id: &str,
) -> bool {
    let OutboundFrame::Message {
        chat_id: frame_chat_id,
        message_id: frame_message_id,
        prekey_id: frame_prekey_id,
        is_prekey,
        sender_username: frame_sender,
        ..
    } = frame
    else {
        return false;
    };

    frame_chat_id == chat_id
        && frame_message_id == message_id
        && frame_sender == original_sender
        && if used_prekey_id.is_empty() {
            !is_prekey && frame_prekey_id.is_empty()
        } else {
            *is_prekey && frame_prekey_id == used_prekey_id
        }
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
    state_signature_b64: &str,
    ack_signature_b64: &str,
    used_prekey_id: &str,
) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    prune_pending_queues(state, now_ms()).await;
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
    let identity_public = Zeroizing::new(decode_exact(identity_public_b64, IDENTITY_PUBLIC_BYTES)?);
    let ack_signature = Zeroizing::new(decode_exact(ack_signature_b64, MESSAGE_SIGNATURE_BYTES)?);
    verify_ack_signature_v8(
        E2EE_PROTOCOL_VERSION,
        chat_id,
        message_id,
        original_sender,
        used_prekey_id,
        &identity_public,
        &ack_signature,
    )?;

    let key = PendingKey {
        chat_id: chat_id.to_string(),
        recipient_username: username.clone(),
    };
    // Keep the lock order used by message admission and claim maintenance:
    // accounts -> pending -> pending_bytes -> prekey_claims.  Every
    // precondition is checked while these guards are held, then the signed
    // state and queue/claim consumption commit as one conversation operation.
    let mut accounts = state.accounts.lock().await;
    let mut pending = state.pending.lock().await;
    let mut pending_bytes = state.pending_bytes.lock().await;
    let mut claims = state.prekey_claims.lock().await;

    let (matching_index, matching_bytes) = {
        let queue = pending
            .get(&key)
            .ok_or_else(|| "message acknowledgement rejected".to_string())?;
        let mut matching_index = None;
        for (index, pending_frame) in queue.iter().enumerate() {
            if pending_frame_matches_ack(
                &pending_frame.frame,
                chat_id,
                message_id,
                original_sender,
                used_prekey_id,
            ) && matching_index.replace(index).is_some()
            {
                return Err("message acknowledgement rejected".to_string());
            }
        }
        let matching_index =
            matching_index.ok_or_else(|| "message acknowledgement rejected".to_string())?;
        (
            matching_index,
            outbound_frame_bytes(&queue[matching_index].frame),
        )
    };
    if *pending_bytes < matching_bytes {
        return Err("message acknowledgement rejected".to_string());
    }

    if !used_prekey_id.is_empty() {
        let claim_key = PrekeyClaimKey {
            code_id,
            prekey_id: used_prekey_id.to_string(),
        };
        let Some(claim) = claims.get(&claim_key) else {
            return Err("message acknowledgement rejected".to_string());
        };
        if claim.chat_id != chat_id
            || claim.message_id != message_id
            || claim.sender_username != original_sender
            || claim.recipient_username != username
        {
            return Err("message acknowledgement rejected".to_string());
        }
    }

    apply_identity_state_locked(
        &mut accounts,
        &code_id,
        revision,
        envelope_b64,
        identity_public_b64,
        current_prekey_id,
        state_signature_b64,
        true,
    )?;

    let queue = pending
        .get_mut(&key)
        .expect("validated pending acknowledgement queue");
    let mut removed = queue.remove(matching_index);
    *pending_bytes -= matching_bytes;
    removed.zeroize_sensitive();
    let queue_is_empty = queue.is_empty();
    if queue_is_empty {
        pending.remove(&key);
    }
    if !used_prekey_id.is_empty() {
        claims.remove(&PrekeyClaimKey {
            code_id,
            prekey_id: used_prekey_id.to_string(),
        });
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
    // Lock order is account_ops -> conversation_ops. Account handshakes and
    // session issuance must finish before this clears every account map.
    let _account_guard = state.account_ops.lock().await;
    let _conversation_guard = state.conversation_ops.lock().await;
    state.attachment_epoch.fetch_add(1, Ordering::AcqRel);
    state
        .purge_epoch
        .send_modify(|epoch| *epoch = epoch.saturating_add(1));
    let clients = state
        .clients
        .lock()
        .await
        .keys()
        .copied()
        .collect::<Vec<_>>();
    if notify_clients {
        for client_id in &clients {
            send_control_to_client(state, *client_id, ClientControl::GlobalWipe).await;
        }
    }

    let mut pending = state.pending.lock().await;
    let mut pending_bytes = state.pending_bytes.lock().await;
    for (_, mut frames) in pending.drain() {
        for pending_frame in &mut frames {
            pending_frame.zeroize_sensitive();
        }
    }
    *pending_bytes = 0;
    drop(pending_bytes);
    drop(pending);
    state.attachments.lock().await.clear();
    let mut attachment_usage = state.attachment_bytes_by_code.lock().await;
    zeroize_code_id_map(&mut attachment_usage);
    drop(attachment_usage);
    state.room_catalog.lock().await.clear();
    state.direct_catalog.lock().await.clear();
    state.rooms.lock().await.clear();
    let mut sessions = state.sessions.lock().await;
    for (token, _) in sessions.drain() {
        drop(token);
    }
    drop(sessions);
    let mut ws_tickets = state.ws_tickets.lock().await;
    clear_ws_tickets_locked(&mut ws_tickets);
    drop(ws_tickets);
    let mut accounts = state.accounts.lock().await;
    zeroize_code_id_map(&mut accounts);
    drop(accounts);
    let mut available_codes = state.available_codes.lock().await;
    zeroize_code_id_set(&mut available_codes);
    drop(available_codes);
    if let Some(mut boot_codes) = state.boot_codes.lock().await.take() {
        for code in &mut boot_codes {
            code.zeroize();
        }
    }
    state.frame_limits.lock().await.clear();
    state.replay_ids.lock().await.clear();
    state.prekey_claims.lock().await.clear();
    state.opaque_handshakes.lock().await.clear();
    let mut login_limits = state.login_limits.lock().await;
    zeroize_code_id_map(&mut login_limits);
    drop(login_limits);
    state.clients.lock().await.clear();
    let mut active_connections = state.active_connections.lock().await;
    zeroize_code_id_map(&mut active_connections);
}

async fn create_room(
    state: &AppState,
    sender_id: Uuid,
    mut room: RoomRecord,
) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    let (owner_code_id, owner_username) = client_identity(state, sender_id).await?;
    room.owner_username = owner_username;
    normalize_room_record(&mut room)?;
    let mut catalog = state.room_catalog.lock().await;
    if let Some(existing) = catalog.get(&room.id) {
        if existing.owner_code_id != owner_code_id {
            return Err("room id rejected".to_string());
        }
    } else {
        if catalog
            .keys()
            .any(|existing_id| existing_id.eq_ignore_ascii_case(&room.id))
        {
            return Err("room id rejected".to_string());
        }
        if catalog.len() >= MAX_ROOM_CATALOG_ENTRIES {
            return Err("room catalog limit reached".to_string());
        }
        if !has_room_capacity(&catalog, &owner_code_id, state.max_rooms_per_user) {
            return Err("room limit reached".to_string());
        }
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
    let _conversation_guard = state.conversation_ops.lock().await;
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
    prune_pending_queues(state, now_ms()).await;
    let mut released_claims = Vec::new();
    {
        let mut pending = state.pending.lock().await;
        let mut pending_bytes = state.pending_bytes.lock().await;
        let keys = pending
            .keys()
            .filter(|key| key.chat_id == chat_id)
            .cloned()
            .collect::<Vec<_>>();
        for key in keys {
            if let Some(mut frames) = pending.remove(&key) {
                for pending_frame in &mut frames {
                    *pending_bytes =
                        (*pending_bytes).saturating_sub(outbound_frame_bytes(&pending_frame.frame));
                    if let Some(details) = prekey_claim_details(&pending_frame.frame) {
                        released_claims.push(details);
                    }
                    pending_frame.zeroize_sensitive();
                }
            }
        }
        drop(pending_bytes);
    }
    for (claim_chat_id, message_id, sender_username, prekey_id) in released_claims {
        release_prekey_claim(
            state,
            &claim_chat_id,
            &message_id,
            &sender_username,
            Some(&prekey_id),
        )
        .await;
    }
    remove_chat_attachments(state, chat_id).await;
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
        .take(MAX_ROOM_CATALOG_ENTRIES)
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
    let _conversation_guard = state.conversation_ops.lock().await;
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
            if catalog.len() >= MAX_DIRECT_CATALOG_ENTRIES {
                return Err("direct catalog unavailable".to_string());
            }
            let sender_direct_count = catalog
                .values()
                .filter(|direct| direct.contains(&sender_username))
                .count();
            let peer_direct_count = catalog
                .values()
                .filter(|direct| direct.contains(&peer_username))
                .count();
            if sender_direct_count >= MAX_DIRECT_CATALOG_PER_USER
                || peer_direct_count >= MAX_DIRECT_CATALOG_PER_USER
            {
                return Err("direct catalog unavailable".to_string());
            }
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
        .take(MAX_DIRECT_CATALOG_PER_USER)
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

fn serialize_outbound_frame(frame: &OutboundFrame) -> Option<String> {
    let serialized = serde_json::to_string(frame).ok()?;
    (serialized.len() <= WS_MAX_FRAME_BYTES).then_some(serialized)
}

fn outbound_queue_bytes(frame: &OutboundFrame) -> usize {
    serialize_outbound_frame(frame)
        .map(|serialized| serialized.len())
        .unwrap_or(WS_MAX_FRAME_BYTES.saturating_add(1))
}

fn reserve_outbound_bytes(global: &AtomicUsize, local: &AtomicUsize, bytes: usize) -> bool {
    let bytes = bytes.max(1);
    let mut local_current = local.load(Ordering::Acquire);
    loop {
        let Some(local_next) = local_current.checked_add(bytes) else {
            return false;
        };
        if local_next > CLIENT_OUTBOUND_BYTES {
            return false;
        }
        match local.compare_exchange_weak(
            local_current,
            local_next,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => break,
            Err(observed) => local_current = observed,
        }
    }

    let mut global_current = global.load(Ordering::Acquire);
    loop {
        let Some(global_next) = global_current.checked_add(bytes) else {
            local.fetch_sub(bytes, Ordering::AcqRel);
            return false;
        };
        if global_next > GLOBAL_OUTBOUND_BYTES {
            local.fetch_sub(bytes, Ordering::AcqRel);
            return false;
        }
        match global.compare_exchange_weak(
            global_current,
            global_next,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(observed) => global_current = observed,
        }
    }
}

fn release_client_outbound_bytes(global: &AtomicUsize, local: &AtomicUsize, frame: &OutboundFrame) {
    let bytes = outbound_queue_bytes(frame).max(1);
    global.fetch_sub(bytes, Ordering::AcqRel);
    local.fetch_sub(bytes, Ordering::AcqRel);
}

async fn invalidate_client_connection(state: &AppState, client_id: Uuid) {
    let Some((code_id, control_tx)) = state
        .clients
        .lock()
        .await
        .get(&client_id)
        .map(|client| (client.code_id, client.control_tx.clone()))
    else {
        return;
    };
    let _ = control_tx.try_send(ClientControl::Close);
    let _account_guard = state.account_ops.lock().await;
    let mut sessions = state.sessions.lock().await;
    sessions.retain(|_, session| session.code_id != code_id);
    drop(sessions);
    replace_connected_clients_for_code(state, &code_id).await;
}

async fn send_message_result(
    state: &AppState,
    client_id: Uuid,
    message_id: &str,
    accepted: bool,
) -> Result<(), String> {
    send_client_result(
        state,
        client_id,
        OutboundFrame::MessageResult {
            message_id: message_id.to_string(),
            accepted,
        },
    )
    .await
}

async fn send_ack_result(
    state: &AppState,
    client_id: Uuid,
    message_id: &str,
    accepted: bool,
) -> Result<(), String> {
    send_client_result(
        state,
        client_id,
        OutboundFrame::AckResult {
            message_id: message_id.to_string(),
            accepted,
        },
    )
    .await
}

async fn send_client_result(
    state: &AppState,
    client_id: Uuid,
    frame: OutboundFrame,
) -> Result<(), String> {
    let Some(result_tx) = state
        .clients
        .lock()
        .await
        .get(&client_id)
        .map(|client| client.result_tx.clone())
    else {
        invalidate_client_connection(state, client_id).await;
        return Err("client connection unavailable".to_string());
    };
    let (completion, delivered) = oneshot::channel();
    if result_tx
        .try_send(ClientResult {
            frame,
            delivered: completion,
        })
        .is_err()
    {
        invalidate_client_connection(state, client_id).await;
        return Err("client result channel unavailable".to_string());
    }
    let delivered = tokio::time::timeout(CLIENT_RESULT_SEND_TIMEOUT, delivered)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(false);
    if !delivered {
        invalidate_client_connection(state, client_id).await;
        return Err("client result delivery failed".to_string());
    }
    Ok(())
}

async fn send_to_client(state: &AppState, client_id: Uuid, frame: &OutboundFrame) {
    let client = state
        .clients
        .lock()
        .await
        .get(&client_id)
        .map(|client| (client.tx.clone(), Arc::clone(&client.queued_bytes)));
    let Some((tx, queued_bytes)) = client else {
        return;
    };
    let bytes = outbound_queue_bytes(frame);
    if bytes > WS_MAX_FRAME_BYTES
        || !reserve_outbound_bytes(&state.outbound_bytes, &queued_bytes, bytes)
    {
        warn!("closing slow or over-budget client {client_id}");
        send_control_to_client(state, client_id, ClientControl::Close).await;
        return;
    }
    if tx.try_send(frame.clone()).is_err() {
        release_client_outbound_bytes(&state.outbound_bytes, &queued_bytes, frame);
        warn!("closing slow or closed client {client_id}");
        send_control_to_client(state, client_id, ClientControl::Close).await;
    }
}

async fn send_control_to_client(state: &AppState, client_id: Uuid, control: ClientControl) {
    let control_tx = state
        .clients
        .lock()
        .await
        .get(&client_id)
        .map(|client| client.control_tx.clone());
    if let Some(control_tx) = control_tx {
        if control_tx.try_send(control).is_err() {
            warn!("dropping control frame for closed client {client_id}");
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

fn reserve_connection(
    active_connections: &mut HashMap<CodeId, Uuid>,
    code_id: CodeId,
    client_id: Uuid,
) -> bool {
    if let std::collections::hash_map::Entry::Vacant(entry) = active_connections.entry(code_id) {
        entry.insert(client_id);
        true
    } else {
        false
    }
}

async fn release_connection_reservation(state: &AppState, code_id: &CodeId, client_id: Uuid) {
    let mut active_connections = state.active_connections.lock().await;
    if active_connections.get(code_id) == Some(&client_id) {
        if let Some((mut removed_code_id, _)) = active_connections.remove_entry(code_id) {
            removed_code_id.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn healthcheck_accepts_only_a_successful_json_health_response() {
        assert!(healthcheck_response_is_healthy(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true,\"storage\":\"ram-only\"}"
        ));
        assert!(!healthcheck_response_is_healthy(
            b"HTTP/1.1 503 Service Unavailable\r\n\r\n{\"ok\":false}"
        ));
        assert!(!healthcheck_response_is_healthy(
            b"HTTP/1.1 200 OK\r\n\r\n{\"storage\":\"ram-only\"}"
        ));
    }

    #[test]
    fn content_security_policy_allows_wasm_without_javascript_eval() {
        assert!(CONTENT_SECURITY_POLICY.contains("script-src 'self' 'wasm-unsafe-eval'"));
        assert!(!CONTENT_SECURITY_POLICY.contains("'unsafe-eval'"));
        assert!(CONTENT_SECURITY_POLICY.contains("connect-src 'self' https: wss:"));
        assert!(CONTENT_SECURITY_POLICY.contains("http://127.0.0.1:*"));
        assert!(CONTENT_SECURITY_POLICY.contains("ws://localhost:*"));
        assert!(!CONTENT_SECURITY_POLICY.contains(" wss: http: ws:;"));
    }

    #[test]
    fn attachment_limits_budget_stateless_wire_overhead() {
        let image_limit = max_serialized_attachment_bytes("IMAGE");
        let video_limit = max_serialized_attachment_bytes("VIDEO");
        let file_limit = max_serialized_attachment_bytes("FILE");
        assert_eq!(
            image_limit,
            IMAGE_ATTACHMENT_LIMIT_BYTES + ATTACHMENT_WIRE_OVERHEAD_BYTES
        );
        assert_eq!(
            video_limit,
            VIDEO_ATTACHMENT_LIMIT_BYTES + ATTACHMENT_WIRE_OVERHEAD_BYTES
        );
        assert_eq!(
            file_limit,
            FILE_ATTACHMENT_LIMIT_BYTES + ATTACHMENT_WIRE_OVERHEAD_BYTES
        );
        assert!(file_limit <= DEFAULT_ATTACHMENT_ACCOUNT_LIMIT_MB * 1024 * 1024);
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
    fn boot_code_writer_flushes_only_the_one_time_startup_output() {
        let codes = vec!["ABCD-12345678".to_string(), "XYZ-123456789".to_string()];
        let mut output = Vec::new();
        write_boot_codes(&mut output, &codes).expect("startup output writes");
        let output = String::from_utf8(output).expect("startup output is utf8");
        assert!(output.starts_with("ABYSSAL RAM-ONLY ACCESS CODES"));
        assert!(output.contains("ABYSSAL_CODE code=ABCD-12345678"));
        assert!(output.contains("ABYSSAL_CODE code=XYZ-123456789"));
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

    #[tokio::test]
    async fn login_limiter_prunes_stale_entries_and_fails_closed_at_capacity() {
        let state = test_state();
        let now = now_ms();
        let oldest = test_code_id(&format!("login-code-{}", MAX_LOGIN_LIMIT_ENTRIES - 1));
        {
            let mut limits = state.login_limits.lock().await;
            for index in 0..MAX_LOGIN_LIMIT_ENTRIES {
                let code_id = test_code_id(&format!("login-code-{index}"));
                limits.insert(
                    code_id,
                    RateState {
                        window_start_ms: now.saturating_sub(index as u64),
                        count: 1,
                        bytes: 0,
                    },
                );
            }
            limits.insert(
                test_code_id("stale-login-code"),
                RateState {
                    window_start_ms: now.saturating_sub(LOGIN_RATE_WINDOW_MS + 1),
                    count: 1,
                    bytes: 0,
                },
            );
        }

        let fresh = test_code_id("fresh-login-code");
        assert!(!login_attempt_allowed(&state, &fresh).await);
        let limits = state.login_limits.lock().await;
        assert_eq!(limits.len(), MAX_LOGIN_LIMIT_ENTRIES);
        assert!(limits.contains_key(&oldest));
        assert!(!limits.contains_key(&test_code_id("stale-login-code")));
        assert!(!limits.contains_key(&fresh));
    }

    #[tokio::test]
    async fn unknown_code_flood_cannot_consume_known_code_limiter_capacity() {
        let state = test_state();
        let known = test_code_id("known-invite-code");
        state.available_codes.lock().await.insert(known);

        for index in 0..(MAX_LOGIN_LIMIT_ENTRIES * 2) {
            let unknown = test_code_id(&format!("unknown-invite-{index}"));
            assert!(!known_code_id(&state, &unknown).await);
            // This mirrors start_opaque_account: unknown IDs return before
            // login_attempt_allowed and therefore never allocate a slot.
        }
        assert!(state.login_limits.lock().await.is_empty());
        assert!(known_code_id(&state, &known).await);

        for _ in 0..LOGIN_MAX_ATTEMPTS_PER_WINDOW {
            assert!(login_attempt_allowed(&state, &known).await);
        }
        assert!(!login_attempt_allowed(&state, &known).await);
    }

    #[tokio::test]
    async fn opaque_handshakes_are_bounded_in_ram() {
        let state = test_state();
        let first_id = Uuid::new_v4();
        for index in 0..MAX_OPAQUE_HANDSHAKES {
            let id = if index == 0 { first_id } else { Uuid::new_v4() };
            assert!(
                store_opaque_handshake(
                    &state,
                    id,
                    OpaqueHandshake::Registration {
                        code_id: test_code_id("handshake"),
                        challenge: Zeroizing::new(vec![0; REGISTRATION_CHALLENGE_BYTES_V8]),
                        created_at_ms: now_ms(),
                    },
                )
                .await
            );
        }
        assert!(
            !store_opaque_handshake(
                &state,
                Uuid::new_v4(),
                OpaqueHandshake::Registration {
                    code_id: test_code_id("overflow-handshake"),
                    challenge: Zeroizing::new(vec![0; REGISTRATION_CHALLENGE_BYTES_V8]),
                    created_at_ms: now_ms(),
                },
            )
            .await
        );
        assert_eq!(
            state.opaque_handshakes.lock().await.len(),
            MAX_OPAQUE_HANDSHAKES
        );
        assert!(state.opaque_handshakes.lock().await.contains_key(&first_id));
    }

    #[tokio::test]
    async fn global_wipe_serializes_with_opaque_start_and_clears_new_handshake() {
        let state = test_state();
        let code = "ABCD-12345678";
        let code_id = derive_code_id(&state.invite_code_pepper[..], code);
        state.available_codes.lock().await.insert(code_id);
        let opaque =
            abyssal_core::secure_protocol::opaque_client_start(b"correct-password".to_vec())
                .expect("opaque start");
        let request = OpaqueAccountStartRequest {
            code: code.to_string(),
            registration_request_b64: URL_SAFE_NO_PAD.encode(opaque.registration_request),
            credential_request_b64: URL_SAFE_NO_PAD.encode(opaque.credential_request),
        };

        let account_guard = state.account_ops.lock().await;
        let start_task = tokio::spawn(start_opaque_account(State(state.clone()), Json(request)));
        tokio::task::yield_now().await;
        let wipe_state = state.clone();
        let mut wipe_task = tokio::spawn(async move {
            wipe_relay_state(&wipe_state, false).await;
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut wipe_task)
                .await
                .is_err(),
            "wipe must wait for an in-flight account operation"
        );
        drop(account_guard);

        tokio::time::timeout(Duration::from_secs(2), start_task)
            .await
            .expect("opaque start should finish")
            .expect("opaque start task should not panic");
        tokio::time::timeout(Duration::from_secs(2), wipe_task)
            .await
            .expect("wipe should finish")
            .expect("wipe task should not panic");

        assert!(state.accounts.lock().await.is_empty());
        assert!(state.sessions.lock().await.is_empty());
        assert!(state.opaque_handshakes.lock().await.is_empty());
        assert!(state.available_codes.lock().await.is_empty());
    }

    #[tokio::test]
    async fn global_wipe_serializes_with_opaque_finish_and_clears_new_account() {
        let state = test_state();
        let code = "ABCD-12345678";
        let code_id = derive_code_id(&state.invite_code_pepper[..], code);
        state.available_codes.lock().await.insert(code_id);
        let opaque =
            abyssal_core::secure_protocol::opaque_client_start(b"correct-password".to_vec())
                .expect("opaque start");
        let registration_response = opaque_server_registration_response(
            &state.opaque_setup,
            &opaque.registration_request,
            code.as_bytes(),
        )
        .expect("registration response");
        let registration = abyssal_core::secure_protocol::opaque_client_finish_registration(
            b"correct-password".to_vec(),
            opaque.registration_state,
            registration_response,
        )
        .expect("registration finish");
        let handshake_id = Uuid::new_v4();
        state.opaque_handshakes.lock().await.insert(
            handshake_id,
            OpaqueHandshake::Registration {
                code_id,
                challenge: Zeroizing::new(vec![0; REGISTRATION_CHALLENGE_BYTES_V8]),
                created_at_ms: now_ms(),
            },
        );
        let request = OpaqueAccountFinishRequest {
            handshake_id,
            registration_upload_b64: Some(URL_SAFE_NO_PAD.encode(registration.registration_upload)),
            credential_finalization_b64: None,
            identity_public_b64: Some(test_identity_public_b64(b'A')),
            identity_prekey_id: Some(test_prekey_id(b'A')),
            identity_envelope_b64: Some(URL_SAFE_NO_PAD.encode({
                let mut envelope = vec![0_u8; 256];
                envelope[0] = IDENTITY_ENVELOPE_VERSION;
                envelope
            })),
            identity_proof_b64: None,
        };

        let account_guard = state.account_ops.lock().await;
        let finish_task = tokio::spawn(finish_opaque_account(State(state.clone()), Json(request)));
        tokio::task::yield_now().await;
        let wipe_state = state.clone();
        let mut wipe_task = tokio::spawn(async move {
            wipe_relay_state(&wipe_state, false).await;
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut wipe_task)
                .await
                .is_err(),
            "wipe must wait for an in-flight account operation"
        );
        drop(account_guard);

        tokio::time::timeout(Duration::from_secs(2), finish_task)
            .await
            .expect("opaque finish should complete")
            .expect("opaque finish task should not panic");
        tokio::time::timeout(Duration::from_secs(2), wipe_task)
            .await
            .expect("wipe should finish")
            .expect("wipe task should not panic");

        assert!(state.accounts.lock().await.is_empty());
        assert!(state.sessions.lock().await.is_empty());
        assert!(state.opaque_handshakes.lock().await.is_empty());
        assert!(state.available_codes.lock().await.is_empty());
    }

    #[test]
    fn attachment_capacity_enforces_global_and_per_account_limits_without_overflow() {
        assert!(attachment_capacity_allows(0, 0, 4, 10, 4));
        assert!(!attachment_capacity_allows(0, 0, 5, 10, 4));
        assert!(!attachment_capacity_allows(9, 0, 2, 10, 4));
        assert!(!attachment_capacity_allows(
            usize::MAX,
            0,
            1,
            usize::MAX,
            usize::MAX
        ));
    }

    #[test]
    fn attachment_record_limits_are_clamped_and_account_bound() {
        assert_eq!(
            attachment_record_limits_from_values(None, None),
            (
                DEFAULT_ATTACHMENT_RECORD_LIMIT,
                DEFAULT_ATTACHMENT_ACCOUNT_RECORD_LIMIT
            )
        );
        assert_eq!(
            attachment_record_limits_from_values(Some("0"), Some("999999")),
            (MIN_ATTACHMENT_RECORD_LIMIT, MIN_ATTACHMENT_RECORD_LIMIT)
        );
        assert_eq!(
            attachment_record_limits_from_values(Some("999999"), Some("999999")),
            (MAX_ATTACHMENT_RECORD_LIMIT, MAX_ATTACHMENT_RECORD_LIMIT)
        );
        assert_eq!(
            attachment_record_limits_from_values(Some("2"), Some("3")),
            (2, 2)
        );
        assert_eq!(
            attachment_record_limits_from_values(Some("2"), None),
            (2, 2)
        );
        assert_eq!(
            attachment_record_limits_from_values(Some("-1"), Some("")),
            (
                DEFAULT_ATTACHMENT_RECORD_LIMIT,
                DEFAULT_ATTACHMENT_ACCOUNT_RECORD_LIMIT
            )
        );
        assert_eq!(
            attachment_record_limits_from_values(Some("not-a-number"), Some("also-invalid")),
            (
                DEFAULT_ATTACHMENT_RECORD_LIMIT,
                DEFAULT_ATTACHMENT_ACCOUNT_RECORD_LIMIT
            )
        );
    }

    #[test]
    fn attachment_record_capacity_isolated_and_boundary_safe() {
        assert!(attachment_record_capacity_allows(0, 0, 1, 1));
        assert!(!attachment_record_capacity_allows(1, 1, 2, 1));
        assert!(!attachment_record_capacity_allows(0, 1, 2, 1));
        assert!(!attachment_record_capacity_allows(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            usize::MAX,
        ));
        assert!(attachment_record_capacity_allows(1, 0, 2, 1));
    }

    #[test]
    fn attachment_content_length_must_be_positive_and_bounded() {
        let headers = HeaderMap::new();
        assert_eq!(
            declared_attachment_length(&headers, 10),
            Err(StatusCode::LENGTH_REQUIRED)
        );
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        assert_eq!(
            declared_attachment_length(&headers, 10),
            Err(StatusCode::LENGTH_REQUIRED)
        );
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("invalid"));
        assert_eq!(
            declared_attachment_length(&headers, 10),
            Err(StatusCode::LENGTH_REQUIRED)
        );
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("11"));
        assert_eq!(
            declared_attachment_length(&headers, 10),
            Err(StatusCode::PAYLOAD_TOO_LARGE)
        );
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("7"));
        assert_eq!(declared_attachment_length(&headers, 10), Ok(7));
    }

    #[test]
    fn attachment_memory_permit_is_weighted_and_released() {
        let memory = Arc::new(Semaphore::new(10));
        let permit = acquire_attachment_memory_permit(&memory, 7).expect("weighted permit");
        assert_eq!(memory.available_permits(), 3);
        assert!(acquire_attachment_memory_permit(&memory, 4).is_err());
        drop(permit);
        assert_eq!(memory.available_permits(), 10);
        let permit = acquire_attachment_memory_permit(&memory, 10).expect("full budget");
        drop(permit);
        assert_eq!(memory.available_permits(), 10);
    }

    #[test]
    fn encrypted_attachment_body_requires_version_and_authentication_overhead() {
        assert!(!valid_encrypted_attachment_body(&[]));
        assert!(!valid_encrypted_attachment_body(
            &[ATTACHMENT_BLOB_VERSION; ATTACHMENT_WIRE_OVERHEAD_BYTES - 1]
        ));
        assert!(!valid_encrypted_attachment_body(
            &[0; ATTACHMENT_WIRE_OVERHEAD_BYTES]
        ));
        assert!(valid_encrypted_attachment_body(
            &[ATTACHMENT_BLOB_VERSION; ATTACHMENT_WIRE_OVERHEAD_BYTES]
        ));
    }

    #[tokio::test]
    async fn uploaded_attachment_cleanup_is_owner_only_and_releases_usage() {
        let mut state = test_state();
        state.attachment_record_limit = 1;
        state.attachment_account_record_limit = 1;
        let owner = test_code_id("cleanup-owner");
        let other = test_code_id("cleanup-other");
        let attachment_id = Uuid::new_v4();
        state.attachments.lock().await.insert(
            attachment_id,
            AttachmentRecord {
                blob: test_attachment_blob(vec![1, 2, 3, 4]),
                chat_id: "dm_cleanup".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                one_time: false,
                delete_after_download: false,
                expires_at_ms: None,
                eligible_recipient_code_ids: HashSet::new(),
                download_claims: HashMap::new(),
                completed_recipient_code_ids: HashSet::new(),
            },
        );
        state.attachment_bytes_by_code.lock().await.insert(owner, 4);
        {
            let attachments = state.attachments.lock().await;
            assert!(!attachment_record_capacity_allows(
                attachments.len(),
                current_attachment_records_for_owner(&attachments, &owner),
                1,
                1,
            ));
        }

        assert_eq!(
            delete_owned_attachment(&state, attachment_id, &other).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            delete_owned_attachment(&state, attachment_id, &owner).await,
            StatusCode::NO_CONTENT
        );
        assert!(!state.attachments.lock().await.contains_key(&attachment_id));
        assert!(state.attachment_bytes_by_code.lock().await.is_empty());
        assert!(attachment_record_capacity_available(&state, &owner).await);
    }

    #[tokio::test]
    async fn attachment_download_permit_lives_with_response() {
        let downloads = Arc::new(Semaphore::new(1));
        let permit = acquire_attachment_download_permit(&downloads).expect("first download");
        let response = attachment_download_response(vec![1, 2, 3], permit, None);

        assert!(acquire_attachment_download_permit(&downloads).is_err());
        drop(response);
        for _ in 0..8 {
            if acquire_attachment_download_permit(&downloads).is_ok() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("download permit was not released after response drop");
    }

    #[tokio::test]
    async fn abandoned_attachment_download_releases_buffer_and_permit_after_stall() {
        let downloads = Arc::new(Semaphore::new(1));
        let permit = acquire_attachment_download_permit(&downloads).expect("download permit");
        let bytes = vec![0xA5_u8; ATTACHMENT_DOWNLOAD_CHUNK_BYTES * 2];
        let response = attachment_download_response_with_timeout(
            bytes,
            permit,
            None,
            Duration::from_millis(5),
        );
        assert!(acquire_attachment_download_permit(&downloads).is_err());
        let mut released = false;
        for _ in 0..20 {
            if let Ok(replacement) = acquire_attachment_download_permit(&downloads) {
                drop(replacement);
                released = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(released, "stalled producer releases its permit");
        drop(response);
    }

    #[test]
    fn attachment_claim_header_requires_a_uuid() {
        let mut headers = HeaderMap::new();
        assert_eq!(attachment_claim_id(&headers), Err(StatusCode::BAD_REQUEST));
        headers.insert(
            ATTACHMENT_CLAIM_HEADER,
            HeaderValue::from_static("not-a-claim"),
        );
        assert_eq!(attachment_claim_id(&headers), Err(StatusCode::BAD_REQUEST));
        let claim_id = Uuid::new_v4();
        headers.insert(
            ATTACHMENT_CLAIM_HEADER,
            HeaderValue::from_str(&claim_id.to_string()).expect("claim header"),
        );
        assert_eq!(attachment_claim_id(&headers), Ok(claim_id));
    }

    #[tokio::test]
    async fn unauthorized_attachment_upload_does_not_poll_request_body() {
        let state = test_state();
        let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let body = Body::from_stream(futures_util::stream::once({
            let polls = Arc::clone(&polls);
            async move {
                polls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok::<Bytes, Infallible>(Bytes::from(vec![7_u8; 1024]))
            }
        }));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer invalid"),
        );
        let response = upload_attachment(
            State(state),
            Query(AttachmentQuery {
                chat_id: "dm_unknown".to_string(),
                media_type: Some("FILE".to_string()),
                one_time: None,
                delete_after_download: None,
                ttl_sec: None,
            }),
            headers,
            body,
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(polls.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn revoked_session_cannot_commit_after_slow_attachment_upload() {
        let state = test_state();
        add_test_account(&state, "slow-owner", "Alice").await;
        let room = test_room("slow_upload_room");
        state.room_catalog.lock().await.insert(
            room.id.clone(),
            RoomEntry {
                room,
                owner_code_id: test_code_id("slow-owner"),
            },
        );
        state.sessions.lock().await.insert(
            SessionToken::new("slow-upload-token".to_string()),
            AuthSession {
                code_id: test_code_id("slow-owner"),
                username: "Alice".to_string(),
                last_activity_ms: now_ms(),
            },
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer slow-upload-token"),
        );
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("9"));
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let body = Body::from_stream(futures_util::stream::once(async move {
            ready_tx.send(()).expect("upload task is listening");
            release_rx.await.expect("release upload body");
            Ok::<Bytes, Infallible>(Bytes::from_static(b"encrypted"))
        }));
        let request_state = state.clone();
        let task = tokio::spawn(async move {
            upload_attachment(
                State(request_state),
                Query(AttachmentQuery {
                    chat_id: "slow_upload_room".to_string(),
                    media_type: Some("FILE".to_string()),
                    one_time: None,
                    delete_after_download: None,
                    ttl_sec: None,
                }),
                headers,
                body,
            )
            .await
            .into_response()
        });
        ready_rx.await.expect("body was polled");
        state.sessions.lock().await.remove("slow-upload-token");
        release_tx.send(()).expect("release body");
        let response = task.await.expect("upload task");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(state.attachments.lock().await.is_empty());
    }

    #[tokio::test]
    async fn global_wipe_rejects_upload_that_started_before_wipe() {
        let state = test_state();
        add_test_account(&state, "wipe-upload-owner", "Alice").await;
        let room = test_room("wipe_upload_room");
        state.room_catalog.lock().await.insert(
            room.id.clone(),
            RoomEntry {
                room,
                owner_code_id: test_code_id("wipe-upload-owner"),
            },
        );
        state.sessions.lock().await.insert(
            SessionToken::new("wipe-upload-token".to_string()),
            AuthSession {
                code_id: test_code_id("wipe-upload-owner"),
                username: "Alice".to_string(),
                last_activity_ms: now_ms(),
            },
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer wipe-upload-token"),
        );
        let body_bytes = vec![ATTACHMENT_BLOB_VERSION; ATTACHMENT_WIRE_OVERHEAD_BYTES];
        headers.insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&body_bytes.len().to_string()).expect("content length"),
        );
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let body = Body::from_stream(futures_util::stream::once(async move {
            ready_tx.send(()).expect("upload task is listening");
            release_rx.await.expect("release upload body");
            Ok::<Bytes, Infallible>(Bytes::from(body_bytes))
        }));
        let request_state = state.clone();
        let task = tokio::spawn(async move {
            upload_attachment(
                State(request_state),
                Query(AttachmentQuery {
                    chat_id: "wipe_upload_room".to_string(),
                    media_type: Some("FILE".to_string()),
                    one_time: None,
                    delete_after_download: None,
                    ttl_sec: None,
                }),
                headers,
                body,
            )
            .await
            .into_response()
        });
        ready_rx.await.expect("body was polled");
        wipe_relay_state(&state, false).await;
        release_tx.send(()).expect("release body");
        let response = task.await.expect("upload task");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(state.attachments.lock().await.is_empty());
        assert_eq!(state.attachment_memory.available_permits(), 8 * 1024 * 1024);
    }

    #[tokio::test]
    async fn global_wipe_stops_download_stream_before_first_chunk() {
        let downloads = Arc::new(Semaphore::new(1));
        let permit = acquire_attachment_download_permit(&downloads).expect("download permit");
        let bytes = test_attachment_blob(vec![0xA5_u8; ATTACHMENT_DOWNLOAD_CHUNK_BYTES]);
        let epoch = Arc::new(AtomicU64::new(0));
        let response = attachment_download_response_with_epoch(
            bytes,
            permit,
            None,
            Arc::clone(&epoch),
            0,
            Duration::from_millis(5),
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
        epoch.fetch_add(1, Ordering::AcqRel);
        let mut stream = response.into_body().into_data_stream();
        assert!(stream.next().await.is_none());
        assert!(acquire_attachment_download_permit(&downloads).is_ok());
    }

    #[tokio::test]
    async fn attachment_download_reservation_shares_owned_bytes_without_copy() {
        let state = test_state();
        let attachment_id = Uuid::new_v4();
        let owner = test_code_id("shared-owner");
        let bytes = test_attachment_blob(vec![1, 2, 3, 4]);
        state.attachments.lock().await.insert(
            attachment_id,
            AttachmentRecord {
                blob: Arc::clone(&bytes),
                chat_id: "dm_shared".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                one_time: false,
                delete_after_download: false,
                expires_at_ms: None,
                eligible_recipient_code_ids: HashSet::new(),
                download_claims: HashMap::new(),
                completed_recipient_code_ids: HashSet::new(),
            },
        );
        let reservation = reserve_attachment_download(&state, attachment_id, &owner)
            .await
            .expect("download reservation");
        assert!(Arc::ptr_eq(&bytes, &reservation.blob));
        assert_eq!(Arc::strong_count(&bytes), 3);
    }

    #[tokio::test]
    async fn attachment_memory_permit_lives_until_final_download_blob_reference() {
        let state = test_state();
        let attachment_id = Uuid::new_v4();
        let owner = test_code_id("blob-owner");
        let permit = acquire_attachment_memory_permit(&state.attachment_memory, 4)
            .expect("attachment memory permit");
        let blob = Arc::new(AttachmentBlob {
            bytes: Zeroizing::new(vec![1, 2, 3, 4]),
            _memory_permit: Some(permit),
        });
        state.attachments.lock().await.insert(
            attachment_id,
            AttachmentRecord {
                blob: Arc::clone(&blob),
                chat_id: "dm_blob_lifetime".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                one_time: false,
                delete_after_download: false,
                expires_at_ms: None,
                eligible_recipient_code_ids: HashSet::new(),
                download_claims: HashMap::new(),
                completed_recipient_code_ids: HashSet::new(),
            },
        );
        drop(blob);

        let reservation = reserve_attachment_download(&state, attachment_id, &owner)
            .await
            .expect("download reservation");
        assert_eq!(
            state.attachment_memory.available_permits(),
            8 * 1024 * 1024 - 4
        );
        let download_permit = acquire_attachment_download_permit(&state.attachment_downloads)
            .expect("download permit");
        let response = attachment_download_response_with_epoch(
            Arc::clone(&reservation.blob),
            download_permit,
            None,
            Arc::clone(&state.attachment_epoch),
            reservation.epoch,
            ATTACHMENT_DOWNLOAD_STALL_TIMEOUT,
        );
        assert_eq!(
            delete_owned_attachment(&state, attachment_id, &owner).await,
            StatusCode::NO_CONTENT
        );
        drop(reservation);
        assert_eq!(
            state.attachment_memory.available_permits(),
            8 * 1024 * 1024 - 4
        );

        let mut stream = response.into_body().into_data_stream();
        while stream.next().await.is_some() {}
        for _ in 0..20 {
            if state.attachment_memory.available_permits() == 8 * 1024 * 1024 {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("attachment memory permit released only after final blob reference");
    }

    #[tokio::test]
    async fn full_data_queue_does_not_block_global_wipe_control_channel() {
        let state = test_state();
        let client_id = Uuid::new_v4();
        let (tx, rx) = mpsc::channel(CLIENT_OUTBOUND_QUEUE_CAPACITY);
        let (control_tx, mut control_rx) = mpsc::channel(CLIENT_CONTROL_QUEUE_CAPACITY);
        let (result_tx, _result_rx) = mpsc::channel(CLIENT_RESULT_QUEUE_CAPACITY);
        state.clients.lock().await.insert(
            client_id,
            ClientHandle {
                code_id: test_code_id("queue-client"),
                username: "Alice".to_string(),
                tx,
                control_tx,
                result_tx,
                queued_bytes: Arc::new(AtomicUsize::new(0)),
            },
        );
        let frame = test_message_frame("dm_queue", "queued-secret", "Alice", "", false);
        for _ in 0..CLIENT_OUTBOUND_QUEUE_CAPACITY {
            send_to_client(&state, client_id, &frame).await;
        }
        assert_eq!(rx.len(), CLIENT_OUTBOUND_QUEUE_CAPACITY);

        send_control_to_client(&state, client_id, ClientControl::GlobalWipe).await;
        assert!(matches!(
            control_rx.try_recv(),
            Ok(ClientControl::GlobalWipe)
        ));
        drop(rx);
        assert!(control_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn bounded_attachment_body_rejects_overflow_empty_and_truncation() {
        assert_eq!(
            read_bounded_attachment_body(Body::from(vec![1_u8, 2, 3]), 2, None)
                .await
                .expect_err("body exceeds limit"),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            read_bounded_attachment_body(Body::from(Vec::<u8>::new()), 2, None)
                .await
                .expect_err("empty body"),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            read_bounded_attachment_body(Body::from(vec![1_u8, 2]), 4, Some(3))
                .await
                .expect_err("truncated declared body"),
            StatusCode::BAD_REQUEST
        );
        let body = read_bounded_attachment_body(Body::from(vec![1_u8, 2, 3]), 4, Some(3))
            .await
            .expect("bounded body");
        assert_eq!(&*body, &[1_u8, 2, 3]);
        assert_eq!(body.capacity(), 3);
    }

    #[tokio::test]
    async fn stalled_attachment_body_times_out_without_waiting_forever() {
        let body = Body::from_stream(futures_util::stream::once(async {
            std::future::pending::<Result<Bytes, Infallible>>().await
        }));
        assert_eq!(
            read_bounded_attachment_body_with_timeout(body, 4, None, Duration::from_millis(5))
                .await
                .expect_err("idle body should time out"),
            StatusCode::REQUEST_TIMEOUT
        );
    }

    #[tokio::test]
    async fn total_attachment_upload_deadline_bounds_slow_chunked_body() {
        let body = Body::from_stream(futures_util::stream::once(async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok::<Bytes, Infallible>(Bytes::from_static(b"encrypted"))
        }));
        assert_eq!(
            read_bounded_attachment_body_with_timeouts(
                body,
                32,
                None,
                Duration::from_millis(100),
                Duration::from_millis(5),
            )
            .await
            .expect_err("total upload deadline should win over idle timeout"),
            StatusCode::REQUEST_TIMEOUT
        );
    }

    #[tokio::test]
    async fn attachment_download_response_preserves_exact_bytes() {
        let downloads = Arc::new(Semaphore::new(1));
        let permit = acquire_attachment_download_permit(&downloads).expect("download permit");
        let expected = (0..(ATTACHMENT_DOWNLOAD_CHUNK_BYTES * 2 + 17))
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let expected_length = expected.len().to_string();
        let claim_id = Uuid::new_v4();
        let response = attachment_download_response(expected.clone(), permit, Some(claim_id));
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok()),
            Some(expected_length.as_str())
        );
        assert_eq!(
            response
                .headers()
                .get(ATTACHMENT_CLAIM_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some(claim_id.to_string().as_str())
        );

        let mut stream = response.into_body().into_data_stream();
        let mut received = Vec::new();
        while let Some(chunk) = stream.next().await {
            received.extend_from_slice(&chunk.expect("attachment body chunk"));
        }
        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn destructive_attachment_requires_explicit_completion_after_stream_eof() {
        let mut state = test_state();
        state.attachment_record_limit = 1;
        state.attachment_account_record_limit = 1;
        let attachment_id = Uuid::new_v4();
        let owner = test_code_id("download-owner");
        let recipient = test_code_id("download-recipient");
        let expected = vec![11_u8, 22, 33, 44];
        state.attachments.lock().await.insert(
            attachment_id,
            AttachmentRecord {
                blob: test_attachment_blob(expected.clone()),
                chat_id: "dm_alice_bob".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                one_time: true,
                delete_after_download: true,
                expires_at_ms: None,
                eligible_recipient_code_ids: HashSet::from([recipient]),
                download_claims: HashMap::new(),
                completed_recipient_code_ids: HashSet::new(),
            },
        );
        state
            .attachment_bytes_by_code
            .lock()
            .await
            .insert(owner, expected.len());
        assert!(!attachment_record_capacity_available(&state, &owner).await);

        let reservation = reserve_attachment_download(&state, attachment_id, &recipient)
            .await
            .expect("first download reservation");
        let claim_id = reservation.claim_id.expect("destructive claim");
        let permit = acquire_attachment_download_permit(&state.attachment_downloads)
            .expect("download permit");
        let response = attachment_download_response_with_epoch(
            Arc::clone(&reservation.blob),
            permit,
            Some(claim_id),
            Arc::clone(&state.attachment_epoch),
            reservation.epoch,
            ATTACHMENT_DOWNLOAD_STALL_TIMEOUT,
        );
        let mut stream = response.into_body().into_data_stream();
        let mut received = Vec::new();
        while let Some(chunk) = stream.next().await {
            received.extend_from_slice(&chunk.expect("attachment body chunk"));
        }
        assert_eq!(received, expected);
        assert!(state.attachments.lock().await.contains_key(&attachment_id));
        assert!(matches!(
            reserve_attachment_download(&state, attachment_id, &recipient).await,
            Err(StatusCode::TOO_MANY_REQUESTS)
        ));
        complete_attachment_download_claim(&state, attachment_id, &recipient, claim_id)
            .await
            .expect("explicit completion");
        assert!(!state.attachments.lock().await.contains_key(&attachment_id));
        assert!(state.attachment_bytes_by_code.lock().await.is_empty());
        assert!(attachment_record_capacity_available(&state, &owner).await);
    }

    #[tokio::test]
    async fn interrupted_destructive_attachment_download_requires_explicit_release() {
        let state = test_state();
        let attachment_id = Uuid::new_v4();
        let owner = test_code_id("interrupted-owner");
        let recipient = test_code_id("interrupted-recipient");
        let expected = vec![55_u8; ATTACHMENT_DOWNLOAD_CHUNK_BYTES + 1];
        state.attachments.lock().await.insert(
            attachment_id,
            AttachmentRecord {
                blob: test_attachment_blob(expected.clone()),
                chat_id: "dm_alice_bob".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                one_time: true,
                delete_after_download: false,
                expires_at_ms: None,
                eligible_recipient_code_ids: HashSet::from([recipient]),
                download_claims: HashMap::new(),
                completed_recipient_code_ids: HashSet::new(),
            },
        );
        state
            .attachment_bytes_by_code
            .lock()
            .await
            .insert(owner, expected.len());

        let reservation = reserve_attachment_download(&state, attachment_id, &recipient)
            .await
            .expect("first download reservation");
        let claim_id = reservation.claim_id.expect("destructive claim");
        let permit = acquire_attachment_download_permit(&state.attachment_downloads)
            .expect("download permit");
        let response = attachment_download_response_with_epoch(
            Arc::clone(&reservation.blob),
            permit,
            Some(claim_id),
            Arc::clone(&state.attachment_epoch),
            reservation.epoch,
            ATTACHMENT_DOWNLOAD_STALL_TIMEOUT,
        );
        let mut stream = response.into_body().into_data_stream();
        let first = stream
            .next()
            .await
            .expect("first attachment chunk")
            .expect("attachment body chunk");
        assert!(!first.is_empty());
        drop(stream);

        assert!(matches!(
            reserve_attachment_download(&state, attachment_id, &recipient).await,
            Err(StatusCode::TOO_MANY_REQUESTS)
        ));
        release_attachment_download_claim(&state, attachment_id, &recipient, claim_id)
            .await
            .expect("explicit release");
        let retry = reserve_attachment_download(&state, attachment_id, &recipient)
            .await
            .expect("retry after release");
        assert_ne!(retry.claim_id, Some(claim_id));
        assert_eq!(&*retry.blob.bytes, &expected);
        release_attachment_download_claim(
            &state,
            attachment_id,
            &recipient,
            retry.claim_id.expect("retry claim"),
        )
        .await
        .expect("release retry claim");
    }

    #[tokio::test]
    async fn expired_attachment_claim_is_pruned_and_can_retry() {
        let state = test_state();
        let attachment_id = Uuid::new_v4();
        let owner = test_code_id("expired-owner");
        let recipient = test_code_id("expired-recipient");
        state.attachments.lock().await.insert(
            attachment_id,
            AttachmentRecord {
                blob: test_attachment_blob(vec![8, 9]),
                chat_id: "dm_alice_bob".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                one_time: true,
                delete_after_download: false,
                expires_at_ms: None,
                eligible_recipient_code_ids: HashSet::from([recipient]),
                download_claims: HashMap::new(),
                completed_recipient_code_ids: HashSet::new(),
            },
        );
        let first = reserve_attachment_download(&state, attachment_id, &recipient)
            .await
            .expect("initial claim");
        let first_claim = first.claim_id.expect("initial claim id");
        state
            .attachments
            .lock()
            .await
            .get_mut(&attachment_id)
            .expect("attachment")
            .download_claims
            .get_mut(&first_claim)
            .expect("claim")
            .created_at_ms = now_ms().saturating_sub(ATTACHMENT_CLAIM_TTL_MS + 1);

        let retry = reserve_attachment_download(&state, attachment_id, &recipient)
            .await
            .expect("expired claim is retryable");
        assert_ne!(retry.claim_id, Some(first_claim));
        release_attachment_download_claim(
            &state,
            attachment_id,
            &recipient,
            retry.claim_id.expect("retry claim"),
        )
        .await
        .expect("release retry claim");
    }

    #[tokio::test]
    async fn destructive_attachment_downloads_allow_only_one_claim() {
        let state = test_state();
        let attachment_id = Uuid::new_v4();
        let owner = test_code_id("concurrent-owner");
        let recipient = test_code_id("concurrent-recipient");
        state.attachments.lock().await.insert(
            attachment_id,
            AttachmentRecord {
                blob: test_attachment_blob(vec![1, 2, 3]),
                chat_id: "dm_alice_bob".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                one_time: false,
                delete_after_download: true,
                expires_at_ms: None,
                eligible_recipient_code_ids: HashSet::from([recipient]),
                download_claims: HashMap::new(),
                completed_recipient_code_ids: HashSet::new(),
            },
        );

        let first = reserve_attachment_download(&state, attachment_id, &recipient)
            .await
            .expect("first download reservation");
        let first_claim = first.claim_id.expect("first claim");
        assert!(matches!(
            reserve_attachment_download(&state, attachment_id, &recipient).await,
            Err(StatusCode::TOO_MANY_REQUESTS)
        ));
        release_attachment_download_claim(&state, attachment_id, &recipient, first_claim)
            .await
            .expect("release first claim");
        assert!(
            reserve_attachment_download(&state, attachment_id, &recipient)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn attachment_claim_rejects_wrong_user_and_claim() {
        let state = test_state();
        let attachment_id = Uuid::new_v4();
        let owner = test_code_id("claim-owner");
        let recipient = test_code_id("claim-recipient");
        let other = test_code_id("claim-other");
        state.attachments.lock().await.insert(
            attachment_id,
            AttachmentRecord {
                blob: test_attachment_blob(vec![4, 5, 6]),
                chat_id: "dm_alice_bob".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                one_time: true,
                delete_after_download: true,
                expires_at_ms: None,
                eligible_recipient_code_ids: HashSet::from([recipient]),
                download_claims: HashMap::new(),
                completed_recipient_code_ids: HashSet::new(),
            },
        );
        let reservation = reserve_attachment_download(&state, attachment_id, &recipient)
            .await
            .expect("claim");
        let claim_id = reservation.claim_id.expect("claim id");
        assert_eq!(
            complete_attachment_download_claim(&state, attachment_id, &other, claim_id).await,
            Err(StatusCode::FORBIDDEN)
        );
        assert_eq!(
            complete_attachment_download_claim(&state, attachment_id, &recipient, Uuid::new_v4())
                .await,
            Err(StatusCode::NOT_FOUND)
        );
        complete_attachment_download_claim(&state, attachment_id, &recipient, claim_id)
            .await
            .expect("matching user and claim");
    }

    #[tokio::test]
    async fn attachment_owner_preview_does_not_consume_recipient_download() {
        let state = test_state();
        let attachment_id = Uuid::new_v4();
        let owner = test_code_id("dm-owner");
        let recipient = test_code_id("dm-recipient");
        state.attachments.lock().await.insert(
            attachment_id,
            AttachmentRecord {
                blob: test_attachment_blob(vec![7, 8, 9]),
                chat_id: "dm_alice_bob".to_string(),
                media_type: "IMAGE".to_string(),
                owner_code_id: owner,
                one_time: true,
                delete_after_download: true,
                expires_at_ms: None,
                eligible_recipient_code_ids: HashSet::from([recipient]),
                download_claims: HashMap::new(),
                completed_recipient_code_ids: HashSet::new(),
            },
        );
        state.attachment_bytes_by_code.lock().await.insert(owner, 3);

        let owner_preview = reserve_attachment_download(&state, attachment_id, &owner)
            .await
            .expect("owner preview");
        assert!(owner_preview.claim_id.is_none());

        let recipient_download = reserve_attachment_download(&state, attachment_id, &recipient)
            .await
            .expect("recipient download");
        let claim_id = recipient_download.claim_id.expect("recipient claim");
        complete_attachment_download_claim(&state, attachment_id, &recipient, claim_id)
            .await
            .expect("recipient completion");
        assert!(!state.attachments.lock().await.contains_key(&attachment_id));
    }

    #[tokio::test]
    async fn room_attachment_completes_once_for_each_recipient() {
        let state = test_state();
        let attachment_id = Uuid::new_v4();
        let owner = test_code_id("room-owner");
        let bob = test_code_id("room-bob");
        let carol = test_code_id("room-carol");
        state.attachments.lock().await.insert(
            attachment_id,
            AttachmentRecord {
                blob: test_attachment_blob(vec![10, 11, 12]),
                chat_id: "forum_shared".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                one_time: false,
                delete_after_download: true,
                expires_at_ms: None,
                eligible_recipient_code_ids: HashSet::from([bob, carol]),
                download_claims: HashMap::new(),
                completed_recipient_code_ids: HashSet::new(),
            },
        );
        state.attachment_bytes_by_code.lock().await.insert(owner, 3);

        let bob_download = reserve_attachment_download(&state, attachment_id, &bob)
            .await
            .expect("Bob download");
        complete_attachment_download_claim(
            &state,
            attachment_id,
            &bob,
            bob_download.claim_id.expect("Bob claim"),
        )
        .await
        .expect("Bob completion");
        assert!(state.attachments.lock().await.contains_key(&attachment_id));

        let carol_download = reserve_attachment_download(&state, attachment_id, &carol)
            .await
            .expect("Carol download");
        complete_attachment_download_claim(
            &state,
            attachment_id,
            &carol,
            carol_download.claim_id.expect("Carol claim"),
        )
        .await
        .expect("Carol completion");
        assert!(!state.attachments.lock().await.contains_key(&attachment_id));
    }

    #[tokio::test]
    async fn destructive_attachment_recipient_snapshot_is_conversation_scoped() {
        let state = test_state();
        add_test_account(&state, "snapshot-a", "Alice").await;
        add_test_account(&state, "snapshot-b", "Bob").await;
        add_test_account(&state, "snapshot-c", "Carol").await;
        state.direct_catalog.lock().await.insert(
            "dm_snapshot".to_string(),
            DirectEntry {
                id: "dm_snapshot".to_string(),
                user_a: "Alice".to_string(),
                user_b: "Bob".to_string(),
            },
        );
        let direct_access = conversation_access(&state, "Alice", "dm_snapshot")
            .await
            .expect("direct access");
        assert_eq!(
            snapshot_attachment_recipients(
                &state,
                &direct_access,
                "dm_snapshot",
                "Alice",
                &test_code_id("snapshot-a"),
            )
            .await,
            HashSet::from([test_code_id("snapshot-b")])
        );

        let room = test_room("forum_snapshot");
        state.room_catalog.lock().await.insert(
            room.id.clone(),
            RoomEntry {
                room: room.clone(),
                owner_code_id: test_code_id("snapshot-a"),
            },
        );
        let room_access = conversation_access(&state, "Alice", &room.id)
            .await
            .expect("room access");
        assert_eq!(
            snapshot_attachment_recipients(
                &state,
                &room_access,
                &room.id,
                "Alice",
                &test_code_id("snapshot-a"),
            )
            .await,
            HashSet::from([test_code_id("snapshot-b"), test_code_id("snapshot-c")])
        );
    }

    #[tokio::test]
    async fn invalid_account_handshakes_do_not_refresh_dead_man_activity() {
        let state = test_state();
        *state.last_activity_ms.lock().await = 123;
        let _ = start_opaque_account(
            State(state.clone()),
            Json(OpaqueAccountStartRequest {
                code: "not-a-code".to_string(),
                registration_request_b64: String::new(),
                credential_request_b64: String::new(),
            }),
        )
        .await;
        assert_eq!(*state.last_activity_ms.lock().await, 123);

        let _ = finish_opaque_account(
            State(state.clone()),
            Json(OpaqueAccountFinishRequest {
                handshake_id: Uuid::new_v4(),
                registration_upload_b64: None,
                credential_finalization_b64: None,
                identity_public_b64: None,
                identity_prekey_id: None,
                identity_envelope_b64: None,
                identity_proof_b64: None,
            }),
        )
        .await;
        assert_eq!(*state.last_activity_ms.lock().await, 123);
    }

    #[tokio::test]
    async fn rejected_ws_operations_do_not_refresh_dead_man_activity() {
        let state = test_state();
        add_test_account(&state, "activity-a", "Alice").await;
        let (client_id, _receiver) = add_test_client(&state, "activity-a", "Alice").await;
        let room = test_room("activity-room");
        state.room_catalog.lock().await.insert(
            room.id.clone(),
            RoomEntry {
                room,
                owner_code_id: test_code_id("activity-a"),
            },
        );

        *state.last_activity_ms.lock().await = 123;
        assert!(handle_frame(
            &state,
            client_id,
            r#"{"type":"message","chat_id":"activity-room","version":0,"message_id":"","nonce_b64":"","ciphertext_b64":"","envelopes":[],"state_revision":0,"identity_envelope_b64":"","identity_public_b64":"","prekey_id":"","state_signature_b64":""}"#,
        )
        .await
        .is_err());
        assert_eq!(*state.last_activity_ms.lock().await, 123);

        *state.last_activity_ms.lock().await = 123;
        assert!(handle_frame(
            &state,
            client_id,
            r#"{"type":"message_ack","chat_id":"activity-room","message_id":"","sender_username":"","state_revision":0,"identity_envelope_b64":"","identity_public_b64":"","prekey_id":"","state_signature_b64":"","ack_signature_b64":"","used_prekey_id":""}"#,
        )
        .await
        .is_err());
        assert_eq!(*state.last_activity_ms.lock().await, 123);

        assert!(handle_frame(
            &state,
            client_id,
            r#"{"type":"join","chat_id":"activity-room"}"#,
        )
        .await
        .is_ok());
        assert!(*state.last_activity_ms.lock().await > 123);

        *state.last_activity_ms.lock().await = 123;
        assert!(handle_frame(&state, client_id, r#"{"type":"activity"}"#)
            .await
            .is_ok());
        assert!(*state.last_activity_ms.lock().await > 123);
    }

    #[tokio::test]
    async fn destructive_attachment_upload_requires_an_eligible_recipient() {
        let state = test_state();
        add_test_account(&state, "solo-owner", "Alice").await;
        let room = test_room("forum_solo");
        state.room_catalog.lock().await.insert(
            room.id.clone(),
            RoomEntry {
                room,
                owner_code_id: test_code_id("solo-owner"),
            },
        );
        state.sessions.lock().await.insert(
            SessionToken::new("solo-token".to_string()),
            AuthSession {
                code_id: test_code_id("solo-owner"),
                username: "Alice".to_string(),
                last_activity_ms: now_ms(),
            },
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer solo-token"),
        );
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("9"));
        let response = upload_attachment(
            State(state),
            Query(AttachmentQuery {
                chat_id: "forum_solo".to_string(),
                media_type: Some("FILE".to_string()),
                one_time: Some(true),
                delete_after_download: Some(true),
                ttl_sec: None,
            }),
            headers,
            Body::from(Bytes::from_static(b"encrypted")),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn attachment_record_limit_rejects_before_body_allocation() {
        let mut state = test_state();
        state.attachment_record_limit = 1;
        state.attachment_account_record_limit = 1;
        add_test_account(&state, "record-limit-owner", "Alice").await;
        let owner = test_code_id("record-limit-owner");
        let room = test_room("record_limit_room");
        state.room_catalog.lock().await.insert(
            room.id.clone(),
            RoomEntry {
                room,
                owner_code_id: owner,
            },
        );
        state.sessions.lock().await.insert(
            SessionToken::new("record-limit-token".to_string()),
            AuthSession {
                code_id: owner,
                username: "Alice".to_string(),
                last_activity_ms: now_ms(),
            },
        );
        state.attachments.lock().await.insert(
            Uuid::new_v4(),
            AttachmentRecord {
                blob: test_attachment_blob(vec![
                    ATTACHMENT_BLOB_VERSION;
                    ATTACHMENT_WIRE_OVERHEAD_BYTES
                ]),
                chat_id: "record_limit_room".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                one_time: false,
                delete_after_download: false,
                expires_at_ms: None,
                eligible_recipient_code_ids: HashSet::new(),
                download_claims: HashMap::new(),
                completed_recipient_code_ids: HashSet::new(),
            },
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer record-limit-token"),
        );
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("41"));
        let body = Body::from_stream(futures_util::stream::once(async {
            panic!("a saturated attachment record limit must reject before reading the body");
            #[allow(unreachable_code)]
            Ok::<Bytes, Infallible>(Bytes::new())
        }));
        let response = upload_attachment(
            State(state.clone()),
            Query(AttachmentQuery {
                chat_id: "record_limit_room".to_string(),
                media_type: Some("FILE".to_string()),
                one_time: None,
                delete_after_download: None,
                ttl_sec: None,
            }),
            headers,
            body,
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::from_u16(507).unwrap());
        assert_eq!(state.attachments.lock().await.len(), 1);
        assert_eq!(state.attachment_memory.available_permits(), 8 * 1024 * 1024);
    }

    #[tokio::test]
    async fn concurrent_attachment_admission_rechecks_global_record_limit_atomically() {
        let mut state = test_state();
        state.attachment_record_limit = 1;
        state.attachment_account_record_limit = 1;
        state.attachment_uploads = Arc::new(Semaphore::new(2));
        add_test_account(&state, "record-race-a", "Alice").await;
        add_test_account(&state, "record-race-b", "Bob").await;
        let room = test_room("record_race_room");
        state.room_catalog.lock().await.insert(
            room.id.clone(),
            RoomEntry {
                room,
                owner_code_id: test_code_id("record-race-a"),
            },
        );
        for (token, code_id, username) in [
            ("record-race-token-a", "record-race-a", "Alice"),
            ("record-race-token-b", "record-race-b", "Bob"),
        ] {
            state.sessions.lock().await.insert(
                SessionToken::new(token.to_string()),
                AuthSession {
                    code_id: test_code_id(code_id),
                    username: username.to_string(),
                    last_activity_ms: now_ms(),
                },
            );
        }

        let gate = Arc::new(tokio::sync::Barrier::new(3));
        let request_state = state.clone();
        let make_request = move |token: &'static str, gate: Arc<tokio::sync::Barrier>| {
            let state = request_state.clone();
            async move {
                let mut headers = HeaderMap::new();
                headers.insert(
                    header::AUTHORIZATION,
                    HeaderValue::from_static(match token {
                        "record-race-token-a" => "Bearer record-race-token-a",
                        _ => "Bearer record-race-token-b",
                    }),
                );
                headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("41"));
                let body_gate = gate;
                upload_attachment(
                    State(state.clone()),
                    Query(AttachmentQuery {
                        chat_id: "record_race_room".to_string(),
                        media_type: Some("FILE".to_string()),
                        one_time: None,
                        delete_after_download: None,
                        ttl_sec: None,
                    }),
                    headers,
                    Body::from_stream(futures_util::stream::once(async move {
                        body_gate.wait().await;
                        Ok::<Bytes, Infallible>(Bytes::from(vec![
                            ATTACHMENT_BLOB_VERSION;
                            ATTACHMENT_WIRE_OVERHEAD_BYTES
                        ]))
                    })),
                )
                .await
            }
        };
        let release_gate = Arc::clone(&gate);
        let (first, second, _) = tokio::join!(
            make_request("record-race-token-a", Arc::clone(&gate)),
            make_request("record-race-token-b", Arc::clone(&gate)),
            async move {
                release_gate.wait().await;
            }
        );
        let statuses = [
            first.into_response().status(),
            second.into_response().status(),
        ];
        assert!(statuses.contains(&StatusCode::OK));
        assert!(statuses.contains(&StatusCode::from_u16(507).unwrap()));
        assert_eq!(state.attachments.lock().await.len(), 1);
        assert_eq!(
            state.attachment_memory.available_permits(),
            8 * 1024 * 1024 - ATTACHMENT_WIRE_OVERHEAD_BYTES
        );
        let usage = state.attachment_bytes_by_code.lock().await;
        assert_eq!(
            usage.values().copied().sum::<usize>(),
            ATTACHMENT_WIRE_OVERHEAD_BYTES
        );
        assert_eq!(usage.len(), 1);
    }

    #[tokio::test]
    async fn attachment_record_limits_enforce_account_then_global_boundaries() {
        let mut state = test_state();
        state.attachment_record_limit = 2;
        state.attachment_account_record_limit = 1;
        add_test_account(&state, "record-boundary-a", "Alice").await;
        add_test_account(&state, "record-boundary-b", "Bob").await;
        let room_id = "record_boundary_room";
        state.room_catalog.lock().await.insert(
            room_id.to_string(),
            RoomEntry {
                room: test_room(room_id),
                owner_code_id: test_code_id("record-boundary-a"),
            },
        );
        for (token, code, username) in [
            ("record-boundary-token-a", "record-boundary-a", "Alice"),
            ("record-boundary-token-b", "record-boundary-b", "Bob"),
        ] {
            state.sessions.lock().await.insert(
                SessionToken::new(token.to_string()),
                AuthSession {
                    code_id: test_code_id(code),
                    username: username.to_string(),
                    last_activity_ms: now_ms(),
                },
            );
        }

        let upload = |token: &'static str| {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {token}")).expect("test bearer token"),
            );
            headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("41"));
            upload_attachment(
                State(state.clone()),
                Query(AttachmentQuery {
                    chat_id: room_id.to_string(),
                    media_type: Some("FILE".to_string()),
                    one_time: None,
                    delete_after_download: None,
                    ttl_sec: None,
                }),
                headers,
                Body::from(vec![
                    ATTACHMENT_BLOB_VERSION;
                    ATTACHMENT_WIRE_OVERHEAD_BYTES
                ]),
            )
        };

        assert_eq!(
            upload("record-boundary-token-a")
                .await
                .into_response()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            upload("record-boundary-token-a")
                .await
                .into_response()
                .status(),
            StatusCode::from_u16(507).unwrap(),
            "the per-account limit rejects the exact next record"
        );
        assert_eq!(
            upload("record-boundary-token-b")
                .await
                .into_response()
                .status(),
            StatusCode::OK,
            "another account can use remaining global capacity"
        );
        assert_eq!(
            upload("record-boundary-token-b")
                .await
                .into_response()
                .status(),
            StatusCode::from_u16(507).unwrap(),
            "the global limit rejects the exact next record"
        );
        assert_eq!(state.attachments.lock().await.len(), 2);
        assert_eq!(
            state.attachment_memory.available_permits(),
            8 * 1024 * 1024 - 2 * ATTACHMENT_WIRE_OVERHEAD_BYTES
        );
        let usage = state.attachment_bytes_by_code.lock().await;
        assert_eq!(usage.get(&test_code_id("record-boundary-a")), Some(&41));
        assert_eq!(usage.get(&test_code_id("record-boundary-b")), Some(&41));
        drop(usage);

        remove_chat_attachments(&state, room_id).await;
        assert!(state.attachments.lock().await.is_empty());
        assert!(state.attachment_bytes_by_code.lock().await.is_empty());
        assert_eq!(state.attachment_memory.available_permits(), 8 * 1024 * 1024);
        assert_eq!(
            upload("record-boundary-token-a")
                .await
                .into_response()
                .status(),
            StatusCode::OK,
            "room deletion cleanup releases record and byte capacity"
        );
    }

    #[tokio::test]
    async fn global_wipe_releases_attachment_record_and_byte_capacity_for_reuse() {
        let mut state = test_state();
        state.attachment_record_limit = 1;
        state.attachment_account_record_limit = 1;
        add_test_account(&state, "record-wipe-owner", "Alice").await;
        let room_id = "record_wipe_room";
        state.room_catalog.lock().await.insert(
            room_id.to_string(),
            RoomEntry {
                room: test_room(room_id),
                owner_code_id: test_code_id("record-wipe-owner"),
            },
        );
        state.sessions.lock().await.insert(
            SessionToken::new("record-wipe-token".to_string()),
            AuthSession {
                code_id: test_code_id("record-wipe-owner"),
                username: "Alice".to_string(),
                last_activity_ms: now_ms(),
            },
        );
        let upload = |state: AppState| async move {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::AUTHORIZATION,
                HeaderValue::from_static("Bearer record-wipe-token"),
            );
            headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("41"));
            upload_attachment(
                State(state),
                Query(AttachmentQuery {
                    chat_id: room_id.to_string(),
                    media_type: Some("FILE".to_string()),
                    one_time: None,
                    delete_after_download: None,
                    ttl_sec: None,
                }),
                headers,
                Body::from(vec![
                    ATTACHMENT_BLOB_VERSION;
                    ATTACHMENT_WIRE_OVERHEAD_BYTES
                ]),
            )
            .await
            .into_response()
            .status()
        };

        assert_eq!(upload(state.clone()).await, StatusCode::OK);
        assert_eq!(state.attachments.lock().await.len(), 1);
        wipe_relay_state(&state, false).await;
        assert!(state.attachments.lock().await.is_empty());
        assert!(state.attachment_bytes_by_code.lock().await.is_empty());
        assert_eq!(state.attachment_memory.available_permits(), 8 * 1024 * 1024);

        add_test_account(&state, "record-wipe-owner", "Alice").await;
        state.room_catalog.lock().await.insert(
            room_id.to_string(),
            RoomEntry {
                room: test_room(room_id),
                owner_code_id: test_code_id("record-wipe-owner"),
            },
        );
        state.sessions.lock().await.insert(
            SessionToken::new("record-wipe-token".to_string()),
            AuthSession {
                code_id: test_code_id("record-wipe-owner"),
                username: "Alice".to_string(),
                last_activity_ms: now_ms(),
            },
        );
        assert_eq!(upload(state.clone()).await, StatusCode::OK);
    }

    #[test]
    fn attachment_upload_permit_rejects_excess_body_readers() {
        let uploads = Arc::new(Semaphore::new(1));
        let permit = acquire_attachment_upload_permit(&uploads).expect("first upload");
        assert!(acquire_attachment_upload_permit(&uploads).is_err());
        drop(permit);
        assert!(acquire_attachment_upload_permit(&uploads).is_ok());
    }

    #[tokio::test]
    async fn account_attachment_upload_permit_isolated_and_bounded() {
        let state = test_state();
        add_test_account(&state, "upload-account", "Alice").await;
        let code_id = test_code_id("upload-account");
        let first = acquire_account_attachment_upload_permit(&state, &code_id)
            .await
            .expect("first account upload");
        let second = acquire_account_attachment_upload_permit(&state, &code_id).await;
        assert!(matches!(second, Err(StatusCode::TOO_MANY_REQUESTS)));
        drop(first);
        assert!(acquire_account_attachment_upload_permit(&state, &code_id)
            .await
            .is_ok());
        assert!(matches!(
            acquire_account_attachment_upload_permit(&state, &test_code_id("missing")).await,
            Err(StatusCode::UNAUTHORIZED)
        ));
    }

    #[test]
    fn protocol_base64_requires_exact_unpadded_lengths() {
        let url_safe_bytes = [0xfb_u8, 0xff, 0x00];
        let url_safe = URL_SAFE_NO_PAD.encode(url_safe_bytes);
        assert_eq!(url_safe, "-_8A");
        assert_eq!(
            decode_bounded(&url_safe, url_safe_bytes.len()).unwrap(),
            url_safe_bytes
        );

        let encoded = URL_SAFE_NO_PAD.encode([7_u8; MESSAGE_NONCE_BYTES]);
        assert_eq!(
            decode_exact(&encoded, MESSAGE_NONCE_BYTES).unwrap(),
            vec![7; 12]
        );
        assert!(decode_exact(&encoded, MESSAGE_NONCE_BYTES + 1).is_err());
        assert!(decode_exact(&encoded[..encoded.len() - 1], MESSAGE_NONCE_BYTES).is_err());

        // URL_SAFE_NO_PAD must reject the padded form and non-canonical
        // trailing bits rather than accepting alternate encodings of bytes.
        assert!(decode_bounded("AQ==", 1).is_err());
        assert!(decode_bounded("AB", 1).is_err());
        assert!(decode_bounded("AA+_", 3).is_err());
        assert!(decode_bounded("", 128).is_err());
        assert!(decode_bounded("not base64!", 128).is_err());

        let oversized = "A".repeat(2 * 4 + 1);
        assert!(decode_bounded(&oversized, 4).is_err());
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

    #[tokio::test]
    async fn room_catalog_is_capped_and_catalog_send_is_bounded() {
        let state = test_state();
        add_test_account(&state, "catalog-owner", "Alice").await;
        let (client_id, mut rx) = add_test_client(&state, "catalog-owner", "Alice").await;
        for index in 0..MAX_ROOM_CATALOG_ENTRIES {
            let mut room = test_room("forum_catalog");
            room.id = format!("forum_catalog_{index}");
            state.room_catalog.lock().await.insert(
                room.id.clone(),
                RoomEntry {
                    room,
                    owner_code_id: test_code_id("catalog-owner"),
                },
            );
        }
        send_room_catalog(&state, client_id).await;
        let frame = rx.try_recv().expect("bounded room catalog");
        assert!(matches!(
            &frame,
            OutboundFrame::Rooms { rooms } if rooms.len() <= MAX_ROOM_CATALOG_ENTRIES
        ));

        let mut extra = test_room("forum_catalog_extra");
        extra.id = "forum_catalog_extra".to_string();
        assert_eq!(
            create_room(&state, client_id, extra).await,
            Err("room catalog limit reached".to_string())
        );
        assert_eq!(
            state.room_catalog.lock().await.len(),
            MAX_ROOM_CATALOG_ENTRIES
        );
    }

    #[tokio::test]
    async fn room_catalog_rejects_case_colliding_ids() {
        let state = test_state();
        add_test_account(&state, "case-owner", "Alice").await;
        let (client_id, _) = add_test_client(&state, "case-owner", "Alice").await;

        let mut first = test_room("forum_case");
        first.id = "forum_case".to_string();
        create_room(&state, client_id, first)
            .await
            .expect("first room should be created");

        let mut collision = test_room("forum_case_upper");
        collision.id = "forum_CASE".to_string();
        assert_eq!(
            create_room(&state, client_id, collision).await,
            Err("room id rejected".to_string())
        );
        assert_eq!(state.room_catalog.lock().await.len(), 1);
    }

    #[test]
    fn pending_message_ttl_defaults_and_clamps_to_safe_bounds() {
        let hour_ms = HOURS_TO_MILLISECONDS;
        assert_eq!(
            pending_message_ttl_ms_from_value(None),
            DEFAULT_PENDING_MESSAGE_TTL_HOURS as u64 * hour_ms
        );
        assert_eq!(pending_message_ttl_ms_from_value(Some("0")), hour_ms);
        assert_eq!(
            pending_message_ttl_ms_from_value(Some("999999")),
            MAX_PENDING_MESSAGE_TTL_HOURS as u64 * hour_ms
        );
        assert_eq!(
            pending_message_ttl_ms_from_value(Some("not-a-number")),
            DEFAULT_PENDING_MESSAGE_TTL_HOURS as u64 * hour_ms
        );
    }

    #[test]
    fn websocket_ticket_requires_protocol_v1_and_rejects_bearer() {
        let raw_ticket = URL_SAFE_NO_PAD.encode([7_u8; WS_TICKET_BYTES]);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_str(&format!("abyssal-v1, ticket.{raw_ticket}"))
                .expect("valid subprotocol"),
        );

        assert_eq!(
            websocket_ticket_header(&headers).as_deref(),
            Some(&raw_ticket)
        );
        headers.insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_str(&format!("abyssal-v1, bearer.{raw_ticket}"))
                .expect("valid subprotocol"),
        );
        assert!(websocket_ticket_header(&headers).is_none());
        headers.insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_str(&format!("ticket.{raw_ticket}")).expect("valid subprotocol"),
        );
        assert!(websocket_ticket_header(&headers).is_none());
        headers.insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static("abyssal-v1, ticket.invalid"),
        );
        assert!(websocket_ticket_header(&headers).is_none());
    }

    #[test]
    fn websocket_ticket_digest_requires_canonical_url_safe_no_pad() {
        let canonical = URL_SAFE_NO_PAD.encode([0_u8; WS_TICKET_BYTES]);
        assert_eq!(canonical.len(), WS_TICKET_B64_LEN);
        assert!(ws_ticket_digest(&canonical).is_some());

        let padded = format!("{canonical}=");
        assert!(ws_ticket_digest(&padded).is_none());

        let mut noncanonical = canonical.clone();
        noncanonical.replace_range((WS_TICKET_B64_LEN - 1).., "B");
        assert!(ws_ticket_digest(&noncanonical).is_none());

        let mut standard_alphabet = canonical;
        standard_alphabet.replace_range((WS_TICKET_B64_LEN - 1).., "/");
        assert!(ws_ticket_digest(&standard_alphabet).is_none());
    }

    fn ticket_auth_headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).expect("valid authorization header"),
        );
        headers
    }

    async fn issue_test_ticket(state: &AppState, token: &str) -> (StatusCode, WsTicketResponse) {
        let response = issue_ws_ticket(State(state.clone()), ticket_auth_headers(token)).await;
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("ticket response body");
        let ticket = serde_json::from_slice(&body).expect("ticket response JSON");
        (status, ticket)
    }

    async fn add_test_session(state: &AppState, token: &str, code: &str, username: &str) {
        state.sessions.lock().await.insert(
            SessionToken::new(token.to_string()),
            AuthSession {
                code_id: test_code_id(code),
                username: username.to_string(),
                last_activity_ms: now_ms(),
            },
        );
    }

    #[tokio::test]
    async fn websocket_ticket_is_hash_only_no_store_and_single_use() {
        let state = test_state();
        add_test_session(&state, "ticket-session", "ticket-code", "Alice").await;

        let (status, response) = issue_test_ticket(&state, "ticket-session").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(response.ticket.len(), WS_TICKET_B64_LEN);
        assert_eq!(response.expires_in_sec, WS_TICKET_TTL_MS / 1000);
        let digest = ws_ticket_digest(&response.ticket).expect("valid issued ticket");
        let tickets = state.ws_tickets.lock().await;
        assert_eq!(tickets.len(), 1);
        assert!(tickets.contains_key(&digest));
        assert!(!tickets.contains_key(&[0_u8; WS_TICKET_BYTES]));
        drop(tickets);

        let (token, session) = consume_ws_ticket(&state, &response.ticket)
            .await
            .expect("first consumption");
        assert_eq!(token.as_str(), "ticket-session");
        assert_eq!(session.username, "Alice");
        assert!(consume_ws_ticket(&state, &response.ticket).await.is_none());
        assert!(state.ws_tickets.lock().await.is_empty());
    }

    #[tokio::test]
    async fn websocket_ticket_rotation_keeps_one_outstanding_and_replays_fail() {
        let state = test_state();
        add_test_session(&state, "rotation-session", "rotation-code", "Alice").await;

        let (_, first) = issue_test_ticket(&state, "rotation-session").await;
        let (_, second) = issue_test_ticket(&state, "rotation-session").await;
        assert_ne!(first.ticket, second.ticket);
        assert_eq!(state.ws_tickets.lock().await.len(), 1);
        assert!(consume_ws_ticket(&state, &first.ticket).await.is_none());
        assert!(consume_ws_ticket(&state, &second.ticket).await.is_some());
    }

    #[tokio::test]
    async fn websocket_ticket_expiry_is_pruned_before_session_validation() {
        let state = test_state();
        let digest = ws_ticket_digest(&URL_SAFE_NO_PAD.encode([9_u8; WS_TICKET_BYTES]))
            .expect("test digest");
        state.ws_tickets.lock().await.insert(
            digest,
            WsTicket {
                session_token: Zeroizing::new("expired-session".to_string()),
                expires_at_ms: now_ms().saturating_sub(1),
            },
        );
        assert!(
            consume_ws_ticket(&state, &URL_SAFE_NO_PAD.encode([9_u8; WS_TICKET_BYTES]))
                .await
                .is_none()
        );
        assert!(state.ws_tickets.lock().await.is_empty());
    }

    #[tokio::test]
    async fn websocket_ticket_cap_fails_closed_without_eviction() {
        let state = test_state();
        add_test_session(&state, "cap-session", "cap-code", "Alice").await;
        let mut tickets = state.ws_tickets.lock().await;
        for index in 0..MAX_WS_TICKETS {
            let mut digest = [0_u8; WS_TICKET_BYTES];
            digest.copy_from_slice(&Sha256::digest(format!("cap-{index}").as_bytes()));
            tickets.insert(
                digest,
                WsTicket {
                    session_token: Zeroizing::new(format!("other-session-{index}")),
                    expires_at_ms: now_ms().saturating_add(WS_TICKET_TTL_MS),
                },
            );
        }
        drop(tickets);

        let response =
            issue_ws_ticket(State(state.clone()), ticket_auth_headers("cap-session")).await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(state.ws_tickets.lock().await.len(), MAX_WS_TICKETS);
    }

    #[tokio::test]
    async fn logout_clears_outstanding_websocket_tickets() {
        let state = test_state();
        add_test_session(&state, "logout-session", "logout-code", "Alice").await;
        let (_, response) = issue_test_ticket(&state, "logout-session").await;
        assert_eq!(state.ws_tickets.lock().await.len(), 1);

        assert_eq!(
            logout_account(State(state.clone()), ticket_auth_headers("logout-session")).await,
            StatusCode::NO_CONTENT
        );
        assert!(state.ws_tickets.lock().await.is_empty());
        assert!(consume_ws_ticket(&state, &response.ticket).await.is_none());
    }

    #[tokio::test]
    async fn global_wipe_clears_outstanding_websocket_tickets() {
        let state = test_state();
        add_test_session(&state, "wipe-session", "wipe-code", "Alice").await;
        let (_, response) = issue_test_ticket(&state, "wipe-session").await;
        assert_eq!(state.ws_tickets.lock().await.len(), 1);

        wipe_relay_state(&state, false).await;

        assert!(state.ws_tickets.lock().await.is_empty());
        assert!(consume_ws_ticket(&state, &response.ticket).await.is_none());
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

        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("HTTPS://WEB.EXAMPLE"),
        );
        headers.insert(header::HOST, HeaderValue::from_static("web.example"));
        assert!(websocket_origin_allowed(&headers, &[]));

        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("http://127.0.0.1:4020"),
        );
        headers.insert(header::HOST, HeaderValue::from_static("127.0.0.1:4020"));
        assert!(websocket_origin_allowed(&headers, &[]));

        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://abyssal.example/path"),
        );
        assert!(!websocket_origin_allowed(&headers, &[]));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("file://abyssal.example"),
        );
        assert!(!websocket_origin_allowed(&headers, &[]));
    }

    #[test]
    fn connection_reservation_does_not_overwrite_existing_owner() {
        let code_id = [3_u8; 32];
        let old_client = Uuid::from_u128(1);
        let new_client = Uuid::from_u128(2);
        let mut active = HashMap::new();

        assert!(reserve_connection(&mut active, code_id, old_client));
        assert!(!reserve_connection(&mut active, code_id, new_client));
        assert_eq!(active.get(&code_id), Some(&old_client));
    }

    #[test]
    fn bearer_tokens_are_bounded_before_allocation() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer 12345678"),
        );
        assert_eq!(bearer_token(&headers).as_deref(), Some("12345678"));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", "a".repeat(129))).unwrap(),
        );
        assert!(bearer_token(&headers).is_none());
    }

    #[test]
    fn outbound_frames_are_bounded_before_websocket_send() {
        let frame = OutboundFrame::Message {
            chat_id: "forum_test".to_string(),
            version: E2EE_PROTOCOL_VERSION,
            message_id: "message_test".to_string(),
            nonce_b64: "nonce".to_string(),
            ciphertext_b64: "x".repeat(WS_MAX_FRAME_BYTES),
            signature_b64: "signature".to_string(),
            wrapped_key_b64: "wrapped".to_string(),
            prekey_id: "prekey".to_string(),
            is_prekey: false,
            sender_username: "Alice".to_string(),
            sender_public_key_b64: "public".to_string(),
            identity_public_b64: "public".to_string(),
        };
        assert!(serialize_outbound_frame(&frame).is_none());
    }

    #[test]
    fn web_origin_normalization_rejects_paths_and_non_http_schemes() {
        assert_eq!(
            normalize_web_origin("https://web.example/").as_deref(),
            Ok("https://web.example")
        );
        assert_eq!(
            normalize_web_origin("HTTPS://WEB.EXAMPLE:8443/").as_deref(),
            Ok("https://web.example:8443")
        );
        assert!(normalize_web_origin("http://web.example").is_err());
        assert_eq!(
            normalize_web_origin("http://127.0.0.1:4020").as_deref(),
            Ok("http://127.0.0.1:4020")
        );
        assert_eq!(
            normalize_web_origin("http://localhost:4173/").as_deref(),
            Ok("http://localhost:4173")
        );
        assert!(normalize_web_origin("https://web.example/path").is_err());
        assert!(normalize_web_origin("file://web.example").is_err());
        assert!(normalize_web_origin("https://user:password@web.example").is_err());
        assert!(normalize_web_origin("https:///missing-host").is_err());
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
    async fn replay_window_never_evicts_live_entries_when_full() {
        let state = test_state();
        let now = now_ms();
        let mut replay_ids = state.replay_ids.lock().await;
        for index in 0..MAX_REPLAY_IDS {
            replay_ids.insert(
                ReplayKey {
                    chat_id: "forum_full".to_string(),
                    sender_username: "Alice".to_string(),
                    message_id: format!("message-{index}"),
                },
                now,
            );
        }
        drop(replay_ids);

        assert!(
            register_message_id(&state, "forum_full", "Alice", "new-message")
                .await
                .is_err()
        );
        assert_eq!(state.replay_ids.lock().await.len(), MAX_REPLAY_IDS);
        assert!(state.replay_ids.lock().await.contains_key(&ReplayKey {
            chat_id: "forum_full".to_string(),
            sender_username: "Alice".to_string(),
            message_id: "message-0".to_string(),
        }));
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
            signature_b64: test_signature_b64(b'S'),
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
    async fn queued_prekey_frame_keeps_claim_alive_until_queue_is_removed() {
        let state = test_state();
        let code_id = test_code_id("code-b");
        let prekey_id = test_prekey_id(b'B');
        let key = PrekeyClaimKey {
            code_id,
            prekey_id: prekey_id.clone(),
        };
        let claim = PrekeyClaim {
            chat_id: "dm_alice_bob".to_string(),
            message_id: "message-1".to_string(),
            sender_username: "Alice".to_string(),
            recipient_username: "Bob".to_string(),
            created_at_ms: now_ms().saturating_sub(PREKEY_CLAIM_TTL_MS + 1),
        };
        state.prekey_claims.lock().await.insert(key.clone(), claim);
        state.pending.lock().await.insert(
            PendingKey {
                chat_id: "dm_alice_bob".to_string(),
                recipient_username: "Bob".to_string(),
            },
            vec![PendingFrame::new(
                test_message_frame("dm_alice_bob", "message-1", "Alice", &prekey_id, true),
                now_ms(),
            )],
        );

        {
            let pending = state.pending.lock().await;
            let mut claims = state.prekey_claims.lock().await;
            prune_prekey_claims(&mut claims, &pending, now_ms());
            assert!(claims.contains_key(&key));
        }

        state.pending.lock().await.clear();
        let pending = state.pending.lock().await;
        let mut claims = state.prekey_claims.lock().await;
        prune_prekey_claims(&mut claims, &pending, now_ms());
        assert!(!claims.contains_key(&key));
    }

    #[tokio::test]
    async fn expired_pending_prekey_frame_releases_claim_and_bytes_together() {
        let mut state = test_state();
        state.pending_message_ttl_ms = MIN_PENDING_MESSAGE_TTL_HOURS as u64 * HOURS_TO_MILLISECONDS;
        let now = now_ms();
        let prekey_id = test_prekey_id(b'B');
        let frame = test_message_frame("dm_alice_bob", "expired-prekey", "Alice", &prekey_id, true);
        let frame_bytes = outbound_frame_bytes(&frame);
        let claim_key = PrekeyClaimKey {
            code_id: test_code_id("code-b"),
            prekey_id: prekey_id.clone(),
        };
        state.prekey_claims.lock().await.insert(
            claim_key.clone(),
            PrekeyClaim {
                chat_id: "dm_alice_bob".to_string(),
                message_id: "expired-prekey".to_string(),
                sender_username: "Alice".to_string(),
                recipient_username: "Bob".to_string(),
                created_at_ms: now,
            },
        );
        state.pending.lock().await.insert(
            PendingKey {
                chat_id: "dm_alice_bob".to_string(),
                recipient_username: "Bob".to_string(),
            },
            vec![PendingFrame::new(
                frame,
                now.saturating_sub(state.pending_message_ttl_ms + 1),
            )],
        );
        *state.pending_bytes.lock().await = frame_bytes;

        prune_pending_queues(&state, now).await;

        assert!(state.pending.lock().await.is_empty());
        assert_eq!(*state.pending_bytes.lock().await, 0);
        assert!(!state.prekey_claims.lock().await.contains_key(&claim_key));
    }

    #[tokio::test]
    async fn expired_non_prekey_frame_subtracts_pending_bytes() {
        let mut state = test_state();
        state.pending_message_ttl_ms = MIN_PENDING_MESSAGE_TTL_HOURS as u64 * HOURS_TO_MILLISECONDS;
        let now = now_ms();
        let frame = test_message_frame("dm_alice_bob", "expired-message", "Alice", "", false);
        let frame_bytes = outbound_frame_bytes(&frame);
        state.pending.lock().await.insert(
            PendingKey {
                chat_id: "dm_alice_bob".to_string(),
                recipient_username: "Bob".to_string(),
            },
            vec![PendingFrame::new(
                frame,
                now.saturating_sub(state.pending_message_ttl_ms + 1),
            )],
        );
        *state.pending_bytes.lock().await = frame_bytes;

        prune_pending_queues(&state, now).await;

        assert!(state.pending.lock().await.is_empty());
        assert_eq!(*state.pending_bytes.lock().await, 0);
    }

    #[tokio::test]
    async fn unexpired_pending_frame_is_replayed_and_bytes_are_retained() {
        let mut state = test_state();
        state.pending_message_ttl_ms = MIN_PENDING_MESSAGE_TTL_HOURS as u64 * HOURS_TO_MILLISECONDS;
        add_test_account(&state, "code-a", "Alice").await;
        add_test_account(&state, "code-b", "Bob").await;
        let (bob_id, mut bob_rx) = add_test_client(&state, "code-b", "Bob").await;
        let room = test_room("pending_replay");
        state.room_catalog.lock().await.insert(
            room.id.clone(),
            RoomEntry {
                room: room.clone(),
                owner_code_id: test_code_id("code-a"),
            },
        );
        let now = now_ms();
        let frame = test_message_frame(&room.id, "retained-message", "Alice", "", false);
        let frame_bytes = outbound_frame_bytes(&frame);
        state.pending.lock().await.insert(
            PendingKey {
                chat_id: room.id.clone(),
                recipient_username: "Bob".to_string(),
            },
            vec![PendingFrame::new(
                frame,
                // Keep a real margin below the expiry boundary. A one-ms
                // margin made this test depend on scheduler timing.
                now.saturating_sub(state.pending_message_ttl_ms - 60_000),
            )],
        );
        *state.pending_bytes.lock().await = frame_bytes;

        join_room(&state, bob_id, room.id)
            .await
            .expect("peer can replay an unexpired frame");

        assert!(bob_rx.try_recv().is_ok());
        assert_eq!(*state.pending_bytes.lock().await, frame_bytes);
        assert_eq!(state.pending.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn pending_queue_never_evicts_the_required_prekey_frame() {
        let state = test_state();
        let prekey_id = test_prekey_id(b'B');
        let mut frames = vec![PendingFrame::new(
            test_message_frame("dm_alice_bob", "first-contact", "Alice", &prekey_id, true),
            now_ms(),
        )];
        frames.extend((0..MAX_PENDING_FRAMES_PER_ROOM - 1).map(|index| {
            PendingFrame::new(
                test_message_frame(
                    "dm_alice_bob",
                    &format!("message-{index}"),
                    "Alice",
                    "",
                    false,
                ),
                now_ms(),
            )
        }));
        state.pending.lock().await.insert(
            PendingKey {
                chat_id: "dm_alice_bob".to_string(),
                recipient_username: "Bob".to_string(),
            },
            frames,
        );

        let _ = queue_pending_frame(
            &state,
            "dm_alice_bob",
            "Bob".to_string(),
            test_message_frame("dm_alice_bob", "new-message", "Alice", "", false),
        )
        .await;

        let pending = state.pending.lock().await;
        let queue = pending
            .get(&PendingKey {
                chat_id: "dm_alice_bob".to_string(),
                recipient_username: "Bob".to_string(),
            })
            .expect("pending queue");
        assert_eq!(queue.len(), MAX_PENDING_FRAMES_PER_ROOM);
        assert!(queue.iter().any(|frame| {
            matches!(
                &frame.frame,
                OutboundFrame::Message {
                    message_id,
                    is_prekey: true,
                    ..
                } if message_id == "first-contact"
            )
        }));
    }

    #[tokio::test]
    async fn pending_preflight_is_all_or_none_when_one_recipient_is_full() {
        let state = test_state();
        let prekey_id = test_prekey_id(b'B');
        let key = PendingKey {
            chat_id: "room_atomic".to_string(),
            recipient_username: "Bob".to_string(),
        };
        let queue = (0..MAX_PENDING_FRAMES_PER_ROOM)
            .map(|index| {
                PendingFrame::new(
                    test_message_frame(
                        "room_atomic",
                        &format!("prekey-{index}"),
                        "Alice",
                        &prekey_id,
                        true,
                    ),
                    now_ms(),
                )
            })
            .collect::<Vec<_>>();
        let queue_bytes = queue
            .iter()
            .map(|pending_frame| outbound_frame_bytes(&pending_frame.frame))
            .sum::<usize>();
        state.pending.lock().await.insert(key.clone(), queue);
        *state.pending_bytes.lock().await = queue_bytes;
        let frames = vec![
            (
                "Bob".to_string(),
                test_message_frame("room_atomic", "rejected-bob", "Alice", "", false),
            ),
            (
                "Carol".to_string(),
                test_message_frame("room_atomic", "rejected-carol", "Alice", "", false),
            ),
        ];

        assert!(preflight_pending_frames(&state, &frames).await.is_err());
        assert_eq!(
            state.pending.lock().await[&key].len(),
            MAX_PENDING_FRAMES_PER_ROOM
        );
        assert!(!state.pending.lock().await.contains_key(&PendingKey {
            chat_id: "room_atomic".to_string(),
            recipient_username: "Carol".to_string(),
        }));
        assert!(state.prekey_claims.lock().await.is_empty());
        assert!(state.replay_ids.lock().await.is_empty());
    }

    #[tokio::test]
    async fn pending_preflight_rejects_transient_fanout_above_global_budget() {
        let state = test_state();
        let payload = "x".repeat(1024 * 1024);
        let frame_count = MAX_TRANSIENT_FANOUT_BYTES / payload.len() + 1;
        let frames = (0..frame_count)
            .map(|index| {
                let mut frame = test_message_frame(
                    "transient_fanout",
                    &format!("message-{index}"),
                    "Alice",
                    "",
                    false,
                );
                if let OutboundFrame::Message { ciphertext_b64, .. } = &mut frame {
                    *ciphertext_b64 = payload.clone();
                }
                (format!("recipient-{index}"), frame)
            })
            .collect::<Vec<_>>();

        assert!(preflight_pending_frames(&state, &frames)
            .await
            .is_err_and(|error| error == "fanout preparation budget full"));
        assert!(state.pending.lock().await.is_empty());
        assert_eq!(*state.pending_bytes.lock().await, 0);
    }

    #[tokio::test]
    async fn rollback_removes_newest_duplicate_and_restores_evicted_frame() {
        let state = test_state();
        let key = PendingKey {
            chat_id: "rollback_duplicate".to_string(),
            recipient_username: "Bob".to_string(),
        };
        let mut old_duplicate =
            test_message_frame("rollback_duplicate", "same-message-id", "Alice", "", false);
        if let OutboundFrame::Message { nonce_b64, .. } = &mut old_duplicate {
            *nonce_b64 = "old-frame".to_string();
        }
        let mut queue = vec![PendingFrame::new(old_duplicate, now_ms())];
        queue.extend((0..MAX_PENDING_FRAMES_PER_ROOM - 1).map(|index| {
            PendingFrame::new(
                test_message_frame(
                    "rollback_duplicate",
                    &format!("other-{index}"),
                    "Alice",
                    "",
                    false,
                ),
                now_ms(),
            )
        }));
        let original_bytes = queue
            .iter()
            .map(|pending_frame| outbound_frame_bytes(&pending_frame.frame))
            .sum::<usize>();
        state.pending.lock().await.insert(key.clone(), queue);
        *state.pending_bytes.lock().await = original_bytes;

        let mut new_duplicate =
            test_message_frame("rollback_duplicate", "same-message-id", "Alice", "", false);
        if let OutboundFrame::Message { nonce_b64, .. } = &mut new_duplicate {
            *nonce_b64 = "new-frame".to_string();
        }
        let frames = vec![("Bob".to_string(), new_duplicate)];
        let mut plan = preflight_pending_frames(&state, &frames)
            .await
            .expect("duplicate admission preflight");
        commit_pending_frames(&state, &frames, &mut plan)
            .await
            .expect("duplicate admission commit");
        assert_eq!(
            state.pending.lock().await[&key].len(),
            MAX_PENDING_FRAMES_PER_ROOM
        );
        rollback_pending_frames(&state, &frames, &mut plan).await;

        let pending = state.pending.lock().await;
        let queue = pending.get(&key).expect("restored queue");
        assert_eq!(queue.len(), MAX_PENDING_FRAMES_PER_ROOM);
        assert_eq!(*state.pending_bytes.lock().await, original_bytes);
        assert!(queue.iter().any(|pending_frame| {
            matches!(
                &pending_frame.frame,
                OutboundFrame::Message { nonce_b64, .. } if nonce_b64 == "old-frame"
            )
        }));
        assert!(!queue.iter().any(|pending_frame| {
            matches!(
                &pending_frame.frame,
                OutboundFrame::Message { nonce_b64, .. } if nonce_b64 == "new-frame"
            )
        }));
    }

    #[tokio::test]
    async fn message_result_uses_dedicated_channel_and_waits_for_sink_delivery() {
        let state = test_state();
        let client_id = Uuid::new_v4();
        let (tx, _rx) = mpsc::channel(CLIENT_OUTBOUND_QUEUE_CAPACITY);
        let (control_tx, _control_rx) = mpsc::channel(CLIENT_CONTROL_QUEUE_CAPACITY);
        let (result_tx, mut result_rx) = mpsc::channel(CLIENT_RESULT_QUEUE_CAPACITY);
        state.clients.lock().await.insert(
            client_id,
            ClientHandle {
                code_id: test_code_id("result-client"),
                username: "Alice".to_string(),
                tx,
                control_tx,
                result_tx,
                queued_bytes: Arc::new(AtomicUsize::new(0)),
            },
        );

        let result_task = tokio::spawn({
            let state = state.clone();
            async move { send_message_result(&state, client_id, "message-1", true).await }
        });
        let result = result_rx.recv().await.expect("dedicated result");
        assert!(matches!(
            result.frame,
            OutboundFrame::MessageResult {
                ref message_id,
                accepted: true
            } if message_id == "message-1"
        ));
        assert!(result.delivered.send(true).is_ok());
        assert!(result_task.await.expect("result task").is_ok());
    }

    #[tokio::test]
    async fn ack_result_reports_success_and_rejection_on_the_dedicated_channel() {
        let state = test_state();
        let client_id = Uuid::new_v4();
        let (tx, _rx) = mpsc::channel(CLIENT_OUTBOUND_QUEUE_CAPACITY);
        let (control_tx, _control_rx) = mpsc::channel(CLIENT_CONTROL_QUEUE_CAPACITY);
        let (result_tx, mut result_rx) = mpsc::channel(CLIENT_RESULT_QUEUE_CAPACITY);
        state.clients.lock().await.insert(
            client_id,
            ClientHandle {
                code_id: test_code_id("ack-result-client"),
                username: "Alice".to_string(),
                tx,
                control_tx,
                result_tx,
                queued_bytes: Arc::new(AtomicUsize::new(0)),
            },
        );

        for (message_id, accepted) in [("ack-success", true), ("ack-rejected", false)] {
            let result_task = tokio::spawn({
                let state = state.clone();
                async move { send_ack_result(&state, client_id, message_id, accepted).await }
            });
            let result = result_rx.recv().await.expect("dedicated ack result");
            assert_eq!(
                serde_json::to_value(&result.frame).expect("ack result JSON"),
                serde_json::json!({
                    "type": "ack_result",
                    "message_id": message_id,
                    "accepted": accepted,
                })
            );
            assert!(result.delivered.send(true).is_ok());
            assert!(result_task.await.expect("ack result task").is_ok());
        }
    }

    #[tokio::test]
    async fn ack_result_sink_failure_invalidates_the_authenticated_connection() {
        let state = test_state();
        let client_id = Uuid::new_v4();
        let code_id = test_code_id("ack-sink-failure");
        let (tx, _rx) = mpsc::channel(CLIENT_OUTBOUND_QUEUE_CAPACITY);
        let (control_tx, mut control_rx) = mpsc::channel(CLIENT_CONTROL_QUEUE_CAPACITY);
        let (result_tx, mut result_rx) = mpsc::channel(CLIENT_RESULT_QUEUE_CAPACITY);
        state.clients.lock().await.insert(
            client_id,
            ClientHandle {
                code_id,
                username: "Alice".to_string(),
                tx,
                control_tx,
                result_tx,
                queued_bytes: Arc::new(AtomicUsize::new(0)),
            },
        );
        state.sessions.lock().await.insert(
            SessionToken::new("ack-sink-token".to_string()),
            AuthSession {
                code_id,
                username: "Alice".to_string(),
                last_activity_ms: now_ms(),
            },
        );

        let result_task = tokio::spawn({
            let state = state.clone();
            async move { send_ack_result(&state, client_id, "ack-sink", true).await }
        });
        let result = result_rx.recv().await.expect("dedicated ack result");
        assert!(result.delivered.send(false).is_ok());
        assert!(result_task.await.expect("ack result task").is_err());
        assert!(state.sessions.lock().await.is_empty());
        assert!(matches!(control_rx.try_recv(), Ok(ClientControl::Close)));
    }

    #[tokio::test]
    async fn rejected_safe_ack_reports_false_without_refreshing_activity() {
        let state = test_state();
        let client_id = Uuid::new_v4();
        let (tx, _rx) = mpsc::channel(CLIENT_OUTBOUND_QUEUE_CAPACITY);
        let (control_tx, _control_rx) = mpsc::channel(CLIENT_CONTROL_QUEUE_CAPACITY);
        let (result_tx, mut result_rx) = mpsc::channel(CLIENT_RESULT_QUEUE_CAPACITY);
        state.clients.lock().await.insert(
            client_id,
            ClientHandle {
                code_id: test_code_id("ack-activity"),
                username: "Alice".to_string(),
                tx,
                control_tx,
                result_tx,
                queued_bytes: Arc::new(AtomicUsize::new(0)),
            },
        );
        *state.last_activity_ms.lock().await = 123;
        let frame = serde_json::json!({
            "type": "message_ack",
            "chat_id": "",
            "message_id": "ack-rejected",
            "sender_username": "",
            "state_revision": 0,
            "identity_envelope_b64": "",
            "identity_public_b64": "",
            "prekey_id": "",
            "state_signature_b64": "",
            "ack_signature_b64": "",
            "used_prekey_id": "",
        });
        let handle_task = tokio::spawn({
            let state = state.clone();
            async move { handle_frame(&state, client_id, &frame.to_string()).await }
        });
        let result = result_rx.recv().await.expect("rejected ack result");
        assert!(matches!(
            result.frame,
            OutboundFrame::AckResult {
                ref message_id,
                accepted: false
            } if message_id == "ack-rejected"
        ));
        assert!(result.delivered.send(true).is_ok());
        assert!(handle_task.await.expect("frame task").is_err());
        assert_eq!(*state.last_activity_ms.lock().await, 123);
    }

    #[tokio::test]
    async fn unsafe_ack_id_does_not_emit_a_result_or_refresh_activity() {
        let state = test_state();
        let client_id = Uuid::new_v4();
        let (tx, _rx) = mpsc::channel(CLIENT_OUTBOUND_QUEUE_CAPACITY);
        let (control_tx, _control_rx) = mpsc::channel(CLIENT_CONTROL_QUEUE_CAPACITY);
        let (result_tx, mut result_rx) = mpsc::channel(CLIENT_RESULT_QUEUE_CAPACITY);
        state.clients.lock().await.insert(
            client_id,
            ClientHandle {
                code_id: test_code_id("unsafe-ack"),
                username: "Alice".to_string(),
                tx,
                control_tx,
                result_tx,
                queued_bytes: Arc::new(AtomicUsize::new(0)),
            },
        );
        *state.last_activity_ms.lock().await = 123;
        let frame = serde_json::json!({
            "type": "message_ack",
            "chat_id": "",
            "message_id": "",
            "sender_username": "",
            "state_revision": 0,
            "identity_envelope_b64": "",
            "identity_public_b64": "",
            "prekey_id": "",
            "state_signature_b64": "",
            "ack_signature_b64": "",
            "used_prekey_id": "",
        });
        assert!(handle_frame(&state, client_id, &frame.to_string())
            .await
            .is_err());
        assert!(result_rx.try_recv().is_err());
        assert_eq!(*state.last_activity_ms.lock().await, 123);
    }

    #[tokio::test]
    async fn accepted_ack_result_follows_atomic_state_and_pending_mutation() {
        let state = test_state();
        add_test_account(&state, "ack-atomic-sender", "Alice").await;
        add_test_account(&state, "ack-atomic-recipient", "Bob").await;
        let (alice_id, _) = add_test_client(&state, "ack-atomic-sender", "Alice").await;
        let bob_id = Uuid::new_v4();
        let (tx, _rx) = mpsc::channel(CLIENT_OUTBOUND_QUEUE_CAPACITY);
        let (control_tx, _control_rx) = mpsc::channel(CLIENT_CONTROL_QUEUE_CAPACITY);
        let (result_tx, mut result_rx) = mpsc::channel(CLIENT_RESULT_QUEUE_CAPACITY);
        state.clients.lock().await.insert(
            bob_id,
            ClientHandle {
                code_id: test_code_id("ack-atomic-recipient"),
                username: "Bob".to_string(),
                tx,
                control_tx,
                result_tx,
                queued_bytes: Arc::new(AtomicUsize::new(0)),
            },
        );
        let room = test_room("ack_result_atomic");
        state.room_catalog.lock().await.insert(
            room.id.clone(),
            RoomEntry {
                room: room.clone(),
                owner_code_id: test_code_id("ack-atomic-sender"),
            },
        );
        join_room(&state, alice_id, room.id.clone())
            .await
            .expect("Alice joins room");
        join_room(&state, bob_id, room.id.clone())
            .await
            .expect("Bob joins room");

        let message_id = "ack-atomic-message";
        route_test_message_with_id(&state, alice_id, &room.id, &["Bob"], message_id)
            .await
            .expect("message queues");
        assert!(state.pending.lock().await.contains_key(&PendingKey {
            chat_id: room.id.clone(),
            recipient_username: "Bob".to_string(),
        }));
        *state.last_activity_ms.lock().await = 123;

        let identity_envelope_b64 = test_identity_envelope_b64(0);
        let identity_public_b64 = test_identity_public_b64(b'B');
        let prekey_id = test_prekey_id(b'B');
        let frame = serde_json::json!({
            "type": "message_ack",
            "chat_id": room.id,
            "message_id": message_id,
            "sender_username": "Alice",
            "state_revision": 1,
            "identity_envelope_b64": identity_envelope_b64,
            "identity_public_b64": identity_public_b64,
            "prekey_id": prekey_id,
            "state_signature_b64": test_valid_state_signature_b64(
                b'B',
                1,
                &test_identity_envelope_b64(0),
                &test_identity_public_b64(b'B'),
                &test_prekey_id(b'B'),
            ),
            "ack_signature_b64": test_valid_ack_signature_b64(
                b'B',
                "ack_result_atomic",
                message_id,
                "Alice",
                "",
            ),
            "used_prekey_id": "",
        });
        let handle_task = tokio::spawn({
            let state = state.clone();
            async move { handle_frame(&state, bob_id, &frame.to_string()).await }
        });
        let result = result_rx.recv().await.expect("ack result");
        assert_eq!(
            serde_json::to_value(&result.frame).expect("ack result JSON"),
            serde_json::json!({
                "type": "ack_result",
                "message_id": message_id,
                "accepted": true,
            })
        );
        // The result is not enqueued until acknowledge_message has committed
        // both the signed state and pending-frame removal.
        assert!(state.pending.lock().await.is_empty());
        assert_eq!(*state.pending_bytes.lock().await, 0);
        assert_eq!(
            state
                .accounts
                .lock()
                .await
                .get(&test_code_id("ack-atomic-recipient"))
                .expect("Bob account")
                .state_revision,
            1
        );
        assert!(result.delivered.send(true).is_ok());
        assert!(handle_task.await.expect("ACK handler").is_ok());
        assert!(*state.last_activity_ms.lock().await > 123);
    }

    #[tokio::test]
    async fn ack_result_queue_overflow_invalidates_the_authenticated_connection() {
        let state = test_state();
        let client_id = Uuid::new_v4();
        let code_id = test_code_id("ack-queue-overflow");
        let (tx, _rx) = mpsc::channel(CLIENT_OUTBOUND_QUEUE_CAPACITY);
        let (control_tx, mut control_rx) = mpsc::channel(CLIENT_CONTROL_QUEUE_CAPACITY);
        let (result_tx, result_rx) = mpsc::channel(CLIENT_RESULT_QUEUE_CAPACITY);
        state.clients.lock().await.insert(
            client_id,
            ClientHandle {
                code_id,
                username: "Alice".to_string(),
                tx,
                control_tx,
                result_tx: result_tx.clone(),
                queued_bytes: Arc::new(AtomicUsize::new(0)),
            },
        );
        state.sessions.lock().await.insert(
            SessionToken::new("ack-queue-token".to_string()),
            AuthSession {
                code_id,
                username: "Alice".to_string(),
                last_activity_ms: now_ms(),
            },
        );
        for index in 0..CLIENT_RESULT_QUEUE_CAPACITY {
            let (delivered, _completion) = oneshot::channel();
            result_tx
                .try_send(ClientResult {
                    frame: OutboundFrame::AckResult {
                        message_id: format!("queued-{index}"),
                        accepted: false,
                    },
                    delivered,
                })
                .expect("result queue capacity");
        }

        let error = send_ack_result(&state, client_id, "overflow", true)
            .await
            .expect_err("full result queue must fail closed");
        assert_eq!(error, "client result channel unavailable");
        assert_eq!(result_rx.len(), CLIENT_RESULT_QUEUE_CAPACITY);
        assert!(state.sessions.lock().await.is_empty());
        assert!(matches!(control_rx.try_recv(), Ok(ClientControl::Close)));
    }

    #[tokio::test]
    async fn purge_epoch_changes_even_when_no_control_slot_is_available() {
        let state = test_state();
        let mut purge_rx = state.purge_epoch.subscribe();
        let (control_tx, _control_rx) = mpsc::channel(CLIENT_CONTROL_QUEUE_CAPACITY);
        let _ = control_tx.try_send(ClientControl::Close);
        wipe_relay_state(&state, false).await;
        assert!(purge_rx.changed().await.is_ok());
        assert_eq!(*purge_rx.borrow(), 1);
    }

    #[tokio::test]
    async fn deleting_room_releases_only_claims_for_removed_prekey_frames() {
        let state = test_state();
        add_test_account(&state, "code-a", "Alice").await;
        let (alice_id, _) = add_test_client(&state, "code-a", "Alice").await;
        let room = test_room("forum_claim_cleanup");
        state.room_catalog.lock().await.insert(
            room.id.clone(),
            RoomEntry {
                room: room.clone(),
                owner_code_id: test_code_id("code-a"),
            },
        );

        let removed_prekey_id = test_prekey_id(b'B');
        let retained_prekey_id = test_prekey_id(b'C');
        let removed_key = PrekeyClaimKey {
            code_id: test_code_id("code-b"),
            prekey_id: removed_prekey_id.clone(),
        };
        let retained_key = PrekeyClaimKey {
            code_id: test_code_id("code-c"),
            prekey_id: retained_prekey_id.clone(),
        };
        let claim = |recipient_username: &str| PrekeyClaim {
            chat_id: room.id.clone(),
            message_id: "message-1".to_string(),
            sender_username: "Alice".to_string(),
            recipient_username: recipient_username.to_string(),
            created_at_ms: now_ms(),
        };
        state.prekey_claims.lock().await.extend([
            (removed_key.clone(), claim("Bob")),
            (retained_key.clone(), claim("Carol")),
        ]);
        state.pending.lock().await.insert(
            PendingKey {
                chat_id: room.id.clone(),
                recipient_username: "Bob".to_string(),
            },
            vec![PendingFrame::new(
                test_message_frame(&room.id, "message-1", "Alice", &removed_prekey_id, true),
                now_ms(),
            )],
        );
        let attachment_id = Uuid::new_v4();
        state.attachments.lock().await.insert(
            attachment_id,
            AttachmentRecord {
                blob: test_attachment_blob(vec![1, 2, 3]),
                chat_id: room.id.clone(),
                media_type: "FILE".to_string(),
                owner_code_id: test_code_id("code-a"),
                one_time: false,
                delete_after_download: false,
                expires_at_ms: None,
                eligible_recipient_code_ids: HashSet::new(),
                download_claims: HashMap::new(),
                completed_recipient_code_ids: HashSet::new(),
            },
        );
        state
            .attachment_bytes_by_code
            .lock()
            .await
            .insert(test_code_id("code-a"), 3);

        delete_room(&state, alice_id, &room.id)
            .await
            .expect("owner can delete room");
        let claims = state.prekey_claims.lock().await;
        assert!(!claims.contains_key(&removed_key));
        assert!(claims.contains_key(&retained_key));
        drop(claims);
        assert!(state.attachments.lock().await.is_empty());
        assert!(state.attachment_bytes_by_code.lock().await.is_empty());
    }

    #[test]
    fn identity_bundle_rejects_empty_prekey_id_and_zero_one_time_key() {
        let public = test_identity_public(7);
        let prekey_id = test_prekey_id(7);
        assert!(valid_identity_public_bundle(&public, &prekey_id));
        assert!(!valid_identity_public_bundle(&public, ""));

        let mut zero_one_time = public;
        zero_one_time[ONE_TIME_KEY_OFFSET..FALLBACK_KEY_OFFSET].fill(0);
        assert!(!valid_identity_public_bundle(&zero_one_time, &prekey_id));
    }

    #[test]
    fn relay_registration_validation_rejects_low_order_keys_in_every_x25519_slot() {
        let valid = test_identity_public(b'A');
        let prekey_id = test_prekey_id(b'A');
        assert!(valid_identity_public_bundle(&valid, &prekey_id));

        for range in [
            0..32,
            ONE_TIME_KEY_OFFSET..FALLBACK_KEY_OFFSET,
            FALLBACK_KEY_OFFSET..IDENTITY_PUBLIC_BYTES,
        ] {
            let mut malformed = valid.clone();
            malformed[range.clone()].fill(0);
            malformed[range.start] = 1;
            assert!(
                !valid_identity_public_bundle(&malformed, &prekey_id),
                "relay registration accepted a low-order key in {:?}",
                range
            );
        }
    }

    #[tokio::test]
    async fn registration_endpoint_rejects_low_order_fallback_before_consuming_code() {
        let state = test_state();
        let code = "ABCD-12345678";
        let code_id = test_code_id(code);
        state.available_codes.lock().await.insert(code_id);
        let password = b"correct horse battery staple".to_vec();
        let start = abyssal_core::secure_protocol::opaque_client_start(password.clone())
            .expect("OPAQUE client start");
        let response = abyssal_core::secure_protocol::opaque_server_registration_response(
            &state.opaque_setup,
            &start.registration_request,
            code.as_bytes(),
        )
        .expect("OPAQUE server response");
        let finish = abyssal_core::secure_protocol::opaque_client_finish_registration(
            password,
            start.registration_state,
            response,
        )
        .expect("OPAQUE client finish");
        let valid = test_identity_public(b'A');
        let mut low_order_fallback = valid;
        low_order_fallback[FALLBACK_KEY_OFFSET..IDENTITY_PUBLIC_BYTES].fill(0);
        low_order_fallback[FALLBACK_KEY_OFFSET] = 1;
        let handshake_id = Uuid::new_v4();
        state.opaque_handshakes.lock().await.insert(
            handshake_id,
            OpaqueHandshake::Registration {
                code_id,
                challenge: Zeroizing::new(vec![0; REGISTRATION_CHALLENGE_BYTES_V8]),
                created_at_ms: now_ms(),
            },
        );

        let response = finish_opaque_account(
            State(state.clone()),
            Json(OpaqueAccountFinishRequest {
                handshake_id,
                registration_upload_b64: Some(URL_SAFE_NO_PAD.encode(finish.registration_upload)),
                credential_finalization_b64: None,
                identity_public_b64: Some(URL_SAFE_NO_PAD.encode(low_order_fallback)),
                identity_prekey_id: Some(test_prekey_id(b'A')),
                identity_envelope_b64: Some(URL_SAFE_NO_PAD.encode({
                    let mut envelope = [0_u8; 256];
                    envelope[0] = IDENTITY_ENVELOPE_VERSION;
                    envelope
                })),
                // The proof only needs to satisfy the mode-exclusive request
                // shape here. The malformed fallback key must be rejected
                // before proof verification, without consuming the code.
                identity_proof_b64: Some(URL_SAFE_NO_PAD.encode([0_u8; MESSAGE_SIGNATURE_BYTES])),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(state.accounts.lock().await.is_empty());
        assert!(state.available_codes.lock().await.contains(&code_id));
    }

    #[tokio::test]
    async fn registration_identity_proof_rejects_copied_key_and_tampering() {
        let state = test_state();
        let code = "ABCD-12345678";
        let code_id = test_code_id(code);
        state.available_codes.lock().await.insert(code_id);
        let password = b"correct horse battery staple".to_vec();
        let start = abyssal_core::secure_protocol::opaque_client_start(password.clone())
            .expect("OPAQUE client start");
        let response = opaque_server_registration_response(
            &state.opaque_setup,
            &start.registration_request,
            code.as_bytes(),
        )
        .expect("OPAQUE server response");
        let finish = abyssal_core::secure_protocol::opaque_client_finish_registration(
            password,
            start.registration_state,
            response,
        )
        .expect("OPAQUE client finish");
        let owner = abyssal_core::secure_protocol::E2eeSession::create(vec![71; 64])
            .expect("owner identity");
        let attacker = abyssal_core::secure_protocol::E2eeSession::create(vec![72; 64])
            .expect("attacker identity");
        let owner_public = owner.public_key();
        let owner_prekey = owner.prekey_id();
        let owner_envelope = owner
            .seal_identity(vec![71; 64], b"registration-context".to_vec())
            .expect("owner envelope");
        let challenge = vec![17; REGISTRATION_CHALLENGE_BYTES_V8];
        let handshake_id = Uuid::new_v4();
        state.opaque_handshakes.lock().await.insert(
            handshake_id,
            OpaqueHandshake::Registration {
                code_id,
                challenge: Zeroizing::new(challenge.clone()),
                created_at_ms: now_ms(),
            },
        );
        let copied_proof = attacker
            .sign_registration_identity_proof(
                state.node_id.clone(),
                handshake_id.to_string(),
                challenge,
                finish.registration_upload.clone(),
                owner_public.clone(),
                owner_prekey.clone(),
                owner_envelope.clone(),
            )
            .expect("copied-key proof");
        let response = finish_opaque_account(
            State(state.clone()),
            Json(OpaqueAccountFinishRequest {
                handshake_id,
                registration_upload_b64: Some(URL_SAFE_NO_PAD.encode(&finish.registration_upload)),
                credential_finalization_b64: None,
                identity_public_b64: Some(URL_SAFE_NO_PAD.encode(&owner_public)),
                identity_prekey_id: Some(owner_prekey),
                identity_envelope_b64: Some(URL_SAFE_NO_PAD.encode(&owner_envelope)),
                identity_proof_b64: Some(URL_SAFE_NO_PAD.encode(copied_proof)),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(state.accounts.lock().await.is_empty());
        assert!(state.available_codes.lock().await.contains(&code_id));
    }

    #[tokio::test]
    async fn registration_identity_proof_accepts_once_and_replay_fails() {
        let state = test_state();
        let code = "ABCD-12345678";
        let code_id = test_code_id(code);
        state.available_codes.lock().await.insert(code_id);
        let password = b"correct horse battery staple".to_vec();
        let start = abyssal_core::secure_protocol::opaque_client_start(password.clone())
            .expect("OPAQUE client start");
        let response = opaque_server_registration_response(
            &state.opaque_setup,
            &start.registration_request,
            code.as_bytes(),
        )
        .expect("OPAQUE server response");
        let finish = abyssal_core::secure_protocol::opaque_client_finish_registration(
            password,
            start.registration_state,
            response,
        )
        .expect("OPAQUE client finish");
        let session =
            abyssal_core::secure_protocol::E2eeSession::create(vec![73; 64]).expect("identity");
        let public = session.public_key();
        let prekey_id = session.prekey_id();
        let envelope = session
            .seal_identity(vec![73; 64], b"registration-context".to_vec())
            .expect("identity envelope");
        let challenge = vec![18; REGISTRATION_CHALLENGE_BYTES_V8];
        let handshake_id = Uuid::new_v4();
        state.opaque_handshakes.lock().await.insert(
            handshake_id,
            OpaqueHandshake::Registration {
                code_id,
                challenge: Zeroizing::new(challenge.clone()),
                created_at_ms: now_ms(),
            },
        );
        let proof = session
            .sign_registration_identity_proof(
                state.node_id.clone(),
                handshake_id.to_string(),
                challenge,
                finish.registration_upload.clone(),
                public.clone(),
                prekey_id.clone(),
                envelope.clone(),
            )
            .expect("identity proof");
        let request = OpaqueAccountFinishRequest {
            handshake_id,
            registration_upload_b64: Some(URL_SAFE_NO_PAD.encode(&finish.registration_upload)),
            credential_finalization_b64: None,
            identity_public_b64: Some(URL_SAFE_NO_PAD.encode(&public)),
            identity_prekey_id: Some(prekey_id),
            identity_envelope_b64: Some(URL_SAFE_NO_PAD.encode(&envelope)),
            identity_proof_b64: Some(URL_SAFE_NO_PAD.encode(&proof)),
        };
        let response = finish_opaque_account(State(state.clone()), Json(request))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(state.accounts.lock().await.contains_key(&code_id));
        assert!(!state.available_codes.lock().await.contains(&code_id));

        let replay = finish_opaque_account(
            State(state.clone()),
            Json(OpaqueAccountFinishRequest {
                handshake_id,
                registration_upload_b64: None,
                credential_finalization_b64: None,
                identity_public_b64: None,
                identity_prekey_id: None,
                identity_envelope_b64: None,
                identity_proof_b64: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn identity_state_update_rejects_low_order_fallback_without_mutating_account() {
        let state = test_state();
        add_test_account(&state, "code-a", "Alice").await;
        let code_id = test_code_id("code-a");
        let (valid, prekey_id, previous_revision) = {
            let accounts = state.accounts.lock().await;
            let account = accounts.get(&code_id).expect("Alice account");
            (
                account.identity_public.clone(),
                account.prekey_id.clone(),
                account.state_revision,
            )
        };
        let mut low_order_fallback = valid.clone();
        low_order_fallback[FALLBACK_KEY_OFFSET..IDENTITY_PUBLIC_BYTES].fill(0);
        low_order_fallback[FALLBACK_KEY_OFFSET] = 1;

        let result = apply_identity_state(
            &state,
            &code_id,
            previous_revision + 1,
            &URL_SAFE_NO_PAD.encode({
                let mut envelope = [0_u8; 256];
                envelope[0] = IDENTITY_ENVELOPE_VERSION;
                envelope
            }),
            &URL_SAFE_NO_PAD.encode(low_order_fallback),
            &prekey_id,
            &test_signature_b64(0),
            true,
        )
        .await;
        assert!(result.is_err());

        let accounts = state.accounts.lock().await;
        let account = accounts.get(&code_id).expect("Alice account");
        assert_eq!(account.state_revision, previous_revision);
        assert_eq!(account.identity_public, valid);
        assert_eq!(account.prekey_id, prekey_id);
    }

    #[tokio::test]
    async fn fanout_rejects_low_order_sender_bundle_before_recipient_delivery() {
        let state = test_state();
        add_test_account(&state, "code-a", "Alice").await;
        add_test_account(&state, "code-b", "Bob").await;
        let (alice_id, _) = add_test_client(&state, "code-a", "Alice").await;
        let (bob_id, mut bob_rx) = add_test_client(&state, "code-b", "Bob").await;
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
        join_room(&state, alice_id, direct_id.clone())
            .await
            .expect("Alice joins direct");
        join_room(&state, bob_id, direct_id.clone())
            .await
            .expect("Bob joins direct");
        while bob_rx.try_recv().is_ok() {}

        let (valid, prekey_id) = {
            let accounts = state.accounts.lock().await;
            let account = accounts
                .get(&test_code_id("code-a"))
                .expect("Alice account");
            (account.identity_public.clone(), account.prekey_id.clone())
        };
        let mut low_order_fallback = valid.clone();
        low_order_fallback[FALLBACK_KEY_OFFSET..IDENTITY_PUBLIC_BYTES].fill(0);
        low_order_fallback[FALLBACK_KEY_OFFSET] = 1;

        let result = route_encrypted_message(
            &state,
            alice_id,
            direct_id,
            E2EE_PROTOCOL_VERSION,
            "low-order-fanout".to_string(),
            URL_SAFE_NO_PAD.encode([2_u8; MESSAGE_NONCE_BYTES]),
            URL_SAFE_NO_PAD.encode(b"ciphertext"),
            Vec::new(),
            1,
            URL_SAFE_NO_PAD.encode({
                let mut envelope = [0_u8; 256];
                envelope[0] = IDENTITY_ENVELOPE_VERSION;
                envelope
            }),
            URL_SAFE_NO_PAD.encode(low_order_fallback),
            prekey_id,
            test_signature_b64(0),
        )
        .await;
        assert!(result.is_err());
        assert!(bob_rx.try_recv().is_err());
        assert!(state.pending.lock().await.is_empty());
    }

    #[tokio::test]
    async fn expired_attachment_pruning_decrements_owner_usage() {
        let mut state = test_state();
        state.attachment_record_limit = 1;
        state.attachment_account_record_limit = 1;
        let owner = test_code_id("code-a");
        let attachment_id = Uuid::new_v4();
        state.attachments.lock().await.insert(
            attachment_id,
            AttachmentRecord {
                blob: test_attachment_blob(vec![1, 2, 3]),
                chat_id: "dm_alice_bob".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                one_time: false,
                delete_after_download: false,
                expires_at_ms: Some(0),
                eligible_recipient_code_ids: HashSet::new(),
                download_claims: HashMap::new(),
                completed_recipient_code_ids: HashSet::new(),
            },
        );
        state.attachment_bytes_by_code.lock().await.insert(owner, 3);
        {
            let attachments = state.attachments.lock().await;
            assert!(!attachment_record_capacity_allows(
                attachments.len(),
                current_attachment_records_for_owner(&attachments, &owner),
                state.attachment_record_limit,
                state.attachment_account_record_limit,
            ));
        }

        prune_expired_attachments(&state).await;
        assert!(state.attachments.lock().await.is_empty());
        assert!(state.attachment_bytes_by_code.lock().await.is_empty());
        assert!(attachment_record_capacity_available(&state, &owner).await);
    }

    #[tokio::test]
    async fn expired_claimed_attachment_waits_for_claim_release() {
        let state = test_state();
        let owner = test_code_id("claimed-expired-owner");
        let recipient = test_code_id("claimed-expired-recipient");
        let attachment_id = Uuid::new_v4();
        state.attachments.lock().await.insert(
            attachment_id,
            AttachmentRecord {
                blob: test_attachment_blob(vec![4, 5, 6]),
                chat_id: "dm_alice_bob".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                one_time: true,
                delete_after_download: false,
                expires_at_ms: Some(0),
                eligible_recipient_code_ids: HashSet::from([recipient]),
                download_claims: HashMap::from([(
                    Uuid::new_v4(),
                    AttachmentDownloadClaim {
                        recipient_code_id: recipient,
                        created_at_ms: now_ms(),
                    },
                )]),
                completed_recipient_code_ids: HashSet::new(),
            },
        );
        state.attachment_bytes_by_code.lock().await.insert(owner, 3);
        let claim_id = state
            .attachments
            .lock()
            .await
            .get(&attachment_id)
            .and_then(|record| record.download_claims.keys().next().copied())
            .expect("claim id");

        prune_expired_attachments(&state).await;
        assert!(state.attachments.lock().await.contains_key(&attachment_id));
        assert_eq!(
            state.attachment_bytes_by_code.lock().await.get(&owner),
            Some(&3)
        );
        assert!(matches!(
            reserve_attachment_download(&state, attachment_id, &recipient).await,
            Err(StatusCode::TOO_MANY_REQUESTS)
        ));

        release_attachment_download_claim(&state, attachment_id, &recipient, claim_id)
            .await
            .expect("release expired claim");
        prune_expired_attachments(&state).await;
        assert!(!state.attachments.lock().await.contains_key(&attachment_id));
        assert!(state.attachment_bytes_by_code.lock().await.is_empty());
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
            effective_attachment_ttl_sec(Some(100), &access, "VIDEO", 604_800),
            20
        );
        assert_eq!(
            effective_attachment_ttl_sec(None, &access, "VIDEO", 604_800),
            20
        );
        assert_eq!(
            effective_attachment_ttl_sec(Some(10), &access, "VIDEO", 604_800),
            10
        );
        assert_eq!(
            effective_attachment_ttl_sec(
                Some(u64::MAX),
                &ConversationAccess::Direct,
                "FILE",
                604_800,
            ),
            86_400
        );
        assert_eq!(
            effective_attachment_ttl_sec(None, &ConversationAccess::Direct, "FILE", 604_800),
            604_800
        );
        assert_eq!(
            effective_attachment_ttl_sec(Some(100), &ConversationAccess::Direct, "FILE", 60,),
            60
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
        assert!(matches!(
            &delivered,
            OutboundFrame::Message {
                ciphertext_b64,
                wrapped_key_b64,
                ..
            } if !ciphertext_b64.is_empty() && !wrapped_key_b64.is_empty()
        ));
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
    async fn direct_catalog_enforces_global_and_per_user_caps() {
        let state = test_state();
        add_test_account(&state, "direct-owner", "Alice").await;
        add_test_account(&state, "direct-peer", "Bob").await;
        let (alice_id, _) = add_test_client(&state, "direct-owner", "Alice").await;

        for index in 0..MAX_DIRECT_CATALOG_PER_USER {
            add_test_account(
                &state,
                &format!("direct-peer-{index}"),
                &format!("Peer{index}"),
            )
            .await;
            open_direct(&state, alice_id, &format!("Peer{index}"))
                .await
                .expect("direct should fit per-user cap");
        }
        assert!(open_direct(&state, alice_id, "Bob").await.is_err());

        let global_state = test_state();
        add_test_account(&global_state, "global-owner", "Alice").await;
        add_test_account(&global_state, "global-peer", "Bob").await;
        let (global_alice_id, _) = add_test_client(&global_state, "global-owner", "Alice").await;
        {
            let mut catalog = global_state.direct_catalog.lock().await;
            for index in 0..MAX_DIRECT_CATALOG_ENTRIES {
                catalog.insert(
                    format!("dm_filled_{index}"),
                    DirectEntry {
                        id: format!("dm_filled_{index}"),
                        user_a: format!("UserA{index}"),
                        user_b: format!("UserB{index}"),
                    },
                );
            }
        }
        assert!(open_direct(&global_state, global_alice_id, "Bob")
            .await
            .is_err());

        let victim_state = test_state();
        add_test_account(&victim_state, "victim-owner", "Alice").await;
        add_test_account(&victim_state, "victim-peer", "Victim").await;
        let (victim_alice_id, _) = add_test_client(&victim_state, "victim-owner", "Alice").await;
        {
            let mut catalog = victim_state.direct_catalog.lock().await;
            for index in 0..MAX_DIRECT_CATALOG_PER_USER {
                catalog.insert(
                    format!("dm_victim_{index}"),
                    DirectEntry {
                        id: format!("dm_victim_{index}"),
                        user_a: "Victim".to_string(),
                        user_b: format!("ExistingPeer{index}"),
                    },
                );
            }
        }
        assert!(open_direct(&victim_state, victim_alice_id, "Victim")
            .await
            .is_err());
    }

    #[test]
    fn opaque_finish_request_shape_is_exclusive_to_handshake_mode() {
        let registration = OpaqueAccountFinishRequest {
            handshake_id: Uuid::new_v4(),
            registration_upload_b64: Some("upload".to_string()),
            credential_finalization_b64: None,
            identity_public_b64: Some("public".to_string()),
            identity_prekey_id: Some("prekey".to_string()),
            identity_envelope_b64: Some("envelope".to_string()),
            identity_proof_b64: Some("proof".to_string()),
        };
        assert!(opaque_finish_request_is_registration(&registration));

        let mut registration_with_login_field = registration;
        registration_with_login_field.credential_finalization_b64 =
            Some("finalization".to_string());
        assert!(!opaque_finish_request_is_registration(
            &registration_with_login_field
        ));

        let login = OpaqueAccountFinishRequest {
            handshake_id: Uuid::new_v4(),
            registration_upload_b64: None,
            credential_finalization_b64: Some("finalization".to_string()),
            identity_public_b64: None,
            identity_prekey_id: None,
            identity_envelope_b64: None,
            identity_proof_b64: None,
        };
        assert!(opaque_finish_request_is_login(&login));

        let mut login_with_identity_field = login;
        login_with_identity_field.identity_proof_b64 = Some("proof".to_string());
        assert!(!opaque_finish_request_is_login(&login_with_identity_field));
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
    async fn relay_requires_v8_signature_on_each_recipient_envelope() {
        let state = test_state();
        add_test_account(&state, "code-a", "Alice").await;
        add_test_account(&state, "code-b", "Bob").await;
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
        let envelope = |signature_b64: &str| InboundRecipientEnvelope {
            recipient_username: "Bob".to_string(),
            wrapped_key_b64: URL_SAFE_NO_PAD.encode([4_u8; 256]),
            prekey_id: String::new(),
            is_prekey: false,
            signature_b64: signature_b64.to_string(),
        };

        assert!(route_test_message_with_envelopes(
            &state,
            alice_id,
            &direct_id,
            E2EE_PROTOCOL_VERSION,
            "missing-envelope-signature",
            vec![envelope("")],
        )
        .await
        .is_err());
        assert!(route_test_message_with_envelopes(
            &state,
            alice_id,
            &direct_id,
            E2EE_PROTOCOL_VERSION,
            "malformed-envelope-signature",
            vec![envelope("not-base64")],
        )
        .await
        .is_err());
        assert!(route_test_message_with_envelopes(
            &state,
            alice_id,
            &direct_id,
            E2EE_PROTOCOL_VERSION,
            "duplicate-recipient-envelope",
            vec![
                envelope(&test_signature_b64(b'A')),
                envelope(&test_signature_b64(b'B')),
            ],
        )
        .await
        .is_err());
        assert!(route_test_message_with_envelopes(
            &state,
            alice_id,
            &direct_id,
            E2EE_PROTOCOL_VERSION - 1,
            "legacy-v5-message",
            vec![envelope(&test_signature_b64(b'C'))],
        )
        .await
        .is_err());

        let (bob_id, mut bob_rx) = add_test_client(&state, "code-b", "Bob").await;
        join_room(&state, alice_id, direct_id.clone())
            .await
            .expect("Alice joins direct");
        join_room(&state, bob_id, direct_id.clone())
            .await
            .expect("Bob joins direct");
        let identity_public = state
            .accounts
            .lock()
            .await
            .get(&test_code_id("code-a"))
            .expect("Alice account")
            .identity_public
            .clone();
        let wrapped_key = [4_u8; 256];
        let valid_signature = test_valid_message_signature_b64(
            b'A',
            &direct_id,
            "forward-envelope-signature",
            "Alice",
            &identity_public,
            "Bob",
            &wrapped_key,
            "",
            false,
        );
        route_test_message_with_envelopes(
            &state,
            alice_id,
            &direct_id,
            E2EE_PROTOCOL_VERSION,
            "forward-envelope-signature",
            vec![InboundRecipientEnvelope {
                recipient_username: "Bob".to_string(),
                wrapped_key_b64: URL_SAFE_NO_PAD.encode(wrapped_key),
                prekey_id: String::new(),
                is_prekey: false,
                signature_b64: valid_signature.clone(),
            }],
        )
        .await
        .expect("valid v8 message should route");
        let OutboundFrame::Message {
            signature_b64,
            identity_public_b64,
            sender_public_key_b64,
            ..
        } = &bob_rx.try_recv().expect("Bob receives v8 message")
        else {
            panic!("expected text frame");
        };
        assert_eq!(signature_b64, &valid_signature);
        assert_eq!(identity_public_b64, sender_public_key_b64);
    }

    #[tokio::test]
    async fn forged_signature_cannot_claim_prekey_or_mutate_relay_state() {
        let state = test_state();
        add_test_account(&state, "code-a", "Alice").await;
        add_test_account(&state, "code-b", "Bob").await;
        let (alice_id, _) = add_test_client(&state, "code-a", "Alice").await;
        let (bob_id, mut bob_rx) = add_test_client(&state, "code-b", "Bob").await;
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
        join_room(&state, alice_id, direct_id.clone())
            .await
            .expect("Alice joins direct");
        join_room(&state, bob_id, direct_id.clone())
            .await
            .expect("Bob joins direct");
        while bob_rx.try_recv().is_ok() {}

        let identity_public = state
            .accounts
            .lock()
            .await
            .get(&test_code_id("code-a"))
            .expect("Alice account")
            .identity_public
            .clone();
        let wrapped_key = [9_u8; 256];
        let mut signature = URL_SAFE_NO_PAD
            .decode(test_valid_message_signature_b64(
                b'A',
                &direct_id,
                "forged-message",
                "Alice",
                &identity_public,
                "Bob",
                &wrapped_key,
                &test_prekey_id(b'B'),
                true,
            ))
            .expect("valid signature");
        signature[0] ^= 1;
        let result = route_test_message_with_envelopes(
            &state,
            alice_id,
            &direct_id,
            E2EE_PROTOCOL_VERSION,
            "forged-message",
            vec![InboundRecipientEnvelope {
                recipient_username: "Bob".to_string(),
                wrapped_key_b64: URL_SAFE_NO_PAD.encode(wrapped_key),
                prekey_id: test_prekey_id(b'B'),
                is_prekey: true,
                signature_b64: URL_SAFE_NO_PAD.encode(signature),
            }],
        )
        .await;
        assert!(result.is_err());
        assert!(state.prekey_claims.lock().await.is_empty());
        assert!(state.replay_ids.lock().await.is_empty());
        assert!(state.pending.lock().await.is_empty());
        assert_eq!(*state.pending_bytes.lock().await, 0);
        assert_eq!(
            state
                .accounts
                .lock()
                .await
                .get(&test_code_id("code-a"))
                .expect("Alice account")
                .state_revision,
            0
        );
        assert!(bob_rx.try_recv().is_err());
    }

    #[test]
    fn inbound_frames_reject_missing_envelope_signature_field() {
        let frame = serde_json::json!({
            "type": "message",
            "chat_id": "dm_a_b",
            "version": E2EE_PROTOCOL_VERSION,
            "message_id": "message-1",
            "nonce_b64": URL_SAFE_NO_PAD.encode([1_u8; MESSAGE_NONCE_BYTES]),
            "ciphertext_b64": URL_SAFE_NO_PAD.encode([2_u8; 16]),
            "envelopes": [{
                "recipient_username": "Bob",
                "wrapped_key_b64": URL_SAFE_NO_PAD.encode([3_u8; 32]),
                "prekey_id": "",
                "is_prekey": false
            }],
            "state_revision": 1,
            "identity_envelope_b64": URL_SAFE_NO_PAD.encode([IDENTITY_ENVELOPE_VERSION; 256]),
            "identity_public_b64": URL_SAFE_NO_PAD.encode([4_u8; IDENTITY_PUBLIC_BYTES]),
            "prekey_id": "fallback"
        });
        assert!(serde_json::from_value::<InboundFrame>(frame).is_err());
    }

    #[tokio::test]
    async fn acknowledgement_without_pending_frame_does_not_mutate_state() {
        let state = test_state();
        add_test_account(&state, "code-a", "Alice").await;
        add_test_account(&state, "code-b", "Bob").await;
        let (bob_id, _) = add_test_client(&state, "code-b", "Bob").await;
        let room = test_room("ack_without_pending");
        state.room_catalog.lock().await.insert(
            room.id.clone(),
            RoomEntry {
                room: room.clone(),
                owner_code_id: test_code_id("code-a"),
            },
        );

        let envelope_b64 = test_identity_envelope_b64(3);
        let identity_public_b64 = test_identity_public_b64(b'B');
        let prekey_id = test_prekey_id(b'B');
        let state_signature_b64 = test_valid_state_signature_b64(
            b'B',
            1,
            &envelope_b64,
            &identity_public_b64,
            &prekey_id,
        );
        let ack_signature_b64 =
            test_valid_ack_signature_b64(b'B', &room.id, "missing-message", "Alice", "");
        let before = state
            .accounts
            .lock()
            .await
            .get(&test_code_id("code-b"))
            .map(|account| {
                (
                    account.state_revision,
                    account.state_revision_window,
                    account.identity_envelope.clone(),
                    account.identity_public.clone(),
                    account.prekey_id.clone(),
                )
            })
            .expect("Bob account");
        let pending_bytes_before = *state.pending_bytes.lock().await;
        let replay_before = state.replay_ids.lock().await.len();
        let claims_before = state.prekey_claims.lock().await.len();

        let result = acknowledge_message(
            &state,
            bob_id,
            &room.id,
            "missing-message",
            "Alice",
            1,
            &envelope_b64,
            &identity_public_b64,
            &prekey_id,
            &state_signature_b64,
            &ack_signature_b64,
            "",
        )
        .await;
        assert!(result.is_err());

        let after = state
            .accounts
            .lock()
            .await
            .get(&test_code_id("code-b"))
            .map(|account| {
                (
                    account.state_revision,
                    account.state_revision_window,
                    account.identity_envelope.clone(),
                    account.identity_public.clone(),
                    account.prekey_id.clone(),
                )
            })
            .expect("Bob account");
        assert_eq!(after, before);
        assert_eq!(*state.pending_bytes.lock().await, pending_bytes_before);
        assert_eq!(state.replay_ids.lock().await.len(), replay_before);
        assert_eq!(state.prekey_claims.lock().await.len(), claims_before);
        assert!(state.pending.lock().await.is_empty());
    }

    #[tokio::test]
    async fn acknowledgement_requires_exact_pending_tuple_and_rejects_duplicate() {
        let state = test_state();
        add_test_account(&state, "code-a", "Alice").await;
        add_test_account(&state, "code-b", "Bob").await;
        let (alice_id, _) = add_test_client(&state, "code-a", "Alice").await;
        let (bob_id, _) = add_test_client(&state, "code-b", "Bob").await;
        let room = test_room("ack_exact_pending");
        state.room_catalog.lock().await.insert(
            room.id.clone(),
            RoomEntry {
                room: room.clone(),
                owner_code_id: test_code_id("code-a"),
            },
        );
        let wrong_chat = test_room("ack_exact_other");
        state.room_catalog.lock().await.insert(
            wrong_chat.id.clone(),
            RoomEntry {
                room: wrong_chat.clone(),
                owner_code_id: test_code_id("code-a"),
            },
        );
        let message_id = "exact-message";
        let prekey_id = test_prekey_id(b'B');
        let wrapped_key = [4_u8; 256];
        route_test_message_with_envelopes(
            &state,
            alice_id,
            &room.id,
            E2EE_PROTOCOL_VERSION,
            message_id,
            vec![InboundRecipientEnvelope {
                recipient_username: "Bob".to_string(),
                wrapped_key_b64: URL_SAFE_NO_PAD.encode(wrapped_key),
                prekey_id: prekey_id.clone(),
                is_prekey: true,
                signature_b64: test_valid_message_signature_b64(
                    b'A',
                    &room.id,
                    message_id,
                    "Alice",
                    &test_identity_public(b'A'),
                    "Bob",
                    &wrapped_key,
                    &prekey_id,
                    true,
                ),
            }],
        )
        .await
        .expect("prekey message queues");

        let envelope_b64 = test_identity_envelope_b64(4);
        let identity_public_b64 = test_identity_public_b64(b'B');
        let state_signature_b64 = test_valid_state_signature_b64(
            b'B',
            1,
            &envelope_b64,
            &identity_public_b64,
            &prekey_id,
        );
        let pending_key = PendingKey {
            chat_id: room.id.clone(),
            recipient_username: "Bob".to_string(),
        };
        let before = ack_test_snapshot(&state, &test_code_id("code-b"), &pending_key).await;
        assert!(!before.3.is_empty(), "prekey claim should be pending");

        let wrong_chat_ack_signature_b64 =
            test_valid_ack_signature_b64(b'B', &wrong_chat.id, message_id, "Alice", &prekey_id);
        assert!(acknowledge_message(
            &state,
            bob_id,
            &wrong_chat.id,
            message_id,
            "Alice",
            1,
            &envelope_b64,
            &identity_public_b64,
            &prekey_id,
            &state_signature_b64,
            &wrong_chat_ack_signature_b64,
            &prekey_id,
        )
        .await
        .is_err());
        let after_wrong_chat =
            ack_test_snapshot(&state, &test_code_id("code-b"), &pending_key).await;
        assert_eq!(after_wrong_chat, before);

        let wrong_prekey_id = test_prekey_id(b'X');
        let wrong_prekey_ack_signature_b64 =
            test_valid_ack_signature_b64(b'B', &room.id, message_id, "Alice", &wrong_prekey_id);
        assert!(acknowledge_message(
            &state,
            bob_id,
            &room.id,
            message_id,
            "Alice",
            1,
            &envelope_b64,
            &identity_public_b64,
            &prekey_id,
            &state_signature_b64,
            &wrong_prekey_ack_signature_b64,
            &wrong_prekey_id,
        )
        .await
        .is_err());
        let after_wrong_prekey =
            ack_test_snapshot(&state, &test_code_id("code-b"), &pending_key).await;
        assert_eq!(after_wrong_prekey, before);

        let wrong_message_id = "wrong-message";
        let wrong_ack_signature_b64 =
            test_valid_ack_signature_b64(b'B', &room.id, wrong_message_id, "Alice", &prekey_id);
        assert!(acknowledge_message(
            &state,
            bob_id,
            &room.id,
            wrong_message_id,
            "Alice",
            1,
            &envelope_b64,
            &identity_public_b64,
            &prekey_id,
            &state_signature_b64,
            &wrong_ack_signature_b64,
            &prekey_id,
        )
        .await
        .is_err());
        let after_wrong = ack_test_snapshot(&state, &test_code_id("code-b"), &pending_key).await;
        assert_eq!(after_wrong, before);

        let ack_signature_b64 =
            test_valid_ack_signature_b64(b'B', &room.id, message_id, "Alice", &prekey_id);
        acknowledge_message(
            &state,
            bob_id,
            &room.id,
            message_id,
            "Alice",
            1,
            &envelope_b64,
            &identity_public_b64,
            &prekey_id,
            &state_signature_b64,
            &ack_signature_b64,
            &prekey_id,
        )
        .await
        .expect("matching acknowledgement");
        let after_matching = state
            .accounts
            .lock()
            .await
            .get(&test_code_id("code-b"))
            .map(|account| {
                (
                    account.state_revision,
                    account.state_revision_window,
                    account.identity_envelope.clone(),
                    account.identity_public.clone(),
                    account.prekey_id.clone(),
                )
            })
            .expect("Bob account");
        let pending_bytes_after_matching = *state.pending_bytes.lock().await;
        assert_eq!(pending_bytes_after_matching, 0);

        assert!(acknowledge_message(
            &state,
            bob_id,
            &room.id,
            message_id,
            "Alice",
            1,
            &envelope_b64,
            &identity_public_b64,
            &prekey_id,
            &state_signature_b64,
            &ack_signature_b64,
            &prekey_id,
        )
        .await
        .is_err());
        let after_duplicate = state
            .accounts
            .lock()
            .await
            .get(&test_code_id("code-b"))
            .map(|account| {
                (
                    account.state_revision,
                    account.state_revision_window,
                    account.identity_envelope.clone(),
                    account.identity_public.clone(),
                    account.prekey_id.clone(),
                )
            })
            .expect("Bob account");
        assert_eq!(after_duplicate, after_matching);
        assert_eq!(
            *state.pending_bytes.lock().await,
            pending_bytes_after_matching
        );
        assert!(state.pending.lock().await.is_empty());
        assert!(state.prekey_claims.lock().await.is_empty());
    }

    #[tokio::test]
    async fn acknowledgement_signature_is_required_and_binds_metadata() {
        let state = test_state();
        add_test_account(&state, "code-a", "Alice").await;
        add_test_account(&state, "code-b", "Bob").await;
        let (alice_id, _) = add_test_client(&state, "code-a", "Alice").await;
        let (bob_id, _) = add_test_client(&state, "code-b", "Bob").await;
        let room = test_room("ack_signature_binding");
        state.room_catalog.lock().await.insert(
            room.id.clone(),
            RoomEntry {
                room: room.clone(),
                owner_code_id: test_code_id("code-a"),
            },
        );
        join_room(&state, alice_id, room.id.clone())
            .await
            .expect("Alice joins room");
        join_room(&state, bob_id, room.id.clone())
            .await
            .expect("Bob joins room");
        let message_id = "ack-signature-message";
        route_test_message_with_id(&state, alice_id, &room.id, &["Bob"], message_id)
            .await
            .expect("message queues");

        let envelope_b64 = test_identity_envelope_b64(0);
        let identity_public_b64 = test_identity_public_b64(b'B');
        let prekey_id = test_prekey_id(b'B');
        let state_signature_b64 = test_valid_state_signature_b64(
            b'B',
            1,
            &envelope_b64,
            &identity_public_b64,
            &prekey_id,
        );
        let valid_ack_signature_b64 =
            test_valid_ack_signature_b64(b'B', &room.id, message_id, "Alice", "");

        assert!(acknowledge_message(
            &state,
            bob_id,
            &room.id,
            message_id,
            "Alice",
            1,
            &envelope_b64,
            &identity_public_b64,
            &prekey_id,
            &state_signature_b64,
            "",
            "",
        )
        .await
        .is_err());
        assert!(state.pending.lock().await.contains_key(&PendingKey {
            chat_id: room.id.clone(),
            recipient_username: "Bob".to_string(),
        }));

        let mut forged_ack = URL_SAFE_NO_PAD
            .decode(&valid_ack_signature_b64)
            .expect("ack signature encoding");
        forged_ack[0] ^= 1;
        assert!(acknowledge_message(
            &state,
            bob_id,
            &room.id,
            message_id,
            "Alice",
            1,
            &envelope_b64,
            &identity_public_b64,
            &prekey_id,
            &state_signature_b64,
            &URL_SAFE_NO_PAD.encode(forged_ack),
            "",
        )
        .await
        .is_err());

        assert!(acknowledge_message(
            &state,
            bob_id,
            &room.id,
            "different-message",
            "Alice",
            1,
            &envelope_b64,
            &identity_public_b64,
            &prekey_id,
            &state_signature_b64,
            &valid_ack_signature_b64,
            "",
        )
        .await
        .is_err());
        assert!(state.pending.lock().await.contains_key(&PendingKey {
            chat_id: room.id.clone(),
            recipient_username: "Bob".to_string(),
        }));
    }

    #[tokio::test]
    async fn acknowledgement_action_signature_survives_a_later_state_snapshot() {
        let state = test_state();
        add_test_account(&state, "code-a", "Alice").await;
        add_test_account(&state, "code-b", "Bob").await;
        let (alice_id, _) = add_test_client(&state, "code-a", "Alice").await;
        let (bob_id, _) = add_test_client(&state, "code-b", "Bob").await;
        let room = test_room("ack_later_state");
        state.room_catalog.lock().await.insert(
            room.id.clone(),
            RoomEntry {
                room: room.clone(),
                owner_code_id: test_code_id("code-a"),
            },
        );
        join_room(&state, alice_id, room.id.clone())
            .await
            .expect("Alice joins room");
        join_room(&state, bob_id, room.id.clone())
            .await
            .expect("Bob joins room");
        let message_id = "ack-later-state-message";
        route_test_message_with_id(&state, alice_id, &room.id, &["Bob"], message_id)
            .await
            .expect("message queues");

        let identity_envelope_b64 = test_identity_envelope_b64(9);
        let identity_public_b64 = test_identity_public_b64(b'B');
        let prekey_id = test_prekey_id(b'B');
        let later_state_signature_b64 = test_valid_state_signature_b64(
            b'B',
            2,
            &identity_envelope_b64,
            &identity_public_b64,
            &prekey_id,
        );
        // This signature proves only the acknowledgement action.  It remains
        // valid even though the separately signed identity snapshot advanced
        // after the message was decrypted.
        let action_signature_b64 =
            test_valid_ack_signature_b64(b'B', &room.id, message_id, "Alice", "");

        acknowledge_message(
            &state,
            bob_id,
            &room.id,
            message_id,
            "Alice",
            2,
            &identity_envelope_b64,
            &identity_public_b64,
            &prekey_id,
            &later_state_signature_b64,
            &action_signature_b64,
            "",
        )
        .await
        .expect("action signature accepts later state");
        assert!(state.pending.lock().await.is_empty());
        assert_eq!(
            state
                .accounts
                .lock()
                .await
                .get(&test_code_id("code-b"))
                .expect("Bob account")
                .state_revision,
            2
        );
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
        let OutboundFrame::Message {
            message_id,
            ciphertext_b64,
            ..
        } = &delivered
        else {
            panic!("expected text frame")
        };
        assert!(!ciphertext_b64.is_empty());
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
            &test_valid_state_signature_b64(
                b'B',
                1,
                &test_identity_envelope_b64(0),
                &test_identity_public_b64(b'B'),
                &test_prekey_id(b'B'),
            ),
            &test_valid_ack_signature_b64(b'B', &direct_id, message_id, "Alice", ""),
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
        let OutboundFrame::Message {
            message_id,
            ciphertext_b64,
            ..
        } = &delivered
        else {
            panic!("expected text frame")
        };
        assert!(!ciphertext_b64.is_empty());
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
            &test_valid_state_signature_b64(
                b'B',
                1,
                &test_identity_envelope_b64(0),
                &test_identity_public_b64(b'B'),
                &test_prekey_id(b'B'),
            ),
            &test_valid_ack_signature_b64(b'B', &room.id, message_id, "Alice", ""),
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
            &test_signature_b64(0),
            &test_signature_b64(0),
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
            &test_valid_state_signature_b64(
                b'B',
                1,
                &test_identity_envelope_b64(0),
                &test_identity_public_b64(b'B'),
                &test_prekey_id(b'B'),
            ),
            &test_valid_ack_signature_b64(b'B', &room.id, shared_message_id, "Alice", ""),
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
            &bob_queue[0].frame,
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
            &test_valid_state_signature_b64(
                b'B',
                1,
                &test_identity_envelope_b64(0),
                &test_identity_public_b64(b'B'),
                &test_prekey_id(b'B'),
            ),
            &test_valid_ack_signature_b64(b'B', &room.id, shared_message_id, "Eve", ""),
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
    async fn mismatched_prekey_ack_does_not_advance_recipient_identity_state() {
        let state = test_state();
        add_test_account(&state, "code-a", "Alice").await;
        add_test_account(&state, "code-b", "Bob").await;
        let (bob_id, _) = add_test_client(&state, "code-b", "Bob").await;
        let room = test_room("prekey_ack_order");
        state.room_catalog.lock().await.insert(
            room.id.clone(),
            RoomEntry {
                room,
                owner_code_id: test_code_id("code-a"),
            },
        );
        let prekey_id = test_prekey_id(b'B');
        state.prekey_claims.lock().await.insert(
            PrekeyClaimKey {
                code_id: test_code_id("code-b"),
                prekey_id: prekey_id.clone(),
            },
            PrekeyClaim {
                chat_id: "prekey_ack_order".to_string(),
                message_id: "claimed-message".to_string(),
                sender_username: "Alice".to_string(),
                recipient_username: "Bob".to_string(),
                created_at_ms: now_ms(),
            },
        );

        let result = acknowledge_message(
            &state,
            bob_id,
            "prekey_ack_order",
            "different-message",
            "Alice",
            5,
            &URL_SAFE_NO_PAD.encode({
                let mut envelope = [0_u8; 256];
                envelope[0] = IDENTITY_ENVELOPE_VERSION;
                envelope
            }),
            &test_identity_public_b64(b'B'),
            &prekey_id,
            &test_signature_b64(0),
            &test_signature_b64(0),
            &prekey_id,
        )
        .await;
        assert!(result.is_err());

        let account = state
            .accounts
            .lock()
            .await
            .get(&test_code_id("code-b"))
            .cloned()
            .expect("Bob account");
        assert_eq!(account.state_revision, 0);
        assert_eq!(account.state_revision_window, 1);
        assert!(state
            .prekey_claims
            .lock()
            .await
            .contains_key(&PrekeyClaimKey {
                code_id: test_code_id("code-b"),
                prekey_id,
            }));
    }

    #[tokio::test]
    async fn prekey_ack_requires_a_matching_claim_before_mutating_state() {
        let state = test_state();
        add_test_account(&state, "code-a", "Alice").await;
        add_test_account(&state, "code-b", "Bob").await;
        let (bob_id, _) = add_test_client(&state, "code-b", "Bob").await;
        let room = test_room("prekey_ack_requires_claim");
        state.room_catalog.lock().await.insert(
            room.id.clone(),
            RoomEntry {
                room,
                owner_code_id: test_code_id("code-a"),
            },
        );

        let result = acknowledge_message(
            &state,
            bob_id,
            "prekey_ack_requires_claim",
            "unclaimed-message",
            "Alice",
            5,
            &URL_SAFE_NO_PAD.encode({
                let mut envelope = [0_u8; 256];
                envelope[0] = IDENTITY_ENVELOPE_VERSION;
                envelope
            }),
            &test_identity_public_b64(b'B'),
            &test_prekey_id(b'B'),
            &test_signature_b64(0),
            &test_signature_b64(0),
            &test_prekey_id(b'B'),
        )
        .await;
        assert!(result.is_err());
        let account = state
            .accounts
            .lock()
            .await
            .get(&test_code_id("code-b"))
            .cloned()
            .expect("Bob account");
        assert_eq!(account.state_revision, 0);
        assert_eq!(account.state_revision_window, 1);
        assert!(state.pending.lock().await.is_empty());
    }

    #[tokio::test]
    async fn replay_sender_quota_does_not_block_another_sender() {
        let state = test_state();
        for index in 0..MAX_REPLAY_IDS_PER_SENDER {
            register_message_id(
                &state,
                "forum_sender_quota",
                "Alice",
                &format!("message-{index}"),
            )
            .await
            .expect("sender quota should fill with unique messages");
        }
        assert!(
            register_message_id(&state, "forum_sender_quota", "Alice", "message-overflow")
                .await
                .is_err()
        );
        assert!(
            register_message_id(&state, "forum_sender_quota", "Bob", "message-1")
                .await
                .is_ok()
        );
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
        let revision_two_b64 = URL_SAFE_NO_PAD.encode(revision_two);
        let revision_one_b64 = URL_SAFE_NO_PAD.encode(revision_one);
        let identity_public_b64 = test_identity_public_b64(b'A');
        let prekey_id = test_prekey_id(b'A');
        let revision_two_signature = test_valid_state_signature_b64(
            b'A',
            2,
            &revision_two_b64,
            &identity_public_b64,
            &prekey_id,
        );
        let revision_one_signature = test_valid_state_signature_b64(
            b'A',
            1,
            &revision_one_b64,
            &identity_public_b64,
            &prekey_id,
        );

        apply_identity_state(
            &state,
            &code_id,
            2,
            &revision_two_b64,
            &identity_public_b64,
            &prekey_id,
            &revision_two_signature,
            false,
        )
        .await
        .expect("newer revision");
        apply_identity_state(
            &state,
            &code_id,
            1,
            &revision_one_b64,
            &identity_public_b64,
            &prekey_id,
            &revision_one_signature,
            false,
        )
        .await
        .expect("bounded out-of-order revision");
        assert!(apply_identity_state(
            &state,
            &code_id,
            1,
            &revision_one_b64,
            &identity_public_b64,
            &prekey_id,
            &revision_one_signature,
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
    async fn identity_state_signature_binds_all_fields_and_limits_revision_jump() {
        let state = test_state();
        add_test_account(&state, "code-a", "Alice").await;
        let code_id = test_code_id("code-a");
        let identity_public_b64 = test_identity_public_b64(b'A');
        let prekey_id = test_prekey_id(b'A');
        let envelope_one_b64 = test_identity_envelope_b64(1);
        let signature_one = test_valid_state_signature_b64(
            b'A',
            1,
            &envelope_one_b64,
            &identity_public_b64,
            &prekey_id,
        );
        apply_identity_state(
            &state,
            &code_id,
            1,
            &envelope_one_b64,
            &identity_public_b64,
            &prekey_id,
            &signature_one,
            false,
        )
        .await
        .expect("valid signed state");

        let envelope_two_b64 = test_identity_envelope_b64(2);
        let signature_two = test_valid_state_signature_b64(
            b'A',
            2,
            &envelope_two_b64,
            &identity_public_b64,
            &prekey_id,
        );
        let mut forged_signature = URL_SAFE_NO_PAD
            .decode(&signature_two)
            .expect("signature encoding");
        forged_signature[0] ^= 1;
        assert!(apply_identity_state(
            &state,
            &code_id,
            2,
            &envelope_two_b64,
            &identity_public_b64,
            &prekey_id,
            &URL_SAFE_NO_PAD.encode(forged_signature),
            false,
        )
        .await
        .is_err());

        let mut tampered_envelope = URL_SAFE_NO_PAD
            .decode(&envelope_two_b64)
            .expect("envelope encoding");
        tampered_envelope[1] ^= 1;
        assert!(apply_identity_state(
            &state,
            &code_id,
            2,
            &URL_SAFE_NO_PAD.encode(tampered_envelope),
            &identity_public_b64,
            &prekey_id,
            &signature_two,
            false,
        )
        .await
        .is_err());

        let mut tampered_public = URL_SAFE_NO_PAD
            .decode(&identity_public_b64)
            .expect("public encoding");
        tampered_public[0] ^= 1;
        assert!(apply_identity_state(
            &state,
            &code_id,
            2,
            &envelope_two_b64,
            &URL_SAFE_NO_PAD.encode(tampered_public),
            &prekey_id,
            &signature_two,
            false,
        )
        .await
        .is_err());

        assert!(apply_identity_state(
            &state,
            &code_id,
            2,
            &envelope_two_b64,
            &identity_public_b64,
            &test_prekey_id(b'B'),
            &signature_two,
            false,
        )
        .await
        .is_err());
        assert!(apply_identity_state(
            &state,
            &code_id,
            3,
            &envelope_two_b64,
            &identity_public_b64,
            &prekey_id,
            &signature_two,
            false,
        )
        .await
        .is_err());

        let huge_revision = 1 + MAX_STATE_REVISION_ADVANCE + 1;
        let huge_signature = test_valid_state_signature_b64(
            b'A',
            huge_revision,
            &envelope_two_b64,
            &identity_public_b64,
            &prekey_id,
        );
        assert!(apply_identity_state(
            &state,
            &code_id,
            huge_revision,
            &envelope_two_b64,
            &identity_public_b64,
            &prekey_id,
            &huge_signature,
            false,
        )
        .await
        .is_err());

        let account = state
            .accounts
            .lock()
            .await
            .get(&code_id)
            .cloned()
            .expect("Alice account");
        assert_eq!(account.state_revision, 1);
        assert_eq!(
            account.identity_envelope,
            URL_SAFE_NO_PAD.decode(envelope_one_b64).unwrap()
        );
    }

    #[tokio::test]
    async fn stale_reusable_state_requires_the_current_public_bundle() {
        let state = test_state();
        add_test_account(&state, "code-a", "Alice").await;
        let code_id = test_code_id("code-a");
        let current_public_b64 = test_identity_public_b64(b'A');
        let current_prekey_id = test_prekey_id(b'A');
        let current_envelope_b64 = test_identity_envelope_b64(7);
        let current_signature = test_valid_state_signature_b64(
            b'A',
            129,
            &current_envelope_b64,
            &current_public_b64,
            &current_prekey_id,
        );
        apply_identity_state(
            &state,
            &code_id,
            129,
            &current_envelope_b64,
            &current_public_b64,
            &current_prekey_id,
            &current_signature,
            false,
        )
        .await
        .expect("current state");

        let mut stale_public = test_identity_public(b'A');
        stale_public[IDENTITY_FINGERPRINT_BYTES..IDENTITY_FINGERPRINT_BYTES + ONE_TIME_KEY_BYTES]
            .fill(b'Z');
        let stale_public_b64 = URL_SAFE_NO_PAD.encode(&stale_public);
        let stale_prekey_id = abyssal_core::secure_protocol::prekey_id_for_public(&[b'Z'; 32]);
        let stale_envelope_b64 = test_identity_envelope_b64(8);
        let stale_signature = test_valid_state_signature_b64(
            b'A',
            1,
            &stale_envelope_b64,
            &stale_public_b64,
            &stale_prekey_id,
        );

        assert!(apply_identity_state(
            &state,
            &code_id,
            1,
            &stale_envelope_b64,
            &stale_public_b64,
            &stale_prekey_id,
            &stale_signature,
            true,
        )
        .await
        .is_err());
        let account = state
            .accounts
            .lock()
            .await
            .get(&code_id)
            .cloned()
            .expect("Alice account");
        assert_eq!(account.state_revision, 129);
        assert_eq!(
            account.identity_public,
            URL_SAFE_NO_PAD.decode(current_public_b64).unwrap()
        );
        assert_eq!(account.prekey_id, current_prekey_id);
    }

    #[tokio::test]
    async fn account_code_allows_only_one_unexpired_session() {
        let state = test_state();
        let code = "ABYS-SESSION-0001";
        let code_id = test_code_id(code);
        state.sessions.lock().await.insert(
            SessionToken::new("active-token".to_string()),
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
            attachment_account_limit_bytes: 4 * 1024 * 1024,
            attachment_record_limit: DEFAULT_ATTACHMENT_RECORD_LIMIT,
            attachment_account_record_limit: DEFAULT_ATTACHMENT_ACCOUNT_RECORD_LIMIT,
            attachment_max_lifetime_sec: DEFAULT_ATTACHMENT_MAX_LIFETIME_HOURS as u64 * 60 * 60,
            max_rooms_per_user: 2,
            conversation_ops: Arc::new(Mutex::new(())),
            pending_message_ttl_ms: pending_message_ttl_ms_from_value(None),
            web_origins: Vec::new(),
            session_inactivity_ms: 60_000,
            inactivity_limit_ms: None,
            last_activity_ms: Arc::new(Mutex::new(now_ms())),
            account_ops: Arc::new(Mutex::new(())),
            opaque_setup: Arc::new(Zeroizing::new(opaque_server_setup())),
            opaque_handshakes: Arc::new(Mutex::new(HashMap::new())),
            invite_code_pepper: Arc::new(Zeroizing::new([7_u8; 32])),
            boot_codes: Arc::new(Mutex::new(None)),
            available_codes: Arc::new(Mutex::new(HashSet::new())),
            accounts: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            ws_tickets: Arc::new(Mutex::new(HashMap::new())),
            clients: Arc::new(Mutex::new(HashMap::new())),
            purge_epoch: watch::channel(0_u64).0,
            outbound_bytes: Arc::new(AtomicUsize::new(0)),
            active_connections: Arc::new(Mutex::new(HashMap::new())),
            frame_limits: Arc::new(Mutex::new(HashMap::new())),
            login_limits: Arc::new(Mutex::new(HashMap::new())),
            replay_ids: Arc::new(Mutex::new(HashMap::new())),
            rooms: Arc::new(Mutex::new(HashMap::new())),
            room_catalog: Arc::new(Mutex::new(HashMap::new())),
            direct_catalog: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
            pending_bytes: Arc::new(Mutex::new(0)),
            attachments: Arc::new(Mutex::new(HashMap::new())),
            attachment_bytes_by_code: Arc::new(Mutex::new(HashMap::new())),
            attachment_downloads: Arc::new(Semaphore::new(DEFAULT_ATTACHMENT_DOWNLOAD_CONCURRENCY)),
            attachment_uploads: Arc::new(Semaphore::new(1)),
            attachment_memory: Arc::new(Semaphore::new(8 * 1024 * 1024)),
            attachment_epoch: Arc::new(AtomicU64::new(0)),
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
                identity_public: test_identity_public(identity_fill),
                prekey_id: test_prekey_id(identity_fill),
                identity_envelope,
                state_revision: 0,
                state_revision_window: 1,
                connected: true,
                attachment_uploads: Arc::new(Semaphore::new(1)),
            },
        );
    }

    type AckTestAccountState = (u64, u128, Vec<u8>, Vec<u8>, String);
    type AckTestFrameState = (u64, serde_json::Value);
    type AckTestClaimState = ([u8; 32], String, String, String, String, String, u64);

    async fn ack_test_snapshot(
        state: &AppState,
        code_id: &CodeId,
        pending_key: &PendingKey,
    ) -> (
        AckTestAccountState,
        usize,
        Vec<AckTestFrameState>,
        Vec<AckTestClaimState>,
    ) {
        let account = state
            .accounts
            .lock()
            .await
            .get(code_id)
            .map(|account| {
                (
                    account.state_revision,
                    account.state_revision_window,
                    account.identity_envelope.clone(),
                    account.identity_public.clone(),
                    account.prekey_id.clone(),
                )
            })
            .expect("ack test account");
        let pending_bytes = *state.pending_bytes.lock().await;
        let pending_frames = state
            .pending
            .lock()
            .await
            .get(pending_key)
            .expect("ack test pending queue")
            .iter()
            .map(|pending_frame| {
                (
                    pending_frame.enqueued_at_ms,
                    serde_json::to_value(&pending_frame.frame).expect("ack test frame JSON"),
                )
            })
            .collect();
        let mut claims = state
            .prekey_claims
            .lock()
            .await
            .iter()
            .map(|(key, claim)| {
                (
                    key.code_id,
                    key.prekey_id.clone(),
                    claim.chat_id.clone(),
                    claim.message_id.clone(),
                    claim.sender_username.clone(),
                    claim.recipient_username.clone(),
                    claim.created_at_ms,
                )
            })
            .collect::<Vec<_>>();
        claims.sort_by(|left, right| left.1.cmp(&right.1));
        (account, pending_bytes, pending_frames, claims)
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
        let (code_id, sender_username) = client_identity(state, sender_id).await?;
        let (state_revision, identity_public, identity_public_b64, prekey_id) = state
            .accounts
            .lock()
            .await
            .get(&code_id)
            .map(|account| {
                (
                    account.state_revision + 1,
                    account.identity_public.clone(),
                    URL_SAFE_NO_PAD.encode(&account.identity_public),
                    account.prekey_id.clone(),
                )
            })
            .ok_or_else(|| "missing test account".to_string())?;
        let identity_envelope_b64 = test_identity_envelope_b64(0);
        let state_signature_b64 = test_valid_state_signature_b64(
            sender_username.as_bytes()[0],
            state_revision,
            &identity_envelope_b64,
            &identity_public_b64,
            &prekey_id,
        );
        route_encrypted_message(
            state,
            sender_id,
            chat_id.to_string(),
            E2EE_PROTOCOL_VERSION,
            message_id.to_string(),
            URL_SAFE_NO_PAD.encode([2_u8; MESSAGE_NONCE_BYTES]),
            URL_SAFE_NO_PAD.encode(b"ciphertext"),
            recipients
                .iter()
                .map(|username| {
                    let wrapped_key = [4_u8; 256];
                    InboundRecipientEnvelope {
                        recipient_username: (*username).to_string(),
                        wrapped_key_b64: URL_SAFE_NO_PAD.encode(wrapped_key),
                        prekey_id: String::new(),
                        is_prekey: false,
                        signature_b64: test_valid_message_signature_b64(
                            sender_username.as_bytes()[0],
                            chat_id,
                            message_id,
                            &sender_username,
                            &identity_public,
                            username,
                            &wrapped_key,
                            "",
                            false,
                        ),
                    }
                })
                .collect(),
            state_revision,
            identity_envelope_b64,
            identity_public_b64,
            prekey_id,
            state_signature_b64,
        )
        .await
    }

    async fn route_test_message_with_envelopes(
        state: &AppState,
        sender_id: Uuid,
        chat_id: &str,
        version: u32,
        message_id: &str,
        envelopes: Vec<InboundRecipientEnvelope>,
    ) -> Result<(), String> {
        let (code_id, sender_username) = client_identity(state, sender_id).await?;
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
        let identity_envelope_b64 = test_identity_envelope_b64(0);
        let state_signature_b64 = test_valid_state_signature_b64(
            sender_username.as_bytes()[0],
            state_revision,
            &identity_envelope_b64,
            &identity_public_b64,
            &prekey_id,
        );
        route_encrypted_message(
            state,
            sender_id,
            chat_id.to_string(),
            version,
            message_id.to_string(),
            URL_SAFE_NO_PAD.encode([2_u8; MESSAGE_NONCE_BYTES]),
            URL_SAFE_NO_PAD.encode(b"ciphertext"),
            envelopes,
            state_revision,
            identity_envelope_b64,
            identity_public_b64,
            prekey_id,
            state_signature_b64,
        )
        .await
    }

    async fn add_test_client(
        state: &AppState,
        code: &str,
        username: &str,
    ) -> (Uuid, mpsc::Receiver<OutboundFrame>) {
        let client_id = Uuid::new_v4();
        let (tx, rx) = mpsc::channel(CLIENT_OUTBOUND_QUEUE_CAPACITY);
        let (control_tx, _control_rx) = mpsc::channel(CLIENT_CONTROL_QUEUE_CAPACITY);
        let (result_tx, _result_rx) = mpsc::channel(CLIENT_RESULT_QUEUE_CAPACITY);
        state.clients.lock().await.insert(
            client_id,
            ClientHandle {
                code_id: test_code_id(code),
                username: username.to_string(),
                tx,
                control_tx,
                result_tx,
                queued_bytes: Arc::new(AtomicUsize::new(0)),
            },
        );
        (client_id, rx)
    }

    fn test_code_id(code: &str) -> CodeId {
        derive_code_id(&[7_u8; 32], code)
    }

    fn test_attachment_blob(bytes: Vec<u8>) -> Arc<AttachmentBlob> {
        Arc::new(AttachmentBlob {
            bytes: Zeroizing::new(bytes),
            _memory_permit: None,
        })
    }

    fn test_identity_public_b64(fill: u8) -> String {
        URL_SAFE_NO_PAD.encode(test_identity_public(fill))
    }

    fn test_identity_public(fill: u8) -> Vec<u8> {
        let signing_key = test_signing_key(fill);
        let mut identity_public = vec![fill; IDENTITY_PUBLIC_BYTES];
        identity_public[IDENTITY_FINGERPRINT_BYTES - 32..IDENTITY_FINGERPRINT_BYTES]
            .copy_from_slice(signing_key.verifying_key().as_bytes());
        identity_public
    }

    fn test_signing_key(fill: u8) -> SigningKey {
        SigningKey::from_bytes(&[fill; 32])
    }

    fn test_prekey_id(fill: u8) -> String {
        abyssal_core::secure_protocol::prekey_id_for_public(&[fill; ONE_TIME_KEY_BYTES])
    }

    fn test_signature_b64(fill: u8) -> String {
        URL_SAFE_NO_PAD.encode([fill; MESSAGE_SIGNATURE_BYTES])
    }

    fn test_identity_envelope_b64(fill: u8) -> String {
        let mut envelope = [fill; 256];
        envelope[0] = IDENTITY_ENVELOPE_VERSION;
        URL_SAFE_NO_PAD.encode(envelope)
    }

    fn test_valid_state_signature_b64(
        fill: u8,
        revision: u64,
        identity_envelope_b64: &str,
        identity_public_b64: &str,
        prekey_id: &str,
    ) -> String {
        let envelope = URL_SAFE_NO_PAD
            .decode(identity_envelope_b64)
            .expect("test identity envelope");
        let identity_public = URL_SAFE_NO_PAD
            .decode(identity_public_b64)
            .expect("test identity public");
        let transcript = abyssal_core::secure_protocol::identity_state_signature_input_v8(
            E2EE_PROTOCOL_VERSION,
            revision,
            &envelope,
            &identity_public,
            prekey_id,
        )
        .expect("test identity state transcript");
        let signature = test_signing_key(fill).sign(&transcript);
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    }

    fn test_valid_ack_signature_b64(
        fill: u8,
        chat_id: &str,
        message_id: &str,
        sender_username: &str,
        used_prekey_id: &str,
    ) -> String {
        let transcript = abyssal_core::secure_protocol::ack_signature_input_v8(
            E2EE_PROTOCOL_VERSION,
            chat_id,
            message_id,
            sender_username,
            used_prekey_id,
        )
        .expect("test acknowledgement transcript");
        let signature = test_signing_key(fill).sign(&transcript);
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    }

    #[allow(clippy::too_many_arguments)]
    fn test_valid_message_signature_b64(
        fill: u8,
        chat_id: &str,
        message_id: &str,
        sender_username: &str,
        identity_public: &[u8],
        recipient_username: &str,
        wrapped_key: &[u8],
        prekey_id: &str,
        is_prekey: bool,
    ) -> String {
        let transcript = abyssal_core::secure_protocol::message_signature_input_v8(
            E2EE_PROTOCOL_VERSION,
            chat_id,
            message_id,
            sender_username,
            identity_public,
            &[2_u8; MESSAGE_NONCE_BYTES],
            b"ciphertext",
            recipient_username,
            wrapped_key,
            prekey_id,
            is_prekey,
        )
        .expect("test transcript");
        let signature = test_signing_key(fill).sign(&transcript);
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    }

    fn test_message_frame(
        chat_id: &str,
        message_id: &str,
        sender_username: &str,
        prekey_id: &str,
        is_prekey: bool,
    ) -> OutboundFrame {
        OutboundFrame::Message {
            chat_id: chat_id.to_string(),
            version: E2EE_PROTOCOL_VERSION,
            message_id: message_id.to_string(),
            nonce_b64: "nonce".to_string(),
            ciphertext_b64: "ciphertext".to_string(),
            signature_b64: "signature".to_string(),
            wrapped_key_b64: "wrapped".to_string(),
            prekey_id: prekey_id.to_string(),
            is_prekey,
            sender_username: sender_username.to_string(),
            sender_public_key_b64: "public".to_string(),
            identity_public_b64: "public".to_string(),
        }
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

    #[test]
    fn hmac_sha256_matches_rfc_4231_known_answer() {
        // RFC 4231, test case 2.
        let mut mac = HmacSha256::new_from_slice(b"Jefe").expect("HMAC accepts any key length");
        mac.update(b"what do ya want for nothing?");
        let mut output = [0_u8; 32];
        output.copy_from_slice(&mac.finalize().into_bytes());
        assert_eq!(
            output,
            [
                0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
                0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
                0x64, 0xec, 0x38, 0x43,
            ]
        );
    }
}
