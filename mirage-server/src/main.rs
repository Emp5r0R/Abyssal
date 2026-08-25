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
    attachment_encrypted_size, attachment_plaintext_size_from_blob, opaque_server_finish_login,
    opaque_server_finish_registration, opaque_server_registration_response, opaque_server_setup,
    opaque_server_start_login, prekey_ids_from_identity_public_v9,
    validate_identity_public_bundle as validate_core_identity_public_bundle,
    verify_ack_signature_v9, verify_identity_state_signature_v9, verify_message_signature_v9,
    verify_registration_identity_proof_v9, IDENTITY_PUBLIC_BYTES_V9, PREKEY_POOL_SIZE_V9,
    REGISTRATION_CHALLENGE_BYTES_V9,
};
#[cfg(test)]
use abyssal_core::secure_protocol::{ATTACHMENT_BLOB_VERSION, ATTACHMENT_CHUNK_RECORD_BYTES};
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
use tracing::{debug, info, warn};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

mod client_platform;
mod mls_wire;
mod release_admission;
mod rooms;
mod transaction_receipts;
mod transport_padding;

use client_platform::{ClientPlatform, InteropPolicy};
use release_admission::{
    BuildAttestationRequest, InstallOutcome, ReleaseAdmissionStore, ReleaseManifestMirror,
};
use transaction_receipts::{
    BeginOutcome as TransactionBeginOutcome, ReceiptError as TransactionReceiptError,
    TransactionKey, TransactionKind, TransactionReceiptStore, TransactionTicket,
};
use transport_padding::{
    control_transport_frame_len, json_array_len, json_bool_len, json_field_len, json_number_len,
    json_object_len, json_string_field_len, pad_control_transport_frame,
    random_message_transport_padding, strip_control_transport_frame,
    valid_message_transport_padding, CONTROL_TRANSPORT_MAX_BUCKET, MESSAGE_TRANSPORT_BUCKETS,
    MESSAGE_TRANSPORT_MAX_BUCKET,
};

const IMAGE_ATTACHMENT_LIMIT_BYTES: usize = 20 * 1024 * 1024;
const VIDEO_ATTACHMENT_LIMIT_BYTES: usize = 100 * 1024 * 1024;
const FILE_ATTACHMENT_LIMIT_BYTES: usize = 200 * 1024 * 1024;
const WS_RATE_WINDOW_MS: u64 = 10_000;
const WS_MAX_FRAMES_PER_WINDOW: usize = 30;
const WS_MAX_BYTES_PER_WINDOW: usize = 32 * 1024 * 1024;
const WS_MAX_FRAME_BYTES: usize = 1024 * 1024;
// MLS state envelopes are bounded at 4 MiB before base64 transport encoding.
// Keep the legacy 1 MiB frame ceiling for protocol-v9 and non-MLS traffic.
const MLS_WS_MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
// Oversized inbound JSON must identify itself before deserialization.  Keep
// this prefix deliberately canonical: accepting arbitrary whitespace, property
// order, or substring matches would let legacy/unknown frames reach the larger
// serde allocation budget.  The full schema and field limits remain enforced
// after this bounded admission check.
const LARGE_MLS_INBOUND_PREFIXES: [&str; 5] = [
    r#"{"type":"mls_create_room","protocol_version":10,"#,
    r#"{"type":"mls_join_request","protocol_version":10,"#,
    r#"{"type":"mls_membership_commit","protocol_version":10,"#,
    r#"{"type":"mls_application","protocol_version":10,"#,
    r#"{"type":"mls_state_snapshot","protocol_version":10,"#,
];
const MLS_CLIENT_OUTBOUND_BYTES: usize = CONTROL_TRANSPORT_MAX_BUCKET;
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
const CLIENT_OUTBOUND_BYTES: usize = WS_MAX_FRAME_BYTES;
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
#[allow(dead_code)]
const MAX_ROOM_CATALOG_ENTRIES: usize = 1_024;
const MAX_DIRECT_CATALOG_ENTRIES: usize = 8_192;
const MAX_DIRECT_CATALOG_PER_USER: usize = 128;
const ACCOUNT_BODY_LIMIT_BYTES: usize = 16 * 1024;
const MAX_CHAT_ID_BYTES: usize = 128;
const MAX_USERNAME_BYTES: usize = 80;
const MAX_NODE_ID_BYTES: usize = 128;
// Directory stamps are deliberately bounded so a peer cannot force an
// unbounded revision/history allocation.  Once the ceiling is reached the
// revision saturates; a changed digest at that point is rejected by peers.
const MAX_DIRECTORY_REVISION: u64 = 65_536;
const DIRECTORY_DIGEST_BYTES: usize = 32;
const MAX_CODE_BYTES: usize = 128;
const LOGIN_RATE_WINDOW_MS: u64 = 60_000;
const LOGIN_MAX_ATTEMPTS_PER_WINDOW: usize = 6;
const MAX_LOGIN_LIMIT_ENTRIES: usize = 4_096;
const WEB_SOCKET_PROTOCOL: &str = "abyssal-v2";
const WS_TICKET_BYTES: usize = 32;
const WS_TICKET_B64_LEN: usize = 43;
const WS_TICKET_TTL_MS: u64 = 30_000;
const MAX_WS_TICKETS: usize = 1_024;
const DEFAULT_RELEASE_MANIFEST_REFRESH_SECONDS: usize = 15 * 60;
const MIN_RELEASE_MANIFEST_REFRESH_SECONDS: usize = 60;
const MAX_RELEASE_MANIFEST_REFRESH_SECONDS: usize = 6 * 60 * 60;
const OPAQUE_HANDSHAKE_TTL_MS: u64 = 60_000;
const MAX_OPAQUE_HANDSHAKES: usize = 1_024;
const IDENTITY_FINGERPRINT_BYTES: usize = 64;
const ONE_TIME_KEY_BYTES: usize = 32;
const ONE_TIME_KEY_OFFSET: usize = IDENTITY_FINGERPRINT_BYTES;
const FALLBACK_KEY_OFFSET: usize = ONE_TIME_KEY_OFFSET + (PREKEY_POOL_SIZE_V9 * ONE_TIME_KEY_BYTES);
const IDENTITY_PUBLIC_BYTES: usize = FALLBACK_KEY_OFFSET + 32;
const _: () = assert!(IDENTITY_PUBLIC_BYTES == IDENTITY_PUBLIC_BYTES_V9);
const MAX_IDENTITY_ENVELOPE_BYTES: usize = 512 * 1024;
const MESSAGE_NONCE_BYTES: usize = 12;
const MESSAGE_SIGNATURE_BYTES: usize = 64;
const MAX_WRAPPED_KEY_BYTES: usize = 4096;
const E2EE_PROTOCOL_VERSION: u32 = 9;
const MAX_STATE_REVISION_ADVANCE: u64 = 1_024;
const IDENTITY_ENVELOPE_VERSION: u8 = 5;
const REPLAY_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;
const MAX_REPLAY_IDS: usize = 50_000;
const MAX_REPLAY_IDS_PER_SENDER: usize = 2_048;
const PREKEY_LEASE_TTL_MS: u64 = 30_000;
const MAX_PREKEY_LEASES: usize = 4_096;
const MAX_PREKEY_LEASES_PER_RECIPIENT: usize = PREKEY_POOL_SIZE_V9;
const ATTACHMENT_CLAIM_TTL_MS: u64 = 10 * 60 * 1000;
// Uploads remain non-downloadable until the exact encrypted message is
// admitted. Keep this window short, and always clamp it to the final
// attachment retention deadline below.
const ATTACHMENT_STAGING_TTL_MS: u64 = 10 * 60 * 1000;
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
    release_admission: Arc<ReleaseAdmissionStore>,
    attachment_ram_limit_bytes: usize,
    attachment_account_limit_bytes: usize,
    attachment_record_limit: usize,
    attachment_account_record_limit: usize,
    attachment_max_lifetime_sec: u64,
    max_rooms_per_user: usize,
    interop_policy: InteropPolicy,
    conversation_ops: Arc<Mutex<()>>,
    presence_broadcast_ops: Arc<Mutex<()>>,
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
    transaction_receipts: Arc<Mutex<TransactionReceiptStore>>,
    prekey_leases: Arc<Mutex<HashMap<PrekeyLeaseKey, PrekeyLease>>>,
    mls_rooms: Arc<Mutex<rooms::RoomAuthority>>,
    rooms: Arc<Mutex<HashMap<String, HashSet<Uuid>>>>,
    room_catalog: Arc<Mutex<HashMap<String, RoomEntry>>>,
    direct_catalog: Arc<Mutex<HashMap<String, DirectEntry>>>,
    pending: Arc<Mutex<HashMap<PendingKey, Vec<PendingFrame>>>>,
    pending_bytes: Arc<Mutex<usize>>,
    // Attachment lifecycle code always locks bindings before attachments and
    // then per-owner usage. This keeps exact publication lookup bounded while
    // making cleanup atomic with record removal.
    attachment_bindings: Arc<Mutex<HashMap<AttachmentBindingKey, Uuid>>>,
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
    client_platform: Option<ClientPlatform>,
    attachment_uploads: Arc<Semaphore>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DirectoryStamp {
    node_id: String,
    revision: u64,
    digest: String,
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
    client_platform: ClientPlatform,
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
    platform: ClientPlatform,
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
    sender_platform: ClientPlatform,
}

impl PendingFrame {
    #[cfg(test)]
    fn new(frame: OutboundFrame, enqueued_at_ms: u64) -> Self {
        Self::new_for_platform(frame, enqueued_at_ms, ClientPlatform::Android)
    }

    fn new_for_platform(
        frame: OutboundFrame,
        enqueued_at_ms: u64,
        sender_platform: ClientPlatform,
    ) -> Self {
        Self {
            frame,
            enqueued_at_ms,
            sender_platform,
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
struct PrekeyLeaseKey {
    code_id: CodeId,
    prekey_id: String,
}

struct PrekeyLease {
    chat_id: String,
    message_id: String,
    sender_username: String,
    recipient_username: String,
    created_at_ms: u64,
}

impl Drop for PrekeyLeaseKey {
    fn drop(&mut self) {
        self.code_id.zeroize();
        self.prekey_id.zeroize();
    }
}

impl Drop for PrekeyLease {
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

#[derive(Clone, Eq, Hash, PartialEq)]
struct AttachmentBindingKey {
    owner_code_id: CodeId,
    chat_id: String,
    message_id: String,
}

impl AttachmentBindingKey {
    fn new(owner_code_id: &CodeId, chat_id: &str, message_id: &str) -> Self {
        Self {
            owner_code_id: *owner_code_id,
            chat_id: chat_id.to_string(),
            message_id: message_id.to_string(),
        }
    }

    fn matches_record(&self, record: &AttachmentRecord) -> bool {
        self.owner_code_id == record.owner_code_id
            && self.chat_id == record.chat_id
            && self.message_id == record.message_id
    }
}

impl Drop for AttachmentBindingKey {
    fn drop(&mut self) {
        self.owner_code_id.zeroize();
        self.chat_id.zeroize();
        self.message_id.zeroize();
    }
}

struct AttachmentRecord {
    blob: Arc<AttachmentBlob>,
    chat_id: String,
    message_id: String,
    media_type: String,
    owner_code_id: CodeId,
    sender_platform: ClientPlatform,
    published: bool,
    staged_expires_at_ms: Option<u64>,
    one_time: bool,
    delete_after_download: bool,
    expires_at_ms: Option<u64>,
    eligible_recipient_code_ids: HashSet<CodeId>,
    download_claims: HashMap<Uuid, AttachmentDownloadClaim>,
    completed_recipient_code_ids: HashSet<CodeId>,
}

struct StagedAttachmentRollback {
    attachment_id: Uuid,
    owner_code_id: CodeId,
    chat_id: String,
    message_id: String,
    eligible_recipient_code_ids: HashSet<CodeId>,
    published: bool,
    staged_expires_at_ms: Option<u64>,
}

impl Drop for StagedAttachmentRollback {
    fn drop(&mut self) {
        self.owner_code_id.zeroize();
        self.chat_id.zeroize();
        self.message_id.zeroize();
        for mut code_id in self.eligible_recipient_code_ids.drain() {
            code_id.zeroize();
        }
    }
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
        self.message_id.zeroize();
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

fn remove_attachment_binding_if_matches(
    bindings: &mut HashMap<AttachmentBindingKey, Uuid>,
    attachment_id: Uuid,
    record: &AttachmentRecord,
) {
    let key = AttachmentBindingKey::new(&record.owner_code_id, &record.chat_id, &record.message_id);
    if bindings.get(&key).copied() == Some(attachment_id) {
        bindings.remove(&key);
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
    MlsRoom(rooms::RoomPolicy),
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
    message_id: String,
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

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MlsRosterWire {
    username: String,
    stable_identity_b64: String,
}

impl Drop for MlsRosterWire {
    fn drop(&mut self) {
        self.username.zeroize();
        self.stable_identity_b64.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "type")]
enum InboundFrame {
    #[serde(rename = "activity")]
    Activity,
    #[serde(rename = "prekey_lease")]
    PrekeyLease {
        chat_id: String,
        message_id: String,
        recipient_username: String,
    },
    #[serde(rename = "prekey_lease_release")]
    PrekeyLeaseRelease {
        chat_id: String,
        message_id: String,
        recipient_username: String,
        prekey_id: String,
    },
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
        directory_node_id: String,
        directory_revision: u64,
        directory_digest: String,
        padding_bucket: usize,
        padding: String,
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
    #[serde(rename = "mls_create_room")]
    MlsCreateRoom {
        protocol_version: u32,
        room_id: String,
        group_id_b64: String,
        #[serde(with = "mls_wire::decimal_u64")]
        epoch: u64,
        #[serde(with = "mls_wire::decimal_u64")]
        revision: u64,
        membership_digest_b64: String,
        stable_identity_b64: String,
        state_envelope_b64: String,
        #[serde(default)]
        policy: rooms::RoomPolicy,
    },
    #[serde(rename = "mls_discover_room")]
    MlsDiscoverRoom {
        protocol_version: u32,
        room_id: String,
    },
    #[serde(rename = "mls_join_request")]
    MlsJoinRequest {
        protocol_version: u32,
        room_id: String,
        request_id: String,
        stable_identity_b64: String,
        key_package_b64: String,
        state_envelope_b64: String,
    },
    #[serde(rename = "mls_join_reject")]
    MlsJoinReject {
        protocol_version: u32,
        room_id: String,
        request_id: String,
    },
    #[serde(rename = "mls_leave_request")]
    MlsLeaveRequest {
        protocol_version: u32,
        room_id: String,
        request_id: String,
    },
    #[serde(rename = "mls_leave_reject")]
    MlsLeaveReject {
        protocol_version: u32,
        room_id: String,
        request_id: String,
    },
    #[serde(rename = "mls_membership_commit")]
    MlsMembershipCommit {
        protocol_version: u32,
        room_id: String,
        message_id: String,
        request_id: Option<String>,
        #[serde(with = "mls_wire::decimal_u64")]
        from_epoch: u64,
        #[serde(with = "mls_wire::decimal_u64")]
        to_epoch: u64,
        #[serde(with = "mls_wire::decimal_u64")]
        revision: u64,
        group_id_b64: String,
        from_membership_digest_b64: String,
        membership_digest_b64: String,
        roster: Vec<MlsRosterWire>,
        control_b64: String,
        welcome_b64: String,
        authenticated_data_b64: String,
        state_envelope_b64: String,
    },
    #[serde(rename = "mls_application")]
    MlsApplication {
        protocol_version: u32,
        room_id: String,
        message_id: String,
        group_id_b64: String,
        #[serde(with = "mls_wire::decimal_u64")]
        epoch: u64,
        #[serde(with = "mls_wire::decimal_u64")]
        revision: u64,
        membership_digest_b64: String,
        ciphertext_b64: String,
        authenticated_data_b64: String,
        state_envelope_b64: String,
    },
    #[serde(rename = "mls_state_snapshot")]
    MlsStateSnapshot {
        protocol_version: u32,
        room_id: String,
        message_id: String,
        #[serde(with = "mls_wire::decimal_u64")]
        epoch: u64,
        #[serde(with = "mls_wire::decimal_u64")]
        revision: u64,
        membership_digest_b64: String,
        state_envelope_b64: String,
    },
    #[serde(rename = "mls_delete_room")]
    MlsDeleteRoom {
        protocol_version: u32,
        room_id: String,
    },
    #[serde(rename = "dummy")]
    Dummy {
        padding_b64: Option<String>,
        bytes: Option<usize>,
    },
}

#[derive(Deserialize, Serialize)]
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

#[allow(dead_code)]
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
        directory_node_id: String,
        directory_revision: u64,
        directory_digest: String,
        padding_bucket: usize,
        padding: String,
    },
    #[serde(rename = "prekey_lease")]
    PrekeyLease {
        chat_id: String,
        message_id: String,
        recipient_username: String,
        recipient_public_key_b64: String,
        prekey_id: String,
        expires_at_ms: u64,
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
    #[serde(rename = "mls_rooms")]
    MlsRooms {
        protocol_version: u32,
        rooms: Vec<MlsRoomWire>,
    },
    #[serde(rename = "mls_room_discovered")]
    MlsRoomDiscovered {
        protocol_version: u32,
        room_id: String,
        group_id_b64: String,
        owner_username: String,
    },
    #[serde(rename = "mls_room_created")]
    MlsRoomCreated {
        protocol_version: u32,
        room: MlsRoomWire,
    },
    #[serde(rename = "mls_join_requested")]
    MlsJoinRequested {
        protocol_version: u32,
        room_id: String,
        request_id: String,
        username: String,
        stable_identity_b64: String,
        key_package_b64: String,
    },
    #[serde(rename = "mls_join_rejected")]
    MlsJoinRejected {
        protocol_version: u32,
        room_id: String,
        request_id: String,
    },
    #[serde(rename = "mls_leave_requested")]
    MlsLeaveRequested {
        protocol_version: u32,
        room_id: String,
        request_id: String,
        username: String,
        stable_identity_b64: String,
    },
    #[serde(rename = "mls_leave_pending")]
    MlsLeavePending {
        protocol_version: u32,
        room_id: String,
        request_id: String,
    },
    #[serde(rename = "mls_leave_rejected")]
    MlsLeaveRejected {
        protocol_version: u32,
        room_id: String,
        request_id: String,
    },
    #[serde(rename = "mls_left")]
    MlsLeft {
        protocol_version: u32,
        room_id: String,
    },
    #[serde(rename = "mls_membership")]
    MlsMembership {
        protocol_version: u32,
        room_id: String,
        message_id: String,
        #[serde(with = "mls_wire::decimal_u64")]
        from_epoch: u64,
        #[serde(with = "mls_wire::decimal_u64")]
        to_epoch: u64,
        #[serde(with = "mls_wire::decimal_u64")]
        revision: u64,
        from_membership_digest_b64: String,
        group_id_b64: String,
        membership_digest_b64: String,
        roster: Vec<MlsRosterWire>,
        control_b64: String,
        welcome_b64: String,
        authenticated_data_b64: String,
    },
    #[serde(rename = "mls_application")]
    MlsApplication {
        protocol_version: u32,
        room_id: String,
        message_id: String,
        sender_username: String,
        #[serde(with = "mls_wire::decimal_u64")]
        epoch: u64,
        #[serde(with = "mls_wire::decimal_u64")]
        revision: u64,
        membership_digest_b64: String,
        ciphertext_b64: String,
        authenticated_data_b64: String,
    },
    #[serde(rename = "mls_room_result")]
    MlsRoomResult {
        protocol_version: u32,
        room_id: String,
        message_id: String,
        #[serde(with = "mls_wire::decimal_u64")]
        revision: u64,
        accepted: bool,
    },
    #[serde(rename = "mls_room_deleted")]
    MlsRoomDeleted {
        protocol_version: u32,
        room_id: String,
    },
    #[serde(rename = "mls_snapshot_result")]
    MlsSnapshotResult {
        protocol_version: u32,
        room_id: String,
        message_id: String,
        #[serde(with = "mls_wire::decimal_u64")]
        revision: u64,
        accepted: bool,
    },
    #[serde(rename = "message_result")]
    MessageResult { message_id: String, accepted: bool },
    #[serde(rename = "ack_result")]
    AckResult { message_id: String, accepted: bool },
}

#[cfg(test)]
#[derive(Serialize)]
struct InboundMessageWire<'a> {
    #[serde(rename = "type")]
    frame_type: &'static str,
    chat_id: &'a str,
    version: u32,
    message_id: &'a str,
    nonce_b64: &'a str,
    ciphertext_b64: &'a str,
    envelopes: &'a [InboundRecipientEnvelope],
    state_revision: u64,
    identity_envelope_b64: &'a str,
    identity_public_b64: &'a str,
    prekey_id: &'a str,
    state_signature_b64: &'a str,
    directory_node_id: &'a str,
    directory_revision: u64,
    directory_digest: &'a str,
    padding_bucket: usize,
    padding: &'a str,
}

impl OutboundFrame {
    fn is_mls(&self) -> bool {
        matches!(
            self,
            Self::MlsRooms { .. }
                | Self::MlsRoomDiscovered { .. }
                | Self::MlsRoomCreated { .. }
                | Self::MlsJoinRequested { .. }
                | Self::MlsJoinRejected { .. }
                | Self::MlsLeaveRequested { .. }
                | Self::MlsLeavePending { .. }
                | Self::MlsLeaveRejected { .. }
                | Self::MlsLeft { .. }
                | Self::MlsMembership { .. }
                | Self::MlsApplication { .. }
                | Self::MlsRoomResult { .. }
                | Self::MlsRoomDeleted { .. }
                | Self::MlsSnapshotResult { .. }
        )
    }

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
            directory_node_id,
            directory_digest,
            padding,
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
            directory_node_id.zeroize();
            directory_digest.zeroize();
            padding.zeroize();
        }
        if let Self::PrekeyLease {
            chat_id,
            message_id,
            recipient_username,
            recipient_public_key_b64,
            prekey_id,
            ..
        } = self
        {
            chat_id.zeroize();
            message_id.zeroize();
            recipient_username.zeroize();
            recipient_public_key_b64.zeroize();
            prekey_id.zeroize();
        }
        if let Self::MessageResult { message_id, .. } | Self::AckResult { message_id, .. } = self {
            message_id.zeroize();
        }
        match self {
            Self::MlsApplication {
                room_id,
                message_id,
                sender_username,
                membership_digest_b64,
                ciphertext_b64,
                authenticated_data_b64,
                ..
            } => {
                room_id.zeroize();
                message_id.zeroize();
                sender_username.zeroize();
                membership_digest_b64.zeroize();
                ciphertext_b64.zeroize();
                authenticated_data_b64.zeroize();
            }
            Self::MlsMembership {
                room_id,
                message_id,
                group_id_b64,
                from_membership_digest_b64,
                membership_digest_b64,
                control_b64,
                welcome_b64,
                authenticated_data_b64,
                roster,
                ..
            } => {
                room_id.zeroize();
                message_id.zeroize();
                group_id_b64.zeroize();
                from_membership_digest_b64.zeroize();
                membership_digest_b64.zeroize();
                control_b64.zeroize();
                welcome_b64.zeroize();
                authenticated_data_b64.zeroize();
                for member in roster {
                    member.username.zeroize();
                    member.stable_identity_b64.zeroize();
                }
            }
            Self::MlsJoinRequested {
                room_id,
                request_id,
                username,
                stable_identity_b64,
                key_package_b64,
                ..
            } => {
                room_id.zeroize();
                request_id.zeroize();
                username.zeroize();
                stable_identity_b64.zeroize();
                key_package_b64.zeroize();
            }
            Self::MlsJoinRejected {
                room_id,
                request_id,
                ..
            } => {
                room_id.zeroize();
                request_id.zeroize();
            }
            Self::MlsLeaveRequested {
                room_id,
                request_id,
                username,
                stable_identity_b64,
                ..
            } => {
                room_id.zeroize();
                request_id.zeroize();
                username.zeroize();
                stable_identity_b64.zeroize();
            }
            Self::MlsLeavePending {
                room_id,
                request_id,
                ..
            }
            | Self::MlsLeaveRejected {
                room_id,
                request_id,
                ..
            } => {
                room_id.zeroize();
                request_id.zeroize();
            }
            Self::MlsLeft { room_id, .. } => room_id.zeroize(),
            Self::MlsRoomResult {
                room_id,
                message_id,
                ..
            } => {
                room_id.zeroize();
                message_id.zeroize();
            }
            Self::MlsRoomDeleted { room_id, .. } => room_id.zeroize(),
            Self::MlsSnapshotResult {
                room_id,
                message_id,
                ..
            } => {
                room_id.zeroize();
                message_id.zeroize();
            }
            Self::MlsRoomCreated { room, .. } => {
                room.room_id.zeroize();
                room.owner_username.zeroize();
                room.group_id_b64.zeroize();
                room.membership_digest_b64.zeroize();
                if let Some(snapshot) = &mut room.recovery_snapshot {
                    snapshot.membership_digest_b64.zeroize();
                    snapshot.state_envelope_b64.zeroize();
                }
                for member in &mut room.roster {
                    member.username.zeroize();
                    member.stable_identity_b64.zeroize();
                }
            }
            Self::MlsRoomDiscovered {
                room_id,
                group_id_b64,
                owner_username,
                ..
            } => {
                room_id.zeroize();
                group_id_b64.zeroize();
                owner_username.zeroize();
            }
            Self::MlsRooms { rooms, .. } => {
                for room in rooms {
                    room.room_id.zeroize();
                    room.owner_username.zeroize();
                    room.group_id_b64.zeroize();
                    room.membership_digest_b64.zeroize();
                    if let Some(snapshot) = &mut room.recovery_snapshot {
                        snapshot.membership_digest_b64.zeroize();
                        snapshot.state_envelope_b64.zeroize();
                    }
                    for member in &mut room.roster {
                        member.username.zeroize();
                        member.stable_identity_b64.zeroize();
                    }
                }
            }
            _ => {}
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
    directory_node_id: String,
    directory_revision: u64,
}

#[derive(Clone, Serialize)]
struct DirectRecord {
    id: String,
    peer_username: String,
}

#[derive(Clone, Serialize)]
struct MlsRoomWire {
    room_id: String,
    owner_username: String,
    group_id_b64: String,
    active: bool,
    synchronized: bool,
    #[serde(with = "mls_wire::decimal_u64")]
    epoch: u64,
    #[serde(with = "mls_wire::decimal_u64")]
    revision: u64,
    membership_digest_b64: String,
    roster: Vec<MlsRosterWire>,
    recovery_snapshot: Option<MlsRecoverySnapshotWire>,
    policy: rooms::RoomPolicy,
}

impl Drop for MlsRoomWire {
    fn drop(&mut self) {
        self.room_id.zeroize();
        self.owner_username.zeroize();
        self.group_id_b64.zeroize();
        self.membership_digest_b64.zeroize();
        self.recovery_snapshot = None;
        self.roster.clear();
    }
}

#[derive(Clone, Serialize)]
struct MlsRecoverySnapshotWire {
    active: bool,
    #[serde(with = "mls_wire::decimal_u64")]
    epoch: u64,
    #[serde(with = "mls_wire::decimal_u64")]
    revision: u64,
    membership_digest_b64: String,
    state_envelope_b64: String,
    roster: Vec<MlsRosterWire>,
}

impl Drop for MlsRecoverySnapshotWire {
    fn drop(&mut self) {
        self.membership_digest_b64.zeroize();
        self.state_envelope_b64.zeroize();
        self.roster.clear();
    }
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

async fn refresh_release_manifest(store: &ReleaseAdmissionStore, mirror: &ReleaseManifestMirror) {
    match mirror.refresh(store, now_ms()).await {
        Ok(InstallOutcome::Installed) => info!("release_manifest_refresh result=installed"),
        Ok(InstallOutcome::Unchanged) => debug!("release_manifest_refresh result=unchanged"),
        Err(error) => warn!("release_manifest_refresh result=rejected reason={error}"),
    }
}

async fn release_manifest_watcher(
    store: Arc<ReleaseAdmissionStore>,
    mirror: ReleaseManifestMirror,
    interval: Duration,
) {
    loop {
        tokio::time::sleep(interval).await;
        refresh_release_manifest(&store, &mirror).await;
    }
}

#[tokio::main]
async fn main() {
    let configured_bind_addr = configured_bind_addr();
    #[cfg(feature = "integration-release-root")]
    assert!(
        configured_bind_addr.ip().is_loopback()
            && env::var("ABYSSAL_INTEGRATION_TEST").as_deref() == Ok("1"),
        "integration release root requires explicit loopback test mode"
    );
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
    #[cfg(feature = "integration-release-root")]
    let integration_manifest_installed = release_admission::install_integration_manifest_from_env(
        &state.release_admission,
        now_ms(),
    )
    .await
    .expect("integration release manifest must verify");
    #[cfg(not(feature = "integration-release-root"))]
    let integration_manifest_installed = false;

    if !integration_manifest_installed {
        if let Ok(mirror) = ReleaseManifestMirror::new() {
            refresh_release_manifest(&state.release_admission, &mirror).await;
            let refresh_seconds = read_usize_env(
                "ABYSSAL_RELEASE_MANIFEST_REFRESH_SECONDS",
                DEFAULT_RELEASE_MANIFEST_REFRESH_SECONDS,
            )
            .clamp(
                MIN_RELEASE_MANIFEST_REFRESH_SECONDS,
                MAX_RELEASE_MANIFEST_REFRESH_SECONDS,
            );
            tokio::spawn(release_manifest_watcher(
                state.release_admission.clone(),
                mirror,
                Duration::from_secs(refresh_seconds as u64),
            ));
        } else {
            warn!("release_admission_unavailable reason=client_configuration");
        }
    }
    tokio::spawn(attachment_sweeper(state.clone()));
    tokio::spawn(session_sweeper(state.clone()));
    tokio::spawn(mls_sweeper(state.clone()));
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
        let node_id = match env::var("ABYSSAL_NODE_ID").or_else(|_| env::var("MIRAGE_NODE_ID")) {
            Ok(value) if valid_node_id(&value) => value,
            Ok(_) => panic!("ABYSSAL_NODE_ID must be 1-128 ASCII identifier characters"),
            Err(_) => format!("abyssal-{}", Uuid::new_v4().simple()),
        };

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
        let interop_policy = InteropPolicy::from_env();
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
            release_admission: Arc::new(ReleaseAdmissionStore::new()),
            attachment_ram_limit_bytes,
            attachment_account_limit_bytes,
            attachment_record_limit,
            attachment_account_record_limit,
            attachment_max_lifetime_sec,
            max_rooms_per_user,
            interop_policy,
            conversation_ops: Arc::new(Mutex::new(())),
            presence_broadcast_ops: Arc::new(Mutex::new(())),
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
            transaction_receipts: Arc::new(Mutex::new(TransactionReceiptStore::new(
                pending_message_ttl_ms,
            ))),
            prekey_leases: Arc::new(Mutex::new(HashMap::new())),
            mls_rooms: Arc::new(Mutex::new(rooms::RoomAuthority::new_with_pending_ttl(
                max_rooms_per_user,
                pending_message_ttl_ms,
            ))),
            rooms: Arc::new(Mutex::new(HashMap::new())),
            room_catalog: Arc::new(Mutex::new(HashMap::new())),
            direct_catalog: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
            pending_bytes: Arc::new(Mutex::new(0)),
            attachment_bindings: Arc::new(Mutex::new(HashMap::new())),
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
            "ABYSSAL_INTEROP_POLICY android_to_web={} web_to_android={}",
            self.interop_policy.allow_android_to_web(),
            self.interop_policy.allow_web_to_android()
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
            .all(|account| !account.username.eq_ignore_ascii_case(&candidate))
        {
            return candidate;
        }
    }

    loop {
        let candidate = format!("Abyssal{}", Uuid::new_v4().simple());
        if accounts
            .values()
            .all(|account| !account.username.eq_ignore_ascii_case(&candidate))
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
    let _conversation_guard = state.conversation_ops.lock().await;
    prune_expired_attachments_locked(state).await;
}

async fn prune_expired_attachments_locked(state: &AppState) {
    let now = now_ms();
    let mut bindings = state.attachment_bindings.lock().await;
    let mut attachments = state.attachments.lock().await;
    let mut usage = state.attachment_bytes_by_code.lock().await;
    let before = attachments.len();
    attachments.retain(|attachment_id, record| {
        record
            .download_claims
            .retain(|_, claim| now.saturating_sub(claim.created_at_ms) < ATTACHMENT_CLAIM_TTL_MS);
        let live = if record.published {
            record.expires_at_ms.is_none_or(|expires| now < expires)
        } else {
            // A staged record without an explicit bounded deadline is
            // malformed and must not survive or become publishable.
            record
                .staged_expires_at_ms
                .is_some_and(|expires| now < expires)
        };
        if live || (record.published && !record.download_claims.is_empty()) {
            true
        } else {
            remove_attachment_binding_if_matches(&mut bindings, *attachment_id, record);
            subtract_attachment_usage(&mut usage, &record.owner_code_id, record.blob.bytes.len());
            false
        }
    });
    let stale_bindings = bindings
        .iter()
        .filter_map(|(key, attachment_id)| {
            attachments
                .get(attachment_id)
                .filter(|record| !key.matches_record(record))
                .map(|_| (key.clone(), *attachment_id))
        })
        .collect::<Vec<_>>();
    for (key, attachment_id) in stale_bindings {
        bindings.remove(&key);
        if !bindings
            .values()
            .any(|candidate_id| *candidate_id == attachment_id)
        {
            if let Some(record) = attachments.remove(&attachment_id) {
                subtract_attachment_usage(
                    &mut usage,
                    &record.owner_code_id,
                    record.blob.bytes.len(),
                );
            }
        }
    }
    bindings.retain(|key, attachment_id| {
        attachments
            .get(attachment_id)
            .is_some_and(|record| key.matches_record(record))
    });
    let removed = before.saturating_sub(attachments.len());
    if removed > 0 {
        info!("expired_attachments_removed count={removed}");
    }
}

async fn remove_chat_attachments(state: &AppState, chat_id: &str) {
    let mut bindings = state.attachment_bindings.lock().await;
    let mut attachments = state.attachments.lock().await;
    let mut usage = state.attachment_bytes_by_code.lock().await;
    attachments.retain(|attachment_id, record| {
        if record.chat_id != chat_id {
            true
        } else {
            remove_attachment_binding_if_matches(&mut bindings, *attachment_id, record);
            subtract_attachment_usage(&mut usage, &record.owner_code_id, record.blob.bytes.len());
            false
        }
    });
}

async fn revoke_mls_attachment_access(state: &AppState, room_id: &str, removed_code_id: &CodeId) {
    let mut attachments = state.attachments.lock().await;
    for record in attachments
        .values_mut()
        .filter(|record| record.chat_id == room_id)
    {
        if let Some(mut code_id) = record.eligible_recipient_code_ids.take(removed_code_id) {
            code_id.zeroize();
        }
        if let Some(mut code_id) = record.completed_recipient_code_ids.take(removed_code_id) {
            code_id.zeroize();
        }
        record
            .download_claims
            .retain(|_, claim| claim.recipient_code_id != *removed_code_id);
    }
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

async fn mls_sweeper(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        state.mls_rooms.lock().await.prune_at(now_ms());
    }
}

async fn prune_pending_queues(state: &AppState, now: u64) {
    let mut pending = state.pending.lock().await;
    let mut pending_bytes = state.pending_bytes.lock().await;
    let mut claims = state.prekey_leases.lock().await;
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
    claims: &mut HashMap<PrekeyLeaseKey, PrekeyLease>,
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
                if let Some(details) = prekey_lease_details(&pending_frame.frame) {
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
        release_prekey_lease_details_locked(claims, &mut details);
    }
    prune_prekey_leases(claims, pending, now);
    removed
}

fn release_prekey_lease_details_locked(
    claims: &mut HashMap<PrekeyLeaseKey, PrekeyLease>,
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

fn pending_contains_leased_frame(
    pending: &HashMap<PendingKey, Vec<PendingFrame>>,
    key: &PrekeyLeaseKey,
    claim: &PrekeyLease,
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

fn prune_prekey_leases(
    claims: &mut HashMap<PrekeyLeaseKey, PrekeyLease>,
    pending: &HashMap<PendingKey, Vec<PendingFrame>>,
    now: u64,
) {
    claims.retain(|key, claim| {
        now.saturating_sub(claim.created_at_ms) < PREKEY_LEASE_TTL_MS
            || pending_contains_leased_frame(pending, key, claim)
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
    attachment_encrypted_size(media_type.to_string(), plain_limit as u64)
        .ok()
        .and_then(|bytes| usize::try_from(bytes).ok())
        .unwrap_or(0)
}

fn encrypted_attachment_limit_bytes(media_type: &str) -> usize {
    max_serialized_attachment_bytes(media_type)
}

fn valid_encrypted_attachment_body(media_type: &str, body: &[u8]) -> bool {
    attachment_plaintext_size_from_blob(media_type, body).is_ok()
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
    if matches!(&access, ConversationAccess::MlsRoom(policy) if !policy_allows_media(policy, media_type))
        || matches!(&access, ConversationAccess::Room(room) if !room_allows_media(room, media_type))
    {
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
    let code_id = state
        .accounts
        .lock()
        .await
        .iter()
        .find_map(|(code_id, account)| (account.username == username).then_some(*code_id));
    if let Some(code_id) = code_id {
        let mut mls_rooms = state.mls_rooms.lock().await;
        if mls_rooms.is_member(chat_id, &code_id) {
            if !mls_rooms.is_active_member(chat_id, &code_id) {
                return None;
            }
            if let Ok(info) = mls_rooms.member_info(chat_id, &code_id) {
                return Some(ConversationAccess::MlsRoom(info.policy));
            }
        }
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
    if let ConversationAccess::MlsRoom(_) = access {
        return state
            .mls_rooms
            .lock()
            .await
            .active_member_code_ids(chat_id)
            .unwrap_or_default()
            .into_iter()
            .filter(|code_id| code_id != owner_code_id)
            .collect();
    }
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
                    (ConversationAccess::MlsRoom(_), _) => false,
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

fn policy_allows_media(policy: &rooms::RoomPolicy, media_type: &str) -> bool {
    match media_type {
        "IMAGE" => policy.allow_images,
        "VIDEO" => policy.allow_videos,
        _ => policy.allow_files,
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

fn enforced_attachment_ttl_sec_policy(policy: &rooms::RoomPolicy, media_type: &str) -> u64 {
    let room_ttl = policy
        .enforce_text_absolute_expiry
        .then_some(policy.overall_expiry_sec)
        .filter(|ttl| *ttl > 0);
    let media_ttl = match media_type {
        "IMAGE" if policy.enforce_image_absolute_expiry => policy.image_overall_expiry_sec,
        "VIDEO" if policy.enforce_video_absolute_expiry => policy.video_overall_expiry_sec,
        "FILE" if policy.enforce_file_absolute_expiry => policy.file_overall_expiry_sec,
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
    let effective = match access {
        ConversationAccess::MlsRoom(policy) => {
            let enforced = enforced_attachment_ttl_sec_policy(policy, media_type);
            match (requested, enforced) {
                (0, enforced) => enforced,
                (requested, 0) => requested,
                (requested, enforced) => requested.min(enforced),
            }
        }
        ConversationAccess::Room(room) => {
            let enforced = enforced_attachment_ttl_sec(room, media_type);
            match (requested, enforced) {
                (0, enforced) => enforced,
                (requested, 0) => requested,
                (requested, enforced) => requested.min(enforced),
            }
        }
        ConversationAccess::Direct => requested,
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

async fn staged_attachment_for_message(
    state: &AppState,
    owner_code_id: &CodeId,
    chat_id: &str,
    message_id: &str,
) -> Result<Option<Uuid>, String> {
    let key = AttachmentBindingKey::new(owner_code_id, chat_id, message_id);
    let mut bindings = state.attachment_bindings.lock().await;
    let Some(attachment_id) = bindings.get(&key).copied() else {
        return Ok(None);
    };
    let mut attachments = state.attachments.lock().await;
    let now = now_ms();
    if let Some(record) = attachments.get_mut(&attachment_id) {
        if key.matches_record(record) {
            record.download_claims.retain(|_, claim| {
                now.saturating_sub(claim.created_at_ms) < ATTACHMENT_CLAIM_TTL_MS
            });
        }
    }
    let action = match attachments.get(&attachment_id) {
        None => 0_u8,
        Some(record) if !key.matches_record(record) => 1,
        Some(record) if record.published => {
            if record.expires_at_ms.is_some_and(|expires| now >= expires)
                && record.download_claims.is_empty()
            {
                2
            } else {
                3
            }
        }
        Some(record)
            if record
                .staged_expires_at_ms
                .is_none_or(|expires| now >= expires)
                || record.expires_at_ms.is_some_and(|expires| now >= expires) =>
        {
            2
        }
        Some(_) => 4,
    };
    match action {
        0 => {
            bindings.remove(&key);
            Ok(None)
        }
        1 => {
            let orphaned_record = !bindings.iter().any(|(candidate_key, candidate_id)| {
                candidate_key != &key && *candidate_id == attachment_id
            });
            bindings.remove(&key);
            if orphaned_record {
                if let Some(record) = attachments.remove(&attachment_id) {
                    let mut usage = state.attachment_bytes_by_code.lock().await;
                    subtract_attachment_usage(
                        &mut usage,
                        &record.owner_code_id,
                        record.blob.bytes.len(),
                    );
                }
            }
            Ok(None)
        }
        2 => {
            if let Some(record) = attachments.remove(&attachment_id) {
                let mut usage = state.attachment_bytes_by_code.lock().await;
                remove_attachment_binding_if_matches(&mut bindings, attachment_id, &record);
                subtract_attachment_usage(
                    &mut usage,
                    &record.owner_code_id,
                    record.blob.bytes.len(),
                );
            } else {
                bindings.remove(&key);
            }
            Ok(None)
        }
        3 => Err("duplicate attachment message binding".to_string()),
        _ => Ok(Some(attachment_id)),
    }
}

async fn publish_staged_attachment_checked(
    state: &AppState,
    attachment_id: Uuid,
    owner_code_id: &CodeId,
    chat_id: &str,
    message_id: &str,
) -> Result<(), String> {
    let key = AttachmentBindingKey::new(owner_code_id, chat_id, message_id);
    let mut bindings = state.attachment_bindings.lock().await;
    let Some(indexed_id) = bindings.get(&key).copied() else {
        return Err("staged attachment unavailable".to_string());
    };
    if indexed_id != attachment_id {
        bindings.remove(&key);
        return Err("staged attachment binding mismatch".to_string());
    }
    let mut attachments = state.attachments.lock().await;
    let now = now_ms();
    let action = match attachments.get(&attachment_id) {
        Some(record) if key.matches_record(record) && record.published => 0_u8,
        Some(record)
            if key.matches_record(record)
                && record
                    .staged_expires_at_ms
                    .is_some_and(|expires| now < expires)
                && record.expires_at_ms.is_none_or(|expires| now < expires) =>
        {
            1
        }
        Some(record) if key.matches_record(record) => 2,
        _ => 3,
    };
    match action {
        0 => Ok(()),
        1 => {
            if let Some(record) = attachments.get_mut(&attachment_id) {
                record.published = true;
                record.staged_expires_at_ms = None;
            }
            Ok(())
        }
        2 => {
            if let Some(record) = attachments.remove(&attachment_id) {
                let mut usage = state.attachment_bytes_by_code.lock().await;
                remove_attachment_binding_if_matches(&mut bindings, attachment_id, &record);
                subtract_attachment_usage(
                    &mut usage,
                    &record.owner_code_id,
                    record.blob.bytes.len(),
                );
            }
            Err("staged attachment expired".to_string())
        }
        _ => {
            let orphaned_record = attachments.get(&attachment_id).is_some_and(|record| {
                !key.matches_record(record)
                    && !bindings.iter().any(|(candidate_key, candidate_id)| {
                        candidate_key != &key && *candidate_id == attachment_id
                    })
            });
            bindings.remove(&key);
            if orphaned_record {
                if let Some(record) = attachments.remove(&attachment_id) {
                    let mut usage = state.attachment_bytes_by_code.lock().await;
                    subtract_attachment_usage(
                        &mut usage,
                        &record.owner_code_id,
                        record.blob.bytes.len(),
                    );
                }
            }
            Err("staged attachment unavailable".to_string())
        }
    }
}

async fn publish_staged_attachment(
    state: &AppState,
    attachment_id: Uuid,
    owner_code_id: &CodeId,
    chat_id: &str,
    message_id: &str,
) {
    let _ =
        publish_staged_attachment_checked(state, attachment_id, owner_code_id, chat_id, message_id)
            .await;
}

async fn rebind_staged_attachment_recipients(
    state: &AppState,
    attachment_id: Uuid,
    recipients: &HashSet<CodeId>,
) -> Result<StagedAttachmentRollback, String> {
    let mut attachments = state.attachments.lock().await;
    let record = attachments
        .get_mut(&attachment_id)
        .ok_or_else(|| "staged attachment unavailable".to_string())?;
    if record.published {
        return Err("staged attachment already published".to_string());
    }
    if (record.one_time || record.delete_after_download) && recipients.is_empty() {
        return Err("attachment recipient roster rejected".to_string());
    }
    let rollback = StagedAttachmentRollback {
        attachment_id,
        owner_code_id: record.owner_code_id,
        chat_id: record.chat_id.clone(),
        message_id: record.message_id.clone(),
        eligible_recipient_code_ids: record.eligible_recipient_code_ids.clone(),
        published: record.published,
        staged_expires_at_ms: record.staged_expires_at_ms,
    };
    if record.one_time || record.delete_after_download {
        record.eligible_recipient_code_ids = recipients.clone();
    }
    Ok(rollback)
}

async fn rollback_staged_attachment(state: &AppState, mut rollback: StagedAttachmentRollback) {
    let attachment_id = rollback.attachment_id;
    let key = AttachmentBindingKey::new(
        &rollback.owner_code_id,
        &rollback.chat_id,
        &rollback.message_id,
    );
    let mut bindings = state.attachment_bindings.lock().await;
    let mut attachments = state.attachments.lock().await;
    let restored = if let Some(record) = attachments.get_mut(&rollback.attachment_id) {
        if key.matches_record(record) {
            record.eligible_recipient_code_ids =
                std::mem::take(&mut rollback.eligible_recipient_code_ids);
            record.published = rollback.published;
            record.staged_expires_at_ms = rollback.staged_expires_at_ms;
            true
        } else {
            false
        }
    } else {
        false
    };
    if restored {
        bindings.insert(key, attachment_id);
    }
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
    prune_expired_attachments_locked(state).await;
    let requester_platform = state
        .accounts
        .lock()
        .await
        .get(requester_code_id)
        .and_then(|account| account.client_platform);
    let mut bindings = state.attachment_bindings.lock().await;
    let mut attachments = state.attachments.lock().await;
    let mut usage = state.attachment_bytes_by_code.lock().await;
    let Some(record) = attachments.get_mut(&attachment_id) else {
        return Err(StatusCode::NOT_FOUND);
    };
    // Staged ciphertext is deliberately indistinguishable from a missing
    // attachment to download callers.
    if !record.published {
        return Err(StatusCode::NOT_FOUND);
    }
    if record
        .expires_at_ms
        .is_some_and(|expires| now_ms() >= expires)
    {
        if !record.download_claims.is_empty() {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        let owner_code_id = record.owner_code_id;
        let encrypted_len = record.blob.bytes.len();
        let Some(record) = attachments.remove(&attachment_id) else {
            return Err(StatusCode::NOT_FOUND);
        };
        remove_attachment_binding_if_matches(&mut bindings, attachment_id, &record);
        subtract_attachment_usage(&mut usage, &owner_code_id, encrypted_len);
        return Err(StatusCode::NOT_FOUND);
    }

    let owner = *requester_code_id == record.owner_code_id;
    if !owner {
        let Some(requester_platform) = requester_platform else {
            return Err(StatusCode::FORBIDDEN);
        };
        if !record
            .eligible_recipient_code_ids
            .contains(requester_code_id)
            || !state
                .interop_policy
                .allows(record.sender_platform, requester_platform)
        {
            return Err(StatusCode::FORBIDDEN);
        }
    }
    let destructive = record.one_time || record.delete_after_download;
    let claim_id = if !destructive || owner {
        None
    } else {
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
    let mut bindings = state.attachment_bindings.lock().await;
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
        remove_attachment_binding_if_matches(&mut bindings, attachment_id, &record);
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
    let mut challenge = Zeroizing::new(vec![0_u8; REGISTRATION_CHALLENGE_BYTES_V9]);
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
            if verify_registration_identity_proof_v9(
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
            let username = {
                // Keep the account-map revision and message admission in the
                // same transaction domain. The outer account guard is already
                // held, preserving account_ops -> conversation_ops lock order.
                let _conversation_guard = state.conversation_ops.lock().await;
                if let Some(mut removed_code_id) = state.available_codes.lock().await.take(code_id)
                {
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
                        client_platform: None,
                        attachment_uploads: Arc::new(Semaphore::new(
                            MAX_ATTACHMENT_UPLOADS_PER_ACCOUNT,
                        )),
                    },
                );
                username
            };
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

fn decode_bounded_allow_empty(value: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    decode_bounded(value, max_bytes)
}

fn valid_mls_correlator(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= rooms::MAX_ROOM_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn require_mls_protocol_version(version: u32) -> Result<(), String> {
    (version == rooms::MLS_PROTOCOL_VERSION)
        .then_some(())
        .ok_or_else(|| "Wrong information".to_string())
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

fn valid_username(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_USERNAME_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn valid_node_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NODE_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_identity_public_bundle(public_key: &[u8], prekey_id: &str) -> bool {
    validate_core_identity_public_bundle(public_key, Some(prekey_id)).is_ok()
        && prekey_ids_from_identity_public_v9(public_key)
            .is_ok_and(|pool| pool.first().is_some_and(|first| first == prekey_id))
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

async fn issue_ws_ticket(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(build_attestation): Json<BuildAttestationRequest>,
) -> Response {
    if state
        .release_admission
        .admit(&build_attestation, now_ms())
        .await
        .is_err()
    {
        return StatusCode::UPGRADE_REQUIRED.into_response();
    }
    let Some(client_platform) = ClientPlatform::parse(&build_attestation.platform) else {
        return StatusCode::UPGRADE_REQUIRED.into_response();
    };
    let Some(session_token) = bearer_token(&headers).map(Zeroizing::new) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let _account_guard = state.account_ops.lock().await;
    let Some(auth_session) = active_session(&state, session_token.as_str(), false).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let accounts = state.accounts.lock().await;
    let Some(account) = accounts.get(&auth_session.code_id) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if account
        .client_platform
        .is_some_and(|bound_platform| bound_platform != client_platform)
    {
        return StatusCode::UPGRADE_REQUIRED.into_response();
    }
    drop(accounts);

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
    // account_ops serializes ticket issuance and session replacement. Bind the
    // session only after all ticket-capacity checks pass so a rejected request
    // cannot relabel the account or pin a platform without a usable ticket.
    drop(tickets);
    let mut accounts = state.accounts.lock().await;
    let Some(account) = accounts.get_mut(&auth_session.code_id) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if account
        .client_platform
        .is_some_and(|bound_platform| bound_platform != client_platform)
    {
        return StatusCode::UPGRADE_REQUIRED.into_response();
    }
    account.client_platform = Some(client_platform);
    drop(accounts);

    state.ws_tickets.lock().await.insert(
        digest,
        WsTicket {
            session_token,
            expires_at_ms: now.saturating_add(WS_TICKET_TTL_MS),
            client_platform,
        },
    );
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
) -> Option<(Zeroizing<String>, AuthSession, ClientPlatform)> {
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
    let client_platform = ticket.client_platform;
    drop(ticket);
    let session = active_session(state, session_token.as_str(), true).await?;
    touch_activity(state).await;
    Some((session_token, session, client_platform))
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
    let message_id = query.message_id.trim().to_string();
    if !valid_chat_id(&message_id) {
        return StatusCode::BAD_REQUEST.into_response();
    }
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
    let sender_platform = match state
        .accounts
        .lock()
        .await
        .get(&auth.code_id)
        .and_then(|account| account.client_platform)
    {
        Some(platform) => platform,
        None => return StatusCode::FORBIDDEN.into_response(),
    };
    if !valid_encrypted_attachment_body(&media_type, &encrypted_body) {
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
    let retention_expires_at_ms =
        (ttl_ms > 0).then(|| now_ms().saturating_add(ttl_ms.saturating_mul(1000)));
    let staged_expires_at_ms = Some(
        now_ms()
            .saturating_add(ATTACHMENT_STAGING_TTL_MS)
            .min(retention_expires_at_ms.unwrap_or(u64::MAX)),
    );
    let one_time = query.one_time.unwrap_or(false);
    let delete_after_download = query.delete_after_download.unwrap_or(one_time);
    let destructive = one_time || delete_after_download;
    let eligible_recipient_code_ids =
        snapshot_attachment_recipients(&state, &access, &chat_id, &auth.username, &auth.code_id)
            .await;
    if destructive && eligible_recipient_code_ids.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    prune_expired_attachments_locked(&state).await;
    let binding_key = AttachmentBindingKey::new(&auth.code_id, &chat_id, &message_id);
    let mut bindings = state.attachment_bindings.lock().await;
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
    if let Some(existing_id) = bindings.get(&binding_key).copied() {
        let live_binding = attachments
            .get(&existing_id)
            .is_some_and(|record| binding_key.matches_record(record));
        if live_binding {
            return StatusCode::CONFLICT.into_response();
        }
        bindings.remove(&binding_key);
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
            message_id,
            media_type,
            owner_code_id: auth.code_id,
            sender_platform,
            published: false,
            staged_expires_at_ms,
            one_time,
            delete_after_download,
            expires_at_ms: retention_expires_at_ms,
            eligible_recipient_code_ids,
            download_claims: HashMap::new(),
            completed_recipient_code_ids: HashSet::new(),
        },
    );
    bindings.insert(binding_key, id);
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
        if !record.published {
            return StatusCode::NOT_FOUND.into_response();
        }
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
    let mut bindings = state.attachment_bindings.lock().await;
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
    remove_attachment_binding_if_matches(&mut bindings, id, &record);

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
    let account_identity = {
        let mut accounts = state.accounts.lock().await;
        accounts.get_mut(&code_id).map(|account| {
            // A newly authenticated session must attest its platform again.
            // Existing sockets use the replaced session token and fail closed.
            account.client_platform = None;
            (
                URL_SAFE_NO_PAD.encode(&account.identity_public),
                account.prekey_id.clone(),
                URL_SAFE_NO_PAD.encode(&account.identity_envelope),
            )
        })
    };
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
        debug!("websocket_upgrade_rejected reason=origin");
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(ticket) = websocket_ticket_header(&headers) else {
        debug!("websocket_upgrade_rejected reason=protocol");
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let auth = consume_ws_ticket(&state, ticket.as_str()).await;

    match auth {
        Some((token, session, client_platform)) => {
            let client_id = Uuid::new_v4();
            let code_id = session.code_id;
            let mut active_connections = state.active_connections.lock().await;
            if !reserve_connection(&mut active_connections, code_id, client_id) {
                debug!("websocket_upgrade_rejected reason=active_connection");
                return StatusCode::CONFLICT.into_response();
            }
            drop(active_connections);
            let failed_state = state.clone();
            ws.max_frame_size(CONTROL_TRANSPORT_MAX_BUCKET)
                .max_message_size(CONTROL_TRANSPORT_MAX_BUCKET)
                .protocols([WEB_SOCKET_PROTOCOL])
                .on_failed_upgrade(move |_| {
                    debug!("websocket_upgrade_failed reason=transport");
                    tokio::spawn(async move {
                        release_connection_reservation(&failed_state, &code_id, client_id).await;
                    });
                })
                .on_upgrade(move |socket| {
                    socket_loop(state, token, session, client_platform, client_id, socket)
                })
                .into_response()
        }
        None => {
            debug!("websocket_upgrade_rejected reason=ticket_or_session");
            StatusCode::UNAUTHORIZED.into_response()
        }
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
    client_platform: ClientPlatform,
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
            platform: client_platform,
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
    send_mls_catalog(&state, client_id, &auth.code_id).await;
    send_mls_pending(&state, client_id, &auth.code_id).await;
    send_mls_pending_joins(&state, client_id, &auth.code_id).await;
    send_mls_pending_leaves(&state, client_id, &auth.code_id).await;
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
                        if let Err(err) = validate_inbound_text_socket_admission(
                            text.as_str(),
                            check_ws_frame_allowed(&state, client_id, text.len()).await,
                        ) {
                            warn!("closing limited frame connection from {client_id}: {err}");
                            break;
                        }
                        let inner = match strip_inbound_control_transport(text.as_str()) {
                            Ok(inner) => inner,
                            Err(err) => {
                                warn!("closing invalid transport frame from {client_id}: {err}");
                                break;
                            }
                        };
                        if let Err(err) = handle_frame(&state, client_id, inner.as_str()).await {
                            warn!("dropping invalid frame from {client_id}: {err}");
                        }
                    }
                    Some(Ok(Message::Binary(bytes))) => {
                        if let Err(err) = check_ws_frame_allowed(&state, client_id, bytes.len()).await {
                            warn!("closing limited binary connection from {client_id}: {err}");
                            break;
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
    if frame_bytes > CONTROL_TRANSPORT_MAX_BUCKET {
        return Err(format!(
            "frame too large: bytes={} max={}",
            frame_bytes, CONTROL_TRANSPORT_MAX_BUCKET
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

fn validate_inbound_frame_size_before_parse(text: &str) -> Result<(), String> {
    let frame_bytes = text.len();
    if frame_bytes <= WS_MAX_FRAME_BYTES {
        return Ok(());
    }
    if frame_bytes > MLS_WS_MAX_FRAME_BYTES {
        return Err(format!(
            "frame too large: bytes={} max={}",
            frame_bytes, MLS_WS_MAX_FRAME_BYTES
        ));
    }
    if LARGE_MLS_INBOUND_PREFIXES
        .iter()
        .any(|prefix| text.starts_with(prefix))
    {
        return Ok(());
    }
    Err(format!(
        "oversized inbound frame is not a canonical protocol-v10 MLS frame: bytes={} legacy_max={}",
        frame_bytes, WS_MAX_FRAME_BYTES
    ))
}

fn validate_inbound_text_socket_admission(
    text: &str,
    frame_limit: Result<(), String>,
) -> Result<(), String> {
    validate_inbound_transport_size_before_parse(text)?;
    frame_limit
}

fn validate_inbound_transport_size_before_parse(text: &str) -> Result<(), String> {
    let frame_bytes = text.len();
    if frame_bytes <= WS_MAX_FRAME_BYTES {
        return Ok(());
    }
    if frame_bytes > CONTROL_TRANSPORT_MAX_BUCKET {
        return Err(format!(
            "transport frame too large: bytes={} max={}",
            frame_bytes, CONTROL_TRANSPORT_MAX_BUCKET
        ));
    }
    if LARGE_MLS_INBOUND_PREFIXES
        .iter()
        .any(|prefix| text.starts_with(prefix))
    {
        return Ok(());
    }
    Err(format!(
        "oversized transport frame is not a canonical protocol-v10 MLS frame: bytes={} legacy_max={}",
        frame_bytes, WS_MAX_FRAME_BYTES
    ))
}

fn strip_inbound_control_transport(text: &str) -> Result<String, String> {
    let value = serde_json::from_str::<serde_json::Value>(text)
        .map_err(|_| "transport frame rejected".to_string())?;
    let frame_type = value
        .as_object()
        .and_then(|object| object.get("type"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "transport frame rejected".to_string())?;
    if frame_type == "message" {
        if text.len() > MESSAGE_TRANSPORT_MAX_BUCKET {
            return Err("message transport frame too large".to_string());
        }
        return Ok(text.to_string());
    }
    let domain_limit = if frame_type.starts_with("mls_") {
        MLS_WS_MAX_FRAME_BYTES
    } else {
        WS_MAX_FRAME_BYTES
    };
    strip_control_transport_frame(text, domain_limit)
}

enum RecoverableTransaction {
    Execute(TransactionTicket),
    Replay(bool),
    RejectForCapacity,
}

async fn begin_recoverable_transaction(
    state: &AppState,
    sender_id: Uuid,
    kind: TransactionKind,
    conversation_id: &str,
    message_id: &str,
    exact_frame: &str,
) -> Result<RecoverableTransaction, String> {
    let (account_id, _) = client_identity(state, sender_id).await?;
    let key = TransactionKey::new(account_id, kind, conversation_id, message_id);
    let outcome = state
        .transaction_receipts
        .lock()
        .await
        .begin(key, exact_frame, now_ms());
    match outcome {
        Ok(TransactionBeginOutcome::Execute(ticket)) => Ok(RecoverableTransaction::Execute(ticket)),
        Ok(TransactionBeginOutcome::Replay(accepted)) => {
            Ok(RecoverableTransaction::Replay(accepted))
        }
        Ok(TransactionBeginOutcome::CapacityExceeded) => {
            Ok(RecoverableTransaction::RejectForCapacity)
        }
        Ok(TransactionBeginOutcome::InProgress) => Err("transaction still in progress".to_string()),
        Err(TransactionReceiptError::ConflictingFrame) => {
            invalidate_client_connection(state, sender_id).await;
            Err("conflicting transaction frame".to_string())
        }
        Err(TransactionReceiptError::MissingReservation) => {
            Err("transaction receipt unavailable".to_string())
        }
    }
}

async fn finish_recoverable_transaction(
    state: &AppState,
    sender_id: Uuid,
    ticket: TransactionTicket,
    accepted: bool,
) -> Result<(), String> {
    if state
        .transaction_receipts
        .lock()
        .await
        .finish(ticket, accepted, now_ms())
        .is_err()
    {
        invalidate_client_connection(state, sender_id).await;
        return Err("transaction receipt unavailable".to_string());
    }
    Ok(())
}

async fn handle_frame(state: &AppState, sender_id: Uuid, text: &str) -> Result<(), String> {
    // Do this before serde_json sees attacker-controlled input.  The websocket
    // layer permits the MLS ceiling so legitimate state envelopes can transit,
    // but legacy and unknown frames retain the smaller parser allocation budget.
    validate_inbound_frame_size_before_parse(text)?;
    let frame: InboundFrame = serde_json::from_str(text).map_err(|err| err.to_string())?;
    validate_inbound_message_padding(text, &frame)?;
    match frame {
        InboundFrame::Activity => {
            touch_activity(state).await;
            Ok(())
        }
        InboundFrame::PrekeyLease {
            chat_id,
            message_id,
            recipient_username,
        } => {
            let lease =
                lease_prekey(state, sender_id, &chat_id, &message_id, &recipient_username).await?;
            send_to_client(state, sender_id, &lease).await;
            touch_activity(state).await;
            Ok(())
        }
        InboundFrame::PrekeyLeaseRelease {
            chat_id,
            message_id,
            recipient_username,
            prekey_id,
        } => {
            touch_activity_on_success(
                state,
                release_unused_prekey_lease(
                    state,
                    sender_id,
                    &chat_id,
                    &message_id,
                    &recipient_username,
                    &prekey_id,
                )
                .await,
            )
            .await
        }
        InboundFrame::Dummy { padding_b64, bytes } => {
            let _discarded_hint = discarded_dummy_hint(padding_b64.as_deref(), bytes);
            Ok(())
        }
        InboundFrame::Join { chat_id } => {
            if state.room_catalog.lock().await.contains_key(&chat_id) {
                return Err("protocol-v9 rooms are unavailable".to_string());
            }
            touch_activity_on_success(state, join_room(state, sender_id, chat_id).await).await
        }
        InboundFrame::Leave { chat_id } => {
            if state.room_catalog.lock().await.contains_key(&chat_id) {
                return Err("protocol-v9 rooms are unavailable".to_string());
            }
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
            directory_node_id,
            directory_revision,
            directory_digest,
            padding_bucket: _,
            padding: _,
        } => {
            let message_id_is_safe = valid_chat_id(&message_id);
            let transaction = if message_id_is_safe && valid_chat_id(&chat_id) {
                Some(
                    begin_recoverable_transaction(
                        state,
                        sender_id,
                        TransactionKind::Message,
                        &chat_id,
                        &message_id,
                        text,
                    )
                    .await?,
                )
            } else {
                None
            };
            match &transaction {
                Some(RecoverableTransaction::Replay(accepted)) => {
                    send_message_result(state, sender_id, &message_id, *accepted).await?;
                    return if *accepted {
                        Ok(())
                    } else {
                        Err("message rejected".to_string())
                    };
                }
                Some(RecoverableTransaction::RejectForCapacity) => {
                    send_message_result(state, sender_id, &message_id, false).await?;
                    return Err("transaction receipt capacity exceeded".to_string());
                }
                _ => {}
            }
            let route_result = route_encrypted_message_with_directory(
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
                directory_evidence(directory_node_id, directory_revision, directory_digest),
            )
            .await;
            if let Some(RecoverableTransaction::Execute(ticket)) = transaction {
                finish_recoverable_transaction(state, sender_id, ticket, route_result.is_ok())
                    .await?;
            }
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
            let transaction = if message_id_is_safe && valid_chat_id(&chat_id) {
                Some(
                    begin_recoverable_transaction(
                        state,
                        sender_id,
                        TransactionKind::Acknowledgement,
                        &chat_id,
                        &message_id,
                        text,
                    )
                    .await?,
                )
            } else {
                None
            };
            match &transaction {
                Some(RecoverableTransaction::Replay(accepted)) => {
                    send_ack_result(state, sender_id, &message_id, *accepted).await?;
                    return if *accepted {
                        Ok(())
                    } else {
                        Err("acknowledgement rejected".to_string())
                    };
                }
                Some(RecoverableTransaction::RejectForCapacity) => {
                    send_ack_result(state, sender_id, &message_id, false).await?;
                    return Err("transaction receipt capacity exceeded".to_string());
                }
                _ => {}
            }
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
            if let Some(RecoverableTransaction::Execute(ticket)) = transaction {
                finish_recoverable_transaction(
                    state,
                    sender_id,
                    ticket,
                    acknowledgement_result.is_ok(),
                )
                .await?;
            }
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
            let _ = room;
            Err("protocol-v9 rooms are unavailable".to_string())
        }
        InboundFrame::DeleteRoom { chat_id } => {
            let _ = chat_id;
            Err("protocol-v9 rooms are unavailable".to_string())
        }
        InboundFrame::OpenDirect { peer_username } => {
            touch_activity_on_success(state, open_direct(state, sender_id, &peer_username).await)
                .await
        }
        InboundFrame::MlsCreateRoom {
            protocol_version,
            room_id,
            group_id_b64,
            epoch,
            revision,
            membership_digest_b64,
            stable_identity_b64,
            state_envelope_b64,
            policy,
        } => {
            require_mls_protocol_version(protocol_version)?;
            touch_activity_on_success(
                state,
                mls_create_room(
                    state,
                    sender_id,
                    room_id,
                    group_id_b64,
                    epoch,
                    revision,
                    membership_digest_b64,
                    stable_identity_b64,
                    state_envelope_b64,
                    policy,
                )
                .await,
            )
            .await
        }
        InboundFrame::MlsDiscoverRoom {
            protocol_version,
            room_id,
        } => {
            require_mls_protocol_version(protocol_version)?;
            touch_activity_on_success(state, mls_discover_room(state, sender_id, &room_id).await)
                .await
        }
        InboundFrame::MlsJoinRequest {
            protocol_version,
            room_id,
            request_id,
            stable_identity_b64,
            key_package_b64,
            state_envelope_b64,
        } => {
            require_mls_protocol_version(protocol_version)?;
            touch_activity_on_success(
                state,
                mls_join_request(
                    state,
                    sender_id,
                    room_id,
                    request_id,
                    stable_identity_b64,
                    key_package_b64,
                    state_envelope_b64,
                )
                .await,
            )
            .await
        }
        InboundFrame::MlsJoinReject {
            protocol_version,
            room_id,
            request_id,
        } => {
            require_mls_protocol_version(protocol_version)?;
            touch_activity_on_success(
                state,
                mls_join_reject(state, sender_id, &room_id, &request_id).await,
            )
            .await
        }
        InboundFrame::MlsLeaveRequest {
            protocol_version,
            room_id,
            request_id,
        } => {
            require_mls_protocol_version(protocol_version)?;
            touch_activity_on_success(
                state,
                mls_leave_request(state, sender_id, room_id, request_id).await,
            )
            .await
        }
        InboundFrame::MlsLeaveReject {
            protocol_version,
            room_id,
            request_id,
        } => {
            require_mls_protocol_version(protocol_version)?;
            touch_activity_on_success(
                state,
                mls_leave_reject(state, sender_id, &room_id, &request_id).await,
            )
            .await
        }
        InboundFrame::MlsMembershipCommit {
            protocol_version,
            room_id,
            message_id,
            request_id,
            from_epoch,
            to_epoch,
            revision,
            group_id_b64,
            from_membership_digest_b64,
            membership_digest_b64,
            roster,
            control_b64,
            welcome_b64,
            authenticated_data_b64,
            state_envelope_b64,
        } => {
            require_mls_protocol_version(protocol_version)?;
            let safe = valid_mls_correlator(&room_id) && valid_mls_correlator(&message_id);
            if !safe {
                return Err("invalid MLS transaction identity".to_string());
            }
            let transaction = begin_recoverable_transaction(
                state,
                sender_id,
                TransactionKind::MlsRoom,
                &room_id,
                &message_id,
                text,
            )
            .await?;
            match transaction {
                RecoverableTransaction::Replay(accepted) => {
                    send_mls_room_result(
                        state,
                        sender_id,
                        &room_id,
                        &message_id,
                        revision,
                        accepted,
                    )
                    .await?;
                    Ok(())
                }
                RecoverableTransaction::RejectForCapacity => {
                    send_mls_room_result(state, sender_id, &room_id, &message_id, revision, false)
                        .await?;
                    Ok(())
                }
                RecoverableTransaction::Execute(ticket) => {
                    let result = mls_membership_commit(
                        state,
                        sender_id,
                        room_id.clone(),
                        message_id.clone(),
                        request_id,
                        from_epoch,
                        to_epoch,
                        revision,
                        group_id_b64,
                        from_membership_digest_b64,
                        membership_digest_b64,
                        roster,
                        control_b64,
                        welcome_b64,
                        authenticated_data_b64,
                        state_envelope_b64,
                    )
                    .await;
                    finish_mls_room_transaction(
                        state, sender_id, room_id, message_id, revision, ticket, result,
                    )
                    .await
                }
            }
        }
        InboundFrame::MlsApplication {
            protocol_version,
            room_id,
            message_id,
            group_id_b64,
            epoch,
            revision,
            membership_digest_b64,
            ciphertext_b64,
            authenticated_data_b64,
            state_envelope_b64,
        } => {
            require_mls_protocol_version(protocol_version)?;
            let safe = valid_mls_correlator(&room_id) && valid_mls_correlator(&message_id);
            if !safe {
                return Err("invalid MLS transaction identity".to_string());
            }
            let transaction = begin_recoverable_transaction(
                state,
                sender_id,
                TransactionKind::MlsRoom,
                &room_id,
                &message_id,
                text,
            )
            .await?;
            match transaction {
                RecoverableTransaction::Replay(accepted) => {
                    send_mls_room_result(
                        state,
                        sender_id,
                        &room_id,
                        &message_id,
                        revision,
                        accepted,
                    )
                    .await?;
                    Ok(())
                }
                RecoverableTransaction::RejectForCapacity => {
                    send_mls_room_result(state, sender_id, &room_id, &message_id, revision, false)
                        .await?;
                    Ok(())
                }
                RecoverableTransaction::Execute(ticket) => {
                    let result = mls_application(
                        state,
                        sender_id,
                        room_id.clone(),
                        message_id.clone(),
                        group_id_b64,
                        epoch,
                        revision,
                        membership_digest_b64,
                        ciphertext_b64,
                        authenticated_data_b64,
                        state_envelope_b64,
                    )
                    .await;
                    finish_mls_room_transaction(
                        state, sender_id, room_id, message_id, revision, ticket, result,
                    )
                    .await
                }
            }
        }
        InboundFrame::MlsStateSnapshot {
            protocol_version,
            room_id,
            message_id,
            epoch,
            revision,
            membership_digest_b64,
            state_envelope_b64,
        } => {
            require_mls_protocol_version(protocol_version)?;
            let safe = valid_mls_correlator(&room_id) && valid_mls_correlator(&message_id);
            if !safe {
                return Err("invalid MLS transaction identity".to_string());
            }
            let transaction = begin_recoverable_transaction(
                state,
                sender_id,
                TransactionKind::MlsSnapshot,
                &room_id,
                &message_id,
                text,
            )
            .await?;
            match transaction {
                RecoverableTransaction::Replay(accepted) => {
                    send_mls_snapshot_result(
                        state,
                        sender_id,
                        &room_id,
                        &message_id,
                        revision,
                        accepted,
                    )
                    .await?;
                    Ok(())
                }
                RecoverableTransaction::RejectForCapacity => {
                    send_mls_snapshot_result(
                        state,
                        sender_id,
                        &room_id,
                        &message_id,
                        revision,
                        false,
                    )
                    .await?;
                    Ok(())
                }
                RecoverableTransaction::Execute(ticket) => {
                    let result = mls_state_snapshot(
                        state,
                        sender_id,
                        room_id.clone(),
                        message_id.clone(),
                        epoch,
                        revision,
                        membership_digest_b64,
                        state_envelope_b64,
                    )
                    .await;
                    finish_mls_snapshot_transaction(
                        state, sender_id, room_id, message_id, revision, ticket, result,
                    )
                    .await
                }
            }
        }
        InboundFrame::MlsDeleteRoom {
            protocol_version,
            room_id,
        } => {
            require_mls_protocol_version(protocol_version)?;
            touch_activity_on_success(state, mls_delete_room(state, sender_id, &room_id).await)
                .await
        }
    }
}

async fn lease_prekey(
    state: &AppState,
    sender_id: Uuid,
    chat_id: &str,
    message_id: &str,
    recipient_username: &str,
) -> Result<OutboundFrame, String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    if !valid_chat_id(chat_id) || !valid_chat_id(message_id) || !valid_username(recipient_username)
    {
        return Err("prekey lease rejected".to_string());
    }
    let (_, sender_username) = client_identity(state, sender_id).await?;
    if sender_username == recipient_username {
        return Err("prekey lease rejected".to_string());
    }
    let access = conversation_access(state, &sender_username, chat_id)
        .await
        .ok_or_else(|| "conversation unavailable".to_string())?;
    let authorized = match access {
        ConversationAccess::MlsRoom(_) => false,
        ConversationAccess::Direct => state
            .direct_catalog
            .lock()
            .await
            .get(chat_id)
            .and_then(|direct| direct.peer_for(&sender_username))
            .is_some_and(|peer| peer == recipient_username),
        ConversationAccess::Room(_) => state
            .accounts
            .lock()
            .await
            .values()
            .any(|account| account.username == recipient_username),
    };
    if !authorized {
        return Err("prekey lease rejected".to_string());
    }

    prune_pending_queues(state, now_ms()).await;
    let accounts = state.accounts.lock().await;
    let (recipient_code_id, recipient) = accounts
        .iter()
        .find(|(_, account)| account.username == recipient_username)
        .ok_or_else(|| "recipient unavailable".to_string())?;
    let pool = prekey_ids_from_identity_public_v9(&recipient.identity_public)
        .map_err(|_| "recipient unavailable".to_string())?;
    let recipient_public_key_b64 = URL_SAFE_NO_PAD.encode(&recipient.identity_public);
    let recipient_code_id = *recipient_code_id;
    let now = now_ms();
    let pending = state.pending.lock().await;
    let mut leases = state.prekey_leases.lock().await;
    prune_prekey_leases(&mut leases, &pending, now);

    let mut matching = leases.iter().filter(|(key, lease)| {
        key.code_id == recipient_code_id
            && lease.chat_id == chat_id
            && lease.message_id == message_id
            && lease.sender_username == sender_username
            && lease.recipient_username == recipient_username
    });
    if let Some((key, lease)) = matching.next() {
        if matching.next().is_some() {
            return Err("prekey lease rejected".to_string());
        }
        return Ok(OutboundFrame::PrekeyLease {
            chat_id: chat_id.to_string(),
            message_id: message_id.to_string(),
            recipient_username: recipient_username.to_string(),
            recipient_public_key_b64,
            prekey_id: key.prekey_id.clone(),
            expires_at_ms: lease.created_at_ms.saturating_add(PREKEY_LEASE_TTL_MS),
        });
    }
    if leases.len() >= MAX_PREKEY_LEASES
        || leases
            .keys()
            .filter(|key| key.code_id == recipient_code_id)
            .count()
            >= MAX_PREKEY_LEASES_PER_RECIPIENT
    {
        return Err("prekey lease capacity full".to_string());
    }
    let prekey_id = pool
        .into_iter()
        .find(|id| {
            !leases.contains_key(&PrekeyLeaseKey {
                code_id: recipient_code_id,
                prekey_id: id.clone(),
            })
        })
        .ok_or_else(|| "recipient prekey unavailable".to_string())?;
    leases.insert(
        PrekeyLeaseKey {
            code_id: recipient_code_id,
            prekey_id: prekey_id.clone(),
        },
        PrekeyLease {
            chat_id: chat_id.to_string(),
            message_id: message_id.to_string(),
            sender_username,
            recipient_username: recipient_username.to_string(),
            created_at_ms: now,
        },
    );
    Ok(OutboundFrame::PrekeyLease {
        chat_id: chat_id.to_string(),
        message_id: message_id.to_string(),
        recipient_username: recipient_username.to_string(),
        recipient_public_key_b64,
        prekey_id,
        expires_at_ms: now.saturating_add(PREKEY_LEASE_TTL_MS),
    })
}

async fn release_unused_prekey_lease(
    state: &AppState,
    sender_id: Uuid,
    chat_id: &str,
    message_id: &str,
    recipient_username: &str,
    prekey_id: &str,
) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    if !valid_chat_id(chat_id)
        || !valid_chat_id(message_id)
        || !valid_username(recipient_username)
        || !valid_prekey_id(prekey_id)
        || prekey_id.is_empty()
    {
        return Err("prekey lease release rejected".to_string());
    }
    let (_, sender_username) = client_identity(state, sender_id).await?;
    let recipient_code_id = state
        .accounts
        .lock()
        .await
        .iter()
        .find_map(|(code_id, account)| (account.username == recipient_username).then_some(*code_id))
        .ok_or_else(|| "prekey lease release rejected".to_string())?;
    let key = PrekeyLeaseKey {
        code_id: recipient_code_id,
        prekey_id: prekey_id.to_string(),
    };
    let pending = state.pending.lock().await;
    let mut leases = state.prekey_leases.lock().await;
    let lease = leases
        .get(&key)
        .ok_or_else(|| "prekey lease release rejected".to_string())?;
    if lease.chat_id != chat_id
        || lease.message_id != message_id
        || lease.sender_username != sender_username
        || lease.recipient_username != recipient_username
        || pending_contains_leased_frame(&pending, &key, lease)
    {
        return Err("prekey lease release rejected".to_string());
    }
    leases.remove(&key);
    Ok(())
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
    let (_, username, recipient_platform) = client_identity_and_platform(state, client_id).await?;
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
        if state
            .interop_policy
            .allows(pending_frame.sender_platform, recipient_platform)
        {
            send_to_client(state, client_id, &pending_frame.frame).await;
        }
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

#[cfg(test)]
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
    let current_directory = current_directory_evidence(state).await;
    route_encrypted_message_with_directory(
        state,
        sender_id,
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
        Some(current_directory),
    )
    .await
}

fn directory_evidence(node_id: String, revision: u64, digest: String) -> Option<DirectoryStamp> {
    if node_id.is_empty() && revision == 0 && digest.is_empty() {
        None
    } else {
        Some(DirectoryStamp {
            node_id,
            revision,
            digest,
        })
    }
}

async fn validate_directory_evidence(
    state: &AppState,
    evidence: Option<DirectoryStamp>,
) -> Result<DirectoryStamp, String> {
    let Some(candidate) = evidence else {
        return Err("directory evidence required".to_string());
    };
    if !valid_node_id(&candidate.node_id)
        || !(1..=MAX_DIRECTORY_REVISION).contains(&candidate.revision)
    {
        return Err("directory evidence rejected".to_string());
    }
    let _decoded_digest = Zeroizing::new(
        decode_exact(&candidate.digest, DIRECTORY_DIGEST_BYTES)
            .map_err(|_| "directory evidence rejected".to_string())?,
    );
    let accounts = state.accounts.lock().await;
    let current = directory_stamp(&state.node_id, &accounts);
    if candidate.node_id == current.node_id
        && candidate.revision == current.revision
        && candidate.digest == current.digest
    {
        Ok(current)
    } else {
        Err("directory evidence rejected".to_string())
    }
}

#[cfg(test)]
async fn current_directory_evidence(state: &AppState) -> DirectoryStamp {
    let accounts = state.accounts.lock().await;
    directory_stamp(&state.node_id, &accounts)
}

#[allow(clippy::too_many_arguments)]
async fn route_encrypted_message_with_directory(
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
    directory_evidence: Option<DirectoryStamp>,
) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    let directory_stamp = validate_directory_evidence(state, directory_evidence).await?;
    if version != E2EE_PROTOCOL_VERSION || !valid_chat_id(&chat_id) || !valid_chat_id(&message_id) {
        return Err("encrypted message rejected".to_string());
    }
    let nonce = Zeroizing::new(decode_exact(&nonce_b64, MESSAGE_NONCE_BYTES)?);
    let ciphertext = Zeroizing::new(decode_bounded(&ciphertext_b64, WS_MAX_FRAME_BYTES)?);

    decode_bounded(&identity_envelope_b64, MAX_IDENTITY_ENVELOPE_BYTES)?;

    let (sender_code_id, sender_username, sender_platform) =
        client_identity_and_platform(state, sender_id).await?;
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
    // Upload and message admission share conversation_ops. This prevents a
    // second live record from racing the exact owner/chat/message binding.
    let staged_attachment_id =
        staged_attachment_for_message(state, &sender_code_id, &chat_id, &message_id).await?;
    let expected_recipients = match access {
        ConversationAccess::MlsRoom(_) => {
            return Err("MLS application required".to_string());
        }
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
    require_recipient_platforms(state, sender_platform, &expected_recipients).await?;

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
        verify_message_signature_v9(
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
        let mut frame = OutboundFrame::Message {
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
            directory_node_id: directory_stamp.node_id.clone(),
            directory_revision: directory_stamp.revision,
            directory_digest: directory_stamp.digest.clone(),
            padding_bucket: 0,
            padding: String::new(),
        };
        prepare_outbound_message_padding(&mut frame)?;
        let frame_bytes = validated_outbound_frame_bytes(&frame)
            .ok_or_else(|| "fanout preparation budget full".to_string())?;
        transient_fanout_bytes = transient_fanout_bytes
            .checked_add(
                frame_bytes
                    .checked_add(recipient_username.len())
                    .ok_or_else(|| "fanout preparation budget full".to_string())?,
            )
            .ok_or_else(|| "fanout preparation budget full".to_string())?;
        if transient_fanout_bytes > MAX_TRANSIENT_FANOUT_BYTES {
            return Err("fanout preparation budget full".to_string());
        }
        prepared_frames.push((recipient_username.clone(), frame));
    }
    admit_prekey_leases(
        state,
        &expected_recipients,
        &envelope_map,
        &chat_id,
        &message_id,
        &sender_username,
    )
    .await?;
    let mut pending_plan = preflight_pending_frames(state, &prepared_frames).await?;
    commit_pending_frames(state, &prepared_frames, &mut pending_plan, sender_platform).await?;
    if let Err(error) = register_message_id(state, &chat_id, &sender_username, &message_id).await {
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
        rollback_pending_frames(state, &prepared_frames, &mut pending_plan).await;
        return Err(error);
    }

    // Publication is deliberately after complete encrypted-message
    // admission, but before fanout. A lost message_result therefore leaves a
    // successfully admitted attachment downloadable, while rejected or
    // rolled-back admissions never publish the staged record.
    if let Some(attachment_id) = staged_attachment_id {
        publish_staged_attachment(state, attachment_id, &sender_code_id, &chat_id, &message_id)
            .await;
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
                (client.username == recipient_username
                    && joined.contains(client_id)
                    && state
                        .interop_policy
                        .allows(sender_platform, client.platform))
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

async fn admit_prekey_leases(
    state: &AppState,
    expected_recipients: &HashSet<String>,
    envelopes: &HashMap<String, InboundRecipientEnvelope>,
    chat_id: &str,
    message_id: &str,
    sender_username: &str,
) -> Result<(), String> {
    // The caller holds conversation_ops. Admission only verifies leases that
    // were created before encryption; it never chooses or reserves a key.
    prune_pending_queues(state, now_ms()).await;
    let accounts = state.accounts.lock().await;
    let pending = state.pending.lock().await;
    let mut leases = state.prekey_leases.lock().await;
    let now = now_ms();
    prune_prekey_leases(&mut leases, &pending, now);
    for username in expected_recipients {
        let Some(envelope) = envelopes.get(username) else {
            return Err("recipient envelope rejected".to_string());
        };
        if !envelope.is_prekey {
            continue;
        }
        let Some((code_id, account)) = accounts
            .iter()
            .find(|(_, account)| account.username == *username)
        else {
            return Err("recipient envelope rejected".to_string());
        };
        let pool = prekey_ids_from_identity_public_v9(&account.identity_public)
            .map_err(|_| "recipient prekey unavailable".to_string())?;
        if !pool.iter().any(|id| id == &envelope.prekey_id) {
            return Err("recipient prekey unavailable".to_string());
        }
        let key = PrekeyLeaseKey {
            code_id: *code_id,
            prekey_id: envelope.prekey_id.clone(),
        };
        let lease = leases
            .get(&key)
            .ok_or_else(|| "recipient prekey lease required".to_string())?;
        if lease.chat_id != chat_id
            || lease.message_id != message_id
            || lease.sender_username != sender_username
            || lease.recipient_username != *username
        {
            return Err("recipient prekey lease rejected".to_string());
        }
    }
    Ok(())
}

#[allow(dead_code)]
async fn release_prekey_lease(
    state: &AppState,
    chat_id: &str,
    message_id: &str,
    sender_username: &str,
    prekey_id: Option<&str>,
) {
    state.prekey_leases.lock().await.retain(|key, claim| {
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

fn prekey_lease_details(frame: &OutboundFrame) -> Option<(String, String, String, String)> {
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
    let OutboundFrame::Message {
        padding_bucket,
        padding,
        ..
    } = frame
    else {
        return 0;
    };
    let Some((canonical_bucket, empty_len)) = canonical_outbound_message_bucket(frame) else {
        return WS_MAX_FRAME_BYTES.saturating_add(1);
    };
    let Some(expected_padding_len) = canonical_bucket.checked_sub(empty_len) else {
        return WS_MAX_FRAME_BYTES.saturating_add(1);
    };
    if *padding_bucket != canonical_bucket || expected_padding_len != padding.len() {
        WS_MAX_FRAME_BYTES.saturating_add(1)
    } else {
        // Relay-created frames already received CSPRNG URL-safe filler. Avoid
        // rescanning up to 1 MiB every time a pending queue is simulated or
        // accounted. The single serialization boundary still revalidates the
        // filler alphabet before bytes reach the socket.
        canonical_bucket
    }
}

fn validated_outbound_frame_bytes(frame: &OutboundFrame) -> Option<usize> {
    let bytes = outbound_frame_bytes(frame);
    if matches!(frame, OutboundFrame::Message { .. }) && bytes > WS_MAX_FRAME_BYTES {
        None
    } else {
        Some(bytes)
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
    // expired frames and their prekey leases cannot consume admission budget.
    let transient_fanout_bytes = frames
        .iter()
        .try_fold(0usize, |total, (recipient, frame)| {
            let frame_and_recipient = validated_outbound_frame_bytes(frame)
                .ok_or_else(|| "fanout preparation budget full".to_string())?
                .checked_add(recipient.len())
                .ok_or_else(|| "fanout preparation budget full".to_string())?;
            total
                .checked_add(frame_and_recipient)
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
                    let bytes = validated_outbound_frame_bytes(&pending_frame.frame)?;
                    Some((bytes, is_prekey_frame(&pending_frame.frame)))
                })
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| "pending frame rejected".to_string())?,
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
        let incoming_bytes = validated_outbound_frame_bytes(frame)
            .ok_or_else(|| "pending frame rejected".to_string())?;
        let Some(projected_next) = projected_bytes.checked_add(incoming_bytes) else {
            return Err("pending message budget full".to_string());
        };
        if projected_next > MAX_PENDING_BYTES {
            return Err("pending message budget full".to_string());
        }
        projected_bytes = projected_next;
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
    sender_platform: ClientPlatform,
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
                    let bytes = validated_outbound_frame_bytes(&pending_frame.frame)?;
                    Some((bytes, is_prekey_frame(&pending_frame.frame)))
                })
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| "pending queue changed during commit".to_string())?,
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
        let incoming_bytes = validated_outbound_frame_bytes(frame)
            .ok_or_else(|| "pending frame rejected".to_string())?;
        let Some(projected_next) = projected_bytes.checked_add(incoming_bytes) else {
            return Err("pending message budget changed during commit".to_string());
        };
        if projected_next > MAX_PENDING_BYTES {
            return Err("pending message budget changed during commit".to_string());
        }
        projected_bytes = projected_next;
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
        let incoming_bytes = validated_outbound_frame_bytes(frame)
            .ok_or_else(|| "pending frame rejected".to_string())?;
        let Some(next_pending_bytes) = pending_bytes.checked_add(incoming_bytes) else {
            return Err("pending message budget changed during commit".to_string());
        };
        queue.push(PendingFrame::new_for_platform(
            frame.clone(),
            now,
            sender_platform,
        ));
        *pending_bytes = next_pending_bytes;
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
    commit_pending_frames(state, &frames, &mut plan, ClientPlatform::Android).await
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
    apply_identity_state_locked_with_consumed(
        accounts,
        code_id,
        revision,
        envelope_b64,
        identity_public_b64,
        prekey_id,
        state_signature_b64,
        allow_reuse,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn apply_identity_state_locked_with_consumed(
    accounts: &mut HashMap<CodeId, Account>,
    code_id: &CodeId,
    revision: u64,
    envelope_b64: &str,
    identity_public_b64: &str,
    prekey_id: &str,
    state_signature_b64: &str,
    allow_reuse: bool,
    consumed_prekey_id: Option<&str>,
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
    validate_prekey_pool_transition(
        &account.identity_public,
        &identity_public,
        consumed_prekey_id,
    )?;
    if verify_identity_state_signature_v9(
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

fn validate_prekey_pool_transition(
    previous_public: &[u8],
    next_public: &[u8],
    consumed_prekey_id: Option<&str>,
) -> Result<(), String> {
    let previous = prekey_ids_from_identity_public_v9(previous_public)
        .map_err(|_| "identity state rejected".to_string())?;
    let next = prekey_ids_from_identity_public_v9(next_public)
        .map_err(|_| "identity state rejected".to_string())?;
    match consumed_prekey_id {
        None if previous == next => Ok(()),
        None => Err("identity prekey pool changed without consumption".to_string()),
        Some(consumed) => {
            let removed = previous
                .iter()
                .filter(|id| !next.contains(id))
                .collect::<Vec<_>>();
            let added = next
                .iter()
                .filter(|id| !previous.contains(id))
                .collect::<Vec<_>>();
            if removed.len() == 1
                && removed[0].as_str() == consumed
                && added.len() == 1
                && !next.iter().any(|id| id == consumed)
            {
                Ok(())
            } else {
                Err("identity prekey pool transition rejected".to_string())
            }
        }
    }
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
        ConversationAccess::MlsRoom(_) => false,
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
    verify_ack_signature_v9(
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
    // accounts -> pending -> pending_bytes -> prekey_leases.  Every
    // precondition is checked while these guards are held, then the signed
    // state and queue/claim consumption commit as one conversation operation.
    let mut accounts = state.accounts.lock().await;
    let mut pending = state.pending.lock().await;
    let mut pending_bytes = state.pending_bytes.lock().await;
    let mut claims = state.prekey_leases.lock().await;

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
        let claim_key = PrekeyLeaseKey {
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

    let next_identity_public =
        Zeroizing::new(decode_exact(identity_public_b64, IDENTITY_PUBLIC_BYTES)?);
    let next_pool = prekey_ids_from_identity_public_v9(&next_identity_public)
        .map_err(|_| "message acknowledgement rejected".to_string())?;
    if leases_for_recipient_missing_from_pool(
        &claims,
        &code_id,
        &next_pool,
        (!used_prekey_id.is_empty()).then_some(used_prekey_id),
    ) {
        return Err("message acknowledgement rejected".to_string());
    }

    apply_identity_state_locked_with_consumed(
        &mut accounts,
        &code_id,
        revision,
        envelope_b64,
        identity_public_b64,
        current_prekey_id,
        state_signature_b64,
        true,
        (!used_prekey_id.is_empty()).then_some(used_prekey_id),
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
        claims.remove(&PrekeyLeaseKey {
            code_id,
            prekey_id: used_prekey_id.to_string(),
        });
    }
    Ok(())
}

fn leases_for_recipient_missing_from_pool(
    leases: &HashMap<PrekeyLeaseKey, PrekeyLease>,
    code_id: &CodeId,
    next_pool: &[String],
    consumed_prekey_id: Option<&str>,
) -> bool {
    leases.keys().any(|key| {
        key.code_id == *code_id
            && consumed_prekey_id != Some(key.prekey_id.as_str())
            && !next_pool.contains(&key.prekey_id)
    })
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
    let mut attachment_bindings = state.attachment_bindings.lock().await;
    let mut attachments = state.attachments.lock().await;
    attachments.clear();
    attachment_bindings.clear();
    let mut attachment_usage = state.attachment_bytes_by_code.lock().await;
    zeroize_code_id_map(&mut attachment_usage);
    drop(attachment_usage);
    state.room_catalog.lock().await.clear();
    state.mls_rooms.lock().await.wipe();
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
    state.transaction_receipts.lock().await.clear();
    state.prekey_leases.lock().await.clear();
    state.opaque_handshakes.lock().await.clear();
    let mut login_limits = state.login_limits.lock().await;
    zeroize_code_id_map(&mut login_limits);
    drop(login_limits);
    state.clients.lock().await.clear();
    let mut active_connections = state.active_connections.lock().await;
    zeroize_code_id_map(&mut active_connections);
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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
                    if let Some(details) = prekey_lease_details(&pending_frame.frame) {
                        released_claims.push(details);
                    }
                    pending_frame.zeroize_sensitive();
                }
            }
        }
        drop(pending_bytes);
    }
    for (claim_chat_id, message_id, sender_username, prekey_id) in released_claims {
        release_prekey_lease(
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

#[allow(dead_code)]
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

fn mls_room_wire(info: rooms::RoomInfo) -> MlsRoomWire {
    MlsRoomWire {
        room_id: info.room_id,
        owner_username: info.owner_username,
        group_id_b64: URL_SAFE_NO_PAD.encode(info.group_id),
        active: info.active,
        synchronized: info.synchronized,
        epoch: info.epoch,
        revision: info.revision,
        membership_digest_b64: URL_SAFE_NO_PAD.encode(info.membership_digest),
        roster: info
            .roster
            .into_iter()
            .map(|member| MlsRosterWire {
                username: member.username.clone(),
                stable_identity_b64: URL_SAFE_NO_PAD.encode(member.stable_identity.clone()),
            })
            .collect(),
        recovery_snapshot: info
            .recovery_snapshot
            .map(|snapshot| MlsRecoverySnapshotWire {
                active: snapshot.active,
                epoch: snapshot.epoch,
                revision: snapshot.revision,
                membership_digest_b64: URL_SAFE_NO_PAD.encode(snapshot.membership_digest.clone()),
                state_envelope_b64: URL_SAFE_NO_PAD.encode(snapshot.state_envelope.clone()),
                roster: snapshot
                    .roster
                    .iter()
                    .map(|member| MlsRosterWire {
                        username: member.username.clone(),
                        stable_identity_b64: URL_SAFE_NO_PAD.encode(&member.stable_identity),
                    })
                    .collect(),
            }),
        policy: info.policy,
    }
}

fn mls_roster_from_wire(roster: Vec<MlsRosterWire>) -> Result<Vec<rooms::RosterMember>, String> {
    roster
        .into_iter()
        .map(|member| {
            Ok(rooms::RosterMember {
                username: member.username.clone(),
                stable_identity: decode_exact(
                    &member.stable_identity_b64,
                    rooms::STABLE_IDENTITY_BYTES,
                )?,
            })
        })
        .collect()
}

async fn send_mls_catalog(state: &AppState, client_id: Uuid, code_id: &CodeId) {
    let mut authority = state.mls_rooms.lock().await;
    let mut rooms = authority
        .rooms_for_member(code_id)
        .into_iter()
        .map(mls_room_wire)
        .collect::<Vec<_>>();
    rooms.extend(
        authority
            .pending_rooms_for_member(code_id)
            .into_iter()
            .map(mls_room_wire),
    );
    drop(authority);
    send_to_client(
        state,
        client_id,
        &OutboundFrame::MlsRooms {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            rooms,
        },
    )
    .await;
}

async fn mls_discover_room(state: &AppState, sender_id: Uuid, room_id: &str) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    let _ = client_identity(state, sender_id).await?;
    let info = state.mls_rooms.lock().await.discover(room_id)?;
    send_to_client(
        state,
        sender_id,
        &OutboundFrame::MlsRoomDiscovered {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id: info.room_id,
            group_id_b64: URL_SAFE_NO_PAD.encode(info.group_id),
            owner_username: info.owner_username,
        },
    )
    .await;
    Ok(())
}

async fn authenticated_mls_identity(
    state: &AppState,
    code_id: &CodeId,
    encoded: &str,
) -> Result<Vec<u8>, String> {
    let supplied = decode_exact(encoded, rooms::STABLE_IDENTITY_BYTES)?;
    let accounts = state.accounts.lock().await;
    let account = accounts
        .get(code_id)
        .ok_or_else(|| "authenticated identity required".to_string())?;
    if account.identity_public.len() < rooms::STABLE_IDENTITY_BYTES
        || account.identity_public[..rooms::STABLE_IDENTITY_BYTES] != supplied
    {
        return Err("authenticated identity required".to_string());
    }
    Ok(supplied)
}

#[allow(clippy::too_many_arguments)]
async fn mls_create_room(
    state: &AppState,
    sender_id: Uuid,
    room_id: String,
    group_id_b64: String,
    epoch: u64,
    revision: u64,
    membership_digest_b64: String,
    stable_identity_b64: String,
    state_envelope_b64: String,
    policy: rooms::RoomPolicy,
) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    let (owner_code_id, owner_username) = client_identity(state, sender_id).await?;
    let group_id = decode_exact(&group_id_b64, rooms::GROUP_ID_BYTES)?;
    let digest = decode_exact(&membership_digest_b64, rooms::MEMBERSHIP_DIGEST_BYTES)?;
    let stable = authenticated_mls_identity(state, &owner_code_id, &stable_identity_b64).await?;
    let info = state.mls_rooms.lock().await.create_with_policy_and_state(
        owner_code_id,
        owner_username,
        room_id,
        group_id,
        epoch,
        revision,
        digest,
        stable,
        policy,
        decode_bounded(&state_envelope_b64, rooms::MAX_STATE_BYTES)?,
    )?;
    send_to_client(
        state,
        sender_id,
        &OutboundFrame::MlsRoomCreated {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room: mls_room_wire(info),
        },
    )
    .await;
    Ok(())
}

async fn mls_join_request(
    state: &AppState,
    sender_id: Uuid,
    room_id: String,
    request_id: String,
    stable_identity_b64: String,
    key_package_b64: String,
    state_envelope_b64: String,
) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    let (code_id, username) = client_identity(state, sender_id).await?;
    let stable = authenticated_mls_identity(state, &code_id, &stable_identity_b64).await?;
    let key_package = decode_bounded(&key_package_b64, rooms::MAX_KEY_PACKAGE_BYTES)?;
    let state_envelope = decode_bounded(&state_envelope_b64, rooms::MAX_STATE_BYTES)?;
    let request = state.mls_rooms.lock().await.request_join(
        code_id,
        username.clone(),
        &room_id,
        request_id,
        stable,
        key_package,
        state_envelope,
    )?;
    let owner_code_id = state.mls_rooms.lock().await.owner_code_id(&room_id)?;
    let owner_ids = state
        .clients
        .lock()
        .await
        .iter()
        .filter_map(|(client_id, client)| (client.code_id == owner_code_id).then_some(*client_id))
        .collect::<Vec<_>>();
    let frame = OutboundFrame::MlsJoinRequested {
        protocol_version: rooms::MLS_PROTOCOL_VERSION,
        room_id,
        request_id: request.request_id.clone(),
        username: request.username.clone(),
        stable_identity_b64: URL_SAFE_NO_PAD.encode(request.stable_identity.clone()),
        key_package_b64: URL_SAFE_NO_PAD.encode(request.key_package.clone()),
    };
    for owner_id in owner_ids {
        send_to_client(state, owner_id, &frame).await;
    }
    Ok(())
}

async fn mls_join_reject(
    state: &AppState,
    sender_id: Uuid,
    room_id: &str,
    request_id: &str,
) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    let (owner_code_id, _) = client_identity(state, sender_id).await?;
    let request = state
        .mls_rooms
        .lock()
        .await
        .remove_join(owner_code_id, room_id, request_id)?;
    let frame = OutboundFrame::MlsJoinRejected {
        protocol_version: rooms::MLS_PROTOCOL_VERSION,
        room_id: room_id.to_string(),
        request_id: request.request_id.clone(),
    };
    for client_id in active_client_ids_for_code(state, &request.code_id).await {
        send_to_client(state, client_id, &frame).await;
    }
    Ok(())
}

async fn active_client_ids_for_code(state: &AppState, code_id: &CodeId) -> Vec<Uuid> {
    state
        .clients
        .lock()
        .await
        .iter()
        .filter_map(|(client_id, client)| (client.code_id == *code_id).then_some(*client_id))
        .collect()
}

async fn mls_leave_request(
    state: &AppState,
    sender_id: Uuid,
    room_id: String,
    request_id: String,
) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    let (code_id, _) = client_identity(state, sender_id).await?;
    let request = state
        .mls_rooms
        .lock()
        .await
        .request_leave(code_id, &room_id, request_id)?;
    let owner_code_id = state.mls_rooms.lock().await.owner_code_id(&room_id)?;
    let owner_frame = OutboundFrame::MlsLeaveRequested {
        protocol_version: rooms::MLS_PROTOCOL_VERSION,
        room_id: room_id.clone(),
        request_id: request.request_id.clone(),
        username: request.username.clone(),
        stable_identity_b64: URL_SAFE_NO_PAD.encode(request.stable_identity.clone()),
    };
    for owner_id in active_client_ids_for_code(state, &owner_code_id).await {
        send_to_client(state, owner_id, &owner_frame).await;
    }
    send_to_client(
        state,
        sender_id,
        &OutboundFrame::MlsLeavePending {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id,
            request_id: request.request_id.clone(),
        },
    )
    .await;
    Ok(())
}

async fn mls_leave_reject(
    state: &AppState,
    sender_id: Uuid,
    room_id: &str,
    request_id: &str,
) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    let (owner_code_id, _) = client_identity(state, sender_id).await?;
    let request = state
        .mls_rooms
        .lock()
        .await
        .remove_leave(owner_code_id, room_id, request_id)?;
    let frame = OutboundFrame::MlsLeaveRejected {
        protocol_version: rooms::MLS_PROTOCOL_VERSION,
        room_id: room_id.to_string(),
        request_id: request_id.to_string(),
    };
    for client_id in active_client_ids_for_code(state, &request.code_id).await {
        send_to_client(state, client_id, &frame).await;
    }
    Ok(())
}

fn mls_delivery_frame(delivery: &rooms::PendingDelivery) -> OutboundFrame {
    match &delivery.payload {
        rooms::DeliveryPayload::Membership {
            from_epoch,
            from_membership_digest,
            group_id,
            roster,
            control,
            welcome,
            authenticated_data,
        } => OutboundFrame::MlsMembership {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id: delivery.room_id.clone(),
            message_id: delivery.message_id.clone(),
            from_epoch: *from_epoch,
            to_epoch: delivery.epoch,
            revision: delivery.revision,
            group_id_b64: URL_SAFE_NO_PAD.encode(group_id),
            from_membership_digest_b64: URL_SAFE_NO_PAD.encode(from_membership_digest),
            membership_digest_b64: URL_SAFE_NO_PAD.encode(&delivery.membership_digest),
            roster: roster
                .iter()
                .map(|member| MlsRosterWire {
                    username: member.username.clone(),
                    stable_identity_b64: URL_SAFE_NO_PAD.encode(&member.stable_identity),
                })
                .collect(),
            control_b64: URL_SAFE_NO_PAD.encode(control),
            welcome_b64: URL_SAFE_NO_PAD.encode(welcome),
            authenticated_data_b64: URL_SAFE_NO_PAD.encode(authenticated_data),
        },
        rooms::DeliveryPayload::Application {
            sender_username,
            ciphertext,
            authenticated_data,
            ..
        } => OutboundFrame::MlsApplication {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id: delivery.room_id.clone(),
            message_id: delivery.message_id.clone(),
            sender_username: sender_username.clone(),
            epoch: delivery.epoch,
            revision: delivery.revision,
            membership_digest_b64: URL_SAFE_NO_PAD.encode(&delivery.membership_digest),
            ciphertext_b64: URL_SAFE_NO_PAD.encode(ciphertext),
            authenticated_data_b64: URL_SAFE_NO_PAD.encode(authenticated_data),
        },
    }
}

async fn send_mls_delivery(state: &AppState, delivery: &rooms::PendingDelivery) {
    let active = state
        .mls_rooms
        .lock()
        .await
        .is_active_member(&delivery.room_id, &delivery.recipient_code_id);
    let welcome_delivery = matches!(
        &delivery.payload,
        rooms::DeliveryPayload::Membership { welcome, .. } if !welcome.is_empty()
    );
    if !active && !welcome_delivery {
        return;
    }
    let clients = state
        .clients
        .lock()
        .await
        .iter()
        .filter_map(|(client_id, client)| {
            (client.code_id == delivery.recipient_code_id
                && mls_delivery_allowed(state.interop_policy, &delivery.payload, client.platform))
            .then_some(*client_id)
        })
        .collect::<Vec<_>>();
    let frame = mls_delivery_frame(delivery);
    for client_id in clients {
        send_to_client(state, client_id, &frame).await;
    }
}

async fn send_mls_pending(state: &AppState, client_id: Uuid, code_id: &CodeId) {
    let Some(recipient_platform) = state
        .clients
        .lock()
        .await
        .get(&client_id)
        .map(|client| client.platform)
    else {
        return;
    };
    let room_ids = state
        .mls_rooms
        .lock()
        .await
        .rooms_for_member(code_id)
        .into_iter()
        .map(|room| (room.room_id, room.active))
        .collect::<Vec<_>>();
    let mut deliveries = Vec::new();
    {
        let mut authority = state.mls_rooms.lock().await;
        for (room_id, active) in room_ids {
            if let Ok(room_deliveries) = authority.deliveries_for_member(&room_id, code_id) {
                deliveries.extend(room_deliveries.into_iter().filter(|delivery| {
                    (active
                        || matches!(
                            &delivery.payload,
                            rooms::DeliveryPayload::Membership { welcome, .. } if !welcome.is_empty()
                        ))
                        && mls_delivery_allowed(
                            state.interop_policy,
                            &delivery.payload,
                            recipient_platform,
                        )
                }));
            }
        }
    }
    for delivery in deliveries {
        send_to_client(state, client_id, &mls_delivery_frame(&delivery)).await;
    }
}

async fn send_mls_pending_joins(state: &AppState, client_id: Uuid, code_id: &CodeId) {
    let joins = state
        .mls_rooms
        .lock()
        .await
        .pending_joins_for_owner(code_id);
    for request in joins {
        send_to_client(
            state,
            client_id,
            &OutboundFrame::MlsJoinRequested {
                protocol_version: rooms::MLS_PROTOCOL_VERSION,
                room_id: request.room_id.clone(),
                request_id: request.request_id.clone(),
                username: request.username.clone(),
                stable_identity_b64: URL_SAFE_NO_PAD.encode(request.stable_identity.clone()),
                key_package_b64: URL_SAFE_NO_PAD.encode(request.key_package.clone()),
            },
        )
        .await;
    }
}

async fn send_mls_pending_leaves(state: &AppState, client_id: Uuid, code_id: &CodeId) {
    let (owner_requests, member_requests) = {
        let mut authority = state.mls_rooms.lock().await;
        (
            authority.pending_leaves_for_owner(code_id),
            authority.pending_leaves_for_member(code_id),
        )
    };
    for request in owner_requests {
        send_to_client(
            state,
            client_id,
            &OutboundFrame::MlsLeaveRequested {
                protocol_version: rooms::MLS_PROTOCOL_VERSION,
                room_id: request.room_id.clone(),
                request_id: request.request_id.clone(),
                username: request.username.clone(),
                stable_identity_b64: URL_SAFE_NO_PAD.encode(request.stable_identity.clone()),
            },
        )
        .await;
    }
    for request in member_requests {
        send_to_client(
            state,
            client_id,
            &OutboundFrame::MlsLeavePending {
                protocol_version: rooms::MLS_PROTOCOL_VERSION,
                room_id: request.room_id.clone(),
                request_id: request.request_id.clone(),
            },
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn mls_membership_commit(
    state: &AppState,
    sender_id: Uuid,
    room_id: String,
    message_id: String,
    request_id: Option<String>,
    from_epoch: u64,
    to_epoch: u64,
    revision: u64,
    group_id_b64: String,
    from_membership_digest_b64: String,
    membership_digest_b64: String,
    roster: Vec<MlsRosterWire>,
    control_b64: String,
    welcome_b64: String,
    authenticated_data_b64: String,
    state_envelope_b64: String,
) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    let (owner_code_id, _) = client_identity(state, sender_id).await?;
    let previous_member_code_ids = state
        .mls_rooms
        .lock()
        .await
        .member_code_ids(&room_id)?
        .into_iter()
        .collect::<HashSet<_>>();
    let transition = rooms::MembershipTransition {
        room_id: room_id.clone(),
        message_id: message_id.clone(),
        request_id,
        from_epoch,
        to_epoch,
        revision,
        group_id: decode_exact(&group_id_b64, rooms::GROUP_ID_BYTES)?,
        from_membership_digest: decode_exact(
            &from_membership_digest_b64,
            rooms::MEMBERSHIP_DIGEST_BYTES,
        )?,
        membership_digest: decode_exact(&membership_digest_b64, rooms::MEMBERSHIP_DIGEST_BYTES)?,
        roster: mls_roster_from_wire(roster)?,
        control: decode_bounded(&control_b64, rooms::MAX_CONTROL_BYTES)?,
        welcome: decode_bounded_allow_empty(&welcome_b64, rooms::MAX_CONTROL_BYTES)?,
        authenticated_data: decode_bounded(
            &authenticated_data_b64,
            rooms::MAX_AUTHENTICATED_DATA_BYTES,
        )?,
        state_envelope: decode_bounded(&state_envelope_b64, rooms::MAX_STATE_BYTES)?,
        created_at_ms: 0,
        expires_at_ms: 0,
    };
    let staged = state
        .mls_rooms
        .lock()
        .await
        .begin_membership(owner_code_id, transition)?;
    if let Err(error) = state.mls_rooms.lock().await.accept_membership(
        owner_code_id,
        &room_id,
        &message_id,
        revision,
    ) {
        let _ = state.mls_rooms.lock().await.rollback_membership(
            owner_code_id,
            &room_id,
            &message_id,
            revision,
        );
        return Err(error);
    }
    let recipient_code_ids = state
        .mls_rooms
        .lock()
        .await
        .member_code_ids(&room_id)
        .unwrap_or_default()
        .into_iter()
        .collect::<HashSet<_>>();
    let removed_code_ids = previous_member_code_ids
        .difference(&recipient_code_ids)
        .copied()
        .collect::<Vec<_>>();
    for recipient_code_id in &recipient_code_ids {
        let deliveries = state
            .mls_rooms
            .lock()
            .await
            .deliveries_for_member(&room_id, recipient_code_id)
            .unwrap_or_default();
        for delivery in deliveries
            .into_iter()
            .filter(|delivery| delivery.message_id == staged.message_id)
        {
            send_mls_delivery(state, &delivery).await;
        }
    }
    for removed_code_id in &removed_code_ids {
        revoke_mls_attachment_access(state, &room_id, removed_code_id).await;
        let frame = OutboundFrame::MlsLeft {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id: room_id.clone(),
        };
        for client_id in active_client_ids_for_code(state, removed_code_id).await {
            send_to_client(state, client_id, &frame).await;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn mls_application(
    state: &AppState,
    sender_id: Uuid,
    room_id: String,
    message_id: String,
    group_id_b64: String,
    epoch: u64,
    revision: u64,
    membership_digest_b64: String,
    ciphertext_b64: String,
    authenticated_data_b64: String,
    state_envelope_b64: String,
) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    let (sender_code_id, _, sender_platform) =
        client_identity_and_platform(state, sender_id).await?;
    let staged_attachment_id =
        staged_attachment_for_message(state, &sender_code_id, &room_id, &message_id).await?;
    let admission = state
        .mls_rooms
        .lock()
        .await
        .admit_application_for_platform(
            sender_code_id,
            sender_platform,
            &room_id,
            message_id.clone(),
            decode_exact(&group_id_b64, rooms::GROUP_ID_BYTES)?,
            epoch,
            revision,
            decode_exact(&membership_digest_b64, rooms::MEMBERSHIP_DIGEST_BYTES)?,
            decode_bounded(&ciphertext_b64, rooms::MAX_APPLICATION_CIPHERTEXT_BYTES)?,
            decode_bounded(&authenticated_data_b64, rooms::MAX_AUTHENTICATED_DATA_BYTES)?,
            decode_bounded(&state_envelope_b64, rooms::MAX_STATE_BYTES)?,
        )?;
    if let Err(error) =
        require_recipient_code_platforms(state, sender_platform, &admission.recipient_code_ids)
            .await
    {
        let _ = state
            .mls_rooms
            .lock()
            .await
            .rollback_application(&room_id, &message_id);
        return Err(error);
    }
    let mut attachment_rollback = None;
    if let Some(attachment_id) = staged_attachment_id {
        let application_recipients = admission
            .recipient_code_ids
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        let rollback = match rebind_staged_attachment_recipients(
            state,
            attachment_id,
            &application_recipients,
        )
        .await
        {
            Ok(rollback) => rollback,
            Err(error) => {
                let _ = state
                    .mls_rooms
                    .lock()
                    .await
                    .rollback_application(&room_id, &message_id);
                return Err(error);
            }
        };
        if let Err(error) = publish_staged_attachment_checked(
            state,
            attachment_id,
            &sender_code_id,
            &room_id,
            &message_id,
        )
        .await
        {
            let _ = state
                .mls_rooms
                .lock()
                .await
                .rollback_application(&room_id, &message_id);
            rollback_staged_attachment(state, rollback).await;
            return Err(error);
        }
        attachment_rollback = Some(rollback);
    }
    if let Err(error) = state
        .mls_rooms
        .lock()
        .await
        .commit_application(&room_id, &message_id)
    {
        let _ = state
            .mls_rooms
            .lock()
            .await
            .rollback_application(&room_id, &message_id);
        if let Some(rollback) = attachment_rollback {
            rollback_staged_attachment(state, rollback).await;
        }
        return Err(error);
    }
    for recipient_code_id in &admission.recipient_code_ids {
        let deliveries = state
            .mls_rooms
            .lock()
            .await
            .deliveries_for_member(&room_id, recipient_code_id)
            .unwrap_or_default();
        for delivery in deliveries
            .into_iter()
            .filter(|delivery| delivery.message_id == admission.message_id)
        {
            send_mls_delivery(state, &delivery).await;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn mls_state_snapshot(
    state: &AppState,
    sender_id: Uuid,
    room_id: String,
    message_id: String,
    epoch: u64,
    revision: u64,
    membership_digest_b64: String,
    state_envelope_b64: String,
) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    let (code_id, _) = client_identity(state, sender_id).await?;
    let (_snapshot, was_active) = {
        let mut authority = state.mls_rooms.lock().await;
        let was_active = authority.member_info(&room_id, &code_id)?.active;
        let snapshot = authority.store_snapshot(
            code_id,
            &room_id,
            &message_id,
            epoch,
            revision,
            decode_exact(&membership_digest_b64, rooms::MEMBERSHIP_DIGEST_BYTES)?,
            decode_bounded(&state_envelope_b64, rooms::MAX_STATE_BYTES)?,
        )?;
        (snapshot, was_active)
    };
    // Only Welcome acknowledgement changes the member's delivery capability.
    // Normal ACKs must not replay the already-published active queue.
    if !was_active {
        send_mls_pending(state, sender_id, &code_id).await;
    }
    send_mls_catalog(state, sender_id, &code_id).await;
    Ok(())
}

async fn finish_mls_room_transaction(
    state: &AppState,
    sender_id: Uuid,
    room_id: String,
    message_id: String,
    revision: u64,
    ticket: TransactionTicket,
    result: Result<(), String>,
) -> Result<(), String> {
    let accepted = result.is_ok();
    finish_recoverable_transaction(state, sender_id, ticket, accepted).await?;
    send_mls_room_result(state, sender_id, &room_id, &message_id, revision, accepted).await?;
    if accepted {
        touch_activity(state).await;
    }
    Ok(())
}

async fn finish_mls_snapshot_transaction(
    state: &AppState,
    sender_id: Uuid,
    room_id: String,
    message_id: String,
    revision: u64,
    ticket: TransactionTicket,
    result: Result<(), String>,
) -> Result<(), String> {
    let accepted = result.is_ok();
    finish_recoverable_transaction(state, sender_id, ticket, accepted).await?;
    send_mls_snapshot_result(state, sender_id, &room_id, &message_id, revision, accepted).await?;
    if accepted {
        touch_activity(state).await;
    }
    Ok(())
}

async fn mls_delete_room(state: &AppState, sender_id: Uuid, room_id: &str) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    let (owner_code_id, _) = client_identity(state, sender_id).await?;
    let member_code_ids = state.mls_rooms.lock().await.member_code_ids(room_id)?;
    state
        .mls_rooms
        .lock()
        .await
        .delete(owner_code_id, room_id)?;
    remove_chat_attachments(state, room_id).await;
    let clients = state
        .clients
        .lock()
        .await
        .iter()
        .filter_map(|(client_id, client)| {
            member_code_ids
                .contains(&client.code_id)
                .then_some(*client_id)
        })
        .collect::<Vec<_>>();
    let frame = OutboundFrame::MlsRoomDeleted {
        protocol_version: rooms::MLS_PROTOCOL_VERSION,
        room_id: room_id.to_string(),
    };
    for client_id in clients {
        send_to_client(state, client_id, &frame).await;
    }
    Ok(())
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

async fn client_identity_and_platform(
    state: &AppState,
    client_id: Uuid,
) -> Result<(CodeId, String, ClientPlatform), String> {
    state
        .clients
        .lock()
        .await
        .get(&client_id)
        .map(|client| (client.code_id, client.username.clone(), client.platform))
        .ok_or_else(|| "authenticated client required".to_string())
}

async fn require_recipient_platforms(
    state: &AppState,
    sender_platform: ClientPlatform,
    recipients: &HashSet<String>,
) -> Result<(), String> {
    let accounts = state.accounts.lock().await;
    for recipient in recipients {
        let recipient_platform = accounts
            .values()
            .find(|account| account.username == *recipient)
            .and_then(|account| account.client_platform)
            .ok_or_else(|| "recipient client unavailable".to_string())?;
        if !state
            .interop_policy
            .allows(sender_platform, recipient_platform)
        {
            return Err("client interoperability policy rejected".to_string());
        }
    }
    Ok(())
}

async fn require_recipient_code_platforms(
    state: &AppState,
    sender_platform: ClientPlatform,
    recipients: &[CodeId],
) -> Result<(), String> {
    let accounts = state.accounts.lock().await;
    for recipient in recipients {
        let recipient_platform = accounts
            .get(recipient)
            .and_then(|account| account.client_platform)
            .ok_or_else(|| "recipient client unavailable".to_string())?;
        if !state
            .interop_policy
            .allows(sender_platform, recipient_platform)
        {
            return Err("client interoperability policy rejected".to_string());
        }
    }
    Ok(())
}

fn mls_delivery_allowed(
    policy: InteropPolicy,
    payload: &rooms::DeliveryPayload,
    recipient_platform: ClientPlatform,
) -> bool {
    match payload {
        rooms::DeliveryPayload::Application {
            sender_platform, ..
        } => policy.allows(*sender_platform, recipient_platform),
        rooms::DeliveryPayload::Membership { .. } => true,
    }
}

#[allow(dead_code)]
fn owned_room_count(catalog: &HashMap<String, RoomEntry>, owner_code_id: &CodeId) -> usize {
    catalog
        .values()
        .filter(|entry| entry.owner_code_id == *owner_code_id)
        .count()
}

#[allow(dead_code)]
fn has_room_capacity(
    catalog: &HashMap<String, RoomEntry>,
    owner_code_id: &CodeId,
    max_rooms_per_user: usize,
) -> bool {
    owned_room_count(catalog, owner_code_id) < max_rooms_per_user
}

#[allow(dead_code)]
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
    // Presence computation and fanout are one ordered operation. Without this
    // guard, concurrent connect/disconnect broadcasts could enqueue an older
    // snapshot after a newer directory revision and force strict clients to
    // fail closed on an honest relay.
    let _broadcast_guard = state.presence_broadcast_ops.lock().await;
    let accounts = state.accounts.lock().await;
    let stamp = directory_stamp(&state.node_id, &accounts);
    let users = accounts
        .values()
        .map(|account| PresenceUser {
            username: account.username.clone(),
            connected: account.connected,
            identity_public_b64: URL_SAFE_NO_PAD.encode(&account.identity_public),
            identity_prekey_id: account.prekey_id.clone(),
            directory_digest: stamp.digest.clone(),
            directory_node_id: stamp.node_id.clone(),
            directory_revision: stamp.revision,
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

#[cfg(test)]
fn identity_directory_digest(accounts: &HashMap<CodeId, Account>) -> String {
    // Kept for existing in-module tests and callers. Production presence uses
    // the V2 transcript below, bound to the relay node and account revision.
    identity_directory_digest_v2("", accounts.len() as u64, accounts)
}

fn directory_stamp(node_id: &str, accounts: &HashMap<CodeId, Account>) -> DirectoryStamp {
    let revision = (accounts.len() as u64).clamp(1, MAX_DIRECTORY_REVISION);
    directory_stamp_at_revision(node_id, revision, accounts)
}

fn directory_stamp_at_revision(
    node_id: &str,
    revision: u64,
    accounts: &HashMap<CodeId, Account>,
) -> DirectoryStamp {
    DirectoryStamp {
        node_id: node_id.to_string(),
        revision: revision.clamp(1, MAX_DIRECTORY_REVISION),
        digest: identity_directory_digest_v2(node_id, revision, accounts),
    }
}

fn discarded_dummy_hint(padding_b64: Option<&str>, bytes: Option<usize>) -> usize {
    padding_b64
        .map(str::len)
        .unwrap_or_default()
        .saturating_add(bytes.unwrap_or_default())
}

fn identity_directory_digest_v2(
    node_id: &str,
    revision: u64,
    accounts: &HashMap<CodeId, Account>,
) -> String {
    let mut entries = accounts
        .values()
        .filter(|account| account.identity_public.len() >= IDENTITY_FINGERPRINT_BYTES)
        .map(|account| {
            (
                account.username.clone(),
                Zeroizing::new(account.identity_public[..IDENTITY_FINGERPRINT_BYTES].to_vec()),
            )
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let mut digest = Sha256::new();
    digest.update(b"ABYSSAL_DIRECTORY_CHECKPOINT_V2");
    digest.update((node_id.len() as u32).to_be_bytes());
    digest.update(node_id.as_bytes());
    digest.update(revision.to_be_bytes());
    digest.update((entries.len() as u32).to_be_bytes());
    for (username, identity_public) in entries {
        digest.update((username.len() as u32).to_be_bytes());
        digest.update(username.as_bytes());
        digest.update(&identity_public);
    }
    URL_SAFE_NO_PAD.encode(digest.finalize())
}

#[allow(dead_code)]
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

fn inbound_recipient_envelope_wire_len(envelope: &InboundRecipientEnvelope) -> Option<usize> {
    json_object_len(&[
        json_string_field_len("recipient_username", &envelope.recipient_username)?,
        json_string_field_len("wrapped_key_b64", &envelope.wrapped_key_b64)?,
        json_string_field_len("prekey_id", &envelope.prekey_id)?,
        json_field_len("is_prekey", json_bool_len(envelope.is_prekey))?,
        json_string_field_len("signature_b64", &envelope.signature_b64)?,
    ])
}

#[allow(clippy::too_many_arguments)]
fn inbound_message_wire_len(
    chat_id: &str,
    version: u32,
    message_id: &str,
    nonce_b64: &str,
    ciphertext_b64: &str,
    envelopes: &[InboundRecipientEnvelope],
    state_revision: u64,
    identity_envelope_b64: &str,
    identity_public_b64: &str,
    prekey_id: &str,
    state_signature_b64: &str,
    directory_node_id: &str,
    directory_revision: u64,
    directory_digest: &str,
    padding_bucket: usize,
    padding: &str,
) -> Option<usize> {
    let envelopes_len = json_array_len(envelopes.iter().map(inbound_recipient_envelope_wire_len))?;
    json_object_len(&[
        json_string_field_len("type", "message")?,
        json_string_field_len("chat_id", chat_id)?,
        json_field_len("version", json_number_len(version)?)?,
        json_string_field_len("message_id", message_id)?,
        json_string_field_len("nonce_b64", nonce_b64)?,
        json_string_field_len("ciphertext_b64", ciphertext_b64)?,
        json_field_len("envelopes", envelopes_len)?,
        json_field_len("state_revision", json_number_len(state_revision)?)?,
        json_string_field_len("identity_envelope_b64", identity_envelope_b64)?,
        json_string_field_len("identity_public_b64", identity_public_b64)?,
        json_string_field_len("prekey_id", prekey_id)?,
        json_string_field_len("state_signature_b64", state_signature_b64)?,
        json_string_field_len("directory_node_id", directory_node_id)?,
        json_field_len("directory_revision", json_number_len(directory_revision)?)?,
        json_string_field_len("directory_digest", directory_digest)?,
        json_field_len("padding_bucket", json_number_len(padding_bucket)?)?,
        json_string_field_len("padding", padding)?,
    ])
}

fn validate_inbound_message_padding(text: &str, frame: &InboundFrame) -> Result<(), String> {
    let InboundFrame::Message {
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
        directory_node_id,
        directory_revision,
        directory_digest,
        padding_bucket,
        padding,
    } = frame
    else {
        return Ok(());
    };
    if text.len() > MESSAGE_TRANSPORT_MAX_BUCKET || !valid_message_transport_padding(padding) {
        return Err("message transport padding rejected".to_string());
    }
    let canonical = MESSAGE_TRANSPORT_BUCKETS.iter().find_map(|bucket| {
        inbound_message_wire_len(
            chat_id,
            *version,
            message_id,
            nonce_b64,
            ciphertext_b64,
            envelopes,
            *state_revision,
            identity_envelope_b64,
            identity_public_b64,
            prekey_id,
            state_signature_b64,
            directory_node_id,
            *directory_revision,
            directory_digest,
            *bucket,
            "",
        )
        .filter(|empty_len| *empty_len <= *bucket)
        .map(|empty_len| (*bucket, empty_len))
    });
    let Some((canonical_bucket, empty_len)) = canonical else {
        return Err("message transport padding unavailable".to_string());
    };
    if *padding_bucket != canonical_bucket {
        return Err("message transport padding bucket rejected".to_string());
    }
    let expected_padding_len = canonical_bucket
        .checked_sub(empty_len)
        .ok_or_else(|| "message transport padding length rejected".to_string())?;
    if padding.len() != expected_padding_len {
        return Err("message transport padding length rejected".to_string());
    }
    let serialized_len = inbound_message_wire_len(
        chat_id,
        *version,
        message_id,
        nonce_b64,
        ciphertext_b64,
        envelopes,
        *state_revision,
        identity_envelope_b64,
        identity_public_b64,
        prekey_id,
        state_signature_b64,
        directory_node_id,
        *directory_revision,
        directory_digest,
        *padding_bucket,
        padding,
    )
    .ok_or_else(|| "message transport padding serialization failed".to_string())?;
    if serialized_len != canonical_bucket || text.len() != canonical_bucket {
        return Err("message transport padding length rejected".to_string());
    }
    Ok(())
}

fn outbound_message_wire_len(
    frame: &OutboundFrame,
    padding_bucket: usize,
    padding: &str,
) -> Option<usize> {
    let OutboundFrame::Message {
        chat_id,
        version,
        message_id,
        nonce_b64,
        ciphertext_b64,
        signature_b64,
        wrapped_key_b64,
        prekey_id,
        is_prekey,
        sender_username,
        sender_public_key_b64,
        identity_public_b64,
        directory_node_id,
        directory_revision,
        directory_digest,
        ..
    } = frame
    else {
        return None;
    };
    json_object_len(&[
        json_string_field_len("type", "message")?,
        json_string_field_len("chat_id", chat_id)?,
        json_field_len("version", json_number_len(*version)?)?,
        json_string_field_len("message_id", message_id)?,
        json_string_field_len("nonce_b64", nonce_b64)?,
        json_string_field_len("ciphertext_b64", ciphertext_b64)?,
        json_string_field_len("signature_b64", signature_b64)?,
        json_string_field_len("wrapped_key_b64", wrapped_key_b64)?,
        json_string_field_len("prekey_id", prekey_id)?,
        json_field_len("is_prekey", json_bool_len(*is_prekey))?,
        json_string_field_len("sender_username", sender_username)?,
        json_string_field_len("sender_public_key_b64", sender_public_key_b64)?,
        json_string_field_len("identity_public_b64", identity_public_b64)?,
        json_string_field_len("directory_node_id", directory_node_id)?,
        json_field_len("directory_revision", json_number_len(*directory_revision)?)?,
        json_string_field_len("directory_digest", directory_digest)?,
        json_field_len("padding_bucket", json_number_len(padding_bucket)?)?,
        json_string_field_len("padding", padding)?,
    ])
}

fn canonical_outbound_message_bucket(frame: &OutboundFrame) -> Option<(usize, usize)> {
    MESSAGE_TRANSPORT_BUCKETS.iter().find_map(|bucket| {
        outbound_message_wire_len(frame, *bucket, "")
            .filter(|empty_len| *empty_len <= *bucket)
            .map(|empty_len| (*bucket, empty_len))
    })
}

fn outbound_message_padding_is_canonical(frame: &OutboundFrame, serialized_len: usize) -> bool {
    let OutboundFrame::Message {
        padding_bucket,
        padding,
        ..
    } = frame
    else {
        return true;
    };
    if !MESSAGE_TRANSPORT_BUCKETS.contains(padding_bucket)
        || !valid_message_transport_padding(padding)
    {
        return false;
    }
    let Some((canonical_bucket, empty_len)) = canonical_outbound_message_bucket(frame) else {
        return false;
    };
    let Some(expected_padding_len) = canonical_bucket.checked_sub(empty_len) else {
        return false;
    };
    *padding_bucket == canonical_bucket
        && expected_padding_len == padding.len()
        && serialized_len == canonical_bucket
}

fn prepare_outbound_message_padding(frame: &mut OutboundFrame) -> Result<(), String> {
    if let OutboundFrame::Message {
        padding_bucket,
        padding,
        ..
    } = frame
    {
        padding.zeroize();
        *padding_bucket = 0;
    } else {
        return Ok(());
    }
    let Some((canonical_bucket, empty_len)) = canonical_outbound_message_bucket(frame) else {
        return Err("message transport padding unavailable".to_string());
    };
    let filler_len = canonical_bucket
        .checked_sub(empty_len)
        .ok_or_else(|| "message transport padding length rejected".to_string())?;
    let filler = random_message_transport_padding(filler_len)?;
    if let OutboundFrame::Message {
        padding_bucket,
        padding,
        ..
    } = frame
    {
        *padding_bucket = canonical_bucket;
        *padding = filler;
    }
    let serialized_len = serde_json::to_string(frame)
        .ok()
        .map(|serialized| serialized.len())
        .ok_or_else(|| "message transport padding serialization failed".to_string())?;
    if serialized_len != canonical_bucket {
        if let OutboundFrame::Message {
            padding_bucket,
            padding,
            ..
        } = frame
        {
            padding.zeroize();
            *padding_bucket = 0;
        }
        return Err("message transport padding length rejected".to_string());
    }
    Ok(())
}

fn serialize_outbound_frame(frame: &OutboundFrame) -> Option<String> {
    let serialized = serde_json::to_string(frame).ok()?;
    if !outbound_message_padding_is_canonical(frame, serialized.len()) {
        return None;
    }
    if matches!(frame, OutboundFrame::Message { .. }) {
        return (serialized.len() <= MESSAGE_TRANSPORT_MAX_BUCKET).then_some(serialized);
    }
    let domain_limit = if frame.is_mls() {
        MLS_WS_MAX_FRAME_BYTES
    } else {
        WS_MAX_FRAME_BYTES
    };
    pad_control_transport_frame(&serialized, domain_limit).ok()
}

fn outbound_queue_bytes(frame: &OutboundFrame) -> usize {
    if matches!(frame, OutboundFrame::Message { .. }) {
        return outbound_frame_bytes(frame);
    }
    serde_json::to_string(frame)
        .ok()
        .and_then(|serialized| {
            let domain_limit = if frame.is_mls() {
                MLS_WS_MAX_FRAME_BYTES
            } else {
                WS_MAX_FRAME_BYTES
            };
            control_transport_frame_len(&serialized, domain_limit)
        })
        .unwrap_or_else(|| {
            if frame.is_mls() {
                CONTROL_TRANSPORT_MAX_BUCKET.saturating_add(1)
            } else {
                WS_MAX_FRAME_BYTES.saturating_add(1)
            }
        })
}

fn reserve_outbound_bytes(
    global: &AtomicUsize,
    local: &AtomicUsize,
    bytes: usize,
    limit: usize,
) -> bool {
    let bytes = bytes.max(1);
    let mut local_current = local.load(Ordering::Acquire);
    loop {
        let Some(local_next) = local_current.checked_add(bytes) else {
            return false;
        };
        if local_next > limit {
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

async fn close_client_transport(state: &AppState, client_id: Uuid) {
    let control_tx = state
        .clients
        .lock()
        .await
        .get(&client_id)
        .map(|client| client.control_tx.clone());
    if let Some(control_tx) = control_tx {
        let _ = control_tx.try_send(ClientControl::Close);
    }
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

async fn send_mls_room_result(
    state: &AppState,
    client_id: Uuid,
    room_id: &str,
    message_id: &str,
    revision: u64,
    accepted: bool,
) -> Result<(), String> {
    send_client_result(
        state,
        client_id,
        OutboundFrame::MlsRoomResult {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id: room_id.to_string(),
            message_id: message_id.to_string(),
            revision,
            accepted,
        },
    )
    .await
}

async fn send_mls_snapshot_result(
    state: &AppState,
    client_id: Uuid,
    room_id: &str,
    message_id: &str,
    revision: u64,
    accepted: bool,
) -> Result<(), String> {
    send_client_result(
        state,
        client_id,
        OutboundFrame::MlsSnapshotResult {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id: room_id.to_string(),
            message_id: message_id.to_string(),
            revision,
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
        close_client_transport(state, client_id).await;
        return Err("client result channel unavailable".to_string());
    }
    let delivered = tokio::time::timeout(CLIENT_RESULT_SEND_TIMEOUT, delivered)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(false);
    if !delivered {
        close_client_transport(state, client_id).await;
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
    let (frame_limit, queue_limit) = if frame.is_mls() {
        (CONTROL_TRANSPORT_MAX_BUCKET, MLS_CLIENT_OUTBOUND_BYTES)
    } else {
        (WS_MAX_FRAME_BYTES, CLIENT_OUTBOUND_BYTES)
    };
    if bytes > frame_limit
        || !reserve_outbound_bytes(&state.outbound_bytes, &queued_bytes, bytes, queue_limit)
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
    fn attachment_limits_budget_fixed_authenticated_chunks() {
        let image_limit = max_serialized_attachment_bytes("IMAGE");
        let video_limit = max_serialized_attachment_bytes("VIDEO");
        let file_limit = max_serialized_attachment_bytes("FILE");
        assert_eq!(
            image_limit,
            attachment_encrypted_size("IMAGE".to_string(), IMAGE_ATTACHMENT_LIMIT_BYTES as u64)
                .expect("image wire limit") as usize
        );
        assert_eq!(
            video_limit,
            attachment_encrypted_size("VIDEO".to_string(), VIDEO_ATTACHMENT_LIMIT_BYTES as u64)
                .expect("video wire limit") as usize
        );
        assert_eq!(
            file_limit,
            attachment_encrypted_size("FILE".to_string(), FILE_ATTACHMENT_LIMIT_BYTES as u64)
                .expect("file wire limit") as usize
        );
        assert!(file_limit > FILE_ATTACHMENT_LIMIT_BYTES);
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
    fn directory_node_ids_match_the_client_protocol_boundary() {
        assert!(valid_node_id("abyssal-node_1:primary"));
        assert!(!valid_node_id(""));
        assert!(!valid_node_id("node with spaces"));
        assert!(!valid_node_id(&"n".repeat(MAX_NODE_ID_BYTES + 1)));
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
                        challenge: Zeroizing::new(vec![0; REGISTRATION_CHALLENGE_BYTES_V9]),
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
                    challenge: Zeroizing::new(vec![0; REGISTRATION_CHALLENGE_BYTES_V9]),
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
                challenge: Zeroizing::new(vec![0; REGISTRATION_CHALLENGE_BYTES_V9]),
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
    fn encrypted_attachment_body_requires_complete_ordered_v2_records() {
        assert!(!valid_encrypted_attachment_body("FILE", &[]));
        assert!(!valid_encrypted_attachment_body(
            "FILE",
            &[ATTACHMENT_BLOB_VERSION; ATTACHMENT_CHUNK_RECORD_BYTES - 1]
        ));
        assert!(!valid_encrypted_attachment_body(
            "FILE",
            &[0; ATTACHMENT_CHUNK_RECORD_BYTES]
        ));
        let valid = test_valid_encrypted_attachment_body(1);
        assert!(valid_encrypted_attachment_body("FILE", &valid));
        let mut bad_index = valid.clone();
        bad_index[4] = 1;
        assert!(!valid_encrypted_attachment_body("FILE", &bad_index));
    }

    #[tokio::test]
    async fn staged_attachment_rebind_rejects_empty_roster_without_mutation() {
        let state = test_state();
        let owner = test_code_id("rebind-empty-owner");
        let recipient = test_code_id("rebind-empty-recipient");
        let attachment_id = Uuid::new_v4();
        {
            let mut attachments = state.attachments.lock().await;
            attachments.insert(
                attachment_id,
                AttachmentRecord {
                    blob: test_attachment_blob(vec![1]),
                    chat_id: "mls-rebind".to_string(),
                    message_id: "application-1".to_string(),
                    media_type: "FILE".to_string(),
                    owner_code_id: owner,
                    sender_platform: ClientPlatform::Android,
                    published: false,
                    staged_expires_at_ms: Some(now_ms().saturating_add(60_000)),
                    one_time: true,
                    delete_after_download: false,
                    expires_at_ms: None,
                    eligible_recipient_code_ids: HashSet::from([recipient]),
                    download_claims: HashMap::new(),
                    completed_recipient_code_ids: HashSet::new(),
                },
            );
        }
        assert!(
            rebind_staged_attachment_recipients(&state, attachment_id, &HashSet::new())
                .await
                .is_err()
        );
        assert_eq!(
            state
                .attachments
                .lock()
                .await
                .get(&attachment_id)
                .expect("staged attachment")
                .eligible_recipient_code_ids,
            HashSet::from([recipient])
        );
    }

    #[tokio::test]
    async fn staged_attachment_requires_a_live_deadline_for_publication() {
        let state = test_state();
        let owner = test_code_id("staged-deadline-owner");
        let now = now_ms();
        let missing_deadline = Uuid::new_v4();
        let expired_deadline = Uuid::new_v4();
        let valid_deadline = Uuid::new_v4();
        let records = [
            (missing_deadline, "missing-deadline", None, vec![1_u8, 2]),
            (
                expired_deadline,
                "expired-deadline",
                Some(now.saturating_sub(1)),
                vec![3_u8, 4],
            ),
            (
                valid_deadline,
                "valid-deadline",
                Some(now.saturating_add(60_000)),
                vec![5_u8, 6],
            ),
        ];
        {
            let mut bindings = state.attachment_bindings.lock().await;
            let mut attachments = state.attachments.lock().await;
            for (id, message_id, staged_expires_at_ms, bytes) in records {
                attachments.insert(
                    id,
                    AttachmentRecord {
                        blob: test_attachment_blob(bytes),
                        chat_id: "dm_staged".to_string(),
                        message_id: message_id.to_string(),
                        media_type: "FILE".to_string(),
                        owner_code_id: owner,
                        sender_platform: ClientPlatform::Android,
                        published: false,
                        staged_expires_at_ms,
                        one_time: false,
                        delete_after_download: false,
                        expires_at_ms: Some(now.saturating_add(60_000)),
                        eligible_recipient_code_ids: HashSet::new(),
                        download_claims: HashMap::new(),
                        completed_recipient_code_ids: HashSet::new(),
                    },
                );
                bindings.insert(
                    AttachmentBindingKey::new(&owner, "dm_staged", message_id),
                    id,
                );
            }
        }
        state.attachment_bytes_by_code.lock().await.insert(owner, 6);

        prune_expired_attachments(&state).await;
        let attachments = state.attachments.lock().await;
        assert!(!attachments.contains_key(&missing_deadline));
        assert!(!attachments.contains_key(&expired_deadline));
        assert!(attachments.contains_key(&valid_deadline));
        drop(attachments);
        let bindings = state.attachment_bindings.lock().await;
        assert!(!bindings.contains_key(&AttachmentBindingKey::new(
            &owner,
            "dm_staged",
            "missing-deadline",
        )));
        assert!(!bindings.contains_key(&AttachmentBindingKey::new(
            &owner,
            "dm_staged",
            "expired-deadline",
        )));
        assert_eq!(
            bindings.get(&AttachmentBindingKey::new(
                &owner,
                "dm_staged",
                "valid-deadline",
            )),
            Some(&valid_deadline)
        );
        drop(bindings);

        assert_eq!(
            staged_attachment_for_message(&state, &owner, "dm_staged", "valid-deadline").await,
            Ok(Some(valid_deadline))
        );
        publish_staged_attachment(
            &state,
            valid_deadline,
            &owner,
            "dm_staged",
            "valid-deadline",
        )
        .await;
        let attachments = state.attachments.lock().await;
        let published = attachments
            .get(&valid_deadline)
            .expect("valid staged record");
        assert!(published.published);
        assert_eq!(published.staged_expires_at_ms, None);
        assert_eq!(
            state.attachment_bytes_by_code.lock().await.get(&owner),
            Some(&2)
        );
    }

    #[tokio::test]
    async fn staged_message_lookup_only_expires_the_exact_indexed_record() {
        let state = test_state();
        let owner = test_code_id("staged-exact-lookup-owner");
        let exact_id = Uuid::new_v4();
        let unrelated_id = Uuid::new_v4();
        let now = now_ms();
        {
            let mut bindings = state.attachment_bindings.lock().await;
            let mut attachments = state.attachments.lock().await;
            attachments.insert(
                exact_id,
                AttachmentRecord {
                    blob: Arc::new(AttachmentBlob {
                        bytes: Zeroizing::new(vec![1, 2, 3]),
                        _memory_permit: Some(
                            acquire_attachment_memory_permit(&state.attachment_memory, 3)
                                .expect("exact attachment memory permit"),
                        ),
                    }),
                    chat_id: "dm_exact_lookup".to_string(),
                    message_id: "exact-message".to_string(),
                    media_type: "FILE".to_string(),
                    owner_code_id: owner,
                    sender_platform: ClientPlatform::Android,
                    published: false,
                    staged_expires_at_ms: Some(now.saturating_add(60_000)),
                    one_time: false,
                    delete_after_download: false,
                    expires_at_ms: Some(now.saturating_add(60_000)),
                    eligible_recipient_code_ids: HashSet::new(),
                    download_claims: HashMap::new(),
                    completed_recipient_code_ids: HashSet::new(),
                },
            );
            attachments.insert(
                unrelated_id,
                AttachmentRecord {
                    blob: test_attachment_blob(vec![4, 5, 6]),
                    chat_id: "dm_exact_lookup".to_string(),
                    message_id: "unrelated-message".to_string(),
                    media_type: "FILE".to_string(),
                    owner_code_id: owner,
                    sender_platform: ClientPlatform::Android,
                    published: false,
                    staged_expires_at_ms: Some(now.saturating_sub(1)),
                    one_time: false,
                    delete_after_download: false,
                    expires_at_ms: Some(now.saturating_add(60_000)),
                    eligible_recipient_code_ids: HashSet::new(),
                    download_claims: HashMap::new(),
                    completed_recipient_code_ids: HashSet::new(),
                },
            );
            bindings.insert(
                AttachmentBindingKey::new(&owner, "dm_exact_lookup", "exact-message"),
                exact_id,
            );
            bindings.insert(
                AttachmentBindingKey::new(&owner, "dm_exact_lookup", "unrelated-message"),
                unrelated_id,
            );
        }
        state.attachment_bytes_by_code.lock().await.insert(owner, 6);

        assert_eq!(
            staged_attachment_for_message(&state, &owner, "dm_exact_lookup", "exact-message").await,
            Ok(Some(exact_id))
        );
        assert_eq!(
            state.attachment_memory.available_permits(),
            8 * 1024 * 1024 - 3
        );
        assert!(state.attachments.lock().await.contains_key(&unrelated_id));
        assert_eq!(
            state
                .attachment_bindings
                .lock()
                .await
                .get(&AttachmentBindingKey::new(
                    &owner,
                    "dm_exact_lookup",
                    "unrelated-message",
                )),
            Some(&unrelated_id)
        );

        state
            .attachments
            .lock()
            .await
            .get_mut(&exact_id)
            .expect("exact staged record")
            .staged_expires_at_ms = Some(now_ms().saturating_sub(1));
        assert_eq!(
            staged_attachment_for_message(&state, &owner, "dm_exact_lookup", "exact-message").await,
            Ok(None)
        );
        assert!(!state.attachments.lock().await.contains_key(&exact_id));
        assert!(state.attachments.lock().await.contains_key(&unrelated_id));
        assert_eq!(
            state
                .attachment_bindings
                .lock()
                .await
                .get(&AttachmentBindingKey::new(
                    &owner,
                    "dm_exact_lookup",
                    "unrelated-message",
                )),
            Some(&unrelated_id)
        );
        assert_eq!(
            state.attachment_bytes_by_code.lock().await.get(&owner),
            Some(&3)
        );
        assert_eq!(state.attachment_memory.available_permits(), 8 * 1024 * 1024);
    }

    #[tokio::test]
    async fn attachment_upload_requires_message_binding_and_rejects_live_duplicate() {
        let state = test_state();
        add_test_account(&state, "staged-upload-owner", "Alice").await;
        let owner = test_code_id("staged-upload-owner");
        let room_id = "staged_upload_room";
        state.room_catalog.lock().await.insert(
            room_id.to_string(),
            RoomEntry {
                room: test_room(room_id),
                owner_code_id: owner,
            },
        );
        state.sessions.lock().await.insert(
            SessionToken::new("staged-upload-token".to_string()),
            AuthSession {
                code_id: owner,
                username: "Alice".to_string(),
                last_activity_ms: now_ms(),
            },
        );

        let upload = |message_id: &'static str| {
            let body = test_valid_encrypted_attachment_body(1);
            let mut headers = HeaderMap::new();
            headers.insert(
                header::AUTHORIZATION,
                HeaderValue::from_static("Bearer staged-upload-token"),
            );
            headers.insert(
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&body.len().to_string()).expect("content length"),
            );
            upload_attachment(
                State(state.clone()),
                Query(AttachmentQuery {
                    chat_id: room_id.to_string(),
                    message_id: message_id.to_string(),
                    media_type: Some("FILE".to_string()),
                    one_time: Some(false),
                    delete_after_download: Some(false),
                    ttl_sec: Some(1),
                }),
                headers,
                Body::from(body),
            )
        };

        assert_eq!(
            upload("").await.into_response().status(),
            StatusCode::BAD_REQUEST
        );
        assert!(state.attachments.lock().await.is_empty());
        assert_eq!(
            upload("staged-upload-message")
                .await
                .into_response()
                .status(),
            StatusCode::OK
        );
        let (attachment_id, original_expiry) = {
            let attachments = state.attachments.lock().await;
            let (id, record) = attachments.iter().next().expect("staged upload");
            assert!(!record.published);
            assert!(
                record.staged_expires_at_ms.expect("staging deadline")
                    <= record.expires_at_ms.expect("retention deadline")
            );
            (*id, record.expires_at_ms)
        };
        assert_eq!(
            upload("staged-upload-message")
                .await
                .into_response()
                .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(state.attachments.lock().await.len(), 1);

        publish_staged_attachment(
            &state,
            attachment_id,
            &owner,
            room_id,
            "staged-upload-message",
        )
        .await;
        let attachments = state.attachments.lock().await;
        let published = attachments.get(&attachment_id).expect("published upload");
        assert!(published.published);
        assert_eq!(published.expires_at_ms, original_expiry);
    }

    #[tokio::test]
    async fn staged_attachment_is_a_generic_not_found_to_owner_and_recipient() {
        let state = test_state();
        add_test_account(&state, "staged-download-owner", "Alice").await;
        add_test_account(&state, "staged-download-recipient", "Bob").await;
        let owner = test_code_id("staged-download-owner");
        let room_id = "staged_download_room";
        state.room_catalog.lock().await.insert(
            room_id.to_string(),
            RoomEntry {
                room: test_room(room_id),
                owner_code_id: owner,
            },
        );
        state.sessions.lock().await.extend([
            (
                SessionToken::new("staged-owner-token".to_string()),
                AuthSession {
                    code_id: owner,
                    username: "Alice".to_string(),
                    last_activity_ms: now_ms(),
                },
            ),
            (
                SessionToken::new("staged-recipient-token".to_string()),
                AuthSession {
                    code_id: test_code_id("staged-download-recipient"),
                    username: "Bob".to_string(),
                    last_activity_ms: now_ms(),
                },
            ),
        ]);
        let attachment_id = Uuid::new_v4();
        state.attachments.lock().await.insert(
            attachment_id,
            AttachmentRecord {
                blob: test_attachment_blob(test_valid_encrypted_attachment_body(1)),
                chat_id: room_id.to_string(),
                message_id: "staged-download-message".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                sender_platform: ClientPlatform::Android,
                published: false,
                staged_expires_at_ms: Some(now_ms().saturating_add(60_000)),
                one_time: false,
                delete_after_download: false,
                expires_at_ms: Some(now_ms().saturating_add(60_000)),
                eligible_recipient_code_ids: HashSet::new(),
                download_claims: HashMap::new(),
                completed_recipient_code_ids: HashSet::new(),
            },
        );
        state.attachment_bindings.lock().await.insert(
            AttachmentBindingKey::new(&owner, room_id, "staged-download-message"),
            attachment_id,
        );

        for token in ["staged-owner-token", "staged-recipient-token"] {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {token}")).expect("test bearer"),
            );
            let response = download_attachment(State(state.clone()), Path(attachment_id), headers)
                .await
                .into_response();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
    }

    #[tokio::test]
    async fn staged_publication_is_exactly_bound_and_rejected_or_rolled_back_admission_never_promotes(
    ) {
        let state = test_state();
        add_test_account(&state, "publication-owner", "Alice").await;
        add_test_account(&state, "publication-other", "Bob").await;
        let (alice_id, _) = add_test_client(&state, "publication-owner", "Alice").await;
        let room_id = "staged_publication_room";
        state.room_catalog.lock().await.insert(
            room_id.to_string(),
            RoomEntry {
                room: test_room(room_id),
                owner_code_id: test_code_id("publication-owner"),
            },
        );
        let now = now_ms();
        let bindings = [
            (
                "matching",
                test_code_id("publication-owner"),
                room_id,
                "publication-message",
            ),
            (
                "wrong-owner",
                test_code_id("publication-other"),
                room_id,
                "publication-message",
            ),
            (
                "wrong-chat",
                test_code_id("publication-owner"),
                "other-publication-room",
                "publication-message",
            ),
            (
                "wrong-message",
                test_code_id("publication-owner"),
                room_id,
                "other-publication-message",
            ),
        ];
        let mut ids = HashMap::new();
        {
            let mut attachment_bindings = state.attachment_bindings.lock().await;
            let mut attachments = state.attachments.lock().await;
            for (label, owner, chat_id, message_id) in bindings {
                let id = Uuid::new_v4();
                ids.insert(label, id);
                attachments.insert(
                    id,
                    AttachmentRecord {
                        blob: test_attachment_blob(vec![1, 2]),
                        chat_id: chat_id.to_string(),
                        message_id: message_id.to_string(),
                        media_type: "FILE".to_string(),
                        owner_code_id: owner,
                        sender_platform: ClientPlatform::Android,
                        published: false,
                        staged_expires_at_ms: Some(now.saturating_add(60_000)),
                        one_time: false,
                        delete_after_download: false,
                        expires_at_ms: Some(now.saturating_add(60_000)),
                        eligible_recipient_code_ids: HashSet::new(),
                        download_claims: HashMap::new(),
                        completed_recipient_code_ids: HashSet::new(),
                    },
                );
                attachment_bindings
                    .insert(AttachmentBindingKey::new(&owner, chat_id, message_id), id);
            }
        }

        assert!(route_test_message_with_envelopes(
            &state,
            alice_id,
            room_id,
            E2EE_PROTOCOL_VERSION,
            "publication-message",
            Vec::new(),
        )
        .await
        .is_err());
        assert!(state
            .attachments
            .lock()
            .await
            .values()
            .all(|record| !record.published));

        state.replay_ids.lock().await.insert(
            ReplayKey {
                chat_id: room_id.to_string(),
                sender_username: "Alice".to_string(),
                message_id: "publication-message".to_string(),
            },
            now_ms(),
        );
        assert!(route_test_message_with_id(
            &state,
            alice_id,
            room_id,
            &["Bob"],
            "publication-message",
        )
        .await
        .is_err());
        assert!(state
            .attachments
            .lock()
            .await
            .values()
            .all(|record| !record.published));
        state.replay_ids.lock().await.clear();

        route_test_message_with_id(&state, alice_id, room_id, &["Bob"], "publication-message")
            .await
            .expect("exact accepted message publishes attachment");
        let attachments = state.attachments.lock().await;
        assert!(attachments[&ids["matching"]].published);
        assert!(!attachments[&ids["wrong-owner"]].published);
        assert!(!attachments[&ids["wrong-chat"]].published);
        assert!(!attachments[&ids["wrong-message"]].published);
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
                message_id: "test-message".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                sender_platform: ClientPlatform::Android,
                published: true,
                staged_expires_at_ms: None,
                one_time: false,
                delete_after_download: false,
                expires_at_ms: None,
                eligible_recipient_code_ids: HashSet::new(),
                download_claims: HashMap::new(),
                completed_recipient_code_ids: HashSet::new(),
            },
        );
        state.attachment_bindings.lock().await.insert(
            AttachmentBindingKey::new(&owner, "dm_cleanup", "test-message"),
            attachment_id,
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
        assert!(state.attachment_bindings.lock().await.is_empty());
        assert!(state.attachment_bytes_by_code.lock().await.is_empty());
        assert!(attachment_record_capacity_available(&state, &owner).await);
    }

    #[tokio::test]
    async fn attachment_binding_index_cleans_destructive_completion() {
        let state = test_state();
        let owner = test_code_id("binding-completion-owner");
        let recipient = test_code_id("binding-completion-recipient");
        let attachment_id = Uuid::new_v4();
        let claim_id = Uuid::new_v4();
        {
            let mut bindings = state.attachment_bindings.lock().await;
            let mut attachments = state.attachments.lock().await;
            attachments.insert(
                attachment_id,
                AttachmentRecord {
                    blob: test_attachment_blob(vec![1, 2, 3]),
                    chat_id: "dm_binding_completion".to_string(),
                    message_id: "binding-completion-message".to_string(),
                    media_type: "FILE".to_string(),
                    owner_code_id: owner,
                    sender_platform: ClientPlatform::Android,
                    published: true,
                    staged_expires_at_ms: None,
                    one_time: true,
                    delete_after_download: true,
                    expires_at_ms: None,
                    eligible_recipient_code_ids: HashSet::from([recipient]),
                    download_claims: HashMap::from([(
                        claim_id,
                        AttachmentDownloadClaim {
                            recipient_code_id: recipient,
                            created_at_ms: now_ms(),
                        },
                    )]),
                    completed_recipient_code_ids: HashSet::new(),
                },
            );
            bindings.insert(
                AttachmentBindingKey::new(
                    &owner,
                    "dm_binding_completion",
                    "binding-completion-message",
                ),
                attachment_id,
            );
        }
        state.attachment_bytes_by_code.lock().await.insert(owner, 3);

        complete_attachment_download_claim(&state, attachment_id, &recipient, claim_id)
            .await
            .expect("destructive completion");
        assert!(!state.attachments.lock().await.contains_key(&attachment_id));
        assert!(state.attachment_bindings.lock().await.is_empty());
        assert!(state.attachment_bytes_by_code.lock().await.is_empty());
    }

    #[tokio::test]
    async fn expired_staged_publication_removes_record_binding_and_usage() {
        let state = test_state();
        let owner = test_code_id("expired-publication-owner");
        let attachment_id = Uuid::new_v4();
        {
            let mut bindings = state.attachment_bindings.lock().await;
            let mut attachments = state.attachments.lock().await;
            attachments.insert(
                attachment_id,
                AttachmentRecord {
                    blob: test_attachment_blob(vec![1, 2, 3]),
                    chat_id: "dm_expired_publication".to_string(),
                    message_id: "expired-publication-message".to_string(),
                    media_type: "FILE".to_string(),
                    owner_code_id: owner,
                    sender_platform: ClientPlatform::Android,
                    published: false,
                    staged_expires_at_ms: Some(now_ms().saturating_sub(1)),
                    one_time: false,
                    delete_after_download: false,
                    expires_at_ms: Some(now_ms().saturating_add(60_000)),
                    eligible_recipient_code_ids: HashSet::new(),
                    download_claims: HashMap::new(),
                    completed_recipient_code_ids: HashSet::new(),
                },
            );
            bindings.insert(
                AttachmentBindingKey::new(
                    &owner,
                    "dm_expired_publication",
                    "expired-publication-message",
                ),
                attachment_id,
            );
        }
        state.attachment_bytes_by_code.lock().await.insert(owner, 3);

        publish_staged_attachment(
            &state,
            attachment_id,
            &owner,
            "dm_expired_publication",
            "expired-publication-message",
        )
        .await;
        assert!(!state.attachments.lock().await.contains_key(&attachment_id));
        assert!(state.attachment_bindings.lock().await.is_empty());
        assert!(state.attachment_bytes_by_code.lock().await.is_empty());
    }

    #[tokio::test]
    async fn mismatched_attachment_binding_cannot_leave_an_orphan_record() {
        let state = test_state();
        let owner = test_code_id("mismatch-binding-owner");
        let attachment_id = Uuid::new_v4();
        {
            let mut bindings = state.attachment_bindings.lock().await;
            let mut attachments = state.attachments.lock().await;
            attachments.insert(
                attachment_id,
                AttachmentRecord {
                    blob: test_attachment_blob(vec![1, 2, 3]),
                    chat_id: "dm_mismatch_binding".to_string(),
                    message_id: "actual-message".to_string(),
                    media_type: "FILE".to_string(),
                    owner_code_id: owner,
                    sender_platform: ClientPlatform::Android,
                    published: false,
                    staged_expires_at_ms: Some(now_ms().saturating_add(60_000)),
                    one_time: false,
                    delete_after_download: false,
                    expires_at_ms: Some(now_ms().saturating_add(60_000)),
                    eligible_recipient_code_ids: HashSet::new(),
                    download_claims: HashMap::new(),
                    completed_recipient_code_ids: HashSet::new(),
                },
            );
            bindings.insert(
                AttachmentBindingKey::new(&owner, "dm_mismatch_binding", "indexed-message"),
                attachment_id,
            );
        }
        state.attachment_bytes_by_code.lock().await.insert(owner, 3);

        assert_eq!(
            staged_attachment_for_message(
                &state,
                &owner,
                "dm_mismatch_binding",
                "indexed-message",
            )
            .await,
            Ok(None)
        );
        assert!(!state.attachments.lock().await.contains_key(&attachment_id));
        assert!(state.attachment_bindings.lock().await.is_empty());
        assert!(state.attachment_bytes_by_code.lock().await.is_empty());
    }

    #[tokio::test]
    async fn attachment_sweeper_pruning_serializes_with_message_admission() {
        let state = test_state();
        let conversation_guard = state.conversation_ops.lock().await;
        let prune_state = state.clone();
        let mut prune_task = tokio::spawn(async move {
            prune_expired_attachments(&prune_state).await;
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut prune_task)
                .await
                .is_err()
        );
        drop(conversation_guard);
        prune_task.await.expect("prune task");
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
                message_id: "test-message".to_string(),
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
                    message_id: "test-message".to_string(),
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
        let body_bytes = test_valid_encrypted_attachment_body(1);
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
                    message_id: "test-message".to_string(),
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
                message_id: "test-message".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                sender_platform: ClientPlatform::Android,
                published: true,
                staged_expires_at_ms: None,
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
                message_id: "test-message".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                sender_platform: ClientPlatform::Android,
                published: true,
                staged_expires_at_ms: None,
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
                platform: ClientPlatform::Android,
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
        add_test_account_with_id(
            &state,
            recipient,
            "DownloadRecipient",
            ClientPlatform::Android,
        )
        .await;
        let expected = vec![11_u8, 22, 33, 44];
        state.attachments.lock().await.insert(
            attachment_id,
            AttachmentRecord {
                blob: test_attachment_blob(expected.clone()),
                chat_id: "dm_alice_bob".to_string(),
                message_id: "test-message".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                sender_platform: ClientPlatform::Android,
                published: true,
                staged_expires_at_ms: None,
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
        add_test_account_with_id(
            &state,
            recipient,
            "InterruptedRecipient",
            ClientPlatform::Android,
        )
        .await;
        let expected = vec![55_u8; ATTACHMENT_DOWNLOAD_CHUNK_BYTES + 1];
        state.attachments.lock().await.insert(
            attachment_id,
            AttachmentRecord {
                blob: test_attachment_blob(expected.clone()),
                chat_id: "dm_alice_bob".to_string(),
                message_id: "test-message".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                sender_platform: ClientPlatform::Android,
                published: true,
                staged_expires_at_ms: None,
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
        add_test_account_with_id(
            &state,
            recipient,
            "ExpiredRecipient",
            ClientPlatform::Android,
        )
        .await;
        state.attachments.lock().await.insert(
            attachment_id,
            AttachmentRecord {
                blob: test_attachment_blob(vec![8, 9]),
                chat_id: "dm_alice_bob".to_string(),
                message_id: "test-message".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                sender_platform: ClientPlatform::Android,
                published: true,
                staged_expires_at_ms: None,
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
        add_test_account_with_id(
            &state,
            recipient,
            "ConcurrentRecipient",
            ClientPlatform::Android,
        )
        .await;
        state.attachments.lock().await.insert(
            attachment_id,
            AttachmentRecord {
                blob: test_attachment_blob(vec![1, 2, 3]),
                chat_id: "dm_alice_bob".to_string(),
                message_id: "test-message".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                sender_platform: ClientPlatform::Android,
                published: true,
                staged_expires_at_ms: None,
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
        add_test_account_with_id(&state, recipient, "ClaimRecipient", ClientPlatform::Android)
            .await;
        state.attachments.lock().await.insert(
            attachment_id,
            AttachmentRecord {
                blob: test_attachment_blob(vec![4, 5, 6]),
                chat_id: "dm_alice_bob".to_string(),
                message_id: "test-message".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                sender_platform: ClientPlatform::Android,
                published: true,
                staged_expires_at_ms: None,
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
        add_test_account_with_id(&state, recipient, "DmRecipient", ClientPlatform::Android).await;
        state.attachments.lock().await.insert(
            attachment_id,
            AttachmentRecord {
                blob: test_attachment_blob(vec![7, 8, 9]),
                chat_id: "dm_alice_bob".to_string(),
                message_id: "test-message".to_string(),
                media_type: "IMAGE".to_string(),
                owner_code_id: owner,
                sender_platform: ClientPlatform::Android,
                published: true,
                staged_expires_at_ms: None,
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
        add_test_account_with_id(&state, bob, "RoomBob", ClientPlatform::Android).await;
        add_test_account_with_id(&state, carol, "RoomCarol", ClientPlatform::Android).await;
        state.attachments.lock().await.insert(
            attachment_id,
            AttachmentRecord {
                blob: test_attachment_blob(vec![10, 11, 12]),
                chat_id: "forum_shared".to_string(),
                message_id: "test-message".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                sender_platform: ClientPlatform::Android,
                published: true,
                staged_expires_at_ms: None,
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
    async fn attachment_download_requires_recipient_membership_and_platform_policy() {
        let mut state = test_state();
        let attachment_id = Uuid::new_v4();
        let owner = test_code_id("policy-owner");
        let android_recipient = test_code_id("policy-android");
        let web_recipient = test_code_id("policy-web");
        let unrelated_recipient = test_code_id("policy-unrelated");
        add_test_account_with_id(
            &state,
            android_recipient,
            "PolicyAndroid",
            ClientPlatform::Android,
        )
        .await;
        add_test_account_with_id(&state, web_recipient, "PolicyWeb", ClientPlatform::Web).await;
        add_test_account_with_id(
            &state,
            unrelated_recipient,
            "PolicyUnrelated",
            ClientPlatform::Android,
        )
        .await;
        state.attachments.lock().await.insert(
            attachment_id,
            AttachmentRecord {
                blob: test_attachment_blob(vec![1, 2, 3]),
                chat_id: "forum_policy".to_string(),
                message_id: "policy-message".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                sender_platform: ClientPlatform::Android,
                published: true,
                staged_expires_at_ms: None,
                one_time: false,
                delete_after_download: false,
                expires_at_ms: None,
                eligible_recipient_code_ids: HashSet::from([android_recipient, web_recipient]),
                download_claims: HashMap::new(),
                completed_recipient_code_ids: HashSet::new(),
            },
        );

        assert!(
            reserve_attachment_download(&state, attachment_id, &android_recipient)
                .await
                .is_ok()
        );
        assert_eq!(
            reserve_attachment_download(&state, attachment_id, &unrelated_recipient)
                .await
                .map(|_| ()),
            Err(StatusCode::FORBIDDEN)
        );
        assert_eq!(
            reserve_attachment_download(&state, attachment_id, &web_recipient)
                .await
                .map(|_| ()),
            Err(StatusCode::FORBIDDEN)
        );

        state.interop_policy = InteropPolicy::new(true, true);
        assert!(
            reserve_attachment_download(&state, attachment_id, &web_recipient)
                .await
                .is_ok()
        );
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
        .is_err());
        assert_eq!(*state.last_activity_ms.lock().await, 123);

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
                message_id: "test-message".to_string(),
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
                blob: test_attachment_blob(test_valid_encrypted_attachment_body(1)),
                chat_id: "record_limit_room".to_string(),
                message_id: "test-message".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                sender_platform: ClientPlatform::Android,
                published: true,
                staged_expires_at_ms: None,
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
        headers.insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&ATTACHMENT_CHUNK_RECORD_BYTES.to_string())
                .expect("content length"),
        );
        let body = Body::from_stream(futures_util::stream::once(async {
            panic!("a saturated attachment record limit must reject before reading the body");
            #[allow(unreachable_code)]
            Ok::<Bytes, Infallible>(Bytes::new())
        }));
        let response = upload_attachment(
            State(state.clone()),
            Query(AttachmentQuery {
                chat_id: "record_limit_room".to_string(),
                message_id: "test-message".to_string(),
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
                let body = test_valid_encrypted_attachment_body(1);
                let mut headers = HeaderMap::new();
                headers.insert(
                    header::AUTHORIZATION,
                    HeaderValue::from_static(match token {
                        "record-race-token-a" => "Bearer record-race-token-a",
                        _ => "Bearer record-race-token-b",
                    }),
                );
                headers.insert(
                    header::CONTENT_LENGTH,
                    HeaderValue::from_str(&body.len().to_string()).expect("content length"),
                );
                let body_gate = gate;
                upload_attachment(
                    State(state.clone()),
                    Query(AttachmentQuery {
                        chat_id: "record_race_room".to_string(),
                        message_id: "test-message".to_string(),
                        media_type: Some("FILE".to_string()),
                        one_time: None,
                        delete_after_download: None,
                        ttl_sec: None,
                    }),
                    headers,
                    Body::from_stream(futures_util::stream::once(async move {
                        body_gate.wait().await;
                        Ok::<Bytes, Infallible>(Bytes::from(body))
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
            8 * 1024 * 1024 - ATTACHMENT_CHUNK_RECORD_BYTES
        );
        let usage = state.attachment_bytes_by_code.lock().await;
        assert_eq!(
            usage.values().copied().sum::<usize>(),
            ATTACHMENT_CHUNK_RECORD_BYTES
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
            let body = test_valid_encrypted_attachment_body(1);
            let mut headers = HeaderMap::new();
            headers.insert(
                header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {token}")).expect("test bearer token"),
            );
            headers.insert(
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&body.len().to_string()).expect("content length"),
            );
            upload_attachment(
                State(state.clone()),
                Query(AttachmentQuery {
                    chat_id: room_id.to_string(),
                    message_id: "test-message".to_string(),
                    media_type: Some("FILE".to_string()),
                    one_time: None,
                    delete_after_download: None,
                    ttl_sec: None,
                }),
                headers,
                Body::from(body),
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
            8 * 1024 * 1024 - 2 * ATTACHMENT_CHUNK_RECORD_BYTES
        );
        let usage = state.attachment_bytes_by_code.lock().await;
        assert_eq!(
            usage.get(&test_code_id("record-boundary-a")),
            Some(&ATTACHMENT_CHUNK_RECORD_BYTES)
        );
        assert_eq!(
            usage.get(&test_code_id("record-boundary-b")),
            Some(&ATTACHMENT_CHUNK_RECORD_BYTES)
        );
        drop(usage);

        remove_chat_attachments(&state, room_id).await;
        assert!(state.attachments.lock().await.is_empty());
        assert!(state.attachment_bindings.lock().await.is_empty());
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
            let body = test_valid_encrypted_attachment_body(1);
            let mut headers = HeaderMap::new();
            headers.insert(
                header::AUTHORIZATION,
                HeaderValue::from_static("Bearer record-wipe-token"),
            );
            headers.insert(
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&body.len().to_string()).expect("content length"),
            );
            upload_attachment(
                State(state),
                Query(AttachmentQuery {
                    chat_id: room_id.to_string(),
                    message_id: "test-message".to_string(),
                    media_type: Some("FILE".to_string()),
                    one_time: None,
                    delete_after_download: None,
                    ttl_sec: None,
                }),
                headers,
                Body::from(body),
            )
            .await
            .into_response()
            .status()
        };

        assert_eq!(upload(state.clone()).await, StatusCode::OK);
        assert_eq!(state.attachments.lock().await.len(), 1);
        wipe_relay_state(&state, false).await;
        assert!(state.attachments.lock().await.is_empty());
        assert!(state.attachment_bindings.lock().await.is_empty());
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
        assert_eq!(decode_bounded_allow_empty("", 4).unwrap(), Vec::<u8>::new());
        assert!(decode_bounded_allow_empty("AQ==", 4).is_err());
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
    fn websocket_ticket_requires_protocol_v2_and_rejects_bearer() {
        let raw_ticket = URL_SAFE_NO_PAD.encode([7_u8; WS_TICKET_BYTES]);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_str(&format!("abyssal-v2, ticket.{raw_ticket}"))
                .expect("valid subprotocol"),
        );

        assert_eq!(
            websocket_ticket_header(&headers).as_deref(),
            Some(&raw_ticket)
        );
        headers.insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_str(&format!("abyssal-v2, bearer.{raw_ticket}"))
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
            HeaderValue::from_static("abyssal-v2, ticket.invalid"),
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

    fn ticket_build_attestation_for(platform: &str) -> BuildAttestationRequest {
        BuildAttestationRequest {
            platform: platform.to_string(),
            version: "2.1.0".to_string(),
            build_signature_b64: URL_SAFE_NO_PAD.encode([2_u8; 64]),
        }
    }

    fn ticket_build_attestation() -> BuildAttestationRequest {
        ticket_build_attestation_for("web")
    }

    async fn issue_test_ticket(state: &AppState, token: &str) -> (StatusCode, WsTicketResponse) {
        let response = issue_ws_ticket(
            State(state.clone()),
            ticket_auth_headers(token),
            Json(ticket_build_attestation()),
        )
        .await;
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("ticket response body");
        let ticket = serde_json::from_slice(&body).expect("ticket response JSON");
        (status, ticket)
    }

    async fn add_test_session(state: &AppState, token: &str, code: &str, username: &str) {
        if !state
            .accounts
            .lock()
            .await
            .contains_key(&test_code_id(code))
        {
            add_test_account(state, code, username).await;
        }
        state
            .accounts
            .lock()
            .await
            .get_mut(&test_code_id(code))
            .expect("test account")
            .client_platform = None;
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

        let (token, session, platform) = consume_ws_ticket(&state, &response.ticket)
            .await
            .expect("first consumption");
        assert_eq!(token.as_str(), "ticket-session");
        assert_eq!(session.username, "Alice");
        assert_eq!(platform, ClientPlatform::Web);
        assert_eq!(
            state
                .accounts
                .lock()
                .await
                .get(&test_code_id("ticket-code"))
                .and_then(|account| account.client_platform),
            Some(ClientPlatform::Web)
        );
        assert!(consume_ws_ticket(&state, &response.ticket).await.is_none());
        assert!(state.ws_tickets.lock().await.is_empty());
    }

    #[tokio::test]
    async fn release_admission_rejects_before_ticket_or_session_access() {
        let mut state = test_state();
        state.release_admission = Arc::new(ReleaseAdmissionStore::new());
        add_test_session(&state, "attestation-session", "attestation-code", "Alice").await;

        let response = issue_ws_ticket(
            State(state.clone()),
            ticket_auth_headers("attestation-session"),
            Json(ticket_build_attestation()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UPGRADE_REQUIRED);
        assert!(state.ws_tickets.lock().await.is_empty());

        let response = issue_ws_ticket(
            State(state.clone()),
            ticket_auth_headers("missing-session"),
            Json(BuildAttestationRequest {
                platform: "web".to_string(),
                version: "2.0.0".to_string(),
                build_signature_b64: URL_SAFE_NO_PAD.encode([2_u8; 64]),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UPGRADE_REQUIRED);
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
    async fn websocket_ticket_cannot_reclassify_an_authenticated_session() {
        let state = test_state();
        add_test_session(&state, "platform-session", "platform-code", "Alice").await;

        let (status, _) = issue_test_ticket(&state, "platform-session").await;
        assert_eq!(status, StatusCode::OK);
        let response = issue_ws_ticket(
            State(state.clone()),
            ticket_auth_headers("platform-session"),
            Json(ticket_build_attestation_for("android")),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UPGRADE_REQUIRED);
        assert_eq!(state.ws_tickets.lock().await.len(), 1);
        assert_eq!(
            state
                .accounts
                .lock()
                .await
                .get(&test_code_id("platform-code"))
                .and_then(|account| account.client_platform),
            Some(ClientPlatform::Web)
        );
    }

    #[tokio::test]
    async fn new_authenticated_session_requires_fresh_platform_attestation() {
        let state = test_state();
        add_test_account(&state, "fresh-platform-code", "Alice").await;
        state
            .accounts
            .lock()
            .await
            .get_mut(&test_code_id("fresh-platform-code"))
            .expect("Alice account")
            .client_platform = Some(ClientPlatform::Web);

        let (status, response) = issue_session(
            &state,
            test_code_id("fresh-platform-code"),
            "Alice".to_string(),
            false,
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(response.accepted);
        assert_eq!(
            state
                .accounts
                .lock()
                .await
                .get(&test_code_id("fresh-platform-code"))
                .and_then(|account| account.client_platform),
            None
        );
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
                client_platform: ClientPlatform::Web,
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
                    client_platform: ClientPlatform::Web,
                },
            );
        }
        drop(tickets);

        let response = issue_ws_ticket(
            State(state.clone()),
            ticket_auth_headers("cap-session"),
            Json(ticket_build_attestation()),
        )
        .await;
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
            directory_node_id: "test-node".to_string(),
            directory_revision: 1,
            directory_digest: URL_SAFE_NO_PAD.encode([0_u8; 32]),
            padding_bucket: 0,
            padding: String::new(),
        };
        assert!(serialize_outbound_frame(&frame).is_none());
    }

    #[test]
    fn outbound_queue_ceiling_is_selected_by_protocol() {
        let mls_global = AtomicUsize::new(0);
        let mls_local = AtomicUsize::new(0);
        assert!(reserve_outbound_bytes(
            &mls_global,
            &mls_local,
            WS_MAX_FRAME_BYTES + 1,
            MLS_CLIENT_OUTBOUND_BYTES,
        ));

        let legacy_global = AtomicUsize::new(0);
        let legacy_local = AtomicUsize::new(0);
        assert!(reserve_outbound_bytes(
            &legacy_global,
            &legacy_local,
            CLIENT_OUTBOUND_BYTES,
            CLIENT_OUTBOUND_BYTES,
        ));
        assert!(!reserve_outbound_bytes(
            &legacy_global,
            &legacy_local,
            1,
            CLIENT_OUTBOUND_BYTES,
        ));
    }

    #[tokio::test]
    async fn send_to_client_allows_mls_frames_above_legacy_one_megabyte_limit() {
        let state = test_state();
        let (client_id, mut rx) = add_test_client(&state, "code-a", "Alice").await;
        let frame = OutboundFrame::MlsApplication {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id: "room-1".to_string(),
            message_id: "message-1".to_string(),
            sender_username: "Bob".to_string(),
            epoch: 1,
            revision: 1,
            membership_digest_b64: "digest".to_string(),
            ciphertext_b64: "x".repeat(WS_MAX_FRAME_BYTES + 1024),
            authenticated_data_b64: "aad".to_string(),
        };
        assert!(serialize_outbound_frame(&frame)
            .as_ref()
            .is_some_and(|serialized| serialized.len() > WS_MAX_FRAME_BYTES));
        send_to_client(&state, client_id, &frame).await;
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn message_transport_padding_hits_bucket_boundaries_exactly() {
        let first_randomized = test_message_frame("forum_test", "random-a", "Alice", "", false);
        let second_randomized = test_message_frame("forum_test", "random-a", "Alice", "", false);
        assert!(matches!(
            (&first_randomized, &second_randomized),
            (
                OutboundFrame::Message { padding: left, .. },
                OutboundFrame::Message { padding: right, .. }
            ) if !left.is_empty() && left != right
        ));

        let mut at_boundary = test_message_frame("forum_test", "boundary", "Alice", "", false);
        let current_ciphertext_len = match &at_boundary {
            OutboundFrame::Message { ciphertext_b64, .. } => ciphertext_b64.len(),
            _ => unreachable!("test message frame"),
        };
        let empty_len = outbound_message_wire_len(&at_boundary, MESSAGE_TRANSPORT_BUCKETS[0], "")
            .expect("empty message wire length");
        if let OutboundFrame::Message {
            ciphertext_b64,
            padding_bucket,
            padding,
            ..
        } = &mut at_boundary
        {
            *ciphertext_b64 = "x".repeat(
                MESSAGE_TRANSPORT_BUCKETS[0]
                    .checked_sub(empty_len)
                    .expect("boundary capacity")
                    .saturating_add(current_ciphertext_len),
            );
            padding.zeroize();
            *padding_bucket = 0;
        }
        prepare_outbound_message_padding(&mut at_boundary).expect("exact first bucket");
        assert!(matches!(
            at_boundary,
            OutboundFrame::Message {
                padding_bucket: 4096,
                ref padding,
                ..
            } if padding.is_empty()
        ));
        assert_eq!(
            serialize_outbound_frame(&at_boundary)
                .expect("boundary frame")
                .len(),
            MESSAGE_TRANSPORT_BUCKETS[0]
        );

        let mut next_bucket = at_boundary.clone();
        if let OutboundFrame::Message {
            ciphertext_b64,
            padding_bucket,
            padding,
            ..
        } = &mut next_bucket
        {
            ciphertext_b64.push('x');
            padding.zeroize();
            *padding_bucket = 0;
        }
        prepare_outbound_message_padding(&mut next_bucket).expect("next bucket");
        assert!(matches!(
            next_bucket,
            OutboundFrame::Message {
                padding_bucket: 16_384,
                ..
            }
        ));
        assert_eq!(
            serialize_outbound_frame(&next_bucket)
                .expect("next bucket frame")
                .len(),
            MESSAGE_TRANSPORT_BUCKETS[1]
        );
    }

    #[test]
    fn message_transport_padding_rejects_tampering_and_noncanonical_input() {
        let envelopes = Vec::new();
        let empty_len = inbound_message_wire_len(
            "dm_a_b",
            E2EE_PROTOCOL_VERSION,
            "message-1",
            "nonce",
            "ciphertext",
            &envelopes,
            1,
            "identity-envelope",
            "identity-public",
            "fallback",
            "state-signature",
            "test-node",
            1,
            &URL_SAFE_NO_PAD.encode([7_u8; DIRECTORY_DIGEST_BYTES]),
            MESSAGE_TRANSPORT_BUCKETS[0],
            "",
        )
        .expect("inbound empty wire length");
        let padding = "A".repeat(
            MESSAGE_TRANSPORT_BUCKETS[0]
                .checked_sub(empty_len)
                .expect("inbound bucket capacity"),
        );
        let directory_digest = URL_SAFE_NO_PAD.encode([7_u8; DIRECTORY_DIGEST_BYTES]);
        let text = serde_json::to_string(&InboundMessageWire {
            frame_type: "message",
            chat_id: "dm_a_b",
            version: E2EE_PROTOCOL_VERSION,
            message_id: "message-1",
            nonce_b64: "nonce",
            ciphertext_b64: "ciphertext",
            envelopes: &envelopes,
            state_revision: 1,
            identity_envelope_b64: "identity-envelope",
            identity_public_b64: "identity-public",
            prekey_id: "fallback",
            state_signature_b64: "state-signature",
            directory_node_id: "test-node",
            directory_revision: 1,
            directory_digest: &directory_digest,
            padding_bucket: MESSAGE_TRANSPORT_BUCKETS[0],
            padding: &padding,
        })
        .expect("inbound padded frame");
        let frame: InboundFrame = serde_json::from_str(&text).expect("inbound message");
        validate_inbound_message_padding(&text, &frame).expect("canonical inbound padding");

        let mut wrong_bucket =
            serde_json::from_str::<InboundFrame>(&text).expect("inbound message");
        if let InboundFrame::Message { padding_bucket, .. } = &mut wrong_bucket {
            *padding_bucket = MESSAGE_TRANSPORT_BUCKETS[1];
        }
        assert!(validate_inbound_message_padding(&text, &wrong_bucket).is_err());

        let mut shortened = serde_json::from_str::<InboundFrame>(&text).expect("inbound message");
        if let InboundFrame::Message { padding, .. } = &mut shortened {
            padding.pop();
        }
        assert!(validate_inbound_message_padding(&text, &shortened).is_err());

        let mut tampered = frame;
        if let InboundFrame::Message { padding, .. } = &mut tampered {
            padding.replace_range(0..1, "!");
        }
        assert!(validate_inbound_message_padding(&text, &tampered).is_err());

        let mut noncanonical = text.clone();
        noncanonical.push(' ');
        let parsed: InboundFrame = serde_json::from_str(&noncanonical).expect("whitespace parse");
        assert!(validate_inbound_message_padding(&noncanonical, &parsed).is_err());
    }

    #[test]
    fn dummy_padding_hint_saturates_without_overflow() {
        assert_eq!(
            discarded_dummy_hint(Some("padding"), Some(usize::MAX)),
            usize::MAX
        );
    }

    #[tokio::test]
    async fn pending_accounting_uses_complete_padded_message_frame() {
        let state = test_state();
        let frame = test_message_frame("dm_a_b", "accounted", "Alice", "", false);
        let expected = serialize_outbound_frame(&frame)
            .expect("padded message serialization")
            .len();
        queue_pending_frame(&state, "dm_a_b", "Bob".to_string(), frame)
            .await
            .expect("pending admission");
        assert_eq!(*state.pending_bytes.lock().await, expected);
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
    async fn one_time_prekey_leases_are_single_use_and_bound_to_recipient_state() {
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
        state.prekey_leases.lock().await.insert(
            PrekeyLeaseKey {
                code_id: test_code_id("code-b"),
                prekey_id: test_prekey_id(b'B'),
            },
            PrekeyLease {
                chat_id: "dm_alice_bob".to_string(),
                message_id: "message-1".to_string(),
                sender_username: "Alice".to_string(),
                recipient_username: "Bob".to_string(),
                created_at_ms: now_ms(),
            },
        );

        admit_prekey_leases(
            &state,
            &expected,
            &envelopes,
            "dm_alice_bob",
            "message-1",
            "Alice",
        )
        .await
        .expect("exact lease");
        assert!(admit_prekey_leases(
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
        assert!(admit_prekey_leases(
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
    async fn authenticated_prekey_lease_is_idempotent_exactly_releasable_and_pending_safe() {
        let state = test_state();
        add_test_account(&state, "code-a", "Alice").await;
        add_test_account(&state, "code-b", "Bob").await;
        let (alice_id, _) = add_test_client(&state, "code-a", "Alice").await;
        open_direct(&state, alice_id, "Bob")
            .await
            .expect("direct conversation");
        let chat_id = state
            .direct_catalog
            .lock()
            .await
            .keys()
            .next()
            .expect("direct id")
            .clone();

        let first = lease_prekey(&state, alice_id, &chat_id, "lease-message", "Bob")
            .await
            .expect("first lease");
        let second = lease_prekey(&state, alice_id, &chat_id, "lease-message", "Bob")
            .await
            .expect("idempotent lease");
        let leased_id = match (&first, &second) {
            (
                OutboundFrame::PrekeyLease {
                    prekey_id: first, ..
                },
                OutboundFrame::PrekeyLease {
                    prekey_id: second, ..
                },
            ) if first == second => first.clone(),
            _ => panic!("expected identical lease responses"),
        };
        assert_eq!(state.prekey_leases.lock().await.len(), 1);
        assert!(release_unused_prekey_lease(
            &state,
            alice_id,
            &chat_id,
            "wrong-message",
            "Bob",
            &leased_id,
        )
        .await
        .is_err());

        state.pending.lock().await.insert(
            PendingKey {
                chat_id: chat_id.clone(),
                recipient_username: "Bob".to_string(),
            },
            vec![PendingFrame::new(
                test_message_frame(&chat_id, "lease-message", "Alice", &leased_id, true),
                now_ms(),
            )],
        );
        assert!(release_unused_prekey_lease(
            &state,
            alice_id,
            &chat_id,
            "lease-message",
            "Bob",
            &leased_id,
        )
        .await
        .is_err());
        state.pending.lock().await.clear();
        release_unused_prekey_lease(
            &state,
            alice_id,
            &chat_id,
            "lease-message",
            "Bob",
            &leased_id,
        )
        .await
        .expect("exact unused release");
        assert!(state.prekey_leases.lock().await.is_empty());
    }

    #[tokio::test]
    async fn concurrent_prekey_leases_are_distinct_bounded_expiring_and_purged() {
        let state = test_state();
        add_test_account(&state, "code-a", "Alice").await;
        add_test_account(&state, "code-b", "Bob").await;
        let (alice_id, _) = add_test_client(&state, "code-a", "Alice").await;
        open_direct(&state, alice_id, "Bob")
            .await
            .expect("direct conversation");
        let chat_id = state
            .direct_catalog
            .lock()
            .await
            .keys()
            .next()
            .expect("direct id")
            .clone();
        let tasks = (0..PREKEY_POOL_SIZE_V9)
            .map(|index| {
                let state = state.clone();
                let chat_id = chat_id.clone();
                tokio::spawn(async move {
                    lease_prekey(
                        &state,
                        alice_id,
                        &chat_id,
                        &format!("concurrent-{index}"),
                        "Bob",
                    )
                    .await
                })
            })
            .collect::<Vec<_>>();
        let mut ids = HashSet::new();
        for task in tasks {
            let frame = task.await.expect("lease task").expect("bounded lease");
            let OutboundFrame::PrekeyLease { ref prekey_id, .. } = frame else {
                panic!("expected lease frame")
            };
            assert!(ids.insert(prekey_id.clone()));
        }
        assert_eq!(ids.len(), PREKEY_POOL_SIZE_V9);
        assert!(lease_prekey(&state, alice_id, &chat_id, "exhausted", "Bob")
            .await
            .is_err());

        let now = now_ms();
        for lease in state.prekey_leases.lock().await.values_mut() {
            lease.created_at_ms = now.saturating_sub(PREKEY_LEASE_TTL_MS);
        }
        let refreshed = lease_prekey(&state, alice_id, &chat_id, "after-expiry", "Bob")
            .await
            .expect("expired leases release capacity");
        assert!(matches!(refreshed, OutboundFrame::PrekeyLease { .. }));
        assert_eq!(state.prekey_leases.lock().await.len(), 1);

        {
            let mut leases = state.prekey_leases.lock().await;
            for index in 1..MAX_PREKEY_LEASES {
                let mut code_id = [0_u8; 32];
                code_id[..8].copy_from_slice(&(index as u64).to_be_bytes());
                leases.insert(
                    PrekeyLeaseKey {
                        code_id,
                        prekey_id: format!("global-{index}"),
                    },
                    PrekeyLease {
                        chat_id: "global-bound".to_string(),
                        message_id: format!("message-{index}"),
                        sender_username: "Other".to_string(),
                        recipient_username: "OtherRecipient".to_string(),
                        created_at_ms: now,
                    },
                );
            }
        }
        assert_eq!(state.prekey_leases.lock().await.len(), MAX_PREKEY_LEASES);
        assert!(
            lease_prekey(&state, alice_id, &chat_id, "global-full", "Bob")
                .await
                .is_err()
        );

        wipe_relay_state(&state, false).await;
        assert!(state.prekey_leases.lock().await.is_empty());
    }

    #[test]
    fn prekey_pool_transition_is_exact_and_preserves_other_live_leases() {
        let previous = test_identity_public(b'B');
        let consumed = test_prekey_id(b'B');
        let (next, _) = test_identity_public_after_consumption(b'B', &consumed);
        validate_prekey_pool_transition(&previous, &next, Some(&consumed))
            .expect("one-for-one transition");
        assert!(validate_prekey_pool_transition(&previous, &next, None).is_err());
        assert!(validate_prekey_pool_transition(&previous, &previous, Some(&consumed)).is_err());
        validate_prekey_pool_transition(&previous, &previous, None)
            .expect("established pool preservation");

        let preserved_id = prekey_ids_from_identity_public_v9(&previous)
            .expect("pool")
            .into_iter()
            .find(|id| id != &consumed)
            .expect("other key");
        let leases = HashMap::from([(
            PrekeyLeaseKey {
                code_id: test_code_id("code-b"),
                prekey_id: preserved_id,
            },
            PrekeyLease {
                chat_id: "dm_alice_bob".to_string(),
                message_id: "other-message".to_string(),
                sender_username: "Carol".to_string(),
                recipient_username: "Bob".to_string(),
                created_at_ms: now_ms(),
            },
        )]);
        let next_pool = prekey_ids_from_identity_public_v9(&next).expect("next pool");
        assert!(!leases_for_recipient_missing_from_pool(
            &leases,
            &test_code_id("code-b"),
            &next_pool,
            Some(&consumed),
        ));
    }

    #[tokio::test]
    async fn queued_prekey_frame_keeps_lease_alive_until_queue_is_removed() {
        let state = test_state();
        let code_id = test_code_id("code-b");
        let prekey_id = test_prekey_id(b'B');
        let key = PrekeyLeaseKey {
            code_id,
            prekey_id: prekey_id.clone(),
        };
        let claim = PrekeyLease {
            chat_id: "dm_alice_bob".to_string(),
            message_id: "message-1".to_string(),
            sender_username: "Alice".to_string(),
            recipient_username: "Bob".to_string(),
            created_at_ms: now_ms().saturating_sub(PREKEY_LEASE_TTL_MS + 1),
        };
        state.prekey_leases.lock().await.insert(key.clone(), claim);
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
            let mut claims = state.prekey_leases.lock().await;
            prune_prekey_leases(&mut claims, &pending, now_ms());
            assert!(claims.contains_key(&key));
        }

        state.pending.lock().await.clear();
        let pending = state.pending.lock().await;
        let mut claims = state.prekey_leases.lock().await;
        prune_prekey_leases(&mut claims, &pending, now_ms());
        assert!(!claims.contains_key(&key));
    }

    #[tokio::test]
    async fn expired_pending_prekey_frame_releases_lease_and_bytes_together() {
        let mut state = test_state();
        state.pending_message_ttl_ms = MIN_PENDING_MESSAGE_TTL_HOURS as u64 * HOURS_TO_MILLISECONDS;
        let now = now_ms();
        let prekey_id = test_prekey_id(b'B');
        let frame = test_message_frame("dm_alice_bob", "expired-prekey", "Alice", &prekey_id, true);
        let frame_bytes = outbound_frame_bytes(&frame);
        let claim_key = PrekeyLeaseKey {
            code_id: test_code_id("code-b"),
            prekey_id: prekey_id.clone(),
        };
        state.prekey_leases.lock().await.insert(
            claim_key.clone(),
            PrekeyLease {
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
        assert!(!state.prekey_leases.lock().await.contains_key(&claim_key));
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
        assert!(state.prekey_leases.lock().await.is_empty());
        assert!(state.replay_ids.lock().await.is_empty());
    }

    #[tokio::test]
    async fn pending_preflight_rejects_transient_fanout_above_global_budget() {
        let state = test_state();
        // Force every otherwise-valid frame into the 1 MiB transport bucket,
        // then exceed the 64 MiB transient fanout budget by exactly one frame.
        let payload = "x".repeat(300_000);
        let frame_count = MAX_TRANSIENT_FANOUT_BYTES / WS_MAX_FRAME_BYTES + 1;
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
                prepare_outbound_message_padding(&mut frame)
                    .expect("large test frame remains canonically pad-able");
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
        prepare_outbound_message_padding(&mut old_duplicate).expect("old duplicate padding");
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
        prepare_outbound_message_padding(&mut new_duplicate).expect("new duplicate padding");
        let frames = vec![("Bob".to_string(), new_duplicate)];
        let mut plan = preflight_pending_frames(&state, &frames)
            .await
            .expect("duplicate admission preflight");
        commit_pending_frames(&state, &frames, &mut plan, ClientPlatform::Android)
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
                platform: ClientPlatform::Android,
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
                platform: ClientPlatform::Android,
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
    async fn ack_result_sink_failure_closes_transport_but_preserves_session() {
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
                platform: ClientPlatform::Android,
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
        assert_eq!(state.sessions.lock().await.len(), 1);
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
                platform: ClientPlatform::Android,
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
                platform: ClientPlatform::Android,
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
                platform: ClientPlatform::Android,
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
        let exact_frame = frame.to_string();
        let handle_task = tokio::spawn({
            let state = state.clone();
            let exact_frame = exact_frame.clone();
            async move { handle_frame(&state, bob_id, &exact_frame).await }
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

        let replay_task = tokio::spawn({
            let state = state.clone();
            let exact_frame = exact_frame.clone();
            async move { handle_frame(&state, bob_id, &exact_frame).await }
        });
        let replay = result_rx.recv().await.expect("replayed ack result");
        assert!(matches!(
            replay.frame,
            OutboundFrame::AckResult {
                ref message_id,
                accepted: true
            } if message_id == "ack-atomic-message"
        ));
        assert!(state.pending.lock().await.is_empty());
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
        assert!(replay.delivered.send(true).is_ok());
        assert!(replay_task.await.expect("replayed ACK handler").is_ok());
    }

    #[tokio::test]
    async fn ack_result_queue_overflow_closes_transport_but_preserves_session() {
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
                platform: ClientPlatform::Android,
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
        assert_eq!(state.sessions.lock().await.len(), 1);
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
    async fn deleting_room_releases_prekey_leases() {
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
        let removed_key = PrekeyLeaseKey {
            code_id: test_code_id("code-b"),
            prekey_id: removed_prekey_id.clone(),
        };
        let retained_key = PrekeyLeaseKey {
            code_id: test_code_id("code-c"),
            prekey_id: retained_prekey_id.clone(),
        };
        let claim = |recipient_username: &str| PrekeyLease {
            chat_id: room.id.clone(),
            message_id: "message-1".to_string(),
            sender_username: "Alice".to_string(),
            recipient_username: recipient_username.to_string(),
            created_at_ms: now_ms(),
        };
        state.prekey_leases.lock().await.extend([
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
                message_id: "test-message".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: test_code_id("code-a"),
                sender_platform: ClientPlatform::Android,
                published: true,
                staged_expires_at_ms: None,
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
        let claims = state.prekey_leases.lock().await;
        assert!(!claims.contains_key(&removed_key));
        assert!(!claims.contains_key(&retained_key));
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
                challenge: Zeroizing::new(vec![0; REGISTRATION_CHALLENGE_BYTES_V9]),
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
        let challenge = vec![17; REGISTRATION_CHALLENGE_BYTES_V9];
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
        let challenge = vec![18; REGISTRATION_CHALLENGE_BYTES_V9];
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
                message_id: "test-message".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                sender_platform: ClientPlatform::Android,
                published: true,
                staged_expires_at_ms: None,
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
                message_id: "test-message".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                sender_platform: ClientPlatform::Android,
                published: true,
                staged_expires_at_ms: None,
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

    #[tokio::test]
    async fn directory_checkpoint_v2_binds_node_revision_and_rejects_stale_evidence() {
        let state = test_state();
        add_test_account(&state, "directory-a", "Alice").await;
        let first = current_directory_evidence(&state).await;
        assert_eq!(first.node_id, state.node_id);
        assert_eq!(first.revision, 1);
        assert_eq!(
            validate_directory_evidence(&state, Some(first.clone())).await,
            Ok(first.clone())
        );

        {
            let mut accounts = state.accounts.lock().await;
            accounts
                .get_mut(&test_code_id("directory-a"))
                .expect("Alice")
                .connected = false;
        }
        assert_eq!(current_directory_evidence(&state).await, first);

        add_test_account(&state, "directory-b", "Bob").await;
        let second = current_directory_evidence(&state).await;
        assert_eq!(second.revision, 2);
        assert_ne!(second.digest, first.digest);
        assert!(validate_directory_evidence(&state, Some(first))
            .await
            .is_err());
        assert!(validate_directory_evidence(&state, None).await.is_err());
        assert_eq!(
            validate_directory_evidence(&state, Some(second.clone())).await,
            Ok(second.clone())
        );
        for malformed in [
            DirectoryStamp {
                node_id: "node with spaces".to_string(),
                ..second.clone()
            },
            DirectoryStamp {
                revision: 0,
                ..second.clone()
            },
            DirectoryStamp {
                digest: format!("{}=", second.digest),
                ..second.clone()
            },
        ] {
            assert!(validate_directory_evidence(&state, Some(malformed))
                .await
                .is_err());
        }

        let accounts = state.accounts.lock().await;
        let other_node = directory_stamp_at_revision("other-node", second.revision, &accounts);
        assert_ne!(other_node.digest, second.digest);
    }

    #[tokio::test]
    async fn concurrent_presence_broadcasts_emit_only_post_lock_directory_snapshots() {
        let state = test_state();
        add_test_account(&state, "presence-a", "Alice").await;
        let (_, mut receiver) = add_test_client(&state, "presence-a", "Alice").await;
        let guard = state.presence_broadcast_ops.lock().await;

        let first_state = state.clone();
        let first = tokio::spawn(async move { broadcast_presence(&first_state).await });
        tokio::task::yield_now().await;
        add_test_account(&state, "presence-b", "Bob").await;
        let second_state = state.clone();
        let second = tokio::spawn(async move { broadcast_presence(&second_state).await });
        tokio::task::yield_now().await;
        drop(guard);

        first.await.expect("first broadcast");
        second.await.expect("second broadcast");
        for _ in 0..2 {
            let frame = receiver.recv().await.expect("presence frame");
            let OutboundFrame::Presence { ref users } = frame else {
                panic!("expected presence frame");
            };
            assert_eq!(users.len(), 2);
            assert!(users.iter().all(|user| user.directory_revision == 2));
            assert_eq!(
                users
                    .iter()
                    .map(|user| user.directory_digest.as_str())
                    .collect::<HashSet<_>>()
                    .len(),
                1
            );
        }
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

    #[test]
    fn mls_attachment_policy_preserves_media_and_absolute_retention_rules() {
        let access = ConversationAccess::MlsRoom(rooms::RoomPolicy {
            allow_images: false,
            enforce_text_absolute_expiry: true,
            overall_expiry_sec: 60,
            enforce_video_absolute_expiry: true,
            video_overall_expiry_sec: 20,
            ..rooms::RoomPolicy::default()
        });
        assert!(!matches!(
            &access,
            ConversationAccess::MlsRoom(policy) if policy_allows_media(policy, "IMAGE")
        ));
        assert!(matches!(
            &access,
            ConversationAccess::MlsRoom(policy) if policy_allows_media(policy, "VIDEO")
        ));
        assert_eq!(
            effective_attachment_ttl_sec(Some(100), &access, "VIDEO", 604_800),
            20
        );
    }

    #[test]
    fn mls_owner_join_notification_omits_private_recovery_envelope() {
        let frame = OutboundFrame::MlsJoinRequested {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id: "room-1".to_string(),
            request_id: "request-1".to_string(),
            username: "Bob".to_string(),
            stable_identity_b64: "identity".to_string(),
            key_package_b64: "key-package".to_string(),
        };
        let wire = serde_json::to_value(&frame).unwrap();
        assert_eq!(wire["type"], "mls_join_requested");
        assert!(wire.get("state_envelope_b64").is_none());
        assert!(wire.get("recovery_snapshot").is_none());
    }

    #[tokio::test]
    async fn every_inbound_mls_frame_rejects_wrong_or_missing_protocol_version_first() {
        let frames = vec![
            serde_json::json!({"type":"mls_create_room","protocol_version":9,"room_id":"r","group_id_b64":"x","epoch":"0","revision":"0","membership_digest_b64":"x","stable_identity_b64":"x","state_envelope_b64":"x"}),
            serde_json::json!({"type":"mls_discover_room","protocol_version":9,"room_id":"r"}),
            serde_json::json!({"type":"mls_join_request","protocol_version":9,"room_id":"r","request_id":"q","stable_identity_b64":"x","key_package_b64":"x","state_envelope_b64":"x"}),
            serde_json::json!({"type":"mls_join_reject","protocol_version":9,"room_id":"r","request_id":"q"}),
            serde_json::json!({"type":"mls_leave_request","protocol_version":9,"room_id":"r","request_id":"q"}),
            serde_json::json!({"type":"mls_leave_reject","protocol_version":9,"room_id":"r","request_id":"q"}),
            serde_json::json!({"type":"mls_membership_commit","protocol_version":9,"room_id":"r","message_id":"m","request_id":null,"from_epoch":"0","to_epoch":"1","revision":"1","group_id_b64":"x","from_membership_digest_b64":"x","membership_digest_b64":"x","roster":[],"control_b64":"x","welcome_b64":"x","authenticated_data_b64":"x","state_envelope_b64":"x"}),
            serde_json::json!({"type":"mls_application","protocol_version":9,"room_id":"r","message_id":"m","group_id_b64":"x","epoch":"0","revision":"1","membership_digest_b64":"x","ciphertext_b64":"x","authenticated_data_b64":"x","state_envelope_b64":"x"}),
            serde_json::json!({"type":"mls_state_snapshot","protocol_version":9,"room_id":"r","message_id":"m","epoch":"0","revision":"0","membership_digest_b64":"x","state_envelope_b64":"x"}),
            serde_json::json!({"type":"mls_delete_room","protocol_version":9,"room_id":"r"}),
        ];
        let state = test_state();
        for frame in frames {
            let encoded = serde_json::to_string(&frame).unwrap();
            assert_eq!(
                handle_frame(&state, Uuid::new_v4(), &encoded)
                    .await
                    .unwrap_err(),
                "Wrong information"
            );
            let mut unknown = frame.clone();
            unknown
                .as_object_mut()
                .unwrap()
                .insert("unexpected".to_string(), serde_json::json!(true));
            assert!(serde_json::from_value::<InboundFrame>(unknown).is_err());
            let mut missing = frame;
            missing.as_object_mut().unwrap().remove("protocol_version");
            assert!(serde_json::from_value::<InboundFrame>(missing).is_err());
        }
    }

    #[test]
    fn protocol_v10_counters_and_policy_durations_are_decimal_strings() {
        let max = u64::MAX;
        let policy = rooms::RoomPolicy {
            self_destruct_timer_sec: max,
            overall_expiry_sec: max,
            image_read_timer_sec: max,
            image_overall_expiry_sec: max,
            video_read_timer_sec: max,
            video_overall_expiry_sec: max,
            file_read_timer_sec: max,
            file_overall_expiry_sec: max,
            ..rooms::RoomPolicy::default()
        };
        let room = MlsRoomWire {
            room_id: "room".to_string(),
            owner_username: "owner".to_string(),
            group_id_b64: "group".to_string(),
            active: true,
            synchronized: true,
            epoch: max,
            revision: max,
            membership_digest_b64: "digest".to_string(),
            roster: Vec::new(),
            recovery_snapshot: Some(MlsRecoverySnapshotWire {
                active: true,
                epoch: max,
                revision: max,
                membership_digest_b64: "digest".to_string(),
                state_envelope_b64: "state".to_string(),
                roster: vec![MlsRosterWire {
                    username: "alice".to_string(),
                    stable_identity_b64: "identity".to_string(),
                }],
            }),
            policy,
        };
        let wire = serde_json::to_value(OutboundFrame::MlsRoomCreated {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room: room.clone(),
        })
        .expect("MLS room JSON");
        let max_string = max.to_string();
        assert_eq!(wire["room"]["epoch"], max_string);
        assert_eq!(wire["room"]["revision"], max_string);
        assert_eq!(wire["room"]["recovery_snapshot"]["epoch"], max_string);
        assert_eq!(wire["room"]["recovery_snapshot"]["revision"], max_string);
        assert_eq!(wire["room"]["synchronized"], true);
        assert_eq!(
            wire["room"]["recovery_snapshot"]["roster"][0]["username"],
            "alice"
        );
        for field in [
            "self_destruct_timer_sec",
            "overall_expiry_sec",
            "image_read_timer_sec",
            "image_overall_expiry_sec",
            "video_read_timer_sec",
            "video_overall_expiry_sec",
            "file_read_timer_sec",
            "file_overall_expiry_sec",
        ] {
            assert_eq!(wire["room"]["policy"][field], max_string);
        }

        let inbound = serde_json::json!({
            "type": "mls_create_room",
            "protocol_version": rooms::MLS_PROTOCOL_VERSION,
            "room_id": "room",
            "group_id_b64": "group",
            "epoch": max_string,
            "revision": max_string,
            "membership_digest_b64": "digest",
            "stable_identity_b64": "identity",
            "state_envelope_b64": "state",
            "policy": wire["room"]["policy"].clone(),
        });
        assert!(serde_json::from_value::<InboundFrame>(inbound).is_ok());
    }

    #[test]
    fn every_mls_counter_field_accepts_only_canonical_decimal_strings() {
        let max = u64::MAX;
        let max_string = max.to_string();
        let policy = rooms::RoomPolicy {
            self_destruct_timer_sec: max,
            overall_expiry_sec: max,
            image_read_timer_sec: max,
            image_overall_expiry_sec: max,
            video_read_timer_sec: max,
            video_overall_expiry_sec: max,
            file_read_timer_sec: max,
            file_overall_expiry_sec: max,
            ..rooms::RoomPolicy::default()
        };
        let policy_json = serde_json::to_value(policy).unwrap();
        let room = || MlsRoomWire {
            room_id: "room".to_string(),
            owner_username: "owner".to_string(),
            group_id_b64: "group".to_string(),
            active: true,
            synchronized: true,
            epoch: max,
            revision: max,
            membership_digest_b64: "digest".to_string(),
            roster: Vec::new(),
            recovery_snapshot: Some(MlsRecoverySnapshotWire {
                active: true,
                epoch: max,
                revision: max,
                membership_digest_b64: "digest".to_string(),
                state_envelope_b64: "state".to_string(),
                roster: Vec::new(),
            }),
            policy,
        };
        let outbound = vec![
            (
                OutboundFrame::MlsRooms {
                    protocol_version: rooms::MLS_PROTOCOL_VERSION,
                    rooms: vec![room()],
                },
                vec![
                    "/rooms/0/epoch",
                    "/rooms/0/revision",
                    "/rooms/0/recovery_snapshot/epoch",
                    "/rooms/0/recovery_snapshot/revision",
                    "/rooms/0/policy/self_destruct_timer_sec",
                    "/rooms/0/policy/overall_expiry_sec",
                    "/rooms/0/policy/image_read_timer_sec",
                    "/rooms/0/policy/image_overall_expiry_sec",
                    "/rooms/0/policy/video_read_timer_sec",
                    "/rooms/0/policy/video_overall_expiry_sec",
                    "/rooms/0/policy/file_read_timer_sec",
                    "/rooms/0/policy/file_overall_expiry_sec",
                ],
            ),
            (
                OutboundFrame::MlsRoomCreated {
                    protocol_version: rooms::MLS_PROTOCOL_VERSION,
                    room: room(),
                },
                vec![
                    "/room/epoch",
                    "/room/revision",
                    "/room/recovery_snapshot/epoch",
                    "/room/recovery_snapshot/revision",
                    "/room/policy/self_destruct_timer_sec",
                    "/room/policy/overall_expiry_sec",
                    "/room/policy/image_read_timer_sec",
                    "/room/policy/image_overall_expiry_sec",
                    "/room/policy/video_read_timer_sec",
                    "/room/policy/video_overall_expiry_sec",
                    "/room/policy/file_read_timer_sec",
                    "/room/policy/file_overall_expiry_sec",
                ],
            ),
            (
                OutboundFrame::MlsMembership {
                    protocol_version: rooms::MLS_PROTOCOL_VERSION,
                    room_id: "room".to_string(),
                    message_id: "message".to_string(),
                    from_epoch: max,
                    to_epoch: max,
                    revision: max,
                    from_membership_digest_b64: "from".to_string(),
                    group_id_b64: "group".to_string(),
                    membership_digest_b64: "digest".to_string(),
                    roster: Vec::new(),
                    control_b64: "control".to_string(),
                    welcome_b64: "welcome".to_string(),
                    authenticated_data_b64: "aad".to_string(),
                },
                vec!["/from_epoch", "/to_epoch", "/revision"],
            ),
            (
                OutboundFrame::MlsApplication {
                    protocol_version: rooms::MLS_PROTOCOL_VERSION,
                    room_id: "room".to_string(),
                    message_id: "message".to_string(),
                    sender_username: "sender".to_string(),
                    epoch: max,
                    revision: max,
                    membership_digest_b64: "digest".to_string(),
                    ciphertext_b64: "ciphertext".to_string(),
                    authenticated_data_b64: "aad".to_string(),
                },
                vec!["/epoch", "/revision"],
            ),
            (
                OutboundFrame::MlsRoomResult {
                    protocol_version: rooms::MLS_PROTOCOL_VERSION,
                    room_id: "room".to_string(),
                    message_id: "message".to_string(),
                    revision: max,
                    accepted: true,
                },
                vec!["/revision"],
            ),
            (
                OutboundFrame::MlsSnapshotResult {
                    protocol_version: rooms::MLS_PROTOCOL_VERSION,
                    room_id: "room".to_string(),
                    message_id: "message".to_string(),
                    revision: max,
                    accepted: true,
                },
                vec!["/revision"],
            ),
        ];
        for (frame, fields) in outbound {
            let wire = serde_json::to_value(frame).unwrap();
            for field in fields {
                assert_eq!(
                    wire.pointer(field),
                    Some(&serde_json::json!(max_string)),
                    "{field}"
                );
            }
        }

        let inbound = vec![
            (
                serde_json::json!({
                    "type": "mls_create_room",
                    "protocol_version": rooms::MLS_PROTOCOL_VERSION,
                    "room_id": "room",
                    "group_id_b64": "group",
                    "epoch": max_string,
                    "revision": max_string,
                    "membership_digest_b64": "digest",
                    "stable_identity_b64": "identity",
                    "state_envelope_b64": "state",
                    "policy": policy_json,
                }),
                vec![
                    "epoch",
                    "revision",
                    "policy.self_destruct_timer_sec",
                    "policy.overall_expiry_sec",
                    "policy.image_read_timer_sec",
                    "policy.image_overall_expiry_sec",
                    "policy.video_read_timer_sec",
                    "policy.video_overall_expiry_sec",
                    "policy.file_read_timer_sec",
                    "policy.file_overall_expiry_sec",
                ],
            ),
            (
                serde_json::json!({
                    "type": "mls_membership_commit",
                    "protocol_version": rooms::MLS_PROTOCOL_VERSION,
                    "room_id": "room",
                    "message_id": "message",
                    "request_id": null,
                    "from_epoch": max_string,
                    "to_epoch": max_string,
                    "revision": max_string,
                    "group_id_b64": "group",
                    "from_membership_digest_b64": "from",
                    "membership_digest_b64": "digest",
                    "roster": [],
                    "control_b64": "control",
                    "welcome_b64": "welcome",
                    "authenticated_data_b64": "aad",
                    "state_envelope_b64": "state",
                }),
                vec!["from_epoch", "to_epoch", "revision"],
            ),
            (
                serde_json::json!({
                    "type": "mls_application",
                    "protocol_version": rooms::MLS_PROTOCOL_VERSION,
                    "room_id": "room",
                    "message_id": "message",
                    "group_id_b64": "group",
                    "epoch": max_string,
                    "revision": max_string,
                    "membership_digest_b64": "digest",
                    "ciphertext_b64": "ciphertext",
                    "authenticated_data_b64": "aad",
                    "state_envelope_b64": "state",
                }),
                vec!["epoch", "revision"],
            ),
            (
                serde_json::json!({
                    "type": "mls_state_snapshot",
                    "protocol_version": rooms::MLS_PROTOCOL_VERSION,
                    "room_id": "room",
                    "message_id": "message",
                    "epoch": max_string,
                    "revision": max_string,
                    "membership_digest_b64": "digest",
                    "state_envelope_b64": "state",
                }),
                vec!["epoch", "revision"],
            ),
        ];
        let invalid_values = [
            serde_json::json!(1),
            serde_json::json!("01"),
            serde_json::json!("+1"),
            serde_json::json!("-1"),
            serde_json::json!(" 1"),
            serde_json::json!("1 "),
            serde_json::json!("not-a-number"),
            serde_json::json!("18446744073709551616"),
        ];
        for (frame, fields) in inbound {
            let parsed = serde_json::from_value::<InboundFrame>(frame.clone());
            assert!(parsed.is_ok(), "{frame}: {:?}", parsed.err());
            for field in fields {
                for invalid in &invalid_values {
                    let mut rejected = frame.clone();
                    let mut cursor = &mut rejected;
                    for segment in field.split('.') {
                        cursor = cursor
                            .get_mut(segment)
                            .unwrap_or_else(|| panic!("missing JSON field {field}"));
                    }
                    *cursor = invalid.clone();
                    assert!(
                        serde_json::from_value::<InboundFrame>(rejected).is_err(),
                        "accepted invalid {invalid} for {field}"
                    );
                }
            }
        }
    }

    #[test]
    fn non_mls_counters_remain_json_numbers() {
        let outbound = OutboundFrame::Message {
            chat_id: "chat".to_string(),
            version: 9,
            message_id: "message".to_string(),
            nonce_b64: "nonce".to_string(),
            ciphertext_b64: "ciphertext".to_string(),
            signature_b64: "signature".to_string(),
            wrapped_key_b64: "wrapped".to_string(),
            prekey_id: "prekey".to_string(),
            is_prekey: false,
            sender_username: "sender".to_string(),
            sender_public_key_b64: "public".to_string(),
            identity_public_b64: "identity".to_string(),
            directory_node_id: "node".to_string(),
            directory_revision: u64::MAX,
            directory_digest: "digest".to_string(),
            padding_bucket: 1,
            padding: "padding".to_string(),
        };
        let wire = serde_json::to_value(outbound).unwrap();
        assert!(wire["directory_revision"].is_u64());

        let inbound = serde_json::json!({
            "type": "message",
            "chat_id": "chat",
            "version": 9,
            "message_id": "message",
            "nonce_b64": "nonce",
            "ciphertext_b64": "ciphertext",
            "envelopes": [],
            "state_revision": u64::MAX,
            "identity_envelope_b64": "identity-envelope",
            "identity_public_b64": "identity",
            "prekey_id": "prekey",
            "state_signature_b64": "state-signature",
            "directory_node_id": "node",
            "directory_revision": u64::MAX,
            "directory_digest": "digest",
            "padding_bucket": 1,
            "padding": "padding",
        });
        assert!(serde_json::from_value::<InboundFrame>(inbound).is_ok());
    }

    #[test]
    fn mls_create_room_omitted_policy_uses_default_policy() {
        let frame = serde_json::json!({
            "type": "mls_create_room",
            "protocol_version": rooms::MLS_PROTOCOL_VERSION,
            "room_id": "room",
            "group_id_b64": "group",
            "epoch": "0",
            "revision": "0",
            "membership_digest_b64": "digest",
            "stable_identity_b64": "identity",
            "state_envelope_b64": "state",
        });
        let InboundFrame::MlsCreateRoom { policy, .. } =
            serde_json::from_value(frame).expect("MLS create room")
        else {
            panic!("expected MLS create room frame");
        };
        assert_eq!(policy, rooms::RoomPolicy::default());
    }

    #[test]
    fn mls_create_room_rejects_unknown_nested_policy_fields() {
        let frame = serde_json::json!({
            "type": "mls_create_room",
            "protocol_version": rooms::MLS_PROTOCOL_VERSION,
            "room_id": "room-1",
            "group_id_b64": "group",
            "epoch": "0",
            "revision": "0",
            "membership_digest_b64": "digest",
            "stable_identity_b64": "identity",
            "state_envelope_b64": "state",
            "policy": {"unexpected": true}
        });

        assert!(serde_json::from_value::<InboundFrame>(frame).is_err());
    }

    #[test]
    fn every_outbound_mls_frame_carries_protocol_v10() {
        let room = || MlsRoomWire {
            room_id: "room-1".to_string(),
            owner_username: "Alice".to_string(),
            group_id_b64: "group".to_string(),
            active: true,
            synchronized: true,
            epoch: 1,
            revision: 1,
            membership_digest_b64: "digest".to_string(),
            roster: Vec::new(),
            recovery_snapshot: None,
            policy: rooms::RoomPolicy::default(),
        };
        let frames = vec![
            OutboundFrame::MlsRooms {
                protocol_version: rooms::MLS_PROTOCOL_VERSION,
                rooms: vec![room()],
            },
            OutboundFrame::MlsRoomDiscovered {
                protocol_version: rooms::MLS_PROTOCOL_VERSION,
                room_id: "r".to_string(),
                group_id_b64: "g".to_string(),
                owner_username: "u".to_string(),
            },
            OutboundFrame::MlsRoomCreated {
                protocol_version: rooms::MLS_PROTOCOL_VERSION,
                room: room(),
            },
            OutboundFrame::MlsJoinRequested {
                protocol_version: rooms::MLS_PROTOCOL_VERSION,
                room_id: "r".to_string(),
                request_id: "q".to_string(),
                username: "u".to_string(),
                stable_identity_b64: "s".to_string(),
                key_package_b64: "k".to_string(),
            },
            OutboundFrame::MlsJoinRejected {
                protocol_version: rooms::MLS_PROTOCOL_VERSION,
                room_id: "r".to_string(),
                request_id: "q".to_string(),
            },
            OutboundFrame::MlsLeaveRequested {
                protocol_version: rooms::MLS_PROTOCOL_VERSION,
                room_id: "r".to_string(),
                request_id: "q".to_string(),
                username: "u".to_string(),
                stable_identity_b64: "s".to_string(),
            },
            OutboundFrame::MlsLeavePending {
                protocol_version: rooms::MLS_PROTOCOL_VERSION,
                room_id: "r".to_string(),
                request_id: "q".to_string(),
            },
            OutboundFrame::MlsLeaveRejected {
                protocol_version: rooms::MLS_PROTOCOL_VERSION,
                room_id: "r".to_string(),
                request_id: "q".to_string(),
            },
            OutboundFrame::MlsLeft {
                protocol_version: rooms::MLS_PROTOCOL_VERSION,
                room_id: "r".to_string(),
            },
            OutboundFrame::MlsMembership {
                protocol_version: rooms::MLS_PROTOCOL_VERSION,
                room_id: "r".to_string(),
                message_id: "m".to_string(),
                from_epoch: 0,
                to_epoch: 1,
                revision: 1,
                group_id_b64: "g".to_string(),
                from_membership_digest_b64: "f".to_string(),
                membership_digest_b64: "d".to_string(),
                roster: Vec::new(),
                control_b64: "c".to_string(),
                welcome_b64: "w".to_string(),
                authenticated_data_b64: "a".to_string(),
            },
            OutboundFrame::MlsApplication {
                protocol_version: rooms::MLS_PROTOCOL_VERSION,
                room_id: "r".to_string(),
                message_id: "m".to_string(),
                sender_username: "u".to_string(),
                epoch: 1,
                revision: 1,
                membership_digest_b64: "d".to_string(),
                ciphertext_b64: "c".to_string(),
                authenticated_data_b64: "a".to_string(),
            },
            OutboundFrame::MlsRoomResult {
                protocol_version: rooms::MLS_PROTOCOL_VERSION,
                room_id: "r".to_string(),
                message_id: "m".to_string(),
                revision: 1,
                accepted: true,
            },
            OutboundFrame::MlsRoomDeleted {
                protocol_version: rooms::MLS_PROTOCOL_VERSION,
                room_id: "r".to_string(),
            },
            OutboundFrame::MlsSnapshotResult {
                protocol_version: rooms::MLS_PROTOCOL_VERSION,
                room_id: "r".to_string(),
                message_id: "m".to_string(),
                revision: 1,
                accepted: true,
            },
        ];
        for frame in frames {
            assert!(frame.is_mls());
            let wire = serde_json::to_value(&frame).unwrap();
            assert_eq!(wire["protocol_version"], rooms::MLS_PROTOCOL_VERSION);
        }
    }

    #[test]
    fn mls_delivery_preserves_authenticated_data_for_core_aad_verification() {
        let authenticated_data = vec![0_u8, 1, 127, 255];
        let delivery = rooms::PendingDelivery {
            room_id: "room-1".to_string(),
            message_id: "message-1".to_string(),
            recipient_code_id: [2_u8; rooms::GROUP_ID_BYTES],
            epoch: 3,
            membership_digest: vec![8_u8; rooms::MEMBERSHIP_DIGEST_BYTES],
            revision: 4,
            payload: rooms::DeliveryPayload::Application {
                sender_code_id: [1_u8; rooms::GROUP_ID_BYTES],
                sender_username: "Alice".to_string(),
                sender_platform: ClientPlatform::Android,
                ciphertext: vec![9_u8],
                authenticated_data: authenticated_data.clone(),
            },
            created_at_ms: 0,
            expires_at_ms: 1,
        };

        let wire = serde_json::to_value(mls_delivery_frame(&delivery)).unwrap();
        assert_eq!(
            wire["authenticated_data_b64"],
            URL_SAFE_NO_PAD.encode(authenticated_data)
        );
        assert_eq!(wire["protocol_version"], rooms::MLS_PROTOCOL_VERSION);
    }

    #[test]
    fn mls_membership_delivery_preserves_prior_membership_digest() {
        let prior_digest = vec![1_u8; rooms::MEMBERSHIP_DIGEST_BYTES];
        let post_digest = vec![2_u8; rooms::MEMBERSHIP_DIGEST_BYTES];
        let delivery = rooms::PendingDelivery {
            room_id: "room-1".to_string(),
            message_id: "membership-1".to_string(),
            recipient_code_id: [2_u8; rooms::GROUP_ID_BYTES],
            epoch: 4,
            membership_digest: post_digest.clone(),
            revision: 5,
            payload: rooms::DeliveryPayload::Membership {
                from_epoch: 3,
                from_membership_digest: prior_digest.clone(),
                group_id: vec![3_u8; rooms::GROUP_ID_BYTES],
                roster: Vec::new(),
                control: vec![4],
                welcome: Vec::new(),
                authenticated_data: vec![5],
            },
            created_at_ms: 0,
            expires_at_ms: 1,
        };

        let wire = serde_json::to_value(mls_delivery_frame(&delivery)).unwrap();
        assert_eq!(
            wire["from_membership_digest_b64"],
            URL_SAFE_NO_PAD.encode(prior_digest)
        );
        assert_eq!(
            wire["membership_digest_b64"],
            URL_SAFE_NO_PAD.encode(post_digest)
        );
        assert_ne!(
            wire["from_membership_digest_b64"],
            wire["membership_digest_b64"]
        );
    }

    #[test]
    fn oversized_inbound_frames_allow_only_canonical_large_mls_families() {
        let oversized = |prefix: &str| {
            format!(
                "{prefix}{}",
                "x".repeat(WS_MAX_FRAME_BYTES + 1 - prefix.len())
            )
        };
        for prefix in LARGE_MLS_INBOUND_PREFIXES {
            let frame = oversized(prefix);
            assert_eq!(frame.len(), WS_MAX_FRAME_BYTES + 1);
            assert!(validate_inbound_frame_size_before_parse(&frame).is_ok());
        }

        for frame in [
            oversized(r#"{"type":"mls_discover_room","protocol_version":10,"#),
            oversized(r#"{"type":"mls_unknown","protocol_version":10,"#),
            oversized(r#"{"type":"mls_application","protocol_version":9,"#),
            oversized(r#" {"type":"mls_application","protocol_version":10,"#),
            oversized(r#"{"protocol_version":10,"type":"mls_application","#),
            oversized(r#"{"type":"message","protocol_version":10,"#),
        ] {
            assert!(validate_inbound_frame_size_before_parse(&frame).is_err());
        }
    }

    #[test]
    fn oversized_mls_prefix_does_not_bypass_full_json_schema_validation() {
        let prefix = LARGE_MLS_INBOUND_PREFIXES[3];
        let suffix = "\"type\":\"message\",\"ciphertext_b64\":\"";
        let filler_len = WS_MAX_FRAME_BYTES + 1 - prefix.len() - suffix.len() - 2;
        let frame = format!("{prefix}{suffix}{}\"}}", "x".repeat(filler_len));
        assert!(frame.len() > WS_MAX_FRAME_BYTES);
        assert!(validate_inbound_frame_size_before_parse(&frame).is_ok());
        assert!(serde_json::from_str::<InboundFrame>(&frame).is_err());
    }

    #[test]
    fn websocket_admission_errors_are_terminal_but_schema_errors_are_not() {
        assert!(validate_inbound_text_socket_admission(r#"{"type":"activity"}"#, Ok(())).is_ok());
        assert!(validate_inbound_text_socket_admission(
            r#"{"type":"activity"}"#,
            Err("rate limit exceeded".to_string()),
        )
        .is_err());

        let oversized_legacy = format!(
            "{{\"type\":\"dummy\",\"padding_b64\":\"{}\"}}",
            "x".repeat(WS_MAX_FRAME_BYTES)
        );
        assert!(validate_inbound_text_socket_admission(&oversized_legacy, Ok(())).is_err());

        // Ordinary malformed or unauthorized frames at the legacy ceiling
        // remain non-terminal; handle_frame reports their schema error after
        // this admission function returns success.
        assert!(validate_inbound_text_socket_admission(r#"{"type":"unknown"}"#, Ok(())).is_ok());
    }

    #[test]
    fn exact_mls_frame_ceiling_is_admitted_but_one_byte_over_is_rejected() {
        let prefix = LARGE_MLS_INBOUND_PREFIXES[4];
        let exact = format!(
            "{prefix}{}",
            "x".repeat(MLS_WS_MAX_FRAME_BYTES - prefix.len())
        );
        assert_eq!(exact.len(), MLS_WS_MAX_FRAME_BYTES);
        assert!(validate_inbound_frame_size_before_parse(&exact).is_ok());

        let over = format!(
            "{prefix}{}",
            "x".repeat(MLS_WS_MAX_FRAME_BYTES + 1 - prefix.len())
        );
        assert_eq!(over.len(), MLS_WS_MAX_FRAME_BYTES + 1);
        assert!(validate_inbound_frame_size_before_parse(&over).is_err());
    }

    #[tokio::test]
    async fn mls_frame_ceiling_fits_bounded_records_but_legacy_frames_stay_small() {
        fn base64_len(bytes: usize) -> usize {
            bytes.checked_add(2).unwrap() / 3 * 4
        }
        let worst_membership = base64_len(rooms::MAX_CONTROL_BYTES)
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(base64_len(rooms::MAX_STATE_BYTES)))
            .and_then(|bytes| bytes.checked_add(base64_len(rooms::MAX_AUTHENTICATED_DATA_BYTES)))
            .and_then(|bytes| bytes.checked_add(256 * 1024))
            .unwrap();
        assert!(worst_membership < MLS_WS_MAX_FRAME_BYTES);

        let state = test_state();
        let client_id = Uuid::new_v4();
        assert!(
            check_ws_frame_allowed(&state, client_id, MLS_WS_MAX_FRAME_BYTES)
                .await
                .is_ok()
        );
        assert!(check_ws_frame_allowed(
            &test_state(),
            Uuid::new_v4(),
            CONTROL_TRANSPORT_MAX_BUCKET + 1
        )
        .await
        .is_err());

        let oversized_legacy = serde_json::json!({"type":"dummy","padding_b64":"x".repeat(WS_MAX_FRAME_BYTES),"bytes":1}).to_string();
        assert!(
            handle_frame(&test_state(), Uuid::new_v4(), &oversized_legacy)
                .await
                .is_err()
        );
        let large_mls = OutboundFrame::MlsApplication {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id: "r".to_string(),
            message_id: "m".to_string(),
            sender_username: "u".to_string(),
            epoch: 1,
            revision: 1,
            membership_digest_b64: "d".to_string(),
            ciphertext_b64: "x".repeat(WS_MAX_FRAME_BYTES),
            authenticated_data_b64: "a".to_string(),
        };
        assert!(serialize_outbound_frame(&large_mls).is_some());
    }

    #[tokio::test]
    async fn websocket_byte_rate_budget_rejects_only_after_exact_boundary() {
        let state = test_state();
        let client_id = Uuid::new_v4();
        assert!(
            check_ws_frame_allowed(&state, client_id, MLS_WS_MAX_FRAME_BYTES)
                .await
                .is_ok()
        );
        assert!(
            check_ws_frame_allowed(&state, client_id, MLS_WS_MAX_FRAME_BYTES)
                .await
                .is_ok()
        );
        assert!(check_ws_frame_allowed(&state, client_id, 1).await.is_err());
    }

    #[tokio::test]
    async fn removed_mls_member_loses_attachment_and_claim_access() {
        let state = test_state();
        let owner = test_code_id("mls-owner");
        let removed = test_code_id("mls-removed");
        let retained = test_code_id("mls-retained");
        let attachment_id = Uuid::new_v4();
        let removed_claim = Uuid::new_v4();
        let retained_claim = Uuid::new_v4();
        state.attachments.lock().await.insert(
            attachment_id,
            AttachmentRecord {
                blob: test_attachment_blob(vec![1]),
                chat_id: "mls-room".to_string(),
                message_id: "message-1".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                sender_platform: ClientPlatform::Android,
                published: true,
                staged_expires_at_ms: None,
                one_time: false,
                delete_after_download: false,
                expires_at_ms: None,
                eligible_recipient_code_ids: HashSet::from([removed, retained]),
                download_claims: HashMap::from([
                    (
                        removed_claim,
                        AttachmentDownloadClaim {
                            recipient_code_id: removed,
                            created_at_ms: now_ms(),
                        },
                    ),
                    (
                        retained_claim,
                        AttachmentDownloadClaim {
                            recipient_code_id: retained,
                            created_at_ms: now_ms(),
                        },
                    ),
                ]),
                completed_recipient_code_ids: HashSet::from([removed, retained]),
            },
        );
        revoke_mls_attachment_access(&state, "mls-room", &removed).await;
        let attachments = state.attachments.lock().await;
        let record = attachments.get(&attachment_id).unwrap();
        assert!(!record.eligible_recipient_code_ids.contains(&removed));
        assert!(record.eligible_recipient_code_ids.contains(&retained));
        assert!(!record.completed_recipient_code_ids.contains(&removed));
        assert!(record.completed_recipient_code_ids.contains(&retained));
        assert!(!record.download_claims.contains_key(&removed_claim));
        assert!(record.download_claims.contains_key(&retained_claim));
    }

    #[tokio::test]
    async fn inactive_mls_joiner_has_no_message_or_attachment_access() {
        let state = test_state();
        add_test_account(&state, "code-a", "Alice").await;
        add_test_account(&state, "code-b", "Bob").await;
        let owner = test_code_id("code-a");
        let joiner = test_code_id("code-b");
        let mut authority = state.mls_rooms.lock().await;
        authority
            .create(
                owner,
                "Alice".to_string(),
                "room-inactive".to_string(),
                vec![7; rooms::GROUP_ID_BYTES],
                0,
                0,
                vec![8; rooms::MEMBERSHIP_DIGEST_BYTES],
                vec![1; rooms::STABLE_IDENTITY_BYTES],
            )
            .unwrap();
        let request = authority
            .request_join(
                joiner,
                "Bob".to_string(),
                "room-inactive",
                "request-1".to_string(),
                vec![2; rooms::STABLE_IDENTITY_BYTES],
                vec![5],
                vec![9],
            )
            .unwrap();
        authority
            .begin_membership(
                owner,
                rooms::MembershipTransition {
                    room_id: "room-inactive".to_string(),
                    message_id: "commit-1".to_string(),
                    request_id: Some(request.request_id.clone()),
                    from_epoch: 0,
                    to_epoch: 1,
                    revision: 1,
                    group_id: vec![7; rooms::GROUP_ID_BYTES],
                    from_membership_digest: vec![8; rooms::MEMBERSHIP_DIGEST_BYTES],
                    membership_digest: vec![8; rooms::MEMBERSHIP_DIGEST_BYTES],
                    roster: vec![
                        rooms::RosterMember {
                            username: "Alice".to_string(),
                            stable_identity: vec![1; rooms::STABLE_IDENTITY_BYTES],
                        },
                        rooms::RosterMember {
                            username: "Bob".to_string(),
                            stable_identity: vec![2; rooms::STABLE_IDENTITY_BYTES],
                        },
                    ],
                    control: vec![1],
                    welcome: vec![2],
                    authenticated_data: vec![3],
                    state_envelope: vec![4],
                    created_at_ms: 0,
                    expires_at_ms: 0,
                },
            )
            .unwrap();
        authority
            .accept_membership(owner, "room-inactive", "commit-1", 1)
            .unwrap();
        drop(authority);

        assert!(conversation_access(&state, "Bob", "room-inactive")
            .await
            .is_none());
        assert!(
            attachment_conversation_access(&state, "Bob", "room-inactive", "FILE")
                .await
                .is_err()
        );
        let access = ConversationAccess::MlsRoom(rooms::RoomPolicy::default());
        assert!(
            snapshot_attachment_recipients(&state, &access, "room-inactive", "Alice", &owner,)
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn authenticated_mls_transaction_rejections_are_exactly_correlated() {
        let group = URL_SAFE_NO_PAD.encode([7_u8; rooms::GROUP_ID_BYTES]);
        let digest = URL_SAFE_NO_PAD.encode([8_u8; rooms::MEMBERSHIP_DIGEST_BYTES]);
        let frames = [
            serde_json::json!({
                "type": "mls_membership_commit",
                "protocol_version": rooms::MLS_PROTOCOL_VERSION,
                "room_id": "missing-room",
                "message_id": "membership-reject",
                "request_id": null,
                "from_epoch": "0",
                "to_epoch": "1",
                "revision": "1",
                "group_id_b64": group,
                "from_membership_digest_b64": digest,
                "membership_digest_b64": digest,
                "roster": [],
                "control_b64": "AQ",
                "welcome_b64": "",
                "authenticated_data_b64": "AQ",
                "state_envelope_b64": "AQ"
            }),
            serde_json::json!({
                "type": "mls_application",
                "protocol_version": rooms::MLS_PROTOCOL_VERSION,
                "room_id": "missing-room",
                "message_id": "application-reject",
                "group_id_b64": group,
                "epoch": "0",
                "revision": "1",
                "membership_digest_b64": digest,
                "ciphertext_b64": "AQ",
                "authenticated_data_b64": "AQ",
                "state_envelope_b64": "AQ"
            }),
        ];
        for (index, frame) in frames.into_iter().enumerate() {
            let state = test_state();
            let code = format!("mls-reject-{index}");
            add_test_account(&state, &code, "Alice").await;
            let (client_id, mut rx, mut result_rx) =
                add_test_client_with_result(&state, &code, "Alice").await;
            let frame_text = frame.to_string();
            let handle_task = tokio::spawn({
                let state = state.clone();
                async move { handle_frame(&state, client_id, &frame_text).await }
            });
            let result = result_rx.recv().await.expect("negative transaction result");
            assert!(matches!(
                result.frame,
                OutboundFrame::MlsRoomResult {
                    accepted: false,
                    revision: 1,
                    ..
                }
            ));
            assert!(result.delivered.send(true).is_ok());
            handle_task
                .await
                .expect("MLS rejection task")
                .expect("safe authenticated rejection is acknowledged");
            assert!(rx.try_recv().is_err());
        }

        let state = test_state();
        add_test_account(&state, "snapshot-reject", "Alice").await;
        let (client_id, mut rx, mut result_rx) =
            add_test_client_with_result(&state, "snapshot-reject", "Alice").await;
        let snapshot = serde_json::json!({
            "type": "mls_state_snapshot",
            "protocol_version": rooms::MLS_PROTOCOL_VERSION,
            "room_id": "missing-room",
            "message_id": "snapshot-reject",
            "epoch": "0",
            "revision": "1",
            "membership_digest_b64": digest,
            "state_envelope_b64": "AQ"
        });
        let snapshot_text = snapshot.to_string();
        let handle_task = tokio::spawn({
            let state = state.clone();
            async move { handle_frame(&state, client_id, &snapshot_text).await }
        });
        let result = result_rx.recv().await.expect("negative snapshot result");
        assert!(matches!(
            result.frame,
            OutboundFrame::MlsSnapshotResult {
                ref message_id,
                revision: 1,
                accepted: false,
                ..
            } if message_id == "snapshot-reject"
        ));
        assert!(result.delivered.send(true).is_ok());
        handle_task
            .await
            .expect("snapshot rejection task")
            .expect("safe authenticated snapshot rejection is acknowledged");
        assert!(rx.try_recv().is_err());

        let state = test_state();
        add_test_account(&state, "unsafe-reject", "Alice").await;
        let (client_id, mut rx) = add_test_client(&state, "unsafe-reject", "Alice").await;
        let unsafe_frame = serde_json::json!({
            "type": "mls_application",
            "protocol_version": rooms::MLS_PROTOCOL_VERSION,
            "room_id": "bad room",
            "message_id": "unsafe-reject",
            "group_id_b64": group,
            "epoch": "0",
            "revision": "1",
            "membership_digest_b64": digest,
            "ciphertext_b64": "AQ",
            "authenticated_data_b64": "AQ",
            "state_envelope_b64": "AQ"
        });
        assert!(handle_frame(&state, client_id, &unsafe_frame.to_string())
            .await
            .is_err());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn mls_wire_activates_joiner_only_after_welcome_snapshot() {
        let owner = [1_u8; 32];
        let joiner = [2_u8; 32];
        let mut authority = rooms::RoomAuthority::new(2);
        authority
            .create(
                owner,
                "Alice".to_string(),
                "room-1".to_string(),
                vec![7; rooms::GROUP_ID_BYTES],
                0,
                0,
                vec![8; rooms::MEMBERSHIP_DIGEST_BYTES],
                vec![1; rooms::STABLE_IDENTITY_BYTES],
            )
            .unwrap();
        let request = authority
            .request_join(
                joiner,
                "Bob".to_string(),
                "room-1",
                "request-1".to_string(),
                vec![2; rooms::STABLE_IDENTITY_BYTES],
                vec![5],
                vec![9],
            )
            .unwrap();
        authority
            .begin_membership(
                owner,
                rooms::MembershipTransition {
                    room_id: "room-1".to_string(),
                    message_id: "commit-1".to_string(),
                    request_id: Some(request.request_id.clone()),
                    from_epoch: 0,
                    to_epoch: 1,
                    revision: 1,
                    group_id: vec![7; rooms::GROUP_ID_BYTES],
                    from_membership_digest: vec![8; rooms::MEMBERSHIP_DIGEST_BYTES],
                    membership_digest: vec![8; rooms::MEMBERSHIP_DIGEST_BYTES],
                    roster: vec![
                        rooms::RosterMember {
                            username: "Alice".to_string(),
                            stable_identity: vec![1; rooms::STABLE_IDENTITY_BYTES],
                        },
                        rooms::RosterMember {
                            username: "Bob".to_string(),
                            stable_identity: vec![2; rooms::STABLE_IDENTITY_BYTES],
                        },
                    ],
                    control: vec![1],
                    welcome: vec![2],
                    authenticated_data: vec![3],
                    state_envelope: vec![4],
                    created_at_ms: 0,
                    expires_at_ms: 0,
                },
            )
            .unwrap();
        authority
            .accept_membership(owner, "room-1", "commit-1", 1)
            .unwrap();
        let before = mls_room_wire(authority.member_info("room-1", &joiner).unwrap());
        assert!(!before.active);
        assert!(!before.recovery_snapshot.as_ref().unwrap().active);

        let welcome = authority
            .deliveries_for_member("room-1", &joiner)
            .unwrap()
            .pop()
            .unwrap();
        authority
            .store_snapshot(
                joiner,
                "room-1",
                &welcome.message_id,
                welcome.epoch,
                welcome.revision,
                welcome.membership_digest.clone(),
                vec![6],
            )
            .unwrap();
        let after = mls_room_wire(authority.member_info("room-1", &joiner).unwrap());
        assert!(after.active);
        assert!(after.recovery_snapshot.as_ref().unwrap().active);
    }

    #[tokio::test]
    async fn active_mls_snapshot_ack_refreshes_catalog_without_domain_result_or_queue_replay() {
        let state = test_state();
        add_test_account(&state, "code-a", "Alice").await;
        add_test_account(&state, "code-b", "Bob").await;
        let owner = test_code_id("code-a");
        let recipient = test_code_id("code-b");
        {
            let mut authority = state.mls_rooms.lock().await;
            authority
                .create(
                    owner,
                    "Alice".to_string(),
                    "room-ack".to_string(),
                    vec![7; rooms::GROUP_ID_BYTES],
                    0,
                    0,
                    vec![8; rooms::MEMBERSHIP_DIGEST_BYTES],
                    vec![1; rooms::STABLE_IDENTITY_BYTES],
                )
                .unwrap();
            let join = authority
                .request_join(
                    recipient,
                    "Bob".to_string(),
                    "room-ack",
                    "request-1".to_string(),
                    vec![2; rooms::STABLE_IDENTITY_BYTES],
                    vec![5],
                    vec![9],
                )
                .unwrap();
            authority
                .begin_membership(
                    owner,
                    rooms::MembershipTransition {
                        room_id: "room-ack".to_string(),
                        message_id: "commit-1".to_string(),
                        request_id: Some(join.request_id.clone()),
                        from_epoch: 0,
                        to_epoch: 1,
                        revision: 1,
                        group_id: vec![7; rooms::GROUP_ID_BYTES],
                        from_membership_digest: vec![8; rooms::MEMBERSHIP_DIGEST_BYTES],
                        membership_digest: vec![8; rooms::MEMBERSHIP_DIGEST_BYTES],
                        roster: vec![
                            rooms::RosterMember {
                                username: "alice".to_string(),
                                stable_identity: vec![1; rooms::STABLE_IDENTITY_BYTES],
                            },
                            rooms::RosterMember {
                                username: "bob".to_string(),
                                stable_identity: vec![2; rooms::STABLE_IDENTITY_BYTES],
                            },
                        ],
                        control: vec![1],
                        welcome: vec![2],
                        authenticated_data: vec![3],
                        state_envelope: vec![4],
                        created_at_ms: 0,
                        expires_at_ms: 0,
                    },
                )
                .unwrap();
            authority
                .accept_membership(owner, "room-ack", "commit-1", 1)
                .unwrap();
            let welcome = authority
                .deliveries_for_member("room-ack", &recipient)
                .unwrap()
                .pop()
                .unwrap();
            authority
                .store_snapshot(
                    recipient,
                    "room-ack",
                    &welcome.message_id,
                    welcome.epoch,
                    welcome.revision,
                    welcome.membership_digest.clone(),
                    vec![6],
                )
                .unwrap();
            authority
                .admit_application(
                    owner,
                    "room-ack",
                    "application-1".to_string(),
                    vec![7; rooms::GROUP_ID_BYTES],
                    1,
                    2,
                    vec![8; rooms::MEMBERSHIP_DIGEST_BYTES],
                    vec![10],
                    vec![11],
                    vec![12],
                )
                .unwrap();
            authority
                .commit_application("room-ack", "application-1")
                .unwrap();
        }
        let client_id = Uuid::new_v4();
        let (data_tx, mut data_rx) = mpsc::channel(CLIENT_OUTBOUND_QUEUE_CAPACITY);
        let (control_tx, _control_rx) = mpsc::channel(CLIENT_CONTROL_QUEUE_CAPACITY);
        let (result_tx, mut result_rx) = mpsc::channel(CLIENT_RESULT_QUEUE_CAPACITY);
        state.clients.lock().await.insert(
            client_id,
            ClientHandle {
                code_id: recipient,
                username: "Bob".to_string(),
                platform: ClientPlatform::Android,
                tx: data_tx,
                control_tx,
                result_tx,
                queued_bytes: Arc::new(AtomicUsize::new(0)),
            },
        );

        mls_state_snapshot(
            &state,
            client_id,
            "room-ack".to_string(),
            "application-1".to_string(),
            1,
            1,
            URL_SAFE_NO_PAD.encode([8_u8; rooms::MEMBERSHIP_DIGEST_BYTES]),
            URL_SAFE_NO_PAD.encode([13_u8]),
        )
        .await
        .unwrap();
        let catalog = data_rx.recv().await.expect("fresh MLS catalog");
        assert!(matches!(
            catalog,
            OutboundFrame::MlsRooms { ref rooms, .. }
                if rooms.len() == 1 && rooms[0].synchronized
        ));
        assert!(data_rx.try_recv().is_err());
        assert!(result_rx.try_recv().is_err());
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
    async fn relay_requires_v9_signature_on_each_recipient_envelope() {
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
        .expect("valid v9 message should route");
        let OutboundFrame::Message {
            signature_b64,
            identity_public_b64,
            sender_public_key_b64,
            ..
        } = &bob_rx.try_recv().expect("Bob receives v9 message")
        else {
            panic!("expected text frame");
        };
        assert_eq!(signature_b64, &valid_signature);
        assert_eq!(identity_public_b64, sender_public_key_b64);
    }

    #[tokio::test]
    async fn forged_signature_cannot_lease_prekey_or_mutate_relay_state() {
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
        assert!(state.prekey_leases.lock().await.is_empty());
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

    #[test]
    fn inbound_message_requires_complete_directory_evidence() {
        let frame = serde_json::json!({
            "type": "message",
            "chat_id": "dm_a_b",
            "version": E2EE_PROTOCOL_VERSION,
            "message_id": "message-directory-1",
            "nonce_b64": URL_SAFE_NO_PAD.encode([1_u8; MESSAGE_NONCE_BYTES]),
            "ciphertext_b64": URL_SAFE_NO_PAD.encode([2_u8; 16]),
            "envelopes": [{
                "recipient_username": "Bob",
                "wrapped_key_b64": URL_SAFE_NO_PAD.encode([3_u8; 32]),
                "prekey_id": "",
                "is_prekey": false,
                "signature_b64": URL_SAFE_NO_PAD.encode([4_u8; MESSAGE_SIGNATURE_BYTES])
            }],
            "state_revision": 1,
            "identity_envelope_b64": URL_SAFE_NO_PAD.encode([IDENTITY_ENVELOPE_VERSION; 256]),
            "identity_public_b64": URL_SAFE_NO_PAD.encode([5_u8; IDENTITY_PUBLIC_BYTES]),
            "prekey_id": "fallback",
            "state_signature_b64": URL_SAFE_NO_PAD.encode([6_u8; MESSAGE_SIGNATURE_BYTES]),
            "directory_node_id": "test-node",
            "directory_revision": 1,
            "directory_digest": URL_SAFE_NO_PAD.encode([7_u8; DIRECTORY_DIGEST_BYTES]),
            "padding_bucket": 4096,
            "padding": ""
        });
        assert!(serde_json::from_value::<InboundFrame>(frame.clone()).is_ok());
        for field in [
            "directory_node_id",
            "directory_revision",
            "directory_digest",
        ] {
            let mut incomplete = frame.clone();
            incomplete
                .as_object_mut()
                .expect("message object")
                .remove(field);
            assert!(
                serde_json::from_value::<InboundFrame>(incomplete).is_err(),
                "missing {field} must fail closed"
            );
        }
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
        let claims_before = state.prekey_leases.lock().await.len();

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
        assert_eq!(state.prekey_leases.lock().await.len(), claims_before);
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
        state.prekey_leases.lock().await.insert(
            PrekeyLeaseKey {
                code_id: test_code_id("code-b"),
                prekey_id: prekey_id.clone(),
            },
            PrekeyLease {
                chat_id: room.id.clone(),
                message_id: message_id.to_string(),
                sender_username: "Alice".to_string(),
                recipient_username: "Bob".to_string(),
                created_at_ms: now_ms(),
            },
        );
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
        let (identity_public, current_prekey_id) =
            test_identity_public_after_consumption(b'B', &prekey_id);
        let identity_public_b64 = URL_SAFE_NO_PAD.encode(identity_public);
        let state_signature_b64 = test_valid_state_signature_b64(
            b'B',
            1,
            &envelope_b64,
            &identity_public_b64,
            &current_prekey_id,
        );
        let pending_key = PendingKey {
            chat_id: room.id.clone(),
            recipient_username: "Bob".to_string(),
        };
        let before = ack_test_snapshot(&state, &test_code_id("code-b"), &pending_key).await;
        assert!(!before.3.is_empty(), "prekey lease should be pending");

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
            &current_prekey_id,
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
            &current_prekey_id,
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
            &current_prekey_id,
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
            &current_prekey_id,
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
        assert!(state.prekey_leases.lock().await.is_empty());
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
        state.prekey_leases.lock().await.insert(
            PrekeyLeaseKey {
                code_id: test_code_id("code-b"),
                prekey_id: prekey_id.clone(),
            },
            PrekeyLease {
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
            .prekey_leases
            .lock()
            .await
            .contains_key(&PrekeyLeaseKey {
                code_id: test_code_id("code-b"),
                prekey_id,
            }));
    }

    #[tokio::test]
    async fn prekey_ack_requires_a_matching_lease_before_mutating_state() {
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
            "wrong-prekey",
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
        for (index, (_, public)) in test_prekey_pool(b'Z').into_iter().enumerate() {
            let start = ONE_TIME_KEY_OFFSET + (index * ONE_TIME_KEY_BYTES);
            stale_public[start..start + ONE_TIME_KEY_BYTES].copy_from_slice(&public);
        }
        let stale_public_b64 = URL_SAFE_NO_PAD.encode(&stale_public);
        let stale_prekey_id = test_prekey_id(b'Z');
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

    #[tokio::test]
    async fn interop_policy_requires_a_known_allowed_recipient_platform() {
        let state = test_state();
        add_test_account(&state, "code-b", "Bob").await;
        let recipients = HashSet::from(["Bob".to_string()]);

        state
            .accounts
            .lock()
            .await
            .get_mut(&test_code_id("code-b"))
            .expect("Bob account")
            .client_platform = Some(ClientPlatform::Web);
        assert!(
            require_recipient_platforms(&state, ClientPlatform::Android, &recipients)
                .await
                .is_err()
        );
        assert!(
            require_recipient_platforms(&state, ClientPlatform::Web, &recipients)
                .await
                .is_ok()
        );

        state
            .accounts
            .lock()
            .await
            .get_mut(&test_code_id("code-b"))
            .expect("Bob account")
            .client_platform = None;
        assert!(
            require_recipient_platforms(&state, ClientPlatform::Web, &recipients)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn pending_android_ciphertext_is_not_delivered_to_a_web_connection() {
        let state = test_state();
        add_test_account(&state, "code-a", "Alice").await;
        add_test_account(&state, "code-b", "Bob").await;
        let (alice_id, _alice_rx) = add_test_client(&state, "code-a", "Alice").await;
        let (bob_id, mut bob_rx) = add_test_client(&state, "code-b", "Bob").await;
        state
            .clients
            .lock()
            .await
            .get_mut(&bob_id)
            .expect("Bob client")
            .platform = ClientPlatform::Web;
        state
            .accounts
            .lock()
            .await
            .get_mut(&test_code_id("code-b"))
            .expect("Bob account")
            .client_platform = Some(ClientPlatform::Web);

        open_direct(&state, alice_id, "Bob")
            .await
            .expect("direct opens");
        let direct_id = state
            .direct_catalog
            .lock()
            .await
            .values()
            .next()
            .expect("direct catalog entry")
            .id
            .clone();
        while bob_rx.try_recv().is_ok() {}
        let frame = test_message_frame(&direct_id, "android-only", "Alice", "", false);
        state.pending.lock().await.insert(
            PendingKey {
                chat_id: direct_id.clone(),
                recipient_username: "Bob".to_string(),
            },
            vec![PendingFrame::new_for_platform(
                frame,
                now_ms(),
                ClientPlatform::Android,
            )],
        );

        join_room(&state, bob_id, direct_id)
            .await
            .expect("authorized peer joins");
        assert!(bob_rx.try_recv().is_err());
    }

    fn test_state() -> AppState {
        AppState {
            node_id: "test-node".to_string(),
            release_admission: Arc::new(ReleaseAdmissionStore::ready_for_tests()),
            attachment_ram_limit_bytes: 8 * 1024 * 1024,
            attachment_account_limit_bytes: 4 * 1024 * 1024,
            attachment_record_limit: DEFAULT_ATTACHMENT_RECORD_LIMIT,
            attachment_account_record_limit: DEFAULT_ATTACHMENT_ACCOUNT_RECORD_LIMIT,
            attachment_max_lifetime_sec: DEFAULT_ATTACHMENT_MAX_LIFETIME_HOURS as u64 * 60 * 60,
            max_rooms_per_user: 2,
            interop_policy: InteropPolicy::new(false, true),
            conversation_ops: Arc::new(Mutex::new(())),
            presence_broadcast_ops: Arc::new(Mutex::new(())),
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
            transaction_receipts: Arc::new(Mutex::new(TransactionReceiptStore::new(
                pending_message_ttl_ms_from_value(None),
            ))),
            mls_rooms: Arc::new(Mutex::new(rooms::RoomAuthority::new(2))),
            rooms: Arc::new(Mutex::new(HashMap::new())),
            room_catalog: Arc::new(Mutex::new(HashMap::new())),
            direct_catalog: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
            pending_bytes: Arc::new(Mutex::new(0)),
            attachment_bindings: Arc::new(Mutex::new(HashMap::new())),
            attachments: Arc::new(Mutex::new(HashMap::new())),
            attachment_bytes_by_code: Arc::new(Mutex::new(HashMap::new())),
            attachment_downloads: Arc::new(Semaphore::new(DEFAULT_ATTACHMENT_DOWNLOAD_CONCURRENCY)),
            attachment_uploads: Arc::new(Semaphore::new(1)),
            attachment_memory: Arc::new(Semaphore::new(8 * 1024 * 1024)),
            attachment_epoch: Arc::new(AtomicU64::new(0)),
            prekey_leases: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn add_test_account(state: &AppState, code: &str, username: &str) {
        add_test_account_with_id(state, test_code_id(code), username, ClientPlatform::Android)
            .await;
    }

    async fn add_test_account_with_id(
        state: &AppState,
        code_id: CodeId,
        username: &str,
        client_platform: ClientPlatform,
    ) {
        let identity_fill = username.as_bytes()[0];
        let mut identity_envelope = vec![0; 256];
        identity_envelope[0] = IDENTITY_ENVELOPE_VERSION;
        state.accounts.lock().await.insert(
            code_id,
            Account {
                username: username.to_string(),
                password_file: vec![1; 192],
                identity_public: test_identity_public(identity_fill),
                prekey_id: test_prekey_id(identity_fill),
                identity_envelope,
                state_revision: 0,
                state_revision_window: 1,
                connected: true,
                client_platform: Some(client_platform),
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
            .prekey_leases
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
                platform: ClientPlatform::Android,
                tx,
                control_tx,
                result_tx,
                queued_bytes: Arc::new(AtomicUsize::new(0)),
            },
        );
        (client_id, rx)
    }

    async fn add_test_client_with_result(
        state: &AppState,
        code: &str,
        username: &str,
    ) -> (
        Uuid,
        mpsc::Receiver<OutboundFrame>,
        mpsc::Receiver<ClientResult>,
    ) {
        let client_id = Uuid::new_v4();
        let (tx, rx) = mpsc::channel(CLIENT_OUTBOUND_QUEUE_CAPACITY);
        let (control_tx, _control_rx) = mpsc::channel(CLIENT_CONTROL_QUEUE_CAPACITY);
        let (result_tx, result_rx) = mpsc::channel(CLIENT_RESULT_QUEUE_CAPACITY);
        state.clients.lock().await.insert(
            client_id,
            ClientHandle {
                code_id: test_code_id(code),
                username: username.to_string(),
                platform: ClientPlatform::Android,
                tx,
                control_tx,
                result_tx,
                queued_bytes: Arc::new(AtomicUsize::new(0)),
            },
        );
        (client_id, rx, result_rx)
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

    fn test_valid_encrypted_attachment_body(plaintext_bytes: usize) -> Vec<u8> {
        abyssal_core::secure_protocol::encrypt_attachment(
            "test_room".to_string(),
            "test-message".to_string(),
            "Alice".to_string(),
            "FILE".to_string(),
            vec![0x5a; plaintext_bytes],
        )
        .expect("test attachment encryption")
        .blob
    }

    fn test_identity_public_b64(fill: u8) -> String {
        URL_SAFE_NO_PAD.encode(test_identity_public(fill))
    }

    fn test_identity_public(fill: u8) -> Vec<u8> {
        let signing_key = test_signing_key(fill);
        let mut identity_public = vec![fill; IDENTITY_PUBLIC_BYTES];
        identity_public[IDENTITY_FINGERPRINT_BYTES - 32..IDENTITY_FINGERPRINT_BYTES]
            .copy_from_slice(signing_key.verifying_key().as_bytes());
        for (index, (_, public)) in test_prekey_pool(fill).into_iter().enumerate() {
            let start = ONE_TIME_KEY_OFFSET + (index * ONE_TIME_KEY_BYTES);
            identity_public[start..start + ONE_TIME_KEY_BYTES].copy_from_slice(&public);
        }
        identity_public
    }

    fn test_signing_key(fill: u8) -> SigningKey {
        SigningKey::from_bytes(&[fill; 32])
    }

    fn test_prekey_id(fill: u8) -> String {
        test_prekey_pool(fill)
            .into_iter()
            .next()
            .expect("test prekey pool")
            .0
    }

    fn test_prekey_pool(fill: u8) -> Vec<(String, [u8; ONE_TIME_KEY_BYTES])> {
        let mut pool = (0..PREKEY_POOL_SIZE_V9)
            .map(|index| {
                let public = [fill.wrapping_add(index as u8); ONE_TIME_KEY_BYTES];
                (
                    abyssal_core::secure_protocol::prekey_id_for_public(&public),
                    public,
                )
            })
            .collect::<Vec<_>>();
        pool.sort_by(|left, right| left.0.cmp(&right.0));
        pool
    }

    fn test_identity_public_after_consumption(
        fill: u8,
        consumed_prekey_id: &str,
    ) -> (Vec<u8>, String) {
        let mut pool = test_prekey_pool(fill);
        pool.retain(|(id, _)| id != consumed_prekey_id);
        let replacement = (1_u16..=u8::MAX as u16)
            .map(|offset| [fill.wrapping_add(offset as u8); ONE_TIME_KEY_BYTES])
            .map(|public| {
                (
                    abyssal_core::secure_protocol::prekey_id_for_public(&public),
                    public,
                )
            })
            .find(|(id, _)| {
                id != consumed_prekey_id && !pool.iter().any(|(existing, _)| existing == id)
            })
            .expect("replacement prekey");
        pool.push(replacement);
        pool.sort_by(|left, right| left.0.cmp(&right.0));
        let current_prekey_id = pool.first().expect("rotated pool").0.clone();
        let mut identity_public = test_identity_public(fill);
        for (index, (_, public)) in pool.into_iter().enumerate() {
            let start = ONE_TIME_KEY_OFFSET + (index * ONE_TIME_KEY_BYTES);
            identity_public[start..start + ONE_TIME_KEY_BYTES].copy_from_slice(&public);
        }
        (identity_public, current_prekey_id)
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
        let transcript = abyssal_core::secure_protocol::identity_state_signature_input_v9(
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
        let transcript = abyssal_core::secure_protocol::ack_signature_input_v9(
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
        let transcript = abyssal_core::secure_protocol::message_signature_input_v9(
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
        let mut frame = OutboundFrame::Message {
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
            directory_node_id: "test-node".to_string(),
            directory_revision: 1,
            directory_digest: URL_SAFE_NO_PAD.encode([0_u8; 32]),
            padding_bucket: 0,
            padding: String::new(),
        };
        prepare_outbound_message_padding(&mut frame).expect("test message transport padding");
        frame
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
