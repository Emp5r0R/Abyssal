use std::{
    borrow::Borrow,
    collections::{HashMap, HashSet},
    convert::Infallible,
    env, io,
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
    verify_registration_identity_proof_v9, IDENTITY_PUBLIC_BYTES_V9, PREKEY_POOL_SIZE_V9,
    REGISTRATION_CHALLENGE_BYTES_V9,
};
#[cfg(test)]
use abyssal_core::secure_protocol::{ATTACHMENT_BLOB_VERSION, ATTACHMENT_CHUNK_RECORD_BYTES};
use abyssal_invite::account_context_v1;
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

mod attachments;
mod auth;
mod client_platform;
mod config;
mod http;
mod invite_bootstrap;
mod messages;
mod mls;
mod mls_wire;
mod release_admission;
mod rooms;
mod transaction_receipts;
mod transport;
mod transport_padding;

use attachments::*;
use auth::*;
use client_platform::{ClientPlatform, InteropPolicy};
use config::*;
#[cfg(test)]
use http::{
    node_descriptor_endpoint, release_manifest_endpoint, release_signature_endpoint,
    CACHE_CONTROL_POLICY, CONTENT_SECURITY_POLICY,
};
use invite_bootstrap::{write_boot_invites, BootstrapMaterials, IssuedInvite};
use messages::*;
use mls::*;
use release_admission::{
    BuildAttestationRequest, InstallOutcome, ReleaseAdmissionStore, ReleaseManifestMirror,
};
use transaction_receipts::{
    BeginOutcome as TransactionBeginOutcome, ReceiptError as TransactionReceiptError,
    TransactionKey, TransactionKind, TransactionReceiptStore, TransactionTicket,
};
use transport::*;
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
const CODE_ID_DOMAIN: &[u8] = b"ABYSSAL_CAPABILITY_ID_V1";

type CodeId = [u8; 32];
type WsTicketDigest = [u8; WS_TICKET_BYTES];
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
struct AppState {
    node_id: String,
    node_public_key: [u8; 32],
    node_descriptor: Arc<Vec<u8>>,
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
    boot_invites: Arc<Mutex<Option<Vec<IssuedInvite>>>>,
    available_codes: Arc<Mutex<HashSet<CodeId>>>,
    capability_expiries: Arc<Mutex<HashMap<CodeId, u64>>>,
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

impl Drop for Account {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password_file.zeroize();
        self.identity_public.zeroize();
        self.identity_envelope.zeroize();
        self.prekey_id.zeroize();
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
    capability_b64: String,
    registration_request_b64: String,
    credential_request_b64: String,
}

impl Drop for OpaqueAccountStartRequest {
    fn drop(&mut self) {
        self.capability_b64.zeroize();
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

    let app = http::router(state.clone());

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .expect("failed to bind ABYSSAL_BIND_ADDR");

    info!("abyssal relay listening on {bind_addr}");
    let invite_print_delay_ms = std::env::var("ABYSSAL_INVITE_PRINT_DELAY_MS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_else(|| read_usize_env("ABYSSAL_CODE_PRINT_DELAY_MS", 0))
        .min(30_000) as u64;
    if invite_print_delay_ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(invite_print_delay_ms)).await;
    }
    state.print_boot_invites().await;
    axum::serve(listener, app).await.expect("server failed");
}

impl AppState {
    fn from_env() -> Self {
        let (purge_epoch, _) = watch::channel(0_u64);
        let mut invite_code_pepper = [0_u8; 32];
        OsRng.fill_bytes(&mut invite_code_pepper);
        let bootstrap = BootstrapMaterials::from_env(now_ms() / 1_000).unwrap_or_else(|error| {
            panic!("Abyssal node bootstrap configuration rejected: {error}")
        });
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

        let available_codes = bootstrap
            .issued_invites
            .iter()
            .map(|invite| derive_code_id(&invite_code_pepper, invite.capability.as_slice()))
            .collect::<HashSet<_>>();
        if available_codes.len() != bootstrap.issued_invites.len() {
            panic!("CSPRNG generated a duplicate bootstrap capability");
        }
        let capability_expiries = bootstrap
            .issued_invites
            .iter()
            .filter_map(|invite| {
                invite.expires_at.map(|expiry| {
                    (
                        derive_code_id(&invite_code_pepper, invite.capability.as_slice()),
                        expiry,
                    )
                })
            })
            .collect::<HashMap<_, _>>();
        info!("ABYSSAL_NODE_IDENTITY node_id={}", bootstrap.node_id);
        info!(
            "ABYSSAL_NODE_FINGERPRINT fingerprint={}",
            bootstrap.fingerprint
        );
        info!(
            "ABYSSAL_PUBLIC_LOCATOR locator={}",
            bootstrap.locator.api_base_url()
        );

        Self {
            node_id: bootstrap.node_id,
            node_public_key: bootstrap.node_public_key,
            node_descriptor: Arc::new(bootstrap.descriptor_binary),
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
            boot_invites: Arc::new(Mutex::new(Some(bootstrap.issued_invites))),
            available_codes: Arc::new(Mutex::new(available_codes)),
            capability_expiries: Arc::new(Mutex::new(capability_expiries)),
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

    async fn print_boot_invites(&self) {
        let Some(invites) = self.boot_invites.lock().await.take() else {
            return;
        };
        let print_result = {
            let stdout = io::stdout();
            let mut output = stdout.lock();
            write_boot_invites(&mut output, &invites)
        };
        if let Err(error) = print_result {
            panic!("failed to print Abyssal startup invites: {error}");
        }
        drop(invites);
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

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

fn derive_code_id(pepper: &[u8], capability: impl AsRef<[u8]>) -> CodeId {
    let mut mac = HmacSha256::new_from_slice(pepper).expect("HMAC accepts any key length");
    mac.update(CODE_ID_DOMAIN);
    mac.update(capability.as_ref());
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
    available_capability_is_live(state, code_id).await
}

async fn available_capability_is_live(state: &AppState, code_id: &CodeId) -> bool {
    let mut available = state.available_codes.lock().await;
    if !available.contains(code_id) {
        return false;
    }
    let expiry = state.capability_expiries.lock().await.get(code_id).copied();
    if expiry.is_some_and(|expires_at| expires_at <= now_ms() / 1_000) {
        if let Some(mut expired) = available.take(code_id) {
            expired.zeroize();
        }
        drop(available);
        let mut expiries = state.capability_expiries.lock().await;
        remove_code_id_map_entry(&mut expiries, code_id);
        return false;
    }
    true
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
    let mut capability_expiries = state.capability_expiries.lock().await;
    zeroize_code_id_map(&mut capability_expiries);
    drop(capability_expiries);
    drop(state.boot_invites.lock().await.take());
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
mod main_tests;
