use std::{
    collections::{HashMap, HashSet},
    env,
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use argon2::{
    password_hash::{
        rand_core::OsRng as SaltOsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
    Argon2,
};
use axum::{
    body::Bytes,
    extract::{
        ws::{Message, WebSocket},
        DefaultBodyLimit, Path, Query, State, WebSocketUpgrade,
    },
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use futures_util::{SinkExt, StreamExt};
use rand::{rngs::OsRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};
use uuid::Uuid;

const IMAGE_ATTACHMENT_LIMIT_BYTES: usize = 20 * 1024 * 1024;
const VIDEO_ATTACHMENT_LIMIT_BYTES: usize = 100 * 1024 * 1024;
const FILE_ATTACHMENT_LIMIT_BYTES: usize = 200 * 1024 * 1024;
const ENCRYPTION_OVERHEAD_BYTES: usize = 64 * 1024;
const WS_RATE_WINDOW_MS: u64 = 10_000;
const WS_MAX_FRAMES_PER_WINDOW: usize = 30;
const WS_MAX_FRAME_BYTES: usize = 64 * 1024;
const MAX_PENDING_FRAMES_PER_ROOM: usize = 500;

#[derive(Clone)]
struct AppState {
    node_id: String,
    attachment_ram_limit_bytes: usize,
    max_rooms_per_user: usize,
    session_inactivity_ms: u64,
    inactivity_limit_ms: Option<u64>,
    last_activity_ms: Arc<Mutex<u64>>,
    account_ops: Arc<Mutex<()>>,
    available_codes: Arc<Mutex<HashSet<String>>>,
    accounts: Arc<Mutex<HashMap<String, Account>>>,
    sessions: Arc<Mutex<HashMap<String, AuthSession>>>,
    clients: Arc<Mutex<HashMap<Uuid, ClientHandle>>>,
    frame_limits: Arc<Mutex<HashMap<Uuid, RateState>>>,
    rooms: Arc<Mutex<HashMap<String, HashSet<Uuid>>>>,
    room_catalog: Arc<Mutex<HashMap<String, RoomEntry>>>,
    pending: Arc<Mutex<HashMap<String, Vec<OutboundFrame>>>>,
    attachments: Arc<Mutex<HashMap<Uuid, AttachmentRecord>>>,
}

#[derive(Clone)]
struct Account {
    username: String,
    password_hash: String,
    connected: bool,
}

#[derive(Clone)]
struct AuthSession {
    code: String,
    username: String,
    last_activity_ms: u64,
}

#[derive(Clone)]
struct ClientHandle {
    code: String,
    username: String,
    tx: mpsc::UnboundedSender<Message>,
}

#[derive(Clone)]
struct RoomEntry {
    room: RoomRecord,
    owner_code: String,
}

#[derive(Clone)]
struct RateState {
    window_start_ms: u64,
    count: usize,
}

struct AttachmentRecord {
    encrypted_bytes: Vec<u8>,
    chat_id: String,
    media_type: String,
    one_time: bool,
    delete_after_download: bool,
    expires_at_ms: Option<u64>,
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
struct AccountRequest {
    code: String,
    password: String,
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
    error: Option<String>,
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
struct WsQuery {
    token: String,
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
        payload_b64: String,
    },
    #[serde(rename = "read_receipt")]
    ReadReceipt {
        chat_id: String,
        message_id: Option<String>,
    },
    #[serde(rename = "global_wipe")]
    GlobalWipe,
    #[serde(rename = "create_room")]
    CreateRoom { room: RoomRecord },
    #[serde(rename = "delete_room")]
    DeleteRoom { chat_id: String },
    #[serde(rename = "dummy")]
    Dummy {
        padding_b64: Option<String>,
        bytes: Option<usize>,
    },
}

#[derive(Clone, Serialize)]
#[serde(tag = "type")]
enum OutboundFrame {
    #[serde(rename = "message")]
    Message {
        chat_id: String,
        payload_b64: String,
    },
    #[serde(rename = "read_receipt")]
    ReadReceipt {
        chat_id: String,
        message_id: Option<String>,
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
}

#[derive(Clone, Serialize)]
struct PresenceUser {
    username: String,
    connected: bool,
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
    state.print_boot_codes().await;
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
    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/account/create", post(create_account))
        .route("/v1/account/login", post(login_account))
        .route("/v1/account/enter", post(enter_account))
        .route("/v1/account/logout", post(logout_account))
        .route("/v1/attachment", post(upload_attachment))
        .route("/v1/attachment/:id", get(download_attachment))
        .route("/v1/invite/validate", post(login_account))
        .layer(DefaultBodyLimit::max(attachment_body_limit))
        .route("/v1/ws", get(ws_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .expect("failed to bind ABYSSAL_BIND_ADDR");

    info!("abyssal relay listening on {bind_addr}");
    axum::serve(listener, app).await.expect("server failed");
}

impl AppState {
    fn from_env() -> Self {
        let node_id = env::var("ABYSSAL_NODE_ID")
            .or_else(|_| env::var("MIRAGE_NODE_ID"))
            .unwrap_or_else(|_| format!("abyssal-{}", Uuid::new_v4().simple()));

        let user_count = read_usize_env("ABYSSAL_CODE_COUNT", 5);
        let min_len = read_usize_env("ABYSSAL_CODE_MIN_LEN", 12).max(12);
        let requested_max_len = read_usize_env("ABYSSAL_CODE_MAX_LEN", min_len + user_count);
        let max_len = requested_max_len.max(min_len + user_count);
        let mut available_codes = HashSet::new();
        let mut generated_lengths = HashSet::new();
        let attachment_ram_limit_bytes =
            read_usize_env("ABYSSAL_ATTACHMENT_RAM_LIMIT_MB", 512).saturating_mul(1024 * 1024);
        let max_rooms_per_user = read_usize_env("ABYSSAL_MAX_ROOMS_PER_USER", 5).clamp(1, 100);
        let session_inactivity_minutes =
            read_usize_env("ABYSSAL_SESSION_INACTIVITY_MINUTES", 15).clamp(1, 24 * 60);
        let session_inactivity_ms = session_inactivity_minutes.saturating_mul(60 * 1000) as u64;
        let inactivity_limit_ms = read_usize_env("ABYSSAL_INACTIVITY_LIMIT_HOURS", 0)
            .checked_mul(60 * 60 * 1000)
            .filter(|limit| *limit > 0)
            .map(|limit| limit as u64);

        for code in parse_codes_from_env("ABYSSAL_INVITE_CODES")
            .into_iter()
            .chain(parse_codes_from_env("MIRAGE_INVITE_CODES"))
        {
            available_codes.insert(code);
        }

        generate_codes(
            &mut available_codes,
            &mut generated_lengths,
            user_count,
            min_len,
            max_len,
        );

        Self {
            node_id,
            attachment_ram_limit_bytes,
            max_rooms_per_user,
            session_inactivity_ms,
            inactivity_limit_ms,
            last_activity_ms: Arc::new(Mutex::new(now_ms())),
            account_ops: Arc::new(Mutex::new(())),
            available_codes: Arc::new(Mutex::new(available_codes)),
            accounts: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            clients: Arc::new(Mutex::new(HashMap::new())),
            frame_limits: Arc::new(Mutex::new(HashMap::new())),
            rooms: Arc::new(Mutex::new(HashMap::new())),
            room_catalog: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
            attachments: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn print_boot_codes(&self) {
        let codes = self.available_codes.lock().await;
        info!("ABYSSAL RAM-ONLY ACCESS CODES - copy these now; they are not written to disk");
        for code in codes.iter() {
            info!("ABYSSAL_CODE code={code}");
        }
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

fn parse_codes_from_env(key: &str) -> Vec<String> {
    env::var(key)
        .unwrap_or_default()
        .split(',')
        .filter_map(|code| normalize_code(code).ok())
        .collect()
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
        let idx = (rng.next_u32() as usize) % ALPHABET.len();
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
        && !code.starts_with('-')
        && !code.ends_with('-')
        && code.chars().any(|ch| ch.is_ascii_alphanumeric())
        && code
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
}

fn validate_password(password: &str) -> Result<(), String> {
    if password.len() < 8 {
        return Err("Password must be at least 8 characters.".to_string());
    }
    if password.len() > 256 {
        return Err("Password is too long.".to_string());
    }
    Ok(())
}

fn code_log_label(code: &str) -> String {
    let suffix_rev: String = code.chars().rev().take(4).collect();
    let suffix: String = suffix_rev.chars().rev().collect();
    format!("len={} suffix={suffix}", code.len())
}

fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut SaltOsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|err| err.to_string())
}

fn verify_password(password: &str, encoded_hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(encoded_hash) {
        Ok(hash) => hash,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
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

fn random_unique_username(accounts: &HashMap<String, Account>) -> String {
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

async fn create_account(
    State(state): State<AppState>,
    Json(request): Json<AccountRequest>,
) -> impl IntoResponse {
    touch_activity(&state).await;
    let _account_guard = state.account_ops.lock().await;
    let code = match normalize_code(&request.code) {
        Ok(code) => code,
        Err(error) => return account_error(StatusCode::BAD_REQUEST, &state, error).await,
    };
    info!("account_create_attempt {}", code_log_label(&code));
    if let Err(error) = validate_password(&request.password) {
        warn!(
            "account_create_rejected {} reason=password_shape",
            code_log_label(&code)
        );
        return account_error(StatusCode::BAD_REQUEST, &state, error).await;
    }

    if !state.available_codes.lock().await.remove(&code) {
        if state.accounts.lock().await.contains_key(&code) {
            warn!(
                "account_create_rejected {} reason=already_created",
                code_log_label(&code)
            );
            return account_error(
                StatusCode::CONFLICT,
                &state,
                "Code already has an account. Use login.".to_string(),
            )
            .await;
        }
        warn!(
            "account_create_rejected {} reason=unknown_code",
            code_log_label(&code)
        );
        return account_error(
            StatusCode::UNAUTHORIZED,
            &state,
            "Code rejected.".to_string(),
        )
        .await;
    }

    let password_hash = match hash_password(&request.password) {
        Ok(hash) => hash,
        Err(error) => return account_error(StatusCode::INTERNAL_SERVER_ERROR, &state, error).await,
    };
    let mut accounts = state.accounts.lock().await;
    let username = random_unique_username(&accounts);
    accounts.insert(
        code.clone(),
        Account {
            username: username.clone(),
            password_hash,
            connected: false,
        },
    );
    drop(accounts);
    info!(
        "account_create_accepted {} username={}",
        code_log_label(&code),
        username
    );

    issue_session(&state, code, username, true).await
}

async fn login_account(
    State(state): State<AppState>,
    Json(request): Json<AccountRequest>,
) -> impl IntoResponse {
    touch_activity(&state).await;
    let code = match normalize_code(&request.code) {
        Ok(code) => code,
        Err(error) => return account_error(StatusCode::BAD_REQUEST, &state, error).await,
    };
    info!("account_login_attempt {}", code_log_label(&code));
    if let Err(error) = validate_password(&request.password) {
        warn!(
            "account_login_rejected {} reason=password_shape",
            code_log_label(&code)
        );
        return account_error(StatusCode::BAD_REQUEST, &state, error).await;
    }

    let account = match state.accounts.lock().await.get(&code).cloned() {
        Some(account) => account,
        None => {
            warn!(
                "account_login_rejected {} reason=no_account",
                code_log_label(&code)
            );
            return account_error(
                StatusCode::UNAUTHORIZED,
                &state,
                "No RAM account for this code. Create it first or restart generated a new code set.".to_string(),
            )
            .await;
        }
    };

    if !verify_password(&request.password, &account.password_hash) {
        warn!(
            "account_login_rejected {} reason=bad_password",
            code_log_label(&code)
        );
        return account_error(
            StatusCode::UNAUTHORIZED,
            &state,
            "Invalid password.".to_string(),
        )
        .await;
    }

    replace_connected_clients_for_code(&state, &code).await;

    info!(
        "account_login_accepted {} username={}",
        code_log_label(&code),
        account.username
    );
    issue_session(&state, code, account.username, false).await
}

async fn enter_account(
    State(state): State<AppState>,
    Json(request): Json<AccountRequest>,
) -> impl IntoResponse {
    touch_activity(&state).await;
    let _account_guard = state.account_ops.lock().await;
    let code = match normalize_code(&request.code) {
        Ok(code) => code,
        Err(error) => return account_error(StatusCode::BAD_REQUEST, &state, error).await,
    };
    info!("account_enter_attempt {}", code_log_label(&code));
    if let Err(error) = validate_password(&request.password) {
        warn!(
            "account_enter_rejected {} reason=password_shape",
            code_log_label(&code)
        );
        return account_error(StatusCode::BAD_REQUEST, &state, error).await;
    }

    if let Some(account) = state.accounts.lock().await.get(&code).cloned() {
        if !verify_password(&request.password, &account.password_hash) {
            warn!(
                "account_enter_rejected {} reason=bad_password",
                code_log_label(&code)
            );
            return account_error(
                StatusCode::UNAUTHORIZED,
                &state,
                "Wrong information.".to_string(),
            )
            .await;
        }

        replace_connected_clients_for_code(&state, &code).await;

        info!(
            "account_enter_login {} username={}",
            code_log_label(&code),
            account.username
        );
        return issue_session(&state, code, account.username, false).await;
    }

    if !state.available_codes.lock().await.remove(&code) {
        warn!(
            "account_enter_rejected {} reason=unknown_code",
            code_log_label(&code)
        );
        return account_error(
            StatusCode::UNAUTHORIZED,
            &state,
            "Wrong information.".to_string(),
        )
        .await;
    }

    let password_hash = match hash_password(&request.password) {
        Ok(hash) => hash,
        Err(error) => return account_error(StatusCode::INTERNAL_SERVER_ERROR, &state, error).await,
    };
    let mut accounts = state.accounts.lock().await;
    let username = random_unique_username(&accounts);
    accounts.insert(
        code.clone(),
        Account {
            username: username.clone(),
            password_hash,
            connected: false,
        },
    );
    drop(accounts);
    info!(
        "account_enter_created {} username={}",
        code_log_label(&code),
        username
    );

    issue_session(&state, code, username, true).await
}

async fn replace_connected_clients_for_code(state: &AppState, code: &str) {
    let old_clients = state
        .clients
        .lock()
        .await
        .iter()
        .filter_map(|(client_id, client)| {
            if client.code == code {
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
        let _ = tx.send(Message::Close(None));
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
    for members in state.rooms.lock().await.values_mut() {
        members.retain(|client_id| !old_ids.contains(client_id));
    }
    if let Some(account) = state.accounts.lock().await.get_mut(code) {
        account.connected = false;
    }
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

    replace_connected_clients_for_code(&state, &session.code).await;
    touch_activity(&state).await;
    StatusCode::NO_CONTENT
}

async fn upload_attachment(
    State(state): State<AppState>,
    Query(query): Query<AttachmentQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if let Err(status) = auth_from_headers(&state, &headers).await {
        return status.into_response();
    }
    touch_activity(&state).await;
    let chat_id = query.chat_id.trim();
    if chat_id.is_empty() || body.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let media_type = normalize_media_type(query.media_type.as_deref());
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
    let ttl_ms = query
        .ttl_sec
        .filter(|ttl| *ttl > 0)
        .map(|ttl| now_ms().saturating_add(ttl.saturating_mul(1000)));
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
    if let Err(status) = auth_from_headers(&state, &headers).await {
        return status.into_response();
    }
    touch_activity(&state).await;

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
    let chat_id = record.chat_id.clone();
    let media_type = record.media_type.clone();
    if record.one_time || record.delete_after_download {
        attachments.remove(&id);
    }
    info!(
        "attachment_downloaded id={} chat_id={} media_type={} bytes={}",
        id,
        chat_id,
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
    error: String,
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
            error: Some(error),
        }),
    )
}

async fn issue_session(
    state: &AppState,
    code: String,
    username: String,
    created: bool,
) -> (StatusCode, Json<AccountResponse>) {
    let token = Uuid::new_v4().to_string();
    let now = now_ms();
    let mut sessions = state.sessions.lock().await;
    sessions.retain(|_, session| session.code != code);
    sessions.insert(
        token.clone(),
        AuthSession {
            code,
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
            error: None,
        }),
    )
}

async fn ws_handler(
    State(state): State<AppState>,
    Query(query): Query<WsQuery>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    let auth = active_session(&state, &query.token, true).await;

    match auth {
        Some(session) => ws
            .on_upgrade(move |socket| socket_loop(state, query.token, session, socket))
            .into_response(),
        None => StatusCode::UNAUTHORIZED.into_response(),
    }
}

async fn socket_loop(state: AppState, session_token: String, auth: AuthSession, socket: WebSocket) {
    let client_id = Uuid::new_v4();
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    state.clients.lock().await.insert(
        client_id,
        ClientHandle {
            code: auth.code.clone(),
            username: auth.username.clone(),
            tx,
        },
    );
    if let Some(account) = state.accounts.lock().await.get_mut(&auth.code) {
        account.connected = true;
    }
    info!("{} connected", auth.username);
    broadcast_presence(&state).await;
    send_room_catalog(&state, client_id).await;

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
    });
    if now.saturating_sub(state.window_start_ms) > WS_RATE_WINDOW_MS {
        state.window_start_ms = now;
        state.count = 0;
    }
    state.count = state.count.saturating_add(1);
    if state.count > WS_MAX_FRAMES_PER_WINDOW {
        return Err(format!(
            "rate limit exceeded: count={} window_ms={}",
            state.count, WS_RATE_WINDOW_MS
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
            payload_b64,
        } => {
            touch_activity(state).await;
            let outbound = OutboundFrame::Message {
                chat_id: chat_id.clone(),
                payload_b64,
            };
            broadcast_to_room(state, sender_id, &chat_id, outbound).await
        }
        InboundFrame::ReadReceipt {
            chat_id,
            message_id,
        } => {
            touch_activity(state).await;
            let outbound = OutboundFrame::ReadReceipt {
                chat_id: chat_id.clone(),
                message_id,
            };
            broadcast_to_room(state, sender_id, &chat_id, outbound).await
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
    }
}

async fn join_room(state: &AppState, client_id: Uuid, chat_id: String) -> Result<(), String> {
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
        .remove(&chat_id)
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

async fn broadcast_to_room(
    state: &AppState,
    sender_id: Uuid,
    chat_id: &str,
    frame: OutboundFrame,
) -> Result<(), String> {
    let recipients = state
        .rooms
        .lock()
        .await
        .get(chat_id)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|id| *id != sender_id)
        .collect::<Vec<_>>();

    if recipients.is_empty() {
        let mut pending = state.pending.lock().await;
        let queue = pending.entry(chat_id.to_string()).or_default();
        if queue.len() >= MAX_PENDING_FRAMES_PER_ROOM {
            queue.remove(0);
        }
        queue.push(frame);
        return Ok(());
    }

    for recipient in recipients {
        send_to_client(state, recipient, &frame).await;
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

    state.pending.lock().await.clear();
    state.attachments.lock().await.clear();
    state.room_catalog.lock().await.clear();
    state.rooms.lock().await.clear();
    state.sessions.lock().await.clear();
    state.accounts.lock().await.clear();
    state.available_codes.lock().await.clear();
    state.frame_limits.lock().await.clear();
    state.clients.lock().await.clear();
}

async fn create_room(
    state: &AppState,
    sender_id: Uuid,
    mut room: RoomRecord,
) -> Result<(), String> {
    let (owner_code, owner_username) = client_identity(state, sender_id).await?;
    room.owner_username = owner_username;
    normalize_room_record(&mut room)?;
    let mut catalog = state.room_catalog.lock().await;
    if let Some(existing) = catalog.get(&room.id) {
        if existing.owner_code != owner_code {
            return Err("room id rejected".to_string());
        }
    } else if !has_room_capacity(&catalog, &owner_code, state.max_rooms_per_user) {
        return Err("room limit reached".to_string());
    }
    catalog.insert(
        room.id.clone(),
        RoomEntry {
            room: room.clone(),
            owner_code,
        },
    );
    drop(catalog);
    broadcast_to_all(state, &OutboundFrame::RoomCreated { room }).await;
    Ok(())
}

async fn delete_room(state: &AppState, sender_id: Uuid, chat_id: &str) -> Result<(), String> {
    let (owner_code, _) = client_identity(state, sender_id).await?;
    let chat_id = chat_id.trim();
    if chat_id.is_empty() {
        return Err("room id is required".to_string());
    }
    let mut catalog = state.room_catalog.lock().await;
    let Some(entry) = catalog.get(chat_id) else {
        return Err("room unavailable".to_string());
    };
    if entry.owner_code != owner_code {
        return Err("room owner required".to_string());
    }
    catalog.remove(chat_id);
    drop(catalog);
    state.pending.lock().await.remove(chat_id);
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

async fn client_identity(state: &AppState, client_id: Uuid) -> Result<(String, String), String> {
    state
        .clients
        .lock()
        .await
        .get(&client_id)
        .map(|client| (client.code.clone(), client.username.clone()))
        .ok_or_else(|| "authenticated client required".to_string())
}

fn owned_room_count(catalog: &HashMap<String, RoomEntry>, owner_code: &str) -> usize {
    catalog
        .values()
        .filter(|entry| entry.owner_code == owner_code)
        .count()
}

fn has_room_capacity(
    catalog: &HashMap<String, RoomEntry>,
    owner_code: &str,
    max_rooms_per_user: usize,
) -> bool {
    owned_room_count(catalog, owner_code) < max_rooms_per_user
}

fn normalize_room_record(room: &mut RoomRecord) -> Result<(), String> {
    room.id = room.id.trim().to_string();
    room.name = room.name.trim().chars().take(36).collect::<String>();
    if room.id.is_empty() || !room.id.starts_with("forum_") {
        return Err("room id rejected".to_string());
    }
    if room.name.is_empty() {
        return Err("room name rejected".to_string());
    }
    room.self_destruct_timer_sec = room.self_destruct_timer_sec.clamp(1, 86_400);
    room.overall_expiry_sec = room.overall_expiry_sec.min(86_400);
    room.image_read_timer_sec = room.image_read_timer_sec.clamp(1, 86_400);
    room.image_overall_expiry_sec = room.image_overall_expiry_sec.min(86_400);
    room.video_read_timer_sec = room.video_read_timer_sec.clamp(1, 86_400);
    room.video_overall_expiry_sec = room.video_overall_expiry_sec.min(86_400);
    room.file_read_timer_sec = room.file_read_timer_sec.clamp(1, 86_400);
    room.file_overall_expiry_sec = room.file_overall_expiry_sec.min(86_400);
    Ok(())
}

async fn broadcast_presence(state: &AppState) {
    let users = state
        .accounts
        .lock()
        .await
        .values()
        .map(|account| PresenceUser {
            username: account.username.clone(),
            connected: account.connected,
        })
        .collect::<Vec<_>>();
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

    if let Some(client) = state.clients.lock().await.get(&client_id) {
        let _ = client.tx.send(Message::Text(serialized));
    }
}

async fn cleanup_client(state: &AppState, client_id: Uuid) {
    state.frame_limits.lock().await.remove(&client_id);
    let code = state
        .clients
        .lock()
        .await
        .remove(&client_id)
        .map(|client| client.code);
    for members in state.rooms.lock().await.values_mut() {
        members.remove(&client_id);
    }
    if let Some(code) = code {
        let still_connected = state
            .clients
            .lock()
            .await
            .values()
            .any(|client| client.code == code);
        if !still_connected {
            if let Some(account) = state.accounts.lock().await.get_mut(&code) {
                account.connected = false;
            }
        }
    }
    broadcast_presence(state).await;
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn code_parser_accepts_variable_lengths() {
        assert!(valid_code_shape("ABCD-1234-WXYZ"));
        assert!(valid_code_shape("ABC-12345678"));
        assert!(!valid_code_shape("SHORT-1"));
        assert!(!valid_code_shape("-ABCD12345678"));
        assert!(!valid_code_shape("ABCD12345678-"));
        assert!(!valid_code_shape("ABCD_12345678"));
    }

    #[test]
    fn password_hash_round_trips() {
        let hash = hash_password("strong-password").expect("hash");
        assert!(verify_password("strong-password", &hash));
        assert!(!verify_password("wrong-password", &hash));
    }

    #[test]
    fn session_expiration_uses_strict_boundary() {
        let session = AuthSession {
            code: "ABCD-1234-WXYZ".to_string(),
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
                    owner_code: owner_code.to_string(),
                },
            );
        }

        assert_eq!(owned_room_count(&catalog, "code-a"), 2);
        assert!(!has_room_capacity(&catalog, "code-a", 2));
        assert!(has_room_capacity(&catalog, "code-b", 2));
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
