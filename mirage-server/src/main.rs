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

#[derive(Clone)]
struct AppState {
    node_id: String,
    account_ops: Arc<Mutex<()>>,
    available_codes: Arc<Mutex<HashMap<String, CodeGrant>>>,
    accounts: Arc<Mutex<HashMap<String, Account>>>,
    sessions: Arc<Mutex<HashMap<String, AuthSession>>>,
    clients: Arc<Mutex<HashMap<Uuid, ClientHandle>>>,
    rooms: Arc<Mutex<HashMap<String, HashSet<Uuid>>>>,
    pending: Arc<Mutex<HashMap<String, Vec<OutboundFrame>>>>,
    attachments: Arc<Mutex<HashMap<Uuid, AttachmentRecord>>>,
}

#[derive(Clone)]
struct CodeGrant {
    admin: bool,
}

#[derive(Clone)]
struct Account {
    username: String,
    password_hash: String,
    admin: bool,
    connected: bool,
}

#[derive(Clone)]
struct AuthSession {
    code: String,
    username: String,
    admin: bool,
}

#[derive(Clone)]
struct ClientHandle {
    code: String,
    admin: bool,
    tx: mpsc::UnboundedSender<Message>,
}

struct AttachmentRecord {
    encrypted_bytes: Vec<u8>,
    one_time: bool,
    delete_after_download: bool,
    expires_at_ms: Option<u64>,
}

#[derive(Deserialize)]
struct AccountRequest {
    code: String,
    password: String,
}

#[derive(Deserialize)]
struct AttachmentQuery {
    chat_id: String,
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
    admin: bool,
    error: Option<String>,
}

#[derive(Serialize)]
struct HealthResponse {
    ok: bool,
    node_id: String,
    storage: &'static str,
    available_codes: usize,
    accounts: usize,
}

#[derive(Deserialize)]
struct WsQuery {
    token: String,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum InboundFrame {
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

    let bind_addr: SocketAddr = env::var("ABYSSAL_BIND_ADDR")
        .or_else(|_| env::var("MIRAGE_BIND_ADDR"))
        .unwrap_or_else(|_| "0.0.0.0:4020".to_string())
        .parse()
        .expect("ABYSSAL_BIND_ADDR must be a valid socket address");

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/account/create", post(create_account))
        .route("/v1/account/login", post(login_account))
        .route("/v1/account/enter", post(enter_account))
        .route("/v1/attachment", post(upload_attachment))
        .route("/v1/attachment/:id", get(download_attachment))
        .route("/v1/invite/validate", post(login_account))
        .layer(DefaultBodyLimit::max(200 * 1024 * 1024))
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
        let admin_count = read_usize_env("ABYSSAL_ADMIN_CODE_COUNT", 1);
        let min_len = read_usize_env("ABYSSAL_CODE_MIN_LEN", 12).max(12);
        let requested_max_len =
            read_usize_env("ABYSSAL_CODE_MAX_LEN", min_len + user_count + admin_count);
        let max_len = requested_max_len.max(min_len + user_count + admin_count);
        let mut available_codes = HashMap::new();
        let mut generated_lengths = HashSet::new();

        for code in parse_codes_from_env("ABYSSAL_INVITE_CODES")
            .into_iter()
            .chain(parse_codes_from_env("MIRAGE_INVITE_CODES"))
        {
            available_codes.insert(code, CodeGrant { admin: false });
        }

        for code in parse_codes_from_env("ABYSSAL_ADMIN_CODES")
            .into_iter()
            .chain(parse_codes_from_env("MIRAGE_ADMIN_CODES"))
        {
            available_codes.insert(code, CodeGrant { admin: true });
        }

        generate_codes(
            &mut available_codes,
            &mut generated_lengths,
            user_count,
            false,
            min_len,
            max_len,
        );
        generate_codes(
            &mut available_codes,
            &mut generated_lengths,
            admin_count,
            true,
            min_len,
            max_len,
        );

        Self {
            node_id,
            account_ops: Arc::new(Mutex::new(())),
            available_codes: Arc::new(Mutex::new(available_codes)),
            accounts: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            clients: Arc::new(Mutex::new(HashMap::new())),
            rooms: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
            attachments: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn print_boot_codes(&self) {
        let codes = self.available_codes.lock().await;
        info!("ABYSSAL RAM-ONLY ACCESS CODES - copy these now; they are not written to disk");
        for (code, grant) in codes.iter() {
            let role = if grant.admin { "admin" } else { "user" };
            info!("ABYSSAL_CODE role={role} code={code}");
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
    codes: &mut HashMap<String, CodeGrant>,
    generated_lengths: &mut HashSet<usize>,
    count: usize,
    admin: bool,
    min_len: usize,
    max_len: usize,
) {
    let mut rng = OsRng;
    for _ in 0..count {
        loop {
            let len = next_unique_length(&mut rng, generated_lengths, min_len, max_len);
            let code = generate_code(&mut rng, len);
            if !codes.contains_key(&code) {
                codes.insert(code, CodeGrant { admin });
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

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        node_id: state.node_id.clone(),
        storage: "ram-only",
        available_codes: state.available_codes.lock().await.len(),
        accounts: state.accounts.lock().await.len(),
    })
}

async fn create_account(
    State(state): State<AppState>,
    Json(request): Json<AccountRequest>,
) -> impl IntoResponse {
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

    let grant = match state.available_codes.lock().await.remove(&code) {
        Some(grant) => grant,
        None => {
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
    };

    let password_hash = match hash_password(&request.password) {
        Ok(hash) => hash,
        Err(error) => return account_error(StatusCode::INTERNAL_SERVER_ERROR, &state, error).await,
    };
    let username = random_username();
    state.accounts.lock().await.insert(
        code.clone(),
        Account {
            username: username.clone(),
            password_hash,
            admin: grant.admin,
            connected: false,
        },
    );
    info!(
        "account_create_accepted {} username={} admin={}",
        code_log_label(&code),
        username,
        grant.admin
    );

    issue_session(&state, code, username, grant.admin, true).await
}

async fn login_account(
    State(state): State<AppState>,
    Json(request): Json<AccountRequest>,
) -> impl IntoResponse {
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
        "account_login_accepted {} username={} admin={}",
        code_log_label(&code),
        account.username,
        account.admin
    );
    issue_session(&state, code, account.username, account.admin, false).await
}

async fn enter_account(
    State(state): State<AppState>,
    Json(request): Json<AccountRequest>,
) -> impl IntoResponse {
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
            "account_enter_login {} username={} admin={}",
            code_log_label(&code),
            account.username,
            account.admin
        );
        return issue_session(&state, code, account.username, account.admin, false).await;
    }

    let grant = match state.available_codes.lock().await.remove(&code) {
        Some(grant) => grant,
        None => {
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
    };

    let password_hash = match hash_password(&request.password) {
        Ok(hash) => hash,
        Err(error) => return account_error(StatusCode::INTERNAL_SERVER_ERROR, &state, error).await,
    };
    let username = random_username();
    state.accounts.lock().await.insert(
        code.clone(),
        Account {
            username: username.clone(),
            password_hash,
            admin: grant.admin,
            connected: false,
        },
    );
    info!(
        "account_enter_created {} username={} admin={}",
        code_log_label(&code),
        username,
        grant.admin
    );

    issue_session(&state, code, username, grant.admin, true).await
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
    state
        .sessions
        .lock()
        .await
        .get(&token)
        .cloned()
        .ok_or(StatusCode::UNAUTHORIZED)
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
    if query.chat_id.trim().is_empty() || body.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let id = Uuid::new_v4();
    let ttl_ms = query
        .ttl_sec
        .filter(|ttl| *ttl > 0)
        .map(|ttl| now_ms().saturating_add(ttl.saturating_mul(1000)));
    let one_time = query.one_time.unwrap_or(false);
    state.attachments.lock().await.insert(
        id,
        AttachmentRecord {
            encrypted_bytes: body.to_vec(),
            one_time,
            delete_after_download: query.delete_after_download.unwrap_or(one_time),
            expires_at_ms: ttl_ms,
        },
    );

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
    if record.one_time || record.delete_after_download {
        attachments.remove(&id);
    }

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
            admin: false,
            error: Some(error),
        }),
    )
}

async fn issue_session(
    state: &AppState,
    code: String,
    username: String,
    admin: bool,
    created: bool,
) -> (StatusCode, Json<AccountResponse>) {
    let token = Uuid::new_v4().to_string();
    state.sessions.lock().await.insert(
        token.clone(),
        AuthSession {
            code,
            username: username.clone(),
            admin,
        },
    );

    (
        StatusCode::OK,
        Json(AccountResponse {
            accepted: true,
            created,
            token: Some(token),
            node_id: state.node_id.clone(),
            username: Some(username),
            admin,
            error: None,
        }),
    )
}

async fn ws_handler(
    State(state): State<AppState>,
    Query(query): Query<WsQuery>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    let auth = {
        let sessions = state.sessions.lock().await;
        sessions.get(&query.token).cloned()
    };

    match auth {
        Some(session) => ws
            .on_upgrade(move |socket| socket_loop(state, session, socket))
            .into_response(),
        None => StatusCode::UNAUTHORIZED.into_response(),
    }
}

async fn socket_loop(state: AppState, auth: AuthSession, socket: WebSocket) {
    let client_id = Uuid::new_v4();
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    state.clients.lock().await.insert(
        client_id,
        ClientHandle {
            code: auth.code.clone(),
            admin: auth.admin,
            tx,
        },
    );
    if let Some(account) = state.accounts.lock().await.get_mut(&auth.code) {
        account.connected = true;
    }
    info!("{} connected", auth.username);
    broadcast_presence(&state).await;

    let writer = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            if sink.send(message).await.is_err() {
                break;
            }
        }
    });

    while let Some(result) = stream.next().await {
        match result {
            Ok(Message::Text(text)) => {
                if let Err(err) = handle_frame(&state, client_id, &text).await {
                    warn!("dropping invalid frame from {client_id}: {err}");
                }
            }
            Ok(Message::Close(_)) => break,
            Ok(_) => {}
            Err(err) => {
                warn!("websocket error from {client_id}: {err}");
                break;
            }
        }
    }

    cleanup_client(&state, client_id).await;
    writer.abort();
}

async fn handle_frame(state: &AppState, sender_id: Uuid, text: &str) -> Result<(), String> {
    let frame: InboundFrame = serde_json::from_str(text).map_err(|err| err.to_string())?;
    match frame {
        InboundFrame::Join { chat_id } => join_room(state, sender_id, chat_id).await,
        InboundFrame::Leave { chat_id } => leave_room(state, sender_id, &chat_id).await,
        InboundFrame::Message {
            chat_id,
            payload_b64,
        } => {
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
            let outbound = OutboundFrame::ReadReceipt {
                chat_id: chat_id.clone(),
                message_id,
            };
            broadcast_to_room(state, sender_id, &chat_id, outbound).await
        }
        InboundFrame::GlobalWipe => broadcast_wipe(state, sender_id).await,
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
        state
            .pending
            .lock()
            .await
            .entry(chat_id.to_string())
            .or_default()
            .push(frame);
        return Ok(());
    }

    for recipient in recipients {
        send_to_client(state, recipient, &frame).await;
    }
    Ok(())
}

async fn broadcast_wipe(state: &AppState, sender_id: Uuid) -> Result<(), String> {
    let sender_admin = state
        .clients
        .lock()
        .await
        .get(&sender_id)
        .map(|client| client.admin)
        .unwrap_or(false);

    if !sender_admin {
        return Err("global wipe requires an admin account".to_string());
    }

    state.pending.lock().await.clear();
    let clients = state
        .clients
        .lock()
        .await
        .keys()
        .copied()
        .collect::<Vec<_>>();
    for client_id in clients {
        send_to_client(state, client_id, &OutboundFrame::GlobalWipe).await;
    }
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
        let mut codes = HashMap::new();
        let mut lengths = HashSet::new();
        generate_codes(&mut codes, &mut lengths, 8, false, 12, 20);
        generate_codes(&mut codes, &mut lengths, 3, true, 12, 20);

        let unique_lengths = codes.keys().map(|code| code.len()).collect::<HashSet<_>>();
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
}
