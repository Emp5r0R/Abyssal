use std::{
    collections::{HashMap, HashSet},
    env,
    net::SocketAddr,
    sync::Arc,
};

use axum::{
    extract::{
        ws::{Message, WebSocket},
        Query, State, WebSocketUpgrade,
    },
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    node_id: String,
    invite_codes: Arc<HashSet<String>>,
    admin_codes: Arc<HashSet<String>>,
    sessions: Arc<Mutex<HashMap<String, AuthSession>>>,
    clients: Arc<Mutex<HashMap<Uuid, ClientHandle>>>,
    rooms: Arc<Mutex<HashMap<String, HashSet<Uuid>>>>,
    pending: Arc<Mutex<HashMap<String, Vec<OutboundFrame>>>>,
}

#[derive(Clone)]
struct AuthSession {
    admin: bool,
}

#[derive(Clone)]
struct ClientHandle {
    admin: bool,
    tx: mpsc::UnboundedSender<Message>,
}

#[derive(Deserialize)]
struct InviteRequest {
    code: String,
}

#[derive(Serialize)]
struct InviteResponse {
    accepted: bool,
    token: Option<String>,
    node_id: String,
    admin: bool,
    error: Option<String>,
}

#[derive(Serialize)]
struct HealthResponse {
    ok: bool,
    node_id: String,
    storage: &'static str,
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
    #[serde(rename = "GLOBAL_WIPE")]
    GlobalWipe,
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
    let bind_addr: SocketAddr = env::var("MIRAGE_BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()
        .expect("MIRAGE_BIND_ADDR must be a valid socket address");

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/invite/validate", post(validate_invite))
        .route("/v1/ws", get(ws_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .expect("failed to bind MIRAGE_BIND_ADDR");

    info!("mirage server listening on {bind_addr}");
    axum::serve(listener, app).await.expect("server failed");
}

impl AppState {
    fn from_env() -> Self {
        let invite_codes = parse_codes("MIRAGE_INVITE_CODES", "MIRA-4729-ZX00");
        let admin_codes = parse_codes("MIRAGE_ADMIN_CODES", "");
        let node_id = env::var("MIRAGE_NODE_ID")
            .unwrap_or_else(|_| format!("mirage-{}", Uuid::new_v4().simple()));

        Self {
            node_id,
            invite_codes: Arc::new(invite_codes),
            admin_codes: Arc::new(admin_codes),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            clients: Arc::new(Mutex::new(HashMap::new())),
            rooms: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn accepts_invite(&self, code: &str) -> bool {
        self.invite_codes.contains(&normalize_code(code))
            || self.admin_codes.contains(&normalize_code(code))
    }

    fn is_admin_code(&self, code: &str) -> bool {
        self.admin_codes.contains(&normalize_code(code))
    }
}

fn parse_codes(key: &str, fallback: &str) -> HashSet<String> {
    env::var(key)
        .unwrap_or_else(|_| fallback.to_string())
        .split(',')
        .filter_map(|code| {
            let normalized = normalize_code(code);
            if normalized.is_empty() {
                None
            } else {
                Some(normalized)
            }
        })
        .collect()
}

fn normalize_code(code: &str) -> String {
    code.trim().to_ascii_uppercase()
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        node_id: state.node_id.clone(),
        storage: "ram-only",
    })
}

async fn validate_invite(
    State(state): State<AppState>,
    Json(request): Json<InviteRequest>,
) -> impl IntoResponse {
    let code = normalize_code(&request.code);
    if !valid_invite_shape(&code) {
        return (
            StatusCode::BAD_REQUEST,
            Json(InviteResponse {
                accepted: false,
                token: None,
                node_id: state.node_id.clone(),
                admin: false,
                error: Some("Invite code must be XXXX-XXXX-XXXX.".to_string()),
            }),
        );
    }

    if !state.accepts_invite(&code) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(InviteResponse {
                accepted: false,
                token: None,
                node_id: state.node_id.clone(),
                admin: false,
                error: Some("Invite code rejected.".to_string()),
            }),
        );
    }

    let token = Uuid::new_v4().to_string();
    let admin = state.is_admin_code(&code);
    state
        .sessions
        .lock()
        .await
        .insert(token.clone(), AuthSession { admin });

    (
        StatusCode::OK,
        Json(InviteResponse {
            accepted: true,
            token: Some(token),
            node_id: state.node_id.clone(),
            admin,
            error: None,
        }),
    )
}

fn valid_invite_shape(code: &str) -> bool {
    let mut parts = code.split('-');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(a), Some(b), Some(c), None)
            if [a, b, c].iter().all(|part| {
                part.len() == 4 && part.chars().all(|ch| ch.is_ascii_alphanumeric())
            })
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
            admin: auth.admin,
            tx,
        },
    );

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
        return Err("global wipe requires an admin invite".to_string());
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
    state.clients.lock().await.remove(&client_id);
    for members in state.rooms.lock().await.values_mut() {
        members.remove(&client_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_shape_requires_three_groups_of_four() {
        assert!(valid_invite_shape("MIRA-4729-ZX00"));
        assert!(!valid_invite_shape("MIRA-4729-ZX"));
        assert!(!valid_invite_shape("MIRA-4729-ZX00-AAAA"));
        assert!(!valid_invite_shape("MIRA-4729-ZX!!"));
    }

    #[test]
    fn code_parser_normalizes_and_skips_blanks() {
        env::set_var("MIRAGE_TEST_CODES", " mira-4729-zx00, ,admin-1111-root ");
        let codes = parse_codes("MIRAGE_TEST_CODES", "");

        assert!(codes.contains("MIRA-4729-ZX00"));
        assert!(codes.contains("ADMIN-1111-ROOT"));
        assert_eq!(2, codes.len());
        env::remove_var("MIRAGE_TEST_CODES");
    }
}
