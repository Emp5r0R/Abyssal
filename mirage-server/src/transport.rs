//! Websocket transport admission and client socket lifecycle.
//!
//! This module owns the framed transport boundary, rate limits, ticket-backed
//! upgrade, and bounded writer/reader lifecycle. Protocol routing remains in
//! the parent module and is invoked only after admission succeeds.

use super::*;
use abyssal_transport::{
    inspect_ws_client_hello, open_ws_client_hello, seal_ws_server_hello, ConnectionNonce,
    WsConnectionBinding, WsSealer, WS_CLIENT_HELLO_BYTES,
};

const WS_PROTOCOL_V11: &str = "abyssal-v11";
const WS_FRAME_AAD: &[u8] = b"ABYSSAL-TRANSPORT-V11-WS-FRAME";
const WS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const WS_HANDSHAKE_WORKER_LIMIT: usize = 64;

pub(super) async fn ws_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    if !websocket_origin_allowed(&headers, &state.web_origins) {
        debug!("websocket_upgrade_rejected reason=origin");
        return StatusCode::FORBIDDEN.into_response();
    }
    if websocket_v11_marker(&headers) {
        return ws
            .max_frame_size(CONTROL_TRANSPORT_MAX_BUCKET)
            .max_message_size(CONTROL_TRANSPORT_MAX_BUCKET)
            .protocols([WS_PROTOCOL_V11])
            .on_failed_upgrade(|_| {
                debug!("websocket_upgrade_failed reason=transport");
            })
            .on_upgrade(move |socket| socket_loop_v11(state, socket))
            .into_response();
    }

    // Never reinterpret a request that mentions v11 as a legacy ticket
    // upgrade. This closes marker-plus-ticket/bearer downgrade combinations.
    if websocket_v11_present(&headers) {
        debug!("websocket_upgrade_rejected reason=v11_metadata");
        return StatusCode::UNAUTHORIZED.into_response();
    }

    // Keep the ticket-bearing v2 path only for clients that have not migrated
    // yet. It is deliberately unreachable when the fixed v11 marker is used.
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
                    legacy_socket_loop(state, token, session, client_platform, client_id, socket)
                })
                .into_response()
        }
        None => {
            debug!("websocket_upgrade_rejected reason=ticket_or_session");
            StatusCode::UNAUTHORIZED.into_response()
        }
    }
}

pub(super) fn websocket_v11_marker(headers: &HeaderMap) -> bool {
    let Some(protocols) = websocket_protocol_header(headers) else {
        return false;
    };
    let mut values = protocols.split(',').map(str::trim);
    values.next() == Some(WS_PROTOCOL_V11) && values.next().is_none()
}

pub(super) fn websocket_v11_present(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|protocols| protocols.split(',').map(str::trim))
        .any(|protocol| protocol == WS_PROTOCOL_V11)
}

fn websocket_protocol_header(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::SEC_WEBSOCKET_PROTOCOL).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()
}

pub(super) fn websocket_ticket_header(headers: &HeaderMap) -> Option<Zeroizing<String>> {
    let protocols = websocket_protocol_header(headers)?;
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
        let value = protocol.strip_prefix("ticket.")?;
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

pub(super) fn websocket_origin_allowed(headers: &HeaderMap, allowed_origins: &[String]) -> bool {
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

struct PendingClientStage {
    initial_frames: Vec<OutboundFrame>,
    live_frames: Vec<OutboundFrame>,
    results: Vec<ClientResult>,
    controls: Vec<ClientControl>,
    queued_bytes: Arc<AtomicUsize>,
    bootstrap_tx: Option<oneshot::Sender<()>>,
    aborted: bool,
}

pub(super) struct ClientStageRegistry {
    stages: Mutex<HashMap<Uuid, PendingClientStage>>,
}

impl ClientStageRegistry {
    pub(super) fn new() -> Self {
        Self {
            stages: Mutex::new(HashMap::new()),
        }
    }
}

pub(super) async fn begin_client_stage(
    registry: &ClientStageRegistry,
    client_id: Uuid,
    queued_bytes: Arc<AtomicUsize>,
) -> oneshot::Receiver<()> {
    let (bootstrap_tx, bootstrap_rx) = oneshot::channel();
    registry.stages.lock().await.insert(
        client_id,
        PendingClientStage {
            initial_frames: Vec::new(),
            live_frames: Vec::new(),
            results: Vec::new(),
            controls: Vec::new(),
            queued_bytes,
            bootstrap_tx: Some(bootstrap_tx),
            aborted: false,
        },
    );
    bootstrap_rx
}

pub(super) enum StageOutcome {
    Pending,
    Ready(OutboundFrame),
    Full(OutboundFrame),
    Aborted(OutboundFrame),
}

pub(super) async fn stage_outbound_frame(
    registry: &ClientStageRegistry,
    client_id: Uuid,
    frame: OutboundFrame,
) -> StageOutcome {
    stage_frame(registry, None, client_id, frame, false).await
}

pub(super) async fn stage_initial_outbound_frame(
    registry: &ClientStageRegistry,
    global_outbound_bytes: &AtomicUsize,
    client_id: Uuid,
    frame: OutboundFrame,
) -> StageOutcome {
    stage_frame(
        registry,
        Some(global_outbound_bytes),
        client_id,
        frame,
        true,
    )
    .await
}

async fn stage_frame(
    registry: &ClientStageRegistry,
    global_outbound_bytes: Option<&AtomicUsize>,
    client_id: Uuid,
    frame: OutboundFrame,
    initial: bool,
) -> StageOutcome {
    let mut stages = registry.stages.lock().await;
    let Some(stage) = stages.get_mut(&client_id) else {
        return StageOutcome::Ready(frame);
    };
    if stage.aborted {
        return StageOutcome::Aborted(frame);
    }
    if stage
        .initial_frames
        .len()
        .saturating_add(stage.live_frames.len())
        >= CLIENT_OUTBOUND_QUEUE_CAPACITY
    {
        return StageOutcome::Full(frame);
    }
    if initial {
        // Presence is computed under presence_broadcast_ops, so any live
        // presence staged before this snapshot is older. Initial frames are
        // flushed before live frames; keeping the older live copy would
        // deliver a newer directory revision followed by an older one.
        if matches!(frame, OutboundFrame::Presence { .. }) {
            if let Some(global) = global_outbound_bytes {
                let queued_bytes = Arc::clone(&stage.queued_bytes);
                stage.live_frames.retain(|staged| {
                    let superseded = matches!(staged, OutboundFrame::Presence { .. });
                    if superseded {
                        release_client_outbound_bytes(global, &queued_bytes, staged);
                    }
                    !superseded
                });
            }
        }
        stage.initial_frames.push(frame);
    } else {
        stage.live_frames.push(frame);
    }
    StageOutcome::Pending
}

pub(super) enum StageControlOutcome {
    Ready,
    Pending,
    Full,
    Aborted,
}

pub(super) async fn stage_control(
    registry: &ClientStageRegistry,
    client_id: Uuid,
    control: ClientControl,
) -> StageControlOutcome {
    let mut stages = registry.stages.lock().await;
    let Some(stage) = stages.get_mut(&client_id) else {
        return StageControlOutcome::Ready;
    };
    if stage.aborted {
        return StageControlOutcome::Aborted;
    }
    if stage.controls.len() >= CLIENT_CONTROL_QUEUE_CAPACITY {
        return StageControlOutcome::Full;
    }
    stage.controls.push(control);
    StageControlOutcome::Pending
}

pub(super) enum StageResultOutcome {
    Pending,
    Ready(ClientResult),
    Full(ClientResult),
    Aborted(ClientResult),
}

pub(super) async fn stage_client_result(
    registry: &ClientStageRegistry,
    client_id: Uuid,
    result: ClientResult,
) -> StageResultOutcome {
    let mut stages = registry.stages.lock().await;
    let Some(stage) = stages.get_mut(&client_id) else {
        return StageResultOutcome::Ready(result);
    };
    if stage.aborted {
        return StageResultOutcome::Aborted(result);
    }
    if stage.results.len() >= CLIENT_RESULT_QUEUE_CAPACITY {
        return StageResultOutcome::Full(result);
    }
    stage.results.push(result);
    StageResultOutcome::Pending
}

/// Commit the snapshot staging gate while holding the stage lock. This makes
/// the order observable by the writer: snapshot frames, then any live frames
/// that raced with snapshot collection, then control signals.
pub(super) async fn abort_client_stage(
    registry: &ClientStageRegistry,
    global_outbound_bytes: &AtomicUsize,
    client_id: Uuid,
) {
    let mut stages = registry.stages.lock().await;
    let Some(stage) = stages.get_mut(&client_id) else {
        return;
    };
    if stage.aborted {
        return;
    }
    stage.aborted = true;
    let queued_bytes = Arc::clone(&stage.queued_bytes);
    for frame in stage
        .initial_frames
        .drain(..)
        .chain(stage.live_frames.drain(..))
    {
        release_client_outbound_bytes(global_outbound_bytes, &queued_bytes, &frame);
    }
    for result in stage.results.drain(..) {
        let _ = result.delivered.send(false);
    }
    stage.controls.clear();
}

pub(super) async fn commit_client_stage(state: &AppState, client_id: Uuid) {
    let client = state.clients.lock().await.get(&client_id).map(|client| {
        (
            client.tx.clone(),
            client.result_tx.clone(),
            client.control_tx.clone(),
        )
    });
    let Some((tx, result_tx, control_tx)) = client else {
        discard_client_stage(state, client_id).await;
        return;
    };
    let mut stages = state.client_stages.stages.lock().await;
    let Some(stage) = stages.remove(&client_id) else {
        return;
    };
    let PendingClientStage {
        initial_frames,
        live_frames,
        results,
        controls,
        queued_bytes,
        bootstrap_tx,
        aborted,
    } = stage;
    if aborted {
        if let Some(bootstrap_tx) = bootstrap_tx {
            let _ = bootstrap_tx.send(());
        }
        return;
    }
    for frame in initial_frames.into_iter().chain(live_frames) {
        if let Err(error) = tx.try_send(frame) {
            // The frame was already included in the weighted queue budget.
            // Restore that budget when the channel cannot accept it.
            let frame = error.into_inner();
            release_client_outbound_bytes(&state.outbound_bytes, &queued_bytes, &frame);
        }
    }
    for result in results {
        if let Err(error) = result_tx.try_send(result) {
            let _ = error.into_inner().delivered.send(false);
        }
    }
    for control in controls {
        let _ = control_tx.try_send(control);
    }
    if let Some(bootstrap_tx) = bootstrap_tx {
        let _ = bootstrap_tx.send(());
    }
}

pub(super) async fn discard_client_stage(state: &AppState, client_id: Uuid) {
    let Some(stage) = state.client_stages.stages.lock().await.remove(&client_id) else {
        return;
    };
    let PendingClientStage {
        initial_frames,
        live_frames,
        results,
        queued_bytes,
        bootstrap_tx,
        ..
    } = stage;
    for frame in initial_frames.into_iter().chain(live_frames) {
        release_client_outbound_bytes(&state.outbound_bytes, &queued_bytes, &frame);
    }
    for result in results {
        let _ = result.delivered.send(false);
    }
    if let Some(bootstrap_tx) = bootstrap_tx {
        let _ = bootstrap_tx.send(());
    }
}

async fn socket_loop_v11(state: AppState, socket: WebSocket) {
    let Some(handshake_permit) = state.ws_handshake_workers.clone().try_acquire_owned().ok() else {
        debug!("websocket_upgrade_rejected reason=handshake_capacity");
        return;
    };
    let (mut sink, mut stream) = socket.split();
    let first = match tokio::time::timeout(WS_HANDSHAKE_TIMEOUT, stream.next()).await {
        Ok(Some(Ok(Message::Binary(bytes)))) => bytes,
        _ => return,
    };
    if first.len() != WS_CLIENT_HELLO_BYTES {
        return;
    }
    let header = match inspect_ws_client_hello(&first) {
        Ok(header) => header,
        Err(_) => return,
    };
    let transport_key = TransportSessionId::new(header.session_id);
    let Some((transport_root, expected_token)) = state
        .transport_sessions
        .lock()
        .await
        .get(&transport_key)
        .map(|transport| (transport.root.clone(), transport.token.0.clone()))
    else {
        return;
    };
    let opened = match open_ws_client_hello(&transport_root, state.node_public_key, &first) {
        Ok(opened) => opened,
        Err(_) => return,
    };
    let Ok(ticket) = std::str::from_utf8(opened.ticket.as_slice()) else {
        return;
    };
    let Some((session_token, auth, client_platform)) =
        consume_ws_ticket_for_session(&state, ticket, expected_token.as_str()).await
    else {
        return;
    };
    let server_nonce = match ConnectionNonce::generate() {
        Ok(nonce) => nonce,
        Err(_) => return,
    };
    let server_hello = match seal_ws_server_hello(
        &transport_root,
        state.node_public_key,
        header.session_id,
        header.client_nonce,
        server_nonce.to_bytes(),
    ) {
        Ok(hello) => hello,
        Err(_) => return,
    };
    if !matches!(
        tokio::time::timeout(
            WS_HANDSHAKE_TIMEOUT,
            sink.send(Message::Binary(server_hello.to_vec())),
        )
        .await,
        Ok(Ok(()))
    ) {
        return;
    }
    let client_nonce = match ConnectionNonce::new(header.client_nonce) {
        Ok(nonce) => nonce,
        Err(_) => return,
    };
    let records = match WsConnectionBinding::new(header.session_id, client_nonce, server_nonce) {
        Ok(binding) => match binding.into_server(&transport_root) {
            Ok(records) => records,
            Err(_) => return,
        },
        Err(_) => return,
    };
    drop(handshake_permit);

    let client_id = Uuid::new_v4();
    let code_id = auth.code_id;
    let mut active_connections = state.active_connections.lock().await;
    if !reserve_connection(&mut active_connections, code_id, client_id) {
        return;
    }
    drop(active_connections);

    let mut purge_rx = state.purge_epoch.subscribe();
    let (tx, rx) = mpsc::channel::<OutboundFrame>(CLIENT_OUTBOUND_QUEUE_CAPACITY);
    let (control_tx, control_rx) = mpsc::channel::<ClientControl>(CLIENT_CONTROL_QUEUE_CAPACITY);
    let (result_tx, result_rx) = mpsc::channel::<ClientResult>(CLIENT_RESULT_QUEUE_CAPACITY);
    let queued_bytes = Arc::new(AtomicUsize::new(0));
    let bootstrap_rx =
        begin_client_stage(&state.client_stages, client_id, Arc::clone(&queued_bytes)).await;
    state.clients.lock().await.insert(
        client_id,
        ClientHandle {
            code_id,
            username: auth.username.clone(),
            platform: client_platform,
            tx,
            control_tx,
            result_tx,
            queued_bytes: Arc::clone(&queued_bytes),
        },
    );
    if let Some(account) = state.accounts.lock().await.get_mut(&code_id) {
        account.connected = true;
    }
    broadcast_presence(&state).await;

    let mut opener = records.opener;
    let mut sealer = records.sealer;
    let global_outbound_bytes = Arc::clone(&state.outbound_bytes);
    let writer = tokio::spawn(async move {
        let mut rx = rx;
        let mut control_rx = control_rx;
        let mut result_rx = result_rx;
        let mut bootstrap_rx = bootstrap_rx;
        let send_frame = |sealer: &mut WsSealer, frame: &OutboundFrame| {
            serialize_outbound_frame(frame).and_then(|serialized| {
                let serialized = Zeroizing::new(serialized);
                sealer
                    .seal(WS_FRAME_AAD, serialized.as_bytes())
                    .ok()
                    .map(Message::Binary)
            })
        };
        let mut bootstrapped = false;
        loop {
            if !bootstrapped {
                tokio::select! {
                    biased;
                    changed = purge_rx.changed() => {
                        if changed.is_err() { break; }
                        if let Some(record) = send_frame(&mut sealer, &OutboundFrame::GlobalWipe) {
                            let _ = tokio::time::timeout(CLIENT_WIPE_SEND_TIMEOUT, sink.send(record)).await;
                        }
                        let _ = tokio::time::timeout(
                            CLIENT_WIPE_SEND_TIMEOUT,
                            sink.send(Message::Close(Some(CloseFrame { code: PURGE_CLOSE_CODE, reason: PURGE_CLOSE_REASON.into() }))),
                        ).await;
                        break;
                    }
                    control = control_rx.recv() => {
                        match control {
                            Some(ClientControl::GlobalWipe) => {
                                if let Some(record) = send_frame(&mut sealer, &OutboundFrame::GlobalWipe) {
                                    let _ = tokio::time::timeout(CLIENT_WIPE_SEND_TIMEOUT, sink.send(record)).await;
                                }
                                let _ = tokio::time::timeout(
                                    CLIENT_WIPE_SEND_TIMEOUT,
                                    sink.send(Message::Close(Some(CloseFrame { code: PURGE_CLOSE_CODE, reason: PURGE_CLOSE_REASON.into() }))),
                                ).await;
                            }
                            Some(ClientControl::Close) | None => {
                                let _ = tokio::time::timeout(CLIENT_WIPE_SEND_TIMEOUT, sink.send(Message::Close(None))).await;
                            }
                        }
                        break;
                    }
                    _ = &mut bootstrap_rx => {
                        bootstrapped = true;
                    }
                }
                if !bootstrapped {
                    continue;
                }
            }
            tokio::select! {
                biased;
                changed = purge_rx.changed() => {
                    if changed.is_err() { break; }
                    if let Some(record) = send_frame(&mut sealer, &OutboundFrame::GlobalWipe) {
                        let _ = tokio::time::timeout(CLIENT_WIPE_SEND_TIMEOUT, sink.send(record)).await;
                    }
                    let _ = tokio::time::timeout(
                        CLIENT_WIPE_SEND_TIMEOUT,
                        sink.send(Message::Close(Some(CloseFrame { code: PURGE_CLOSE_CODE, reason: PURGE_CLOSE_REASON.into() }))),
                    ).await;
                    break;
                }
                control = control_rx.recv() => {
                    match control {
                        Some(ClientControl::GlobalWipe) => {
                            if let Some(record) = send_frame(&mut sealer, &OutboundFrame::GlobalWipe) {
                                let _ = tokio::time::timeout(CLIENT_WIPE_SEND_TIMEOUT, sink.send(record)).await;
                            }
                            let _ = tokio::time::timeout(
                                CLIENT_WIPE_SEND_TIMEOUT,
                                sink.send(Message::Close(Some(CloseFrame { code: PURGE_CLOSE_CODE, reason: PURGE_CLOSE_REASON.into() }))),
                            ).await;
                        }
                        Some(ClientControl::Close) => {
                            let _ = tokio::time::timeout(CLIENT_WIPE_SEND_TIMEOUT, sink.send(Message::Close(None))).await;
                        }
                        None => break,
                    }
                    break;
                }
                result = result_rx.recv() => {
                    let Some(result) = result else { break; };
                    let delivered = send_frame(&mut sealer, &result.frame).map(|record| async {
                        matches!(tokio::time::timeout(CLIENT_RESULT_SEND_TIMEOUT, sink.send(record)).await, Ok(Ok(())))
                    });
                    let delivered = match delivered { Some(future) => future.await, None => false };
                    let _ = result.delivered.send(delivered);
                    if !delivered { break; }
                }
                frame = rx.recv() => {
                    let Some(frame) = frame else { break; };
                    let Some(record) = send_frame(&mut sealer, &frame) else {
                        release_client_outbound_bytes(&global_outbound_bytes, &queued_bytes, &frame);
                        break;
                    };
                    release_client_outbound_bytes(&global_outbound_bytes, &queued_bytes, &frame);
                    let sent = tokio::time::timeout(CLIENT_SINK_SEND_TIMEOUT, sink.send(record)).await;
                    if !matches!(sent, Ok(Ok(()))) { break; }
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

    // Snapshot builders only enqueue into the stage. The writer cannot see
    // them until every snapshot has been collected and the gate is committed.
    send_initial_presence(&state, client_id).await;
    send_initial_mls_catalog(&state, client_id, &code_id).await;
    send_initial_mls_public_catalog(&state, client_id).await;
    send_initial_mls_pending(&state, client_id, &code_id).await;
    send_initial_mls_pending_joins(&state, client_id, &code_id).await;
    send_initial_mls_pending_leaves(&state, client_id, &code_id).await;
    send_initial_direct_catalog(&state, client_id, &auth.username).await;
    commit_client_stage(&state, client_id).await;

    let mut session_watchdog = tokio::time::interval(Duration::from_secs(1));
    session_watchdog.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = session_watchdog.tick() => {
                if active_session(&state, session_token.as_str(), false).await.is_none() { break; }
            }
            result = stream.next() => {
                match result {
                    Some(Ok(Message::Binary(bytes))) => {
                        if bytes.len() > CONTROL_TRANSPORT_MAX_BUCKET || check_ws_frame_allowed(&state, client_id, bytes.len()).await.is_err() { break; }
                        let plaintext = match opener.open(WS_FRAME_AAD, &bytes) { Ok(value) => value, Err(_) => break };
                        let text = match String::from_utf8(plaintext.to_vec()) { Ok(value) => Zeroizing::new(value), Err(_) => break };
                        if validate_inbound_transport_size_before_parse(&text).is_err() { break; }
                        let inner = match strip_inbound_control_transport(&text) { Ok(inner) => Zeroizing::new(inner), Err(_) => break };
                        if handle_frame(&state, client_id, inner.as_str()).await.is_err() { break; }
                    }
                    Some(Ok(Message::Text(_))) => break,
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {}
                    Some(Err(_)) => break,
                }
            }
        }
    }
    cleanup_client(&state, client_id).await;
    let _ = tokio::time::timeout(CLIENT_WIPE_SEND_TIMEOUT, writer).await;
}

pub(super) async fn legacy_socket_loop(
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
    broadcast_presence(&state).await;
    send_mls_catalog(&state, client_id, &auth.code_id).await;
    send_mls_public_catalog(&state, client_id).await;
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
                        if validate_inbound_text_socket_admission(
                            text.as_str(),
                            check_ws_frame_allowed(&state, client_id, text.len()).await,
                        ).is_err() {
                            warn!("closing limited frame connection");
                            break;
                        }
                        let inner = match strip_inbound_control_transport(text.as_str()) {
                            Ok(inner) => inner,
                            Err(_) => {
                                warn!("closing invalid transport frame");
                                break;
                            }
                        };
                        if handle_frame(&state, client_id, inner.as_str()).await.is_err() {
                            warn!("dropping invalid frame");
                        }
                    }
                    Some(Ok(Message::Binary(bytes))) => {
                        if check_ws_frame_allowed(&state, client_id, bytes.len()).await.is_err() {
                            warn!("closing limited binary connection");
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {}
                    Some(Err(_)) => {
                        warn!("websocket transport error");
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

pub(super) async fn check_ws_frame_allowed(
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

pub(super) fn validate_inbound_frame_size_before_parse(text: &str) -> Result<(), String> {
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

pub(super) fn validate_inbound_text_socket_admission(
    text: &str,
    frame_limit: Result<(), String>,
) -> Result<(), String> {
    validate_inbound_transport_size_before_parse(text)?;
    frame_limit
}

pub(super) fn validate_inbound_transport_size_before_parse(text: &str) -> Result<(), String> {
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

pub(super) fn strip_inbound_control_transport(text: &str) -> Result<String, String> {
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

pub(super) enum RecoverableTransaction {
    Execute(TransactionTicket),
    Replay(bool),
    RejectForCapacity,
}

pub(super) async fn begin_recoverable_transaction(
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

pub(super) async fn finish_recoverable_transaction(
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
