//! Websocket transport admission and client socket lifecycle.
//!
//! This module owns the framed transport boundary, rate limits, ticket-backed
//! upgrade, and bounded writer/reader lifecycle. Protocol routing remains in
//! the parent module and is invoked only after admission succeeds.

use super::*;

pub(super) async fn ws_handler(
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

pub(super) fn websocket_ticket_header(headers: &HeaderMap) -> Option<Zeroizing<String>> {
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

pub(super) async fn socket_loop(
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
