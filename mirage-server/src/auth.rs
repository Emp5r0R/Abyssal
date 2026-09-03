//! Authentication sessions, OPAQUE handshakes, and websocket tickets.

use super::*;

pub(super) enum OpaqueHandshake {
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
pub(super) struct AuthSession {
    pub(super) code_id: CodeId,
    pub(super) username: String,
    pub(super) last_activity_ms: u64,
}

pub(super) struct WsTicket {
    pub(super) session_token: Zeroizing<String>,
    pub(super) expires_at_ms: u64,
    pub(super) client_platform: ClientPlatform,
}

impl Drop for WsTicket {
    fn drop(&mut self) {
        self.session_token.zeroize();
    }
}

#[derive(Eq, Hash, PartialEq)]
pub(super) struct SessionToken(pub(super) String);

impl SessionToken {
    pub(super) fn new(value: String) -> Self {
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

// Account and session workflows.
pub(super) fn session_is_expired(
    session: &AuthSession,
    now: u64,
    inactivity_limit_ms: u64,
) -> bool {
    now.saturating_sub(session.last_activity_ms) >= inactivity_limit_ms
}

pub(super) async fn active_session(
    state: &AppState,
    token: &str,
    touch: bool,
) -> Option<AuthSession> {
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

pub(super) async fn code_has_active_session(state: &AppState, code_id: &CodeId) -> bool {
    let now = now_ms();
    let mut sessions = state.sessions.lock().await;
    sessions.retain(|_, session| !session_is_expired(session, now, state.session_inactivity_ms));
    sessions.values().any(|session| session.code_id == *code_id)
}

pub(super) async fn start_opaque_account(
    State(state): State<AppState>,
    Json(request): Json<OpaqueAccountStartRequest>,
) -> impl IntoResponse {
    let _account_guard = state.account_ops.lock().await;
    prune_opaque_handshakes(&state).await;
    let capability = match decode_exact(&request.capability_b64, 32) {
        Ok(value) => Zeroizing::new(value),
        Err(_) => return opaque_start_error(StatusCode::BAD_REQUEST, &state),
    };
    let code_id = derive_code_id(&state.invite_code_pepper[..], capability.as_slice());
    let mut capability_array = [0_u8; 32];
    capability_array.copy_from_slice(&capability);
    let account_context = Zeroizing::new(account_context_v1(
        &state.node_public_key,
        &capability_array,
    ));
    capability_array.zeroize();
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
            account_context.as_slice(),
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
        account_context.as_slice(),
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

pub(super) async fn finish_opaque_account(
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
                || !available_capability_is_live(&state, code_id).await
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
                let mut expiries = state.capability_expiries.lock().await;
                remove_code_id_map_entry(&mut expiries, code_id);
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

pub(super) fn opaque_finish_request_is_registration(request: &OpaqueAccountFinishRequest) -> bool {
    request.registration_upload_b64.is_some()
        && request.credential_finalization_b64.is_none()
        && request.identity_public_b64.is_some()
        && request.identity_prekey_id.is_some()
        && request.identity_envelope_b64.is_some()
        && request.identity_proof_b64.is_some()
}

pub(super) fn opaque_finish_request_is_login(request: &OpaqueAccountFinishRequest) -> bool {
    request.registration_upload_b64.is_none()
        && request.credential_finalization_b64.is_some()
        && request.identity_public_b64.is_none()
        && request.identity_prekey_id.is_none()
        && request.identity_envelope_b64.is_none()
        && request.identity_proof_b64.is_none()
}

pub(super) fn opaque_start_error(
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

pub(super) async fn prune_opaque_handshakes(state: &AppState) {
    let now = now_ms();
    state.opaque_handshakes.lock().await.retain(|_, handshake| {
        let created_at_ms = match handshake {
            OpaqueHandshake::Registration { created_at_ms, .. }
            | OpaqueHandshake::Login { created_at_ms, .. } => *created_at_ms,
        };
        now.saturating_sub(created_at_ms) < OPAQUE_HANDSHAKE_TTL_MS
    });
}

pub(super) async fn store_opaque_handshake(
    state: &AppState,
    id: Uuid,
    handshake: OpaqueHandshake,
) -> bool {
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

pub(super) fn decode_bounded(value: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
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

pub(super) fn decode_bounded_allow_empty(value: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    decode_bounded(value, max_bytes)
}

pub(super) fn valid_mls_correlator(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= rooms::MAX_ROOM_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub(super) fn require_mls_protocol_version(version: u32) -> Result<(), String> {
    (version == rooms::MLS_PROTOCOL_VERSION)
        .then_some(())
        .ok_or_else(|| "Wrong information".to_string())
}

pub(super) fn decode_exact(value: &str, expected_bytes: usize) -> Result<Vec<u8>, String> {
    let bytes = decode_bounded(value, expected_bytes)?;
    (bytes.len() == expected_bytes)
        .then_some(bytes)
        .ok_or_else(|| "Wrong information".to_string())
}

pub(super) fn valid_prekey_id(value: &str) -> bool {
    value.len() <= MAX_PREKEY_ID_BYTES
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

pub(super) fn valid_username(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_USERNAME_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

pub(super) fn valid_node_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NODE_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

pub(super) fn valid_identity_public_bundle(public_key: &[u8], prekey_id: &str) -> bool {
    validate_core_identity_public_bundle(public_key, Some(prekey_id)).is_ok()
        && prekey_ids_from_identity_public_v9(public_key)
            .is_ok_and(|pool| pool.first().is_some_and(|first| first == prekey_id))
}

pub(super) async fn replace_connected_clients_for_code(state: &AppState, code_id: &CodeId) {
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

pub(super) fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|token| !token.is_empty() && token.len() <= 128)
        .map(ToOwned::to_owned)
}

pub(super) async fn auth_from_headers(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthSession, StatusCode> {
    let token = Zeroizing::new(bearer_token(headers).ok_or(StatusCode::UNAUTHORIZED)?);
    active_session(state, token.as_str(), true)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)
}

pub(super) fn ws_ticket_digest(value: &str) -> Option<WsTicketDigest> {
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

pub(super) fn prune_ws_tickets_locked(
    tickets: &mut HashMap<WsTicketDigest, WsTicket>,
    now: u64,
) -> usize {
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

pub(super) fn clear_ws_tickets_locked(tickets: &mut HashMap<WsTicketDigest, WsTicket>) {
    for (mut digest, ticket) in tickets.drain() {
        digest.zeroize();
        drop(ticket);
    }
}

pub(super) async fn clear_ws_tickets_for_session(state: &AppState, session_token: &str) {
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

pub(super) async fn prune_ws_tickets(state: &AppState, now: u64) {
    let mut tickets = state.ws_tickets.lock().await;
    prune_ws_tickets_locked(&mut tickets, now);
}

pub(super) async fn issue_ws_ticket(
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

pub(super) async fn consume_ws_ticket(
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

pub(super) async fn logout_account(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> StatusCode {
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

pub(super) async fn account_error(
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

pub(super) async fn issue_session(
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
