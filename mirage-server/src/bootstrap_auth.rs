//! Direct OPAQUE account operations for the binary bootstrap transport.
//!
//! The relay framing layer owns only wire encoding. This service owns account
//! locks, OPAQUE handshakes, capability consumption, and transport-session
//! lifecycle so the HTTP boundary never round-trips response bodies.

use super::auth::{self, AuthSession, OpaqueHandshake, SessionToken};
use super::*;
use abyssal_transport::AccountBootstrapResult as BootstrapResult;

pub(super) struct SessionTransportState {
    pub(super) token: SessionToken,
    pub(super) root: Zeroizing<[u8; 32]>,
    pub(super) session_id: [u8; 32],
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub(super) struct TransportSessionId([u8; 32]);

impl TransportSessionId {
    pub(super) fn new(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl Drop for TransportSessionId {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SessionTransportState {
    fn drop(&mut self) {
        self.root.zeroize();
        self.session_id.zeroize();
    }
}

pub(super) async fn bootstrap_start(
    state: &AppState,
    capability: Zeroizing<[u8; 32]>,
    registration_request: Zeroizing<Vec<u8>>,
    credential_request: Zeroizing<Vec<u8>>,
) -> BootstrapResult {
    let _account_guard = state.account_ops.lock().await;
    auth::prune_opaque_handshakes(state).await;
    let code_id = derive_code_id(&state.invite_code_pepper[..], capability.as_ref());
    if !known_code_id(state, &code_id).await
        || !login_attempt_allowed(state, &code_id).await
        || auth::code_has_active_session(state, &code_id).await
    {
        return BootstrapResult::Failure;
    }
    let handshake_id = Uuid::new_v4();
    if let Some(account) = state.accounts.lock().await.get(&code_id).cloned() {
        let request = match bounded_raw(&credential_request, ACCOUNT_BODY_LIMIT_BYTES) {
            Ok(value) => value,
            Err(_) => return BootstrapResult::Failure,
        };
        let context = Zeroizing::new(account_context_v1(&state.node_public_key, &capability));
        let (server_state, response) = match opaque_server_start_login(
            &state.opaque_setup,
            &account.password_file,
            request.as_slice(),
            context.as_slice(),
        ) {
            Ok(value) => value,
            Err(_) => return BootstrapResult::Failure,
        };
        if !auth::store_opaque_handshake(
            state,
            handshake_id,
            OpaqueHandshake::Login {
                code_id,
                username: account.username.clone(),
                server_state,
                created_at_ms: now_ms(),
                created: false,
            },
        )
        .await
        {
            return BootstrapResult::Failure;
        }
        touch_activity(state).await;
        return BootstrapResult::LoginStart {
            handshake_id: *handshake_id.as_bytes(),
            credential_response: Zeroizing::new(response),
            identity_public: Zeroizing::new(account.identity_public.clone()),
            identity_prekey_id: Zeroizing::new(account.prekey_id.clone()),
            identity_envelope: Zeroizing::new(account.identity_envelope.clone()),
        };
    }

    let request = match bounded_raw(&registration_request, ACCOUNT_BODY_LIMIT_BYTES) {
        Ok(value) => value,
        Err(_) => return BootstrapResult::Failure,
    };
    let context = Zeroizing::new(account_context_v1(&state.node_public_key, &capability));
    let response = match opaque_server_registration_response(
        &state.opaque_setup,
        request.as_slice(),
        context.as_slice(),
    ) {
        Ok(value) => value,
        Err(_) => return BootstrapResult::Failure,
    };
    let mut challenge = Zeroizing::new(vec![0_u8; REGISTRATION_CHALLENGE_BYTES_V9]);
    OsRng.fill_bytes(&mut challenge);
    if !auth::store_opaque_handshake(
        state,
        handshake_id,
        OpaqueHandshake::Registration {
            code_id,
            challenge: challenge.clone(),
            created_at_ms: now_ms(),
        },
    )
    .await
    {
        return BootstrapResult::Failure;
    }
    state.registration_credential_requests.lock().await.insert(
        handshake_id,
        (credential_request, Zeroizing::new(context.to_vec())),
    );
    touch_activity(state).await;
    BootstrapResult::RegistrationStart {
        handshake_id: *handshake_id.as_bytes(),
        registration_response: Zeroizing::new(response),
        challenge,
    }
}

pub(super) async fn bootstrap_finish_registration(
    state: &AppState,
    handshake_id: Uuid,
    upload: Zeroizing<Vec<u8>>,
    identity_public: Zeroizing<Vec<u8>>,
    prekey_id: Zeroizing<String>,
    identity_envelope: Zeroizing<Vec<u8>>,
    proof: Zeroizing<Vec<u8>>,
) -> BootstrapResult {
    let _account_guard = state.account_ops.lock().await;
    auth::prune_opaque_handshakes(state).await;
    let Some(handshake) = state.opaque_handshakes.lock().await.remove(&handshake_id) else {
        return BootstrapResult::Failure;
    };
    let (code_id, challenge) = match &handshake {
        OpaqueHandshake::Registration {
            code_id, challenge, ..
        } => (*code_id, challenge.clone()),
        OpaqueHandshake::Login { .. } => return BootstrapResult::Failure,
    };
    let Some((credential_request, context)) = state
        .registration_credential_requests
        .lock()
        .await
        .remove(&handshake_id)
    else {
        return BootstrapResult::Failure;
    };
    if state.accounts.lock().await.contains_key(&code_id)
        || !available_capability_is_live(state, &code_id).await
        || !valid_identity_public_bundle(&identity_public, prekey_id.as_str())
    {
        return BootstrapResult::Failure;
    }
    if verify_registration_identity_proof_v9(
        &state.node_id,
        &handshake_id.to_string(),
        challenge.as_slice(),
        upload.as_slice(),
        identity_public.as_slice(),
        prekey_id.as_str(),
        identity_envelope.as_slice(),
        proof.as_slice(),
    )
    .is_err()
    {
        return BootstrapResult::Failure;
    }
    let password_file = match opaque_server_finish_registration(upload.as_slice()) {
        Ok(value) => value,
        Err(_) => return BootstrapResult::Failure,
    };
    let credential_request = match bounded_raw(&credential_request, ACCOUNT_BODY_LIMIT_BYTES) {
        Ok(value) => value,
        Err(_) => return BootstrapResult::Failure,
    };
    let (server_state, response) = match opaque_server_start_login(
        &state.opaque_setup,
        &password_file,
        credential_request.as_slice(),
        context.as_slice(),
    ) {
        Ok(value) => value,
        Err(_) => return BootstrapResult::Failure,
    };
    let username = {
        let _conversation_guard = state.conversation_ops.lock().await;
        let Some(username) = random_unique_username(&*state.accounts.lock().await) else {
            return BootstrapResult::Failure;
        };
        if let Some(mut removed) = state.available_codes.lock().await.take(&code_id) {
            removed.zeroize();
        }
        let mut expiries = state.capability_expiries.lock().await;
        remove_code_id_map_entry(&mut expiries, &code_id);
        drop(expiries);
        state.accounts.lock().await.insert(
            code_id,
            Account {
                username: username.clone(),
                password_file,
                identity_public: identity_public.to_vec(),
                identity_envelope: identity_envelope.to_vec(),
                prekey_id: prekey_id.to_string(),
                state_revision: 0,
                state_revision_window: 1,
                connected: false,
                client_platform: None,
                attachment_uploads: Arc::new(Semaphore::new(MAX_ATTACHMENT_UPLOADS_PER_ACCOUNT)),
            },
        );
        username
    };
    clear_login_limit(state, &code_id).await;
    let continuation_id = Uuid::new_v4();
    if !auth::store_opaque_handshake(
        state,
        continuation_id,
        OpaqueHandshake::Login {
            code_id,
            username,
            server_state,
            created_at_ms: now_ms(),
            created: true,
        },
    )
    .await
    {
        return BootstrapResult::Failure;
    }
    touch_activity(state).await;
    BootstrapResult::RegistrationContinuation {
        handshake_id: *continuation_id.as_bytes(),
        credential_response: Zeroizing::new(response),
    }
}

pub(super) async fn bootstrap_finish_login(
    state: &AppState,
    handshake_id: Uuid,
    finalization: Zeroizing<Vec<u8>>,
) -> BootstrapResult {
    let _account_guard = state.account_ops.lock().await;
    auth::prune_opaque_handshakes(state).await;
    let Some(handshake) = state.opaque_handshakes.lock().await.remove(&handshake_id) else {
        return BootstrapResult::Failure;
    };
    let (code_id, username, server_state, created) = match &handshake {
        OpaqueHandshake::Login {
            code_id,
            username,
            server_state,
            created,
            ..
        } => (*code_id, username.clone(), server_state.clone(), *created),
        OpaqueHandshake::Registration { .. } => return BootstrapResult::Failure,
    };
    let finalization = match bounded_raw(&finalization, ACCOUNT_BODY_LIMIT_BYTES) {
        Ok(value) => value,
        Err(_) => return BootstrapResult::Failure,
    };
    let transport_root = match opaque_server_finish_login(&server_state, finalization.as_slice()) {
        Ok(value) => Zeroizing::new(value),
        Err(_) => return BootstrapResult::Failure,
    };
    if auth::code_has_active_session(state, &code_id).await {
        return BootstrapResult::Failure;
    }
    clear_login_limit(state, &code_id).await;
    let Some(session) =
        issue_transport_session(state, code_id, username, transport_root, created).await
    else {
        return BootstrapResult::Failure;
    };
    touch_activity(state).await;
    session
}

async fn issue_transport_session(
    state: &AppState,
    code_id: CodeId,
    username: String,
    transport_root: Zeroizing<[u8; 32]>,
    created: bool,
) -> Option<BootstrapResult> {
    let max_rooms_per_user = u32::try_from(state.max_rooms_per_user).ok()?;
    let session_inactivity_sec = u32::try_from(state.session_inactivity_ms / 1000).ok()?;
    if !(1..=100).contains(&max_rooms_per_user)
        || !(60..=24 * 60 * 60).contains(&session_inactivity_sec)
    {
        return None;
    }
    let identity = {
        let mut accounts = state.accounts.lock().await;
        let account = accounts.get_mut(&code_id)?;
        account.client_platform = None;
        (
            account.identity_public.clone(),
            account.prekey_id.clone(),
            account.identity_envelope.clone(),
        )
    };
    let random_session_id = random_nonzero_session_id();
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
    let mut transport_sessions = state.transport_sessions.lock().await;
    transport_sessions.retain(|_, transport| !replaced_tokens.contains(&transport.token.0));
    transport_sessions.insert(
        TransportSessionId::new(random_session_id),
        SessionTransportState {
            token: SessionToken::new(token),
            root: transport_root,
            session_id: random_session_id,
        },
    );
    drop(transport_sessions);
    for mut replaced_token in replaced_tokens {
        clear_ws_tickets_for_session(state, &replaced_token).await;
        replaced_token.zeroize();
    }
    Some(BootstrapResult::Session {
        session_id: Zeroizing::new(random_session_id),
        created,
        max_rooms_per_user,
        session_inactivity_sec,
        username: Zeroizing::new(username),
        identity_public: Zeroizing::new(identity.0),
        identity_prekey_id: Zeroizing::new(identity.1),
        identity_envelope: Zeroizing::new(identity.2),
    })
}

fn random_nonzero_session_id() -> [u8; 32] {
    let mut session_id = [0_u8; 32];
    while session_id == [0_u8; 32] {
        OsRng.fill_bytes(&mut session_id);
    }
    session_id
}

fn bounded_raw(value: &[u8], max_bytes: usize) -> Result<Zeroizing<Vec<u8>>, ()> {
    if value.is_empty() || value.len() > max_bytes {
        return Err(());
    }
    Ok(Zeroizing::new(value.to_vec()))
}
