//! Authenticated fixed-size HTTP control transport.
//!
//! The request header is the only routing material visible outside the
//! record.  Receipt lookup intentionally precedes session lookup so a retry
//! can be served from the encrypted cache after logout removes the session.

use super::*;
pub(super) use abyssal_transport::CONTROL_RECORD_BYTES;
use abyssal_transport::{
    decode_control_action, encode_control_result, inspect_http_record, ControlAction,
    ControlResult, Direction, HttpSealer, HttpSessionBinding, CONTROL_AAD,
};
use axum::extract::rejection::BytesRejection;

pub(super) const CONTROL_WORKER_LIMIT: usize = 16;
const CONTROL_RECEIPT_TTL_MS: u64 = 10 * 60 * 1000;
const CONTROL_WORKER_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const MAX_CONTROL_RECEIPTS: usize = 4_096;
const MAX_CONTROL_RECEIPT_BYTES: usize = 32 * 1024 * 1024;
const MAX_CONTROL_SPENT_HANDLES: usize = 16_384;
const CONTROL_SPENT_HANDLE_BYTES: usize = 32 + 16;
const MAX_CONTROL_SPENT_HANDLE_BYTES: usize =
    MAX_CONTROL_SPENT_HANDLES * CONTROL_SPENT_HANDLE_BYTES;

#[derive(Clone, Eq, Hash, PartialEq)]
struct ControlReceiptKey {
    session_id: [u8; 32],
    handle: [u8; 16],
}

impl Drop for ControlReceiptKey {
    fn drop(&mut self) {
        self.session_id.zeroize();
        self.handle.zeroize();
    }
}

enum ControlReceiptState {
    InFlight(watch::Sender<Option<Arc<Zeroizing<Vec<u8>>>>>),
    Complete(Arc<Zeroizing<Vec<u8>>>),
}

struct ControlReceipt {
    request_digest: [u8; 32],
    generation: u64,
    created_at_ms: u64,
    state: ControlReceiptState,
}

impl Drop for ControlReceipt {
    fn drop(&mut self) {
        self.request_digest.zeroize();
    }
}

pub(super) struct ControlReceiptStore {
    entries: HashMap<ControlReceiptKey, ControlReceipt>,
    used_bytes: usize,
    generation: u64,
    // Receipt responses are intentionally short-lived, but a client handle is
    // spent for the lifetime of its transport session. Keeping this marker
    // separate prevents cache expiry from making a nonce usable again.
    spent_handles: HashSet<ControlReceiptKey>,
    spent_handle_bytes: usize,
}

enum ControlReceiptLookup {
    Missing,
    Mismatch,
    Stale,
    Spent,
    InFlight(watch::Receiver<Option<Arc<Zeroizing<Vec<u8>>>>>),
    Complete(Arc<Zeroizing<Vec<u8>>>),
}

enum ControlReceiptReservation {
    Owner(u64),
    Existing,
    Mismatch,
    Stale,
    Spent,
    Capacity,
}

struct AuthenticatedControlRequest {
    session_id: [u8; 32],
    handle: [u8; 16],
    token: Zeroizing<String>,
    action: Option<ControlAction>,
    response_sealer: Option<HttpSealer>,
    timeout_sealer: Option<HttpSealer>,
}

impl Drop for AuthenticatedControlRequest {
    fn drop(&mut self) {
        self.session_id.zeroize();
        self.handle.zeroize();
        self.token.zeroize();
    }
}

impl ControlReceiptStore {
    pub(super) fn new() -> Self {
        Self {
            entries: HashMap::new(),
            used_bytes: 0,
            generation: 0,
            spent_handles: HashSet::new(),
            spent_handle_bytes: 0,
        }
    }

    pub(super) fn prune(&mut self, now_ms: u64) {
        // Session invalidation is asynchronous and owned by auth/main.rs. Do
        // not evict spent handles here: a concurrent authenticated request
        // could otherwise recreate a nonce. Global wipe calls clear(), which
        // is the only safe lifetime boundary available to this store.
        let expired = self
            .entries
            .iter()
            .filter(|(_, receipt)| {
                now_ms.saturating_sub(receipt.created_at_ms) >= CONTROL_RECEIPT_TTL_MS
            })
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in expired {
            if self.entries.remove(&key).is_some() {
                self.used_bytes = self.used_bytes.saturating_sub(CONTROL_RECORD_BYTES);
            }
        }
    }

    fn generation(&self) -> u64 {
        self.generation
    }

    fn lookup(
        &mut self,
        key: &ControlReceiptKey,
        request_digest: [u8; 32],
        expected_generation: u64,
        now_ms: u64,
    ) -> ControlReceiptLookup {
        if self.generation != expected_generation {
            return ControlReceiptLookup::Stale;
        }
        self.prune(now_ms);
        let Some(receipt) = self.entries.get(key) else {
            return if self.spent_handles.contains(key) {
                ControlReceiptLookup::Spent
            } else {
                ControlReceiptLookup::Missing
            };
        };
        if receipt.request_digest != request_digest {
            return ControlReceiptLookup::Mismatch;
        }
        match &receipt.state {
            ControlReceiptState::InFlight(sender) => {
                ControlReceiptLookup::InFlight(sender.subscribe())
            }
            ControlReceiptState::Complete(response) => {
                ControlReceiptLookup::Complete(response.clone())
            }
        }
    }

    fn reserve(
        &mut self,
        key: ControlReceiptKey,
        request_digest: [u8; 32],
        expected_generation: u64,
        now_ms: u64,
    ) -> ControlReceiptReservation {
        if self.generation != expected_generation {
            return ControlReceiptReservation::Stale;
        }
        self.prune(now_ms);
        if let Some(receipt) = self.entries.get(&key) {
            return if receipt.request_digest == request_digest {
                ControlReceiptReservation::Existing
            } else {
                ControlReceiptReservation::Mismatch
            };
        }
        if self.spent_handles.contains(&key) {
            return ControlReceiptReservation::Spent;
        }
        let Some(next_used_bytes) = self.used_bytes.checked_add(CONTROL_RECORD_BYTES) else {
            return ControlReceiptReservation::Capacity;
        };
        if self.entries.len() >= MAX_CONTROL_RECEIPTS
            || next_used_bytes > MAX_CONTROL_RECEIPT_BYTES
            || self.spent_handles.len() >= MAX_CONTROL_SPENT_HANDLES
            || self
                .spent_handle_bytes
                .checked_add(CONTROL_SPENT_HANDLE_BYTES)
                .is_none_or(|bytes| bytes > MAX_CONTROL_SPENT_HANDLE_BYTES)
        {
            return ControlReceiptReservation::Capacity;
        }
        let (sender, _) = watch::channel(None);
        let marker_key = key.clone();
        self.spent_handles.insert(marker_key);
        self.spent_handle_bytes += CONTROL_SPENT_HANDLE_BYTES;
        let generation = self.generation;
        self.entries.insert(
            key,
            ControlReceipt {
                request_digest,
                generation,
                created_at_ms: now_ms,
                state: ControlReceiptState::InFlight(sender),
            },
        );
        self.used_bytes = next_used_bytes;
        ControlReceiptReservation::Owner(generation)
    }

    fn complete(
        &mut self,
        key: &ControlReceiptKey,
        request_digest: [u8; 32],
        generation: u64,
        response: Vec<u8>,
        now_ms: u64,
    ) {
        self.prune(now_ms);
        let Some(receipt) = self.entries.get_mut(key) else {
            return;
        };
        if receipt.request_digest != request_digest
            || receipt.generation != generation
            || response.len() != CONTROL_RECORD_BYTES
        {
            return;
        }
        let response = Arc::new(Zeroizing::new(response));
        if let ControlReceiptState::InFlight(sender) = &receipt.state {
            let _ = sender.send(Some(response.clone()));
        }
        receipt.state = ControlReceiptState::Complete(response);
        receipt.created_at_ms = now_ms;
    }

    pub(super) fn clear(&mut self) {
        self.entries.clear();
        self.used_bytes = 0;
        self.generation = self.generation.wrapping_add(1);
        self.spent_handles.clear();
        self.spent_handle_bytes = 0;
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(super) fn spent_len(&self) -> usize {
        self.spent_handles.len()
    }
}

pub(super) async fn handle_control(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        handle_control_inner(state, headers, body),
    )
    .await
    .unwrap_or_else(|_| Ok::<Vec<u8>, ()>(random_control_response()));
    fixed_control_response(response.unwrap_or_else(|_| random_control_response()))
}

pub(super) async fn handle_control_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    match body {
        Ok(body) => handle_control(State(state), headers, body).await,
        Err(_) => fixed_control_response(random_control_response()),
    }
}

fn fixed_control_response(body: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::CACHE_CONTROL, "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        body,
    )
        .into_response()
}

async fn handle_control_inner(
    state: AppState,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Vec<u8>, ()> {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/octet-stream")
        || body.len() != CONTROL_RECORD_BYTES
    {
        return Err(());
    }
    let header = inspect_http_record(&body).map_err(|_| ())?;
    if header.direction != Direction::ClientToServer {
        return Err(());
    }
    let request_digest: [u8; 32] = Sha256::digest(body.as_ref()).into();
    let key = ControlReceiptKey {
        session_id: header.session_id,
        handle: header.handle,
    };
    let receipt_generation = {
        let receipts = state.control_receipts.lock().await;
        receipts.generation()
    };

    // A cached response is authoritative for exact retries, including after
    // logout removed the transport session and its root.
    if let Some(response) =
        cached_control_response(&state, &key, request_digest, receipt_generation).await?
    {
        return Ok(response);
    }
    let worker_permit = state
        .control_workers
        .clone()
        .try_acquire_owned()
        .map_err(|_| ())?;
    let authenticated = match authenticate_control_request(&state, &body, header).await {
        Ok(request) => request,
        Err(_) => {
            drop(worker_permit);
            return Err(());
        }
    };
    let reservation = {
        let mut receipts = state.control_receipts.lock().await;
        receipts.reserve(key.clone(), request_digest, receipt_generation, now_ms())
    };
    match reservation {
        ControlReceiptReservation::Owner(generation) => {
            let worker_state = state.clone();
            let worker_key = key.clone();
            tokio::spawn(async move {
                let _worker_permit = worker_permit;
                // The request future is detached from the HTTP task. Bound
                // its execution so a cancellation or stalled admission gets
                // one terminal cached response and can never seal later.
                let response = run_control_worker(&worker_state, authenticated).await;
                worker_state.control_receipts.lock().await.complete(
                    &worker_key,
                    request_digest,
                    generation,
                    response,
                    now_ms(),
                );
            });
        }
        ControlReceiptReservation::Existing => {
            drop(authenticated);
            drop(worker_permit);
        }
        ControlReceiptReservation::Mismatch
        | ControlReceiptReservation::Stale
        | ControlReceiptReservation::Spent
        | ControlReceiptReservation::Capacity => {
            drop(authenticated);
            drop(worker_permit);
            return Err(());
        }
    }
    cached_control_response(&state, &key, request_digest, receipt_generation)
        .await?
        .ok_or(())
}

async fn authenticate_control_request(
    state: &AppState,
    body: &[u8],
    header: abyssal_transport::HttpRecordHeader,
) -> Result<AuthenticatedControlRequest, ()> {
    let (token, root) = {
        let sessions = state.transport_sessions.lock().await;
        let session_id = TransportSessionId::new(header.session_id);
        let transport = sessions.get(&session_id).ok_or(())?;
        (
            Zeroizing::new(transport.token.0.clone()),
            transport.root.clone(),
        )
    };
    if active_session(state, token.as_str(), false).await.is_none() {
        return Err(());
    }
    let mut records = HttpSessionBinding::new(state.node_public_key, header.session_id)
        .map_err(|_| ())?
        .into_server(&root)
        .map_err(|_| ())?;
    let timeout_sealer = HttpSessionBinding::new(state.node_public_key, header.session_id)
        .map_err(|_| ())?
        .into_server(&root)
        .map_err(|_| ())?
        .sealer;
    let plaintext = records
        .opener
        .open(header.handle, CONTROL_AAD, body)
        .map_err(|_| ())?;
    let action = decode_control_action(&plaintext).map_err(|_| ())?;
    Ok(AuthenticatedControlRequest {
        session_id: header.session_id,
        handle: header.handle,
        token,
        action: Some(action),
        response_sealer: Some(records.sealer),
        timeout_sealer: Some(timeout_sealer),
    })
}

async fn cached_control_response(
    state: &AppState,
    key: &ControlReceiptKey,
    request_digest: [u8; 32],
    expected_generation: u64,
) -> Result<Option<Vec<u8>>, ()> {
    let lookup = {
        let mut receipts = state.control_receipts.lock().await;
        receipts.lookup(key, request_digest, expected_generation, now_ms())
    };
    match lookup {
        ControlReceiptLookup::Missing => Ok(None),
        ControlReceiptLookup::Mismatch
        | ControlReceiptLookup::Stale
        | ControlReceiptLookup::Spent => Err(()),
        ControlReceiptLookup::Complete(response) => Ok(Some(response.as_slice().to_vec())),
        ControlReceiptLookup::InFlight(mut receiver) => loop {
            if let Some(response) = receiver.borrow().clone() {
                return Ok(Some(response.as_slice().to_vec()));
            }
            receiver.changed().await.map_err(|_| ())?;
        },
    }
}

async fn dispatch_control(
    state: &AppState,
    mut request: AuthenticatedControlRequest,
) -> Result<Vec<u8>, ()> {
    let session_id = request.session_id;
    let handle = request.handle;
    let token = &request.token;
    let action = request.action.take().ok_or(())?;
    let result = match action {
        ControlAction::IssueWsTicket {
            platform,
            version,
            build_signature,
        } => {
            let mut attestation = BuildAttestationRequest {
                platform: platform.to_string(),
                version: version.to_string(),
                build_signature_b64: build_signature.to_string(),
            };
            let result =
                issue_ws_ticket_for_transport(state, session_id, token.as_str(), &mut attestation)
                    .await;
            attestation.platform.zeroize();
            attestation.version.zeroize();
            attestation.build_signature_b64.zeroize();
            result
        }
        ControlAction::Logout => logout_transport_session(state, session_id, token.as_str()).await,
    };
    let encoded = encode_control_result(&result).map_err(|_| ())?;
    let mut response_sealer = request.response_sealer.take().ok_or(())?;
    response_sealer
        .seal(handle, CONTROL_AAD, &encoded)
        .map_err(|_| ())
}

async fn run_control_worker(state: &AppState, mut request: AuthenticatedControlRequest) -> Vec<u8> {
    let handle = request.handle;
    let mut timeout_sealer = request.timeout_sealer.take();
    let response = tokio::time::timeout(CONTROL_WORKER_TIMEOUT, dispatch_control(state, request))
        .await
        .ok()
        .and_then(Result::ok);
    match response {
        Some(response) => response,
        None => seal_control_failure(&mut timeout_sealer, handle)
            .unwrap_or_else(|_| random_control_response()),
    }
}

fn seal_control_failure(
    timeout_sealer: &mut Option<HttpSealer>,
    handle: [u8; 16],
) -> Result<Vec<u8>, ()> {
    let encoded = encode_control_result(&ControlResult::Failure).map_err(|_| ())?;
    timeout_sealer
        .as_mut()
        .ok_or(())?
        .seal(handle, CONTROL_AAD, &encoded)
        .map_err(|_| ())
}

async fn issue_ws_ticket_for_transport(
    state: &AppState,
    session_id: [u8; 32],
    token: &str,
    attestation: &mut BuildAttestationRequest,
) -> ControlResult {
    if state
        .release_admission
        .admit(attestation, now_ms())
        .await
        .is_err()
    {
        return ControlResult::Failure;
    }
    let Some(client_platform) = ClientPlatform::parse(&attestation.platform) else {
        return ControlResult::Failure;
    };
    let _account_guard = state.account_ops.lock().await;
    // Keep the session and transport generations locked through the final
    // account/ticket writes. The sweeper uses the same sessions -> transport
    // order, so expiry cannot interleave between validation and mutation.
    let mut sessions = state.sessions.lock().await;
    let auth_session = sessions.get(token).cloned();
    let Some(auth_session) = auth_session else {
        return ControlResult::Failure;
    };
    if session_is_expired(&auth_session, now_ms(), state.session_inactivity_ms) {
        sessions.remove(token);
        state
            .transport_sessions
            .lock()
            .await
            .retain(|_, transport| transport.token.0 != token);
        return ControlResult::Failure;
    }
    let transport_sessions = state.transport_sessions.lock().await;
    let transport_live = transport_sessions
        .get(&TransportSessionId::new(session_id))
        .is_some_and(|transport| transport.token.0 == token);
    if !transport_live {
        return ControlResult::Failure;
    }
    let mut accounts = state.accounts.lock().await;
    let Some(account) = accounts.get_mut(&auth_session.code_id) else {
        return ControlResult::Failure;
    };
    if account
        .client_platform
        .is_some_and(|bound| bound != client_platform)
    {
        return ControlResult::Failure;
    }

    let now = now_ms();
    let mut tickets = state.ws_tickets.lock().await;
    prune_ws_tickets_locked(&mut tickets, now);
    let existing = tickets
        .iter()
        .filter(|(_, ticket)| ticket.session_token.as_str() == token)
        .map(|(digest, _)| *digest)
        .collect::<Vec<_>>();
    if existing.is_empty() && tickets.len() >= MAX_WS_TICKETS {
        return ControlResult::Failure;
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
    for mut old_digest in existing {
        if let Some((mut stored_digest, _)) = tickets.remove_entry(&old_digest) {
            stored_digest.zeroize();
        }
        old_digest.zeroize();
    }
    account.client_platform = Some(client_platform);
    tickets.insert(
        digest,
        WsTicket {
            session_token: Zeroizing::new(token.to_owned()),
            expires_at_ms: now.saturating_add(WS_TICKET_TTL_MS),
            client_platform,
        },
    );
    drop(tickets);
    drop(accounts);
    drop(transport_sessions);
    drop(sessions);
    touch_activity(state).await;
    ControlResult::WsTicket {
        ticket: Zeroizing::new(ticket),
        expires_in_sec: (WS_TICKET_TTL_MS / 1000) as u32,
    }
}

async fn logout_transport_session(
    state: &AppState,
    session_id: [u8; 32],
    token: &str,
) -> ControlResult {
    let _account_guard = state.account_ops.lock().await;
    let mut sessions = state.sessions.lock().await;
    let Some(session) = sessions.get(token).cloned() else {
        return ControlResult::Failure;
    };
    let mut transport_sessions = state.transport_sessions.lock().await;
    let transport_live = transport_sessions
        .get(&TransportSessionId::new(session_id))
        .is_some_and(|transport| transport.token.0 == token);
    if !transport_live {
        return ControlResult::Failure;
    }
    if session_is_expired(&session, now_ms(), state.session_inactivity_ms) {
        sessions.remove(token);
        transport_sessions.retain(|_, transport| transport.token.0 != token);
        return ControlResult::Failure;
    }
    sessions.remove(token);
    transport_sessions.retain(|_, transport| transport.token.0 != token);
    drop(transport_sessions);
    drop(sessions);
    clear_ws_tickets_for_session(state, token).await;
    replace_connected_clients_for_code(state, &session.code_id).await;
    touch_activity(state).await;
    ControlResult::LoggedOut
}

pub(super) fn random_control_response() -> Vec<u8> {
    let mut body = vec![0_u8; CONTROL_RECORD_BYTES];
    OsRng.fill_bytes(&mut body);
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_store_binds_digest_and_bounds_memory() {
        let mut store = ControlReceiptStore::new();
        let key = ControlReceiptKey {
            session_id: [1; 32],
            handle: [2; 16],
        };
        assert!(matches!(
            store.reserve(key.clone(), [3; 32], 0, 10),
            ControlReceiptReservation::Owner(_)
        ));
        assert!(matches!(
            store.reserve(key.clone(), [4; 32], 0, 10),
            ControlReceiptReservation::Mismatch
        ));
        store.complete(&key, [3; 32], 0, vec![5; CONTROL_RECORD_BYTES], 11);
        assert!(matches!(
            store.lookup(&key, [3; 32], 0, 11),
            ControlReceiptLookup::Complete(_)
        ));
        store.prune(11 + CONTROL_RECEIPT_TTL_MS);
        assert_eq!(store.used_bytes, 0);
        assert_eq!(store.spent_len(), 1);
    }

    #[test]
    fn receipt_store_retains_spent_in_flight_handles_after_cache_expiry() {
        let mut store = ControlReceiptStore::new();
        let key = ControlReceiptKey {
            session_id: [4; 32],
            handle: [5; 16],
        };
        assert!(matches!(
            store.reserve(key.clone(), [6; 32], 0, 100),
            ControlReceiptReservation::Owner(_)
        ));
        assert!(matches!(
            store.lookup(&key, [6; 32], 0, 100 + CONTROL_RECEIPT_TTL_MS),
            ControlReceiptLookup::Spent
        ));
        assert_eq!(store.len(), 0);
        assert_eq!(store.used_bytes, 0);
        assert_eq!(store.spent_len(), 1);
        assert!(matches!(
            store.reserve(key, [7; 32], 0, 100 + CONTROL_RECEIPT_TTL_MS),
            ControlReceiptReservation::Spent
        ));
    }

    #[test]
    fn late_completion_after_clear_cannot_publish_into_a_new_generation() {
        let mut store = ControlReceiptStore::new();
        let key = ControlReceiptKey {
            session_id: [8; 32],
            handle: [9; 16],
        };
        let ControlReceiptReservation::Owner(old_generation) =
            store.reserve(key.clone(), [10; 32], 0, 100)
        else {
            panic!("initial receipt reservation");
        };
        store.clear();
        assert!(matches!(
            store.lookup(&key, [10; 32], old_generation, 200),
            ControlReceiptLookup::Stale
        ));
        assert!(matches!(
            store.reserve(key.clone(), [10; 32], old_generation, 200),
            ControlReceiptReservation::Stale
        ));
        let ControlReceiptReservation::Owner(new_generation) =
            store.reserve(key.clone(), [10; 32], 1, 200)
        else {
            panic!("new-generation receipt reservation");
        };
        assert_ne!(old_generation, new_generation);
        store.complete(
            &key,
            [10; 32],
            old_generation,
            vec![11; CONTROL_RECORD_BYTES],
            201,
        );
        assert!(matches!(
            store.lookup(&key, [10; 32], 1, 201),
            ControlReceiptLookup::InFlight(_)
        ));
        store.complete(
            &key,
            [10; 32],
            new_generation,
            vec![12; CONTROL_RECORD_BYTES],
            202,
        );
        assert!(matches!(
            store.lookup(&key, [10; 32], 1, 202),
            ControlReceiptLookup::Complete(_)
        ));
    }

    #[test]
    fn receipt_store_fails_closed_when_spent_handle_capacity_is_exhausted() {
        let mut store = ControlReceiptStore::new();
        for index in 0..MAX_CONTROL_SPENT_HANDLES {
            let mut session_id = [0_u8; 32];
            session_id[24..].copy_from_slice(&(index as u64).to_be_bytes());
            let mut handle = [0_u8; 16];
            handle[8..].copy_from_slice(&(index as u64).to_be_bytes());
            assert!(matches!(
                store.reserve(
                    ControlReceiptKey { session_id, handle },
                    [index as u8; 32],
                    0,
                    0,
                ),
                ControlReceiptReservation::Owner(_)
            ));
            store.prune(CONTROL_RECEIPT_TTL_MS);
        }
        let rejected = store.reserve(
            ControlReceiptKey {
                session_id: [0xff; 32],
                handle: [0xfe; 16],
            },
            [0xfd; 32],
            0,
            0,
        );
        assert!(matches!(rejected, ControlReceiptReservation::Capacity));
        assert_eq!(store.spent_len(), MAX_CONTROL_SPENT_HANDLES);
    }

    #[test]
    fn receipt_store_fails_closed_at_entry_capacity_without_eviction() {
        let mut store = ControlReceiptStore::new();
        for index in 0..MAX_CONTROL_RECEIPTS {
            let mut session_id = [0_u8; 32];
            session_id[24..].copy_from_slice(&(index as u64).to_be_bytes());
            let mut handle = [0_u8; 16];
            handle[8..].copy_from_slice(&(index as u64).to_be_bytes());
            assert!(matches!(
                store.reserve(
                    ControlReceiptKey { session_id, handle },
                    [index as u8; 32],
                    0,
                    0,
                ),
                ControlReceiptReservation::Owner(_)
            ));
        }
        let rejected = store.reserve(
            ControlReceiptKey {
                session_id: [0xff; 32],
                handle: [0xfe; 16],
            },
            [0xfd; 32],
            0,
            0,
        );
        assert!(matches!(rejected, ControlReceiptReservation::Capacity));
        assert_eq!(store.len(), MAX_CONTROL_RECEIPTS);
    }
}
