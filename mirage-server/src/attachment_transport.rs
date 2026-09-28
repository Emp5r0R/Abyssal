//! Authenticated fixed-endpoint attachment-v3 relay transport.

use super::*;
use abyssal_transport::{
    decode_attachment_action, encode_attachment_result, inspect_http_record, AttachmentAction,
    AttachmentResult, AttachmentStreamBinding, Direction, HttpSealer, HttpSessionBinding,
    ATTACHMENT_ACTION_AAD, ATTACHMENT_ACTION_RECORD_BYTES,
};
use futures_util::FutureExt;

const RECEIPT_TTL_MS: u64 = 10 * 60 * 1000;
const MAX_RECEIPTS: usize = 4_096;
const MAX_RECEIPT_BYTES: usize = 32 * 1024 * 1024;
const MAX_SPENT_HANDLES: usize = 8_192;
const RECEIPT_WAIT_TIMEOUT: Duration = Duration::from_secs(15);
const ATTACHMENT_PREFIX_TIMEOUT: Duration = Duration::from_secs(10);
const ATTACHMENT_OWNER_TIMEOUT: Duration = Duration::from_secs(10 * 60 + 30);
pub(super) const WORKER_LIMIT: usize = 16;
pub(super) const ATTACHMENT_V3_MAX_BODY_BYTES: usize = ATTACHMENT_ACTION_RECORD_BYTES
    + ((abyssal_transport::MAX_ATTACHMENT_BUCKET_FRAMES as usize + 1)
        * abyssal_transport::ATTACHMENT_STREAM_FRAME_BYTES);

#[derive(Clone, Eq, Hash, PartialEq)]
struct ReceiptKey {
    session_id: [u8; 32],
    handle: [u8; 16],
}

impl Drop for ReceiptKey {
    fn drop(&mut self) {
        self.session_id.zeroize();
        self.handle.zeroize();
    }
}

enum ReceiptState {
    InFlight(watch::Sender<Option<Arc<Zeroizing<Vec<u8>>>>>),
    Complete(Arc<Zeroizing<Vec<u8>>>),
}

struct Receipt {
    request_digest: [u8; 32],
    generation: u64,
    /// Whether the original request streamed an upload body. A cached retry
    /// must drain the same kind of body without re-authenticating.
    upload_retry: bool,
    created_at_ms: u64,
    state: ReceiptState,
}

impl Drop for Receipt {
    fn drop(&mut self) {
        self.request_digest.zeroize();
    }
}

pub(super) struct AttachmentReceiptStore {
    entries: HashMap<ReceiptKey, Receipt>,
    spent: HashSet<ReceiptKey>,
    used_bytes: usize,
}

enum Lookup {
    Missing,
    Mismatch,
    Stale,
    InFlight(watch::Receiver<Option<Arc<Zeroizing<Vec<u8>>>>>, bool),
    Complete(Arc<Zeroizing<Vec<u8>>>, bool),
    Spent,
    Saturated,
}

enum Reservation {
    Owner,
    Existing,
    Mismatch,
    Capacity,
    Spent,
    Stale,
}

struct AuthenticatedRequest {
    session_id: [u8; 32],
    handle: [u8; 16],
    generation: u64,
    token: Zeroizing<String>,
    root: Zeroizing<[u8; 32]>,
    auth: AuthSession,
    action: Option<AttachmentAction>,
    response_sealer: HttpSealer,
}

struct FirstResponse {
    record: Vec<u8>,
    download: Option<DownloadResponse>,
}

struct DownloadResponse {
    blob: Arc<AttachmentBlob>,
    sealer: abyssal_transport::AttachmentStreamSealer,
    permit: OwnedSemaphorePermit,
    epoch: u64,
}

impl AttachmentReceiptStore {
    pub(super) fn new() -> Self {
        Self {
            entries: HashMap::new(),
            spent: HashSet::new(),
            used_bytes: 0,
        }
    }

    fn prune(&mut self, now: u64) {
        let expired = self
            .entries
            .iter()
            .filter(|(_, receipt)| now.saturating_sub(receipt.created_at_ms) >= RECEIPT_TTL_MS)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in expired {
            if self.spent.len() >= MAX_SPENT_HANDLES {
                break;
            }
            if self.entries.remove(&key).is_some() {
                self.used_bytes = self
                    .used_bytes
                    .saturating_sub(ATTACHMENT_ACTION_RECORD_BYTES);
                self.spent.insert(key);
            }
        }
    }

    fn lookup(&mut self, key: &ReceiptKey, digest: [u8; 32], generation: u64, now: u64) -> Lookup {
        self.prune(now);
        if self.spent.contains(key) {
            return Lookup::Spent;
        }
        let Some(receipt) = self.entries.get(key) else {
            return Lookup::Missing;
        };
        if receipt.generation != generation {
            return Lookup::Stale;
        }
        if receipt.request_digest != digest {
            return Lookup::Mismatch;
        }
        if matches!(receipt.state, ReceiptState::Complete(_))
            && now.saturating_sub(receipt.created_at_ms) >= RECEIPT_TTL_MS
        {
            return Lookup::Saturated;
        }
        match &receipt.state {
            ReceiptState::InFlight(sender) => {
                Lookup::InFlight(sender.subscribe(), receipt.upload_retry)
            }
            ReceiptState::Complete(response) => {
                Lookup::Complete(response.clone(), receipt.upload_retry)
            }
        }
    }

    fn reserve(
        &mut self,
        key: ReceiptKey,
        digest: [u8; 32],
        generation: u64,
        upload_retry: bool,
        now: u64,
    ) -> Reservation {
        self.prune(now);
        if self.spent.contains(&key) {
            return Reservation::Spent;
        }
        if let Some(receipt) = self.entries.get(&key) {
            if matches!(receipt.state, ReceiptState::Complete(_))
                && now.saturating_sub(receipt.created_at_ms) >= RECEIPT_TTL_MS
            {
                return Reservation::Capacity;
            }
            return if receipt.request_digest == digest {
                Reservation::Existing
            } else {
                Reservation::Mismatch
            };
        }
        if self.spent.len() >= MAX_SPENT_HANDLES {
            return Reservation::Capacity;
        }
        let Some(next_bytes) = self.used_bytes.checked_add(ATTACHMENT_ACTION_RECORD_BYTES) else {
            return Reservation::Capacity;
        };
        if self.entries.len() >= MAX_RECEIPTS || next_bytes > MAX_RECEIPT_BYTES {
            return Reservation::Capacity;
        }
        let (sender, _) = watch::channel(None);
        self.entries.insert(
            key,
            Receipt {
                request_digest: digest,
                generation,
                upload_retry,
                created_at_ms: now,
                state: ReceiptState::InFlight(sender),
            },
        );
        self.used_bytes = next_bytes;
        Reservation::Owner
    }

    fn complete(
        &mut self,
        key: &ReceiptKey,
        digest: [u8; 32],
        generation: u64,
        response: Vec<u8>,
        now: u64,
    ) {
        self.prune(now);
        let Some(receipt) = self.entries.get_mut(key) else {
            return;
        };
        if receipt.request_digest != digest
            || receipt.generation != generation
            || response.len() != ATTACHMENT_ACTION_RECORD_BYTES
        {
            return;
        }
        let response = Arc::new(Zeroizing::new(response));
        if let ReceiptState::InFlight(sender) = &receipt.state {
            let _ = sender.send(Some(response.clone()));
        }
        receipt.state = ReceiptState::Complete(response);
        receipt.created_at_ms = now;
    }

    pub(super) fn clear(&mut self) {
        self.entries.clear();
        self.spent.clear();
        self.used_bytes = 0;
    }
}

pub(super) async fn handle_attachment(State(state): State<AppState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    if parts.uri.query().is_some()
        || parts.headers.get(header::AUTHORIZATION).is_some()
        || parts.headers.get(ATTACHMENT_CLAIM_HEADER).is_some()
        || parts
            .headers
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|length| length > ATTACHMENT_V3_MAX_BODY_BYTES)
        || parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            != Some("application/octet-stream")
    {
        return random_response();
    }
    let generation = state.attachment_epoch.load(Ordering::Acquire);
    let prefix_permit = match state.attachment_prefix_workers.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return random_response(),
    };
    let (prefix, body) = match read_action_prefix(body).await {
        Ok(value) => value,
        Err(()) => return random_response(),
    };
    let header = match inspect_http_record(&prefix) {
        Ok(header) if header.direction == Direction::ClientToServer => header,
        _ => return random_response(),
    };
    let key = ReceiptKey {
        session_id: header.session_id,
        handle: header.handle,
    };
    // A cached response is authoritative for an exact retry, even after the
    // session expired or logout removed it (mirrors the control transport).
    let request_digest: [u8; 32] = Sha256::digest(prefix.as_slice()).into();
    match cached_response(&state, &key, request_digest, generation).await {
        Ok(Some((record, upload_retry))) => {
            if consume_cached_retry_body_kind(body, upload_retry)
                .await
                .is_err()
            {
                return random_response();
            }
            if state.attachment_epoch.load(Ordering::Acquire) != generation {
                return random_response();
            }
            return attachment_stream::record_only_response(record);
        }
        Err(()) => return random_response(),
        Ok(None) => {}
    }
    let mut authenticated = match authenticate(&state, prefix.as_slice(), header, generation).await
    {
        Ok(value) => value,
        Err(()) => return random_response(),
    };
    let upload_retry = authenticated
        .action
        .as_ref()
        .is_some_and(|action| matches!(action, AttachmentAction::BeginUpload { .. }));
    drop(prefix_permit);
    let worker_permit = match state.attachment_workers.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return random_response(),
    };
    let reservation = {
        let mut receipts = state.attachment_receipts.lock().await;
        if state.attachment_epoch.load(Ordering::Acquire) != generation {
            Reservation::Stale
        } else {
            receipts.reserve(
                key.clone(),
                request_digest,
                generation,
                upload_retry,
                now_ms(),
            )
        }
    };
    match reservation {
        Reservation::Owner => {}
        Reservation::Existing => {
            drop(authenticated);
            drop(worker_permit);
            let body_result = consume_cached_retry_body_kind(body, upload_retry).await;
            if body_result.is_err() {
                return random_response();
            }
            if state.attachment_epoch.load(Ordering::Acquire) != generation {
                return random_response();
            }
            let cached = cached_response(&state, &key, request_digest, generation)
                .await
                .ok()
                .flatten()
                .map(|(record, _)| record);
            if state.attachment_epoch.load(Ordering::Acquire) != generation {
                return random_response();
            }
            return cached
                .map(attachment_stream::record_only_response)
                .unwrap_or_else(random_response);
        }
        Reservation::Mismatch | Reservation::Capacity | Reservation::Spent | Reservation::Stale => {
            drop(authenticated);
            drop(worker_permit);
            return random_response();
        }
    }
    let (sender, receiver) = oneshot::channel();
    let worker_state = state.clone();
    let worker_key = key.clone();
    tokio::spawn(async move {
        let _permit = worker_permit;
        // A panic in action/lifecycle code must still consume this
        // authenticated handle. The fixed encrypted failure is terminal and
        // keeps a retry from recreating the same AEAD nonce.
        let response = match std::panic::AssertUnwindSafe(execute_with_deadline(
            &worker_state,
            &mut authenticated,
            body,
        ))
        .catch_unwind()
        .await
        {
            Ok(response) => response,
            Err(_) => terminal_failure(&mut authenticated),
        };
        worker_state.attachment_receipts.lock().await.complete(
            &worker_key,
            request_digest,
            generation,
            response.record.clone(),
            now_ms(),
        );
        let _ = sender.send(response);
    });
    match tokio::time::timeout(ATTACHMENT_OWNER_TIMEOUT, receiver).await {
        Ok(Ok(response)) if state.attachment_epoch.load(Ordering::Acquire) == generation => {
            match response.download {
                Some(download) => attachment_stream::download_response(
                    response.record,
                    download.blob,
                    download.sealer,
                    download.permit,
                    Arc::clone(&state.attachment_epoch),
                    download.epoch,
                ),
                None => attachment_stream::record_only_response(response.record),
            }
        }
        _ => random_response(),
    }
}

async fn consume_cached_retry_body_kind(body: Body, allow_upload_retry: bool) -> Result<(), ()> {
    if allow_upload_retry {
        let retry_body_limit =
            ATTACHMENT_V3_MAX_BODY_BYTES.saturating_sub(ATTACHMENT_ACTION_RECORD_BYTES);
        attachment_stream::consume_retry_stream(
            body,
            ATTACHMENT_UPLOAD_TOTAL_TIMEOUT,
            retry_body_limit,
        )
        .await
    } else {
        attachment_stream::digest_empty_stream_with_timeout(body, RECEIPT_WAIT_TIMEOUT).await
    }
}

async fn execute_with_deadline(
    state: &AppState,
    request: &mut AuthenticatedRequest,
    body: Body,
) -> FirstResponse {
    match tokio::time::timeout(ATTACHMENT_OWNER_TIMEOUT, execute(state, request, body)).await {
        Ok(response) => response,
        Err(_) => terminal_failure(request),
    }
}

async fn execute(
    state: &AppState,
    request: &mut AuthenticatedRequest,
    body: Body,
) -> FirstResponse {
    let Some(action) = request.action.take() else {
        return terminal_failure(request);
    };
    let result = match action {
        action @ AttachmentAction::BeginUpload { .. } => {
            match attachment_transport_actions::admit_upload(
                state,
                request.token.as_str(),
                &request.auth,
                action,
                request.generation,
            )
            .await
            {
                Err(()) => AttachmentResult::Failure,
                Ok(admission) => {
                    let opener = abyssal_transport::attachment_data_frame_count(
                        admission.ciphertext_len as u64,
                    )
                    .and_then(|data_frames| {
                        abyssal_transport::attachment_bucket_frame_count(data_frames)
                            .map(|bucket_frames| (data_frames, bucket_frames))
                    })
                    .and_then(|(data_frames, bucket_frames)| {
                        AttachmentStreamBinding::new(
                            state.node_public_key,
                            request.session_id,
                            request.handle,
                        )?
                        .into_opener(
                            &request.root,
                            Direction::ClientToServer,
                            admission.ciphertext_len as u64,
                            data_frames,
                            bucket_frames,
                        )
                    });
                    match opener {
                        Err(_) => AttachmentResult::Failure,
                        Ok(opener) => match attachment_stream::receive_upload_stream(
                            body,
                            opener,
                            admission.ciphertext_len,
                            Arc::clone(&state.attachment_epoch),
                            admission.epoch,
                        )
                        .await
                        {
                            Err(()) => AttachmentResult::Failure,
                            Ok(received) => {
                                if received.ciphertext_digest != admission.expected_digest {
                                    AttachmentResult::Failure
                                } else {
                                    attachment_transport_actions::commit_upload(
                                        state,
                                        request.token.as_str(),
                                        &request.auth,
                                        admission,
                                        received.ciphertext,
                                    )
                                    .await
                                    .unwrap_or(AttachmentResult::Failure)
                                }
                            }
                        },
                    }
                }
            }
        }
        AttachmentAction::BeginDownload { attachment_id } => {
            if attachment_stream::digest_empty_stream(body).await.is_err() {
                AttachmentResult::Failure
            } else {
                match attachment_transport_actions::begin_download(
                    state,
                    request.token.as_str(),
                    &request.auth,
                    attachment_id,
                    request.generation,
                )
                .await
                {
                    Ok(download) => {
                        let attachment_transport_actions::DownloadExecution {
                            result,
                            blob,
                            permit,
                            epoch,
                        } = download;
                        let encoded = encode_attachment_result(&result).ok();
                        let record = encoded.and_then(|encoded| {
                            request
                                .response_sealer
                                .seal(request.handle, ATTACHMENT_ACTION_AAD, &encoded)
                                .ok()
                        });
                        let stream_sealer = AttachmentStreamBinding::new(
                            state.node_public_key,
                            request.session_id,
                            request.handle,
                        )
                        .and_then(|binding| {
                            binding.into_sealer(
                                &request.root,
                                Direction::ServerToClient,
                                blob.bytes.len() as u64,
                            )
                        });
                        if let (Some(record), Ok(sealer)) = (record, stream_sealer) {
                            return FirstResponse {
                                record,
                                download: Some(DownloadResponse {
                                    blob,
                                    sealer,
                                    permit,
                                    epoch,
                                }),
                            };
                        }
                        AttachmentResult::Failure
                    }
                    Err(()) => AttachmentResult::Failure,
                }
            }
        }
        action => {
            if attachment_stream::digest_empty_stream(body).await.is_err() {
                AttachmentResult::Failure
            } else {
                attachment_transport_actions::execute_command(
                    state,
                    request.token.as_str(),
                    &request.auth,
                    action,
                    request.generation,
                )
                .await
            }
        }
    };
    let record = seal_result(&mut request.response_sealer, request.handle, &result)
        .unwrap_or_else(random_record);
    FirstResponse {
        record,
        download: None,
    }
}

fn terminal_failure(request: &mut AuthenticatedRequest) -> FirstResponse {
    let record = seal_result(
        &mut request.response_sealer,
        request.handle,
        &AttachmentResult::Failure,
    )
    .unwrap_or_else(random_record);
    FirstResponse {
        record,
        download: None,
    }
}

async fn authenticate(
    state: &AppState,
    record: &[u8],
    header: abyssal_transport::HttpRecordHeader,
    generation: u64,
) -> Result<AuthenticatedRequest, ()> {
    let (token, root) = {
        let sessions = state.transport_sessions.lock().await;
        let transport = sessions
            .get(&TransportSessionId::new(header.session_id))
            .ok_or(())?;
        (
            Zeroizing::new(transport.token.0.clone()),
            transport.root.clone(),
        )
    };
    let auth = active_session(state, token.as_str(), false)
        .await
        .ok_or(())?;
    let mut records = HttpSessionBinding::new(state.node_public_key, header.session_id)
        .map_err(|_| ())?
        .into_server(&root)
        .map_err(|_| ())?;
    let plaintext = records
        .opener
        .open(header.handle, ATTACHMENT_ACTION_AAD, record)
        .map_err(|_| ())?;
    let action = decode_attachment_action(&plaintext).map_err(|_| ())?;
    Ok(AuthenticatedRequest {
        session_id: header.session_id,
        handle: header.handle,
        generation,
        token,
        root,
        auth,
        action: Some(action),
        response_sealer: records.sealer,
    })
}

async fn read_action_prefix(body: Body) -> Result<(Zeroizing<Vec<u8>>, Body), ()> {
    let deadline = tokio::time::Instant::now() + ATTACHMENT_PREFIX_TIMEOUT;
    tokio::time::timeout_at(deadline, async move {
        let mut stream = body.into_data_stream();
        let mut prefix = Zeroizing::new(Vec::with_capacity(ATTACHMENT_ACTION_RECORD_BYTES));
        while prefix.len() < ATTACHMENT_ACTION_RECORD_BYTES {
            let idle_deadline =
                (tokio::time::Instant::now() + ATTACHMENT_UPLOAD_IDLE_TIMEOUT).min(deadline);
            let mut chunk = tokio::time::timeout_at(idle_deadline, stream.next())
                .await
                .map_err(|_| ())?
                .ok_or(())?
                .map_err(|_| ())?;
            let take = (ATTACHMENT_ACTION_RECORD_BYTES - prefix.len()).min(chunk.len());
            prefix.extend_from_slice(&chunk[..take]);
            chunk = chunk.slice(take..);
            if prefix.len() == ATTACHMENT_ACTION_RECORD_BYTES {
                let remainder =
                    futures_util::stream::once(async move { Ok::<_, axum::Error>(chunk) })
                        .chain(stream);
                return Ok((prefix, Body::from_stream(remainder)));
            }
        }
        Err(())
    })
    .await
    .map_err(|_| ())?
}

async fn cached_response(
    state: &AppState,
    key: &ReceiptKey,
    digest: [u8; 32],
    generation: u64,
) -> Result<Option<(Vec<u8>, bool)>, ()> {
    let lookup = state
        .attachment_receipts
        .lock()
        .await
        .lookup(key, digest, generation, now_ms());
    match lookup {
        Lookup::Missing => Ok(None),
        Lookup::Mismatch | Lookup::Stale | Lookup::Spent | Lookup::Saturated => Err(()),
        Lookup::Complete(response, upload_retry) => {
            Ok(Some((response.as_slice().to_vec(), upload_retry)))
        }
        Lookup::InFlight(mut receiver, upload_retry) => {
            tokio::time::timeout(RECEIPT_WAIT_TIMEOUT, async move {
                loop {
                    if let Some(response) = receiver.borrow().clone() {
                        return Ok(Some((response.as_slice().to_vec(), upload_retry)));
                    }
                    receiver.changed().await.map_err(|_| ())?;
                }
            })
            .await
            .map_err(|_| ())?
        }
    }
}

fn seal_result(
    sealer: &mut HttpSealer,
    handle: [u8; 16],
    result: &AttachmentResult,
) -> Option<Vec<u8>> {
    let encoded = encode_attachment_result(result).ok()?;
    sealer.seal(handle, ATTACHMENT_ACTION_AAD, &encoded).ok()
}

fn random_record() -> Vec<u8> {
    let mut response = vec![0_u8; ATTACHMENT_ACTION_RECORD_BYTES];
    OsRng.fill_bytes(&mut response);
    response
}

fn random_response() -> Response {
    attachment_stream::record_only_response(random_record())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(fill: u8) -> ReceiptKey {
        ReceiptKey {
            session_id: [fill; 32],
            handle: [fill; 16],
        }
    }

    #[test]
    fn completed_receipt_replays_then_becomes_spent() {
        let mut store = AttachmentReceiptStore::new();
        let key = key(1);
        let digest = [2; 32];
        assert!(matches!(
            store.reserve(key.clone(), digest, 1, false, 10),
            Reservation::Owner
        ));
        let response = vec![7; ATTACHMENT_ACTION_RECORD_BYTES];
        store.complete(&key, digest, 1, response.clone(), 20);
        assert!(matches!(
            store.lookup(&key, digest, 1, 20),
            Lookup::Complete(value, false) if value.as_slice() == response.as_slice()
        ));
        assert!(matches!(store.lookup(&key, digest, 2, 20), Lookup::Stale));
        assert!(matches!(
            store.lookup(&key, [3; 32], 1, 20),
            Lookup::Mismatch
        ));
        assert!(matches!(
            store.lookup(&key, digest, 1, 20 + RECEIPT_TTL_MS),
            Lookup::Spent
        ));
        assert!(matches!(
            store.reserve(key, digest, 1, false, 20 + RECEIPT_TTL_MS),
            Reservation::Spent
        ));
    }

    #[test]
    fn receipt_remembers_upload_kind_for_session_free_retries() {
        let mut store = AttachmentReceiptStore::new();
        let key = key(6);
        let digest = [7; 32];
        assert!(matches!(
            store.reserve(key.clone(), digest, 1, true, 10),
            Reservation::Owner
        ));
        assert!(matches!(
            store.lookup(&key, digest, 1, 10),
            Lookup::InFlight(_, true)
        ));
        store.complete(&key, digest, 1, vec![1; ATTACHMENT_ACTION_RECORD_BYTES], 20);
        assert!(matches!(
            store.lookup(&key, digest, 1, 20),
            Lookup::Complete(_, true)
        ));
    }

    #[test]
    fn inflight_receipt_expires_to_a_spent_handle() {
        let mut store = AttachmentReceiptStore::new();
        let key = key(4);
        let digest = [5; 32];
        assert!(matches!(
            store.reserve(key.clone(), digest, 4, false, 10),
            Reservation::Owner
        ));
        assert!(matches!(
            store.lookup(&key, digest, 4, 10 + RECEIPT_TTL_MS),
            Lookup::Spent
        ));
        assert!(matches!(
            store.reserve(key, digest, 4, false, 10 + RECEIPT_TTL_MS),
            Reservation::Spent
        ));
    }

    #[test]
    fn wipe_generation_rejects_old_owner_completion_and_allows_new_handle() {
        let mut store = AttachmentReceiptStore::new();
        let key = key(8);
        let digest = [9; 32];
        assert!(matches!(
            store.reserve(key.clone(), digest, 11, false, 10),
            Reservation::Owner
        ));
        store.clear();
        store.complete(
            &key,
            digest,
            11,
            vec![7; ATTACHMENT_ACTION_RECORD_BYTES],
            20,
        );
        assert!(matches!(
            store.reserve(key, digest, 12, false, 20),
            Reservation::Owner
        ));
    }
}
