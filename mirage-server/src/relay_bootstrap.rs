//! Binary account bootstrap transport for protocol v11.
//!
//! This module is the HTTP and replay boundary for the shared bootstrap codec.
//! Account operations live in
//! `bootstrap_auth`, where they share the same locks and lifecycle invariants
//! as the legacy routes.

use super::*;
use abyssal_transport::{
    decode_account_bootstrap_action, encode_account_bootstrap_result, inspect_bootstrap_request,
    AccountBootstrapAction, AccountBootstrapResult, BootstrapContext, BootstrapServerExchange,
    ACCOUNT_BOOTSTRAP_OPERATION, MAX_BOOTSTRAP_PLAINTEXT_BYTES,
};
use tokio::sync::watch;

pub(super) const BOOTSTRAP_PLAINTEXT_BYTES: usize = MAX_BOOTSTRAP_PLAINTEXT_BYTES;
pub(super) const BOOTSTRAP_REQUEST_BYTES: usize =
    4 + 1 + 32 + 32 + 4 + BOOTSTRAP_PLAINTEXT_BYTES + 16;
pub(super) const BOOTSTRAP_RESPONSE_BYTES: usize = BOOTSTRAP_PLAINTEXT_BYTES + 16;
pub(super) const BOOTSTRAP_WORKER_LIMIT: usize = 32;
const BOOTSTRAP_RECEIPT_TTL_MS: u64 = 10 * 60 * 1000;
const MAX_BOOTSTRAP_RECEIPTS: usize = 4096;
const MAX_BOOTSTRAP_RECEIPT_BYTES: usize = 32 * 1024 * 1024;
const MAX_BOOTSTRAP_SPENT_IDS: usize = 8192;
const BOOTSTRAP_WORKER_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Eq, Hash, PartialEq)]
pub(super) struct BootstrapRequestId([u8; 32]);

impl BootstrapRequestId {
    fn new(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl Drop for BootstrapRequestId {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

enum BootstrapReceiptState {
    InFlight(watch::Sender<Option<Arc<Zeroizing<Vec<u8>>>>>),
    Complete(Arc<Zeroizing<Vec<u8>>>),
}

struct BootstrapReceipt {
    request_digest: [u8; 32],
    created_at_ms: u64,
    state: BootstrapReceiptState,
}

pub(super) struct BootstrapReceiptStore {
    entries: HashMap<BootstrapRequestId, BootstrapReceipt>,
    // This ledger lives for the bootstrap-key lifetime, unlike the response
    // cache which is intentionally cleared during a RAM wipe.
    spent: HashMap<BootstrapRequestId, [u8; 32]>,
    // Expired entries retain whether their authenticated response was sealed.
    // An expired in-flight reservation may still be rolled back by its worker;
    // a terminal response must never be reopened by a late abort.
    terminal_spent: HashSet<BootstrapRequestId>,
    used_bytes: usize,
}

enum BootstrapReceiptLookup {
    Missing,
    Mismatch,
    InFlight(watch::Receiver<Option<Arc<Zeroizing<Vec<u8>>>>>),
    Complete(Arc<Zeroizing<Vec<u8>>>),
    Spent,
}

enum BootstrapReceiptReservation {
    Owner,
    Existing,
    Mismatch,
    Capacity,
    Spent,
}

impl BootstrapReceiptStore {
    pub(super) fn new() -> Self {
        Self {
            entries: HashMap::new(),
            spent: HashMap::new(),
            terminal_spent: HashSet::new(),
            used_bytes: 0,
        }
    }

    pub(super) fn prune(&mut self, now_ms: u64) {
        let expired_ids = self
            .entries
            .iter()
            .filter(|(_, receipt)| {
                now_ms.saturating_sub(receipt.created_at_ms) >= BOOTSTRAP_RECEIPT_TTL_MS
            })
            .map(|(request_id, _)| request_id.clone())
            .collect::<Vec<_>>();
        for request_id in expired_ids {
            let Some(receipt) = self.entries.get(&request_id) else {
                continue;
            };
            // Keep the authenticated request digest when its response cache
            // expires. The bootstrap key outlives the cache, so forgetting
            // this marker would make the same request ID/nonce reusable.
            if self.spent.len() >= MAX_BOOTSTRAP_SPENT_IDS {
                continue;
            }
            let request_digest = receipt.request_digest;
            let terminal = matches!(receipt.state, BootstrapReceiptState::Complete(_));
            if self.entries.remove(&request_id).is_some() {
                self.used_bytes = match self.used_bytes.checked_sub(BOOTSTRAP_RESPONSE_BYTES) {
                    Some(used_bytes) => used_bytes,
                    None => {
                        debug_assert!(false, "bootstrap receipt byte budget invariant");
                        0
                    }
                };
                if terminal {
                    self.terminal_spent.insert(request_id.clone());
                }
                self.spent.insert(request_id, request_digest);
            }
        }
    }

    fn lookup(
        &mut self,
        request_id: &BootstrapRequestId,
        request_digest: [u8; 32],
        now_ms: u64,
    ) -> BootstrapReceiptLookup {
        self.prune(now_ms);
        let Some(receipt) = self.entries.get(request_id) else {
            return match self.spent.get(request_id) {
                Some(spent_digest) if spent_digest == &request_digest => {
                    BootstrapReceiptLookup::Spent
                }
                Some(_) => BootstrapReceiptLookup::Mismatch,
                None => BootstrapReceiptLookup::Missing,
            };
        };
        if receipt.request_digest != request_digest {
            return BootstrapReceiptLookup::Mismatch;
        }
        match &receipt.state {
            BootstrapReceiptState::InFlight(sender) => {
                BootstrapReceiptLookup::InFlight(sender.subscribe())
            }
            BootstrapReceiptState::Complete(response) => {
                BootstrapReceiptLookup::Complete(response.clone())
            }
        }
    }

    fn reserve(
        &mut self,
        request_id: BootstrapRequestId,
        request_digest: [u8; 32],
        now_ms: u64,
    ) -> BootstrapReceiptReservation {
        self.prune(now_ms);
        if let Some(receipt) = self.entries.get(&request_id) {
            return if receipt.request_digest == request_digest {
                BootstrapReceiptReservation::Existing
            } else {
                BootstrapReceiptReservation::Mismatch
            };
        }
        if let Some(spent_digest) = self.spent.get(&request_id) {
            return if spent_digest == &request_digest {
                BootstrapReceiptReservation::Spent
            } else {
                BootstrapReceiptReservation::Mismatch
            };
        }
        if self.spent.len() >= MAX_BOOTSTRAP_SPENT_IDS {
            return BootstrapReceiptReservation::Capacity;
        }
        let Some(next_used_bytes) = self.used_bytes.checked_add(BOOTSTRAP_RESPONSE_BYTES) else {
            return BootstrapReceiptReservation::Capacity;
        };
        if self.entries.len() >= MAX_BOOTSTRAP_RECEIPTS
            || next_used_bytes > MAX_BOOTSTRAP_RECEIPT_BYTES
        {
            return BootstrapReceiptReservation::Capacity;
        }
        let (sender, _) = watch::channel(None);
        self.spent.insert(request_id.clone(), request_digest);
        self.entries.insert(
            request_id,
            BootstrapReceipt {
                request_digest,
                created_at_ms: now_ms,
                state: BootstrapReceiptState::InFlight(sender),
            },
        );
        self.used_bytes = next_used_bytes;
        BootstrapReceiptReservation::Owner
    }

    fn complete(
        &mut self,
        request_id: &BootstrapRequestId,
        request_digest: [u8; 32],
        response: Zeroizing<Vec<u8>>,
        now_ms: u64,
    ) {
        self.prune(now_ms);
        if self.spent.get(request_id) != Some(&request_digest) {
            return;
        }
        let Some(receipt) = self.entries.get_mut(request_id) else {
            self.terminal_spent.insert(request_id.clone());
            return;
        };
        if receipt.request_digest != request_digest {
            return;
        }
        let response = Arc::new(response);
        if let BootstrapReceiptState::InFlight(sender) = &receipt.state {
            let _ = sender.send(Some(response.clone()));
        }
        receipt.state = BootstrapReceiptState::Complete(response);
        receipt.created_at_ms = now_ms;
    }

    fn abort(&mut self, request_id: &BootstrapRequestId, request_digest: [u8; 32]) {
        let Some(spent_digest) = self.spent.get(request_id) else {
            return;
        };
        if spent_digest != &request_digest {
            return;
        }
        let unsealed = self
            .entries
            .get(request_id)
            .is_some_and(|receipt| matches!(receipt.state, BootstrapReceiptState::InFlight(_)));
        let expired_unsealed =
            !self.entries.contains_key(request_id) && !self.terminal_spent.contains(request_id);
        if !unsealed && !expired_unsealed {
            return;
        }
        self.spent.remove(request_id);
        if self.entries.remove(request_id).is_some() {
            self.used_bytes = match self.used_bytes.checked_sub(BOOTSTRAP_RESPONSE_BYTES) {
                Some(used_bytes) => used_bytes,
                None => {
                    debug_assert!(false, "bootstrap receipt byte budget invariant");
                    0
                }
            };
        }
    }

    pub(super) fn clear(&mut self) {
        // Wipe invalidates all workers. Their late aborts must not reopen an
        // authenticated request ID from the prior bootstrap-key lifetime.
        self.terminal_spent.extend(self.spent.keys().cloned());
        self.entries.clear();
        self.used_bytes = 0;
    }
}

#[cfg(test)]
impl BootstrapReceiptStore {
    pub(super) fn fill_to_capacity_for_test(&mut self, now_ms: u64) {
        let capacity = MAX_BOOTSTRAP_RECEIPT_BYTES / BOOTSTRAP_RESPONSE_BYTES;
        for index in 0..capacity {
            let mut request_id = [0_u8; 32];
            request_id[..8].copy_from_slice(&(index as u64).to_be_bytes());
            let _ = self.reserve(
                BootstrapRequestId::new(request_id),
                [index as u8; 32],
                now_ms,
            );
        }
    }

    pub(super) fn fill_spent_to_capacity_for_test(&mut self, _now_ms: u64) {
        for index in 0..MAX_BOOTSTRAP_SPENT_IDS {
            let mut request_id = [0_u8; 32];
            request_id[..8].copy_from_slice(&(index as u64).to_be_bytes());
            self.spent
                .insert(BootstrapRequestId::new(request_id), [index as u8; 32]);
        }
    }
}

pub(super) async fn handle_bootstrap(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        handle_bootstrap_inner(state, headers, body),
    )
    .await
    .unwrap_or_else(|_| Ok::<Vec<u8>, ()>(random_response_bytes()));
    let body = response.unwrap_or_else(|_| random_response_bytes());
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

async fn handle_bootstrap_inner(
    state: AppState,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Vec<u8>, ()> {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/octet-stream")
        || body.len() != BOOTSTRAP_REQUEST_BYTES
    {
        return Err(());
    }
    let header = inspect_bootstrap_request(&body).map_err(|_| ())?;
    let request_digest: [u8; 32] = Sha256::digest(body.as_ref()).into();
    let request_id = BootstrapRequestId::new(header.request_id);
    if let Some(response) = cached_receipt_response(&state, &request_id, request_digest).await? {
        return Ok(response);
    }
    let context = BootstrapContext::new(
        state.node_public_key,
        state.bootstrap_hpke_public_key,
        ACCOUNT_BOOTSTRAP_OPERATION.to_vec(),
        header.request_id,
    )
    .map_err(|_| ())?;
    let worker_permit = match state.bootstrap_workers.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return Err(()),
    };
    let replay_now_ms = now_ms();
    let opened = {
        let mut replay = state.bootstrap_replay_guard.lock().await;
        match replay.open_request(
            state.bootstrap_hpke_keypair.private_key(),
            &context,
            &body,
            replay_now_ms,
        ) {
            Ok(exchange) => {
                let reservation = {
                    let mut receipts = state.bootstrap_receipts.lock().await;
                    receipts.reserve(request_id.clone(), request_digest, replay_now_ms)
                };
                if !matches!(&reservation, BootstrapReceiptReservation::Owner) {
                    replay.discard_authenticated_request(header.request_id, replay_now_ms);
                }
                Ok((exchange, reservation))
            }
            Err(_) => Err(()),
        }
    };
    let (exchange, reservation) = match opened {
        Ok(opened) => opened,
        Err(_) => {
            drop(worker_permit);
            return cached_receipt_response(&state, &request_id, request_digest)
                .await?
                .ok_or(());
        }
    };
    match reservation {
        BootstrapReceiptReservation::Owner => {
            let worker_state = state.clone();
            let worker_request_id = request_id.clone();
            let replay_request_id = header.request_id;
            tokio::spawn(async move {
                let _worker_permit = worker_permit;
                match tokio::time::timeout(
                    BOOTSTRAP_WORKER_TIMEOUT,
                    dispatch_exchange(&worker_state, exchange),
                )
                .await
                {
                    Ok(Ok(response)) => {
                        worker_state.bootstrap_receipts.lock().await.complete(
                            &worker_request_id,
                            request_digest,
                            Zeroizing::new(response),
                            now_ms(),
                        );
                    }
                    Ok(Err(())) | Err(_) => {
                        // Keep replay and receipt locks in admission order.
                        let mut replay = worker_state.bootstrap_replay_guard.lock().await;
                        worker_state
                            .bootstrap_receipts
                            .lock()
                            .await
                            .abort(&worker_request_id, request_digest);
                        replay.discard_authenticated_request(replay_request_id, replay_now_ms);
                    }
                }
            });
        }
        BootstrapReceiptReservation::Existing => {
            drop(exchange);
            drop(worker_permit);
        }
        BootstrapReceiptReservation::Mismatch
        | BootstrapReceiptReservation::Capacity
        | BootstrapReceiptReservation::Spent => {
            drop(exchange);
            drop(worker_permit);
            return Err(());
        }
    }
    cached_receipt_response(&state, &request_id, request_digest)
        .await?
        .ok_or(())
}

async fn cached_receipt_response(
    state: &AppState,
    request_id: &BootstrapRequestId,
    request_digest: [u8; 32],
) -> Result<Option<Vec<u8>>, ()> {
    let lookup = {
        let mut receipts = state.bootstrap_receipts.lock().await;
        receipts.lookup(request_id, request_digest, now_ms())
    };
    match lookup {
        BootstrapReceiptLookup::Missing => Ok(None),
        BootstrapReceiptLookup::Mismatch | BootstrapReceiptLookup::Spent => Err(()),
        BootstrapReceiptLookup::Complete(response) => Ok(Some(response.as_slice().to_vec())),
        BootstrapReceiptLookup::InFlight(mut receiver) => loop {
            if let Some(response) = { receiver.borrow().clone() } {
                return Ok(Some(response.as_slice().to_vec()));
            }
            receiver.changed().await.map_err(|_| ())?;
        },
    }
}

async fn dispatch_exchange(
    state: &AppState,
    exchange: BootstrapServerExchange,
) -> Result<Vec<u8>, ()> {
    let result = match decode_account_bootstrap_action(exchange.plaintext.as_slice()) {
        Ok(AccountBootstrapAction::Start {
            capability,
            registration_request,
            credential_request,
        }) => {
            bootstrap_auth::bootstrap_start(
                state,
                capability,
                registration_request,
                credential_request,
            )
            .await
        }
        Ok(AccountBootstrapAction::FinishRegistration {
            handshake_id,
            registration_upload,
            identity_public,
            identity_prekey_id,
            identity_envelope,
            identity_proof,
        }) => {
            bootstrap_auth::bootstrap_finish_registration(
                state,
                Uuid::from_bytes(handshake_id),
                registration_upload,
                identity_public,
                identity_prekey_id,
                identity_envelope,
                identity_proof,
            )
            .await
        }
        Ok(AccountBootstrapAction::FinishLogin {
            handshake_id,
            credential_finalization,
        }) => {
            bootstrap_auth::bootstrap_finish_login(
                state,
                Uuid::from_bytes(handshake_id),
                credential_finalization,
            )
            .await
        }
        Err(_) => AccountBootstrapResult::Failure,
    };
    let plain = encode_account_bootstrap_result(&result).map_err(|_| ())?;
    exchange
        .response_sealer
        .seal(plain.as_slice())
        .map_err(|_| ())
}

pub(super) fn random_response_bytes() -> Vec<u8> {
    let mut body = vec![0_u8; BOOTSTRAP_RESPONSE_BYTES];
    OsRng.fill_bytes(&mut body);
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn receipt_retry_survives_cancelled_waiter_and_reuses_response() {
        let mut store = BootstrapReceiptStore::new();
        let request_id = BootstrapRequestId::new([9; 32]);
        let digest = [4; 32];
        assert!(matches!(
            store.reserve(request_id.clone(), digest, 10),
            BootstrapReceiptReservation::Owner
        ));
        let BootstrapReceiptLookup::InFlight(mut receiver) = store.lookup(&request_id, digest, 10)
        else {
            panic!("receipt was not in flight");
        };
        let cancelled = tokio::time::timeout(Duration::from_millis(1), receiver.changed()).await;
        assert!(cancelled.is_err());
        drop(receiver);
        store.complete(
            &request_id,
            digest,
            Zeroizing::new(vec![7; BOOTSTRAP_RESPONSE_BYTES]),
            11,
        );
        let BootstrapReceiptLookup::Complete(response) = store.lookup(&request_id, digest, 11)
        else {
            panic!("completed receipt was not reusable");
        };
        assert_eq!(
            response.as_slice(),
            vec![7; BOOTSTRAP_RESPONSE_BYTES].as_slice()
        );
    }

    #[test]
    fn receipt_digest_binding_and_capacity_are_bounded() {
        let mut store = BootstrapReceiptStore::new();
        let request_id = BootstrapRequestId::new([1; 32]);
        assert!(matches!(
            store.reserve(request_id.clone(), [2; 32], 20),
            BootstrapReceiptReservation::Owner
        ));
        assert!(matches!(
            store.reserve(request_id.clone(), [3; 32], 20),
            BootstrapReceiptReservation::Mismatch
        ));
        let mut byte_store = BootstrapReceiptStore::new();
        let byte_budget_entries = MAX_BOOTSTRAP_RECEIPT_BYTES / BOOTSTRAP_RESPONSE_BYTES;
        for index in 0..byte_budget_entries {
            let mut id = [0_u8; 32];
            id[..8].copy_from_slice(&(index as u64).to_be_bytes());
            assert!(matches!(
                byte_store.reserve(BootstrapRequestId::new(id), [index as u8; 32], 20),
                BootstrapReceiptReservation::Owner
            ));
        }
        assert_eq!(
            byte_store.used_bytes,
            byte_budget_entries * BOOTSTRAP_RESPONSE_BYTES
        );
        assert!(matches!(
            byte_store.reserve(BootstrapRequestId::new([8; 32]), [8; 32], 20),
            BootstrapReceiptReservation::Capacity
        ));
        byte_store.prune(20 + BOOTSTRAP_RECEIPT_TTL_MS);
        assert_eq!(byte_store.used_bytes, 0);
        let mut expired_id = [0_u8; 32];
        expired_id[..8].copy_from_slice(&1_u64.to_be_bytes());
        assert!(matches!(
            byte_store.lookup(
                &BootstrapRequestId::new(expired_id),
                [2; 32],
                20 + BOOTSTRAP_RECEIPT_TTL_MS
            ),
            BootstrapReceiptLookup::Mismatch
        ));
    }

    #[test]
    fn expired_and_wiped_receipts_keep_spent_ids() {
        let mut store = BootstrapReceiptStore::new();
        let expired_id = BootstrapRequestId::new([2; 32]);
        let expired_digest = [3; 32];
        assert!(matches!(
            store.reserve(expired_id.clone(), expired_digest, 10),
            BootstrapReceiptReservation::Owner
        ));
        store.complete(
            &expired_id,
            expired_digest,
            Zeroizing::new(vec![7; BOOTSTRAP_RESPONSE_BYTES]),
            11,
        );
        assert!(matches!(
            store.lookup(&expired_id, expired_digest, 11 + BOOTSTRAP_RECEIPT_TTL_MS),
            BootstrapReceiptLookup::Spent
        ));
        assert!(matches!(
            store.reserve(expired_id, expired_digest, 11 + BOOTSTRAP_RECEIPT_TTL_MS),
            BootstrapReceiptReservation::Spent
        ));

        let wiped_id = BootstrapRequestId::new([4; 32]);
        let wiped_digest = [5; 32];
        assert!(matches!(
            store.reserve(wiped_id.clone(), wiped_digest, 20),
            BootstrapReceiptReservation::Owner
        ));
        store.clear();
        assert!(matches!(
            store.lookup(&wiped_id, wiped_digest, 20),
            BootstrapReceiptLookup::Spent
        ));
        assert!(matches!(
            store.reserve(wiped_id, wiped_digest, 20),
            BootstrapReceiptReservation::Spent
        ));
    }

    #[test]
    fn inflight_expiration_and_late_completion_do_not_resurrect_cache() {
        let mut store = BootstrapReceiptStore::new();
        let request_id = BootstrapRequestId::new([6; 32]);
        let digest = [7; 32];
        assert!(matches!(
            store.reserve(request_id.clone(), digest, 10),
            BootstrapReceiptReservation::Owner
        ));
        let expiry = 10 + BOOTSTRAP_RECEIPT_TTL_MS;
        assert!(matches!(
            store.lookup(&request_id, digest, expiry),
            BootstrapReceiptLookup::Spent
        ));
        store.complete(
            &request_id,
            digest,
            Zeroizing::new(vec![8; BOOTSTRAP_RESPONSE_BYTES]),
            expiry + 1,
        );
        assert!(store.entries.is_empty());
        assert_eq!(store.used_bytes, 0);
        assert!(matches!(
            store.lookup(&request_id, digest, expiry + 1),
            BootstrapReceiptLookup::Spent
        ));

        let aborted_id = BootstrapRequestId::new([9; 32]);
        let aborted_digest = [10; 32];
        assert!(matches!(
            store.reserve(aborted_id.clone(), aborted_digest, 30),
            BootstrapReceiptReservation::Owner
        ));
        store.prune(30 + BOOTSTRAP_RECEIPT_TTL_MS);
        store.abort(&aborted_id, aborted_digest);
        assert!(matches!(
            store.lookup(&aborted_id, aborted_digest, 30 + BOOTSTRAP_RECEIPT_TTL_MS),
            BootstrapReceiptLookup::Missing
        ));
        assert!(matches!(
            store.reserve(aborted_id, aborted_digest, 30 + BOOTSTRAP_RECEIPT_TTL_MS),
            BootstrapReceiptReservation::Owner
        ));
    }

    #[test]
    fn spent_ledger_is_bounded_without_eviction() {
        let mut store = BootstrapReceiptStore::new();
        store.fill_spent_to_capacity_for_test(40);
        assert_eq!(store.spent.len(), MAX_BOOTSTRAP_SPENT_IDS);
        let request_id = BootstrapRequestId::new([0xa5; 32]);
        let digest = [0xa6; 32];
        assert!(matches!(
            store.reserve(request_id.clone(), digest, 40),
            BootstrapReceiptReservation::Capacity
        ));
        store.clear();
        assert_eq!(store.spent.len(), MAX_BOOTSTRAP_SPENT_IDS);
        assert!(matches!(
            store.reserve(request_id, digest, 40),
            BootstrapReceiptReservation::Capacity
        ));
    }

    #[test]
    fn abort_rolls_back_only_unsealed_reservation() {
        let mut store = BootstrapReceiptStore::new();
        let request_id = BootstrapRequestId::new([0xb1; 32]);
        let digest = [0xb2; 32];
        assert!(matches!(
            store.reserve(request_id.clone(), digest, 50),
            BootstrapReceiptReservation::Owner
        ));
        store.abort(&request_id, digest);
        assert!(matches!(
            store.reserve(request_id.clone(), digest, 50),
            BootstrapReceiptReservation::Owner
        ));
        store.complete(
            &request_id,
            digest,
            Zeroizing::new(vec![1; BOOTSTRAP_RESPONSE_BYTES]),
            51,
        );
        store.abort(&request_id, digest);
        assert!(matches!(
            store.lookup(&request_id, digest, 51),
            BootstrapReceiptLookup::Complete(_)
        ));
    }
}
