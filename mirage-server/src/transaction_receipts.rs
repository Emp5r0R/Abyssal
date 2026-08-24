use std::collections::HashMap;

use sha2::{Digest, Sha256};

pub(crate) const DEFAULT_GLOBAL_RECEIPT_LIMIT: usize = 50_000;
pub(crate) const DEFAULT_ACCOUNT_RECEIPT_LIMIT: usize = 2_048;
pub(crate) type AccountId = [u8; 32];

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum TransactionKind {
    Message,
    Acknowledgement,
    MlsRoom,
    MlsSnapshot,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct TransactionKey {
    account_id: AccountId,
    kind: TransactionKind,
    conversation_id: String,
    message_id: String,
}

impl TransactionKey {
    pub(crate) fn new(
        account_id: AccountId,
        kind: TransactionKind,
        conversation_id: &str,
        message_id: &str,
    ) -> Self {
        Self {
            account_id,
            kind,
            conversation_id: conversation_id.to_owned(),
            message_id: message_id.to_owned(),
        }
    }
}

#[derive(Clone, Debug)]
struct Receipt {
    frame_digest: [u8; 32],
    accepted: Option<bool>,
    expires_at_ms: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct TransactionTicket {
    key: TransactionKey,
    frame_digest: [u8; 32],
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum BeginOutcome {
    Execute(TransactionTicket),
    Replay(bool),
    InProgress,
    CapacityExceeded,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ReceiptError {
    ConflictingFrame,
    MissingReservation,
}

pub(crate) struct TransactionReceiptStore {
    receipts: HashMap<TransactionKey, Receipt>,
    terminal_ttl_ms: u64,
    global_limit: usize,
    account_limit: usize,
}

impl TransactionReceiptStore {
    pub(crate) fn new(terminal_ttl_ms: u64) -> Self {
        Self::with_limits(
            terminal_ttl_ms,
            DEFAULT_GLOBAL_RECEIPT_LIMIT,
            DEFAULT_ACCOUNT_RECEIPT_LIMIT,
        )
    }

    fn with_limits(terminal_ttl_ms: u64, global_limit: usize, account_limit: usize) -> Self {
        Self {
            receipts: HashMap::new(),
            terminal_ttl_ms,
            global_limit,
            account_limit,
        }
    }

    pub(crate) fn begin(
        &mut self,
        key: TransactionKey,
        exact_frame: &str,
        now_ms: u64,
    ) -> Result<BeginOutcome, ReceiptError> {
        self.remove_expired(now_ms);
        let frame_digest: [u8; 32] = Sha256::digest(exact_frame.as_bytes()).into();

        if let Some(receipt) = self.receipts.get(&key) {
            if receipt.frame_digest != frame_digest {
                return Err(ReceiptError::ConflictingFrame);
            }
            return Ok(match receipt.accepted {
                Some(accepted) => BeginOutcome::Replay(accepted),
                None => BeginOutcome::InProgress,
            });
        }

        if self.receipts.len() >= self.global_limit
            || self
                .receipts
                .keys()
                .filter(|existing| existing.account_id == key.account_id)
                .count()
                >= self.account_limit
        {
            return Ok(BeginOutcome::CapacityExceeded);
        }

        self.receipts.insert(
            key.clone(),
            Receipt {
                frame_digest,
                accepted: None,
                expires_at_ms: now_ms.saturating_add(self.terminal_ttl_ms),
            },
        );
        Ok(BeginOutcome::Execute(TransactionTicket {
            key,
            frame_digest,
        }))
    }

    pub(crate) fn finish(
        &mut self,
        ticket: TransactionTicket,
        accepted: bool,
        now_ms: u64,
    ) -> Result<(), ReceiptError> {
        let Some(receipt) = self.receipts.get_mut(&ticket.key) else {
            return Err(ReceiptError::MissingReservation);
        };
        if receipt.frame_digest != ticket.frame_digest || receipt.accepted.is_some() {
            return Err(ReceiptError::ConflictingFrame);
        }
        receipt.accepted = Some(accepted);
        receipt.expires_at_ms = now_ms.saturating_add(self.terminal_ttl_ms);
        Ok(())
    }

    pub(crate) fn clear(&mut self) {
        self.receipts.clear();
    }

    fn remove_expired(&mut self, now_ms: u64) {
        self.receipts
            .retain(|_, receipt| receipt.expires_at_ms > now_ms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(account: u8, message_id: &str) -> TransactionKey {
        TransactionKey::new(
            [account; 32],
            TransactionKind::Message,
            "direct_alpha",
            message_id,
        )
    }

    #[test]
    fn exact_frame_replays_only_after_terminal_outcome() {
        let mut store = TransactionReceiptStore::with_limits(60_000, 4, 4);
        let ticket = match store.begin(key(1, "message-1"), "exact-frame", 1) {
            Ok(BeginOutcome::Execute(ticket)) => ticket,
            other => panic!("unexpected admission: {other:?}"),
        };
        assert_eq!(
            store.begin(key(1, "message-1"), "exact-frame", 2),
            Ok(BeginOutcome::InProgress)
        );
        store.finish(ticket, true, 3).expect("finish receipt");
        assert_eq!(
            store.begin(key(1, "message-1"), "exact-frame", 4),
            Ok(BeginOutcome::Replay(true))
        );
    }

    #[test]
    fn conflicting_bytes_never_reuse_a_transaction_identity() {
        let mut store = TransactionReceiptStore::with_limits(60_000, 4, 4);
        assert!(matches!(
            store.begin(key(1, "message-1"), "first-frame", 1),
            Ok(BeginOutcome::Execute(_))
        ));
        assert_eq!(
            store.begin(key(1, "message-1"), "changed-frame", 2),
            Err(ReceiptError::ConflictingFrame)
        );
    }

    #[test]
    fn capacity_and_expiry_are_enforced_per_account_and_globally() {
        let mut store = TransactionReceiptStore::with_limits(10, 2, 1);
        assert!(matches!(
            store.begin(key(1, "message-1"), "one", 1),
            Ok(BeginOutcome::Execute(_))
        ));
        assert_eq!(
            store.begin(key(1, "message-2"), "two", 2),
            Ok(BeginOutcome::CapacityExceeded)
        );
        assert!(matches!(
            store.begin(key(2, "message-2"), "two", 2),
            Ok(BeginOutcome::Execute(_))
        ));
        assert_eq!(
            store.begin(key(3, "message-3"), "three", 3),
            Ok(BeginOutcome::CapacityExceeded)
        );
        assert!(matches!(
            store.begin(key(3, "message-3"), "three", 12),
            Ok(BeginOutcome::Execute(_))
        ));
    }

    #[test]
    fn clear_removes_terminal_replay_evidence() {
        let mut store = TransactionReceiptStore::with_limits(60_000, 4, 4);
        let ticket = match store.begin(key(1, "message-1"), "frame", 1) {
            Ok(BeginOutcome::Execute(ticket)) => ticket,
            other => panic!("unexpected admission: {other:?}"),
        };
        store.finish(ticket, false, 2).expect("finish receipt");
        store.clear();
        assert!(matches!(
            store.begin(key(1, "message-1"), "frame", 3),
            Ok(BeginOutcome::Execute(_))
        ));
    }
}
