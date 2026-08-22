use super::storage::{RamGroupStateStorage, RamKeyPackageStorage};
use super::{
    canonical_fields, membership_digest, AbyssalError, KeyPackageSnapshot, MlsClient, MlsGroup,
    MAX_EPOCH_RETENTION, MAX_KEY_PACKAGES, MAX_KEY_PACKAGE_BYTES, MAX_REPLAY_IDS, MAX_STATE_BYTES,
    MAX_STATE_PLAINTEXT_BYTES, STATE_ENVELOPE_OVERHEAD_BYTES, STATE_ENVELOPE_VERSION, STATE_MAGIC,
    STATE_NONCE_BYTES,
};
use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use std::{collections::VecDeque, mem};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SealedRoomState {
    pub(super) current: Vec<u8>,
    pub(super) epochs: Vec<(u64, Vec<u8>)>,
    pub(super) key_packages: KeyPackageSnapshot,
    pub(super) issued_key_packages: Vec<Vec<u8>>,
    pub(super) revision: u64,
    pub(super) replay_ids: Vec<[u8; 32]>,
    pub(super) membership_digest: Vec<u8>,
}

impl Drop for SealedRoomState {
    fn drop(&mut self) {
        self.current.zeroize();
        for (_, bytes) in &mut self.epochs {
            bytes.zeroize();
        }
        for (id, bytes) in &mut self.key_packages {
            id.zeroize();
            bytes.zeroize();
        }
        for package in &mut self.issued_key_packages {
            package.zeroize();
        }
        for id in &mut self.replay_ids {
            id.zeroize();
        }
        self.membership_digest.zeroize();
    }
}

pub(super) struct MlsRoomState {
    pub(super) client: MlsClient,
    pub(super) group: Option<MlsGroup>,
    pub(super) storage: RamGroupStateStorage,
    pub(super) key_packages: RamKeyPackageStorage,
    pub(super) issued_key_packages: Vec<Vec<u8>>,
    pub(super) revision: u64,
    pub(super) pending: Option<PendingOutbound>,
    pub(super) replay_ids: VecDeque<[u8; 32]>,
    pub(super) closed: bool,
}

pub(super) struct PendingOutbound {
    pub(super) message_id: String,
    pub(super) revision: u64,
    pub(super) before: SealedRoomState,
    pub(super) post_envelope: Vec<u8>,
    pub(super) from_epoch: u64,
    pub(super) to_epoch: u64,
    pub(super) membership_digest: [u8; 32],
    pub(super) replay_id: Option<[u8; 32]>,
}

impl MlsRoomState {
    pub(super) fn close(&mut self) {
        self.closed = true;
        self.group.take();
        self.storage.wipe();
        self.key_packages.wipe();
        self.issued_key_packages.zeroize();
        if let Some(mut pending) = self.pending.take() {
            pending.message_id.zeroize();
            pending.post_envelope.zeroize();
            pending.membership_digest.zeroize();
            pending.replay_id.zeroize();
        }
        while let Some(mut replay_id) = self.replay_ids.pop_front() {
            replay_id.zeroize();
        }
    }

    pub(super) fn group_snapshot(&mut self) -> Result<Vec<u8>, AbyssalError> {
        let group = self
            .group
            .as_mut()
            .ok_or_else(|| AbyssalError::from("Room unavailable".to_string()))?;
        group
            .write_to_storage()
            .map_err(|_| AbyssalError::from("Room unavailable".to_string()))?;
        self.storage
            .snapshot(group.group_id())
            .map_err(AbyssalError::from)
    }

    pub(super) fn restore_sealed_snapshot(
        &mut self,
        group_id: &[u8],
        mut snapshot: SealedRoomState,
    ) -> Result<(), AbyssalError> {
        let current = mem::take(&mut snapshot.current);
        let epochs = mem::take(&mut snapshot.epochs);
        let key_packages = mem::take(&mut snapshot.key_packages);
        let issued_key_packages = mem::take(&mut snapshot.issued_key_packages);
        let replay_ids = mem::take(&mut snapshot.replay_ids);
        let expected_digest = mem::take(&mut snapshot.membership_digest);
        let has_current = !current.is_empty();
        if has_current {
            self.storage
                .put_snapshot(group_id.to_vec(), current)
                .map_err(AbyssalError::from)?;
            self.storage
                .put_epochs(group_id.to_vec(), epochs)
                .map_err(AbyssalError::from)?;
        } else if !epochs.is_empty() {
            return Err("Room unavailable".to_string().into());
        }
        self.key_packages
            .restore(key_packages)
            .map_err(AbyssalError::from)?;
        self.issued_key_packages = issued_key_packages;
        self.revision = snapshot.revision;
        self.replay_ids = replay_ids.into_iter().collect();
        if !has_current {
            if !expected_digest.is_empty() {
                return Err("Room unavailable".to_string().into());
            }
            self.group = None;
        } else {
            if expected_digest.len() != 32 {
                return Err("Room unavailable".to_string().into());
            }
            let group = self
                .client
                .load_group(group_id)
                .map_err(|_| AbyssalError::from("Room unavailable".to_string()))?;
            if membership_digest(&group).map_err(AbyssalError::from)? != expected_digest.as_slice()
            {
                return Err("Room unavailable".to_string().into());
            }
            self.group = Some(group);
        }
        Ok(())
    }

    pub(super) fn sealed_snapshot(&mut self) -> Result<SealedRoomState, AbyssalError> {
        let (current, epochs) = if let Some(group) = self.group.as_ref() {
            let group_id = group.group_id().to_vec();
            let current = self.group_snapshot()?;
            let epochs = self
                .storage
                .snapshot_epochs(&group_id)
                .map_err(AbyssalError::from)?;
            (current, epochs)
        } else {
            (Vec::new(), Vec::new())
        };
        let key_packages = self.key_packages.snapshot().map_err(AbyssalError::from)?;
        let membership_digest = self
            .group
            .as_ref()
            .map(membership_digest)
            .transpose()
            .map_err(AbyssalError::from)?
            .map(|digest| digest.to_vec())
            .unwrap_or_default();
        if self.replay_ids.len() > MAX_REPLAY_IDS {
            return Err("Room unavailable".to_string().into());
        }
        Ok(SealedRoomState {
            current,
            epochs,
            key_packages,
            issued_key_packages: self.issued_key_packages.clone(),
            revision: self.revision,
            replay_ids: self.replay_ids.iter().copied().collect(),
            membership_digest,
        })
    }

    pub(super) fn commit_replay_id(&mut self, replay_id: [u8; 32]) -> Result<(), AbyssalError> {
        if self.replay_ids.len() > MAX_REPLAY_IDS || self.replay_ids.contains(&replay_id) {
            return Err("Room unavailable".to_string().into());
        }
        if self.replay_ids.len() == MAX_REPLAY_IDS {
            let mut evicted = self
                .replay_ids
                .pop_front()
                .ok_or_else(|| AbyssalError::from("Room unavailable".to_string()))?;
            evicted.zeroize();
        }
        self.replay_ids.push_back(replay_id);
        Ok(())
    }
}

impl SealedRoomState {
    pub(super) fn append_replay_id(&mut self, replay_id: [u8; 32]) -> Result<(), AbyssalError> {
        if self.replay_ids.len() > MAX_REPLAY_IDS || self.replay_ids.contains(&replay_id) {
            return Err("Room unavailable".to_string().into());
        }
        if self.replay_ids.len() == MAX_REPLAY_IDS {
            let mut evicted = self.replay_ids.remove(0);
            evicted.zeroize();
        }
        self.replay_ids.push(replay_id);
        Ok(())
    }
}

pub(super) fn derive_state_key(
    root: &[u8; 32],
    username: &str,
    room_id: &str,
    node_context: &[u8],
    stable: &[u8; 64],
    group_id: &[u8; 32],
) -> Result<[u8; 32], String> {
    let mut key = [0_u8; 32];
    let context = canonical_fields(
        b"ABYSSAL-MLS-V10-STATE",
        &[
            username.as_bytes(),
            room_id.as_bytes(),
            node_context,
            stable,
            group_id,
        ],
    )?;
    Hkdf::<Sha256>::new(Some(b"ABYSSAL-MLS-V10-STATE"), root)
        .expand(&context, &mut key)
        .map_err(|_| "Identity unavailable".to_string())?;
    Ok(key)
}

pub(super) fn seal_state(
    key: &[u8; 32],
    username: &str,
    room_id: &str,
    node_context: &[u8],
    stable: &[u8; 64],
    group_id: &[u8],
    state: &[u8],
) -> Result<Vec<u8>, String> {
    if group_id.len() != 32 || state.is_empty() || state.len() > MAX_STATE_PLAINTEXT_BYTES {
        return Err("Room unavailable".to_string());
    }
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| "Room unavailable".to_string())?;
    let mut nonce = [0_u8; STATE_NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);
    let aad = canonical_fields(
        STATE_MAGIC,
        &[
            &[STATE_ENVELOPE_VERSION],
            username.as_bytes(),
            room_id.as_bytes(),
            node_context,
            stable,
            group_id,
        ],
    )?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: state,
                aad: &aad,
            },
        )
        .map_err(|_| "Room unavailable".to_string())?;
    let mut out = Vec::with_capacity(1 + group_id.len() + nonce.len() + ciphertext.len());
    out.push(STATE_ENVELOPE_VERSION);
    out.extend_from_slice(group_id);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    if out.len() != state.len() + STATE_ENVELOPE_OVERHEAD_BYTES || out.len() > MAX_STATE_BYTES {
        return Err("Room unavailable".to_string());
    }
    Ok(out)
}

pub(super) fn open_state(
    root: &[u8; 32],
    username: &str,
    room_id: &str,
    node_context: &[u8],
    stable: &[u8; 64],
    envelope: &[u8],
) -> Result<(Vec<u8>, SealedRoomState), String> {
    if envelope.len() <= 1 + 32 + STATE_NONCE_BYTES
        || envelope.len() > MAX_STATE_BYTES
        || envelope[0] != STATE_ENVELOPE_VERSION
    {
        return Err("Room unavailable".to_string());
    }
    let group_id = &envelope[1..33];
    let key = derive_state_key(
        root,
        username,
        room_id,
        node_context,
        stable,
        group_id
            .try_into()
            .map_err(|_| "Room unavailable".to_string())?,
    )?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(&key).map_err(|_| "Room unavailable".to_string())?;
    let aad = canonical_fields(
        STATE_MAGIC,
        &[
            &[STATE_ENVELOPE_VERSION],
            username.as_bytes(),
            room_id.as_bytes(),
            node_context,
            stable,
            group_id,
        ],
    )?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&envelope[33..33 + STATE_NONCE_BYTES]),
                chacha20poly1305::aead::Payload {
                    msg: &envelope[33 + STATE_NONCE_BYTES..],
                    aad: &aad,
                },
            )
            .map_err(|_| "Room unavailable".to_string())?,
    );
    if plain.is_empty() || plain.len() > MAX_STATE_PLAINTEXT_BYTES {
        return Err("Room unavailable".to_string());
    }
    let mut decoder = serde_json::Deserializer::from_slice(&plain);
    let state = <SealedRoomState as serde::Deserialize>::deserialize(&mut decoder)
        .map_err(|_| "Room unavailable".to_string())?;
    decoder.end().map_err(|_| "Room unavailable".to_string())?;
    validate_sealed_state(&state)?;
    Ok((group_id.to_vec(), state))
}

pub(super) fn validate_sealed_state(state: &SealedRoomState) -> Result<(), String> {
    let aggregate = state.current.len()
        + state
            .epochs
            .iter()
            .map(|(_, bytes)| bytes.len())
            .sum::<usize>()
        + state
            .key_packages
            .iter()
            .map(|(id, bytes)| id.len() + bytes.len())
            .sum::<usize>()
        + state
            .issued_key_packages
            .iter()
            .map(Vec::len)
            .sum::<usize>()
        + state.membership_digest.len()
        + state.replay_ids.len() * 32;
    let pending_shape = state.current.is_empty()
        && state.epochs.is_empty()
        && (!state.key_packages.is_empty() || !state.issued_key_packages.is_empty())
        && state.revision == 0
        && state.membership_digest.is_empty();
    if (state.current.is_empty() && !pending_shape)
        || (!state.current.is_empty() && state.membership_digest.len() != 32)
        || aggregate > MAX_STATE_BYTES
        || state.epochs.len() > MAX_EPOCH_RETENTION
        || state.key_packages.len() > MAX_KEY_PACKAGES
        || state.replay_ids.len() > MAX_REPLAY_IDS
        || state
            .epochs
            .iter()
            .any(|(_, bytes)| bytes.is_empty() || bytes.len() > MAX_STATE_BYTES)
        || state.key_packages.iter().any(|(id, bytes)| {
            id.is_empty()
                || id.len() > 128
                || bytes.is_empty()
                || bytes.len() > MAX_KEY_PACKAGE_BYTES
        })
        || state.issued_key_packages.len() > MAX_KEY_PACKAGES
        || state
            .issued_key_packages
            .iter()
            .any(|bytes| bytes.is_empty() || bytes.len() > MAX_KEY_PACKAGE_BYTES)
    {
        return Err("Room unavailable".to_string());
    }
    let mut ids = std::collections::HashSet::new();
    if state.key_packages.iter().any(|(id, _)| !ids.insert(id)) {
        return Err("Room unavailable".to_string());
    }
    Ok(())
}
