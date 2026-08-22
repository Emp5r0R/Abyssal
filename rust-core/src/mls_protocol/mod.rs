//! Protocol-v10 MLS room adapter.
//!
//! The adapter deliberately keeps MLS implementation types private.  Only
//! bounded byte records cross the FFI boundary, and all state storage is
//! process memory.  Direct-message Olm state is implemented in
//! `secure_protocol`; this module is room-only and never falls back to it.

use crate::{secure_protocol::AccountLifetime, AbyssalError};
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use mls_rs::mls_rs_codec::MlsDecode;
use mls_rs::{
    client_builder::{
        BaseConfig, IntoConfigOutput, WithCryptoProvider, WithGroupStateStorage,
        WithIdentityProvider, WithKeyPackageRepo,
    },
    crypto::{SignaturePublicKey, SignatureSecretKey},
    group::{CommitEffect, ReceivedMessage},
    identity::{Credential, CredentialType, CustomCredential, SigningIdentity},
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList, Group, MlsMessage,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    mem,
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex},
};
use zeroize::{Zeroize, Zeroizing};

mod identity;
mod state;
mod storage;
#[cfg(test)]
mod tests;
#[cfg(target_arch = "wasm32")]
mod wasm;

#[cfg(target_arch = "wasm32")]
pub(crate) use wasm::{parse_roster_json, WasmMlsRoom};

pub(crate) use identity::{credential_transcript, mls_public_for_root};
use identity::{encode_credential, parse_credential, AbyssalIdentityProvider};
use state::{
    derive_state_key, open_state, seal_state, MlsRoomState, PendingOutbound, SealedRoomState,
};
use storage::{RamGroupStateStorage, RamKeyPackageStorage};

pub const MLS_PROTOCOL_VERSION: u32 = 10;
pub const MLS_CIPHERSUITE: CipherSuite = CipherSuite::CURVE25519_CHACHA;
pub const MAX_ROOM_ID_BYTES: usize = 128;
pub const MAX_MEMBERS: usize = 117;
pub const MAX_KEY_PACKAGE_BYTES: usize = 64 * 1024;
pub const MAX_CONTROL_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_APPLICATION_PLAINTEXT_BYTES: usize = 768 * 1024;
pub const MAX_APPLICATION_CIPHERTEXT_BYTES: usize = 1024 * 1024;
pub const MAX_STATE_BYTES: usize = 4 * 1024 * 1024;
// Version, group id, XChaCha nonce, and Poly1305 tag are part of the relay
// bounded envelope and must fit inside MAX_STATE_BYTES as well.
pub const STATE_ENVELOPE_OVERHEAD_BYTES: usize = 1 + 32 + 24 + 16;
pub const MAX_STATE_PLAINTEXT_BYTES: usize = MAX_STATE_BYTES - STATE_ENVELOPE_OVERHEAD_BYTES;
pub const MAX_REPLAY_IDS: usize = 2048;
const MAX_EPOCH_RETENTION: usize = 3;
const MAX_KEY_PACKAGES: usize = 16;
const STATE_ENVELOPE_VERSION: u8 = 1;
const STATE_NONCE_BYTES: usize = 24;
const CREDENTIAL_TYPE: CredentialType = CredentialType::new(0xA510);
const CREDENTIAL_MAGIC: &[u8] = b"ABYSSAL-MLS-CREDENTIAL";
const STATE_MAGIC: &[u8] = b"ABYSSAL-MLS-STATE-V10";
const COMMIT_AAD_MAGIC: &[u8] = b"ABYSSAL-MLS-COMMIT-AAD-V10";
const MEMBERSHIP_REPLAY_DOMAIN: &[u8] = b"membership";
const APPLICATION_REPLAY_DOMAIN: &[u8] = b"application";

type MlsKeyConfig = WithKeyPackageRepo<RamKeyPackageStorage, BaseConfig>;
type MlsIdentityConfig = WithIdentityProvider<AbyssalIdentityProvider, MlsKeyConfig>;
type MlsCryptoConfig = WithCryptoProvider<RustCryptoProvider, MlsIdentityConfig>;
type MlsStorageConfig = WithGroupStateStorage<RamGroupStateStorage, MlsCryptoConfig>;
type MlsClientConfig = IntoConfigOutput<MlsStorageConfig>;
type MlsClient = Client<MlsClientConfig>;
type MlsGroup = Group<MlsClientConfig>;
type KeyPackageSnapshot = Vec<(Vec<u8>, Vec<u8>)>;

struct MlsRoomStateGuard<'a> {
    _lifetime: std::sync::RwLockReadGuard<'a, ()>,
    state: std::sync::MutexGuard<'a, MlsRoomState>,
}

impl Deref for MlsRoomStateGuard<'_> {
    type Target = MlsRoomState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl DerefMut for MlsRoomStateGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.state
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MlsRoomInfo {
    pub room_id: String,
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub member_count: u32,
    pub revision: u64,
    pub membership_digest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MlsCommit {
    pub message_id: String,
    pub revision: u64,
    pub group_id: Vec<u8>,
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub from_membership_digest: Vec<u8>,
    pub membership_digest: Vec<u8>,
    pub roster: Vec<MlsRosterMember>,
    pub state_envelope: Vec<u8>,
    pub authenticated_data: Vec<u8>,
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MlsRosterMember {
    pub username: String,
    pub stable_identity: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MlsApplicationMessage {
    pub message_id: String,
    pub plaintext: Vec<u8>,
    pub sender_index: u32,
    pub epoch: u64,
    pub group_id: Vec<u8>,
    pub membership_digest: Vec<u8>,
    pub revision: u64,
    pub state_envelope: Vec<u8>,
    pub authenticated_data: Vec<u8>,
}

#[derive(Debug, uniffi::Object)]
pub struct MlsProcessedControl {
    pub room_id: String,
    pub message_id: String,
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub member_count: u32,
    pub revision: u64,
    pub membership_digest: Vec<u8>,
    pub state_envelope: Vec<u8>,
}

#[uniffi::export]
impl MlsProcessedControl {
    pub fn room_id(&self) -> String {
        self.room_id.clone()
    }
    pub fn message_id(&self) -> String {
        self.message_id.clone()
    }
    pub fn group_id(&self) -> Vec<u8> {
        self.group_id.clone()
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn member_count(&self) -> u32 {
        self.member_count
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn membership_digest(&self) -> Vec<u8> {
        self.membership_digest.clone()
    }
    pub fn state_envelope(&self) -> Vec<u8> {
        self.state_envelope.clone()
    }
}

impl Drop for MlsProcessedControl {
    fn drop(&mut self) {
        self.room_id.zeroize();
        self.message_id.zeroize();
        self.group_id.zeroize();
        self.membership_digest.zeroize();
        self.state_envelope.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MlsEncryptedApplication {
    pub message_id: String,
    pub revision: u64,
    pub ciphertext: Vec<u8>,
    pub state_envelope: Vec<u8>,
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub membership_digest: Vec<u8>,
    pub sender_index: u32,
    pub authenticated_data: Vec<u8>,
}

#[derive(uniffi::Object)]
pub struct MlsRoom {
    username: String,
    node_context: Vec<u8>,
    room_id: String,
    group_id: Vec<u8>,
    stable_identity: [u8; 64],
    state_key: Zeroizing<[u8; 32]>,
    account_lifetime: Arc<AccountLifetime>,
    state: Mutex<MlsRoomState>,
}

impl MlsRoom {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_from_account(
        root: &[u8; 32],
        account_lifetime: Arc<AccountLifetime>,
        room_id: String,
        username: String,
        node_context: Vec<u8>,
        stable_identity: Vec<u8>,
        credential_signature: Vec<u8>,
        group_id: Vec<u8>,
    ) -> Result<Arc<Self>, AbyssalError> {
        let stable = parse_stable_identity(&stable_identity).map_err(AbyssalError::from)?;
        validate_room_id(&room_id).map_err(AbyssalError::from)?;
        let username = canonical_username(&username).map_err(AbyssalError::from)?;
        let node_context = validate_node_context(&node_context).map_err(AbyssalError::from)?;
        let group_id = parse_group_id(&group_id).map_err(AbyssalError::from)?;
        let mls_public = mls_public_for_root(root, &username, &node_context, &room_id, &group_id)
            .map_err(AbyssalError::from)?;
        let transcript = credential_transcript(
            &username,
            &room_id,
            &node_context,
            &group_id,
            &stable,
            &mls_public,
        )
        .map_err(AbyssalError::from)?;
        verify_stable_signature(&stable, &transcript, &credential_signature)
            .map_err(AbyssalError::from)?;
        Self::new_room(
            root,
            account_lifetime,
            room_id,
            username,
            node_context,
            stable,
            credential_signature,
            group_id.to_vec(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn recover_from_account(
        root: &[u8; 32],
        account_lifetime: Arc<AccountLifetime>,
        room_id: String,
        username: String,
        node_context: Vec<u8>,
        stable_identity: Vec<u8>,
        credential_signature: Vec<u8>,
        group_id: Vec<u8>,
        envelope: Vec<u8>,
        expected_active: bool,
        expected_epoch: u64,
        expected_revision: u64,
        expected_members: Vec<MlsRosterMember>,
        expected_digest: Vec<u8>,
    ) -> Result<Arc<Self>, AbyssalError> {
        let stable = parse_stable_identity(&stable_identity).map_err(AbyssalError::from)?;
        validate_room_id(&room_id).map_err(AbyssalError::from)?;
        let username = canonical_username(&username).map_err(AbyssalError::from)?;
        let node_context = validate_node_context(&node_context).map_err(AbyssalError::from)?;
        let expected_group_id = parse_group_id(&group_id).map_err(AbyssalError::from)?;
        let mls_public =
            mls_public_for_root(root, &username, &node_context, &room_id, &expected_group_id)
                .map_err(AbyssalError::from)?;
        let transcript = credential_transcript(
            &username,
            &room_id,
            &node_context,
            &expected_group_id,
            &stable,
            &mls_public,
        )
        .map_err(AbyssalError::from)?;
        verify_stable_signature(&stable, &transcript, &credential_signature)
            .map_err(AbyssalError::from)?;
        let (group_id, mut state_bytes) =
            open_state(root, &username, &room_id, &node_context, &stable, &envelope)
                .map_err(AbyssalError::from)?;
        if group_id != expected_group_id {
            return Err("Room unavailable".to_string().into());
        }
        if state_bytes.revision != expected_revision
            || (!expected_active
                && (expected_epoch != 0
                    || !expected_members.is_empty()
                    || !expected_digest.is_empty()
                    || !state_bytes.current.is_empty()))
            || (expected_active
                && (state_bytes.current.is_empty()
                    || expected_members.is_empty()
                    || expected_members.len() > MAX_MEMBERS
                    || expected_digest.len() != 32
                    || state_bytes.membership_digest != expected_digest))
        {
            return Err("Room unavailable".to_string().into());
        }
        let expected_digest_array: [u8; 32] = if expected_active {
            expected_digest
                .as_slice()
                .try_into()
                .map_err(|_| AbyssalError::from("Room unavailable".to_string()))?
        } else {
            [0_u8; 32]
        };
        let room = Self::new_pending(
            root,
            account_lifetime,
            room_id,
            username,
            node_context,
            stable,
            credential_signature,
            group_id,
        )?;
        {
            let mut state = room
                .state
                .lock()
                .map_err(|_| AbyssalError::from("Room unavailable".to_string()))?;
            let current = mem::take(&mut state_bytes.current);
            let has_current = !current.is_empty();
            let epochs = mem::take(&mut state_bytes.epochs);
            let key_packages = mem::take(&mut state_bytes.key_packages);
            let issued_key_packages = mem::take(&mut state_bytes.issued_key_packages);
            let replay_ids = mem::take(&mut state_bytes.replay_ids);
            let expected_digest = mem::take(&mut state_bytes.membership_digest);
            if has_current {
                state
                    .storage
                    .put_snapshot(room.group_id.clone(), current)
                    .map_err(AbyssalError::from)?;
                state
                    .storage
                    .put_epochs(room.group_id.clone(), epochs)
                    .map_err(AbyssalError::from)?;
            } else if !epochs.is_empty() {
                return Err("Room unavailable".to_string().into());
            }
            state
                .key_packages
                .restore(key_packages)
                .map_err(AbyssalError::from)?;
            state.issued_key_packages = issued_key_packages;
            state.revision = state_bytes.revision;
            state.replay_ids = replay_ids.into_iter().collect();
            if has_current {
                if expected_digest.len() != 32 {
                    return Err("Room unavailable".to_string().into());
                }
                let group = state
                    .client
                    .load_group(&room.group_id)
                    .map_err(|_| AbyssalError::from("Room unavailable".to_string()))?;
                if membership_digest(&group).map_err(AbyssalError::from)?
                    != expected_digest_array.as_slice()
                {
                    return Err("Room unavailable".to_string().into());
                }
                if !expected_active
                    || group.current_epoch() != expected_epoch
                    || verify_group_directory(
                        &group,
                        &room.room_id,
                        &room.node_context,
                        &room.group_id,
                        &expected_members,
                        &expected_digest_array,
                    )
                    .is_err()
                {
                    return Err("Room unavailable".to_string().into());
                }
                state.group = Some(group);
                validate_group_context(
                    state.group.as_ref().expect("group assigned"),
                    &room.room_id,
                    &room.node_context,
                    &room.group_id,
                )
                .map_err(AbyssalError::from)?;
            } else if expected_active || expected_digest_array != [0_u8; 32] {
                return Err("Room unavailable".to_string().into());
            }
        }
        Ok(room)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn pending_from_account(
        root: &[u8; 32],
        account_lifetime: Arc<AccountLifetime>,
        room_id: String,
        username: String,
        node_context: Vec<u8>,
        stable_identity: Vec<u8>,
        credential_signature: Vec<u8>,
        group_id: Vec<u8>,
    ) -> Result<Arc<Self>, AbyssalError> {
        let stable = parse_stable_identity(&stable_identity).map_err(AbyssalError::from)?;
        validate_room_id(&room_id).map_err(AbyssalError::from)?;
        let username = canonical_username(&username).map_err(AbyssalError::from)?;
        let node_context = validate_node_context(&node_context).map_err(AbyssalError::from)?;
        let group_id = parse_group_id(&group_id).map_err(AbyssalError::from)?;
        let mls_public = mls_public_for_root(root, &username, &node_context, &room_id, &group_id)
            .map_err(AbyssalError::from)?;
        let transcript = credential_transcript(
            &username,
            &room_id,
            &node_context,
            &group_id,
            &stable,
            &mls_public,
        )
        .map_err(AbyssalError::from)?;
        verify_stable_signature(&stable, &transcript, &credential_signature)
            .map_err(AbyssalError::from)?;
        Self::new_pending(
            root,
            account_lifetime,
            room_id,
            username,
            node_context,
            stable,
            credential_signature,
            group_id.to_vec(),
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create(
        export_key: Vec<u8>,
        room_id: String,
        username: String,
        node_context: Vec<u8>,
        stable_identity: Vec<u8>,
        group_id: Vec<u8>,
        credential_signature: Vec<u8>,
    ) -> Result<Arc<Self>, AbyssalError> {
        let root: [u8; 32] = export_key
            .as_slice()
            .try_into()
            .map_err(|_| AbyssalError::from("Identity unavailable".to_string()))?;
        Self::create_from_account(
            &root,
            AccountLifetime::new(),
            room_id,
            username,
            node_context,
            stable_identity,
            credential_signature,
            group_id,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn recover(
        export_key: Vec<u8>,
        room_id: String,
        username: String,
        node_context: Vec<u8>,
        stable_identity: Vec<u8>,
        group_id: Vec<u8>,
        credential_signature: Vec<u8>,
        envelope: Vec<u8>,
        expected_active: bool,
        expected_epoch: u64,
        expected_revision: u64,
        expected_members: Vec<MlsRosterMember>,
        expected_digest: Vec<u8>,
    ) -> Result<Arc<Self>, AbyssalError> {
        let root: [u8; 32] = export_key
            .as_slice()
            .try_into()
            .map_err(|_| AbyssalError::from("Identity unavailable".to_string()))?;
        Self::recover_from_account(
            &root,
            AccountLifetime::new(),
            room_id,
            username,
            node_context,
            stable_identity,
            credential_signature,
            group_id,
            envelope,
            expected_active,
            expected_epoch,
            expected_revision,
            expected_members,
            expected_digest,
        )
    }

    #[cfg(test)]
    pub(crate) fn pending_join(
        export_key: Vec<u8>,
        room_id: String,
        username: String,
        node_context: Vec<u8>,
        stable_identity: Vec<u8>,
        group_id: Vec<u8>,
        credential_signature: Vec<u8>,
    ) -> Result<Arc<Self>, AbyssalError> {
        let root: [u8; 32] = export_key
            .as_slice()
            .try_into()
            .map_err(|_| AbyssalError::from("Identity unavailable".to_string()))?;
        Self::pending_from_account(
            &root,
            AccountLifetime::new(),
            room_id,
            username,
            node_context,
            stable_identity,
            credential_signature,
            group_id,
        )
    }
}

#[uniffi::export]
impl MlsRoom {
    pub fn room_info(&self) -> Result<MlsRoomInfo, AbyssalError> {
        let state = self.lock_state()?;
        if state.closed {
            return Err("Room unavailable".to_string().into());
        }
        let (epoch, member_count, membership_digest) = match state.group.as_ref() {
            Some(group) => (
                group.current_epoch(),
                group.roster().members_iter().count() as u32,
                membership_digest(group)
                    .map_err(AbyssalError::from)?
                    .to_vec(),
            ),
            None => (0, 0, Vec::new()),
        };
        Ok(MlsRoomInfo {
            room_id: self.room_id.clone(),
            group_id: self.group_id.clone(),
            epoch,
            member_count,
            revision: state.revision,
            membership_digest,
        })
    }

    pub fn key_package(&self) -> Result<Vec<u8>, AbyssalError> {
        let mut state = self.lock_state_mut()?;
        if state.closed {
            return Err("Room unavailable".to_string().into());
        }
        let message = state
            .client
            .generate_key_package_message(ExtensionList::default(), ExtensionList::default(), None)
            .map_err(|_| AbyssalError::from("Room unavailable".to_string()))?;
        let encoded = message
            .to_bytes()
            .map_err(|_| AbyssalError::from("Room unavailable".to_string()))?;
        let encoded = bounded_bytes(encoded, MAX_KEY_PACKAGE_BYTES, "Room unavailable")?;
        if state.issued_key_packages.len() >= MAX_KEY_PACKAGES
            || state
                .issued_key_packages
                .iter()
                .map(Vec::len)
                .sum::<usize>()
                + encoded.len()
                > MAX_STATE_BYTES
        {
            return Err("Room unavailable".to_string().into());
        }
        state.issued_key_packages.push(encoded.clone());
        Ok(encoded)
    }

    /// Add a member. MLS state is advanced locally and held behind an exact
    /// outbound checkpoint until the relay acknowledges the same revision.
    pub fn add_member(
        &self,
        key_package: Vec<u8>,
        expected_username: String,
        expected_stable_identity: Vec<u8>,
        message_id: String,
    ) -> Result<MlsCommit, AbyssalError> {
        let expected =
            parse_stable_identity(&expected_stable_identity).map_err(AbyssalError::from)?;
        let expected_username =
            canonical_username(&expected_username).map_err(AbyssalError::from)?;
        validate_message_id(&message_id).map_err(AbyssalError::from)?;
        let key_package = bounded_bytes(key_package, MAX_KEY_PACKAGE_BYTES, "Room unavailable")?;
        let mut state = self.lock_state_mut()?;
        if state.closed || state.pending.is_some() || state.revision == u64::MAX {
            return Err("Room unavailable".to_string().into());
        }
        verify_key_package_directory(
            &key_package,
            &expected_username,
            &self.room_id,
            &self.node_context,
            &self.group_id,
            &expected,
        )
        .map_err(AbyssalError::from)?;
        // Capture the reusable checkpoint before MLS builds a pending commit.
        // The builder mutates group state even though the commit is still
        // transactional from the relay's perspective.
        let before = state.sealed_snapshot()?;
        let (authenticated_data, output) = {
            let group = state
                .group
                .as_mut()
                .ok_or_else(|| AbyssalError::from("Room unavailable".to_string()))?;
            if group.roster().members_iter().count() >= MAX_MEMBERS {
                return Err("Room unavailable".to_string().into());
            }
            if group.roster().members_iter().any(|member| {
                parse_credential(&member.signing_identity)
                    .map(|parts| {
                        parts.stable_identity == expected || parts.username == expected_username
                    })
                    .unwrap_or(false)
            }) {
                return Err("Room unavailable".to_string().into());
            }
            let from_epoch = group.current_epoch();
            let authenticated_data = commit_authenticated_data(
                &message_id,
                &self.room_id,
                &self.group_id,
                from_epoch,
                b"add",
                &expected_username,
                &expected,
            )
            .map_err(AbyssalError::from)?;
            let decoded_key_package = decode_complete_message(&key_package, "Room unavailable")?;
            let output = group
                .commit_builder()
                .add_member(decoded_key_package)
                .map(|builder| builder.authenticated_data(authenticated_data.clone()))
                .and_then(|builder| builder.build())
                .map_err(|_| AbyssalError::from("Room unavailable".to_string()));
            (authenticated_data, output)
        };
        let output = match output {
            Ok(output) => output,
            Err(error) => {
                if state
                    .restore_sealed_snapshot(&self.group_id, before.clone())
                    .is_err()
                {
                    state.close();
                }
                return Err(error);
            }
        };
        let commit = match output.commit_message.to_bytes() {
            Ok(commit) => commit,
            Err(_) => {
                if state
                    .restore_sealed_snapshot(&self.group_id, before.clone())
                    .is_err()
                {
                    state.close();
                }
                return Err("Room unavailable".to_string().into());
            }
        };
        let welcome = match output.welcome_messages.first() {
            Some(welcome) => match welcome.to_bytes() {
                Ok(welcome) => welcome,
                Err(_) => {
                    if state
                        .restore_sealed_snapshot(&self.group_id, before.clone())
                        .is_err()
                    {
                        state.close();
                    }
                    return Err("Room unavailable".to_string().into());
                }
            },
            None => {
                if state
                    .restore_sealed_snapshot(&self.group_id, before.clone())
                    .is_err()
                {
                    state.close();
                }
                return Err("Room unavailable".to_string().into());
            }
        };
        if commit.len() > MAX_CONTROL_BYTES || welcome.len() > MAX_CONTROL_BYTES {
            if state
                .restore_sealed_snapshot(&self.group_id, before.clone())
                .is_err()
            {
                state.close();
            }
            return Err("Room unavailable".to_string().into());
        }
        self.stage_membership_commit(
            &mut state,
            before,
            message_id,
            commit,
            welcome,
            authenticated_data,
        )
    }

    /// Remove a member by its expected stable identity, never by a caller-
    /// supplied mutable leaf index.
    pub fn remove_member(
        &self,
        expected_username: String,
        expected_stable_identity: Vec<u8>,
        message_id: String,
    ) -> Result<MlsCommit, AbyssalError> {
        let expected =
            parse_stable_identity(&expected_stable_identity).map_err(AbyssalError::from)?;
        let expected_username =
            canonical_username(&expected_username).map_err(AbyssalError::from)?;
        validate_message_id(&message_id).map_err(AbyssalError::from)?;
        let mut state = self.lock_state_mut()?;
        if state.closed || state.pending.is_some() || state.revision == u64::MAX {
            return Err("Room unavailable".to_string().into());
        }
        let before = state.sealed_snapshot()?;
        let (authenticated_data, output) = {
            let group = state
                .group
                .as_mut()
                .ok_or_else(|| AbyssalError::from("Room unavailable".to_string()))?;
            let matching: Vec<u32> = group
                .roster()
                .members_iter()
                .filter_map(|member| {
                    parse_credential(&member.signing_identity)
                        .ok()
                        .filter(|parts| {
                            parts.username == expected_username && parts.stable_identity == expected
                        })
                        .map(|_| member.index)
                })
                .collect();
            let [member_index] = matching.as_slice() else {
                return Err("Room unavailable".to_string().into());
            };
            let from_epoch = group.current_epoch();
            let authenticated_data = commit_authenticated_data(
                &message_id,
                &self.room_id,
                &self.group_id,
                from_epoch,
                b"remove",
                &expected_username,
                &expected,
            )
            .map_err(AbyssalError::from)?;
            let output = group
                .commit_builder()
                .remove_member(*member_index)
                .map(|builder| builder.authenticated_data(authenticated_data.clone()))
                .and_then(|builder| builder.build())
                .map_err(|_| AbyssalError::from("Room unavailable".to_string()));
            (authenticated_data, output)
        };
        let output = match output {
            Ok(output) => output,
            Err(error) => {
                if state
                    .restore_sealed_snapshot(&self.group_id, before.clone())
                    .is_err()
                {
                    state.close();
                }
                return Err(error);
            }
        };
        let commit = match output.commit_message.to_bytes() {
            Ok(commit) => commit,
            Err(_) => {
                if state
                    .restore_sealed_snapshot(&self.group_id, before.clone())
                    .is_err()
                {
                    state.close();
                }
                return Err("Room unavailable".to_string().into());
            }
        };
        if commit.len() > MAX_CONTROL_BYTES {
            if state
                .restore_sealed_snapshot(&self.group_id, before.clone())
                .is_err()
            {
                state.close();
            }
            return Err("Room unavailable".to_string().into());
        }
        self.stage_membership_commit(
            &mut state,
            before,
            message_id,
            commit,
            Vec::new(),
            authenticated_data,
        )
    }

    pub fn commit_outbound(&self, message_id: String, revision: u64) -> Result<(), AbyssalError> {
        let mut state = self.lock_state_mut()?;
        if state.closed
            || !state.pending.as_ref().is_some_and(|pending| {
                pending.message_id == message_id && pending.revision == revision
            })
        {
            return Err("Room unavailable".to_string().into());
        }
        let valid = state
            .group
            .as_ref()
            .map(|group| {
                group.current_epoch()
                    == state.pending.as_ref().map_or(0, |pending| pending.to_epoch)
                    && membership_digest(group).ok()
                        == state
                            .pending
                            .as_ref()
                            .map(|pending| pending.membership_digest)
            })
            .unwrap_or(false)
            && state.revision == revision
            && state.pending.as_ref().is_some_and(|pending| {
                !pending.post_envelope.is_empty() && pending.from_epoch <= pending.to_epoch
            });
        if !valid {
            state.close();
            return Err("Room unavailable".to_string().into());
        }
        if let Some(replay_id) = state.pending.as_ref().and_then(|pending| pending.replay_id) {
            if state.commit_replay_id(replay_id).is_err() {
                state.close();
                return Err("Room unavailable".to_string().into());
            }
        }
        if let Some(mut pending) = state.pending.take() {
            pending.message_id.zeroize();
            pending.post_envelope.zeroize();
            pending.membership_digest.zeroize();
            pending.replay_id.zeroize();
        }
        Ok(())
    }

    pub fn rollback_outbound(&self, message_id: String, revision: u64) -> Result<(), AbyssalError> {
        let mut state = self.lock_state_mut()?;
        if state.closed
            || !state.pending.as_ref().is_some_and(|pending| {
                pending.message_id == message_id && pending.revision == revision
            })
        {
            return Err("Room unavailable".to_string().into());
        }
        let pending = state
            .pending
            .take()
            .ok_or_else(|| AbyssalError::from("Room unavailable".to_string()))?;
        if state
            .restore_sealed_snapshot(&self.group_id, pending.before)
            .is_err()
        {
            state.close();
            return Err("Room unavailable".to_string().into());
        }
        Ok(())
    }

    pub fn join_welcome(
        &self,
        welcome: Vec<u8>,
        expected_members: Vec<MlsRosterMember>,
        expected_digest: Vec<u8>,
    ) -> Result<MlsRoomInfo, AbyssalError> {
        let welcome = bounded_bytes(welcome, MAX_CONTROL_BYTES, "Room unavailable")?;
        let expected_digest: [u8; 32] = expected_digest
            .try_into()
            .map_err(|_| AbyssalError::from("Room unavailable".to_string()))?;
        let mut state = self.lock_state_mut()?;
        if state.closed || state.group.is_some() || state.pending.is_some() {
            return Err("Room unavailable".to_string().into());
        }
        let (mut group, _) = state
            .client
            .join_group(
                None,
                &decode_complete_message(&welcome, "Room unavailable")?,
                None,
            )
            .map_err(|_| AbyssalError::from("Room unavailable".to_string()))?;
        if group.group_id() != self.group_id.as_slice() {
            return Err("Room unavailable".to_string().into());
        }
        verify_group_directory(
            &group,
            &self.room_id,
            &self.node_context,
            &self.group_id,
            &expected_members,
            &expected_digest,
        )
        .map_err(AbyssalError::from)?;
        group
            .write_to_storage()
            .map_err(|_| AbyssalError::from("Room unavailable".to_string()))?;
        state.group = Some(group);
        state.issued_key_packages.zeroize();
        state.issued_key_packages.clear();
        self.info_from_state(&state)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn process_control(
        &self,
        control: Vec<u8>,
        expected_from_epoch: u64,
        expected_to_epoch: u64,
        expected_members: Vec<MlsRosterMember>,
        expected_digest: Vec<u8>,
        message_id: String,
        expected_authenticated_data: Vec<u8>,
    ) -> Result<Arc<MlsProcessedControl>, AbyssalError> {
        let control = bounded_bytes(control, MAX_CONTROL_BYTES, "Room unavailable")?;
        validate_message_id(&message_id).map_err(AbyssalError::from)?;
        let expected_digest: [u8; 32] = expected_digest
            .try_into()
            .map_err(|_| AbyssalError::from("Room unavailable".to_string()))?;
        let replay_id = replay_digest_from_message_id(MEMBERSHIP_REPLAY_DOMAIN, &message_id);
        let expected_authenticated_data =
            bounded_bytes(expected_authenticated_data, 4096, "Room unavailable")?;
        let mut state = self.lock_state_mut()?;
        if state.closed || state.replay_ids.contains(&replay_id) || state.pending.is_some() {
            return Err("Room unavailable".to_string().into());
        }
        let group = state
            .group
            .as_ref()
            .ok_or_else(|| AbyssalError::from("Room unavailable".to_string()))?;
        let message = decode_complete_message(&control, "Room unavailable")?;
        if message.group_id() != Some(self.group_id.as_slice())
            || message.epoch() != Some(expected_from_epoch)
            || expected_from_epoch != group.current_epoch()
            || expected_to_epoch
                != expected_from_epoch
                    .checked_add(1)
                    .ok_or_else(|| AbyssalError::from("Room unavailable".to_string()))?
        {
            return Err("Room unavailable".to_string().into());
        }
        let snapshot = state.sealed_snapshot()?;
        let mut removed_self = false;
        let result = match state
            .group
            .as_mut()
            .expect("active checked")
            .process_incoming_message(message)
        {
            Ok(ReceivedMessage::Commit(description)) => {
                removed_self = matches!(&description.effect, CommitEffect::Removed { .. });
                let group = state.group.as_ref().expect("active checked");
                let epoch_ok = group.current_epoch() == expected_to_epoch;
                let verify = verify_group_directory(
                    group,
                    &self.room_id,
                    &self.node_context,
                    &self.group_id,
                    &expected_members,
                    &expected_digest,
                );
                let aad_ok = description.authenticated_data == expected_authenticated_data
                    && validate_commit_authenticated_data(
                        &expected_authenticated_data,
                        &message_id,
                        &self.room_id,
                        &self.group_id,
                        expected_from_epoch,
                    )
                    .is_ok();
                if !epoch_ok || verify.is_err() || !aad_ok {
                    Err("Room unavailable".to_string())
                } else {
                    Ok(())
                }
            }
            _ => Err("Room unavailable".to_string()),
        };
        if result.is_err()
            || state.revision == u64::MAX
            || state
                .group
                .as_mut()
                .expect("active checked")
                .write_to_storage()
                .is_err()
        {
            if removed_self {
                state.close();
                return Err("Room unavailable".to_string().into());
            }
            if state
                .restore_sealed_snapshot(&self.group_id, snapshot)
                .is_err()
            {
                state.close();
            }
            return Err("Room unavailable".to_string().into());
        }
        state.revision += 1;
        let digest = membership_digest(state.group.as_ref().expect("active checked"))
            .map_err(AbyssalError::from)?;
        // Include the accepted replay key in the emitted envelope, but keep
        // recording transactional until commit_outbound confirms relay
        // acceptance. Rollback restores the exact preflight snapshot.
        let mut post = state.sealed_snapshot()?;
        post.append_replay_id(replay_id)?;
        let post_json = Zeroizing::new(
            serde_json::to_vec(&post)
                .map_err(|_| AbyssalError::from("Room unavailable".to_string()))?,
        );
        let state_envelope = match seal_state(
            &self.state_key,
            &self.username,
            &self.room_id,
            &self.node_context,
            &self.stable_identity,
            &self.group_id,
            &post_json,
        ) {
            Ok(value) => value,
            Err(_) => {
                if state
                    .restore_sealed_snapshot(&self.group_id, snapshot)
                    .is_err()
                {
                    state.close();
                }
                return Err("Room unavailable".to_string().into());
            }
        };
        state.pending = Some(PendingOutbound {
            message_id: message_id.clone(),
            revision: state.revision,
            before: snapshot,
            post_envelope: state_envelope,
            from_epoch: expected_from_epoch,
            to_epoch: expected_to_epoch,
            membership_digest: digest,
            replay_id: Some(replay_id),
        });
        let info = self.info_from_state(&state)?;
        Ok(Arc::new(MlsProcessedControl {
            room_id: info.room_id,
            message_id,
            group_id: info.group_id,
            epoch: info.epoch,
            member_count: info.member_count,
            revision: info.revision,
            membership_digest: info.membership_digest,
            state_envelope: state
                .pending
                .as_ref()
                .ok_or_else(|| AbyssalError::from("Room unavailable".to_string()))?
                .post_envelope
                .clone(),
        }))
    }

    pub fn encrypt_application(
        &self,
        message_id: String,
        plaintext: Vec<u8>,
        authenticated_data: Vec<u8>,
    ) -> Result<MlsEncryptedApplication, AbyssalError> {
        validate_message_id(&message_id).map_err(AbyssalError::from)?;
        let plaintext = bounded_bytes(
            plaintext,
            MAX_APPLICATION_PLAINTEXT_BYTES,
            "Payload unavailable",
        )?;
        let authenticated_data = bounded_bytes(authenticated_data, 4096, "Payload unavailable")?;
        let mut state = self.lock_state_mut()?;
        if state.closed || state.pending.is_some() || state.group.is_none() {
            return Err("Payload unavailable".to_string().into());
        }
        let snapshot = state.sealed_snapshot()?;
        let epoch = state
            .group
            .as_ref()
            .expect("active checked")
            .current_epoch();
        let sender_index = self_member_index(
            state.group.as_ref().expect("active checked"),
            &self.stable_identity,
        )
        .map_err(AbyssalError::from)?;
        let result = state
            .group
            .as_mut()
            .expect("active checked")
            .encrypt_application_message(&plaintext, authenticated_data.clone())
            .and_then(|message| message.to_bytes())
            .map_err(|_| "Payload unavailable".to_string());
        let encoded = match result {
            Ok(encoded) if encoded.len() <= MAX_APPLICATION_CIPHERTEXT_BYTES => encoded,
            _ => {
                if state
                    .restore_sealed_snapshot(&self.group_id, snapshot.clone())
                    .is_err()
                {
                    state.close();
                }
                return Err("Payload unavailable".to_string().into());
            }
        };
        let storage_result = state
            .group
            .as_mut()
            .expect("active checked")
            .write_to_storage();
        if state.revision == u64::MAX || storage_result.is_err() {
            if state
                .restore_sealed_snapshot(&self.group_id, snapshot.clone())
                .is_err()
            {
                state.close();
            }
            return Err("Payload unavailable".to_string().into());
        }
        state.revision += 1;
        let digest = membership_digest(state.group.as_ref().expect("active checked"))
            .map_err(AbyssalError::from)?;
        let post = state.sealed_snapshot()?;
        let post_json = Zeroizing::new(
            serde_json::to_vec(&post)
                .map_err(|_| AbyssalError::from("Payload unavailable".to_string()))?,
        );
        let state_envelope = match seal_state(
            &self.state_key,
            &self.username,
            &self.room_id,
            &self.node_context,
            &self.stable_identity,
            &self.group_id,
            &post_json,
        ) {
            Ok(value) => value,
            Err(error) => {
                if state
                    .restore_sealed_snapshot(&self.group_id, snapshot.clone())
                    .is_err()
                {
                    state.close();
                }
                return Err(error.into());
            }
        };
        let revision = state.revision;
        state.pending = Some(PendingOutbound {
            message_id: message_id.clone(),
            revision,
            before: snapshot,
            post_envelope: state_envelope.clone(),
            from_epoch: state
                .group
                .as_ref()
                .expect("active checked")
                .current_epoch(),
            to_epoch: state
                .group
                .as_ref()
                .expect("active checked")
                .current_epoch(),
            membership_digest: digest,
            replay_id: None,
        });
        Ok(MlsEncryptedApplication {
            message_id,
            revision,
            ciphertext: encoded,
            state_envelope,
            group_id: self.group_id.clone(),
            epoch,
            membership_digest: digest.to_vec(),
            sender_index,
            authenticated_data,
        })
    }

    pub fn decrypt_application(
        &self,
        ciphertext: Vec<u8>,
        expected_epoch: u64,
        message_id: String,
        expected_authenticated_data: Vec<u8>,
    ) -> Result<MlsApplicationMessage, AbyssalError> {
        let ciphertext = bounded_bytes(
            ciphertext,
            MAX_APPLICATION_CIPHERTEXT_BYTES,
            "Payload unavailable",
        )?;
        validate_message_id(&message_id).map_err(AbyssalError::from)?;
        let replay_id = replay_digest_from_message_id(APPLICATION_REPLAY_DOMAIN, &message_id);
        let expected_authenticated_data =
            bounded_bytes(expected_authenticated_data, 4096, "Payload unavailable")?;
        let mut state = self.lock_state_mut()?;
        if state.closed
            || state.pending.is_some()
            || state.group.is_none()
            || state.replay_ids.contains(&replay_id)
        {
            return Err("Payload unavailable".to_string().into());
        }
        let message = decode_complete_message(&ciphertext, "Payload unavailable")?;
        if message.group_id() != Some(self.group_id.as_slice())
            || message.epoch() != Some(expected_epoch)
            || state
                .group
                .as_ref()
                .expect("active checked")
                .current_epoch()
                != expected_epoch
        {
            return Err("Payload unavailable".to_string().into());
        }
        let snapshot = state.sealed_snapshot()?;
        let received = match state
            .group
            .as_mut()
            .expect("active checked")
            .process_incoming_message(message)
        {
            Ok(received) => received,
            Err(_) => {
                if state
                    .restore_sealed_snapshot(&self.group_id, snapshot.clone())
                    .is_err()
                {
                    state.close();
                }
                return Err("Payload unavailable".to_string().into());
            }
        };
        let ReceivedMessage::ApplicationMessage(description) = received else {
            if state
                .restore_sealed_snapshot(&self.group_id, snapshot.clone())
                .is_err()
            {
                state.close();
            }
            return Err("Payload unavailable".to_string().into());
        };
        let sender_index = description.sender_index;
        if description.authenticated_data != expected_authenticated_data {
            if state
                .restore_sealed_snapshot(&self.group_id, snapshot.clone())
                .is_err()
            {
                state.close();
            }
            return Err("Payload unavailable".to_string().into());
        }
        let plaintext = description.data().to_vec();
        if plaintext.len() > MAX_APPLICATION_PLAINTEXT_BYTES
            || state.revision == u64::MAX
            || state
                .group
                .as_mut()
                .expect("active checked")
                .write_to_storage()
                .is_err()
        {
            if state
                .restore_sealed_snapshot(&self.group_id, snapshot.clone())
                .is_err()
            {
                state.close();
            }
            return Err("Payload unavailable".to_string().into());
        }
        state.revision += 1;
        let digest = membership_digest(state.group.as_ref().expect("active checked"))
            .map_err(AbyssalError::from)?;
        let mut post = state.sealed_snapshot()?;
        post.append_replay_id(replay_id)
            .map_err(|_| AbyssalError::from("Payload unavailable".to_string()))?;
        let post_json = Zeroizing::new(
            serde_json::to_vec(&post)
                .map_err(|_| AbyssalError::from("Payload unavailable".to_string()))?,
        );
        let state_envelope = match seal_state(
            &self.state_key,
            &self.username,
            &self.room_id,
            &self.node_context,
            &self.stable_identity,
            &self.group_id,
            &post_json,
        ) {
            Ok(value) => value,
            Err(_) => {
                if state
                    .restore_sealed_snapshot(&self.group_id, snapshot)
                    .is_err()
                {
                    state.close();
                }
                return Err("Payload unavailable".to_string().into());
            }
        };
        state.pending = Some(PendingOutbound {
            message_id: message_id.clone(),
            revision: state.revision,
            before: snapshot,
            post_envelope: state_envelope,
            from_epoch: expected_epoch,
            to_epoch: expected_epoch,
            membership_digest: digest,
            replay_id: Some(replay_id),
        });
        Ok(MlsApplicationMessage {
            message_id,
            plaintext,
            sender_index,
            epoch: expected_epoch,
            group_id: self.group_id.clone(),
            membership_digest: digest.to_vec(),
            revision: state.revision,
            state_envelope: state
                .pending
                .as_ref()
                .ok_or_else(|| AbyssalError::from("Payload unavailable".to_string()))?
                .post_envelope
                .clone(),
            authenticated_data: expected_authenticated_data,
        })
    }

    pub fn seal_state(&self) -> Result<Vec<u8>, AbyssalError> {
        let mut state = self.lock_state_mut()?;
        if state.closed || state.pending.is_some() {
            return Err("Room unavailable".to_string().into());
        }
        let snapshot = state.sealed_snapshot()?;
        let encoded = Zeroizing::new(
            serde_json::to_vec(&snapshot)
                .map_err(|_| AbyssalError::from("Room unavailable".to_string()))?,
        );
        seal_state(
            &self.state_key,
            &self.username,
            &self.room_id,
            &self.node_context,
            &self.stable_identity,
            &self.group_id,
            &encoded,
        )
        .map_err(AbyssalError::from)
    }
}

impl MlsRoom {
    #[allow(clippy::too_many_arguments)]
    fn new_room(
        root: &[u8; 32],
        account_lifetime: Arc<AccountLifetime>,
        room_id: String,
        username: String,
        node_context: Vec<u8>,
        stable_identity: [u8; 64],
        credential_signature: Vec<u8>,
        group_id: Vec<u8>,
    ) -> Result<Arc<Self>, AbyssalError> {
        let mls_public = mls_public_for_root(
            root,
            &username,
            &node_context,
            &room_id,
            &parse_group_id(&group_id).map_err(AbyssalError::from)?,
        )
        .map_err(AbyssalError::from)?;
        let credential = encode_credential(
            &username,
            &room_id,
            &node_context,
            &group_id,
            &stable_identity,
            &mls_public,
            &credential_signature,
        )
        .map_err(AbyssalError::from)?;
        let storage = RamGroupStateStorage::default();
        let key_packages = RamKeyPackageStorage::default();
        let client = build_client(
            root,
            &username,
            &node_context,
            &room_id,
            &group_id,
            &credential,
            storage.clone(),
            key_packages.clone(),
        )
        .map_err(AbyssalError::from)?;
        let mut group_id_array = [0_u8; 32];
        group_id_array.copy_from_slice(&group_id);
        let mut group = client
            .create_group_with_id(
                group_id,
                ExtensionList::default(),
                ExtensionList::default(),
                None,
            )
            .map_err(|_| AbyssalError::from("Room unavailable".to_string()))?;
        group
            .write_to_storage()
            .map_err(|_| AbyssalError::from("Room unavailable".to_string()))?;
        let state_key = derive_state_key(
            root,
            &username,
            &room_id,
            &node_context,
            &stable_identity,
            &group_id_array,
        )
        .map_err(AbyssalError::from)?;
        Ok(Arc::new(Self {
            username,
            node_context,
            room_id,
            group_id: group_id_array.to_vec(),
            stable_identity,
            state_key: Zeroizing::new(state_key),
            account_lifetime,
            state: Mutex::new(MlsRoomState {
                client,
                group: Some(group),
                storage,
                key_packages,
                issued_key_packages: Vec::new(),
                revision: 0,
                pending: None,
                replay_ids: VecDeque::new(),
                closed: false,
            }),
        }))
    }

    #[allow(clippy::too_many_arguments)]
    fn new_pending(
        root: &[u8; 32],
        account_lifetime: Arc<AccountLifetime>,
        room_id: String,
        username: String,
        node_context: Vec<u8>,
        stable_identity: [u8; 64],
        credential_signature: Vec<u8>,
        group_id: Vec<u8>,
    ) -> Result<Arc<Self>, AbyssalError> {
        let mls_public = mls_public_for_root(
            root,
            &username,
            &node_context,
            &room_id,
            &parse_group_id(&group_id).map_err(AbyssalError::from)?,
        )
        .map_err(AbyssalError::from)?;
        let credential = encode_credential(
            &username,
            &room_id,
            &node_context,
            &group_id,
            &stable_identity,
            &mls_public,
            &credential_signature,
        )
        .map_err(AbyssalError::from)?;
        let storage = RamGroupStateStorage::default();
        let key_packages = RamKeyPackageStorage::default();
        let client = build_client(
            root,
            &username,
            &node_context,
            &room_id,
            &group_id,
            &credential,
            storage.clone(),
            key_packages.clone(),
        )
        .map_err(AbyssalError::from)?;
        let group_id_array = parse_group_id(&group_id).map_err(AbyssalError::from)?;
        let state_key = derive_state_key(
            root,
            &username,
            &room_id,
            &node_context,
            &stable_identity,
            &group_id_array,
        )
        .map_err(AbyssalError::from)?;
        Ok(Arc::new(Self {
            username,
            node_context,
            room_id,
            group_id: group_id_array.to_vec(),
            stable_identity,
            state_key: Zeroizing::new(state_key),
            account_lifetime,
            state: Mutex::new(MlsRoomState {
                client,
                group: None,
                storage,
                key_packages,
                issued_key_packages: Vec::new(),
                revision: 0,
                pending: None,
                replay_ids: VecDeque::new(),
                closed: false,
            }),
        }))
    }

    fn lock_state(&self) -> Result<MlsRoomStateGuard<'_>, AbyssalError> {
        let lifetime = self
            .account_lifetime
            .operation()
            .map_err(|_| AbyssalError::from("Room unavailable".to_string()))?;
        let state = self
            .state
            .lock()
            .map_err(|_| AbyssalError::from("Room unavailable".to_string()))?;
        Ok(MlsRoomStateGuard {
            _lifetime: lifetime,
            state,
        })
    }

    fn lock_state_mut(&self) -> Result<MlsRoomStateGuard<'_>, AbyssalError> {
        self.lock_state()
    }

    fn info_from_state(&self, state: &MlsRoomState) -> Result<MlsRoomInfo, AbyssalError> {
        let group = state
            .group
            .as_ref()
            .ok_or_else(|| AbyssalError::from("Room unavailable".to_string()))?;
        Ok(MlsRoomInfo {
            room_id: self.room_id.clone(),
            group_id: self.group_id.clone(),
            epoch: group.current_epoch(),
            member_count: group.roster().members_iter().count() as u32,
            revision: state.revision,
            membership_digest: membership_digest(group)
                .map_err(AbyssalError::from)?
                .to_vec(),
        })
    }

    fn stage_membership_commit(
        &self,
        state: &mut MlsRoomState,
        before: SealedRoomState,
        message_id: String,
        commit: Vec<u8>,
        welcome: Vec<u8>,
        authenticated_data: Vec<u8>,
    ) -> Result<MlsCommit, AbyssalError> {
        let rollback = before.clone();
        let result = (|| {
            let from_epoch = state
                .group
                .as_ref()
                .ok_or_else(|| AbyssalError::from("Room unavailable".to_string()))?
                .current_epoch();
            let from_membership_digest = before.membership_digest.clone();
            state
                .group
                .as_mut()
                .ok_or_else(|| AbyssalError::from("Room unavailable".to_string()))?
                .apply_pending_commit()
                .map_err(|_| AbyssalError::from("Room unavailable".to_string()))?;
            let to_epoch = state
                .group
                .as_ref()
                .ok_or_else(|| AbyssalError::from("Room unavailable".to_string()))?
                .current_epoch();
            if to_epoch
                != from_epoch
                    .checked_add(1)
                    .ok_or_else(|| AbyssalError::from("Room unavailable".to_string()))?
                || state.revision == u64::MAX
            {
                return Err("Room unavailable".to_string().into());
            }
            state
                .group
                .as_mut()
                .ok_or_else(|| AbyssalError::from("Room unavailable".to_string()))?
                .write_to_storage()
                .map_err(|_| AbyssalError::from("Room unavailable".to_string()))?;
            state.revision += 1;
            let digest = membership_digest(
                state
                    .group
                    .as_ref()
                    .ok_or_else(|| AbyssalError::from("Room unavailable".to_string()))?,
            )
            .map_err(AbyssalError::from)?;
            let roster = group_roster(
                state
                    .group
                    .as_ref()
                    .ok_or_else(|| AbyssalError::from("Room unavailable".to_string()))?,
            )?;
            let post = state.sealed_snapshot()?;
            let post_json = Zeroizing::new(
                serde_json::to_vec(&post)
                    .map_err(|_| AbyssalError::from("Room unavailable".to_string()))?,
            );
            let state_envelope = seal_state(
                &self.state_key,
                &self.username,
                &self.room_id,
                &self.node_context,
                &self.stable_identity,
                &self.group_id,
                &post_json,
            )
            .map_err(AbyssalError::from)?;
            state.pending = Some(PendingOutbound {
                message_id: message_id.clone(),
                revision: state.revision,
                before,
                post_envelope: state_envelope.clone(),
                from_epoch,
                to_epoch,
                membership_digest: digest,
                replay_id: None,
            });
            Ok(MlsCommit {
                message_id,
                revision: state.revision,
                group_id: self.group_id.clone(),
                from_epoch,
                to_epoch,
                from_membership_digest,
                membership_digest: digest.to_vec(),
                roster,
                state_envelope,
                authenticated_data,
                commit,
                welcome,
            })
        })();
        if result.is_err()
            && state
                .restore_sealed_snapshot(&self.group_id, rollback)
                .is_err()
        {
            state.close();
        }
        result
    }
}

impl Drop for MlsRoom {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.close();
        }
        self.node_context.zeroize();
        self.stable_identity.zeroize();
    }
}

#[allow(clippy::too_many_arguments)]
fn build_client(
    root: &[u8; 32],
    username: &str,
    node_context: &[u8],
    room_id: &str,
    group_id: &[u8],
    credential: &[u8],
    storage: RamGroupStateStorage,
    key_packages: RamKeyPackageStorage,
) -> Result<MlsClient, String> {
    let group_id: [u8; 32] = group_id
        .try_into()
        .map_err(|_| "Identity unavailable".to_string())?;
    let public = mls_public_for_root(root, username, node_context, room_id, &group_id)?;
    let mut seed = Zeroizing::new([0_u8; 32]);
    let info = canonical_fields(
        b"ABYSSAL-MLS-V10-SIGNING",
        &[
            username.as_bytes(),
            node_context,
            room_id.as_bytes(),
            &group_id,
        ],
    )?;
    Hkdf::<Sha256>::new(Some(b"ABYSSAL-MLS-V10-SIGNING"), root)
        .expand(&info, seed.as_mut())
        .map_err(|_| "Identity unavailable".to_string())?;
    let key = SigningKey::from_bytes(&seed);
    let keypair = key.to_keypair_bytes().to_vec();
    seed.zeroize();
    let secret = SignatureSecretKey::new(keypair);
    let provider = RustCryptoProvider::with_enabled_cipher_suites(vec![MLS_CIPHERSUITE]);
    let cipher = provider
        .cipher_suite_provider(MLS_CIPHERSUITE)
        .ok_or_else(|| "Identity unavailable".to_string())?;
    let derived = cipher
        .signature_key_derive_public(&secret)
        .map_err(|_| "Identity unavailable".to_string())?;
    if derived.as_bytes() != public {
        return Err("Identity unavailable".to_string());
    }
    let credential =
        Credential::Custom(CustomCredential::new(CREDENTIAL_TYPE, credential.to_vec()));
    let signing_identity =
        SigningIdentity::new(credential, SignaturePublicKey::new(public.to_vec()));
    Ok(Client::builder()
        .key_package_repo(key_packages)
        .group_state_storage(storage)
        .identity_provider(AbyssalIdentityProvider)
        .crypto_provider(provider)
        .signing_identity(signing_identity, secret, MLS_CIPHERSUITE)
        .build())
}

fn parse_stable_identity(value: &[u8]) -> Result<[u8; 64], String> {
    if value.len() != 64 || value.iter().all(|byte| *byte == 0) {
        return Err("Identity unavailable".to_string());
    }
    let mut out = [0_u8; 64];
    out.copy_from_slice(value);
    Ok(out)
}
fn parse_group_id(value: &[u8]) -> Result<[u8; 32], String> {
    if value.len() != 32 || value.iter().all(|byte| *byte == 0) {
        return Err("Room unavailable".to_string());
    }
    let mut out = [0_u8; 32];
    out.copy_from_slice(value);
    Ok(out)
}
fn validate_node_context(value: &[u8]) -> Result<Vec<u8>, String> {
    if value.is_empty() || value.len() > 512 || !value.is_ascii() {
        return Err("Identity unavailable".to_string());
    }
    Ok(value.to_vec())
}
fn validate_username(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        Err("Identity unavailable".to_string())
    } else {
        Ok(())
    }
}
fn canonical_username(value: &str) -> Result<String, String> {
    validate_username(value)?;
    Ok(value.to_ascii_lowercase())
}
fn validate_room_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_ROOM_ID_BYTES
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        Err("Room unavailable".to_string())
    } else {
        Ok(())
    }
}
fn validate_message_id(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 128 || !value.is_ascii() {
        Err("Room unavailable".to_string())
    } else {
        Ok(())
    }
}
fn bounded_bytes(value: Vec<u8>, limit: usize, error: &str) -> Result<Vec<u8>, AbyssalError> {
    if value.is_empty() || value.len() > limit {
        Err(error.to_string().into())
    } else {
        Ok(value)
    }
}
fn decode_complete_message(bytes: &[u8], error: &str) -> Result<MlsMessage, AbyssalError> {
    let mut input = bytes;
    let message =
        MlsMessage::mls_decode(&mut input).map_err(|_| AbyssalError::from(error.to_string()))?;
    if !input.is_empty() {
        return Err(error.to_string().into());
    }
    Ok(message)
}
fn verify_stable_signature(
    stable: &[u8; 64],
    transcript: &[u8],
    proof: &[u8],
) -> Result<(), String> {
    if proof.len() != 64 {
        return Err("Identity unavailable".to_string());
    }
    let key = VerifyingKey::from_bytes(
        stable[32..]
            .try_into()
            .map_err(|_| "Identity unavailable".to_string())?,
    )
    .map_err(|_| "Identity unavailable".to_string())?;
    let sig = Signature::from_slice(proof).map_err(|_| "Identity unavailable".to_string())?;
    key.verify(transcript, &sig)
        .map_err(|_| "Identity unavailable".to_string())
}
fn verify_key_package_directory(
    bytes: &[u8],
    expected_username: &str,
    room_id: &str,
    node_context: &[u8],
    group_id: &[u8],
    expected: &[u8; 64],
) -> Result<(), String> {
    let message = decode_complete_message(bytes, "Room unavailable")
        .map_err(|_| "Room unavailable".to_string())?;
    if message.cipher_suite() != Some(MLS_CIPHERSUITE) {
        return Err("Room unavailable".to_string());
    }
    let kp = message
        .as_key_package()
        .ok_or_else(|| "Room unavailable".to_string())?;
    let parts =
        parse_credential(kp.signing_identity()).map_err(|_| "Room unavailable".to_string())?;
    if parts.username != canonical_username(expected_username)?
        || parts.room_id != room_id
        || parts.node_context != node_context
        || parts.group_id.as_slice() != group_id
        || parts.stable_identity != *expected
    {
        return Err("Room unavailable".to_string());
    }
    Ok(())
}
fn verify_group_directory(
    group: &MlsGroup,
    room_id: &str,
    node_context: &[u8],
    group_id: &[u8],
    expected: &[MlsRosterMember],
    expected_digest: &[u8; 32],
) -> Result<(), String> {
    if expected.is_empty() || expected.len() > MAX_MEMBERS {
        return Err("Room unavailable".to_string());
    }
    let mut actual = Vec::new();
    for member in group.roster().members_iter() {
        let parts = parse_credential(&member.signing_identity)
            .map_err(|_| "Room unavailable".to_string())?;
        if parts.room_id != room_id
            || parts.node_context != node_context
            || parts.group_id.as_slice() != group_id
        {
            return Err("Room unavailable".to_string());
        }
        actual.push(MlsRosterMember {
            username: parts.username,
            stable_identity: parts.stable_identity.to_vec(),
        });
    }
    let mut unique_expected = std::collections::HashSet::new();
    for member in expected {
        validate_username(&member.username)?;
        let stable = parse_stable_identity(&member.stable_identity)?;
        if !unique_expected.insert((member.username.to_ascii_lowercase(), stable)) {
            return Err("Room unavailable".to_string());
        }
    }
    if actual.len() != expected.len()
        || actual.iter().any(|member| {
            !expected.iter().any(|candidate| {
                candidate.username.eq_ignore_ascii_case(&member.username)
                    && candidate.stable_identity == member.stable_identity
            })
        })
        || &membership_digest(group)? != expected_digest
    {
        return Err("Room unavailable".to_string());
    }
    Ok(())
}
fn validate_group_context(
    group: &MlsGroup,
    room_id: &str,
    node_context: &[u8],
    group_id: &[u8],
) -> Result<(), String> {
    let mut identities = std::collections::HashSet::new();
    let mut usernames = std::collections::HashSet::new();
    let members = group.roster().members_iter().count();
    if members == 0 || members > MAX_MEMBERS {
        return Err("Room unavailable".to_string());
    }
    for member in group.roster().members_iter() {
        let parts = parse_credential(&member.signing_identity)
            .map_err(|_| "Room unavailable".to_string())?;
        if parts.room_id != room_id
            || parts.node_context != node_context
            || parts.group_id.as_slice() != group_id
            || !identities.insert(parts.stable_identity)
            || !usernames.insert(parts.username)
        {
            return Err("Room unavailable".to_string());
        }
    }
    Ok(())
}
fn group_roster(group: &MlsGroup) -> Result<Vec<MlsRosterMember>, AbyssalError> {
    group
        .roster()
        .members_iter()
        .map(|member| {
            parse_credential(&member.signing_identity)
                .map(|parts| MlsRosterMember {
                    username: parts.username,
                    stable_identity: parts.stable_identity.to_vec(),
                })
                .map_err(|_| AbyssalError::from("Room unavailable".to_string()))
        })
        .collect()
}
fn self_member_index(group: &MlsGroup, stable_identity: &[u8; 64]) -> Result<u32, String> {
    group
        .roster()
        .members_iter()
        .find_map(|member| {
            parse_credential(&member.signing_identity)
                .ok()
                .filter(|parts| parts.stable_identity == *stable_identity)
                .map(|_| member.index)
        })
        .ok_or_else(|| "Payload unavailable".to_string())
}
fn commit_authenticated_data(
    message_id: &str,
    room_id: &str,
    group_id: &[u8],
    from_epoch: u64,
    action: &[u8],
    target_username: &str,
    target_stable_identity: &[u8; 64],
) -> Result<Vec<u8>, String> {
    validate_message_id(message_id)?;
    validate_room_id(room_id)?;
    canonical_username(target_username)?;
    if group_id.len() != 32 || (action != b"add" && action != b"remove") {
        return Err("Room unavailable".to_string());
    }
    let epoch = from_epoch.to_be_bytes();
    canonical_fields(
        COMMIT_AAD_MAGIC,
        &[
            &[MLS_PROTOCOL_VERSION as u8],
            message_id.as_bytes(),
            room_id.as_bytes(),
            group_id,
            &epoch,
            action,
            target_username.as_bytes(),
            target_stable_identity,
        ],
    )
}
fn validate_commit_authenticated_data(
    data: &[u8],
    message_id: &str,
    room_id: &str,
    group_id: &[u8],
    from_epoch: u64,
) -> Result<(), String> {
    let fields = decode_canonical_fields(data, COMMIT_AAD_MAGIC)?;
    if fields.len() != 8
        || fields[0] != [MLS_PROTOCOL_VERSION as u8]
        || fields[1] != message_id.as_bytes()
        || fields[2] != room_id.as_bytes()
        || fields[3] != group_id
        || fields[4] != from_epoch.to_be_bytes()
        || (fields[5].as_slice() != b"add" && fields[5].as_slice() != b"remove")
    {
        return Err("Room unavailable".to_string());
    }
    let username = std::str::from_utf8(&fields[6]).map_err(|_| "Room unavailable".to_string())?;
    if canonical_username(username)? != username
        || fields[7].len() != 64
        || fields[7].iter().all(|byte| *byte == 0)
    {
        return Err("Room unavailable".to_string());
    }
    Ok(())
}
fn membership_digest(group: &MlsGroup) -> Result<[u8; 32], String> {
    let mut entries = Vec::new();
    for member in group.roster().members_iter() {
        let parts = parse_credential(&member.signing_identity)
            .map_err(|_| "Room unavailable".to_string())?;
        entries.push((
            member.index,
            parts.username,
            parts.stable_identity,
            parts.mls_public,
        ));
    }
    entries.sort_by_key(|(index, _, _, _)| *index);
    let mut fields = Vec::new();
    fields.extend_from_slice(&MLS_PROTOCOL_VERSION.to_be_bytes());
    for (index, username, stable, mls_public) in entries {
        fields.extend_from_slice(&index.to_be_bytes());
        fields.extend_from_slice(&(username.len() as u32).to_be_bytes());
        fields.extend_from_slice(username.as_bytes());
        fields.extend_from_slice(&stable);
        fields.extend_from_slice(&mls_public);
    }
    Ok(Sha256::digest(canonical_fields(b"ABYSSAL-MLS-V10-MEMBERS", &[&fields])?).into())
}
fn canonical_fields(domain: &[u8], fields: &[&[u8]]) -> Result<Vec<u8>, String> {
    if domain.is_empty() || domain.len() > u32::MAX as usize || fields.len() > 16 {
        return Err("Room unavailable".to_string());
    }
    let mut out = Vec::new();
    out.extend_from_slice(&(domain.len() as u32).to_be_bytes());
    out.extend_from_slice(domain);
    out.extend_from_slice(&(fields.len() as u32).to_be_bytes());
    for field in fields {
        if field.len() > u32::MAX as usize {
            return Err("Room unavailable".to_string());
        }
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field);
        if out.len() > MAX_STATE_BYTES {
            return Err("Room unavailable".to_string());
        }
    }
    Ok(out)
}
fn decode_canonical_fields(data: &[u8], expected_domain: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if data.len() < 8 {
        return Err("Room unavailable".to_string());
    }
    let domain_len = u32::from_be_bytes(
        data[..4]
            .try_into()
            .map_err(|_| "Room unavailable".to_string())?,
    ) as usize;
    let mut cursor = 4usize;
    if domain_len != expected_domain.len()
        || cursor + domain_len > data.len()
        || &data[cursor..cursor + domain_len] != expected_domain
    {
        return Err("Room unavailable".to_string());
    }
    cursor += domain_len;
    if cursor + 4 > data.len() {
        return Err("Room unavailable".to_string());
    }
    let count = u32::from_be_bytes(
        data[cursor..cursor + 4]
            .try_into()
            .map_err(|_| "Room unavailable".to_string())?,
    ) as usize;
    cursor += 4;
    if count > 16 {
        return Err("Room unavailable".to_string());
    }
    let mut fields = Vec::with_capacity(count);
    for _ in 0..count {
        if cursor + 4 > data.len() {
            return Err("Room unavailable".to_string());
        }
        let len = u32::from_be_bytes(
            data[cursor..cursor + 4]
                .try_into()
                .map_err(|_| "Room unavailable".to_string())?,
        ) as usize;
        cursor += 4;
        if len > data.len().saturating_sub(cursor) {
            return Err("Room unavailable".to_string());
        }
        fields.push(data[cursor..cursor + len].to_vec());
        cursor += len;
    }
    if cursor != data.len() {
        return Err("Room unavailable".to_string());
    }
    Ok(fields)
}
fn replay_digest_from_message_id(domain: &[u8], message_id: &str) -> [u8; 32] {
    let digest = Sha256::digest(
        canonical_fields(b"ABYSSAL-MLS-V10-REPLAY", &[domain, message_id.as_bytes()])
            .expect("validated message ID fits canonical replay fields"),
    );
    digest.into()
}
