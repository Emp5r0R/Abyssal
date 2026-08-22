use super::{
    MlsApplicationMessage, MlsCommit, MlsEncryptedApplication, MlsProcessedControl, MlsRoom,
    MlsRoomInfo, MlsRosterMember, MAX_MEMBERS,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

const MAX_ROSTER_JSON_BYTES: usize = 64 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RosterMemberInput {
    username: String,
    stable_identity: Vec<u8>,
}

#[derive(Debug, Serialize)]
struct RosterMemberOutput<'a> {
    username: &'a str,
    stable_identity: &'a [u8],
}

pub(crate) fn parse_roster_json(value: &str) -> Result<Vec<MlsRosterMember>, JsValue> {
    if value.len() > MAX_ROSTER_JSON_BYTES {
        return Err(js_error("Roster unavailable"));
    }
    let members: Vec<RosterMemberInput> =
        serde_json::from_str(value).map_err(|_| js_error("Roster unavailable"))?;
    if members.len() > MAX_MEMBERS {
        return Err(js_error("Roster unavailable"));
    }
    members
        .into_iter()
        .map(|member| {
            if member.stable_identity.len() != 64 {
                return Err(js_error("Roster unavailable"));
            }
            Ok(MlsRosterMember {
                username: member.username,
                stable_identity: member.stable_identity,
            })
        })
        .collect()
}

fn roster_json(roster: &[MlsRosterMember]) -> Result<String, JsValue> {
    if roster.len() > MAX_MEMBERS {
        return Err(js_error("Roster unavailable"));
    }
    let output: Vec<_> = roster
        .iter()
        .map(|member| RosterMemberOutput {
            username: &member.username,
            stable_identity: &member.stable_identity,
        })
        .collect();
    let encoded = serde_json::to_string(&output).map_err(|_| js_error("Roster unavailable"))?;
    if encoded.len() > MAX_ROSTER_JSON_BYTES {
        return Err(js_error("Roster unavailable"));
    }
    Ok(encoded)
}

fn js_error(message: impl AsRef<str>) -> JsValue {
    JsValue::from_str(message.as_ref())
}

#[wasm_bindgen]
pub struct WasmMlsRoomInfo {
    inner: MlsRoomInfo,
}

impl WasmMlsRoomInfo {
    pub(crate) fn from_inner(inner: MlsRoomInfo) -> Self {
        Self { inner }
    }
}

impl Drop for WasmMlsRoomInfo {
    fn drop(&mut self) {
        self.inner.room_id.zeroize();
        self.inner.group_id.zeroize();
        self.inner.membership_digest.zeroize();
    }
}

#[wasm_bindgen]
impl WasmMlsRoomInfo {
    #[wasm_bindgen(getter, js_name = roomId)]
    pub fn room_id(&self) -> String {
        self.inner.room_id.clone()
    }

    #[wasm_bindgen(getter, js_name = groupId)]
    pub fn group_id(&self) -> Vec<u8> {
        self.inner.group_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn epoch(&self) -> u64 {
        self.inner.epoch
    }

    #[wasm_bindgen(getter, js_name = memberCount)]
    pub fn member_count(&self) -> u32 {
        self.inner.member_count
    }

    #[wasm_bindgen(getter)]
    pub fn revision(&self) -> u64 {
        self.inner.revision
    }

    #[wasm_bindgen(getter, js_name = membershipDigest)]
    pub fn membership_digest(&self) -> Vec<u8> {
        self.inner.membership_digest.clone()
    }
}

#[wasm_bindgen]
pub struct WasmMlsCommit {
    inner: MlsCommit,
}

impl WasmMlsCommit {
    pub(crate) fn from_inner(inner: MlsCommit) -> Self {
        Self { inner }
    }
}

impl Drop for WasmMlsCommit {
    fn drop(&mut self) {
        self.inner.message_id.zeroize();
        self.inner.group_id.zeroize();
        self.inner.from_membership_digest.zeroize();
        self.inner.membership_digest.zeroize();
        self.inner.state_envelope.zeroize();
        self.inner.authenticated_data.zeroize();
        self.inner.commit.zeroize();
        self.inner.welcome.zeroize();
        for member in &mut self.inner.roster {
            member.username.zeroize();
            member.stable_identity.zeroize();
        }
    }
}

#[wasm_bindgen]
impl WasmMlsCommit {
    #[wasm_bindgen(getter, js_name = messageId)]
    pub fn message_id(&self) -> String {
        self.inner.message_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn revision(&self) -> u64 {
        self.inner.revision
    }

    #[wasm_bindgen(getter, js_name = groupId)]
    pub fn group_id(&self) -> Vec<u8> {
        self.inner.group_id.clone()
    }

    #[wasm_bindgen(getter, js_name = fromEpoch)]
    #[allow(clippy::wrong_self_convention)]
    pub fn from_epoch(&self) -> u64 {
        self.inner.from_epoch
    }

    #[wasm_bindgen(getter, js_name = toEpoch)]
    pub fn to_epoch(&self) -> u64 {
        self.inner.to_epoch
    }

    #[wasm_bindgen(getter, js_name = fromMembershipDigest)]
    #[allow(clippy::wrong_self_convention)]
    pub fn from_membership_digest(&self) -> Vec<u8> {
        self.inner.from_membership_digest.clone()
    }

    #[wasm_bindgen(getter, js_name = membershipDigest)]
    pub fn membership_digest(&self) -> Vec<u8> {
        self.inner.membership_digest.clone()
    }

    #[wasm_bindgen(getter, js_name = rosterJson)]
    pub fn roster_json(&self) -> Result<String, JsValue> {
        roster_json(&self.inner.roster)
    }

    #[wasm_bindgen(getter, js_name = stateEnvelope)]
    pub fn state_envelope(&self) -> Vec<u8> {
        self.inner.state_envelope.clone()
    }

    #[wasm_bindgen(getter, js_name = authenticatedData)]
    pub fn authenticated_data(&self) -> Vec<u8> {
        self.inner.authenticated_data.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn commit(&self) -> Vec<u8> {
        self.inner.commit.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn welcome(&self) -> Vec<u8> {
        self.inner.welcome.clone()
    }
}

#[wasm_bindgen]
pub struct WasmMlsApplicationMessage {
    inner: MlsApplicationMessage,
}

impl WasmMlsApplicationMessage {
    pub(crate) fn from_inner(inner: MlsApplicationMessage) -> Self {
        Self { inner }
    }
}

impl Drop for WasmMlsApplicationMessage {
    fn drop(&mut self) {
        self.inner.message_id.zeroize();
        self.inner.plaintext.zeroize();
        self.inner.group_id.zeroize();
        self.inner.membership_digest.zeroize();
        self.inner.state_envelope.zeroize();
        self.inner.authenticated_data.zeroize();
    }
}

#[wasm_bindgen]
impl WasmMlsApplicationMessage {
    #[wasm_bindgen(getter, js_name = messageId)]
    pub fn message_id(&self) -> String {
        self.inner.message_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn plaintext(&self) -> Vec<u8> {
        self.inner.plaintext.clone()
    }

    #[wasm_bindgen(getter, js_name = senderIndex)]
    pub fn sender_index(&self) -> u32 {
        self.inner.sender_index
    }

    #[wasm_bindgen(getter)]
    pub fn epoch(&self) -> u64 {
        self.inner.epoch
    }

    #[wasm_bindgen(getter, js_name = groupId)]
    pub fn group_id(&self) -> Vec<u8> {
        self.inner.group_id.clone()
    }

    #[wasm_bindgen(getter, js_name = membershipDigest)]
    pub fn membership_digest(&self) -> Vec<u8> {
        self.inner.membership_digest.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn revision(&self) -> u64 {
        self.inner.revision
    }

    #[wasm_bindgen(getter, js_name = stateEnvelope)]
    pub fn state_envelope(&self) -> Vec<u8> {
        self.inner.state_envelope.clone()
    }

    #[wasm_bindgen(getter, js_name = authenticatedData)]
    pub fn authenticated_data(&self) -> Vec<u8> {
        self.inner.authenticated_data.clone()
    }
}

#[wasm_bindgen]
pub struct WasmMlsProcessedControl {
    inner: Arc<MlsProcessedControl>,
}

impl WasmMlsProcessedControl {
    fn from_inner(inner: Arc<MlsProcessedControl>) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
impl WasmMlsProcessedControl {
    #[wasm_bindgen(getter, js_name = roomId)]
    pub fn room_id(&self) -> String {
        self.inner.room_id.clone()
    }
    #[wasm_bindgen(getter, js_name = messageId)]
    pub fn message_id(&self) -> String {
        self.inner.message_id.clone()
    }
    #[wasm_bindgen(getter, js_name = groupId)]
    pub fn group_id(&self) -> Vec<u8> {
        self.inner.group_id.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn epoch(&self) -> u64 {
        self.inner.epoch
    }
    #[wasm_bindgen(getter, js_name = memberCount)]
    pub fn member_count(&self) -> u32 {
        self.inner.member_count
    }
    #[wasm_bindgen(getter)]
    pub fn revision(&self) -> u64 {
        self.inner.revision
    }
    #[wasm_bindgen(getter, js_name = membershipDigest)]
    pub fn membership_digest(&self) -> Vec<u8> {
        self.inner.membership_digest.clone()
    }
    #[wasm_bindgen(getter, js_name = stateEnvelope)]
    pub fn state_envelope(&self) -> Vec<u8> {
        self.inner.state_envelope.clone()
    }
}

#[wasm_bindgen]
pub struct WasmMlsEncryptedApplication {
    inner: MlsEncryptedApplication,
}

impl WasmMlsEncryptedApplication {
    pub(crate) fn from_inner(inner: MlsEncryptedApplication) -> Self {
        Self { inner }
    }
}

impl Drop for WasmMlsEncryptedApplication {
    fn drop(&mut self) {
        self.inner.message_id.zeroize();
        self.inner.ciphertext.zeroize();
        self.inner.state_envelope.zeroize();
        self.inner.group_id.zeroize();
        self.inner.membership_digest.zeroize();
        self.inner.authenticated_data.zeroize();
    }
}

#[wasm_bindgen]
impl WasmMlsEncryptedApplication {
    #[wasm_bindgen(getter, js_name = messageId)]
    pub fn message_id(&self) -> String {
        self.inner.message_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn revision(&self) -> u64 {
        self.inner.revision
    }

    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.inner.ciphertext.clone()
    }

    #[wasm_bindgen(getter, js_name = stateEnvelope)]
    pub fn state_envelope(&self) -> Vec<u8> {
        self.inner.state_envelope.clone()
    }

    #[wasm_bindgen(getter, js_name = groupId)]
    pub fn group_id(&self) -> Vec<u8> {
        self.inner.group_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn epoch(&self) -> u64 {
        self.inner.epoch
    }

    #[wasm_bindgen(getter, js_name = membershipDigest)]
    pub fn membership_digest(&self) -> Vec<u8> {
        self.inner.membership_digest.clone()
    }

    #[wasm_bindgen(getter, js_name = senderIndex)]
    pub fn sender_index(&self) -> u32 {
        self.inner.sender_index
    }

    #[wasm_bindgen(getter, js_name = authenticatedData)]
    pub fn authenticated_data(&self) -> Vec<u8> {
        self.inner.authenticated_data.clone()
    }
}

#[wasm_bindgen]
pub struct WasmMlsRoom {
    inner: Arc<MlsRoom>,
}

impl WasmMlsRoom {
    pub(crate) fn from_inner(inner: Arc<MlsRoom>) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
impl WasmMlsRoom {
    #[wasm_bindgen(js_name = roomInfo)]
    pub fn room_info(&self) -> Result<WasmMlsRoomInfo, JsValue> {
        self.inner
            .room_info()
            .map(WasmMlsRoomInfo::from_inner)
            .map_err(|error| js_error(error.to_string()))
    }

    #[wasm_bindgen(js_name = keyPackage)]
    pub fn key_package(&self) -> Result<Vec<u8>, JsValue> {
        self.inner
            .key_package()
            .map_err(|error| js_error(error.to_string()))
    }

    #[wasm_bindgen(js_name = addMember)]
    pub fn add_member(
        &self,
        key_package: Vec<u8>,
        expected_username: String,
        expected_stable_identity: Vec<u8>,
        message_id: String,
    ) -> Result<WasmMlsCommit, JsValue> {
        self.inner
            .add_member(
                key_package,
                expected_username,
                expected_stable_identity,
                message_id,
            )
            .map(WasmMlsCommit::from_inner)
            .map_err(|error| js_error(error.to_string()))
    }

    #[wasm_bindgen(js_name = removeMember)]
    pub fn remove_member(
        &self,
        expected_username: String,
        expected_stable_identity: Vec<u8>,
        message_id: String,
    ) -> Result<WasmMlsCommit, JsValue> {
        self.inner
            .remove_member(expected_username, expected_stable_identity, message_id)
            .map(WasmMlsCommit::from_inner)
            .map_err(|error| js_error(error.to_string()))
    }

    #[wasm_bindgen(js_name = commitOutbound)]
    pub fn commit_outbound(&self, message_id: String, revision: u64) -> Result<(), JsValue> {
        self.inner
            .commit_outbound(message_id, revision)
            .map_err(|error| js_error(error.to_string()))
    }

    #[wasm_bindgen(js_name = rollbackOutbound)]
    pub fn rollback_outbound(&self, message_id: String, revision: u64) -> Result<(), JsValue> {
        self.inner
            .rollback_outbound(message_id, revision)
            .map_err(|error| js_error(error.to_string()))
    }

    #[wasm_bindgen(js_name = joinWelcome)]
    pub fn join_welcome(
        &self,
        welcome: Vec<u8>,
        expected_members_json: String,
        expected_digest: Vec<u8>,
    ) -> Result<WasmMlsRoomInfo, JsValue> {
        let expected_members = parse_roster_json(&expected_members_json)?;
        self.inner
            .join_welcome(welcome, expected_members, expected_digest)
            .map(WasmMlsRoomInfo::from_inner)
            .map_err(|error| js_error(error.to_string()))
    }

    #[wasm_bindgen(js_name = processControl)]
    #[allow(clippy::too_many_arguments)]
    pub fn process_control(
        &self,
        control: Vec<u8>,
        expected_from_epoch: u64,
        expected_to_epoch: u64,
        expected_members_json: String,
        expected_digest: Vec<u8>,
        message_id: String,
        expected_authenticated_data: Vec<u8>,
    ) -> Result<WasmMlsProcessedControl, JsValue> {
        let expected_members = parse_roster_json(&expected_members_json)?;
        self.inner
            .process_control(
                control,
                expected_from_epoch,
                expected_to_epoch,
                expected_members,
                expected_digest,
                message_id,
                expected_authenticated_data,
            )
            .map(WasmMlsProcessedControl::from_inner)
            .map_err(|error| js_error(error.to_string()))
    }

    #[wasm_bindgen(js_name = encryptApplication)]
    pub fn encrypt_application(
        &self,
        message_id: String,
        plaintext: Vec<u8>,
        authenticated_data: Vec<u8>,
    ) -> Result<WasmMlsEncryptedApplication, JsValue> {
        self.inner
            .encrypt_application(message_id, plaintext, authenticated_data)
            .map(WasmMlsEncryptedApplication::from_inner)
            .map_err(|error| js_error(error.to_string()))
    }

    #[wasm_bindgen(js_name = decryptApplication)]
    pub fn decrypt_application(
        &self,
        ciphertext: Vec<u8>,
        expected_epoch: u64,
        message_id: String,
        expected_authenticated_data: Vec<u8>,
    ) -> Result<WasmMlsApplicationMessage, JsValue> {
        self.inner
            .decrypt_application(
                ciphertext,
                expected_epoch,
                message_id,
                expected_authenticated_data,
            )
            .map(WasmMlsApplicationMessage::from_inner)
            .map_err(|error| js_error(error.to_string()))
    }

    #[wasm_bindgen(js_name = sealState)]
    pub fn seal_state(&self) -> Result<Vec<u8>, JsValue> {
        self.inner
            .seal_state()
            .map_err(|error| js_error(error.to_string()))
    }
}
