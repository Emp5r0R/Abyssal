use std::collections::{BTreeMap, HashMap, VecDeque};

use zeroize::Zeroize;

use crate::client_platform::ClientPlatform;

use super::policy::RoomPolicy;

pub type CodeId = [u8; 32];

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) enum ReplayDomain {
    Membership,
    Application,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ReplayKey {
    pub(super) domain: ReplayDomain,
    pub(super) message_id: String,
}

impl ReplayKey {
    pub(super) fn membership(message_id: &str) -> Self {
        Self {
            domain: ReplayDomain::Membership,
            message_id: message_id.to_string(),
        }
    }

    pub(super) fn application(message_id: &str) -> Self {
        Self {
            domain: ReplayDomain::Application,
            message_id: message_id.to_string(),
        }
    }
}

impl Drop for ReplayKey {
    fn drop(&mut self) {
        self.message_id.zeroize();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RosterMember {
    pub username: String,
    pub stable_identity: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverySnapshot {
    pub active: bool,
    pub epoch: u64,
    pub revision: u64,
    pub membership_digest: Vec<u8>,
    pub state_envelope: Vec<u8>,
    pub roster: Vec<RosterMember>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoomInfo {
    pub room_id: String,
    pub owner_username: String,
    pub group_id: Vec<u8>,
    pub active: bool,
    pub synchronized: bool,
    pub epoch: u64,
    pub revision: u64,
    pub recovery_snapshot: Option<RecoverySnapshot>,
    pub membership_digest: Vec<u8>,
    pub roster: Vec<RosterMember>,
    pub policy: RoomPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JoinRequest {
    pub request_id: String,
    pub room_id: String,
    pub code_id: CodeId,
    pub username: String,
    pub stable_identity: Vec<u8>,
    pub key_package: Vec<u8>,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaveRequest {
    pub request_id: String,
    pub room_id: String,
    pub code_id: CodeId,
    pub username: String,
    pub stable_identity: Vec<u8>,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

pub(super) struct PendingJoin {
    pub(super) request: JoinRequest,
    pub(super) state_envelope: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipTransition {
    pub room_id: String,
    pub message_id: String,
    pub request_id: Option<String>,
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub revision: u64,
    pub group_id: Vec<u8>,
    pub from_membership_digest: Vec<u8>,
    pub membership_digest: Vec<u8>,
    pub roster: Vec<RosterMember>,
    pub control: Vec<u8>,
    pub welcome: Vec<u8>,
    pub authenticated_data: Vec<u8>,
    pub state_envelope: Vec<u8>,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationAdmission {
    pub message_id: String,
    pub room_id: String,
    pub sender_username: String,
    pub recipient_code_ids: Vec<CodeId>,
    pub recipient_revisions: Vec<(CodeId, u64)>,
    pub sender_revision: u64,
    pub epoch: u64,
    pub membership_digest: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub authenticated_data: Vec<u8>,
    pub state_envelope: Vec<u8>,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeliveryPayload {
    Membership {
        from_epoch: u64,
        from_membership_digest: Vec<u8>,
        group_id: Vec<u8>,
        roster: Vec<RosterMember>,
        control: Vec<u8>,
        welcome: Vec<u8>,
        authenticated_data: Vec<u8>,
    },
    Application {
        sender_code_id: CodeId,
        sender_username: String,
        sender_platform: ClientPlatform,
        ciphertext: Vec<u8>,
        authenticated_data: Vec<u8>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingDelivery {
    pub room_id: String,
    pub message_id: String,
    pub recipient_code_id: CodeId,
    pub epoch: u64,
    pub membership_digest: Vec<u8>,
    pub revision: u64,
    pub payload: DeliveryPayload,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateSnapshot {
    pub room_id: String,
    pub message_id: String,
    pub member_code_id: CodeId,
    pub epoch: u64,
    pub revision: u64,
    pub membership_digest: Vec<u8>,
    pub state_envelope: Vec<u8>,
    pub roster: Vec<RosterMember>,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MembershipResult {
    Accepted(Box<MembershipTransition>),
    RolledBack { message_id: String, revision: u64 },
}

#[derive(Clone)]
pub(super) struct Member {
    pub(super) username: String,
    pub(super) code_id: CodeId,
    pub(super) stable_identity: Vec<u8>,
    pub(super) active: bool,
}

#[derive(Clone)]
pub(super) struct PendingApplication {
    pub(super) admission: ApplicationAdmission,
    pub(super) sender_code_id: CodeId,
    pub(super) previous_sender_revision: u64,
    pub(super) previous_snapshot: Option<StateSnapshot>,
}

pub(super) struct RelayRoom {
    pub(super) room_id: String,
    pub(super) owner_code_id: CodeId,
    pub(super) owner_username: String,
    pub(super) policy: RoomPolicy,
    pub(super) group_id: Vec<u8>,
    pub(super) epoch: u64,
    pub(super) membership_digest: Vec<u8>,
    pub(super) members: BTreeMap<String, Member>,
    pub(super) joins: HashMap<String, PendingJoin>,
    pub(super) leaves: HashMap<String, LeaveRequest>,
    pub(super) pending_transition: Option<MembershipTransition>,
    pub(super) pending_applications: HashMap<String, PendingApplication>,
    pub(super) pending_bytes: usize,
    pub(super) replay_ids: VecDeque<(ReplayKey, u64)>,
    pub(super) snapshots: HashMap<CodeId, StateSnapshot>,
    pub(super) snapshot_bytes: usize,
    pub(super) member_revisions: HashMap<CodeId, u64>,
    pub(super) deliveries: HashMap<CodeId, VecDeque<PendingDelivery>>,
    pub(super) delivery_bytes: usize,
    pub(super) expired_sender_gaps: HashMap<(CodeId, CodeId), u16>,
}

pub struct RoomAuthority {
    pub(super) rooms: HashMap<String, RelayRoom>,
    pub(super) max_rooms: usize,
    pub(super) join_ttl_ms: u64,
    pub(super) pending_ttl_ms: u64,
    pub(super) replay_ttl_ms: u64,
    pub(super) max_delivery_count: usize,
    pub(super) max_delivery_bytes: usize,
    pub(super) global_pending_bytes: usize,
    pub(super) global_pending_count: usize,
    pub(super) global_snapshot_bytes: usize,
    pub(super) global_snapshot_count: usize,
    pub(super) global_replay_count: usize,
    pub(super) global_delivery_bytes: usize,
    pub(super) global_delivery_count: usize,
    pub(super) global_expired_gap_pairs: usize,
}

pub(super) struct AuthorityAccounting {
    pub(super) pending_bytes: usize,
    pub(super) pending_count: usize,
    pub(super) snapshot_bytes: usize,
    pub(super) snapshot_count: usize,
    pub(super) replay_count: usize,
    pub(super) delivery_bytes: usize,
    pub(super) delivery_count: usize,
    pub(super) expired_gap_pairs: usize,
}

impl Drop for RosterMember {
    fn drop(&mut self) {
        self.username.zeroize();
        self.stable_identity.zeroize();
    }
}

impl Drop for RecoverySnapshot {
    fn drop(&mut self) {
        self.membership_digest.zeroize();
        self.state_envelope.zeroize();
        self.roster.clear();
    }
}

impl Drop for JoinRequest {
    fn drop(&mut self) {
        self.request_id.zeroize();
        self.room_id.zeroize();
        self.code_id.zeroize();
        self.username.zeroize();
        self.stable_identity.zeroize();
        self.key_package.zeroize();
    }
}

impl Drop for LeaveRequest {
    fn drop(&mut self) {
        self.request_id.zeroize();
        self.room_id.zeroize();
        self.code_id.zeroize();
        self.username.zeroize();
        self.stable_identity.zeroize();
    }
}

impl Drop for PendingJoin {
    fn drop(&mut self) {
        self.state_envelope.zeroize();
    }
}

impl Drop for MembershipTransition {
    fn drop(&mut self) {
        self.room_id.zeroize();
        self.message_id.zeroize();
        self.request_id.zeroize();
        self.group_id.zeroize();
        self.from_membership_digest.zeroize();
        self.membership_digest.zeroize();
        self.roster.clear();
        self.control.zeroize();
        self.welcome.zeroize();
        self.authenticated_data.zeroize();
        self.state_envelope.zeroize();
    }
}

impl Drop for ApplicationAdmission {
    fn drop(&mut self) {
        self.message_id.zeroize();
        self.room_id.zeroize();
        self.sender_username.zeroize();
        self.recipient_code_ids.zeroize();
        self.recipient_revisions.zeroize();
        self.membership_digest.zeroize();
        self.ciphertext.zeroize();
        self.authenticated_data.zeroize();
        self.state_envelope.zeroize();
    }
}

impl Drop for PendingApplication {
    fn drop(&mut self) {
        self.sender_code_id.zeroize();
        self.admission.state_envelope.zeroize();
    }
}

impl Drop for DeliveryPayload {
    fn drop(&mut self) {
        match self {
            Self::Membership {
                from_membership_digest,
                group_id,
                roster,
                control,
                welcome,
                authenticated_data,
                ..
            } => {
                from_membership_digest.zeroize();
                group_id.zeroize();
                roster.clear();
                control.zeroize();
                welcome.zeroize();
                authenticated_data.zeroize();
            }
            Self::Application {
                sender_code_id,
                sender_username,
                ciphertext,
                authenticated_data,
                ..
            } => {
                sender_code_id.zeroize();
                sender_username.zeroize();
                ciphertext.zeroize();
                authenticated_data.zeroize();
            }
        }
    }
}

impl Drop for PendingDelivery {
    fn drop(&mut self) {
        self.room_id.zeroize();
        self.message_id.zeroize();
        self.recipient_code_id.zeroize();
        self.membership_digest.zeroize();
    }
}

impl Drop for StateSnapshot {
    fn drop(&mut self) {
        self.room_id.zeroize();
        self.message_id.zeroize();
        self.member_code_id.zeroize();
        self.membership_digest.zeroize();
        self.state_envelope.zeroize();
        self.roster.clear();
    }
}

impl Drop for Member {
    fn drop(&mut self) {
        self.username.zeroize();
        self.code_id.zeroize();
        self.stable_identity.zeroize();
    }
}

impl Drop for RelayRoom {
    fn drop(&mut self) {
        self.room_id.zeroize();
        self.owner_code_id.zeroize();
        self.owner_username.zeroize();
        self.group_id.zeroize();
        self.membership_digest.zeroize();
        self.members.clear();
        self.joins.clear();
        self.leaves.clear();
        self.pending_transition = None;
        self.pending_applications.clear();
        self.replay_ids.clear();
        self.snapshots.clear();
        self.member_revisions.clear();
        self.deliveries.clear();
        self.expired_sender_gaps.clear();
    }
}

impl Drop for RoomAuthority {
    fn drop(&mut self) {
        self.rooms.clear();
    }
}
