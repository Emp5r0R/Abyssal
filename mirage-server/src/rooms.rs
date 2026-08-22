//! Protocol-v10 MLS room authority.
//!
//! The relay never decrypts MLS records or constructs an MLS group.  It keeps
//! only the authenticated routing metadata and bounded encrypted records that
//! are needed to coordinate clients.  Direct conversations remain outside
//! this module.

use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroize;

pub const GROUP_ID_BYTES: usize = 32;
pub const MLS_PROTOCOL_VERSION: u32 = 10;
pub const MEMBERSHIP_DIGEST_BYTES: usize = 32;
pub const STABLE_IDENTITY_BYTES: usize = 64;
pub const MAX_ROOM_ID_BYTES: usize = 128;
pub const MAX_USERNAME_BYTES: usize = 80;
pub const MAX_MEMBERS: usize = 117;
pub const MAX_ROOMS_PER_MEMBER: usize = 128;
pub const MAX_JOIN_REQUESTS: usize = 128;
pub const MAX_LEAVE_REQUESTS: usize = 128;
pub const MAX_GLOBAL_LEAVE_REQUESTS: usize = 16_384;
pub const MAX_KEY_PACKAGE_BYTES: usize = 64 * 1024;
pub const MAX_CONTROL_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_APPLICATION_CIPHERTEXT_BYTES: usize = 1024 * 1024;
pub const MAX_AUTHENTICATED_DATA_BYTES: usize = 4096;
pub const MAX_PENDING_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_PENDING_APPLICATIONS: usize = 2048;
pub const MAX_GLOBAL_PENDING_APPLICATIONS: usize = 16_384;
pub const MAX_GLOBAL_PENDING_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_REPLAY_IDS: usize = 2048;
pub const MAX_GLOBAL_REPLAY_IDS: usize = 16_384;
pub const MAX_STATE_SNAPSHOTS: usize = 117;
pub const MAX_STATE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_GLOBAL_STATE_SNAPSHOTS: usize = 16_384;
pub const MAX_GLOBAL_STATE_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_ROOMS_TOTAL: usize = 1024;
pub const MAX_DELIVERIES_PER_ROOM: usize = 4096;
pub const MAX_GLOBAL_DELIVERIES: usize = 16_384;
pub const MAX_GLOBAL_DELIVERY_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_RATCHET_BACK_HISTORY: u16 = 1024;
const MAX_EXPIRED_GAP_PAIRS_PER_ROOM: usize = MAX_MEMBERS * MAX_MEMBERS;
const MAX_GLOBAL_EXPIRED_GAP_PAIRS: usize = 65_536;
pub const DEFAULT_JOIN_TTL_MS: u64 = 10 * 60 * 1000;
#[allow(dead_code)]
pub const DEFAULT_PENDING_TTL_MS: u64 = 10 * 60 * 1000;
pub const DEFAULT_REPLAY_TTL_MS: u64 = 24 * 60 * 60 * 1000;
#[allow(dead_code)]
pub const DEFAULT_STATE_TTL_MS: u64 = 10 * 60 * 1000;

pub type CodeId = [u8; 32];

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum ReplayDomain {
    Membership,
    Application,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReplayKey {
    domain: ReplayDomain,
    message_id: String,
}

impl ReplayKey {
    fn membership(message_id: &str) -> Self {
        Self {
            domain: ReplayDomain::Membership,
            message_id: message_id.to_string(),
        }
    }

    fn application(message_id: &str) -> Self {
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RoomPolicy {
    #[serde(with = "crate::mls_wire::decimal_u64")]
    pub self_destruct_timer_sec: u64,
    #[serde(with = "crate::mls_wire::decimal_u64")]
    pub overall_expiry_sec: u64,
    pub allow_images: bool,
    pub allow_videos: bool,
    pub allow_files: bool,
    pub enforce_text_absolute_expiry: bool,
    #[serde(with = "crate::mls_wire::decimal_u64")]
    pub image_read_timer_sec: u64,
    #[serde(with = "crate::mls_wire::decimal_u64")]
    pub image_overall_expiry_sec: u64,
    pub enforce_image_absolute_expiry: bool,
    #[serde(with = "crate::mls_wire::decimal_u64")]
    pub video_read_timer_sec: u64,
    #[serde(with = "crate::mls_wire::decimal_u64")]
    pub video_overall_expiry_sec: u64,
    pub enforce_video_absolute_expiry: bool,
    #[serde(with = "crate::mls_wire::decimal_u64")]
    pub file_read_timer_sec: u64,
    #[serde(with = "crate::mls_wire::decimal_u64")]
    pub file_overall_expiry_sec: u64,
    pub enforce_file_absolute_expiry: bool,
}

impl Default for RoomPolicy {
    fn default() -> Self {
        Self {
            self_destruct_timer_sec: 0,
            overall_expiry_sec: 0,
            allow_images: true,
            allow_videos: true,
            allow_files: true,
            enforce_text_absolute_expiry: false,
            image_read_timer_sec: 0,
            image_overall_expiry_sec: 0,
            enforce_image_absolute_expiry: false,
            video_read_timer_sec: 0,
            video_overall_expiry_sec: 0,
            enforce_video_absolute_expiry: false,
            file_read_timer_sec: 0,
            file_overall_expiry_sec: 0,
            enforce_file_absolute_expiry: false,
        }
    }
}

impl RoomPolicy {
    fn normalized(mut self) -> Self {
        self.self_destruct_timer_sec = self.self_destruct_timer_sec.min(86_400);
        self.overall_expiry_sec = self.overall_expiry_sec.min(86_400);
        self.image_read_timer_sec = self.image_read_timer_sec.min(86_400);
        self.image_overall_expiry_sec = self.image_overall_expiry_sec.min(86_400);
        self.video_read_timer_sec = self.video_read_timer_sec.min(86_400);
        self.video_overall_expiry_sec = self.video_overall_expiry_sec.min(86_400);
        self.file_read_timer_sec = self.file_read_timer_sec.min(86_400);
        self.file_overall_expiry_sec = self.file_overall_expiry_sec.min(86_400);
        self
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

struct PendingJoin {
    request: JoinRequest,
    state_envelope: Vec<u8>,
}

impl Drop for PendingJoin {
    fn drop(&mut self) {
        self.state_envelope.zeroize();
    }
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
struct Member {
    username: String,
    code_id: CodeId,
    stable_identity: Vec<u8>,
    active: bool,
}

#[derive(Clone)]
struct PendingApplication {
    admission: ApplicationAdmission,
    sender_code_id: CodeId,
    previous_sender_revision: u64,
    previous_snapshot: Option<StateSnapshot>,
}

struct RelayRoom {
    room_id: String,
    owner_code_id: CodeId,
    owner_username: String,
    policy: RoomPolicy,
    group_id: Vec<u8>,
    epoch: u64,
    membership_digest: Vec<u8>,
    members: BTreeMap<String, Member>,
    joins: HashMap<String, PendingJoin>,
    leaves: HashMap<String, LeaveRequest>,
    pending_transition: Option<MembershipTransition>,
    pending_applications: HashMap<String, PendingApplication>,
    pending_bytes: usize,
    replay_ids: VecDeque<(ReplayKey, u64)>,
    snapshots: HashMap<CodeId, StateSnapshot>,
    snapshot_bytes: usize,
    member_revisions: HashMap<CodeId, u64>,
    deliveries: HashMap<CodeId, VecDeque<PendingDelivery>>,
    delivery_bytes: usize,
    expired_sender_gaps: HashMap<(CodeId, CodeId), u16>,
}

pub struct RoomAuthority {
    rooms: HashMap<String, RelayRoom>,
    max_rooms: usize,
    join_ttl_ms: u64,
    pending_ttl_ms: u64,
    replay_ttl_ms: u64,
    max_delivery_count: usize,
    max_delivery_bytes: usize,
    global_pending_bytes: usize,
    global_pending_count: usize,
    global_snapshot_bytes: usize,
    global_snapshot_count: usize,
    global_replay_count: usize,
    global_delivery_bytes: usize,
    global_delivery_count: usize,
    global_expired_gap_pairs: usize,
}

struct AuthorityAccounting {
    pending_bytes: usize,
    pending_count: usize,
    snapshot_bytes: usize,
    snapshot_count: usize,
    replay_count: usize,
    delivery_bytes: usize,
    delivery_count: usize,
    expired_gap_pairs: usize,
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

impl RoomAuthority {
    #[allow(dead_code)]
    pub fn new(max_rooms: usize) -> Self {
        Self::new_with_pending_ttl(max_rooms, DEFAULT_PENDING_TTL_MS)
    }

    pub fn new_with_pending_ttl(max_rooms: usize, pending_ttl_ms: u64) -> Self {
        Self {
            rooms: HashMap::new(),
            max_rooms: max_rooms.max(1),
            join_ttl_ms: DEFAULT_JOIN_TTL_MS,
            pending_ttl_ms,
            replay_ttl_ms: DEFAULT_REPLAY_TTL_MS,
            max_delivery_count: MAX_GLOBAL_DELIVERIES,
            max_delivery_bytes: MAX_GLOBAL_DELIVERY_BYTES,
            global_pending_bytes: 0,
            global_pending_count: 0,
            global_snapshot_bytes: 0,
            global_snapshot_count: 0,
            global_replay_count: 0,
            global_delivery_bytes: 0,
            global_delivery_count: 0,
            global_expired_gap_pairs: 0,
        }
    }

    #[cfg(test)]
    pub fn with_ttls(
        max_rooms: usize,
        join_ttl_ms: u64,
        pending_ttl_ms: u64,
        replay_ttl_ms: u64,
        _state_ttl_ms: u64,
    ) -> Self {
        Self {
            rooms: HashMap::new(),
            max_rooms: max_rooms.max(1),
            join_ttl_ms,
            pending_ttl_ms,
            replay_ttl_ms,
            max_delivery_count: MAX_GLOBAL_DELIVERIES,
            max_delivery_bytes: MAX_GLOBAL_DELIVERY_BYTES,
            global_pending_bytes: 0,
            global_pending_count: 0,
            global_snapshot_bytes: 0,
            global_snapshot_count: 0,
            global_replay_count: 0,
            global_delivery_bytes: 0,
            global_delivery_count: 0,
            global_expired_gap_pairs: 0,
        }
    }

    #[allow(dead_code)]
    pub fn room_count(&self) -> usize {
        self.rooms.len()
    }

    #[cfg(test)]
    fn set_delivery_limits(&mut self, count: usize, bytes: usize) {
        self.max_delivery_count = count;
        self.max_delivery_bytes = bytes;
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)]
    pub fn create(
        &mut self,
        owner_code_id: CodeId,
        owner_username: String,
        room_id: String,
        group_id: Vec<u8>,
        epoch: u64,
        revision: u64,
        membership_digest: Vec<u8>,
        stable_identity: Vec<u8>,
    ) -> Result<RoomInfo, String> {
        self.create_with_policy_and_state(
            owner_code_id,
            owner_username,
            room_id,
            group_id,
            epoch,
            revision,
            membership_digest,
            stable_identity,
            RoomPolicy::default(),
            vec![1],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_with_policy_and_state(
        &mut self,
        owner_code_id: CodeId,
        owner_username: String,
        room_id: String,
        group_id: Vec<u8>,
        epoch: u64,
        revision: u64,
        membership_digest: Vec<u8>,
        stable_identity: Vec<u8>,
        policy: RoomPolicy,
        state_envelope: Vec<u8>,
    ) -> Result<RoomInfo, String> {
        self.prune_expired(now_ms());
        validate_room_id(&room_id)?;
        validate_username(&owner_username)?;
        validate_group_id(&group_id)?;
        validate_digest(&membership_digest)?;
        validate_stable_identity(&stable_identity)?;
        validate_state_envelope(&state_envelope)?;
        if epoch != 0 || revision != 0 {
            return Err("room initial checkpoint rejected".to_string());
        }
        if self.rooms.len() >= MAX_ROOMS_TOTAL {
            return Err("room catalog limit reached".to_string());
        }
        if self
            .rooms
            .values()
            .filter(|room| room.owner_code_id == owner_code_id)
            .count()
            >= self.max_rooms
        {
            return Err("room limit reached".to_string());
        }
        if self.rooms.contains_key(&room_id) {
            return Err("room already exists".to_string());
        }
        let next_global_snapshot_count = self
            .global_snapshot_count
            .checked_add(1)
            .ok_or_else(|| "global state snapshot budget reached".to_string())?;
        let initial_roster = vec![RosterMember {
            username: canonical_username(&owner_username)?,
            stable_identity: stable_identity.clone(),
        }];
        let initial_snapshot_bytes = state_envelope
            .len()
            .checked_add(roster_size(&initial_roster)?)
            .ok_or_else(|| "global state snapshot budget reached".to_string())?;
        let next_global_snapshot_bytes = self
            .global_snapshot_bytes
            .checked_add(initial_snapshot_bytes)
            .ok_or_else(|| "global state snapshot budget reached".to_string())?;
        if next_global_snapshot_count > MAX_GLOBAL_STATE_SNAPSHOTS
            || next_global_snapshot_bytes > MAX_GLOBAL_STATE_BYTES
        {
            return Err("global state snapshot budget reached".to_string());
        }
        let mut members = BTreeMap::new();
        members.insert(
            canonical_username(&owner_username)?,
            Member {
                username: owner_username.clone(),
                code_id: owner_code_id,
                stable_identity: stable_identity.clone(),
                active: true,
            },
        );
        let now = now_ms();
        let initial_snapshot = StateSnapshot {
            room_id: room_id.clone(),
            message_id: String::new(),
            member_code_id: owner_code_id,
            epoch: 0,
            revision: 0,
            membership_digest: membership_digest.clone(),
            state_envelope,
            roster: initial_roster,
            created_at_ms: now,
            expires_at_ms: u64::MAX,
        };
        let mut room = RelayRoom {
            room_id: room_id.clone(),
            owner_code_id,
            owner_username,
            policy: policy.normalized(),
            group_id,
            epoch: 0,
            membership_digest,
            members,
            joins: HashMap::new(),
            leaves: HashMap::new(),
            pending_transition: None,
            pending_applications: HashMap::new(),
            pending_bytes: 0,
            replay_ids: VecDeque::new(),
            snapshots: HashMap::new(),
            snapshot_bytes: 0,
            member_revisions: HashMap::from([(owner_code_id, 0)]),
            deliveries: HashMap::new(),
            delivery_bytes: 0,
            expired_sender_gaps: HashMap::new(),
        };
        room.snapshot_bytes = snapshot_size(&initial_snapshot)?;
        room.snapshots.insert(owner_code_id, initial_snapshot);
        let info = room_info_for(&room, Some(&owner_code_id), true);
        self.rooms.insert(room_id, room);
        self.global_snapshot_count = next_global_snapshot_count;
        self.global_snapshot_bytes = next_global_snapshot_bytes;
        Ok(info)
    }

    #[allow(dead_code)]
    pub fn info(&mut self, room_id: &str) -> Option<RoomInfo> {
        self.prune_expired(now_ms());
        self.rooms
            .get(room_id)
            .map(|room| room_info_for(room, Some(&room.owner_code_id), true))
    }

    pub fn member_code_ids(&mut self, room_id: &str) -> Result<Vec<CodeId>, String> {
        self.prune_expired(now_ms());
        let room = self.room(room_id)?;
        Ok(room.members.values().map(|member| member.code_id).collect())
    }

    pub fn active_member_code_ids(&mut self, room_id: &str) -> Result<Vec<CodeId>, String> {
        self.prune_expired(now_ms());
        let room = self.room(room_id)?;
        Ok(room
            .members
            .values()
            .filter(|member| member.active)
            .map(|member| member.code_id)
            .collect())
    }

    #[allow(dead_code)]
    pub fn member_revision(&mut self, room_id: &str, code_id: &CodeId) -> Result<u64, String> {
        self.prune_expired(now_ms());
        let room = self.room(room_id)?;
        if !room
            .members
            .values()
            .any(|member| member.code_id == *code_id)
        {
            return Err("room member required".to_string());
        }
        Ok(room
            .member_revisions
            .get(code_id)
            .copied()
            .unwrap_or_default())
    }

    pub fn member_info(&mut self, room_id: &str, code_id: &CodeId) -> Result<RoomInfo, String> {
        self.prune_expired(now_ms());
        let room = self.room(room_id)?;
        if !room
            .members
            .values()
            .any(|member| member.code_id == *code_id)
        {
            return Err("room member required".to_string());
        }
        Ok(room_info_for(room, Some(code_id), true))
    }

    /// Check only whether this authenticated code has completed its Welcome
    /// snapshot. Callers use this narrow capability gate before conversation,
    /// application, or attachment operations.
    pub fn is_active_member(&mut self, room_id: &str, code_id: &CodeId) -> bool {
        self.prune_expired(now_ms());
        self.rooms.get(room_id).is_some_and(|room| {
            room.members
                .values()
                .any(|member| member.code_id == *code_id && member.active)
        })
    }

    pub fn discover(&mut self, room_id: &str) -> Result<RoomInfo, String> {
        self.prune_expired(now_ms());
        Ok(room_info_for(self.room(room_id)?, None, false))
    }

    pub fn deliveries_for_member(
        &mut self,
        room_id: &str,
        code_id: &CodeId,
    ) -> Result<Vec<PendingDelivery>, String> {
        self.prune_expired(now_ms());
        Ok(self
            .room(room_id)?
            .deliveries
            .get(code_id)
            .map(|queue| queue.iter().cloned().collect())
            .unwrap_or_default())
    }

    #[allow(dead_code)]
    pub fn pending_member_code_ids(&mut self, room_id: &str) -> Result<Vec<CodeId>, String> {
        self.prune_expired(now_ms());
        let room = self.room(room_id)?;
        let mut ids = room
            .members
            .values()
            .map(|member| member.code_id)
            .collect::<Vec<_>>();
        if let Some(transition) = &room.pending_transition {
            if let Some(request_id) = &transition.request_id {
                if let Some(request) = room.joins.get(request_id) {
                    ids.push(request.request.code_id);
                }
            }
        }
        ids.sort_unstable();
        ids.dedup();
        Ok(ids)
    }

    pub fn rooms_for_member(&mut self, code_id: &CodeId) -> Vec<RoomInfo> {
        self.prune_expired(now_ms());
        self.rooms
            .values()
            .filter(|room| {
                room.members
                    .values()
                    .any(|member| member.code_id == *code_id)
            })
            .map(|room| room_info_for(room, Some(code_id), true))
            .collect()
    }

    /// Return only the inactive recovery records owned by this joining code.
    /// The owner-facing join list intentionally has no state envelope field.
    pub fn pending_rooms_for_member(&mut self, code_id: &CodeId) -> Vec<RoomInfo> {
        self.prune_expired(now_ms());
        self.rooms
            .values()
            .filter_map(|room| {
                room.joins
                    .values()
                    .find(|join| join.request.code_id == *code_id)
                    .map(|join| pending_room_info_for(room, &join.state_envelope))
            })
            .collect()
    }

    /// Remove a pending join without revealing or returning its private state.
    pub fn remove_join(
        &mut self,
        owner_code_id: CodeId,
        room_id: &str,
        request_id: &str,
    ) -> Result<JoinRequest, String> {
        self.prune_expired(now_ms());
        let room = self.room_mut(room_id)?;
        if room.owner_code_id != owner_code_id {
            return Err("room owner required".to_string());
        }
        let request = room
            .joins
            .remove(request_id)
            .map(|pending| pending.request.clone())
            .ok_or_else(|| "join request unavailable".to_string())?;
        self.recompute_state_accounting()?;
        Ok(request)
    }

    pub fn request_leave(
        &mut self,
        code_id: CodeId,
        room_id: &str,
        request_id: String,
    ) -> Result<LeaveRequest, String> {
        let now = now_ms();
        let expires_at_ms = now.saturating_add(self.join_ttl_ms);
        self.prune_expired(now);
        validate_request_id(&request_id)?;
        let global_leave_count = self
            .rooms
            .values()
            .map(|room| room.leaves.len())
            .try_fold(0_usize, usize::checked_add)
            .ok_or_else(|| "leave request limit reached".to_string())?;
        let room = self.room_mut(room_id)?;
        if room.owner_code_id == code_id {
            return Err("room owner cannot leave".to_string());
        }
        let (_, member) = room
            .members
            .iter()
            .find(|(_, member)| member.code_id == code_id && member.active)
            .ok_or_else(|| "active room member required".to_string())?;
        if room.joins.contains_key(&request_id) {
            return Err("membership request already exists".to_string());
        }
        if let Some(existing) = room.leaves.get(&request_id) {
            if existing.code_id == code_id && existing.username == member.username {
                return Ok(existing.clone());
            }
            return Err("leave request already exists".to_string());
        }
        if room.leaves.len() >= MAX_LEAVE_REQUESTS
            || global_leave_count >= MAX_GLOBAL_LEAVE_REQUESTS
            || room.leaves.values().any(|leave| leave.code_id == code_id)
        {
            return Err("leave request limit reached".to_string());
        }
        let request = LeaveRequest {
            request_id: request_id.clone(),
            room_id: room_id.to_string(),
            code_id,
            username: member.username.clone(),
            stable_identity: member.stable_identity.clone(),
            created_at_ms: now,
            expires_at_ms,
        };
        room.leaves.insert(request_id, request.clone());
        Ok(request)
    }

    pub fn remove_leave(
        &mut self,
        owner_code_id: CodeId,
        room_id: &str,
        request_id: &str,
    ) -> Result<LeaveRequest, String> {
        self.prune_expired(now_ms());
        let room = self.room_mut(room_id)?;
        if room.owner_code_id != owner_code_id {
            return Err("room owner required".to_string());
        }
        room.leaves
            .remove(request_id)
            .ok_or_else(|| "leave request unavailable".to_string())
    }

    pub fn pending_leaves_for_owner(&mut self, owner_code_id: &CodeId) -> Vec<LeaveRequest> {
        self.prune_expired(now_ms());
        let mut leaves = self
            .rooms
            .values()
            .filter(|room| room.owner_code_id == *owner_code_id)
            .flat_map(|room| room.leaves.values().cloned())
            .collect::<Vec<_>>();
        leaves.sort_by(|left, right| {
            left.created_at_ms
                .cmp(&right.created_at_ms)
                .then_with(|| left.room_id.cmp(&right.room_id))
                .then_with(|| left.request_id.cmp(&right.request_id))
        });
        leaves.truncate(MAX_LEAVE_REQUESTS);
        leaves
    }

    pub fn pending_leaves_for_member(&mut self, code_id: &CodeId) -> Vec<LeaveRequest> {
        self.prune_expired(now_ms());
        self.rooms
            .values()
            .flat_map(|room| room.leaves.values())
            .filter(|leave| leave.code_id == *code_id)
            .cloned()
            .collect()
    }

    #[allow(dead_code)]
    pub fn is_member(&mut self, room_id: &str, code_id: &CodeId) -> bool {
        self.prune_expired(now_ms());
        self.rooms.get(room_id).is_some_and(|room| {
            room.members
                .values()
                .any(|member| member.code_id == *code_id)
        })
    }

    pub fn owner_code_id(&mut self, room_id: &str) -> Result<CodeId, String> {
        self.prune_expired(now_ms());
        Ok(self.room(room_id)?.owner_code_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn request_join(
        &mut self,
        code_id: CodeId,
        username: String,
        room_id: &str,
        request_id: String,
        stable_identity: Vec<u8>,
        key_package: Vec<u8>,
        state_envelope: Vec<u8>,
    ) -> Result<JoinRequest, String> {
        let now = now_ms();
        let join_ttl_ms = self.join_ttl_ms;
        self.prune_expired(now);
        let current_global_state_count = self.global_snapshot_count;
        let current_global_state_bytes = self.global_snapshot_bytes;
        validate_username(&username)?;
        validate_request_id(&request_id)?;
        validate_stable_identity(&stable_identity)?;
        if key_package.is_empty() || key_package.len() > MAX_KEY_PACKAGE_BYTES {
            return Err("key package rejected".to_string());
        }
        validate_state_envelope(&state_envelope)?;
        let member_room_count = self
            .rooms
            .values()
            .filter(|room| {
                room.members
                    .values()
                    .any(|member| member.code_id == code_id)
                    || room
                        .joins
                        .values()
                        .any(|join| join.request.code_id == code_id)
            })
            .count();
        let already_present = self.rooms.get(room_id).is_some_and(|room| {
            room.members
                .values()
                .any(|member| member.code_id == code_id)
                || room
                    .joins
                    .values()
                    .any(|join| join.request.code_id == code_id)
        });
        if !already_present && member_room_count >= MAX_ROOMS_PER_MEMBER {
            return Err("member room limit reached".to_string());
        }
        let room = self.room_mut(room_id)?;
        if room.leaves.contains_key(&request_id) {
            return Err("membership request already exists".to_string());
        }
        let canonical = canonical_username(&username)?;
        if room.members.contains_key(&canonical)
            || room.members.values().any(|member| {
                member.code_id == code_id || member.stable_identity == stable_identity
            })
        {
            return Err("room member already exists".to_string());
        }
        if room.joins.len() >= MAX_JOIN_REQUESTS && !room.joins.contains_key(&request_id) {
            return Err("join request limit reached".to_string());
        }
        if room.joins.values().any(|join| {
            canonical_username(&join.request.username).as_deref() == Ok(canonical.as_str())
                || join.request.code_id == code_id
                || join.request.stable_identity == stable_identity
        }) && !room.joins.contains_key(&request_id)
        {
            return Err("join request already exists".to_string());
        }
        if let Some(existing) = room.joins.get(&request_id) {
            if existing.request.code_id == code_id
                && existing.request.username == username
                && existing.request.stable_identity == stable_identity
                && existing.request.key_package == key_package
                && existing.state_envelope == state_envelope
            {
                return Ok(existing.request.clone());
            }
            return Err("join request already exists".to_string());
        }
        let state_count = room
            .snapshots
            .len()
            .checked_add(room.joins.len())
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| "state snapshot budget reached".to_string())?;
        let state_bytes = room
            .snapshot_bytes
            .checked_add(
                room.joins
                    .values()
                    .map(|join| join.state_envelope.len())
                    .try_fold(0_usize, usize::checked_add)
                    .ok_or_else(|| "state snapshot budget reached".to_string())?,
            )
            .and_then(|bytes| bytes.checked_add(state_envelope.len()))
            .ok_or_else(|| "state snapshot budget reached".to_string())?;
        if state_count > MAX_STATE_SNAPSHOTS || state_bytes > MAX_STATE_BYTES {
            return Err("state snapshot budget reached".to_string());
        }
        let global_state_count = current_global_state_count
            .checked_add(1)
            .ok_or_else(|| "global state snapshot budget reached".to_string())?;
        let global_state_bytes = current_global_state_bytes
            .checked_add(state_envelope.len())
            .ok_or_else(|| "global state snapshot budget reached".to_string())?;
        if global_state_count > MAX_GLOBAL_STATE_SNAPSHOTS
            || global_state_bytes > MAX_GLOBAL_STATE_BYTES
        {
            return Err("global state snapshot budget reached".to_string());
        }
        let request = JoinRequest {
            request_id: request_id.clone(),
            room_id: room_id.to_string(),
            code_id,
            username,
            stable_identity,
            key_package,
            created_at_ms: now,
            expires_at_ms: now.saturating_add(join_ttl_ms),
        };
        room.joins.insert(
            request_id,
            PendingJoin {
                request: request.clone(),
                state_envelope,
            },
        );
        self.global_snapshot_count = global_state_count;
        self.global_snapshot_bytes = global_state_bytes;
        Ok(request)
    }

    #[allow(dead_code)]
    pub fn pending_joins(&mut self, room_id: &str) -> Result<Vec<JoinRequest>, String> {
        self.prune_expired(now_ms());
        Ok(self
            .room(room_id)?
            .joins
            .values()
            .map(|join| join.request.clone())
            .collect())
    }

    pub fn pending_joins_for_owner(&mut self, owner_code_id: &CodeId) -> Vec<JoinRequest> {
        self.prune_expired(now_ms());
        let mut joins = self
            .rooms
            .values()
            .filter(|room| room.owner_code_id == *owner_code_id)
            .flat_map(|room| room.joins.values().map(|join| join.request.clone()))
            .collect::<Vec<_>>();
        joins.sort_by(|left, right| {
            left.created_at_ms
                .cmp(&right.created_at_ms)
                .then_with(|| left.room_id.cmp(&right.room_id))
                .then_with(|| left.request_id.cmp(&right.request_id))
        });
        joins.truncate(MAX_JOIN_REQUESTS);
        joins
    }

    pub fn begin_membership(
        &mut self,
        owner_code_id: CodeId,
        transition: MembershipTransition,
    ) -> Result<MembershipTransition, String> {
        let now = now_ms();
        let pending_ttl_ms = self.pending_ttl_ms;
        self.prune_expired(now);
        validate_transition(&transition)?;
        let room = self.room_mut(&transition.room_id)?;
        if room.owner_code_id != owner_code_id {
            return Err("room owner required".to_string());
        }
        if room
            .deliveries
            .get(&owner_code_id)
            .is_some_and(|queue| !queue.is_empty())
        {
            return Err("owner delivery snapshot required".to_string());
        }
        if !room.pending_applications.is_empty() {
            return Err("application admission in flight".to_string());
        }
        if room.pending_transition.is_some() {
            return Err("membership transition already in flight".to_string());
        }
        let membership_replay = ReplayKey::membership(&transition.message_id);
        if room
            .replay_ids
            .iter()
            .any(|(key, _)| key == &membership_replay)
        {
            return Err("membership replay rejected".to_string());
        }
        validate_digest(&transition.from_membership_digest)?;
        validate_current_metadata(
            room,
            &transition.group_id,
            transition.from_epoch,
            &transition.from_membership_digest,
        )?;
        let expected_epoch = transition
            .from_epoch
            .checked_add(1)
            .ok_or_else(|| "membership epoch rejected".to_string())?;
        if transition.to_epoch != expected_epoch {
            return Err("membership epoch rejected".to_string());
        }
        let owner_revision = room
            .member_revisions
            .get(&owner_code_id)
            .copied()
            .ok_or_else(|| "room owner unavailable".to_string())?;
        let expected_revision = owner_revision
            .checked_add(1)
            .ok_or_else(|| "membership revision rejected".to_string())?;
        if transition.revision != expected_revision {
            return Err("membership revision rejected".to_string());
        }
        let next = resolve_next_roster(room, &transition)?;
        let owner_username = canonical_username(&room.owner_username)?;
        if next.len() > MAX_MEMBERS || !next.contains_key(&owner_username) {
            return Err("membership roster rejected".to_string());
        }
        let changed = changed_usernames(&room.members, &next);
        if changed.len() != 1 {
            return Err("membership transition rejected".to_string());
        }
        let changed_username = changed
            .iter()
            .next()
            .ok_or_else(|| "membership transition rejected".to_string())?;
        if next.contains_key(changed_username) {
            if transition.welcome.is_empty() {
                return Err("membership welcome rejected".to_string());
            }
            let request_id = transition
                .request_id
                .as_ref()
                .ok_or_else(|| "join request required".to_string())?;
            let request = room
                .joins
                .get(request_id)
                .ok_or_else(|| "join request unavailable".to_string())?;
            if canonical_username(&request.request.username)? != *changed_username
                || next
                    .get(changed_username)
                    .map(|member| member.stable_identity.as_slice())
                    != Some(request.request.stable_identity.as_slice())
            {
                return Err("join request binding rejected".to_string());
            }
            let member = next
                .get(changed_username)
                .ok_or_else(|| "join request binding rejected".to_string())?;
            if member.stable_identity != request.request.stable_identity
                || member.code_id != request.request.code_id
            {
                return Err("join request binding rejected".to_string());
            }
        } else {
            if !transition.welcome.is_empty() {
                return Err("membership welcome rejected".to_string());
            }
            if let Some(request_id) = &transition.request_id {
                let leave = room
                    .leaves
                    .get(request_id)
                    .ok_or_else(|| "leave request unavailable".to_string())?;
                let member = room
                    .members
                    .get(changed_username)
                    .ok_or_else(|| "leave request binding rejected".to_string())?;
                if canonical_username(&leave.username)? != *changed_username
                    || leave.code_id != member.code_id
                    || leave.stable_identity != member.stable_identity
                {
                    return Err("leave request binding rejected".to_string());
                }
            }
        }
        let mut staged = transition;
        staged.created_at_ms = now;
        staged.expires_at_ms = now.saturating_add(pending_ttl_ms);
        room.pending_transition = Some(staged.clone());
        Ok(staged)
    }

    pub fn accept_membership(
        &mut self,
        owner_code_id: CodeId,
        room_id: &str,
        message_id: &str,
        revision: u64,
    ) -> Result<MembershipResult, String> {
        self.prune_expired(now_ms());
        let global_delivery_count = self.global_delivery_count;
        let global_delivery_bytes = self.global_delivery_bytes;
        let max_delivery_count = self.max_delivery_count;
        let max_delivery_bytes = self.max_delivery_bytes;
        let global_snapshot_count = self.global_snapshot_count;
        let global_snapshot_bytes = self.global_snapshot_bytes;
        let (transition, next_global_snapshot_count, next_global_snapshot_bytes) = {
            let room = self.room_mut(room_id)?;
            if room.owner_code_id != owner_code_id {
                return Err("room owner required".to_string());
            }
            let transition = room
                .pending_transition
                .as_ref()
                .cloned()
                .ok_or_else(|| "membership transition unavailable".to_string())?;
            if transition.message_id != message_id || transition.revision != revision {
                return Err("membership result mismatch".to_string());
            }
            if !room.pending_applications.is_empty() {
                return Err("application admission in flight".to_string());
            }
            let membership_replay = ReplayKey::membership(&transition.message_id);
            if room
                .replay_ids
                .iter()
                .any(|(key, _)| key == &membership_replay)
            {
                return Err("membership replay rejected".to_string());
            }
            let next = resolve_next_roster(room, &transition)?;
            let next_code_ids = next
                .values()
                .map(|member| member.code_id)
                .collect::<HashSet<_>>();
            let mut removed_code_ids = HashSet::new();
            for code_id in room.deliveries.keys().chain(room.snapshots.keys()) {
                if !next_code_ids.contains(code_id) {
                    removed_code_ids.insert(*code_id);
                }
            }
            let removed_delivery_count = removed_code_ids
                .iter()
                .filter_map(|code_id| room.deliveries.get(code_id))
                .map(VecDeque::len)
                .try_fold(0_usize, usize::checked_add)
                .ok_or_else(|| "room delivery budget reached".to_string())?;
            let removed_delivery_bytes = delivery_bytes(
                removed_code_ids
                    .iter()
                    .filter_map(|code_id| room.deliveries.get(code_id))
                    .flat_map(|queue| queue.iter()),
            )?;
            let removed_snapshot_count = removed_code_ids
                .iter()
                .filter(|code_id| room.snapshots.contains_key(*code_id))
                .count();
            let removed_snapshot_bytes = removed_code_ids
                .iter()
                .filter_map(|code_id| room.snapshots.get(code_id))
                .try_fold(0_usize, |total, snapshot| {
                    total
                        .checked_add(snapshot_size(snapshot)?)
                        .ok_or_else(|| "state snapshot accounting rejected".to_string())
                })?;
            let deliveries = membership_deliveries(room, &transition, &next)?;
            let queued_count = deliveries.len();
            let queued_bytes = delivery_bytes(deliveries.iter())?;
            let room_delivery_count = room
                .deliveries
                .values()
                .map(VecDeque::len)
                .try_fold(0_usize, usize::checked_add)
                .and_then(|count| count.checked_sub(removed_delivery_count))
                .and_then(|count| count.checked_add(queued_count));
            let next_global_delivery_count = global_delivery_count
                .checked_sub(removed_delivery_count)
                .and_then(|count| count.checked_add(queued_count));
            let next_global_delivery_bytes = global_delivery_bytes
                .checked_sub(removed_delivery_bytes)
                .and_then(|bytes| bytes.checked_add(queued_bytes));
            let next_room_delivery_bytes = room
                .delivery_bytes
                .checked_sub(removed_delivery_bytes)
                .and_then(|bytes| bytes.checked_add(queued_bytes));
            if room_delivery_count.is_none_or(|count| count > MAX_DELIVERIES_PER_ROOM)
                || next_global_delivery_count.is_none_or(|count| count > max_delivery_count)
                || next_global_delivery_bytes.is_none_or(|bytes| bytes > max_delivery_bytes)
                || next_room_delivery_bytes.is_none()
            {
                return Err("room delivery budget reached".to_string());
            }
            let previous_snapshot_bytes = room
                .snapshots
                .get(&owner_code_id)
                .map(snapshot_size)
                .transpose()?
                .unwrap_or_default();
            let owner_snapshot_bytes = transition
                .state_envelope
                .len()
                .checked_add(roster_size(&transition.roster)?)
                .ok_or_else(|| "state snapshot budget reached".to_string())?;
            let new_snapshot = !room.snapshots.contains_key(&owner_code_id);
            let pending_join = transition
                .request_id
                .as_ref()
                .and_then(|request_id| room.joins.get(request_id))
                .map(|join| (join.request.code_id, join.state_envelope.clone()));
            let pending_leave = transition
                .request_id
                .as_ref()
                .and_then(|request_id| room.leaves.get(request_id))
                .cloned();
            if transition.request_id.is_some()
                && (pending_join.is_some() == pending_leave.is_some())
            {
                return Err("membership request unavailable".to_string());
            }
            let pending_join_bytes = pending_join
                .as_ref()
                .map(|(_, state_envelope)| state_envelope.len())
                .unwrap_or_default();
            let all_join_bytes = room
                .joins
                .values()
                .map(|join| join.state_envelope.len())
                .try_fold(0_usize, usize::checked_add)
                .ok_or_else(|| "state snapshot budget reached".to_string())?;
            let room_state_count = room
                .snapshots
                .len()
                .checked_sub(removed_snapshot_count)
                .and_then(|count| count.checked_add(room.joins.len()))
                .and_then(|count| count.checked_sub(usize::from(pending_join.is_some())))
                .and_then(|count| count.checked_add(if new_snapshot { 1 } else { 0 }))
                .and_then(|count| count.checked_add(if pending_join.is_some() { 1 } else { 0 }));
            let global_state_count = global_snapshot_count
                .checked_sub(removed_snapshot_count)
                .and_then(|count| count.checked_add(if new_snapshot { 1 } else { 0 }));
            let next_room_snapshot_bytes = room
                .snapshot_bytes
                .checked_sub(removed_snapshot_bytes)
                .and_then(|bytes| bytes.checked_sub(previous_snapshot_bytes))
                .and_then(|bytes| bytes.checked_add(owner_snapshot_bytes))
                .and_then(|bytes| bytes.checked_add(pending_join_bytes));
            let room_state_bytes = next_room_snapshot_bytes
                .and_then(|bytes| bytes.checked_add(all_join_bytes))
                .and_then(|bytes| bytes.checked_sub(pending_join_bytes));
            let global_state_bytes = global_snapshot_bytes
                .checked_sub(removed_snapshot_bytes)
                .and_then(|bytes| bytes.checked_sub(previous_snapshot_bytes))
                .and_then(|bytes| bytes.checked_add(owner_snapshot_bytes));
            if room_state_count.is_none_or(|count| count > MAX_STATE_SNAPSHOTS)
                || room_state_bytes.is_none_or(|bytes| bytes > MAX_STATE_BYTES)
                || global_state_count.is_none_or(|count| count > MAX_GLOBAL_STATE_SNAPSHOTS)
                || global_state_bytes.is_none_or(|bytes| bytes > MAX_GLOBAL_STATE_BYTES)
            {
                return Err("state snapshot budget reached".to_string());
            }
            let next_room_delivery_bytes = next_room_delivery_bytes
                .ok_or_else(|| "room delivery budget reached".to_string())?;
            let next_room_snapshot_bytes = next_room_snapshot_bytes
                .ok_or_else(|| "state snapshot budget reached".to_string())?;
            let global_state_count =
                global_state_count.ok_or_else(|| "state snapshot budget reached".to_string())?;
            let global_state_bytes =
                global_state_bytes.ok_or_else(|| "state snapshot budget reached".to_string())?;
            room.pending_transition = None;
            if room.replay_ids.len() >= MAX_REPLAY_IDS {
                room.replay_ids.pop_front();
            }
            room.replay_ids.push_back((membership_replay, now_ms()));
            for code_id in &removed_code_ids {
                room.deliveries.remove(code_id);
                room.snapshots.remove(code_id);
            }
            for delivery in deliveries {
                room.deliveries
                    .entry(delivery.recipient_code_id)
                    .or_default()
                    .push_back(delivery);
            }
            room.delivery_bytes = next_room_delivery_bytes;
            room.members = next;
            // MLS secret-tree generations restart at each epoch. Carrying an
            // application gap into the next membership epoch can permanently
            // block otherwise valid traffic.
            room.expired_sender_gaps.clear();
            room.epoch = transition.to_epoch;
            room.member_revisions
                .insert(owner_code_id, transition.revision);
            let member_codes = room
                .members
                .values()
                .map(|member| member.code_id)
                .collect::<Vec<_>>();
            let member_code_set = member_codes.iter().copied().collect::<HashSet<_>>();
            room.member_revisions
                .retain(|code_id, _| member_code_set.contains(code_id));
            room.leaves
                .retain(|_, leave| member_code_set.contains(&leave.code_id));
            for code_id in member_codes {
                room.member_revisions.entry(code_id).or_insert(0);
            }
            room.membership_digest = transition.membership_digest.clone();
            let snapshot = StateSnapshot {
                room_id: room.room_id.clone(),
                message_id: transition.message_id.clone(),
                member_code_id: owner_code_id,
                epoch: room.epoch,
                revision: transition.revision,
                membership_digest: room.membership_digest.clone(),
                state_envelope: transition.state_envelope.clone(),
                roster: transition.roster.clone(),
                created_at_ms: now_ms(),
                expires_at_ms: u64::MAX,
            };
            room.snapshot_bytes = next_room_snapshot_bytes;
            room.snapshots.insert(owner_code_id, snapshot);
            if let (Some(request_id), Some((member_code_id, state_envelope))) =
                (&transition.request_id, pending_join)
            {
                room.joins.remove(request_id);
                room.snapshots.insert(
                    member_code_id,
                    StateSnapshot {
                        room_id: room.room_id.clone(),
                        message_id: String::new(),
                        member_code_id,
                        epoch: 0,
                        revision: 0,
                        membership_digest: Vec::new(),
                        state_envelope,
                        roster: Vec::new(),
                        created_at_ms: now_ms(),
                        expires_at_ms: u64::MAX,
                    },
                );
            } else if let (Some(request_id), Some(_)) = (&transition.request_id, pending_leave) {
                room.leaves.remove(request_id);
            }
            (transition, global_state_count, global_state_bytes)
        };
        self.trim_replay_ids()?;
        self.global_snapshot_count = next_global_snapshot_count;
        self.global_snapshot_bytes = next_global_snapshot_bytes;
        self.global_delivery_count = self
            .rooms
            .values()
            .flat_map(|room| room.deliveries.values())
            .map(VecDeque::len)
            .try_fold(0_usize, usize::checked_add)
            .unwrap_or(usize::MAX);
        self.global_delivery_bytes = self
            .rooms
            .values()
            .map(|room| room.delivery_bytes)
            .try_fold(0_usize, usize::checked_add)
            .unwrap_or(usize::MAX);
        self.recompute_gap_accounting()?;
        Ok(MembershipResult::Accepted(Box::new(transition)))
    }

    #[allow(dead_code)]
    pub fn rollback_membership(
        &mut self,
        owner_code_id: CodeId,
        room_id: &str,
        message_id: &str,
        revision: u64,
    ) -> Result<MembershipResult, String> {
        self.prune_expired(now_ms());
        let room = self.room_mut(room_id)?;
        if room.owner_code_id != owner_code_id {
            return Err("room owner required".to_string());
        }
        let transition = room
            .pending_transition
            .as_ref()
            .ok_or_else(|| "membership transition unavailable".to_string())?;
        if transition.message_id != message_id || transition.revision != revision {
            return Err("membership result mismatch".to_string());
        }
        room.pending_transition = None;
        Ok(MembershipResult::RolledBack {
            message_id: message_id.to_string(),
            revision,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn admit_application(
        &mut self,
        sender_code_id: CodeId,
        room_id: &str,
        message_id: String,
        group_id: Vec<u8>,
        epoch: u64,
        sender_revision: u64,
        membership_digest: Vec<u8>,
        ciphertext: Vec<u8>,
        authenticated_data: Vec<u8>,
        state_envelope: Vec<u8>,
    ) -> Result<ApplicationAdmission, String> {
        let now = now_ms();
        let pending_ttl_ms = self.pending_ttl_ms;
        self.prune_expired(now);
        validate_request_id(&message_id)?;
        validate_group_id(&group_id)?;
        validate_digest(&membership_digest)?;
        if ciphertext.is_empty() || ciphertext.len() > MAX_APPLICATION_CIPHERTEXT_BYTES {
            return Err("application rejected".to_string());
        }
        if authenticated_data.is_empty() || authenticated_data.len() > MAX_AUTHENTICATED_DATA_BYTES
        {
            return Err("authenticated data rejected".to_string());
        }
        validate_state_envelope(&state_envelope)?;
        let global_delivery_count = self.global_delivery_count;
        let global_delivery_bytes = self.global_delivery_bytes;
        let max_delivery_count = self.max_delivery_count;
        let max_delivery_bytes = self.max_delivery_bytes;
        let global_pending_count = self.global_pending_count;
        let global_pending_bytes = self.global_pending_bytes;
        let global_snapshot_count = self.global_snapshot_count;
        let global_snapshot_bytes = self.global_snapshot_bytes;
        let (
            admission,
            next_global_delivery_count,
            next_global_delivery_bytes,
            next_global_pending_count,
            next_global_pending_bytes,
            next_global_snapshot_count,
            next_global_snapshot_bytes,
        ) = {
            let room = self.room_mut(room_id)?;
            validate_current_metadata(room, &group_id, epoch, &membership_digest)?;
            if room
                .deliveries
                .get(&sender_code_id)
                .is_some_and(|queue| !queue.is_empty())
            {
                return Err("sender delivery snapshot required".to_string());
            }
            if room
                .pending_applications
                .values()
                .any(|pending| pending.sender_code_id == sender_code_id)
            {
                return Err("sender application admission in flight".to_string());
            }
            if room.pending_transition.is_some() {
                return Err("membership transition in flight".to_string());
            }
            let mut application_expires_at_ms = now
                .checked_add(pending_ttl_ms)
                .ok_or_else(|| "application expiry rejected".to_string())?;
            if room.policy.enforce_text_absolute_expiry && room.policy.overall_expiry_sec > 0 {
                let policy_expiry = room
                    .policy
                    .overall_expiry_sec
                    .checked_mul(1000)
                    .and_then(|ttl| now.checked_add(ttl))
                    .ok_or_else(|| "application expiry rejected".to_string())?;
                application_expires_at_ms = application_expires_at_ms.min(policy_expiry);
            }
            let current_sender_revision = room
                .member_revisions
                .get(&sender_code_id)
                .copied()
                .ok_or_else(|| "room member required".to_string())?;
            let expected_sender_revision = current_sender_revision
                .checked_add(1)
                .ok_or_else(|| "application revision rejected".to_string())?;
            if sender_revision != expected_sender_revision {
                return Err("application revision rejected".to_string());
            }
            let sender_username = room
                .members
                .values()
                .find(|member| member.code_id == sender_code_id && member.active)
                .map(|member| member.username.clone())
                .ok_or_else(|| "active room member required".to_string())?;
            let application_replay = ReplayKey::application(&message_id);
            if room.pending_applications.contains_key(&message_id)
                || room
                    .replay_ids
                    .iter()
                    .any(|(key, _)| key == &application_replay)
            {
                return Err("application replay rejected".to_string());
            }
            let bytes = ciphertext
                .len()
                .checked_add(authenticated_data.len())
                .and_then(|bytes| bytes.checked_add(message_id.len()))
                .ok_or_else(|| "pending application budget reached".to_string())?;
            let next_room_pending_bytes = room.pending_bytes.checked_add(bytes);
            let next_room_pending_count = room.pending_applications.len().checked_add(1);
            let next_global_pending_count = global_pending_count.checked_add(1);
            let next_global_pending_bytes = global_pending_bytes.checked_add(bytes);
            if next_room_pending_bytes.is_none_or(|bytes| bytes > MAX_PENDING_BYTES) {
                return Err("room pending limit reached".to_string());
            }
            if next_room_pending_count.is_none_or(|count| count > MAX_PENDING_APPLICATIONS)
                || next_global_pending_count
                    .is_none_or(|count| count > MAX_GLOBAL_PENDING_APPLICATIONS)
                || next_global_pending_bytes.is_none_or(|bytes| bytes > MAX_GLOBAL_PENDING_BYTES)
            {
                return Err("pending application budget reached".to_string());
            }
            let next_room_pending_bytes =
                next_room_pending_bytes.ok_or_else(|| "room pending limit reached".to_string())?;
            let next_global_pending_count = next_global_pending_count
                .ok_or_else(|| "pending application budget reached".to_string())?;
            let next_global_pending_bytes = next_global_pending_bytes
                .ok_or_else(|| "pending application budget reached".to_string())?;
            let previous_snapshot_bytes = room
                .snapshots
                .get(&sender_code_id)
                .map(snapshot_size)
                .transpose()?
                .unwrap_or_default();
            let previous_snapshot = room.snapshots.get(&sender_code_id).cloned();
            let snapshot_roster = previous_snapshot
                .as_ref()
                .map(|snapshot| snapshot.roster.clone())
                .unwrap_or(canonical_room_roster(room)?);
            let next_snapshot_bytes = state_envelope
                .len()
                .checked_add(roster_size(&snapshot_roster)?)
                .ok_or_else(|| "state snapshot budget reached".to_string())?;
            let new_snapshot = !room.snapshots.contains_key(&sender_code_id);
            let next_room_snapshot_bytes = room
                .snapshot_bytes
                .checked_sub(previous_snapshot_bytes)
                .and_then(|bytes| bytes.checked_add(next_snapshot_bytes));
            let next_global_snapshot_count =
                global_snapshot_count.checked_add(usize::from(new_snapshot));
            let next_global_snapshot_bytes = global_snapshot_bytes
                .checked_sub(previous_snapshot_bytes)
                .and_then(|bytes| bytes.checked_add(next_snapshot_bytes));
            if (new_snapshot && room.snapshots.len() >= MAX_STATE_SNAPSHOTS)
                || next_room_snapshot_bytes.is_none_or(|bytes| bytes > MAX_STATE_BYTES)
                || next_global_snapshot_count.is_none_or(|count| count > MAX_GLOBAL_STATE_SNAPSHOTS)
                || next_global_snapshot_bytes.is_none_or(|bytes| bytes > MAX_GLOBAL_STATE_BYTES)
            {
                return Err("state snapshot budget reached".to_string());
            }
            let next_room_snapshot_bytes = next_room_snapshot_bytes
                .ok_or_else(|| "state snapshot budget reached".to_string())?;
            let next_global_snapshot_count = next_global_snapshot_count
                .ok_or_else(|| "state snapshot budget reached".to_string())?;
            let next_global_snapshot_bytes = next_global_snapshot_bytes
                .ok_or_else(|| "state snapshot budget reached".to_string())?;
            let recipients = room
                .members
                .values()
                .filter(|member| member.active && member.code_id != sender_code_id)
                .map(|member| {
                    Ok((
                        member.code_id,
                        next_delivery_revision(room, &member.code_id)?,
                    ))
                })
                .collect::<Result<Vec<_>, String>>()?;
            if recipients.iter().any(|(recipient_code_id, _)| {
                room.expired_sender_gaps
                    .get(&(*recipient_code_id, sender_code_id))
                    .is_some_and(|gap| *gap > MAX_RATCHET_BACK_HISTORY)
            }) {
                return Err("application sender generation gap rejected".to_string());
            }
            let admission = ApplicationAdmission {
                message_id: message_id.clone(),
                room_id: room_id.to_string(),
                sender_username: sender_username.clone(),
                recipient_code_ids: recipients.iter().map(|(code_id, _)| *code_id).collect(),
                recipient_revisions: recipients.clone(),
                sender_revision,
                epoch,
                membership_digest: membership_digest.clone(),
                ciphertext: ciphertext.clone(),
                authenticated_data: authenticated_data.clone(),
                state_envelope: state_envelope.clone(),
                created_at_ms: now,
                expires_at_ms: application_expires_at_ms,
            };
            let deliveries = recipients
                .iter()
                .map(|(code_id, revision)| PendingDelivery {
                    room_id: room_id.to_string(),
                    message_id: message_id.clone(),
                    recipient_code_id: *code_id,
                    epoch,
                    membership_digest: membership_digest.clone(),
                    revision: *revision,
                    payload: DeliveryPayload::Application {
                        sender_code_id,
                        sender_username: sender_username.clone(),
                        ciphertext: ciphertext.clone(),
                        authenticated_data: authenticated_data.clone(),
                    },
                    created_at_ms: now,
                    expires_at_ms: application_expires_at_ms,
                })
                .collect::<Vec<_>>();
            let queued_count = deliveries.len();
            let queued_bytes = delivery_bytes(deliveries.iter())?;
            let next_room_delivery_count = room
                .deliveries
                .values()
                .map(VecDeque::len)
                .try_fold(0_usize, usize::checked_add)
                .and_then(|count| count.checked_add(queued_count));
            let next_room_delivery_bytes = room.delivery_bytes.checked_add(queued_bytes);
            let next_global_delivery_count = global_delivery_count.checked_add(queued_count);
            let next_global_delivery_bytes = global_delivery_bytes.checked_add(queued_bytes);
            if next_room_delivery_count.is_none_or(|count| count > MAX_DELIVERIES_PER_ROOM)
                || next_room_delivery_bytes.is_none()
                || next_global_delivery_count.is_none_or(|count| count > max_delivery_count)
                || next_global_delivery_bytes.is_none_or(|bytes| bytes > max_delivery_bytes)
            {
                return Err("room delivery budget reached".to_string());
            }
            let next_room_delivery_bytes = next_room_delivery_bytes
                .ok_or_else(|| "room delivery budget reached".to_string())?;
            let next_global_delivery_count = next_global_delivery_count
                .ok_or_else(|| "room delivery budget reached".to_string())?;
            let next_global_delivery_bytes = next_global_delivery_bytes
                .ok_or_else(|| "room delivery budget reached".to_string())?;
            for delivery in deliveries {
                room.deliveries
                    .entry(delivery.recipient_code_id)
                    .or_default()
                    .push_back(delivery);
            }
            room.delivery_bytes = next_room_delivery_bytes;
            room.member_revisions
                .insert(sender_code_id, sender_revision);
            let snapshot = StateSnapshot {
                room_id: room.room_id.clone(),
                message_id: message_id.clone(),
                member_code_id: sender_code_id,
                epoch,
                revision: sender_revision,
                membership_digest: membership_digest.clone(),
                state_envelope,
                roster: snapshot_roster,
                created_at_ms: now,
                expires_at_ms: u64::MAX,
            };
            room.snapshot_bytes = next_room_snapshot_bytes;
            room.snapshots.insert(sender_code_id, snapshot);
            room.pending_bytes = next_room_pending_bytes;
            room.pending_applications.insert(
                message_id,
                PendingApplication {
                    admission: admission.clone(),
                    sender_code_id,
                    previous_sender_revision: current_sender_revision,
                    previous_snapshot,
                },
            );
            (
                admission,
                next_global_delivery_count,
                next_global_delivery_bytes,
                next_global_pending_count,
                next_global_pending_bytes,
                next_global_snapshot_count,
                next_global_snapshot_bytes,
            )
        };
        self.global_delivery_count = next_global_delivery_count;
        self.global_delivery_bytes = next_global_delivery_bytes;
        self.global_pending_count = next_global_pending_count;
        self.global_pending_bytes = next_global_pending_bytes;
        self.global_snapshot_count = next_global_snapshot_count;
        self.global_snapshot_bytes = next_global_snapshot_bytes;
        Ok(admission)
    }

    pub fn commit_application(&mut self, room_id: &str, message_id: &str) -> Result<(), String> {
        let (bytes, next_room_pending_bytes) = {
            let room = self.room(room_id)?;
            let pending = room
                .pending_applications
                .get(message_id)
                .ok_or_else(|| "application admission unavailable".to_string())?;
            let replay_key = ReplayKey::application(message_id);
            if room.replay_ids.iter().any(|(key, _)| key == &replay_key) {
                return Err("application replay rejected".to_string());
            }
            let bytes = pending
                .admission
                .ciphertext
                .len()
                .checked_add(pending.admission.authenticated_data.len())
                .and_then(|bytes| bytes.checked_add(message_id.len()))
                .ok_or_else(|| "pending application accounting rejected".to_string())?;
            let next_room_pending_bytes = room
                .pending_bytes
                .checked_sub(bytes)
                .ok_or_else(|| "pending application accounting rejected".to_string())?;
            (bytes, next_room_pending_bytes)
        };
        let next_global_pending_count = self
            .global_pending_count
            .checked_sub(1)
            .ok_or_else(|| "pending application accounting rejected".to_string())?;
        let next_global_pending_bytes = self
            .global_pending_bytes
            .checked_sub(bytes)
            .ok_or_else(|| "pending application accounting rejected".to_string())?;
        {
            let room = self.room_mut(room_id)?;
            room.pending_applications
                .remove(message_id)
                .ok_or_else(|| "application admission unavailable".to_string())?;
            room.pending_bytes = next_room_pending_bytes;
            if room.replay_ids.len() >= MAX_REPLAY_IDS {
                room.replay_ids.pop_front();
            }
            room.replay_ids
                .push_back((ReplayKey::application(message_id), now_ms()));
        }
        self.global_pending_count = next_global_pending_count;
        self.global_pending_bytes = next_global_pending_bytes;
        self.trim_replay_ids()?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn rollback_application(&mut self, room_id: &str, message_id: &str) -> Result<(), String> {
        let (
            pending,
            next_room_pending_bytes,
            next_room_delivery_bytes,
            next_room_snapshot_bytes,
            next_global_pending_count,
            next_global_pending_bytes,
            next_global_delivery_count,
            next_global_delivery_bytes,
            next_global_snapshot_count,
            next_global_snapshot_bytes,
        ) = {
            let room = self.room(room_id)?;
            let pending = room
                .pending_applications
                .get(message_id)
                .cloned()
                .ok_or_else(|| "application admission unavailable".to_string())?;
            let bytes = pending
                .admission
                .ciphertext
                .len()
                .checked_add(pending.admission.authenticated_data.len())
                .and_then(|bytes| bytes.checked_add(message_id.len()))
                .ok_or_else(|| "pending application accounting rejected".to_string())?;
            let next_room_pending_bytes = room
                .pending_bytes
                .checked_sub(bytes)
                .ok_or_else(|| "pending application accounting rejected".to_string())?;
            let removed_delivery_count = room
                .deliveries
                .values()
                .map(|queue| {
                    queue
                        .iter()
                        .filter(|delivery| delivery.message_id == message_id)
                        .count()
                })
                .try_fold(0_usize, usize::checked_add)
                .ok_or_else(|| "delivery accounting rejected".to_string())?;
            let removed_delivery_bytes = delivery_bytes(
                room.deliveries
                    .values()
                    .flat_map(|queue| queue.iter())
                    .filter(|delivery| delivery.message_id == message_id),
            )?;
            let next_room_delivery_bytes = room
                .delivery_bytes
                .checked_sub(removed_delivery_bytes)
                .ok_or_else(|| "delivery accounting rejected".to_string())?;
            let sender_code_id = pending.sender_code_id;
            let current_snapshot_bytes = room
                .snapshots
                .get(&sender_code_id)
                .map(snapshot_size)
                .transpose()?
                .unwrap_or_default();
            let restored_snapshot_bytes = pending
                .previous_snapshot
                .as_ref()
                .map(snapshot_size)
                .transpose()?
                .unwrap_or_default();
            let next_room_snapshot_bytes = room
                .snapshot_bytes
                .checked_sub(current_snapshot_bytes)
                .and_then(|bytes| bytes.checked_add(restored_snapshot_bytes))
                .ok_or_else(|| "state snapshot accounting rejected".to_string())?;
            let next_global_pending_count = self
                .global_pending_count
                .checked_sub(1)
                .ok_or_else(|| "pending application accounting rejected".to_string())?;
            let next_global_pending_bytes = self
                .global_pending_bytes
                .checked_sub(bytes)
                .ok_or_else(|| "pending application accounting rejected".to_string())?;
            let next_global_delivery_count = self
                .global_delivery_count
                .checked_sub(removed_delivery_count)
                .ok_or_else(|| "delivery accounting rejected".to_string())?;
            let next_global_delivery_bytes = self
                .global_delivery_bytes
                .checked_sub(removed_delivery_bytes)
                .ok_or_else(|| "delivery accounting rejected".to_string())?;
            let current_snapshot_count = usize::from(room.snapshots.contains_key(&sender_code_id));
            let restored_snapshot_count = usize::from(pending.previous_snapshot.is_some());
            let next_global_snapshot_count = self
                .global_snapshot_count
                .checked_sub(current_snapshot_count)
                .and_then(|count| count.checked_add(restored_snapshot_count))
                .ok_or_else(|| "state snapshot accounting rejected".to_string())?;
            let next_global_snapshot_bytes = self
                .global_snapshot_bytes
                .checked_sub(current_snapshot_bytes)
                .and_then(|bytes| bytes.checked_add(restored_snapshot_bytes))
                .ok_or_else(|| "state snapshot accounting rejected".to_string())?;
            (
                pending,
                next_room_pending_bytes,
                next_room_delivery_bytes,
                next_room_snapshot_bytes,
                next_global_pending_count,
                next_global_pending_bytes,
                next_global_delivery_count,
                next_global_delivery_bytes,
                next_global_snapshot_count,
                next_global_snapshot_bytes,
            )
        };
        {
            let room = self.room_mut(room_id)?;
            if room.pending_applications.remove(message_id).is_none() {
                return Err("application admission unavailable".to_string());
            }
            let sender_code_id = pending.sender_code_id;
            let recipient_ids = room.deliveries.keys().copied().collect::<Vec<_>>();
            for code_id in recipient_ids {
                if let Some(queue) = room.deliveries.get_mut(&code_id) {
                    queue.retain(|delivery| delivery.message_id != message_id);
                }
                compact_delivery_revisions(room, &code_id)?;
            }
            room.deliveries.retain(|_, queue| !queue.is_empty());
            room.delivery_bytes = next_room_delivery_bytes;
            room.member_revisions
                .insert(sender_code_id, pending.previous_sender_revision);
            if let Some(snapshot) = pending.previous_snapshot.clone() {
                room.snapshots.insert(sender_code_id, snapshot);
            } else {
                room.snapshots.remove(&sender_code_id);
            }
            room.snapshot_bytes = next_room_snapshot_bytes;
            room.pending_bytes = next_room_pending_bytes;
        }
        self.global_pending_count = next_global_pending_count;
        self.global_pending_bytes = next_global_pending_bytes;
        self.global_delivery_count = next_global_delivery_count;
        self.global_delivery_bytes = next_global_delivery_bytes;
        self.global_snapshot_count = next_global_snapshot_count;
        self.global_snapshot_bytes = next_global_snapshot_bytes;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn store_snapshot(
        &mut self,
        member_code_id: CodeId,
        room_id: &str,
        message_id: &str,
        epoch: u64,
        revision: u64,
        membership_digest: Vec<u8>,
        state_envelope: Vec<u8>,
    ) -> Result<StateSnapshot, String> {
        let now = now_ms();
        self.prune_expired(now);
        validate_request_id(message_id)?;
        validate_digest(&membership_digest)?;
        validate_state_envelope(&state_envelope)?;
        let global_snapshot_count = self.global_snapshot_count;
        let global_snapshot_bytes = self.global_snapshot_bytes;
        let global_delivery_count = self.global_delivery_count;
        let global_delivery_bytes = self.global_delivery_bytes;
        let (
            snapshot,
            next_global_delivery_count,
            next_global_delivery_bytes,
            next_global_snapshot_count,
            next_global_snapshot_bytes,
        ) = {
            let room = self.room_mut(room_id)?;
            if !room
                .members
                .values()
                .any(|member| member.code_id == member_code_id)
            {
                return Err("room member required".to_string());
            }
            let current_revision = room
                .member_revisions
                .get(&member_code_id)
                .copied()
                .unwrap_or_default();
            let member_active = room
                .members
                .values()
                .find(|member| member.code_id == member_code_id)
                .is_some_and(|member| member.active);
            let queue = room.deliveries.get(&member_code_id);
            let max_queued_revision = queue
                .and_then(|queue| queue.back())
                .map(|delivery| delivery.revision)
                .unwrap_or(current_revision);
            if revision < current_revision || revision > max_queued_revision {
                return Err("state snapshot revision rejected".to_string());
            }
            // A snapshot can retire only the contiguous prefix of this
            // member's ordered queue. A missing or skipped revision fails
            // closed instead of allowing a bare acknowledgement to delete
            // an earlier delivery.
            let mut retire_count = 0_usize;
            if !member_active {
                let welcome_delivery = queue
                    .and_then(|queue| queue.front())
                    .ok_or_else(|| "state snapshot welcome unavailable".to_string())?;
                if revision != current_revision || welcome_delivery.revision != revision {
                    return Err("state snapshot delivery order rejected".to_string());
                }
                if welcome_delivery.message_id != message_id {
                    return Err("state snapshot message rejected".to_string());
                }
                if welcome_delivery.epoch != epoch
                    || welcome_delivery.membership_digest != membership_digest
                {
                    return Err("state snapshot delivery checkpoint rejected".to_string());
                }
                match &welcome_delivery.payload {
                    DeliveryPayload::Membership {
                        group_id, welcome, ..
                    } if group_id == &room.group_id && !welcome.is_empty() => {}
                    _ => return Err("state snapshot welcome rejected".to_string()),
                }
                retire_count = 1;
            } else if revision > current_revision {
                let queue =
                    queue.ok_or_else(|| "state snapshot delivery unavailable".to_string())?;
                let mut expected = current_revision
                    .checked_add(1)
                    .ok_or_else(|| "delivery revision exhausted".to_string())?;
                loop {
                    if queue
                        .get(retire_count)
                        .is_none_or(|delivery| delivery.revision != expected)
                    {
                        return Err("state snapshot delivery order rejected".to_string());
                    }
                    retire_count = retire_count
                        .checked_add(1)
                        .ok_or_else(|| "delivery retirement exhausted".to_string())?;
                    if expected == revision {
                        break;
                    }
                    expected = expected
                        .checked_add(1)
                        .ok_or_else(|| "delivery revision exhausted".to_string())?;
                }
                if queue
                    .get(retire_count - 1)
                    .is_none_or(|delivery| delivery.message_id != message_id)
                {
                    return Err("state snapshot message rejected".to_string());
                }
            }
            if member_active && retire_count > 0 {
                let target = queue
                    .and_then(|queue| queue.get(retire_count - 1))
                    .ok_or_else(|| "state snapshot delivery unavailable".to_string())?;
                if target.epoch != epoch || target.membership_digest != membership_digest {
                    return Err("state snapshot delivery checkpoint rejected".to_string());
                }
            } else if member_active {
                if let Some(existing) = room.snapshots.get(&member_code_id) {
                    if existing.epoch != epoch
                        || existing.revision != revision
                        || existing.message_id != message_id
                        || existing.membership_digest != membership_digest
                        || existing.state_envelope != state_envelope
                    {
                        return Err("state snapshot checkpoint rejected".to_string());
                    }
                } else if room.epoch != epoch
                    || room.membership_digest != membership_digest
                    || current_revision != revision
                {
                    return Err("state snapshot checkpoint unavailable".to_string());
                }
            }
            let mut snapshot_roster = room
                .snapshots
                .get(&member_code_id)
                .map(|snapshot| snapshot.roster.clone())
                .unwrap_or_default();
            let retired_senders = queue
                .into_iter()
                .flat_map(|queue| queue.iter().take(retire_count))
                .filter_map(|delivery| match &delivery.payload {
                    DeliveryPayload::Application { sender_code_id, .. } => Some(*sender_code_id),
                    DeliveryPayload::Membership { .. } => None,
                })
                .collect::<HashSet<_>>();
            let retired_membership = queue.into_iter().any(|queue| {
                queue
                    .iter()
                    .take(retire_count)
                    .any(|delivery| matches!(delivery.payload, DeliveryPayload::Membership { .. }))
            });
            if let Some(queue) = queue {
                for delivery in queue.iter().take(retire_count) {
                    if let DeliveryPayload::Membership { roster, .. } = &delivery.payload {
                        roster_map(roster)?;
                        snapshot_roster = roster.clone();
                    }
                }
            }
            if snapshot_roster.is_empty() && member_active && retire_count == 0 {
                snapshot_roster = canonical_room_roster(room)?;
            }
            if snapshot_roster.is_empty()
                || (epoch == room.epoch
                    && membership_digest == room.membership_digest
                    && !rosters_match_room(&snapshot_roster, room)?)
            {
                return Err("state snapshot roster rejected".to_string());
            }
            if room.snapshots.len() >= MAX_STATE_SNAPSHOTS
                && !room.snapshots.contains_key(&member_code_id)
            {
                return Err("state snapshot limit reached".to_string());
            }
            let previous_bytes = room
                .snapshots
                .get(&member_code_id)
                .map(snapshot_size)
                .transpose()?
                .unwrap_or_default();
            let next_snapshot_bytes = state_envelope
                .len()
                .checked_add(roster_size(&snapshot_roster)?)
                .ok_or_else(|| "state snapshot bytes limit reached".to_string())?;
            let is_new = !room.snapshots.contains_key(&member_code_id);
            let next_room_snapshot_bytes = room
                .snapshot_bytes
                .checked_sub(previous_bytes)
                .and_then(|bytes| bytes.checked_add(next_snapshot_bytes));
            let next_global_snapshot_count = global_snapshot_count.checked_add(usize::from(is_new));
            let next_global_snapshot_bytes = global_snapshot_bytes
                .checked_sub(previous_bytes)
                .and_then(|bytes| bytes.checked_add(next_snapshot_bytes));
            if next_room_snapshot_bytes.is_none_or(|bytes| bytes > MAX_STATE_BYTES) {
                return Err("state snapshot bytes limit reached".to_string());
            }
            if next_global_snapshot_count.is_none_or(|count| count > MAX_GLOBAL_STATE_SNAPSHOTS)
                || next_global_snapshot_bytes.is_none_or(|bytes| bytes > MAX_GLOBAL_STATE_BYTES)
            {
                return Err("global state snapshot budget reached".to_string());
            }
            let next_room_snapshot_bytes = next_room_snapshot_bytes
                .ok_or_else(|| "state snapshot bytes limit reached".to_string())?;
            let next_global_snapshot_count = next_global_snapshot_count
                .ok_or_else(|| "global state snapshot budget reached".to_string())?;
            let next_global_snapshot_bytes = next_global_snapshot_bytes
                .ok_or_else(|| "global state snapshot budget reached".to_string())?;
            let removed_bytes = delivery_bytes(
                queue
                    .into_iter()
                    .flat_map(|queue| queue.iter().take(retire_count)),
            )?;
            let next_room_delivery_bytes = room.delivery_bytes.checked_sub(removed_bytes);
            let next_global_delivery_count = global_delivery_count.checked_sub(retire_count);
            let next_global_delivery_bytes = global_delivery_bytes.checked_sub(removed_bytes);
            if next_room_delivery_bytes.is_none()
                || next_global_delivery_count.is_none()
                || next_global_delivery_bytes.is_none()
            {
                return Err("delivery accounting rejected".to_string());
            }
            let next_room_delivery_bytes = next_room_delivery_bytes
                .ok_or_else(|| "delivery accounting rejected".to_string())?;
            let next_global_delivery_count = next_global_delivery_count
                .ok_or_else(|| "delivery accounting rejected".to_string())?;
            let next_global_delivery_bytes = next_global_delivery_bytes
                .ok_or_else(|| "delivery accounting rejected".to_string())?;
            let snapshot = StateSnapshot {
                room_id: room_id.to_string(),
                message_id: message_id.to_string(),
                member_code_id,
                epoch,
                revision,
                membership_digest,
                state_envelope,
                roster: snapshot_roster,
                created_at_ms: now,
                expires_at_ms: u64::MAX,
            };
            let member_username = room
                .members
                .iter()
                .find(|(_, member)| member.code_id == member_code_id)
                .map(|(username, _)| username.clone())
                .ok_or_else(|| "room member required".to_string())?;
            if retire_count > 0 {
                let queue_len = room
                    .deliveries
                    .get(&member_code_id)
                    .map(VecDeque::len)
                    .ok_or_else(|| "state snapshot delivery unavailable".to_string())?;
                if queue_len < retire_count {
                    return Err("state snapshot delivery order rejected".to_string());
                }
            }
            room.members
                .get_mut(&member_username)
                .ok_or_else(|| "room member required".to_string())?
                .active = true;
            if retire_count > 0 {
                let queue = room
                    .deliveries
                    .get_mut(&member_code_id)
                    .ok_or_else(|| "state snapshot delivery unavailable".to_string())?;
                for _ in 0..retire_count {
                    let _ = queue.pop_front();
                }
            }
            for sender_code_id in retired_senders {
                room.expired_sender_gaps
                    .remove(&(member_code_id, sender_code_id));
            }
            if retired_membership {
                room.expired_sender_gaps
                    .retain(|(recipient_code_id, _), _| *recipient_code_id != member_code_id);
            }
            room.delivery_bytes = next_room_delivery_bytes;
            room.member_revisions.insert(member_code_id, revision);
            room.snapshot_bytes = next_room_snapshot_bytes;
            room.snapshots.insert(member_code_id, snapshot.clone());
            (
                snapshot,
                next_global_delivery_count,
                next_global_delivery_bytes,
                next_global_snapshot_count,
                next_global_snapshot_bytes,
            )
        };
        self.global_delivery_count = next_global_delivery_count;
        self.global_delivery_bytes = next_global_delivery_bytes;
        self.global_snapshot_count = next_global_snapshot_count;
        self.global_snapshot_bytes = next_global_snapshot_bytes;
        self.recompute_gap_accounting()?;
        Ok(snapshot)
    }

    #[allow(dead_code)]
    pub fn snapshot(&mut self, member_code_id: &CodeId, room_id: &str) -> Option<StateSnapshot> {
        self.prune_expired(now_ms());
        self.rooms
            .get(room_id)
            .and_then(|room| room.snapshots.get(member_code_id).cloned())
    }

    pub fn delete(&mut self, owner_code_id: CodeId, room_id: &str) -> Result<RoomInfo, String> {
        self.prune_expired(now_ms());
        let room = self
            .rooms
            .get(room_id)
            .ok_or_else(|| "room unavailable".to_string())?;
        if room.owner_code_id != owner_code_id {
            return Err("room owner required".to_string());
        }
        let next_accounting = self.checked_accounting_excluding(Some(room_id))?;
        let room = self
            .rooms
            .remove(room_id)
            .ok_or_else(|| "room unavailable".to_string())?;
        self.apply_accounting(next_accounting);
        Ok(room_info_for(&room, Some(&owner_code_id), true))
    }

    pub fn wipe(&mut self) {
        self.rooms.clear();
        self.global_pending_count = 0;
        self.global_pending_bytes = 0;
        self.global_snapshot_count = 0;
        self.global_snapshot_bytes = 0;
        self.global_replay_count = 0;
        self.global_delivery_count = 0;
        self.global_delivery_bytes = 0;
        self.global_expired_gap_pairs = 0;
    }

    pub fn prune_at(&mut self, now: u64) {
        self.prune_expired(now);
    }

    fn room(&self, room_id: &str) -> Result<&RelayRoom, String> {
        self.rooms
            .get(room_id)
            .ok_or_else(|| "room unavailable".to_string())
    }

    fn room_mut(&mut self, room_id: &str) -> Result<&mut RelayRoom, String> {
        self.rooms
            .get_mut(room_id)
            .ok_or_else(|| "room unavailable".to_string())
    }

    fn checked_accounting_excluding(
        &self,
        excluded_room_id: Option<&str>,
    ) -> Result<AuthorityAccounting, String> {
        let mut totals = AuthorityAccounting {
            pending_bytes: 0,
            pending_count: 0,
            snapshot_bytes: 0,
            snapshot_count: 0,
            replay_count: 0,
            delivery_bytes: 0,
            delivery_count: 0,
            expired_gap_pairs: 0,
        };
        for room in self
            .rooms
            .values()
            .filter(|room| excluded_room_id != Some(room.room_id.as_str()))
        {
            totals.pending_count = totals
                .pending_count
                .checked_add(room.pending_applications.len())
                .ok_or_else(|| "pending application accounting rejected".to_string())?;
            for pending in room.pending_applications.values() {
                let bytes = pending
                    .admission
                    .ciphertext
                    .len()
                    .checked_add(pending.admission.authenticated_data.len())
                    .and_then(|bytes| bytes.checked_add(pending.admission.message_id.len()))
                    .ok_or_else(|| "pending application accounting rejected".to_string())?;
                totals.pending_bytes = totals
                    .pending_bytes
                    .checked_add(bytes)
                    .ok_or_else(|| "pending application accounting rejected".to_string())?;
            }
            totals.snapshot_count = totals
                .snapshot_count
                .checked_add(room.snapshots.len())
                .and_then(|count| count.checked_add(room.joins.len()))
                .ok_or_else(|| "state snapshot accounting rejected".to_string())?;
            totals.snapshot_bytes = totals
                .snapshot_bytes
                .checked_add(room.snapshot_bytes)
                .ok_or_else(|| "state snapshot accounting rejected".to_string())?;
            for join in room.joins.values() {
                totals.snapshot_bytes = totals
                    .snapshot_bytes
                    .checked_add(join.state_envelope.len())
                    .ok_or_else(|| "state snapshot accounting rejected".to_string())?;
            }
            totals.replay_count = totals
                .replay_count
                .checked_add(room.replay_ids.len())
                .ok_or_else(|| "replay accounting rejected".to_string())?;
            for queue in room.deliveries.values() {
                totals.delivery_count = totals
                    .delivery_count
                    .checked_add(queue.len())
                    .ok_or_else(|| "delivery accounting rejected".to_string())?;
                for delivery in queue {
                    totals.delivery_bytes = totals
                        .delivery_bytes
                        .checked_add(delivery_size(delivery)?)
                        .ok_or_else(|| "delivery accounting rejected".to_string())?;
                }
            }
            totals.expired_gap_pairs = totals
                .expired_gap_pairs
                .checked_add(room.expired_sender_gaps.len())
                .filter(|count| *count <= MAX_GLOBAL_EXPIRED_GAP_PAIRS)
                .ok_or_else(|| "expired sender gap accounting rejected".to_string())?;
        }
        Ok(totals)
    }

    fn apply_accounting(&mut self, totals: AuthorityAccounting) {
        self.global_pending_bytes = totals.pending_bytes;
        self.global_pending_count = totals.pending_count;
        self.global_snapshot_bytes = totals.snapshot_bytes;
        self.global_snapshot_count = totals.snapshot_count;
        self.global_replay_count = totals.replay_count;
        self.global_delivery_bytes = totals.delivery_bytes;
        self.global_delivery_count = totals.delivery_count;
        self.global_expired_gap_pairs = totals.expired_gap_pairs;
    }

    fn trim_replay_ids(&mut self) -> Result<(), String> {
        self.global_replay_count = self
            .rooms
            .values()
            .map(|room| room.replay_ids.len())
            .try_fold(0_usize, usize::checked_add)
            .ok_or_else(|| "replay accounting rejected".to_string())?;
        while self.global_replay_count > MAX_GLOBAL_REPLAY_IDS {
            let oldest_room_id = self
                .rooms
                .iter()
                .filter_map(|(room_id, room)| {
                    room.replay_ids
                        .front()
                        .map(|(_, created_at)| (room_id, *created_at))
                })
                .min_by_key(|(_, created_at)| *created_at)
                .map(|(room_id, _)| room_id.clone());
            let Some(oldest_room_id) = oldest_room_id else {
                return Err("replay accounting rejected".to_string());
            };
            if let Some(room) = self.rooms.get_mut(&oldest_room_id) {
                if room.replay_ids.pop_front().is_none() {
                    return Err("replay accounting rejected".to_string());
                }
            }
            self.global_replay_count = self
                .global_replay_count
                .checked_sub(1)
                .ok_or_else(|| "replay accounting rejected".to_string())?;
        }
        Ok(())
    }

    fn recompute_state_accounting(&mut self) -> Result<(), String> {
        let totals = self.checked_accounting_excluding(None)?;
        self.global_snapshot_count = totals.snapshot_count;
        self.global_snapshot_bytes = totals.snapshot_bytes;
        Ok(())
    }

    fn recompute_gap_accounting(&mut self) -> Result<(), String> {
        self.global_expired_gap_pairs = self
            .rooms
            .values()
            .map(|room| room.expired_sender_gaps.len())
            .try_fold(0_usize, usize::checked_add)
            .filter(|count| *count <= MAX_GLOBAL_EXPIRED_GAP_PAIRS)
            .ok_or_else(|| "expired sender gap accounting rejected".to_string())?;
        Ok(())
    }

    fn prune_expired(&mut self, now: u64) {
        let mut global_gap_pairs = self
            .rooms
            .values()
            .map(|room| room.expired_sender_gaps.len())
            .try_fold(0_usize, usize::checked_add)
            .unwrap_or(usize::MAX);
        for room in self.rooms.values_mut() {
            room.joins
                .retain(|_, join| join.request.expires_at_ms > now);
            room.leaves.retain(|_, leave| leave.expires_at_ms > now);
            if room
                .pending_transition
                .as_ref()
                .is_some_and(|transition| transition.expires_at_ms <= now)
            {
                room.pending_transition = None;
            }
            let expired_applications = room
                .pending_applications
                .iter()
                .filter(|(_, pending)| pending.admission.expires_at_ms <= now)
                .map(|(message_id, _)| message_id.clone())
                .collect::<Vec<_>>();
            for message_id in expired_applications {
                let Some(pending) = room.pending_applications.remove(&message_id) else {
                    continue;
                };
                let recipient_ids = room.deliveries.keys().copied().collect::<Vec<_>>();
                for code_id in recipient_ids {
                    if let Some(queue) = room.deliveries.get_mut(&code_id) {
                        queue.retain(|delivery| delivery.message_id != message_id);
                    }
                    if compact_delivery_revisions(room, &code_id).is_err() {
                        room.delivery_bytes = usize::MAX;
                    }
                }
                let sender_code_id = pending.sender_code_id;
                room.member_revisions
                    .insert(sender_code_id, pending.previous_sender_revision);
                if let Some(snapshot) = pending.previous_snapshot.clone() {
                    room.snapshots.insert(sender_code_id, snapshot);
                } else {
                    room.snapshots.remove(&sender_code_id);
                }
            }
            room.deliveries.retain(|_, queue| !queue.is_empty());
            room.pending_bytes = room
                .pending_applications
                .values()
                .map(|pending| {
                    pending
                        .admission
                        .ciphertext
                        .len()
                        .checked_add(pending.admission.authenticated_data.len())
                        .and_then(|bytes| bytes.checked_add(pending.admission.message_id.len()))
                })
                .try_fold(0_usize, |total, bytes| total.checked_add(bytes?))
                .unwrap_or(usize::MAX);
            room.snapshot_bytes = room
                .snapshots
                .values()
                .try_fold(0_usize, |total, snapshot| {
                    total
                        .checked_add(snapshot_size(snapshot)?)
                        .ok_or_else(|| "state snapshot accounting rejected".to_string())
                })
                .unwrap_or(usize::MAX);
            while room
                .replay_ids
                .front()
                .is_some_and(|(_, created)| now.saturating_sub(*created) >= self.replay_ttl_ms)
            {
                room.replay_ids.pop_front();
            }
            room.snapshot_bytes = room
                .snapshots
                .values()
                .try_fold(0_usize, |total, snapshot| {
                    total
                        .checked_add(snapshot_size(snapshot)?)
                        .ok_or_else(|| "state snapshot accounting rejected".to_string())
                })
                .unwrap_or(usize::MAX);
            if prune_expired_application_deliveries(room, now, &mut global_gap_pairs).is_err() {
                room.delivery_bytes = usize::MAX;
            }
            room.deliveries.retain(|_, queue| !queue.is_empty());
            room.delivery_bytes =
                delivery_bytes(room.deliveries.values().flat_map(|queue| queue.iter()))
                    .unwrap_or(usize::MAX);
        }
        match self.checked_accounting_excluding(None) {
            Ok(totals) => self.apply_accounting(totals),
            Err(_) => {
                self.global_pending_count = usize::MAX;
                self.global_pending_bytes = usize::MAX;
                self.global_snapshot_count = usize::MAX;
                self.global_snapshot_bytes = usize::MAX;
                self.global_replay_count = usize::MAX;
                self.global_delivery_count = usize::MAX;
                self.global_delivery_bytes = usize::MAX;
            }
        }
        if self.trim_replay_ids().is_err() {
            self.global_replay_count = usize::MAX;
        }
    }
}

fn room_info_for(
    room: &RelayRoom,
    member_code_id: Option<&CodeId>,
    include_roster: bool,
) -> RoomInfo {
    let active = member_code_id.is_some_and(|code_id| {
        room.members
            .values()
            .any(|member| member.code_id == *code_id && member.active)
    });
    let revision = member_code_id
        .and_then(|code_id| room.member_revisions.get(code_id).copied())
        .unwrap_or_default();
    let recovery_snapshot = member_code_id.and_then(|code_id| {
        room.snapshots
            .get(code_id)
            .map(|snapshot| RecoverySnapshot {
                active,
                epoch: snapshot.epoch,
                revision: snapshot.revision,
                membership_digest: snapshot.membership_digest.clone(),
                state_envelope: snapshot.state_envelope.clone(),
                roster: snapshot.roster.clone(),
            })
    });
    let synchronized = member_code_id.is_some_and(|code_id| {
        active
            && room.deliveries.get(code_id).is_none_or(VecDeque::is_empty)
            && !room
                .expired_sender_gaps
                .iter()
                .any(|((recipient, _), gap)| {
                    recipient == code_id && *gap > MAX_RATCHET_BACK_HISTORY
                })
            && room.snapshots.get(code_id).is_some_and(|snapshot| {
                room.member_revisions.get(code_id).copied() == Some(snapshot.revision)
                    && snapshot.epoch == room.epoch
                    && snapshot.membership_digest == room.membership_digest
                    && rosters_match_room(&snapshot.roster, room).unwrap_or(false)
            })
    });
    RoomInfo {
        room_id: room.room_id.clone(),
        owner_username: room.owner_username.clone(),
        group_id: room.group_id.clone(),
        active,
        synchronized,
        epoch: room.epoch,
        revision,
        recovery_snapshot,
        membership_digest: room.membership_digest.clone(),
        roster: if include_roster {
            room.members
                .values()
                .map(|member| RosterMember {
                    username: member.username.clone(),
                    stable_identity: member.stable_identity.clone(),
                })
                .collect()
        } else {
            Vec::new()
        },
        policy: room.policy,
    }
}

fn pending_room_info_for(room: &RelayRoom, state_envelope: &[u8]) -> RoomInfo {
    RoomInfo {
        room_id: room.room_id.clone(),
        owner_username: room.owner_username.clone(),
        group_id: room.group_id.clone(),
        active: false,
        synchronized: false,
        epoch: 0,
        revision: 0,
        recovery_snapshot: Some(RecoverySnapshot {
            active: false,
            epoch: 0,
            revision: 0,
            membership_digest: Vec::new(),
            state_envelope: state_envelope.to_vec(),
            roster: Vec::new(),
        }),
        membership_digest: Vec::new(),
        roster: Vec::new(),
        policy: room.policy,
    }
}

fn changed_usernames(
    current: &BTreeMap<String, Member>,
    next: &BTreeMap<String, Member>,
) -> HashSet<String> {
    current
        .keys()
        .chain(next.keys())
        .filter(|username| {
            current
                .get(*username)
                .map(|member| (&member.code_id, &member.stable_identity))
                != next
                    .get(*username)
                    .map(|member| (&member.code_id, &member.stable_identity))
        })
        .cloned()
        .collect()
}

fn canonical_username(value: &str) -> Result<String, String> {
    validate_username(value)?;
    Ok(value.to_ascii_lowercase())
}

fn roster_size(roster: &[RosterMember]) -> Result<usize, String> {
    roster.iter().try_fold(0_usize, |total, member| {
        total
            .checked_add(member.username.len())
            .and_then(|bytes| bytes.checked_add(member.stable_identity.len()))
            .ok_or_else(|| "state snapshot accounting rejected".to_string())
    })
}

fn snapshot_size(snapshot: &StateSnapshot) -> Result<usize, String> {
    snapshot
        .state_envelope
        .len()
        .checked_add(roster_size(&snapshot.roster)?)
        .ok_or_else(|| "state snapshot accounting rejected".to_string())
}

fn canonical_room_roster(room: &RelayRoom) -> Result<Vec<RosterMember>, String> {
    room.members
        .values()
        .map(|member| {
            Ok(RosterMember {
                username: canonical_username(&member.username)?,
                stable_identity: member.stable_identity.clone(),
            })
        })
        .collect()
}

fn rosters_match_room(roster: &[RosterMember], room: &RelayRoom) -> Result<bool, String> {
    let candidate = roster_map(roster)?;
    if candidate.len() != room.members.len() {
        return Ok(false);
    }
    Ok(candidate.iter().all(|(username, member)| {
        room.members.get(username).is_some_and(|current| {
            current.code_id != [0_u8; 32] && current.stable_identity == member.stable_identity
        })
    }))
}

fn roster_map(roster: &[RosterMember]) -> Result<BTreeMap<String, Member>, String> {
    if roster.is_empty() || roster.len() > MAX_MEMBERS {
        return Err("membership roster rejected".to_string());
    }
    let mut members = BTreeMap::new();
    let mut identities = HashSet::new();
    for member in roster {
        validate_username(&member.username)?;
        validate_stable_identity(&member.stable_identity)?;
        let canonical = canonical_username(&member.username)?;
        if !identities.insert(member.stable_identity.clone()) || members.contains_key(&canonical) {
            return Err("membership roster rejected".to_string());
        }
        // New-member code IDs are bound from their JoinRequest in
        // `begin_membership`; existing members use a sentinel until then.
        members.insert(
            canonical,
            Member {
                username: member.username.clone(),
                code_id: [0_u8; 32],
                stable_identity: member.stable_identity.clone(),
                active: false,
            },
        );
    }
    Ok(members)
}

fn resolve_next_roster(
    room: &RelayRoom,
    transition: &MembershipTransition,
) -> Result<BTreeMap<String, Member>, String> {
    let requested_next = roster_map(&transition.roster)?;
    let mut next = BTreeMap::new();
    for (username, member) in requested_next {
        if let Some(current) = room.members.get(&username) {
            if current.stable_identity != member.stable_identity {
                return Err("membership roster identity changed".to_string());
            }
            next.insert(username, current.clone());
        } else {
            let request = transition
                .request_id
                .as_ref()
                .and_then(|id| room.joins.get(id))
                .ok_or_else(|| "join request required".to_string())?;
            if canonical_username(&request.request.username)? != username
                || request.request.stable_identity != member.stable_identity
            {
                return Err("join request binding rejected".to_string());
            }
            next.insert(
                username,
                Member {
                    username: request.request.username.clone(),
                    code_id: request.request.code_id,
                    stable_identity: member.stable_identity.clone(),
                    active: false,
                },
            );
        }
    }
    Ok(next)
}

fn next_delivery_revision(room: &RelayRoom, code_id: &CodeId) -> Result<u64, String> {
    room.member_revisions
        .get(code_id)
        .copied()
        .unwrap_or_default()
        .max(
            room.deliveries
                .get(code_id)
                .and_then(|queue| queue.back())
                .map(|delivery| delivery.revision)
                .unwrap_or_default(),
        )
        .checked_add(1)
        .ok_or_else(|| "delivery revision exhausted".to_string())
}

fn compact_delivery_revisions(room: &mut RelayRoom, code_id: &CodeId) -> Result<(), String> {
    let member_active = room
        .members
        .values()
        .find(|member| member.code_id == *code_id)
        .is_some_and(|member| member.active);
    let mut next = room
        .member_revisions
        .get(code_id)
        .copied()
        .unwrap_or_default()
        .checked_add(1)
        .ok_or_else(|| "delivery revision exhausted".to_string())?;
    if let Some(queue) = room.deliveries.get_mut(code_id) {
        let mut revisions = Vec::with_capacity(queue.len());
        for (index, delivery) in queue.iter().enumerate() {
            if !member_active
                && index == 0
                && matches!(delivery.payload, DeliveryPayload::Membership { ref welcome, .. } if !welcome.is_empty())
            {
                revisions.push(0);
                next = 1;
            } else {
                revisions.push(next);
                next = next
                    .checked_add(1)
                    .ok_or_else(|| "delivery revision exhausted".to_string())?;
            }
        }
        for (delivery, revision) in queue.iter_mut().zip(revisions) {
            delivery.revision = revision;
        }
    }
    Ok(())
}

fn prune_expired_application_deliveries(
    room: &mut RelayRoom,
    now: u64,
    global_gap_pairs: &mut usize,
) -> Result<(), String> {
    let code_ids = room.deliveries.keys().copied().collect::<Vec<_>>();
    for code_id in code_ids {
        let Some(current_queue) = room.deliveries.get(&code_id) else {
            continue;
        };
        let mut next_queue = VecDeque::with_capacity(current_queue.len());
        let mut next_gaps = room.expired_sender_gaps.clone();
        let mut removed = false;
        for delivery in current_queue {
            let expired_sender = match &delivery.payload {
                DeliveryPayload::Application { sender_code_id, .. }
                    if delivery.expires_at_ms <= now =>
                {
                    Some(*sender_code_id)
                }
                _ => None,
            };
            if let Some(sender_code_id) = expired_sender {
                let is_new = !next_gaps.contains_key(&(code_id, sender_code_id));
                if is_new
                    && (next_gaps.len() >= MAX_EXPIRED_GAP_PAIRS_PER_ROOM
                        || *global_gap_pairs >= MAX_GLOBAL_EXPIRED_GAP_PAIRS)
                {
                    return Err("expired sender gap limit reached".to_string());
                }
                let gap = next_gaps.entry((code_id, sender_code_id)).or_default();
                *gap = gap
                    .checked_add(1)
                    .ok_or_else(|| "expired sender gap exhausted".to_string())?;
                removed = true;
                if is_new {
                    *global_gap_pairs = global_gap_pairs
                        .checked_add(1)
                        .ok_or_else(|| "expired sender gap accounting rejected".to_string())?;
                }
            } else if matches!(
                &delivery.payload,
                DeliveryPayload::Application { sender_code_id, .. }
                    if next_gaps
                        .get(&(code_id, *sender_code_id))
                        .is_some_and(|gap| *gap > MAX_RATCHET_BACK_HISTORY)
            ) {
                removed = true;
            } else {
                next_queue.push_back(delivery.clone());
            }
        }
        if removed {
            room.deliveries.insert(code_id, next_queue);
            room.expired_sender_gaps = next_gaps;
            compact_delivery_revisions(room, &code_id)?;
        }
    }
    Ok(())
}

fn membership_deliveries(
    room: &RelayRoom,
    transition: &MembershipTransition,
    next: &BTreeMap<String, Member>,
) -> Result<Vec<PendingDelivery>, String> {
    let mut deliveries = Vec::new();
    for (username, member) in &room.members {
        if member.code_id == room.owner_code_id || !next.contains_key(username) {
            continue;
        }
        deliveries.push(PendingDelivery {
            room_id: room.room_id.clone(),
            message_id: transition.message_id.clone(),
            recipient_code_id: member.code_id,
            epoch: transition.to_epoch,
            membership_digest: transition.membership_digest.clone(),
            revision: next_delivery_revision(room, &member.code_id)?,
            payload: DeliveryPayload::Membership {
                from_epoch: transition.from_epoch,
                from_membership_digest: transition.from_membership_digest.clone(),
                group_id: transition.group_id.clone(),
                roster: transition.roster.clone(),
                control: transition.control.clone(),
                welcome: Vec::new(),
                authenticated_data: transition.authenticated_data.clone(),
            },
            created_at_ms: transition.created_at_ms,
            expires_at_ms: u64::MAX,
        });
    }
    for (username, member) in next {
        if room.members.contains_key(username) {
            continue;
        }
        deliveries.push(PendingDelivery {
            room_id: room.room_id.clone(),
            message_id: transition.message_id.clone(),
            recipient_code_id: member.code_id,
            epoch: transition.to_epoch,
            membership_digest: transition.membership_digest.clone(),
            revision: 0,
            payload: DeliveryPayload::Membership {
                from_epoch: transition.from_epoch,
                from_membership_digest: transition.from_membership_digest.clone(),
                group_id: transition.group_id.clone(),
                roster: transition.roster.clone(),
                control: Vec::new(),
                welcome: transition.welcome.clone(),
                authenticated_data: transition.authenticated_data.clone(),
            },
            created_at_ms: transition.created_at_ms,
            expires_at_ms: u64::MAX,
        });
    }
    Ok(deliveries)
}

fn delivery_bytes<'a>(
    mut deliveries: impl Iterator<Item = &'a PendingDelivery>,
) -> Result<usize, String> {
    deliveries.try_fold(0_usize, |total, delivery| {
        total
            .checked_add(delivery_size(delivery)?)
            .ok_or_else(|| "delivery accounting rejected".to_string())
    })
}

fn delivery_size(delivery: &PendingDelivery) -> Result<usize, String> {
    let payload_bytes = match &delivery.payload {
        DeliveryPayload::Membership {
            from_membership_digest,
            group_id,
            roster,
            control,
            welcome,
            authenticated_data,
            ..
        } => {
            let roster_bytes = roster.iter().try_fold(0_usize, |total, member| {
                total
                    .checked_add(member.username.len())
                    .and_then(|bytes| bytes.checked_add(member.stable_identity.len()))
            });
            from_membership_digest
                .len()
                .checked_add(group_id.len())
                .and_then(|bytes| roster_bytes.and_then(|roster| bytes.checked_add(roster)))
                .and_then(|bytes| bytes.checked_add(control.len()))
                .and_then(|bytes| bytes.checked_add(welcome.len()))
                .and_then(|bytes| bytes.checked_add(authenticated_data.len()))
        }
        DeliveryPayload::Application {
            sender_code_id,
            sender_username,
            ciphertext,
            authenticated_data,
        } => sender_code_id
            .len()
            .checked_add(sender_username.len())
            .and_then(|bytes| bytes.checked_add(ciphertext.len()))
            .and_then(|bytes| bytes.checked_add(authenticated_data.len())),
    }
    .ok_or_else(|| "delivery accounting rejected".to_string())?;
    delivery
        .room_id
        .len()
        .checked_add(delivery.message_id.len())
        .and_then(|bytes| bytes.checked_add(delivery.membership_digest.len()))
        .and_then(|bytes| bytes.checked_add(payload_bytes))
        .ok_or_else(|| "delivery accounting rejected".to_string())
}

fn validate_transition(transition: &MembershipTransition) -> Result<(), String> {
    validate_room_id(&transition.room_id)?;
    validate_request_id(&transition.message_id)?;
    if let Some(request_id) = &transition.request_id {
        validate_request_id(request_id)?;
    }
    validate_group_id(&transition.group_id)?;
    validate_digest(&transition.membership_digest)?;
    if transition.control.is_empty() || transition.control.len() > MAX_CONTROL_BYTES {
        return Err("membership control rejected".to_string());
    }
    if transition.welcome.len() > MAX_CONTROL_BYTES {
        return Err("membership welcome rejected".to_string());
    }
    if transition.authenticated_data.is_empty()
        || transition.authenticated_data.len() > MAX_AUTHENTICATED_DATA_BYTES
    {
        return Err("membership authenticated data rejected".to_string());
    }
    if transition.state_envelope.is_empty() || transition.state_envelope.len() > MAX_STATE_BYTES {
        return Err("membership state rejected".to_string());
    }
    Ok(())
}

fn validate_current_metadata(
    room: &RelayRoom,
    group_id: &[u8],
    epoch: u64,
    membership_digest: &[u8],
) -> Result<(), String> {
    if room.group_id != group_id
        || room.epoch != epoch
        || room.membership_digest != membership_digest
    {
        return Err("room checkpoint rejected".to_string());
    }
    Ok(())
}

fn validate_room_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_ROOM_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("room id rejected".to_string());
    }
    Ok(())
}

fn validate_request_id(value: &str) -> Result<(), String> {
    validate_room_id(value).map_err(|_| "message id rejected".to_string())
}

fn validate_username(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_USERNAME_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("username rejected".to_string());
    }
    Ok(())
}

fn validate_group_id(value: &[u8]) -> Result<(), String> {
    if value.len() != GROUP_ID_BYTES || value.iter().all(|byte| *byte == 0) {
        return Err("group id rejected".to_string());
    }
    Ok(())
}

fn validate_digest(value: &[u8]) -> Result<(), String> {
    if value.len() != MEMBERSHIP_DIGEST_BYTES {
        return Err("membership digest rejected".to_string());
    }
    Ok(())
}

fn validate_stable_identity(value: &[u8]) -> Result<(), String> {
    if value.len() != STABLE_IDENTITY_BYTES || value.iter().all(|byte| *byte == 0) {
        return Err("stable identity rejected".to_string());
    }
    Ok(())
}

fn validate_state_envelope(value: &[u8]) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_STATE_BYTES {
        return Err("state snapshot rejected".to_string());
    }
    Ok(())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(seed: u8) -> CodeId {
        [seed; 32]
    }

    fn stable(seed: u8) -> Vec<u8> {
        vec![seed; STABLE_IDENTITY_BYTES]
    }

    fn digest(seed: u8) -> Vec<u8> {
        vec![seed; MEMBERSHIP_DIGEST_BYTES]
    }

    fn transition(
        room_id: &str,
        request: &JoinRequest,
        epoch: u64,
        revision: u64,
    ) -> MembershipTransition {
        MembershipTransition {
            room_id: room_id.to_string(),
            message_id: "commit-1".to_string(),
            request_id: Some(request.request_id.clone()),
            from_epoch: epoch,
            to_epoch: epoch.checked_add(1).expect("test epoch available"),
            revision,
            group_id: vec![7; GROUP_ID_BYTES],
            from_membership_digest: digest(8),
            membership_digest: digest(8),
            roster: vec![
                RosterMember {
                    username: "alice".to_string(),
                    stable_identity: stable(1),
                },
                RosterMember {
                    username: request.username.clone(),
                    stable_identity: request.stable_identity.clone(),
                },
            ],
            control: vec![1],
            welcome: vec![2],
            authenticated_data: vec![3],
            state_envelope: vec![4],
            created_at_ms: 0,
            expires_at_ms: 0,
        }
    }

    fn two_member_authority() -> RoomAuthority {
        let mut authority = RoomAuthority::new(2);
        authority
            .create(
                code(1),
                "alice".to_string(),
                "room-1".to_string(),
                vec![7; GROUP_ID_BYTES],
                0,
                0,
                digest(8),
                stable(1),
            )
            .unwrap();
        let request = authority
            .request_join(
                code(2),
                "bob".to_string(),
                "room-1",
                "request-1".to_string(),
                stable(2),
                vec![5],
                vec![9],
            )
            .unwrap();
        authority
            .begin_membership(code(1), transition("room-1", &request, 0, 1))
            .unwrap();
        authority
            .accept_membership(code(1), "room-1", "commit-1", 1)
            .unwrap();
        authority
    }

    #[test]
    fn exact_checkpoint_and_unique_roster_are_enforced() {
        let mut authority = RoomAuthority::new(2);
        authority
            .create(
                code(1),
                "alice".to_string(),
                "room-1".to_string(),
                vec![7; 32],
                0,
                0,
                digest(8),
                stable(1),
            )
            .unwrap();
        assert!(authority
            .create(
                code(2),
                "bob".to_string(),
                "room-1".to_string(),
                vec![7; 31],
                0,
                0,
                digest(8),
                stable(2)
            )
            .is_err());
        let request = authority
            .request_join(
                code(2),
                "bob".to_string(),
                "room-1",
                "request-1".to_string(),
                stable(2),
                vec![5],
                vec![9],
            )
            .unwrap();
        let mut commit = transition("room-1", &request, 0, 1);
        let mut bad_checkpoint = commit.clone();
        bad_checkpoint.from_membership_digest = digest(9);
        assert!(authority.begin_membership(code(1), bad_checkpoint).is_err());
        assert!(authority.begin_membership(code(1), commit.clone()).is_ok());
        assert!(authority.begin_membership(code(1), commit.clone()).is_err());
        commit.membership_digest = vec![8; 31];
        assert!(authority
            .accept_membership(code(1), "room-1", "commit-1", 2)
            .is_err());
    }

    #[test]
    fn membership_welcome_is_required_only_for_additions() {
        let mut authority = RoomAuthority::new(2);
        authority
            .create(
                code(1),
                "alice".to_string(),
                "room-1".to_string(),
                vec![7; GROUP_ID_BYTES],
                0,
                0,
                digest(8),
                stable(1),
            )
            .unwrap();
        let request = authority
            .request_join(
                code(2),
                "bob".to_string(),
                "room-1",
                "request-1".to_string(),
                stable(2),
                vec![5],
                vec![9],
            )
            .unwrap();
        let mut addition = transition("room-1", &request, 0, 1);
        addition.welcome.clear();
        assert_eq!(
            authority.begin_membership(code(1), addition).unwrap_err(),
            "membership welcome rejected"
        );

        let addition = transition("room-1", &request, 0, 1);
        authority.begin_membership(code(1), addition).unwrap();
        authority
            .accept_membership(code(1), "room-1", "commit-1", 1)
            .unwrap();
        let mut removal = MembershipTransition {
            room_id: "room-1".to_string(),
            message_id: "remove-1".to_string(),
            request_id: None,
            from_epoch: 1,
            to_epoch: 2,
            revision: 2,
            group_id: vec![7; GROUP_ID_BYTES],
            from_membership_digest: digest(8),
            membership_digest: digest(9),
            roster: vec![RosterMember {
                username: "alice".to_string(),
                stable_identity: stable(1),
            }],
            control: vec![1],
            welcome: Vec::new(),
            authenticated_data: vec![3],
            state_envelope: vec![4],
            created_at_ms: 0,
            expires_at_ms: 0,
        };
        assert!(authority.begin_membership(code(1), removal.clone()).is_ok());
        authority
            .rollback_membership(code(1), "room-1", "remove-1", 2)
            .unwrap();
        removal.message_id = "remove-2".to_string();
        removal.welcome = vec![2];
        assert_eq!(
            authority.begin_membership(code(1), removal).unwrap_err(),
            "membership welcome rejected"
        );
    }

    #[test]
    fn snapshot_acceptance_is_exactly_message_bound_and_idempotent() {
        let mut authority = active_two_member_authority();
        authority
            .admit_application(
                code(1),
                "room-1",
                "application-bound".to_string(),
                vec![7; GROUP_ID_BYTES],
                1,
                2,
                digest(8),
                vec![1],
                vec![2],
                vec![9],
            )
            .unwrap();
        authority
            .commit_application("room-1", "application-bound")
            .unwrap();
        let before = authority.deliveries_for_member("room-1", &code(2)).unwrap();
        assert!(authority
            .store_snapshot(
                code(2),
                "room-1",
                "wrong-message",
                1,
                1,
                digest(8),
                vec![10],
            )
            .is_err());
        assert_eq!(
            authority.deliveries_for_member("room-1", &code(2)).unwrap(),
            before
        );
        let accepted = authority
            .store_snapshot(
                code(2),
                "room-1",
                "application-bound",
                1,
                1,
                digest(8),
                vec![10],
            )
            .unwrap();
        assert_eq!(accepted.message_id, "application-bound");
        assert!(authority
            .store_snapshot(
                code(2),
                "room-1",
                "application-bound",
                1,
                1,
                digest(8),
                vec![10],
            )
            .is_ok());
        assert!(authority
            .store_snapshot(
                code(2),
                "room-1",
                "application-bound",
                1,
                1,
                digest(8),
                vec![11],
            )
            .is_err());
        assert!(authority
            .store_snapshot(
                code(2),
                "room-1",
                "different-message",
                1,
                1,
                digest(8),
                vec![10],
            )
            .is_err());
    }

    #[test]
    fn membership_accept_and_rollback_require_exact_result() {
        let mut authority = RoomAuthority::new(2);
        authority
            .create(
                code(1),
                "alice".to_string(),
                "room-1".to_string(),
                vec![7; 32],
                0,
                0,
                digest(8),
                stable(1),
            )
            .unwrap();
        let request = authority
            .request_join(
                code(2),
                "bob".to_string(),
                "room-1",
                "request-1".to_string(),
                stable(2),
                vec![5],
                vec![9],
            )
            .unwrap();
        let commit = transition("room-1", &request, 0, 1);
        authority.begin_membership(code(1), commit).unwrap();
        assert!(authority
            .rollback_membership(code(1), "room-1", "commit-1", 2)
            .is_err());
        assert!(matches!(
            authority.rollback_membership(code(1), "room-1", "commit-1", 1),
            Ok(MembershipResult::RolledBack { .. })
        ));
        assert_eq!(authority.info("room-1").unwrap().roster.len(), 1);
    }

    #[test]
    fn applications_are_member_only_bounded_and_replay_safe() {
        let mut authority = RoomAuthority::new(1);
        authority
            .create(
                code(1),
                "alice".to_string(),
                "room-1".to_string(),
                vec![7; 32],
                0,
                0,
                digest(8),
                stable(1),
            )
            .unwrap();
        assert!(authority
            .admit_application(
                code(2),
                "room-1",
                "message-1".to_string(),
                vec![7; 32],
                0,
                1,
                digest(8),
                vec![1],
                vec![2],
                vec![9],
            )
            .is_err());
        let admission = authority
            .admit_application(
                code(1),
                "room-1",
                "message-1".to_string(),
                vec![7; 32],
                0,
                1,
                digest(8),
                vec![1],
                vec![2],
                vec![9],
            )
            .unwrap();
        assert!(admission.recipient_code_ids.is_empty());
        authority.commit_application("room-1", "message-1").unwrap();
        assert!(authority
            .admit_application(
                code(1),
                "room-1",
                "message-1".to_string(),
                vec![7; 32],
                0,
                1,
                digest(8),
                vec![1],
                vec![2],
                vec![9]
            )
            .is_err());
    }

    #[test]
    fn active_member_join_is_rejected_without_state_or_accounting_mutation() {
        let mut authority = active_two_member_authority();
        let before = authority.info("room-1").unwrap();
        let before_snapshot_count = authority.global_snapshot_count;
        let before_snapshot_bytes = authority.global_snapshot_bytes;
        let before_join_count = authority.rooms["room-1"].joins.len();

        assert!(authority
            .request_join(
                code(2),
                "bob".to_string(),
                "room-1",
                "online-duplicate-join".to_string(),
                stable(2),
                vec![5],
                vec![9],
            )
            .is_err());

        assert_eq!(authority.info("room-1").unwrap(), before);
        assert_eq!(authority.global_snapshot_count, before_snapshot_count);
        assert_eq!(authority.global_snapshot_bytes, before_snapshot_bytes);
        assert_eq!(authority.rooms["room-1"].joins.len(), before_join_count);
    }

    #[test]
    fn empty_authenticated_data_is_rejected_before_membership_or_application_mutation() {
        let mut authority = RoomAuthority::new(2);
        authority
            .create(
                code(1),
                "alice".to_string(),
                "room-1".to_string(),
                vec![7; GROUP_ID_BYTES],
                0,
                0,
                digest(8),
                stable(1),
            )
            .unwrap();
        let request = authority
            .request_join(
                code(2),
                "bob".to_string(),
                "room-1",
                "request-empty-aad".to_string(),
                stable(2),
                vec![5],
                vec![9],
            )
            .unwrap();
        let mut membership = transition("room-1", &request, 0, 1);
        membership.authenticated_data.clear();
        let before = authority.info("room-1").unwrap();
        let before_snapshot_count = authority.global_snapshot_count;
        let before_snapshot_bytes = authority.global_snapshot_bytes;
        assert!(authority.begin_membership(code(1), membership).is_err());
        assert_eq!(authority.info("room-1").unwrap(), before);
        assert_eq!(authority.global_snapshot_count, before_snapshot_count);
        assert_eq!(authority.global_snapshot_bytes, before_snapshot_bytes);
        assert!(authority.rooms["room-1"].pending_transition.is_none());

        let mut active = active_two_member_authority();
        let before = active.info("room-1").unwrap();
        let before_pending_count = active.global_pending_count;
        let before_pending_bytes = active.global_pending_bytes;
        let before_revision = active.rooms["room-1"].member_revisions[&code(1)];
        assert!(active
            .admit_application(
                code(1),
                "room-1",
                "application-empty-aad".to_string(),
                vec![7; GROUP_ID_BYTES],
                1,
                1,
                digest(8),
                vec![1],
                Vec::new(),
                vec![9],
            )
            .is_err());
        assert_eq!(active.info("room-1").unwrap(), before);
        assert_eq!(active.global_pending_count, before_pending_count);
        assert_eq!(active.global_pending_bytes, before_pending_bytes);
        assert_eq!(
            active.rooms["room-1"].member_revisions[&code(1)],
            before_revision
        );
        assert!(active.rooms["room-1"].pending_applications.is_empty());
    }

    #[test]
    fn replay_domains_and_inactive_members_are_isolated() {
        let mut authority = two_member_authority();
        assert_eq!(
            authority.active_member_code_ids("room-1").unwrap(),
            vec![code(1)]
        );

        let cross_domain_id = "cross-domain-id";
        let admission = authority
            .admit_application(
                code(1),
                "room-1",
                cross_domain_id.to_string(),
                vec![7; GROUP_ID_BYTES],
                1,
                2,
                digest(8),
                vec![1],
                vec![2],
                vec![9],
            )
            .unwrap();
        assert!(admission.recipient_code_ids.is_empty());
        authority
            .commit_application("room-1", cross_domain_id)
            .unwrap();

        let request = authority
            .request_join(
                code(3),
                "carol".to_string(),
                "room-1",
                "request-3".to_string(),
                stable(3),
                vec![5],
                vec![9],
            )
            .unwrap();
        let mut membership = transition("room-1", &request, 1, 3);
        membership.message_id = cross_domain_id.to_string();
        membership.roster.insert(
            1,
            RosterMember {
                username: "bob".to_string(),
                stable_identity: stable(2),
            },
        );
        authority
            .begin_membership(code(1), membership.clone())
            .unwrap();
        authority
            .accept_membership(code(1), "room-1", cross_domain_id, 3)
            .unwrap();
        let replay_ids = &authority.rooms["room-1"].replay_ids;
        assert!(replay_ids.iter().any(|(key, _)| {
            key.domain == ReplayDomain::Application && key.message_id == cross_domain_id
        }));
        assert!(replay_ids.iter().any(|(key, _)| {
            key.domain == ReplayDomain::Membership && key.message_id == cross_domain_id
        }));
        assert_eq!(authority.global_replay_count, replay_ids.len());

        let before = authority.info("room-1").unwrap();
        let replay_count = authority.global_replay_count;
        let snapshot_count = authority.global_snapshot_count;
        let snapshot_bytes = authority.global_snapshot_bytes;
        let mut duplicate = membership;
        duplicate.revision = 4;
        duplicate.from_epoch = 2;
        duplicate.to_epoch = 3;
        assert!(authority.begin_membership(code(1), duplicate).is_err());
        assert_eq!(authority.info("room-1").unwrap(), before);
        assert_eq!(authority.global_replay_count, replay_count);
        assert_eq!(authority.global_snapshot_count, snapshot_count);
        assert_eq!(authority.global_snapshot_bytes, snapshot_bytes);
        assert!(authority.rooms["room-1"].pending_transition.is_none());
    }

    #[test]
    fn application_ciphertext_cap_is_exact_and_oversize_fails_before_mutation() {
        let mut authority = active_two_member_authority();
        let boundary = authority
            .admit_application(
                code(1),
                "room-1",
                "application-boundary".to_string(),
                vec![7; GROUP_ID_BYTES],
                1,
                2,
                digest(8),
                vec![0; MAX_APPLICATION_CIPHERTEXT_BYTES],
                vec![2],
                vec![9],
            )
            .unwrap();
        assert_eq!(boundary.ciphertext.len(), MAX_APPLICATION_CIPHERTEXT_BYTES);
        authority
            .rollback_application("room-1", "application-boundary")
            .unwrap();

        let room = authority.rooms.get("room-1").unwrap();
        let before_pending_bytes = room.pending_bytes;
        let before_pending_count = room.pending_applications.len();
        let before_revision = room.member_revisions[&code(1)];
        let before_global_pending_bytes = authority.global_pending_bytes;
        let before_global_pending_count = authority.global_pending_count;
        assert!(authority
            .admit_application(
                code(1),
                "room-1",
                "application-oversize".to_string(),
                vec![7; GROUP_ID_BYTES],
                1,
                2,
                digest(8),
                vec![0; MAX_APPLICATION_CIPHERTEXT_BYTES + 1],
                vec![2],
                vec![9],
            )
            .is_err());
        let room = authority.rooms.get("room-1").unwrap();
        assert_eq!(room.pending_bytes, before_pending_bytes);
        assert_eq!(room.pending_applications.len(), before_pending_count);
        assert_eq!(room.member_revisions[&code(1)], before_revision);
        assert_eq!(authority.global_pending_bytes, before_global_pending_bytes);
        assert_eq!(authority.global_pending_count, before_global_pending_count);
    }

    #[test]
    fn catalogs_are_caller_scoped_and_nonmember_discovery_is_minimal() {
        let mut authority = RoomAuthority::new(1);
        let info = authority
            .create_with_policy_and_state(
                code(1),
                "alice".to_string(),
                "room-1".to_string(),
                vec![7; GROUP_ID_BYTES],
                0,
                0,
                digest(8),
                stable(1),
                RoomPolicy {
                    allow_images: false,
                    ..RoomPolicy::default()
                },
                vec![9],
            )
            .unwrap();
        assert_eq!(info.revision, 0);
        assert_eq!(
            info.recovery_snapshot
                .as_ref()
                .map(|snapshot| snapshot.epoch),
            Some(0)
        );
        assert_eq!(
            info.recovery_snapshot
                .as_ref()
                .map(|snapshot| snapshot.state_envelope.clone()),
            Some(vec![9])
        );
        assert!(!info.policy.allow_images);

        let member = authority.member_info("room-1", &code(1)).unwrap();
        assert_eq!(member.revision, 0);
        assert_eq!(
            member
                .recovery_snapshot
                .as_ref()
                .map(|snapshot| snapshot.revision),
            Some(0)
        );
        let discovery = authority.discover("room-1").unwrap();
        assert_eq!(discovery.owner_username, "alice");
        assert_eq!(discovery.group_id, vec![7; GROUP_ID_BYTES]);
        assert!(discovery.roster.is_empty());
        assert!(discovery.recovery_snapshot.is_none());
    }

    #[test]
    fn active_snapshots_survive_ttl_and_wipe_clears_all_room_state() {
        let mut authority = RoomAuthority::with_ttls(1, 1, 1, 1, 0);
        authority
            .create(
                code(1),
                "alice".to_string(),
                "room-1".to_string(),
                vec![7; 32],
                0,
                0,
                digest(8),
                stable(1),
            )
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert!(authority.snapshot(&code(1), "room-1").is_some());
        authority.wipe();
        assert_eq!(authority.room_count(), 0);
    }

    #[test]
    fn offline_delivery_survives_response_loss_until_snapshot() {
        let mut authority = two_member_authority();
        let delivery = authority
            .deliveries_for_member("room-1", &code(2))
            .unwrap()
            .pop()
            .expect("new member welcome is queued");
        assert!(authority
            .deliveries_for_member("room-1", &code(1))
            .unwrap()
            .is_empty());
        assert_eq!(
            authority
                .deliveries_for_member("room-1", &code(2))
                .unwrap()
                .len(),
            1
        );
        authority
            .store_snapshot(
                code(2),
                "room-1",
                &delivery.message_id,
                delivery.epoch,
                delivery.revision,
                digest(8),
                vec![9],
            )
            .unwrap();
        assert!(authority
            .deliveries_for_member("room-1", &code(2))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn member_revisions_diverge_and_snapshot_acks_queued_application() {
        let mut authority = two_member_authority();
        let welcome = authority
            .deliveries_for_member("room-1", &code(2))
            .unwrap()
            .pop()
            .unwrap();
        authority
            .store_snapshot(
                code(2),
                "room-1",
                &welcome.message_id,
                welcome.epoch,
                welcome.revision,
                digest(8),
                vec![9],
            )
            .unwrap();
        let admission = authority
            .admit_application(
                code(1),
                "room-1",
                "application-1".to_string(),
                vec![7; GROUP_ID_BYTES],
                1,
                2,
                digest(8),
                vec![1],
                vec![2],
                vec![9],
            )
            .unwrap();
        authority
            .commit_application("room-1", "application-1")
            .unwrap();
        assert_eq!(authority.member_revision("room-1", &code(1)).unwrap(), 2);
        assert_eq!(
            authority
                .snapshot(&code(1), "room-1")
                .expect("sender snapshot")
                .state_envelope,
            vec![9]
        );
        assert_eq!(authority.member_revision("room-1", &code(2)).unwrap(), 0);
        let application = authority
            .deliveries_for_member("room-1", &code(2))
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(application.message_id, admission.message_id);
        assert_eq!(application.revision, 1);
        let snapshot = authority
            .store_snapshot(
                code(2),
                "room-1",
                &application.message_id,
                1,
                1,
                digest(8),
                vec![9],
            )
            .unwrap();
        assert_eq!(snapshot.revision, 1);
        assert!(authority
            .deliveries_for_member("room-1", &code(2))
            .unwrap()
            .is_empty());
        assert_eq!(authority.member_revision("room-1", &code(2)).unwrap(), 1);
    }

    #[test]
    fn membership_delivery_survives_ttl_and_global_delivery_limit_is_atomic() {
        let mut authority = two_member_authority();
        let welcome = authority
            .deliveries_for_member("room-1", &code(2))
            .unwrap()
            .pop()
            .unwrap();
        for queue in authority
            .rooms
            .get_mut("room-1")
            .unwrap()
            .deliveries
            .values_mut()
        {
            for delivery in queue {
                delivery.expires_at_ms = 0;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert_eq!(
            authority
                .deliveries_for_member("room-1", &code(2))
                .unwrap()
                .len(),
            1
        );
        authority
            .store_snapshot(
                code(2),
                "room-1",
                &welcome.message_id,
                welcome.epoch,
                welcome.revision,
                digest(8),
                vec![9],
            )
            .unwrap();
        assert!(authority.member_info("room-1", &code(2)).unwrap().active);

        let mut bounded = two_member_authority();
        bounded.set_delivery_limits(0, usize::MAX);
        let request = bounded
            .request_join(
                code(3),
                "carol".to_string(),
                "room-1",
                "request-2".to_string(),
                stable(3),
                vec![6],
                vec![9],
            )
            .unwrap();
        let mut transition = transition("room-1", &request, 1, 2);
        transition.message_id = "commit-2".to_string();
        transition.from_epoch = 1;
        transition.to_epoch = 2;
        transition.revision = 2;
        transition.roster = vec![
            RosterMember {
                username: "alice".to_string(),
                stable_identity: stable(1),
            },
            RosterMember {
                username: "bob".to_string(),
                stable_identity: stable(2),
            },
            RosterMember {
                username: "carol".to_string(),
                stable_identity: stable(3),
            },
        ];
        bounded.begin_membership(code(1), transition).unwrap();
        assert!(bounded
            .accept_membership(code(1), "room-1", "commit-2", 2)
            .is_err());
        assert_eq!(bounded.info("room-1").unwrap().epoch, 1);
    }

    #[test]
    fn inbound_delivery_queues_gate_sender_and_owner_state_changes() {
        let mut authority = two_member_authority();
        let mut removal = MembershipTransition {
            room_id: "room-1".to_string(),
            message_id: "remove-1".to_string(),
            request_id: None,
            from_epoch: 1,
            to_epoch: 2,
            revision: 2,
            group_id: vec![7; GROUP_ID_BYTES],
            from_membership_digest: digest(8),
            membership_digest: digest(9),
            roster: vec![RosterMember {
                username: "alice".to_string(),
                stable_identity: stable(1),
            }],
            control: vec![1],
            welcome: Vec::new(),
            authenticated_data: vec![3],
            state_envelope: vec![4],
            created_at_ms: 0,
            expires_at_ms: 0,
        };
        assert!(authority
            .admit_application(
                code(2),
                "room-1",
                "application-queue".to_string(),
                vec![7; GROUP_ID_BYTES],
                1,
                1,
                digest(8),
                vec![1],
                vec![2],
                vec![9],
            )
            .is_err());
        authority
            .store_snapshot(code(2), "room-1", "commit-1", 1, 0, digest(8), vec![9])
            .unwrap();
        let admission = authority
            .admit_application(
                code(2),
                "room-1",
                "application-owner-queue".to_string(),
                vec![7; GROUP_ID_BYTES],
                1,
                1,
                digest(8),
                vec![1],
                vec![2],
                vec![9],
            )
            .unwrap();
        assert!(admission.recipient_code_ids.contains(&code(1)));
        assert!(authority
            .begin_membership(code(1), removal.clone())
            .is_err());
        authority
            .rollback_application("room-1", "application-owner-queue")
            .unwrap();
        removal.message_id = "remove-2".to_string();
        assert!(authority.begin_membership(code(1), removal).is_ok());
    }

    #[test]
    fn pending_membership_blocks_outgoing_application_admission() {
        let mut authority = two_member_authority();
        let request = authority
            .request_join(
                code(3),
                "carol".to_string(),
                "room-1",
                "request-pending-app".to_string(),
                stable(3),
                vec![6],
                vec![9],
            )
            .unwrap();
        let mut membership = transition("room-1", &request, 1, 2);
        membership.message_id = "pending-membership".to_string();
        membership.roster.insert(
            1,
            RosterMember {
                username: "bob".to_string(),
                stable_identity: stable(2),
            },
        );
        authority.begin_membership(code(1), membership).unwrap();
        assert!(authority
            .admit_application(
                code(1),
                "room-1",
                "blocked-application".to_string(),
                vec![7; GROUP_ID_BYTES],
                1,
                2,
                digest(8),
                vec![1],
                vec![2],
                vec![9],
            )
            .is_err());
        authority
            .rollback_membership(code(1), "room-1", "pending-membership", 2)
            .unwrap();
        assert!(authority
            .admit_application(
                code(1),
                "room-1",
                "allowed-application".to_string(),
                vec![7; GROUP_ID_BYTES],
                1,
                2,
                digest(8),
                vec![1],
                vec![2],
                vec![9],
            )
            .is_ok());
    }

    #[test]
    fn application_rollback_restores_revision_snapshot_and_delivery_budget() {
        let mut authority = two_member_authority();
        authority
            .store_snapshot(code(2), "room-1", "commit-1", 1, 0, digest(8), vec![9])
            .unwrap();
        let before = authority.snapshot(&code(1), "room-1").unwrap();
        authority
            .admit_application(
                code(1),
                "room-1",
                "application-rollback".to_string(),
                vec![7; GROUP_ID_BYTES],
                1,
                2,
                digest(8),
                vec![1],
                vec![2],
                vec![10],
            )
            .unwrap();
        assert!(!authority
            .deliveries_for_member("room-1", &code(2))
            .unwrap()
            .is_empty());
        authority
            .rollback_application("room-1", "application-rollback")
            .unwrap();
        assert!(authority
            .deliveries_for_member("room-1", &code(2))
            .unwrap()
            .is_empty());
        assert_eq!(authority.member_revision("room-1", &code(1)).unwrap(), 1);
        assert_eq!(authority.snapshot(&code(1), "room-1").unwrap(), before);
    }

    #[test]
    fn snapshot_retirement_uses_delivery_checkpoint_not_room_current_checkpoint() {
        let mut authority = two_member_authority();
        authority
            .store_snapshot(code(2), "room-1", "commit-1", 1, 0, digest(8), vec![9])
            .unwrap();
        authority
            .admit_application(
                code(1),
                "room-1",
                "application-stale-room".to_string(),
                vec![7; GROUP_ID_BYTES],
                1,
                2,
                digest(8),
                vec![1],
                vec![2],
                vec![10],
            )
            .unwrap();
        authority
            .commit_application("room-1", "application-stale-room")
            .unwrap();
        let delivery = authority
            .deliveries_for_member("room-1", &code(2))
            .unwrap()
            .pop()
            .unwrap();
        let room = authority.rooms.get_mut("room-1").unwrap();
        room.epoch = 99;
        room.membership_digest = digest(99);
        authority
            .store_snapshot(
                code(2),
                "room-1",
                &delivery.message_id,
                delivery.epoch,
                delivery.revision,
                delivery.membership_digest.clone(),
                vec![11],
            )
            .unwrap();
        assert!(authority
            .deliveries_for_member("room-1", &code(2))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn removed_member_state_is_purged_with_its_unreachable_queue() {
        let mut authority = two_member_authority();
        let removal = MembershipTransition {
            room_id: "room-1".to_string(),
            message_id: "remove-member".to_string(),
            request_id: None,
            from_epoch: 1,
            to_epoch: 2,
            revision: 2,
            group_id: vec![7; GROUP_ID_BYTES],
            from_membership_digest: digest(8),
            membership_digest: digest(9),
            roster: vec![RosterMember {
                username: "alice".to_string(),
                stable_identity: stable(1),
            }],
            control: vec![1],
            welcome: Vec::new(),
            authenticated_data: vec![3],
            state_envelope: vec![4],
            created_at_ms: 0,
            expires_at_ms: 0,
        };
        authority.begin_membership(code(1), removal).unwrap();
        authority
            .accept_membership(code(1), "room-1", "remove-member", 2)
            .unwrap();
        let room = authority.rooms.get("room-1").unwrap();
        assert!(!room
            .members
            .values()
            .any(|member| member.code_id == code(2)));
        assert!(!room.deliveries.contains_key(&code(2)));
        assert!(!room.snapshots.contains_key(&code(2)));
        assert_eq!(room.delivery_bytes, 0);
    }

    #[test]
    fn pending_join_replay_is_bounded_and_owner_scoped() {
        let mut authority = RoomAuthority::new(1);
        authority
            .create(
                code(1),
                "alice".to_string(),
                "room-1".to_string(),
                vec![7; GROUP_ID_BYTES],
                0,
                0,
                digest(8),
                stable(1),
            )
            .unwrap();
        authority
            .request_join(
                code(2),
                "bob".to_string(),
                "room-1",
                "request-1".to_string(),
                stable(2),
                vec![5],
                vec![9],
            )
            .unwrap();
        assert_eq!(authority.pending_joins_for_owner(&code(1)).len(), 1);
        assert!(authority.pending_joins_for_owner(&code(2)).is_empty());
    }

    #[test]
    fn private_join_recovery_survives_reconnect_and_activates_on_welcome_snapshot() {
        let mut authority = RoomAuthority::new(2);
        authority
            .create(
                code(1),
                "alice".to_string(),
                "room-1".to_string(),
                vec![7; GROUP_ID_BYTES],
                0,
                0,
                digest(8),
                stable(1),
            )
            .unwrap();
        let private_recovery = vec![173, 173, 173];
        let request = authority
            .request_join(
                code(2),
                "bob".to_string(),
                "room-1",
                "request-1".to_string(),
                stable(2),
                vec![5],
                private_recovery.clone(),
            )
            .unwrap();

        let owner_request = authority.pending_joins_for_owner(&code(1)).pop().unwrap();
        assert_eq!(owner_request, request);
        assert!(!format!("{owner_request:?}").contains("[173, 173, 173]"));
        let first_reconnect = authority.pending_rooms_for_member(&code(2));
        let second_reconnect = authority.pending_rooms_for_member(&code(2));
        for pending in [&first_reconnect, &second_reconnect] {
            assert!(!pending[0].active);
            let recovery = pending[0].recovery_snapshot.as_ref().unwrap();
            assert!(!recovery.active);
            assert_eq!(recovery.epoch, 0);
            assert_eq!(recovery.revision, 0);
            assert!(recovery.membership_digest.is_empty());
            assert_eq!(recovery.state_envelope, private_recovery);
        }
        assert_eq!(authority.global_snapshot_count, 2);
        assert_eq!(authority.global_snapshot_bytes, 73);

        authority
            .begin_membership(code(1), transition("room-1", &request, 0, 1))
            .unwrap();
        authority
            .accept_membership(code(1), "room-1", "commit-1", 1)
            .unwrap();
        assert!(authority.pending_rooms_for_member(&code(2)).is_empty());
        let room = authority.rooms.get("room-1").unwrap();
        assert!(room.joins.is_empty());
        assert_eq!(room.snapshot_bytes, 140);
        assert_eq!(authority.global_snapshot_count, 2);
        assert_eq!(authority.global_snapshot_bytes, 140);
        let inactive = authority.member_info("room-1", &code(2)).unwrap();
        assert!(!inactive.active);
        assert!(!inactive.recovery_snapshot.as_ref().unwrap().active);
        assert_eq!(
            inactive.recovery_snapshot.unwrap().state_envelope,
            private_recovery
        );

        let welcome = authority
            .deliveries_for_member("room-1", &code(2))
            .unwrap()
            .pop()
            .unwrap();
        authority
            .store_snapshot(
                code(2),
                "room-1",
                &welcome.message_id,
                welcome.epoch,
                welcome.revision,
                welcome.membership_digest.clone(),
                vec![7, 8],
            )
            .unwrap();
        let active = authority.member_info("room-1", &code(2)).unwrap();
        assert!(active.active);
        let active_recovery = active.recovery_snapshot.unwrap();
        assert!(active_recovery.active);
        assert_eq!(active_recovery.epoch, 1);
        assert_eq!(active_recovery.revision, 0);
        assert_eq!(active_recovery.membership_digest, digest(8));
        assert_eq!(active_recovery.state_envelope, vec![7, 8]);
        assert_eq!(authority.rooms["room-1"].snapshot_bytes, 275);
        assert_eq!(authority.global_snapshot_bytes, 275);
    }

    #[test]
    fn inactive_joiner_membership_delivery_does_not_expire() {
        let mut authority = RoomAuthority::new(2);
        authority
            .create(
                code(1),
                "alice".to_string(),
                "room-1".to_string(),
                vec![7; GROUP_ID_BYTES],
                0,
                0,
                digest(8),
                stable(1),
            )
            .unwrap();
        let request = authority
            .request_join(
                code(2),
                "bob".to_string(),
                "room-1",
                "request-1".to_string(),
                stable(2),
                vec![5],
                vec![9],
            )
            .unwrap();
        authority
            .begin_membership(code(1), transition("room-1", &request, 0, 1))
            .unwrap();
        authority
            .accept_membership(code(1), "room-1", "commit-1", 1)
            .unwrap();

        authority
            .rooms
            .get_mut("room-1")
            .unwrap()
            .deliveries
            .get_mut(&code(2))
            .unwrap()
            .front_mut()
            .unwrap()
            .expires_at_ms = 0;
        assert_eq!(
            authority
                .deliveries_for_member("room-1", &code(2))
                .unwrap()
                .len(),
            1
        );

        authority
            .store_snapshot(code(2), "room-1", "commit-1", 1, 0, digest(8), vec![7])
            .unwrap();
        assert!(authority.member_info("room-1", &code(2)).unwrap().active);
    }

    #[test]
    fn snapshot_retirement_rejects_out_of_order_active_deliveries() {
        let mut authority = active_two_member_authority();
        authority
            .admit_application(
                code(1),
                "room-1",
                "application-first".to_string(),
                vec![7; GROUP_ID_BYTES],
                1,
                2,
                digest(8),
                vec![1],
                vec![2],
                vec![9],
            )
            .unwrap();
        authority
            .commit_application("room-1", "application-first")
            .unwrap();
        authority
            .admit_application(
                code(1),
                "room-1",
                "application-second".to_string(),
                vec![7; GROUP_ID_BYTES],
                1,
                3,
                digest(8),
                vec![1],
                vec![2],
                vec![9],
            )
            .unwrap();
        authority
            .commit_application("room-1", "application-second")
            .unwrap();
        let room = authority.rooms.get_mut("room-1").unwrap();
        let queue = room.deliveries.get_mut(&code(2)).unwrap();
        assert_eq!(queue.len(), 2);
        queue.swap(0, 1);
        let before = queue.clone();

        assert!(authority
            .store_snapshot(
                code(2),
                "room-1",
                "application-second",
                1,
                2,
                digest(8),
                vec![7],
            )
            .is_err());
        assert_eq!(
            authority.deliveries_for_member("room-1", &code(2)).unwrap(),
            before.into_iter().collect::<Vec<_>>()
        );
        assert!(authority.member_info("room-1", &code(2)).unwrap().active);
    }

    #[test]
    fn epoch_and_delivery_revision_exhaustion_fail_closed_without_max_loop() {
        let mut authority = RoomAuthority::new(2);
        authority
            .create(
                code(1),
                "alice".to_string(),
                "room-1".to_string(),
                vec![7; GROUP_ID_BYTES],
                0,
                0,
                digest(8),
                stable(1),
            )
            .unwrap();
        let request = authority
            .request_join(
                code(2),
                "bob".to_string(),
                "room-1",
                "request-1".to_string(),
                stable(2),
                vec![5],
                vec![9],
            )
            .unwrap();
        authority.rooms.get_mut("room-1").unwrap().epoch = u64::MAX;
        let exhausted_epoch = MembershipTransition {
            room_id: "room-1".to_string(),
            message_id: "commit-max".to_string(),
            request_id: Some(request.request_id.clone()),
            from_epoch: u64::MAX,
            to_epoch: u64::MAX,
            revision: 1,
            group_id: vec![7; GROUP_ID_BYTES],
            from_membership_digest: digest(8),
            membership_digest: digest(9),
            roster: vec![
                RosterMember {
                    username: "alice".to_string(),
                    stable_identity: stable(1),
                },
                RosterMember {
                    username: "bob".to_string(),
                    stable_identity: stable(2),
                },
            ],
            control: vec![1],
            welcome: vec![2],
            authenticated_data: vec![3],
            state_envelope: vec![4],
            created_at_ms: 0,
            expires_at_ms: 0,
        };
        assert_eq!(
            authority
                .begin_membership(code(1), exhausted_epoch)
                .unwrap_err(),
            "membership epoch rejected"
        );
        assert!(authority.rooms["room-1"].pending_transition.is_none());

        let mut authority = two_member_authority();
        let room = authority.rooms.get_mut("room-1").unwrap();
        let mut welcome = room
            .deliveries
            .get_mut(&code(2))
            .unwrap()
            .pop_front()
            .unwrap();
        welcome.revision = u64::MAX;
        room.deliveries
            .get_mut(&code(2))
            .unwrap()
            .push_back(welcome);
        room.member_revisions.insert(code(2), u64::MAX);
        assert_eq!(
            next_delivery_revision(room, &code(2)).unwrap_err(),
            "delivery revision exhausted"
        );
        authority
            .store_snapshot(
                code(2),
                "room-1",
                "commit-1",
                1,
                u64::MAX,
                digest(8),
                vec![7],
            )
            .unwrap();
        assert!(authority
            .deliveries_for_member("room-1", &code(2))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn application_and_delete_accounting_reject_corruption_or_recompute_exactly() {
        let mut authority = active_two_member_authority();
        authority
            .admit_application(
                code(1),
                "room-1",
                "application-1".to_string(),
                vec![7; GROUP_ID_BYTES],
                1,
                2,
                digest(8),
                vec![1],
                vec![2],
                vec![9],
            )
            .unwrap();
        let pending_bytes = authority.rooms["room-1"].pending_bytes;
        authority.rooms.get_mut("room-1").unwrap().pending_bytes = 0;
        assert_eq!(
            authority
                .commit_application("room-1", "application-1")
                .unwrap_err(),
            "pending application accounting rejected"
        );
        assert!(authority.rooms["room-1"]
            .pending_applications
            .contains_key("application-1"));
        assert_eq!(authority.rooms["room-1"].replay_ids.len(), 1);
        assert!(authority.rooms["room-1"]
            .replay_ids
            .iter()
            .all(|(key, _)| key.domain == ReplayDomain::Membership));

        authority.rooms.get_mut("room-1").unwrap().pending_bytes = pending_bytes;
        authority.global_delivery_count = 0;
        assert_eq!(
            authority
                .rollback_application("room-1", "application-1")
                .unwrap_err(),
            "delivery accounting rejected"
        );
        assert!(authority.rooms["room-1"]
            .pending_applications
            .contains_key("application-1"));
        let totals = authority.checked_accounting_excluding(None).unwrap();
        authority.apply_accounting(totals);
        authority
            .rollback_application("room-1", "application-1")
            .unwrap();
        assert!(authority.rooms["room-1"].pending_applications.is_empty());

        authority.global_pending_count = usize::MAX;
        authority.global_pending_bytes = usize::MAX;
        authority.global_snapshot_count = usize::MAX;
        authority.global_snapshot_bytes = usize::MAX;
        authority.global_replay_count = usize::MAX;
        authority.global_delivery_count = usize::MAX;
        authority.global_delivery_bytes = usize::MAX;
        authority.delete(code(1), "room-1").unwrap();
        assert_eq!(authority.global_pending_count, 0);
        assert_eq!(authority.global_pending_bytes, 0);
        assert_eq!(authority.global_snapshot_count, 0);
        assert_eq!(authority.global_snapshot_bytes, 0);
        assert_eq!(authority.global_replay_count, 0);
        assert_eq!(authority.global_delivery_count, 0);
        assert_eq!(authority.global_delivery_bytes, 0);
    }

    #[test]
    fn application_budget_preflight_fails_without_partial_mutation() {
        let mut authority = active_two_member_authority();
        authority.prune_expired(now_ms());
        let before_deliveries = authority.rooms["room-1"].deliveries.clone();
        let before_snapshot = authority.rooms["room-1"].snapshots.get(&code(1)).cloned();
        let before_revision = authority.rooms["room-1"].member_revisions[&code(1)];
        authority.max_delivery_count = 0;
        assert_eq!(
            authority
                .admit_application(
                    code(1),
                    "room-1",
                    "application-overflow".to_string(),
                    vec![7; GROUP_ID_BYTES],
                    1,
                    2,
                    digest(8),
                    vec![1],
                    vec![2],
                    vec![9],
                )
                .unwrap_err(),
            "room delivery budget reached"
        );
        assert!(authority.rooms["room-1"].pending_applications.is_empty());
        assert_eq!(authority.rooms["room-1"].deliveries, before_deliveries);
        assert_eq!(
            authority.rooms["room-1"].snapshots.get(&code(1)),
            before_snapshot.as_ref()
        );
        assert_eq!(
            authority.rooms["room-1"].member_revisions[&code(1)],
            before_revision
        );
    }

    fn active_two_member_authority() -> RoomAuthority {
        let mut authority = two_member_authority();
        let welcome = authority
            .deliveries_for_member("room-1", &code(2))
            .unwrap()
            .pop()
            .unwrap();
        authority
            .store_snapshot(
                code(2),
                "room-1",
                &welcome.message_id,
                welcome.epoch,
                welcome.revision,
                welcome.membership_digest.clone(),
                vec![7],
            )
            .unwrap();
        authority
    }

    fn leave_transition(request: &LeaveRequest) -> MembershipTransition {
        MembershipTransition {
            room_id: request.room_id.clone(),
            message_id: "leave-commit".to_string(),
            request_id: Some(request.request_id.clone()),
            from_epoch: 1,
            to_epoch: 2,
            revision: 2,
            group_id: vec![7; GROUP_ID_BYTES],
            from_membership_digest: digest(8),
            membership_digest: digest(10),
            roster: vec![RosterMember {
                username: "alice".to_string(),
                stable_identity: stable(1),
            }],
            control: vec![1],
            welcome: Vec::new(),
            authenticated_data: vec![3],
            state_envelope: vec![4],
            created_at_ms: 0,
            expires_at_ms: 0,
        }
    }

    #[test]
    fn leave_request_is_member_bound_reconnectable_and_transactional() {
        let mut authority = active_two_member_authority();
        assert!(authority
            .request_leave(code(1), "room-1", "owner-leave".to_string())
            .is_err());
        assert!(authority
            .request_leave(code(9), "room-1", "outsider-leave".to_string())
            .is_err());

        let request = authority
            .request_leave(code(2), "room-1", "leave-1".to_string())
            .unwrap();
        assert_eq!(
            authority
                .request_leave(code(2), "room-1", "leave-1".to_string())
                .unwrap(),
            request
        );
        assert_eq!(
            authority.pending_leaves_for_owner(&code(1)),
            vec![request.clone()]
        );
        assert_eq!(
            authority.pending_leaves_for_member(&code(2)),
            vec![request.clone()]
        );

        let transition = leave_transition(&request);
        authority
            .begin_membership(code(1), transition.clone())
            .unwrap();
        authority
            .rollback_membership(code(1), "room-1", "leave-commit", 2)
            .unwrap();
        assert_eq!(authority.pending_leaves_for_member(&code(2)).len(), 1);

        authority.begin_membership(code(1), transition).unwrap();
        authority
            .accept_membership(code(1), "room-1", "leave-commit", 2)
            .unwrap();
        assert!(!authority.is_member("room-1", &code(2)));
        assert!(authority.pending_leaves_for_owner(&code(1)).is_empty());
        assert!(authority.pending_leaves_for_member(&code(2)).is_empty());
    }

    #[test]
    fn leave_reject_expiry_and_request_binding_fail_closed() {
        let mut authority = active_two_member_authority();
        let request = authority
            .request_leave(code(2), "room-1", "leave-1".to_string())
            .unwrap();
        assert!(authority
            .remove_leave(code(2), "room-1", &request.request_id)
            .is_err());
        assert_eq!(
            authority
                .remove_leave(code(1), "room-1", &request.request_id)
                .unwrap(),
            request
        );
        assert!(authority.pending_leaves_for_member(&code(2)).is_empty());

        let request = authority
            .request_leave(code(2), "room-1", "leave-2".to_string())
            .unwrap();
        let mut wrong = leave_transition(&request);
        wrong.request_id = Some("missing-request".to_string());
        assert!(authority.begin_membership(code(1), wrong).is_err());
        assert!(authority.rooms["room-1"].pending_transition.is_none());

        authority
            .rooms
            .get_mut("room-1")
            .unwrap()
            .leaves
            .get_mut(&request.request_id)
            .unwrap()
            .expires_at_ms = 0;
        assert!(authority.pending_leaves_for_owner(&code(1)).is_empty());
        assert!(authority.pending_leaves_for_member(&code(2)).is_empty());
    }

    #[test]
    fn mixed_case_accounts_bind_to_canonical_mls_rosters_and_preserve_display_names() {
        let mut authority = RoomAuthority::new(2);
        authority
            .create(
                code(1),
                "Alice".to_string(),
                "room-1".to_string(),
                vec![7; GROUP_ID_BYTES],
                0,
                0,
                digest(8),
                stable(1),
            )
            .unwrap();
        assert!(authority
            .request_join(
                code(9),
                "aLiCe".to_string(),
                "room-1",
                "collision".to_string(),
                stable(9),
                vec![5],
                vec![9],
            )
            .is_err());
        assert!(authority
            .request_join(
                code(9),
                "Carol".to_string(),
                "room-1",
                "identity-collision".to_string(),
                stable(1),
                vec![5],
                vec![9],
            )
            .is_err());

        let request = authority
            .request_join(
                code(2),
                "Bob".to_string(),
                "room-1",
                "request-1".to_string(),
                stable(2),
                vec![5],
                vec![9],
            )
            .unwrap();
        let mut join = transition("room-1", &request, 0, 1);
        join.roster[1].username = "bob".to_string();
        authority.begin_membership(code(1), join).unwrap();
        authority
            .accept_membership(code(1), "room-1", "commit-1", 1)
            .unwrap();
        let info = authority.member_info("room-1", &code(1)).unwrap();
        assert_eq!(
            info.roster
                .iter()
                .map(|member| member.username.as_str())
                .collect::<Vec<_>>(),
            vec!["Alice", "Bob"]
        );
        let admission = authority
            .admit_application(
                code(1),
                "room-1",
                "application-1".to_string(),
                vec![7; GROUP_ID_BYTES],
                1,
                2,
                digest(8),
                vec![1],
                vec![2],
                vec![9],
            )
            .unwrap();
        assert_eq!(admission.sender_username, "Alice");
        authority
            .rollback_application("room-1", "application-1")
            .unwrap();

        let welcome = authority
            .deliveries_for_member("room-1", &code(2))
            .unwrap()
            .pop()
            .unwrap();
        authority
            .store_snapshot(
                code(2),
                "room-1",
                &welcome.message_id,
                welcome.epoch,
                welcome.revision,
                welcome.membership_digest.clone(),
                vec![7],
            )
            .unwrap();
        let leave = authority
            .request_leave(code(2), "room-1", "leave-1".to_string())
            .unwrap();
        let mut removal = leave_transition(&leave);
        removal.roster[0].username = "alice".to_string();
        authority.begin_membership(code(1), removal).unwrap();
        authority
            .accept_membership(code(1), "room-1", "leave-commit", 2)
            .unwrap();
        assert!(!authority.is_member("room-1", &code(2)));
    }

    #[test]
    fn recovery_snapshot_roster_tracks_only_acknowledged_delivery_prefix() {
        let mut authority = active_two_member_authority();
        let request = authority
            .request_join(
                code(3),
                "Carol".to_string(),
                "room-1",
                "request-2".to_string(),
                stable(3),
                vec![6],
                vec![10],
            )
            .unwrap();
        let mut join = transition("room-1", &request, 1, 2);
        join.message_id = "commit-2".to_string();
        join.roster.insert(
            1,
            RosterMember {
                username: "bob".to_string(),
                stable_identity: stable(2),
            },
        );
        authority.begin_membership(code(1), join).unwrap();
        authority
            .accept_membership(code(1), "room-1", "commit-2", 2)
            .unwrap();

        let stale = authority.member_info("room-1", &code(2)).unwrap();
        assert!(!stale.synchronized);
        assert_eq!(stale.epoch, 2);
        assert_eq!(stale.roster.len(), 3);
        let recovery = stale.recovery_snapshot.unwrap();
        assert_eq!(recovery.epoch, 1);
        assert_eq!(recovery.roster.len(), 2);

        let membership = authority
            .deliveries_for_member("room-1", &code(2))
            .unwrap()
            .pop()
            .unwrap();
        authority
            .store_snapshot(
                code(2),
                "room-1",
                &membership.message_id,
                membership.epoch,
                membership.revision,
                membership.membership_digest.clone(),
                vec![11],
            )
            .unwrap();
        let synchronized = authority.member_info("room-1", &code(2)).unwrap();
        assert!(synchronized.synchronized);
        assert_eq!(synchronized.recovery_snapshot.unwrap().roster.len(), 3);
    }

    #[test]
    fn expired_application_compacts_later_delivery_revision_for_exact_ack() {
        let mut authority = active_two_member_authority();
        for (message_id, sender_revision) in [("application-1", 2), ("application-2", 3)] {
            authority
                .admit_application(
                    code(1),
                    "room-1",
                    message_id.to_string(),
                    vec![7; GROUP_ID_BYTES],
                    1,
                    sender_revision,
                    digest(8),
                    vec![1],
                    vec![2],
                    vec![9],
                )
                .unwrap();
            authority.commit_application("room-1", message_id).unwrap();
        }
        let queue = authority
            .rooms
            .get_mut("room-1")
            .unwrap()
            .deliveries
            .get_mut(&code(2))
            .unwrap();
        queue.front_mut().unwrap().expires_at_ms = 0;
        let deliveries = authority.deliveries_for_member("room-1", &code(2)).unwrap();
        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].message_id, "application-2");
        assert_eq!(deliveries[0].revision, 1);
        assert_eq!(authority.global_expired_gap_pairs, 1);
        assert_eq!(
            authority.rooms["room-1"]
                .expired_sender_gaps
                .get(&(code(2), code(1))),
            Some(&1)
        );
        assert!(
            !authority
                .member_info("room-1", &code(2))
                .unwrap()
                .synchronized
        );
        authority
            .store_snapshot(
                code(2),
                "room-1",
                "application-2",
                1,
                1,
                digest(8),
                vec![12],
            )
            .unwrap();
        assert!(
            authority
                .member_info("room-1", &code(2))
                .unwrap()
                .synchronized
        );
        assert_eq!(authority.global_expired_gap_pairs, 0);
        assert!(authority.rooms["room-1"].expired_sender_gaps.is_empty());
    }

    #[test]
    fn sender_generation_gap_boundary_is_exact_and_rejection_is_atomic() {
        let mut authority = active_two_member_authority();
        authority
            .rooms
            .get_mut("room-1")
            .unwrap()
            .expired_sender_gaps
            .insert((code(2), code(1)), MAX_RATCHET_BACK_HISTORY);
        authority.recompute_gap_accounting().unwrap();
        authority
            .admit_application(
                code(1),
                "room-1",
                "application-boundary".to_string(),
                vec![7; GROUP_ID_BYTES],
                1,
                2,
                digest(8),
                vec![1],
                vec![2],
                vec![9],
            )
            .unwrap();
        authority
            .rollback_application("room-1", "application-boundary")
            .unwrap();

        authority
            .rooms
            .get_mut("room-1")
            .unwrap()
            .expired_sender_gaps
            .insert((code(2), code(1)), MAX_RATCHET_BACK_HISTORY + 1);
        authority.recompute_gap_accounting().unwrap();
        let before_snapshot = authority.snapshot(&code(1), "room-1").unwrap();
        let before_revision = authority.member_revision("room-1", &code(1)).unwrap();
        let before_delivery_count = authority.global_delivery_count;
        let before_pending_count = authority.global_pending_count;
        assert!(authority
            .admit_application(
                code(1),
                "room-1",
                "application-rejected".to_string(),
                vec![7; GROUP_ID_BYTES],
                1,
                2,
                digest(8),
                vec![1],
                vec![2],
                vec![9],
            )
            .is_err());
        assert_eq!(
            authority.snapshot(&code(1), "room-1").unwrap(),
            before_snapshot
        );
        assert_eq!(
            authority.member_revision("room-1", &code(1)).unwrap(),
            before_revision
        );
        assert_eq!(authority.global_delivery_count, before_delivery_count);
        assert_eq!(authority.global_pending_count, before_pending_count);
    }

    #[test]
    fn generation_gap_overflow_drops_undecryptable_tail_until_epoch_recovery() {
        let mut authority = active_two_member_authority();
        authority
            .rooms
            .get_mut("room-1")
            .unwrap()
            .expired_sender_gaps
            .insert((code(2), code(1)), MAX_RATCHET_BACK_HISTORY);
        authority.recompute_gap_accounting().unwrap();
        for (message_id, sender_revision) in [("gap-expired", 2), ("gap-tail", 3)] {
            authority
                .admit_application(
                    code(1),
                    "room-1",
                    message_id.to_string(),
                    vec![7; GROUP_ID_BYTES],
                    1,
                    sender_revision,
                    digest(8),
                    vec![1],
                    vec![2],
                    vec![9],
                )
                .unwrap();
            authority.commit_application("room-1", message_id).unwrap();
        }
        authority
            .rooms
            .get_mut("room-1")
            .unwrap()
            .deliveries
            .get_mut(&code(2))
            .unwrap()
            .front_mut()
            .unwrap()
            .expires_at_ms = 0;
        assert!(authority
            .deliveries_for_member("room-1", &code(2))
            .unwrap()
            .is_empty());
        assert!(
            !authority
                .member_info("room-1", &code(2))
                .unwrap()
                .synchronized
        );
        assert_eq!(
            authority.rooms["room-1"]
                .expired_sender_gaps
                .get(&(code(2), code(1))),
            Some(&(MAX_RATCHET_BACK_HISTORY + 1))
        );

        let request = authority
            .request_join(
                code(3),
                "Carol".to_string(),
                "room-1",
                "gap-recovery-join".to_string(),
                stable(3),
                vec![6],
                vec![10],
            )
            .unwrap();
        let mut join = transition("room-1", &request, 1, 4);
        join.message_id = "gap-recovery-commit".to_string();
        join.roster.insert(
            1,
            RosterMember {
                username: "bob".to_string(),
                stable_identity: stable(2),
            },
        );
        authority.begin_membership(code(1), join).unwrap();
        authority
            .accept_membership(code(1), "room-1", "gap-recovery-commit", 4)
            .unwrap();
        assert!(authority.rooms["room-1"].expired_sender_gaps.is_empty());
        assert_eq!(authority.global_expired_gap_pairs, 0);
    }

    #[test]
    fn pending_and_active_rooms_share_exact_per_member_limit() {
        let mut authority = RoomAuthority::new(MAX_ROOMS_PER_MEMBER + 1);
        for index in 0..=MAX_ROOMS_PER_MEMBER {
            let room_id = format!("room-{index}");
            authority
                .create(
                    code(1),
                    "Alice".to_string(),
                    room_id.clone(),
                    vec![7; GROUP_ID_BYTES],
                    0,
                    0,
                    digest(8),
                    stable(1),
                )
                .unwrap();
            let result = authority.request_join(
                code(2),
                "Bob".to_string(),
                &room_id,
                format!("request-{index}"),
                stable(2),
                vec![5],
                vec![9],
            );
            if index < MAX_ROOMS_PER_MEMBER {
                assert!(result.is_ok(), "room {index}");
            } else {
                assert_eq!(result.unwrap_err(), "member room limit reached");
            }
        }
        assert_eq!(
            authority
                .rooms
                .values()
                .filter(|room| room
                    .joins
                    .values()
                    .any(|join| join.request.code_id == code(2)))
                .count(),
            MAX_ROOMS_PER_MEMBER
        );
    }
}
