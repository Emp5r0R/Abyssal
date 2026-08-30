//! RoomAuthority workflow implementation.

use super::*;

impl RoomAuthority {
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
}
