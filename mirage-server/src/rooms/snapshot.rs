//! Room views and state-snapshot metadata projections.

use super::*;

pub(super) fn room_info_for(
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

pub(super) fn pending_room_info_for(room: &RelayRoom, state_envelope: &[u8]) -> RoomInfo {
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

impl RoomAuthority {
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
}
