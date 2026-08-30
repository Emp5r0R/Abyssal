//! RoomAuthority workflow implementation.

use super::*;

impl RoomAuthority {
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
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
        self.admit_application_for_platform(
            sender_code_id,
            ClientPlatform::Android,
            room_id,
            message_id,
            group_id,
            epoch,
            sender_revision,
            membership_digest,
            ciphertext,
            authenticated_data,
            state_envelope,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn admit_application_for_platform(
        &mut self,
        sender_code_id: CodeId,
        sender_platform: ClientPlatform,
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
                        sender_platform,
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
}
