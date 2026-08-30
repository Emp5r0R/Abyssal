//! Pending delivery construction, sizing, and ratchet-gap maintenance.

use super::*;

pub(super) fn next_delivery_revision(room: &RelayRoom, code_id: &CodeId) -> Result<u64, String> {
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

pub(super) fn compact_delivery_revisions(
    room: &mut RelayRoom,
    code_id: &CodeId,
) -> Result<(), String> {
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

pub(super) fn prune_expired_application_deliveries(
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

pub(super) fn membership_deliveries(
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

pub(super) fn delivery_bytes<'a>(
    mut deliveries: impl Iterator<Item = &'a PendingDelivery>,
) -> Result<usize, String> {
    deliveries.try_fold(0_usize, |total, delivery| {
        total
            .checked_add(delivery_size(delivery)?)
            .ok_or_else(|| "delivery accounting rejected".to_string())
    })
}

pub(super) fn delivery_size(delivery: &PendingDelivery) -> Result<usize, String> {
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
            ..
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
