//! MLS room relay, catalog, delivery, and transaction operations.

use std::collections::HashSet;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use uuid::Uuid;

use super::rooms;
use super::{
    client_identity, client_identity_and_platform, decode_bounded, decode_bounded_allow_empty,
    decode_exact, finish_recoverable_transaction, publish_staged_attachment_checked,
    rebind_staged_attachment_recipients, remove_chat_attachments, require_recipient_code_platforms,
    revoke_mls_attachment_access, rollback_staged_attachment, send_client_result, send_to_client,
    staged_attachment_for_message, touch_activity, AppState, ClientPlatform, CodeId, InteropPolicy,
    MlsRecoverySnapshotWire, MlsRoomWire, MlsRosterWire, OutboundFrame, TransactionTicket,
};

pub(super) fn mls_room_wire(info: rooms::RoomInfo) -> MlsRoomWire {
    MlsRoomWire {
        room_id: info.room_id,
        owner_username: info.owner_username,
        group_id_b64: URL_SAFE_NO_PAD.encode(info.group_id),
        active: info.active,
        synchronized: info.synchronized,
        epoch: info.epoch,
        revision: info.revision,
        membership_digest_b64: URL_SAFE_NO_PAD.encode(info.membership_digest),
        roster: info
            .roster
            .into_iter()
            .map(|member| MlsRosterWire {
                username: member.username.clone(),
                stable_identity_b64: URL_SAFE_NO_PAD.encode(member.stable_identity.clone()),
            })
            .collect(),
        recovery_snapshot: info
            .recovery_snapshot
            .map(|snapshot| MlsRecoverySnapshotWire {
                active: snapshot.active,
                epoch: snapshot.epoch,
                revision: snapshot.revision,
                membership_digest_b64: URL_SAFE_NO_PAD.encode(snapshot.membership_digest.clone()),
                state_envelope_b64: URL_SAFE_NO_PAD.encode(snapshot.state_envelope.clone()),
                roster: snapshot
                    .roster
                    .iter()
                    .map(|member| MlsRosterWire {
                        username: member.username.clone(),
                        stable_identity_b64: URL_SAFE_NO_PAD.encode(&member.stable_identity),
                    })
                    .collect(),
            }),
        policy: info.policy,
    }
}

pub(super) fn mls_roster_from_wire(
    roster: Vec<MlsRosterWire>,
) -> Result<Vec<rooms::RosterMember>, String> {
    roster
        .into_iter()
        .map(|member| {
            Ok(rooms::RosterMember {
                username: member.username.clone(),
                stable_identity: decode_exact(
                    &member.stable_identity_b64,
                    rooms::STABLE_IDENTITY_BYTES,
                )?,
            })
        })
        .collect()
}

pub(super) async fn send_mls_catalog(state: &AppState, client_id: Uuid, code_id: &CodeId) {
    let mut authority = state.mls_rooms.lock().await;
    let mut rooms = authority
        .rooms_for_member(code_id)
        .into_iter()
        .map(mls_room_wire)
        .collect::<Vec<_>>();
    rooms.extend(
        authority
            .pending_rooms_for_member(code_id)
            .into_iter()
            .map(mls_room_wire),
    );
    drop(authority);
    send_to_client(
        state,
        client_id,
        &OutboundFrame::MlsRooms {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            rooms,
        },
    )
    .await;
}

pub(super) async fn mls_discover_room(
    state: &AppState,
    sender_id: Uuid,
    room_id: &str,
) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    let _ = client_identity(state, sender_id).await?;
    let info = state.mls_rooms.lock().await.discover(room_id)?;
    send_to_client(
        state,
        sender_id,
        &OutboundFrame::MlsRoomDiscovered {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id: info.room_id,
            group_id_b64: URL_SAFE_NO_PAD.encode(info.group_id),
            owner_username: info.owner_username,
        },
    )
    .await;
    Ok(())
}

pub(super) async fn authenticated_mls_identity(
    state: &AppState,
    code_id: &CodeId,
    encoded: &str,
) -> Result<Vec<u8>, String> {
    let supplied = decode_exact(encoded, rooms::STABLE_IDENTITY_BYTES)?;
    let accounts = state.accounts.lock().await;
    let account = accounts
        .get(code_id)
        .ok_or_else(|| "authenticated identity required".to_string())?;
    if account.identity_public.len() < rooms::STABLE_IDENTITY_BYTES
        || account.identity_public[..rooms::STABLE_IDENTITY_BYTES] != supplied
    {
        return Err("authenticated identity required".to_string());
    }
    Ok(supplied)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn mls_create_room(
    state: &AppState,
    sender_id: Uuid,
    room_id: String,
    group_id_b64: String,
    epoch: u64,
    revision: u64,
    membership_digest_b64: String,
    stable_identity_b64: String,
    state_envelope_b64: String,
    policy: rooms::RoomPolicy,
) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    let (owner_code_id, owner_username) = client_identity(state, sender_id).await?;
    let group_id = decode_exact(&group_id_b64, rooms::GROUP_ID_BYTES)?;
    let digest = decode_exact(&membership_digest_b64, rooms::MEMBERSHIP_DIGEST_BYTES)?;
    let stable = authenticated_mls_identity(state, &owner_code_id, &stable_identity_b64).await?;
    let info = state.mls_rooms.lock().await.create_with_policy_and_state(
        owner_code_id,
        owner_username,
        room_id,
        group_id,
        epoch,
        revision,
        digest,
        stable,
        policy,
        decode_bounded(&state_envelope_b64, rooms::MAX_STATE_BYTES)?,
    )?;
    send_to_client(
        state,
        sender_id,
        &OutboundFrame::MlsRoomCreated {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room: mls_room_wire(info),
        },
    )
    .await;
    Ok(())
}

pub(super) async fn mls_join_request(
    state: &AppState,
    sender_id: Uuid,
    room_id: String,
    request_id: String,
    stable_identity_b64: String,
    key_package_b64: String,
    state_envelope_b64: String,
) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    let (code_id, username) = client_identity(state, sender_id).await?;
    let stable = authenticated_mls_identity(state, &code_id, &stable_identity_b64).await?;
    let key_package = decode_bounded(&key_package_b64, rooms::MAX_KEY_PACKAGE_BYTES)?;
    let state_envelope = decode_bounded(&state_envelope_b64, rooms::MAX_STATE_BYTES)?;
    let request = state.mls_rooms.lock().await.request_join(
        code_id,
        username.clone(),
        &room_id,
        request_id,
        stable,
        key_package,
        state_envelope,
    )?;
    let owner_code_id = state.mls_rooms.lock().await.owner_code_id(&room_id)?;
    let owner_ids = state
        .clients
        .lock()
        .await
        .iter()
        .filter_map(|(client_id, client)| (client.code_id == owner_code_id).then_some(*client_id))
        .collect::<Vec<_>>();
    let frame = OutboundFrame::MlsJoinRequested {
        protocol_version: rooms::MLS_PROTOCOL_VERSION,
        room_id,
        request_id: request.request_id.clone(),
        username: request.username.clone(),
        stable_identity_b64: URL_SAFE_NO_PAD.encode(request.stable_identity.clone()),
        key_package_b64: URL_SAFE_NO_PAD.encode(request.key_package.clone()),
    };
    for owner_id in owner_ids {
        send_to_client(state, owner_id, &frame).await;
    }
    Ok(())
}

pub(super) async fn mls_join_reject(
    state: &AppState,
    sender_id: Uuid,
    room_id: &str,
    request_id: &str,
) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    let (owner_code_id, _) = client_identity(state, sender_id).await?;
    let request = state
        .mls_rooms
        .lock()
        .await
        .remove_join(owner_code_id, room_id, request_id)?;
    let frame = OutboundFrame::MlsJoinRejected {
        protocol_version: rooms::MLS_PROTOCOL_VERSION,
        room_id: room_id.to_string(),
        request_id: request.request_id.clone(),
    };
    for client_id in active_client_ids_for_code(state, &request.code_id).await {
        send_to_client(state, client_id, &frame).await;
    }
    Ok(())
}

pub(super) async fn active_client_ids_for_code(state: &AppState, code_id: &CodeId) -> Vec<Uuid> {
    state
        .clients
        .lock()
        .await
        .iter()
        .filter_map(|(client_id, client)| (client.code_id == *code_id).then_some(*client_id))
        .collect()
}

pub(super) async fn mls_leave_request(
    state: &AppState,
    sender_id: Uuid,
    room_id: String,
    request_id: String,
) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    let (code_id, _) = client_identity(state, sender_id).await?;
    let request = state
        .mls_rooms
        .lock()
        .await
        .request_leave(code_id, &room_id, request_id)?;
    let owner_code_id = state.mls_rooms.lock().await.owner_code_id(&room_id)?;
    let owner_frame = OutboundFrame::MlsLeaveRequested {
        protocol_version: rooms::MLS_PROTOCOL_VERSION,
        room_id: room_id.clone(),
        request_id: request.request_id.clone(),
        username: request.username.clone(),
        stable_identity_b64: URL_SAFE_NO_PAD.encode(request.stable_identity.clone()),
    };
    for owner_id in active_client_ids_for_code(state, &owner_code_id).await {
        send_to_client(state, owner_id, &owner_frame).await;
    }
    send_to_client(
        state,
        sender_id,
        &OutboundFrame::MlsLeavePending {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id,
            request_id: request.request_id.clone(),
        },
    )
    .await;
    Ok(())
}

pub(super) async fn mls_leave_reject(
    state: &AppState,
    sender_id: Uuid,
    room_id: &str,
    request_id: &str,
) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    let (owner_code_id, _) = client_identity(state, sender_id).await?;
    let request = state
        .mls_rooms
        .lock()
        .await
        .remove_leave(owner_code_id, room_id, request_id)?;
    let frame = OutboundFrame::MlsLeaveRejected {
        protocol_version: rooms::MLS_PROTOCOL_VERSION,
        room_id: room_id.to_string(),
        request_id: request_id.to_string(),
    };
    for client_id in active_client_ids_for_code(state, &request.code_id).await {
        send_to_client(state, client_id, &frame).await;
    }
    Ok(())
}

pub(super) fn mls_delivery_frame(delivery: &rooms::PendingDelivery) -> OutboundFrame {
    match &delivery.payload {
        rooms::DeliveryPayload::Membership {
            from_epoch,
            from_membership_digest,
            group_id,
            roster,
            control,
            welcome,
            authenticated_data,
        } => OutboundFrame::MlsMembership {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id: delivery.room_id.clone(),
            message_id: delivery.message_id.clone(),
            from_epoch: *from_epoch,
            to_epoch: delivery.epoch,
            revision: delivery.revision,
            group_id_b64: URL_SAFE_NO_PAD.encode(group_id),
            from_membership_digest_b64: URL_SAFE_NO_PAD.encode(from_membership_digest),
            membership_digest_b64: URL_SAFE_NO_PAD.encode(&delivery.membership_digest),
            roster: roster
                .iter()
                .map(|member| MlsRosterWire {
                    username: member.username.clone(),
                    stable_identity_b64: URL_SAFE_NO_PAD.encode(&member.stable_identity),
                })
                .collect(),
            control_b64: URL_SAFE_NO_PAD.encode(control),
            welcome_b64: URL_SAFE_NO_PAD.encode(welcome),
            authenticated_data_b64: URL_SAFE_NO_PAD.encode(authenticated_data),
        },
        rooms::DeliveryPayload::Application {
            sender_username,
            ciphertext,
            authenticated_data,
            ..
        } => OutboundFrame::MlsApplication {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id: delivery.room_id.clone(),
            message_id: delivery.message_id.clone(),
            sender_username: sender_username.clone(),
            epoch: delivery.epoch,
            revision: delivery.revision,
            membership_digest_b64: URL_SAFE_NO_PAD.encode(&delivery.membership_digest),
            ciphertext_b64: URL_SAFE_NO_PAD.encode(ciphertext),
            authenticated_data_b64: URL_SAFE_NO_PAD.encode(authenticated_data),
        },
    }
}

pub(super) async fn send_mls_delivery(state: &AppState, delivery: &rooms::PendingDelivery) {
    let active = state
        .mls_rooms
        .lock()
        .await
        .is_active_member(&delivery.room_id, &delivery.recipient_code_id);
    let welcome_delivery = matches!(
        &delivery.payload,
        rooms::DeliveryPayload::Membership { welcome, .. } if !welcome.is_empty()
    );
    if !active && !welcome_delivery {
        return;
    }
    let clients = state
        .clients
        .lock()
        .await
        .iter()
        .filter_map(|(client_id, client)| {
            (client.code_id == delivery.recipient_code_id
                && mls_delivery_allowed(state.interop_policy, &delivery.payload, client.platform))
            .then_some(*client_id)
        })
        .collect::<Vec<_>>();
    let frame = mls_delivery_frame(delivery);
    for client_id in clients {
        send_to_client(state, client_id, &frame).await;
    }
}

pub(super) async fn send_mls_pending(state: &AppState, client_id: Uuid, code_id: &CodeId) {
    let Some(recipient_platform) = state
        .clients
        .lock()
        .await
        .get(&client_id)
        .map(|client| client.platform)
    else {
        return;
    };
    let room_ids = state
        .mls_rooms
        .lock()
        .await
        .rooms_for_member(code_id)
        .into_iter()
        .map(|room| (room.room_id, room.active))
        .collect::<Vec<_>>();
    let mut deliveries = Vec::new();
    {
        let mut authority = state.mls_rooms.lock().await;
        for (room_id, active) in room_ids {
            if let Ok(room_deliveries) = authority.deliveries_for_member(&room_id, code_id) {
                deliveries.extend(room_deliveries.into_iter().filter(|delivery| {
                    (active
                        || matches!(
                            &delivery.payload,
                            rooms::DeliveryPayload::Membership { welcome, .. } if !welcome.is_empty()
                        ))
                        && mls_delivery_allowed(
                            state.interop_policy,
                            &delivery.payload,
                            recipient_platform,
                        )
                }));
            }
        }
    }
    for delivery in deliveries {
        send_to_client(state, client_id, &mls_delivery_frame(&delivery)).await;
    }
}

pub(super) async fn send_mls_pending_joins(state: &AppState, client_id: Uuid, code_id: &CodeId) {
    let joins = state
        .mls_rooms
        .lock()
        .await
        .pending_joins_for_owner(code_id);
    for request in joins {
        send_to_client(
            state,
            client_id,
            &OutboundFrame::MlsJoinRequested {
                protocol_version: rooms::MLS_PROTOCOL_VERSION,
                room_id: request.room_id.clone(),
                request_id: request.request_id.clone(),
                username: request.username.clone(),
                stable_identity_b64: URL_SAFE_NO_PAD.encode(request.stable_identity.clone()),
                key_package_b64: URL_SAFE_NO_PAD.encode(request.key_package.clone()),
            },
        )
        .await;
    }
}

pub(super) async fn send_mls_pending_leaves(state: &AppState, client_id: Uuid, code_id: &CodeId) {
    let (owner_requests, member_requests) = {
        let mut authority = state.mls_rooms.lock().await;
        (
            authority.pending_leaves_for_owner(code_id),
            authority.pending_leaves_for_member(code_id),
        )
    };
    for request in owner_requests {
        send_to_client(
            state,
            client_id,
            &OutboundFrame::MlsLeaveRequested {
                protocol_version: rooms::MLS_PROTOCOL_VERSION,
                room_id: request.room_id.clone(),
                request_id: request.request_id.clone(),
                username: request.username.clone(),
                stable_identity_b64: URL_SAFE_NO_PAD.encode(request.stable_identity.clone()),
            },
        )
        .await;
    }
    for request in member_requests {
        send_to_client(
            state,
            client_id,
            &OutboundFrame::MlsLeavePending {
                protocol_version: rooms::MLS_PROTOCOL_VERSION,
                room_id: request.room_id.clone(),
                request_id: request.request_id.clone(),
            },
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn mls_membership_commit(
    state: &AppState,
    sender_id: Uuid,
    room_id: String,
    message_id: String,
    request_id: Option<String>,
    from_epoch: u64,
    to_epoch: u64,
    revision: u64,
    group_id_b64: String,
    from_membership_digest_b64: String,
    membership_digest_b64: String,
    roster: Vec<MlsRosterWire>,
    control_b64: String,
    welcome_b64: String,
    authenticated_data_b64: String,
    state_envelope_b64: String,
) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    let (owner_code_id, _) = client_identity(state, sender_id).await?;
    let previous_member_code_ids = state
        .mls_rooms
        .lock()
        .await
        .member_code_ids(&room_id)?
        .into_iter()
        .collect::<HashSet<_>>();
    let transition = rooms::MembershipTransition {
        room_id: room_id.clone(),
        message_id: message_id.clone(),
        request_id,
        from_epoch,
        to_epoch,
        revision,
        group_id: decode_exact(&group_id_b64, rooms::GROUP_ID_BYTES)?,
        from_membership_digest: decode_exact(
            &from_membership_digest_b64,
            rooms::MEMBERSHIP_DIGEST_BYTES,
        )?,
        membership_digest: decode_exact(&membership_digest_b64, rooms::MEMBERSHIP_DIGEST_BYTES)?,
        roster: mls_roster_from_wire(roster)?,
        control: decode_bounded(&control_b64, rooms::MAX_CONTROL_BYTES)?,
        welcome: decode_bounded_allow_empty(&welcome_b64, rooms::MAX_CONTROL_BYTES)?,
        authenticated_data: decode_bounded(
            &authenticated_data_b64,
            rooms::MAX_AUTHENTICATED_DATA_BYTES,
        )?,
        state_envelope: decode_bounded(&state_envelope_b64, rooms::MAX_STATE_BYTES)?,
        created_at_ms: 0,
        expires_at_ms: 0,
    };
    let staged = state
        .mls_rooms
        .lock()
        .await
        .begin_membership(owner_code_id, transition)?;
    if let Err(error) = state.mls_rooms.lock().await.accept_membership(
        owner_code_id,
        &room_id,
        &message_id,
        revision,
    ) {
        let _ = state.mls_rooms.lock().await.rollback_membership(
            owner_code_id,
            &room_id,
            &message_id,
            revision,
        );
        return Err(error);
    }
    let recipient_code_ids = state
        .mls_rooms
        .lock()
        .await
        .member_code_ids(&room_id)
        .unwrap_or_default()
        .into_iter()
        .collect::<HashSet<_>>();
    let removed_code_ids = previous_member_code_ids
        .difference(&recipient_code_ids)
        .copied()
        .collect::<Vec<_>>();
    for recipient_code_id in &recipient_code_ids {
        let deliveries = state
            .mls_rooms
            .lock()
            .await
            .deliveries_for_member(&room_id, recipient_code_id)
            .unwrap_or_default();
        for delivery in deliveries
            .into_iter()
            .filter(|delivery| delivery.message_id == staged.message_id)
        {
            send_mls_delivery(state, &delivery).await;
        }
    }
    for removed_code_id in &removed_code_ids {
        revoke_mls_attachment_access(state, &room_id, removed_code_id).await;
        let frame = OutboundFrame::MlsLeft {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id: room_id.clone(),
        };
        for client_id in active_client_ids_for_code(state, removed_code_id).await {
            send_to_client(state, client_id, &frame).await;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn mls_application(
    state: &AppState,
    sender_id: Uuid,
    room_id: String,
    message_id: String,
    group_id_b64: String,
    epoch: u64,
    revision: u64,
    membership_digest_b64: String,
    ciphertext_b64: String,
    authenticated_data_b64: String,
    state_envelope_b64: String,
) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    let (sender_code_id, _, sender_platform) =
        client_identity_and_platform(state, sender_id).await?;
    let staged_attachment_id =
        staged_attachment_for_message(state, &sender_code_id, &room_id, &message_id).await?;
    let admission = state
        .mls_rooms
        .lock()
        .await
        .admit_application_for_platform(
            sender_code_id,
            sender_platform,
            &room_id,
            message_id.clone(),
            decode_exact(&group_id_b64, rooms::GROUP_ID_BYTES)?,
            epoch,
            revision,
            decode_exact(&membership_digest_b64, rooms::MEMBERSHIP_DIGEST_BYTES)?,
            decode_bounded(&ciphertext_b64, rooms::MAX_APPLICATION_CIPHERTEXT_BYTES)?,
            decode_bounded(&authenticated_data_b64, rooms::MAX_AUTHENTICATED_DATA_BYTES)?,
            decode_bounded(&state_envelope_b64, rooms::MAX_STATE_BYTES)?,
        )?;
    if let Err(error) =
        require_recipient_code_platforms(state, sender_platform, &admission.recipient_code_ids)
            .await
    {
        let _ = state
            .mls_rooms
            .lock()
            .await
            .rollback_application(&room_id, &message_id);
        return Err(error);
    }
    let mut attachment_rollback = None;
    if let Some(attachment_id) = staged_attachment_id {
        let application_recipients = admission
            .recipient_code_ids
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        let rollback = match rebind_staged_attachment_recipients(
            state,
            attachment_id,
            &application_recipients,
        )
        .await
        {
            Ok(rollback) => rollback,
            Err(error) => {
                let _ = state
                    .mls_rooms
                    .lock()
                    .await
                    .rollback_application(&room_id, &message_id);
                return Err(error);
            }
        };
        if let Err(error) = publish_staged_attachment_checked(
            state,
            attachment_id,
            &sender_code_id,
            &room_id,
            &message_id,
        )
        .await
        {
            let _ = state
                .mls_rooms
                .lock()
                .await
                .rollback_application(&room_id, &message_id);
            rollback_staged_attachment(state, rollback).await;
            return Err(error);
        }
        attachment_rollback = Some(rollback);
    }
    if let Err(error) = state
        .mls_rooms
        .lock()
        .await
        .commit_application(&room_id, &message_id)
    {
        let _ = state
            .mls_rooms
            .lock()
            .await
            .rollback_application(&room_id, &message_id);
        if let Some(rollback) = attachment_rollback {
            rollback_staged_attachment(state, rollback).await;
        }
        return Err(error);
    }
    for recipient_code_id in &admission.recipient_code_ids {
        let deliveries = state
            .mls_rooms
            .lock()
            .await
            .deliveries_for_member(&room_id, recipient_code_id)
            .unwrap_or_default();
        for delivery in deliveries
            .into_iter()
            .filter(|delivery| delivery.message_id == admission.message_id)
        {
            send_mls_delivery(state, &delivery).await;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn mls_state_snapshot(
    state: &AppState,
    sender_id: Uuid,
    room_id: String,
    message_id: String,
    epoch: u64,
    revision: u64,
    membership_digest_b64: String,
    state_envelope_b64: String,
) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    let (code_id, _) = client_identity(state, sender_id).await?;
    let (_snapshot, was_active) = {
        let mut authority = state.mls_rooms.lock().await;
        let was_active = authority.member_info(&room_id, &code_id)?.active;
        let snapshot = authority.store_snapshot(
            code_id,
            &room_id,
            &message_id,
            epoch,
            revision,
            decode_exact(&membership_digest_b64, rooms::MEMBERSHIP_DIGEST_BYTES)?,
            decode_bounded(&state_envelope_b64, rooms::MAX_STATE_BYTES)?,
        )?;
        (snapshot, was_active)
    };
    // Only Welcome acknowledgement changes the member's delivery capability.
    // Normal ACKs must not replay the already-published active queue.
    if !was_active {
        send_mls_pending(state, sender_id, &code_id).await;
    }
    send_mls_catalog(state, sender_id, &code_id).await;
    Ok(())
}

pub(super) async fn finish_mls_room_transaction(
    state: &AppState,
    sender_id: Uuid,
    room_id: String,
    message_id: String,
    revision: u64,
    ticket: TransactionTicket,
    result: Result<(), String>,
) -> Result<(), String> {
    let accepted = result.is_ok();
    finish_recoverable_transaction(state, sender_id, ticket, accepted).await?;
    send_mls_room_result(state, sender_id, &room_id, &message_id, revision, accepted).await?;
    if accepted {
        touch_activity(state).await;
    }
    Ok(())
}

pub(super) async fn finish_mls_snapshot_transaction(
    state: &AppState,
    sender_id: Uuid,
    room_id: String,
    message_id: String,
    revision: u64,
    ticket: TransactionTicket,
    result: Result<(), String>,
) -> Result<(), String> {
    let accepted = result.is_ok();
    finish_recoverable_transaction(state, sender_id, ticket, accepted).await?;
    send_mls_snapshot_result(state, sender_id, &room_id, &message_id, revision, accepted).await?;
    if accepted {
        touch_activity(state).await;
    }
    Ok(())
}

pub(super) async fn mls_delete_room(
    state: &AppState,
    sender_id: Uuid,
    room_id: &str,
) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    let (owner_code_id, _) = client_identity(state, sender_id).await?;
    let member_code_ids = state.mls_rooms.lock().await.member_code_ids(room_id)?;
    state
        .mls_rooms
        .lock()
        .await
        .delete(owner_code_id, room_id)?;
    remove_chat_attachments(state, room_id).await;
    let clients = state
        .clients
        .lock()
        .await
        .iter()
        .filter_map(|(client_id, client)| {
            member_code_ids
                .contains(&client.code_id)
                .then_some(*client_id)
        })
        .collect::<Vec<_>>();
    let frame = OutboundFrame::MlsRoomDeleted {
        protocol_version: rooms::MLS_PROTOCOL_VERSION,
        room_id: room_id.to_string(),
    };
    for client_id in clients {
        send_to_client(state, client_id, &frame).await;
    }
    Ok(())
}
pub(super) fn mls_delivery_allowed(
    policy: InteropPolicy,
    payload: &rooms::DeliveryPayload,
    recipient_platform: ClientPlatform,
) -> bool {
    match payload {
        rooms::DeliveryPayload::Application {
            sender_platform, ..
        } => policy.allows(*sender_platform, recipient_platform),
        rooms::DeliveryPayload::Membership { .. } => true,
    }
}
pub(super) async fn send_mls_room_result(
    state: &AppState,
    client_id: Uuid,
    room_id: &str,
    message_id: &str,
    revision: u64,
    accepted: bool,
) -> Result<(), String> {
    send_client_result(
        state,
        client_id,
        OutboundFrame::MlsRoomResult {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id: room_id.to_string(),
            message_id: message_id.to_string(),
            revision,
            accepted,
        },
    )
    .await
}

pub(super) async fn send_mls_snapshot_result(
    state: &AppState,
    client_id: Uuid,
    room_id: &str,
    message_id: &str,
    revision: u64,
    accepted: bool,
) -> Result<(), String> {
    send_client_result(
        state,
        client_id,
        OutboundFrame::MlsSnapshotResult {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id: room_id.to_string(),
            message_id: message_id.to_string(),
            revision,
            accepted,
        },
    )
    .await
}
