//! Protocol-v9 message routing, identity state, and recoverable delivery transactions.

use std::collections::{HashMap, HashSet};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use abyssal_core::secure_protocol::{
    prekey_ids_from_identity_public_v9, verify_ack_signature_v9,
    verify_identity_state_signature_v9, verify_message_signature_v9,
};

use super::{
    canonical_outbound_message_bucket, client_identity, client_identity_and_platform,
    conversation_access, decode_bounded, decode_exact, directory_stamp, now_ms,
    pending_contains_leased_frame, prepare_outbound_message_padding, prune_pending_queues,
    prune_prekey_leases, publish_staged_attachment, require_recipient_platforms, send_to_client,
    staged_attachment_for_message, valid_chat_id, valid_identity_public_bundle, valid_node_id,
    valid_prekey_id, valid_username, Account, AppState, ClientPlatform, CodeId, ConversationAccess,
    DirectoryStamp, InboundRecipientEnvelope, OutboundFrame, PendingFrame, PendingKey, PrekeyLease,
    PrekeyLeaseKey, ReplayKey, DIRECTORY_DIGEST_BYTES, E2EE_PROTOCOL_VERSION,
    IDENTITY_ENVELOPE_VERSION, IDENTITY_FINGERPRINT_BYTES, IDENTITY_PUBLIC_BYTES,
    MAX_DIRECTORY_REVISION, MAX_IDENTITY_ENVELOPE_BYTES, MAX_PENDING_BYTES,
    MAX_PENDING_FRAMES_PER_ROOM, MAX_PREKEY_LEASES, MAX_PREKEY_LEASES_PER_RECIPIENT,
    MAX_REPLAY_IDS, MAX_REPLAY_IDS_PER_SENDER, MAX_STATE_REVISION_ADVANCE,
    MAX_TRANSIENT_FANOUT_BYTES, MAX_WRAPPED_KEY_BYTES, MESSAGE_NONCE_BYTES,
    MESSAGE_SIGNATURE_BYTES, PREKEY_LEASE_TTL_MS, REPLAY_WINDOW_MS, STATE_REVISION_WINDOW_BITS,
    WS_MAX_FRAME_BYTES,
};

pub(super) async fn lease_prekey(
    state: &AppState,
    sender_id: Uuid,
    chat_id: &str,
    message_id: &str,
    recipient_username: &str,
) -> Result<OutboundFrame, String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    if !valid_chat_id(chat_id) || !valid_chat_id(message_id) || !valid_username(recipient_username)
    {
        return Err("prekey lease rejected".to_string());
    }
    let (_, sender_username) = client_identity(state, sender_id).await?;
    if sender_username == recipient_username {
        return Err("prekey lease rejected".to_string());
    }
    let access = conversation_access(state, &sender_username, chat_id)
        .await
        .ok_or_else(|| "conversation unavailable".to_string())?;
    let authorized = match access {
        ConversationAccess::MlsRoom(_) => false,
        ConversationAccess::Direct => state
            .direct_catalog
            .lock()
            .await
            .get(chat_id)
            .and_then(|direct| direct.peer_for(&sender_username))
            .is_some_and(|peer| peer == recipient_username),
        ConversationAccess::Room(_) => state
            .accounts
            .lock()
            .await
            .values()
            .any(|account| account.username == recipient_username),
    };
    if !authorized {
        return Err("prekey lease rejected".to_string());
    }

    prune_pending_queues(state, now_ms()).await;
    let accounts = state.accounts.lock().await;
    let (recipient_code_id, recipient) = accounts
        .iter()
        .find(|(_, account)| account.username == recipient_username)
        .ok_or_else(|| "recipient unavailable".to_string())?;
    let pool = prekey_ids_from_identity_public_v9(&recipient.identity_public)
        .map_err(|_| "recipient unavailable".to_string())?;
    let recipient_public_key_b64 = URL_SAFE_NO_PAD.encode(&recipient.identity_public);
    let recipient_code_id = *recipient_code_id;
    let now = now_ms();
    let pending = state.pending.lock().await;
    let mut leases = state.prekey_leases.lock().await;
    prune_prekey_leases(&mut leases, &pending, now);

    let mut matching = leases.iter().filter(|(key, lease)| {
        key.code_id == recipient_code_id
            && lease.chat_id == chat_id
            && lease.message_id == message_id
            && lease.sender_username == sender_username
            && lease.recipient_username == recipient_username
    });
    if let Some((key, lease)) = matching.next() {
        if matching.next().is_some() {
            return Err("prekey lease rejected".to_string());
        }
        return Ok(OutboundFrame::PrekeyLease {
            chat_id: chat_id.to_string(),
            message_id: message_id.to_string(),
            recipient_username: recipient_username.to_string(),
            recipient_public_key_b64,
            prekey_id: key.prekey_id.clone(),
            expires_at_ms: lease.created_at_ms.saturating_add(PREKEY_LEASE_TTL_MS),
        });
    }
    if leases.len() >= MAX_PREKEY_LEASES
        || leases
            .keys()
            .filter(|key| key.code_id == recipient_code_id)
            .count()
            >= MAX_PREKEY_LEASES_PER_RECIPIENT
    {
        return Err("prekey lease capacity full".to_string());
    }
    let prekey_id = pool
        .into_iter()
        .find(|id| {
            !leases.contains_key(&PrekeyLeaseKey {
                code_id: recipient_code_id,
                prekey_id: id.clone(),
            })
        })
        .ok_or_else(|| "recipient prekey unavailable".to_string())?;
    leases.insert(
        PrekeyLeaseKey {
            code_id: recipient_code_id,
            prekey_id: prekey_id.clone(),
        },
        PrekeyLease {
            chat_id: chat_id.to_string(),
            message_id: message_id.to_string(),
            sender_username,
            recipient_username: recipient_username.to_string(),
            created_at_ms: now,
        },
    );
    Ok(OutboundFrame::PrekeyLease {
        chat_id: chat_id.to_string(),
        message_id: message_id.to_string(),
        recipient_username: recipient_username.to_string(),
        recipient_public_key_b64,
        prekey_id,
        expires_at_ms: now.saturating_add(PREKEY_LEASE_TTL_MS),
    })
}

pub(super) async fn release_unused_prekey_lease(
    state: &AppState,
    sender_id: Uuid,
    chat_id: &str,
    message_id: &str,
    recipient_username: &str,
    prekey_id: &str,
) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    if !valid_chat_id(chat_id)
        || !valid_chat_id(message_id)
        || !valid_username(recipient_username)
        || !valid_prekey_id(prekey_id)
        || prekey_id.is_empty()
    {
        return Err("prekey lease release rejected".to_string());
    }
    let (_, sender_username) = client_identity(state, sender_id).await?;
    let recipient_code_id = state
        .accounts
        .lock()
        .await
        .iter()
        .find_map(|(code_id, account)| (account.username == recipient_username).then_some(*code_id))
        .ok_or_else(|| "prekey lease release rejected".to_string())?;
    let key = PrekeyLeaseKey {
        code_id: recipient_code_id,
        prekey_id: prekey_id.to_string(),
    };
    let pending = state.pending.lock().await;
    let mut leases = state.prekey_leases.lock().await;
    let lease = leases
        .get(&key)
        .ok_or_else(|| "prekey lease release rejected".to_string())?;
    if lease.chat_id != chat_id
        || lease.message_id != message_id
        || lease.sender_username != sender_username
        || lease.recipient_username != recipient_username
        || pending_contains_leased_frame(&pending, &key, lease)
    {
        return Err("prekey lease release rejected".to_string());
    }
    leases.remove(&key);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) async fn route_encrypted_message(
    state: &AppState,
    sender_id: Uuid,
    chat_id: String,
    version: u32,
    message_id: String,
    nonce_b64: String,
    ciphertext_b64: String,
    envelopes: Vec<InboundRecipientEnvelope>,
    state_revision: u64,
    identity_envelope_b64: String,
    identity_public_b64: String,
    prekey_id: String,
    state_signature_b64: String,
) -> Result<(), String> {
    let current_directory = current_directory_evidence(state).await;
    route_encrypted_message_with_directory(
        state,
        sender_id,
        chat_id,
        version,
        message_id,
        nonce_b64,
        ciphertext_b64,
        envelopes,
        state_revision,
        identity_envelope_b64,
        identity_public_b64,
        prekey_id,
        state_signature_b64,
        Some(current_directory),
    )
    .await
}

pub(super) fn directory_evidence(
    node_id: String,
    revision: u64,
    digest: String,
) -> Option<DirectoryStamp> {
    if node_id.is_empty() && revision == 0 && digest.is_empty() {
        None
    } else {
        Some(DirectoryStamp {
            node_id,
            revision,
            digest,
        })
    }
}

pub(super) async fn validate_directory_evidence(
    state: &AppState,
    evidence: Option<DirectoryStamp>,
) -> Result<DirectoryStamp, String> {
    let Some(candidate) = evidence else {
        return Err("directory evidence required".to_string());
    };
    if !valid_node_id(&candidate.node_id)
        || !(1..=MAX_DIRECTORY_REVISION).contains(&candidate.revision)
    {
        return Err("directory evidence rejected".to_string());
    }
    let _decoded_digest = Zeroizing::new(
        decode_exact(&candidate.digest, DIRECTORY_DIGEST_BYTES)
            .map_err(|_| "directory evidence rejected".to_string())?,
    );
    let accounts = state.accounts.lock().await;
    let current = directory_stamp(&state.node_id, &accounts);
    if candidate.node_id == current.node_id
        && candidate.revision == current.revision
        && candidate.digest == current.digest
    {
        Ok(current)
    } else {
        Err("directory evidence rejected".to_string())
    }
}

#[cfg(test)]
pub(super) async fn current_directory_evidence(state: &AppState) -> DirectoryStamp {
    let accounts = state.accounts.lock().await;
    directory_stamp(&state.node_id, &accounts)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn route_encrypted_message_with_directory(
    state: &AppState,
    sender_id: Uuid,
    chat_id: String,
    version: u32,
    message_id: String,
    nonce_b64: String,
    ciphertext_b64: String,
    envelopes: Vec<InboundRecipientEnvelope>,
    state_revision: u64,
    identity_envelope_b64: String,
    identity_public_b64: String,
    prekey_id: String,
    state_signature_b64: String,
    directory_evidence: Option<DirectoryStamp>,
) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    let directory_stamp = validate_directory_evidence(state, directory_evidence).await?;
    if version != E2EE_PROTOCOL_VERSION || !valid_chat_id(&chat_id) || !valid_chat_id(&message_id) {
        return Err("encrypted message rejected".to_string());
    }
    let nonce = Zeroizing::new(decode_exact(&nonce_b64, MESSAGE_NONCE_BYTES)?);
    let ciphertext = Zeroizing::new(decode_bounded(&ciphertext_b64, WS_MAX_FRAME_BYTES)?);

    decode_bounded(&identity_envelope_b64, MAX_IDENTITY_ENVELOPE_BYTES)?;

    let (sender_code_id, sender_username, sender_platform) =
        client_identity_and_platform(state, sender_id).await?;
    let sender_identity_public =
        Zeroizing::new(decode_exact(&identity_public_b64, IDENTITY_PUBLIC_BYTES)?);
    // Validate the complete bundle before any recipient fanout.  The relay
    // must not distribute a sender identity containing a low-order or
    // otherwise non-contributory X25519 key, even when its fingerprint looks
    // consistent with the authenticated account.
    if !valid_identity_public_bundle(&sender_identity_public, &prekey_id) {
        return Err("authenticated identity required".to_string());
    }
    let authenticated_identity_public = Zeroizing::new(
        state
            .accounts
            .lock()
            .await
            .get(&sender_code_id)
            .map(|account| account.identity_public.clone())
            .ok_or_else(|| "authenticated identity required".to_string())?,
    );
    if authenticated_identity_public.len() != IDENTITY_PUBLIC_BYTES
        || authenticated_identity_public[..IDENTITY_FINGERPRINT_BYTES]
            != sender_identity_public[..IDENTITY_FINGERPRINT_BYTES]
    {
        return Err("authenticated identity required".to_string());
    }
    let access = conversation_access(state, &sender_username, &chat_id)
        .await
        .ok_or_else(|| "conversation unavailable".to_string())?;
    // Upload and message admission share conversation_ops. This prevents a
    // second live record from racing the exact owner/chat/message binding.
    let staged_attachment_id =
        staged_attachment_for_message(state, &sender_code_id, &chat_id, &message_id).await?;
    let expected_recipients = match access {
        ConversationAccess::MlsRoom(_) => {
            return Err("MLS application required".to_string());
        }
        ConversationAccess::Room(_) => state
            .accounts
            .lock()
            .await
            .values()
            .map(|account| account.username.clone())
            .filter(|username| username != &sender_username)
            .collect::<HashSet<_>>(),
        ConversationAccess::Direct => {
            let peer = state
                .direct_catalog
                .lock()
                .await
                .get(&chat_id)
                .and_then(|direct| direct.peer_for(&sender_username))
                .ok_or_else(|| "direct conversation unavailable".to_string())?;
            HashSet::from([peer])
        }
    };
    require_recipient_platforms(state, sender_platform, &expected_recipients).await?;

    if envelopes.len() != expected_recipients.len() {
        return Err("recipient envelope set rejected".to_string());
    }
    let mut envelope_map = HashMap::with_capacity(envelopes.len());
    for envelope in envelopes {
        if !expected_recipients.contains(&envelope.recipient_username)
            || envelope_map.contains_key(&envelope.recipient_username)
        {
            return Err("recipient envelope rejected".to_string());
        }
        if !valid_prekey_id(&envelope.prekey_id) {
            return Err("recipient envelope rejected".to_string());
        }
        if envelope.is_prekey == envelope.prekey_id.is_empty() {
            return Err("recipient envelope rejected".to_string());
        }
        let wrapped = Zeroizing::new(decode_bounded(
            &envelope.wrapped_key_b64,
            MAX_WRAPPED_KEY_BYTES,
        )?);
        if wrapped.is_empty() {
            return Err("recipient envelope rejected".to_string());
        }
        let signature = Zeroizing::new(decode_exact(
            &envelope.signature_b64,
            MESSAGE_SIGNATURE_BYTES,
        )?);
        verify_message_signature_v9(
            version,
            &chat_id,
            &message_id,
            &sender_username,
            &sender_identity_public,
            &nonce,
            &ciphertext,
            &envelope.recipient_username,
            &wrapped,
            &envelope.prekey_id,
            envelope.is_prekey,
            &signature,
        )?;
        let recipient_username = envelope.recipient_username.clone();
        envelope_map.insert(recipient_username, envelope);
    }
    if envelope_map.keys().collect::<HashSet<_>>()
        != expected_recipients.iter().collect::<HashSet<_>>()
    {
        return Err("recipient envelope set rejected".to_string());
    }

    let sender_public_key_b64 = state
        .accounts
        .lock()
        .await
        .get(&sender_code_id)
        .map(|account| URL_SAFE_NO_PAD.encode(&account.identity_public))
        .ok_or_else(|| "authenticated identity required".to_string())?;
    let mut prepared_frames = Vec::with_capacity(expected_recipients.len());
    let mut transient_fanout_bytes = 0usize;
    for recipient_username in &expected_recipients {
        let envelope = envelope_map
            .get(recipient_username)
            .ok_or_else(|| "recipient envelope rejected".to_string())?;
        let mut frame = OutboundFrame::Message {
            chat_id: chat_id.clone(),
            version,
            message_id: message_id.clone(),
            nonce_b64: nonce_b64.clone(),
            ciphertext_b64: ciphertext_b64.clone(),
            signature_b64: envelope.signature_b64.clone(),
            wrapped_key_b64: envelope.wrapped_key_b64.clone(),
            prekey_id: envelope.prekey_id.clone(),
            is_prekey: envelope.is_prekey,
            sender_username: sender_username.clone(),
            sender_public_key_b64: sender_public_key_b64.clone(),
            identity_public_b64: sender_public_key_b64.clone(),
            directory_node_id: directory_stamp.node_id.clone(),
            directory_revision: directory_stamp.revision,
            directory_digest: directory_stamp.digest.clone(),
            padding_bucket: 0,
            padding: String::new(),
        };
        prepare_outbound_message_padding(&mut frame)?;
        let frame_bytes = validated_outbound_frame_bytes(&frame)
            .ok_or_else(|| "fanout preparation budget full".to_string())?;
        transient_fanout_bytes = transient_fanout_bytes
            .checked_add(
                frame_bytes
                    .checked_add(recipient_username.len())
                    .ok_or_else(|| "fanout preparation budget full".to_string())?,
            )
            .ok_or_else(|| "fanout preparation budget full".to_string())?;
        if transient_fanout_bytes > MAX_TRANSIENT_FANOUT_BYTES {
            return Err("fanout preparation budget full".to_string());
        }
        prepared_frames.push((recipient_username.clone(), frame));
    }
    admit_prekey_leases(
        state,
        &expected_recipients,
        &envelope_map,
        &chat_id,
        &message_id,
        &sender_username,
    )
    .await?;
    let mut pending_plan = preflight_pending_frames(state, &prepared_frames).await?;
    commit_pending_frames(state, &prepared_frames, &mut pending_plan, sender_platform).await?;
    if let Err(error) = register_message_id(state, &chat_id, &sender_username, &message_id).await {
        rollback_pending_frames(state, &prepared_frames, &mut pending_plan).await;
        return Err(error);
    }
    if let Err(error) = apply_identity_state(
        state,
        &sender_code_id,
        state_revision,
        &identity_envelope_b64,
        &identity_public_b64,
        &prekey_id,
        &state_signature_b64,
        false,
    )
    .await
    {
        unregister_message_id(state, &chat_id, &sender_username, &message_id).await;
        rollback_pending_frames(state, &prepared_frames, &mut pending_plan).await;
        return Err(error);
    }

    // Publication is deliberately after complete encrypted-message
    // admission, but before fanout. A lost message_result therefore leaves a
    // successfully admitted attachment downloadable, while rejected or
    // rolled-back admissions never publish the staged record.
    if let Some(attachment_id) = staged_attachment_id {
        publish_staged_attachment(state, attachment_id, &sender_code_id, &chat_id, &message_id)
            .await;
    }

    let joined = state
        .rooms
        .lock()
        .await
        .get(&chat_id)
        .cloned()
        .unwrap_or_default();
    let clients = state.clients.lock().await.clone();
    for (recipient_username, frame) in prepared_frames {
        let recipient_ids = clients
            .iter()
            .filter_map(|(client_id, client)| {
                (client.username == recipient_username
                    && joined.contains(client_id)
                    && state
                        .interop_policy
                        .allows(sender_platform, client.platform))
                .then_some(*client_id)
            })
            .collect::<Vec<_>>();
        if !recipient_ids.is_empty() {
            for recipient_id in recipient_ids {
                send_to_client(state, recipient_id, &frame).await;
            }
        }
    }
    Ok(())
}

pub(super) async fn register_message_id(
    state: &AppState,
    chat_id: &str,
    sender_username: &str,
    message_id: &str,
) -> Result<(), String> {
    let now = now_ms();
    let mut replay_ids = state.replay_ids.lock().await;
    replay_ids.retain(|_, seen_at| now.saturating_sub(*seen_at) < REPLAY_WINDOW_MS);
    let key = ReplayKey {
        chat_id: chat_id.to_string(),
        sender_username: sender_username.to_string(),
        message_id: message_id.to_string(),
    };
    if replay_ids.contains_key(&key) {
        return Err("message replay rejected".to_string());
    }
    if replay_ids
        .keys()
        .filter(|candidate| candidate.sender_username == sender_username)
        .count()
        >= MAX_REPLAY_IDS_PER_SENDER
    {
        return Err("sender replay window full".to_string());
    }
    if replay_ids.len() >= MAX_REPLAY_IDS {
        // Never evict a live replay-window entry to admit new traffic. An
        // attacker could otherwise fill the map and replay an older message.
        return Err("replay window full".to_string());
    }
    replay_ids.insert(key, now);
    Ok(())
}

pub(super) async fn unregister_message_id(
    state: &AppState,
    chat_id: &str,
    sender_username: &str,
    message_id: &str,
) {
    state.replay_ids.lock().await.remove(&ReplayKey {
        chat_id: chat_id.to_string(),
        sender_username: sender_username.to_string(),
        message_id: message_id.to_string(),
    });
}

pub(super) async fn admit_prekey_leases(
    state: &AppState,
    expected_recipients: &HashSet<String>,
    envelopes: &HashMap<String, InboundRecipientEnvelope>,
    chat_id: &str,
    message_id: &str,
    sender_username: &str,
) -> Result<(), String> {
    // The caller holds conversation_ops. Admission only verifies leases that
    // were created before encryption; it never chooses or reserves a key.
    prune_pending_queues(state, now_ms()).await;
    let accounts = state.accounts.lock().await;
    let pending = state.pending.lock().await;
    let mut leases = state.prekey_leases.lock().await;
    let now = now_ms();
    prune_prekey_leases(&mut leases, &pending, now);
    for username in expected_recipients {
        let Some(envelope) = envelopes.get(username) else {
            return Err("recipient envelope rejected".to_string());
        };
        if !envelope.is_prekey {
            continue;
        }
        let Some((code_id, account)) = accounts
            .iter()
            .find(|(_, account)| account.username == *username)
        else {
            return Err("recipient envelope rejected".to_string());
        };
        let pool = prekey_ids_from_identity_public_v9(&account.identity_public)
            .map_err(|_| "recipient prekey unavailable".to_string())?;
        if !pool.iter().any(|id| id == &envelope.prekey_id) {
            return Err("recipient prekey unavailable".to_string());
        }
        let key = PrekeyLeaseKey {
            code_id: *code_id,
            prekey_id: envelope.prekey_id.clone(),
        };
        let lease = leases
            .get(&key)
            .ok_or_else(|| "recipient prekey lease required".to_string())?;
        if lease.chat_id != chat_id
            || lease.message_id != message_id
            || lease.sender_username != sender_username
            || lease.recipient_username != *username
        {
            return Err("recipient prekey lease rejected".to_string());
        }
    }
    Ok(())
}

#[allow(dead_code)]
pub(super) async fn release_prekey_lease(
    state: &AppState,
    chat_id: &str,
    message_id: &str,
    sender_username: &str,
    prekey_id: Option<&str>,
) {
    state.prekey_leases.lock().await.retain(|key, claim| {
        !(claim.chat_id == chat_id
            && claim.message_id == message_id
            && claim.sender_username == sender_username
            && prekey_id.is_none_or(|expected| key.prekey_id == expected))
    });
}

pub(super) fn is_prekey_frame(frame: &OutboundFrame) -> bool {
    matches!(
        frame,
        OutboundFrame::Message {
            is_prekey: true,
            prekey_id,
            ..
        } if !prekey_id.is_empty()
    )
}

pub(super) fn prekey_lease_details(
    frame: &OutboundFrame,
) -> Option<(String, String, String, String)> {
    match frame {
        OutboundFrame::Message {
            chat_id,
            message_id,
            prekey_id,
            is_prekey: true,
            sender_username,
            ..
        } if !prekey_id.is_empty() => Some((
            chat_id.clone(),
            message_id.clone(),
            sender_username.clone(),
            prekey_id.clone(),
        )),
        _ => None,
    }
}

pub(super) fn outbound_frame_bytes(frame: &OutboundFrame) -> usize {
    let OutboundFrame::Message {
        padding_bucket,
        padding,
        ..
    } = frame
    else {
        return 0;
    };
    let Some((canonical_bucket, empty_len)) = canonical_outbound_message_bucket(frame) else {
        return WS_MAX_FRAME_BYTES.saturating_add(1);
    };
    let Some(expected_padding_len) = canonical_bucket.checked_sub(empty_len) else {
        return WS_MAX_FRAME_BYTES.saturating_add(1);
    };
    if *padding_bucket != canonical_bucket || expected_padding_len != padding.len() {
        WS_MAX_FRAME_BYTES.saturating_add(1)
    } else {
        // Relay-created frames already received CSPRNG URL-safe filler. Avoid
        // rescanning up to 1 MiB every time a pending queue is simulated or
        // accounted. The single serialization boundary still revalidates the
        // filler alphabet before bytes reach the socket.
        canonical_bucket
    }
}

pub(super) fn validated_outbound_frame_bytes(frame: &OutboundFrame) -> Option<usize> {
    let bytes = outbound_frame_bytes(frame);
    if matches!(frame, OutboundFrame::Message { .. }) && bytes > WS_MAX_FRAME_BYTES {
        None
    } else {
        Some(bytes)
    }
}

pub(super) struct PendingQueuePlan {
    key: PendingKey,
    eviction_index: Option<usize>,
    evicted: Option<PendingFrame>,
}

impl Drop for PendingQueuePlan {
    fn drop(&mut self) {
        if let Some(evicted) = self.evicted.as_mut() {
            evicted.zeroize_sensitive();
        }
    }
}

pub(super) async fn preflight_pending_frames(
    state: &AppState,
    frames: &[(String, OutboundFrame)],
) -> Result<Vec<PendingQueuePlan>, String> {
    // The caller holds conversation_ops. Prune before taking the snapshot so
    // expired frames and their prekey leases cannot consume admission budget.
    let transient_fanout_bytes = frames
        .iter()
        .try_fold(0usize, |total, (recipient, frame)| {
            let frame_and_recipient = validated_outbound_frame_bytes(frame)
                .ok_or_else(|| "fanout preparation budget full".to_string())?
                .checked_add(recipient.len())
                .ok_or_else(|| "fanout preparation budget full".to_string())?;
            total
                .checked_add(frame_and_recipient)
                .filter(|bytes| *bytes <= MAX_TRANSIENT_FANOUT_BYTES)
                .ok_or_else(|| "fanout preparation budget full".to_string())
        })?;
    let _ = transient_fanout_bytes;
    prune_pending_queues(state, now_ms()).await;
    let pending = state.pending.lock().await;
    let pending_bytes = state.pending_bytes.lock().await;
    let mut projected_bytes = *pending_bytes;
    let mut simulated = HashMap::<PendingKey, Vec<(usize, bool)>>::new();
    for (key, queue) in pending.iter() {
        simulated.insert(
            key.clone(),
            queue
                .iter()
                .map(|pending_frame| {
                    let bytes = validated_outbound_frame_bytes(&pending_frame.frame)?;
                    Some((bytes, is_prekey_frame(&pending_frame.frame)))
                })
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| "pending frame rejected".to_string())?,
        );
    }
    let mut plan = Vec::with_capacity(frames.len());
    for (recipient_username, frame) in frames {
        let key = PendingKey {
            chat_id: match frame {
                OutboundFrame::Message { chat_id, .. } => chat_id.clone(),
                _ => return Err("pending frame rejected".to_string()),
            },
            recipient_username: recipient_username.clone(),
        };
        let queue = simulated.entry(key.clone()).or_default();
        let eviction_index = if queue.len() >= MAX_PENDING_FRAMES_PER_ROOM {
            let Some(index) = queue.iter().position(|(_, is_prekey)| !*is_prekey) else {
                return Err("recipient pending queue full".to_string());
            };
            let (evicted_bytes, _) = queue.remove(index);
            projected_bytes = projected_bytes.saturating_sub(evicted_bytes);
            Some(index)
        } else {
            None
        };
        let incoming_bytes = validated_outbound_frame_bytes(frame)
            .ok_or_else(|| "pending frame rejected".to_string())?;
        let Some(projected_next) = projected_bytes.checked_add(incoming_bytes) else {
            return Err("pending message budget full".to_string());
        };
        if projected_next > MAX_PENDING_BYTES {
            return Err("pending message budget full".to_string());
        }
        projected_bytes = projected_next;
        queue.push((incoming_bytes, is_prekey_frame(frame)));
        plan.push(PendingQueuePlan {
            key,
            eviction_index,
            evicted: None,
        });
    }
    drop(pending_bytes);
    drop(pending);
    Ok(plan)
}

pub(super) async fn commit_pending_frames(
    state: &AppState,
    frames: &[(String, OutboundFrame)],
    plan: &mut [PendingQueuePlan],
    sender_platform: ClientPlatform,
) -> Result<(), String> {
    if frames.len() != plan.len() {
        return Err("pending frame plan mismatch".to_string());
    }
    let mut pending = state.pending.lock().await;
    let mut pending_bytes = state.pending_bytes.lock().await;
    let now = now_ms();

    // Validate the complete plan against the live queues before mutating
    // anything. conversation_ops normally makes this snapshot stable, but
    // keeping the validation transactional also protects maintenance/tests
    // that call this helper directly.
    let mut projected_bytes = *pending_bytes;
    let mut simulated = HashMap::<PendingKey, Vec<(usize, bool)>>::new();
    for (key, queue) in pending.iter() {
        simulated.insert(
            key.clone(),
            queue
                .iter()
                .map(|pending_frame| {
                    let bytes = validated_outbound_frame_bytes(&pending_frame.frame)?;
                    Some((bytes, is_prekey_frame(&pending_frame.frame)))
                })
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| "pending queue changed during commit".to_string())?,
        );
    }
    for ((_, frame), queue_plan) in frames.iter().zip(plan.iter()) {
        let queue = simulated.entry(queue_plan.key.clone()).or_default();
        let expected_eviction = if queue.len() >= MAX_PENDING_FRAMES_PER_ROOM {
            let Some(index) = queue.iter().position(|(_, is_prekey)| !*is_prekey) else {
                return Err("pending queue changed during commit".to_string());
            };
            let (evicted_bytes, _) = queue.remove(index);
            projected_bytes = projected_bytes.saturating_sub(evicted_bytes);
            Some(index)
        } else {
            None
        };
        if expected_eviction != queue_plan.eviction_index {
            return Err("pending queue changed during commit".to_string());
        }
        if queue_plan.evicted.is_some() {
            return Err("pending frame plan already committed".to_string());
        }
        let incoming_bytes = validated_outbound_frame_bytes(frame)
            .ok_or_else(|| "pending frame rejected".to_string())?;
        let Some(projected_next) = projected_bytes.checked_add(incoming_bytes) else {
            return Err("pending message budget changed during commit".to_string());
        };
        if projected_next > MAX_PENDING_BYTES {
            return Err("pending message budget changed during commit".to_string());
        }
        projected_bytes = projected_next;
        queue.push((incoming_bytes, is_prekey_frame(frame)));
    }

    for ((_, frame), queue_plan) in frames.iter().zip(plan.iter_mut()) {
        let queue = pending.entry(queue_plan.key.clone()).or_default();
        if queue.len() >= MAX_PENDING_FRAMES_PER_ROOM {
            let Some(eviction_index) = queue_plan.eviction_index else {
                return Err("pending queue changed during commit".to_string());
            };
            if eviction_index >= queue.len() || is_prekey_frame(&queue[eviction_index].frame) {
                return Err("pending queue changed during commit".to_string());
            }
            let evicted = queue.remove(eviction_index);
            *pending_bytes = pending_bytes.saturating_sub(outbound_frame_bytes(&evicted.frame));
            queue_plan.evicted = Some(evicted);
        } else if queue_plan.eviction_index.is_some() {
            return Err("pending queue changed during commit".to_string());
        }
        let incoming_bytes = validated_outbound_frame_bytes(frame)
            .ok_or_else(|| "pending frame rejected".to_string())?;
        let Some(next_pending_bytes) = pending_bytes.checked_add(incoming_bytes) else {
            return Err("pending message budget changed during commit".to_string());
        };
        queue.push(PendingFrame::new_for_platform(
            frame.clone(),
            now,
            sender_platform,
        ));
        *pending_bytes = next_pending_bytes;
    }
    Ok(())
}

pub(super) async fn rollback_pending_frames(
    state: &AppState,
    frames: &[(String, OutboundFrame)],
    plan: &mut [PendingQueuePlan],
) {
    let mut pending = state.pending.lock().await;
    let mut pending_bytes = state.pending_bytes.lock().await;
    for ((_, frame), queue_plan) in frames.iter().zip(plan.iter_mut()) {
        let Some(queue) = pending.get_mut(&queue_plan.key) else {
            continue;
        };
        let Some((message_id, sender_username)) = (match frame {
            OutboundFrame::Message {
                message_id,
                sender_username,
                ..
            } => Some((message_id, sender_username)),
            _ => None,
        }) else {
            continue;
        };
        if let Some(index) = queue.iter().rposition(|pending_frame| {
            matches!(
                &pending_frame.frame,
                OutboundFrame::Message {
                    message_id: pending_id,
                    sender_username: pending_sender,
                    ..
                } if pending_id == message_id && pending_sender == sender_username
            )
        }) {
            let mut removed = queue.remove(index);
            *pending_bytes = pending_bytes.saturating_sub(outbound_frame_bytes(&removed.frame));
            removed.zeroize_sensitive();
        }
        if let Some(evicted) = queue_plan.evicted.take() {
            let insertion_index = queue_plan
                .eviction_index
                .unwrap_or(queue.len())
                .min(queue.len());
            *pending_bytes = pending_bytes.saturating_add(outbound_frame_bytes(&evicted.frame));
            queue.insert(insertion_index, evicted);
        }
    }
    pending.retain(|_, queue| !queue.is_empty());
}

#[cfg(test)]
pub(super) async fn queue_pending_frame(
    state: &AppState,
    _chat_id: &str,
    recipient_username: String,
    frame: OutboundFrame,
) -> Result<(), String> {
    let frames = vec![(recipient_username, frame)];
    let mut plan = preflight_pending_frames(state, &frames).await?;
    commit_pending_frames(state, &frames, &mut plan, ClientPlatform::Android).await
}

pub(super) async fn update_identity_state(
    state: &AppState,
    sender_id: Uuid,
    revision: u64,
    envelope_b64: &str,
    identity_public_b64: &str,
    prekey_id: &str,
    state_signature_b64: &str,
) -> Result<(), String> {
    let (code_id, _) = client_identity(state, sender_id).await?;
    apply_identity_state(
        state,
        &code_id,
        revision,
        envelope_b64,
        identity_public_b64,
        prekey_id,
        state_signature_b64,
        true,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn apply_identity_state(
    state: &AppState,
    code_id: &CodeId,
    revision: u64,
    envelope_b64: &str,
    identity_public_b64: &str,
    prekey_id: &str,
    state_signature_b64: &str,
    allow_reuse: bool,
) -> Result<(), String> {
    let mut accounts = state.accounts.lock().await;
    apply_identity_state_locked(
        &mut accounts,
        code_id,
        revision,
        envelope_b64,
        identity_public_b64,
        prekey_id,
        state_signature_b64,
        allow_reuse,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn apply_identity_state_locked(
    accounts: &mut HashMap<CodeId, Account>,
    code_id: &CodeId,
    revision: u64,
    envelope_b64: &str,
    identity_public_b64: &str,
    prekey_id: &str,
    state_signature_b64: &str,
    allow_reuse: bool,
) -> Result<(), String> {
    apply_identity_state_locked_with_consumed(
        accounts,
        code_id,
        revision,
        envelope_b64,
        identity_public_b64,
        prekey_id,
        state_signature_b64,
        allow_reuse,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn apply_identity_state_locked_with_consumed(
    accounts: &mut HashMap<CodeId, Account>,
    code_id: &CodeId,
    revision: u64,
    envelope_b64: &str,
    identity_public_b64: &str,
    prekey_id: &str,
    state_signature_b64: &str,
    allow_reuse: bool,
    consumed_prekey_id: Option<&str>,
) -> Result<(), String> {
    let mut envelope = decode_bounded(envelope_b64, MAX_IDENTITY_ENVELOPE_BYTES)?;
    let mut identity_public = decode_exact(identity_public_b64, IDENTITY_PUBLIC_BYTES)?;
    let state_signature =
        Zeroizing::new(decode_exact(state_signature_b64, MESSAGE_SIGNATURE_BYTES)?);
    if envelope.len() <= 1 + MESSAGE_NONCE_BYTES
        || envelope.first() != Some(&IDENTITY_ENVELOPE_VERSION)
        || !valid_identity_public_bundle(&identity_public, prekey_id)
    {
        envelope.zeroize();
        identity_public.zeroize();
        return Err("identity state rejected".to_string());
    }
    let account = accounts.get_mut(code_id).ok_or_else(|| {
        envelope.zeroize();
        identity_public.zeroize();
        "authenticated identity required".to_string()
    })?;
    if account.identity_public.len() != IDENTITY_PUBLIC_BYTES
        || account.identity_public[..IDENTITY_FINGERPRINT_BYTES]
            != identity_public[..IDENTITY_FINGERPRINT_BYTES]
    {
        envelope.zeroize();
        identity_public.zeroize();
        return Err("identity state rejected".to_string());
    }
    validate_prekey_pool_transition(
        &account.identity_public,
        &identity_public,
        consumed_prekey_id,
    )?;
    if verify_identity_state_signature_v9(
        E2EE_PROTOCOL_VERSION,
        revision,
        &envelope,
        &identity_public,
        prekey_id,
        &state_signature,
    )
    .is_err()
    {
        envelope.zeroize();
        identity_public.zeroize();
        return Err("identity state rejected".to_string());
    }
    if revision > account.state_revision {
        let Some(advance) = revision.checked_sub(account.state_revision) else {
            envelope.zeroize();
            identity_public.zeroize();
            return Err("identity state rejected".to_string());
        };
        if advance > MAX_STATE_REVISION_ADVANCE {
            envelope.zeroize();
            identity_public.zeroize();
            return Err("identity state rejected".to_string());
        }
        account.state_revision_window = if advance >= u64::from(STATE_REVISION_WINDOW_BITS) {
            1
        } else {
            (account.state_revision_window << advance) | 1
        };
        let mut previous = std::mem::replace(&mut account.identity_envelope, envelope);
        previous.zeroize();
        let mut previous_public = std::mem::replace(&mut account.identity_public, identity_public);
        previous_public.zeroize();
        account.prekey_id = prekey_id.to_string();
        account.state_revision = revision;
        return Ok(());
    }

    // A reusable stale snapshot must still describe the exact current public
    // bundle and prekey. The fingerprint check above only binds the long-term
    // signing key; without this full comparison, a lagged ACK could carry a
    // signed but stale prekey bundle and be accepted without validation.
    if account.identity_public != identity_public || account.prekey_id != prekey_id {
        envelope.zeroize();
        identity_public.zeroize();
        return Err("identity state rejected".to_string());
    }

    let lag = account.state_revision - revision;
    if lag >= u64::from(STATE_REVISION_WINDOW_BITS) {
        envelope.zeroize();
        identity_public.zeroize();
        return if allow_reuse {
            Ok(())
        } else {
            Err("identity state rejected".to_string())
        };
    }
    let revision_bit = 1_u128 << lag;
    if account.state_revision_window & revision_bit != 0 && !allow_reuse {
        envelope.zeroize();
        identity_public.zeroize();
        return Err("identity state rejected".to_string());
    }
    account.state_revision_window |= revision_bit;
    envelope.zeroize();
    identity_public.zeroize();
    Ok(())
}

pub(super) fn validate_prekey_pool_transition(
    previous_public: &[u8],
    next_public: &[u8],
    consumed_prekey_id: Option<&str>,
) -> Result<(), String> {
    let previous = prekey_ids_from_identity_public_v9(previous_public)
        .map_err(|_| "identity state rejected".to_string())?;
    let next = prekey_ids_from_identity_public_v9(next_public)
        .map_err(|_| "identity state rejected".to_string())?;
    match consumed_prekey_id {
        None if previous == next => Ok(()),
        None => Err("identity prekey pool changed without consumption".to_string()),
        Some(consumed) => {
            let removed = previous
                .iter()
                .filter(|id| !next.contains(id))
                .collect::<Vec<_>>();
            let added = next
                .iter()
                .filter(|id| !previous.contains(id))
                .collect::<Vec<_>>();
            if removed.len() == 1
                && removed[0].as_str() == consumed
                && added.len() == 1
                && !next.iter().any(|id| id == consumed)
            {
                Ok(())
            } else {
                Err("identity prekey pool transition rejected".to_string())
            }
        }
    }
}

pub(super) fn pending_frame_matches_ack(
    frame: &OutboundFrame,
    chat_id: &str,
    message_id: &str,
    original_sender: &str,
    used_prekey_id: &str,
) -> bool {
    let OutboundFrame::Message {
        chat_id: frame_chat_id,
        message_id: frame_message_id,
        prekey_id: frame_prekey_id,
        is_prekey,
        sender_username: frame_sender,
        ..
    } = frame
    else {
        return false;
    };

    frame_chat_id == chat_id
        && frame_message_id == message_id
        && frame_sender == original_sender
        && if used_prekey_id.is_empty() {
            !is_prekey && frame_prekey_id.is_empty()
        } else {
            *is_prekey && frame_prekey_id == used_prekey_id
        }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn acknowledge_message(
    state: &AppState,
    sender_id: Uuid,
    chat_id: &str,
    message_id: &str,
    original_sender: &str,
    revision: u64,
    envelope_b64: &str,
    identity_public_b64: &str,
    current_prekey_id: &str,
    state_signature_b64: &str,
    ack_signature_b64: &str,
    used_prekey_id: &str,
) -> Result<(), String> {
    let _conversation_guard = state.conversation_ops.lock().await;
    prune_pending_queues(state, now_ms()).await;
    if !valid_chat_id(chat_id)
        || !valid_chat_id(message_id)
        || original_sender.is_empty()
        || original_sender.len() > 80
        || !original_sender.is_ascii()
    {
        return Err("message acknowledgement rejected".to_string());
    }
    let (code_id, username) = client_identity(state, sender_id).await?;
    let access = conversation_access(state, &username, chat_id)
        .await
        .ok_or_else(|| "conversation unavailable".to_string())?;
    let valid_sender = match access {
        ConversationAccess::MlsRoom(_) => false,
        ConversationAccess::Room(_) => state
            .accounts
            .lock()
            .await
            .values()
            .any(|account| account.username == original_sender),
        ConversationAccess::Direct => state
            .direct_catalog
            .lock()
            .await
            .get(chat_id)
            .and_then(|direct| direct.peer_for(&username))
            .is_some_and(|peer| peer == original_sender),
    };
    if !valid_sender || original_sender == username {
        return Err("conversation unavailable".to_string());
    }
    let identity_public = Zeroizing::new(decode_exact(identity_public_b64, IDENTITY_PUBLIC_BYTES)?);
    let ack_signature = Zeroizing::new(decode_exact(ack_signature_b64, MESSAGE_SIGNATURE_BYTES)?);
    verify_ack_signature_v9(
        E2EE_PROTOCOL_VERSION,
        chat_id,
        message_id,
        original_sender,
        used_prekey_id,
        &identity_public,
        &ack_signature,
    )?;

    let key = PendingKey {
        chat_id: chat_id.to_string(),
        recipient_username: username.clone(),
    };
    // Keep the lock order used by message admission and claim maintenance:
    // accounts -> pending -> pending_bytes -> prekey_leases.  Every
    // precondition is checked while these guards are held, then the signed
    // state and queue/claim consumption commit as one conversation operation.
    let mut accounts = state.accounts.lock().await;
    let mut pending = state.pending.lock().await;
    let mut pending_bytes = state.pending_bytes.lock().await;
    let mut claims = state.prekey_leases.lock().await;

    let (matching_index, matching_bytes) = {
        let queue = pending
            .get(&key)
            .ok_or_else(|| "message acknowledgement rejected".to_string())?;
        let mut matching_index = None;
        for (index, pending_frame) in queue.iter().enumerate() {
            if pending_frame_matches_ack(
                &pending_frame.frame,
                chat_id,
                message_id,
                original_sender,
                used_prekey_id,
            ) && matching_index.replace(index).is_some()
            {
                return Err("message acknowledgement rejected".to_string());
            }
        }
        let matching_index =
            matching_index.ok_or_else(|| "message acknowledgement rejected".to_string())?;
        (
            matching_index,
            outbound_frame_bytes(&queue[matching_index].frame),
        )
    };
    if *pending_bytes < matching_bytes {
        return Err("message acknowledgement rejected".to_string());
    }

    if !used_prekey_id.is_empty() {
        let claim_key = PrekeyLeaseKey {
            code_id,
            prekey_id: used_prekey_id.to_string(),
        };
        let Some(claim) = claims.get(&claim_key) else {
            return Err("message acknowledgement rejected".to_string());
        };
        if claim.chat_id != chat_id
            || claim.message_id != message_id
            || claim.sender_username != original_sender
            || claim.recipient_username != username
        {
            return Err("message acknowledgement rejected".to_string());
        }
    }

    let next_identity_public =
        Zeroizing::new(decode_exact(identity_public_b64, IDENTITY_PUBLIC_BYTES)?);
    let next_pool = prekey_ids_from_identity_public_v9(&next_identity_public)
        .map_err(|_| "message acknowledgement rejected".to_string())?;
    if leases_for_recipient_missing_from_pool(
        &claims,
        &code_id,
        &next_pool,
        (!used_prekey_id.is_empty()).then_some(used_prekey_id),
    ) {
        return Err("message acknowledgement rejected".to_string());
    }

    apply_identity_state_locked_with_consumed(
        &mut accounts,
        &code_id,
        revision,
        envelope_b64,
        identity_public_b64,
        current_prekey_id,
        state_signature_b64,
        true,
        (!used_prekey_id.is_empty()).then_some(used_prekey_id),
    )?;

    let queue = pending
        .get_mut(&key)
        .expect("validated pending acknowledgement queue");
    let mut removed = queue.remove(matching_index);
    *pending_bytes -= matching_bytes;
    removed.zeroize_sensitive();
    let queue_is_empty = queue.is_empty();
    if queue_is_empty {
        pending.remove(&key);
    }
    if !used_prekey_id.is_empty() {
        claims.remove(&PrekeyLeaseKey {
            code_id,
            prekey_id: used_prekey_id.to_string(),
        });
    }
    Ok(())
}

pub(super) fn leases_for_recipient_missing_from_pool(
    leases: &HashMap<PrekeyLeaseKey, PrekeyLease>,
    code_id: &CodeId,
    next_pool: &[String],
    consumed_prekey_id: Option<&str>,
) -> bool {
    leases.keys().any(|key| {
        key.code_id == *code_id
            && consumed_prekey_id != Some(key.prekey_id.as_str())
            && !next_pool.contains(&key.prekey_id)
    })
}
