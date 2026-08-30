//! In-memory encrypted attachment state and lifecycle operations.
//!
//! This module owns encrypted attachment records, admission limits, staged
//! publication, expiry cleanup, recipient claims, and bounded streaming.
//! Request handlers remain in the protocol module and call these helpers.

use super::*;

pub(super) struct AttachmentBlob {
    pub(super) bytes: Zeroizing<Vec<u8>>,
    pub(super) _memory_permit: Option<OwnedSemaphorePermit>,
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub(super) struct AttachmentBindingKey {
    pub(super) owner_code_id: CodeId,
    pub(super) chat_id: String,
    pub(super) message_id: String,
}

impl AttachmentBindingKey {
    pub(super) fn new(owner_code_id: &CodeId, chat_id: &str, message_id: &str) -> Self {
        Self {
            owner_code_id: *owner_code_id,
            chat_id: chat_id.to_string(),
            message_id: message_id.to_string(),
        }
    }

    pub(super) fn matches_record(&self, record: &AttachmentRecord) -> bool {
        self.owner_code_id == record.owner_code_id
            && self.chat_id == record.chat_id
            && self.message_id == record.message_id
    }
}

impl Drop for AttachmentBindingKey {
    fn drop(&mut self) {
        self.owner_code_id.zeroize();
        self.chat_id.zeroize();
        self.message_id.zeroize();
    }
}

pub(super) struct AttachmentRecord {
    pub(super) blob: Arc<AttachmentBlob>,
    pub(super) chat_id: String,
    pub(super) message_id: String,
    pub(super) media_type: String,
    pub(super) owner_code_id: CodeId,
    pub(super) sender_platform: ClientPlatform,
    pub(super) published: bool,
    pub(super) staged_expires_at_ms: Option<u64>,
    pub(super) one_time: bool,
    pub(super) delete_after_download: bool,
    pub(super) expires_at_ms: Option<u64>,
    pub(super) eligible_recipient_code_ids: HashSet<CodeId>,
    pub(super) download_claims: HashMap<Uuid, AttachmentDownloadClaim>,
    pub(super) completed_recipient_code_ids: HashSet<CodeId>,
}

pub(super) struct StagedAttachmentRollback {
    pub(super) attachment_id: Uuid,
    pub(super) owner_code_id: CodeId,
    pub(super) chat_id: String,
    pub(super) message_id: String,
    pub(super) eligible_recipient_code_ids: HashSet<CodeId>,
    pub(super) published: bool,
    pub(super) staged_expires_at_ms: Option<u64>,
}

impl Drop for StagedAttachmentRollback {
    fn drop(&mut self) {
        self.owner_code_id.zeroize();
        self.chat_id.zeroize();
        self.message_id.zeroize();
        for mut code_id in self.eligible_recipient_code_ids.drain() {
            code_id.zeroize();
        }
    }
}

pub(super) struct AttachmentDownloadClaim {
    pub(super) recipient_code_id: CodeId,
    pub(super) created_at_ms: u64,
}

impl Drop for AttachmentDownloadClaim {
    fn drop(&mut self) {
        self.recipient_code_id.zeroize();
    }
}

impl Drop for AttachmentRecord {
    fn drop(&mut self) {
        self.chat_id.zeroize();
        self.message_id.zeroize();
        self.media_type.zeroize();
        self.owner_code_id.zeroize();
        for mut code_id in self.eligible_recipient_code_ids.drain() {
            code_id.zeroize();
        }
        for (_, mut claim) in self.download_claims.drain() {
            claim.recipient_code_id.zeroize();
        }
        for mut code_id in self.completed_recipient_code_ids.drain() {
            code_id.zeroize();
        }
    }
}

pub(super) fn remove_attachment_binding_if_matches(
    bindings: &mut HashMap<AttachmentBindingKey, Uuid>,
    attachment_id: Uuid,
    record: &AttachmentRecord,
) {
    let key = AttachmentBindingKey::new(&record.owner_code_id, &record.chat_id, &record.message_id);
    if bindings.get(&key).copied() == Some(attachment_id) {
        bindings.remove(&key);
    }
}

pub(super) async fn attachment_sweeper(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
    loop {
        interval.tick().await;
        prune_expired_attachments(&state).await;
    }
}

pub(super) async fn prune_expired_attachments(state: &AppState) {
    let _conversation_guard = state.conversation_ops.lock().await;
    prune_expired_attachments_locked(state).await;
}

pub(super) async fn prune_expired_attachments_locked(state: &AppState) {
    let now = now_ms();
    let mut bindings = state.attachment_bindings.lock().await;
    let mut attachments = state.attachments.lock().await;
    let mut usage = state.attachment_bytes_by_code.lock().await;
    let before = attachments.len();
    attachments.retain(|attachment_id, record| {
        record
            .download_claims
            .retain(|_, claim| now.saturating_sub(claim.created_at_ms) < ATTACHMENT_CLAIM_TTL_MS);
        let live = if record.published {
            record.expires_at_ms.is_none_or(|expires| now < expires)
        } else {
            // A staged record without an explicit bounded deadline is
            // malformed and must not survive or become publishable.
            record
                .staged_expires_at_ms
                .is_some_and(|expires| now < expires)
        };
        if live || (record.published && !record.download_claims.is_empty()) {
            true
        } else {
            remove_attachment_binding_if_matches(&mut bindings, *attachment_id, record);
            subtract_attachment_usage(&mut usage, &record.owner_code_id, record.blob.bytes.len());
            false
        }
    });
    let stale_bindings = bindings
        .iter()
        .filter_map(|(key, attachment_id)| {
            attachments
                .get(attachment_id)
                .filter(|record| !key.matches_record(record))
                .map(|_| (key.clone(), *attachment_id))
        })
        .collect::<Vec<_>>();
    for (key, attachment_id) in stale_bindings {
        bindings.remove(&key);
        if !bindings
            .values()
            .any(|candidate_id| *candidate_id == attachment_id)
        {
            if let Some(record) = attachments.remove(&attachment_id) {
                subtract_attachment_usage(
                    &mut usage,
                    &record.owner_code_id,
                    record.blob.bytes.len(),
                );
            }
        }
    }
    bindings.retain(|key, attachment_id| {
        attachments
            .get(attachment_id)
            .is_some_and(|record| key.matches_record(record))
    });
    let removed = before.saturating_sub(attachments.len());
    if removed > 0 {
        info!("expired_attachments_removed count={removed}");
    }
}

pub(super) async fn remove_chat_attachments(state: &AppState, chat_id: &str) {
    let mut bindings = state.attachment_bindings.lock().await;
    let mut attachments = state.attachments.lock().await;
    let mut usage = state.attachment_bytes_by_code.lock().await;
    attachments.retain(|attachment_id, record| {
        if record.chat_id != chat_id {
            true
        } else {
            remove_attachment_binding_if_matches(&mut bindings, *attachment_id, record);
            subtract_attachment_usage(&mut usage, &record.owner_code_id, record.blob.bytes.len());
            false
        }
    });
}

pub(super) async fn revoke_mls_attachment_access(
    state: &AppState,
    room_id: &str,
    removed_code_id: &CodeId,
) {
    let mut attachments = state.attachments.lock().await;
    for record in attachments
        .values_mut()
        .filter(|record| record.chat_id == room_id)
    {
        if let Some(mut code_id) = record.eligible_recipient_code_ids.take(removed_code_id) {
            code_id.zeroize();
        }
        if let Some(mut code_id) = record.completed_recipient_code_ids.take(removed_code_id) {
            code_id.zeroize();
        }
        record
            .download_claims
            .retain(|_, claim| claim.recipient_code_id != *removed_code_id);
    }
}

pub(super) fn normalize_media_type(media_type: Option<&str>) -> String {
    match media_type
        .unwrap_or("FILE")
        .trim()
        .to_ascii_uppercase()
        .as_str()
    {
        "IMAGE" => "IMAGE".to_string(),
        "VIDEO" => "VIDEO".to_string(),
        _ => "FILE".to_string(),
    }
}

pub(super) fn max_serialized_attachment_bytes(media_type: &str) -> usize {
    let plain_limit = match media_type {
        "IMAGE" => IMAGE_ATTACHMENT_LIMIT_BYTES,
        "VIDEO" => VIDEO_ATTACHMENT_LIMIT_BYTES,
        _ => FILE_ATTACHMENT_LIMIT_BYTES,
    };
    attachment_encrypted_size(media_type.to_string(), plain_limit as u64)
        .ok()
        .and_then(|bytes| usize::try_from(bytes).ok())
        .unwrap_or(0)
}

pub(super) fn encrypted_attachment_limit_bytes(media_type: &str) -> usize {
    max_serialized_attachment_bytes(media_type)
}

pub(super) fn valid_encrypted_attachment_body(media_type: &str, body: &[u8]) -> bool {
    attachment_plaintext_size_from_blob(media_type, body).is_ok()
}

pub(super) fn declared_attachment_length(
    headers: &HeaderMap,
    max_bytes: usize,
) -> Result<usize, StatusCode> {
    let value = headers
        .get(header::CONTENT_LENGTH)
        .ok_or(StatusCode::LENGTH_REQUIRED)?;
    let length = value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|length| *length > 0)
        .ok_or(StatusCode::LENGTH_REQUIRED)?;
    if length > max_bytes {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    Ok(length)
}

pub(super) async fn read_bounded_attachment_body(
    body: Body,
    max_bytes: usize,
    declared_length: Option<usize>,
) -> Result<Zeroizing<Vec<u8>>, StatusCode> {
    read_bounded_attachment_body_with_timeout(
        body,
        max_bytes,
        declared_length,
        ATTACHMENT_UPLOAD_IDLE_TIMEOUT,
    )
    .await
}

pub(super) async fn read_bounded_attachment_body_with_timeout(
    body: Body,
    max_bytes: usize,
    declared_length: Option<usize>,
    idle_timeout: Duration,
) -> Result<Zeroizing<Vec<u8>>, StatusCode> {
    read_bounded_attachment_body_with_timeouts(
        body,
        max_bytes,
        declared_length,
        idle_timeout,
        ATTACHMENT_UPLOAD_TOTAL_TIMEOUT,
    )
    .await
}

pub(super) async fn read_bounded_attachment_body_with_timeouts(
    body: Body,
    max_bytes: usize,
    declared_length: Option<usize>,
    idle_timeout: Duration,
    total_timeout: Duration,
) -> Result<Zeroizing<Vec<u8>>, StatusCode> {
    tokio::time::timeout(total_timeout, async move {
        let initial_capacity = declared_length
            .unwrap_or(ATTACHMENT_DOWNLOAD_CHUNK_BYTES)
            .min(max_bytes);
        let mut encrypted_body = Zeroizing::new(Vec::with_capacity(initial_capacity));
        let mut stream = body.into_data_stream();
        loop {
            let next = tokio::time::timeout(idle_timeout, stream.next())
                .await
                .map_err(|_| StatusCode::REQUEST_TIMEOUT)?;
            let Some(chunk) = next else {
                break;
            };
            let chunk = chunk.map_err(|_| StatusCode::BAD_REQUEST)?;
            let next_len = encrypted_body
                .len()
                .checked_add(chunk.len())
                .ok_or(StatusCode::PAYLOAD_TOO_LARGE)?;
            if declared_length.is_some_and(|declared| next_len > declared) {
                return Err(StatusCode::BAD_REQUEST);
            }
            if next_len > max_bytes {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            let capacity = encrypted_body.capacity();
            if capacity < next_len {
                let target_capacity = capacity.saturating_mul(2).max(next_len).min(max_bytes);
                encrypted_body.reserve_exact(target_capacity - capacity);
            }
            encrypted_body.extend_from_slice(&chunk);
        }
        if encrypted_body.is_empty() {
            return Err(StatusCode::BAD_REQUEST);
        }
        if declared_length.is_some_and(|declared| declared != encrypted_body.len()) {
            return Err(StatusCode::BAD_REQUEST);
        }
        Ok(encrypted_body)
    })
    .await
    .map_err(|_| StatusCode::REQUEST_TIMEOUT)?
}

pub(super) async fn attachment_conversation_access(
    state: &AppState,
    username: &str,
    chat_id: &str,
    media_type: &str,
) -> Result<ConversationAccess, StatusCode> {
    if !valid_chat_id(chat_id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let Some(access) = conversation_access(state, username, chat_id).await else {
        return Err(StatusCode::FORBIDDEN);
    };
    if matches!(&access, ConversationAccess::MlsRoom(policy) if !policy_allows_media(policy, media_type))
        || matches!(&access, ConversationAccess::Room(room) if !room_allows_media(room, media_type))
    {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(access)
}

pub(super) fn valid_chat_id(chat_id: &str) -> bool {
    !chat_id.is_empty()
        && chat_id.len() <= MAX_CHAT_ID_BYTES
        && chat_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub(super) async fn conversation_access(
    state: &AppState,
    username: &str,
    chat_id: &str,
) -> Option<ConversationAccess> {
    if !valid_chat_id(chat_id) {
        return None;
    }
    let code_id = state
        .accounts
        .lock()
        .await
        .iter()
        .find_map(|(code_id, account)| (account.username == username).then_some(*code_id));
    if let Some(code_id) = code_id {
        let mut mls_rooms = state.mls_rooms.lock().await;
        if mls_rooms.is_member(chat_id, &code_id) {
            if !mls_rooms.is_active_member(chat_id, &code_id) {
                return None;
            }
            if let Ok(info) = mls_rooms.member_info(chat_id, &code_id) {
                return Some(ConversationAccess::MlsRoom(info.policy));
            }
        }
    }
    if let Some(room) = state
        .room_catalog
        .lock()
        .await
        .get(chat_id)
        .map(|entry| entry.room.clone())
    {
        return Some(ConversationAccess::Room(room));
    }
    state
        .direct_catalog
        .lock()
        .await
        .get(chat_id)
        .filter(|direct| direct.user_a == username || direct.user_b == username)
        .map(|_| ConversationAccess::Direct)
}

pub(super) async fn snapshot_attachment_recipients(
    state: &AppState,
    access: &ConversationAccess,
    chat_id: &str,
    owner_username: &str,
    owner_code_id: &CodeId,
) -> HashSet<CodeId> {
    if let ConversationAccess::MlsRoom(_) = access {
        return state
            .mls_rooms
            .lock()
            .await
            .active_member_code_ids(chat_id)
            .unwrap_or_default()
            .into_iter()
            .filter(|code_id| code_id != owner_code_id)
            .collect();
    }
    let peer_username = if matches!(access, ConversationAccess::Direct) {
        state
            .direct_catalog
            .lock()
            .await
            .get(chat_id)
            .and_then(|direct| direct.peer_for(owner_username))
    } else {
        None
    };
    state
        .accounts
        .lock()
        .await
        .iter()
        .filter(|(code_id, account)| {
            **code_id != *owner_code_id
                && match (&access, &peer_username) {
                    (ConversationAccess::MlsRoom(_), _) => false,
                    (ConversationAccess::Room(_), _) => true,
                    (ConversationAccess::Direct, Some(peer)) => account.username == *peer,
                    (ConversationAccess::Direct, None) => false,
                }
        })
        .map(|(code_id, _)| *code_id)
        .collect()
}

pub(super) fn room_allows_media(room: &RoomRecord, media_type: &str) -> bool {
    match media_type {
        "IMAGE" => room.allow_images,
        "VIDEO" => room.allow_videos,
        _ => room.allow_files,
    }
}

pub(super) fn policy_allows_media(policy: &rooms::RoomPolicy, media_type: &str) -> bool {
    match media_type {
        "IMAGE" => policy.allow_images,
        "VIDEO" => policy.allow_videos,
        _ => policy.allow_files,
    }
}

pub(super) fn enforced_attachment_ttl_sec(room: &RoomRecord, media_type: &str) -> u64 {
    let room_ttl = room
        .enforce_text_absolute_expiry
        .then_some(room.overall_expiry_sec)
        .filter(|ttl| *ttl > 0);
    let media_ttl = match media_type {
        "IMAGE" if room.enforce_image_absolute_expiry => room.image_overall_expiry_sec,
        "VIDEO" if room.enforce_video_absolute_expiry => room.video_overall_expiry_sec,
        "FILE" if room.enforce_file_absolute_expiry => room.file_overall_expiry_sec,
        _ => 0,
    };
    room_ttl
        .into_iter()
        .chain((media_ttl > 0).then_some(media_ttl))
        .min()
        .unwrap_or(0)
}

pub(super) fn enforced_attachment_ttl_sec_policy(
    policy: &rooms::RoomPolicy,
    media_type: &str,
) -> u64 {
    let room_ttl = policy
        .enforce_text_absolute_expiry
        .then_some(policy.overall_expiry_sec)
        .filter(|ttl| *ttl > 0);
    let media_ttl = match media_type {
        "IMAGE" if policy.enforce_image_absolute_expiry => policy.image_overall_expiry_sec,
        "VIDEO" if policy.enforce_video_absolute_expiry => policy.video_overall_expiry_sec,
        "FILE" if policy.enforce_file_absolute_expiry => policy.file_overall_expiry_sec,
        _ => 0,
    };
    room_ttl
        .into_iter()
        .chain((media_ttl > 0).then_some(media_ttl))
        .min()
        .unwrap_or(0)
}

pub(super) fn effective_attachment_ttl_sec(
    requested: Option<u64>,
    access: &ConversationAccess,
    media_type: &str,
    max_lifetime_sec: u64,
) -> u64 {
    let requested = requested.unwrap_or_default().min(86_400);
    let effective = match access {
        ConversationAccess::MlsRoom(policy) => {
            let enforced = enforced_attachment_ttl_sec_policy(policy, media_type);
            match (requested, enforced) {
                (0, enforced) => enforced,
                (requested, 0) => requested,
                (requested, enforced) => requested.min(enforced),
            }
        }
        ConversationAccess::Room(room) => {
            let enforced = enforced_attachment_ttl_sec(room, media_type);
            match (requested, enforced) {
                (0, enforced) => enforced,
                (requested, 0) => requested,
                (requested, enforced) => requested.min(enforced),
            }
        }
        ConversationAccess::Direct => requested,
    };
    // Even an explicit zero/no-expiry request gets a finite relay-side
    // lifetime.  Room policy can still shorten this value, never extend it.
    if effective == 0 {
        max_lifetime_sec
    } else {
        effective.min(max_lifetime_sec)
    }
}

pub(super) fn current_attachment_bytes(attachments: &HashMap<Uuid, AttachmentRecord>) -> usize {
    attachments
        .values()
        .map(|record| record.blob.bytes.len())
        .sum()
}

pub(super) fn current_attachment_records_for_owner(
    attachments: &HashMap<Uuid, AttachmentRecord>,
    owner_code_id: &CodeId,
) -> usize {
    attachments
        .values()
        .filter(|record| record.owner_code_id == *owner_code_id)
        .count()
}

pub(super) async fn staged_attachment_for_message(
    state: &AppState,
    owner_code_id: &CodeId,
    chat_id: &str,
    message_id: &str,
) -> Result<Option<Uuid>, String> {
    let key = AttachmentBindingKey::new(owner_code_id, chat_id, message_id);
    let mut bindings = state.attachment_bindings.lock().await;
    let Some(attachment_id) = bindings.get(&key).copied() else {
        return Ok(None);
    };
    let mut attachments = state.attachments.lock().await;
    let now = now_ms();
    if let Some(record) = attachments.get_mut(&attachment_id) {
        if key.matches_record(record) {
            record.download_claims.retain(|_, claim| {
                now.saturating_sub(claim.created_at_ms) < ATTACHMENT_CLAIM_TTL_MS
            });
        }
    }
    let action = match attachments.get(&attachment_id) {
        None => 0_u8,
        Some(record) if !key.matches_record(record) => 1,
        Some(record) if record.published => {
            if record.expires_at_ms.is_some_and(|expires| now >= expires)
                && record.download_claims.is_empty()
            {
                2
            } else {
                3
            }
        }
        Some(record)
            if record
                .staged_expires_at_ms
                .is_none_or(|expires| now >= expires)
                || record.expires_at_ms.is_some_and(|expires| now >= expires) =>
        {
            2
        }
        Some(_) => 4,
    };
    match action {
        0 => {
            bindings.remove(&key);
            Ok(None)
        }
        1 => {
            let orphaned_record = !bindings.iter().any(|(candidate_key, candidate_id)| {
                candidate_key != &key && *candidate_id == attachment_id
            });
            bindings.remove(&key);
            if orphaned_record {
                if let Some(record) = attachments.remove(&attachment_id) {
                    let mut usage = state.attachment_bytes_by_code.lock().await;
                    subtract_attachment_usage(
                        &mut usage,
                        &record.owner_code_id,
                        record.blob.bytes.len(),
                    );
                }
            }
            Ok(None)
        }
        2 => {
            if let Some(record) = attachments.remove(&attachment_id) {
                let mut usage = state.attachment_bytes_by_code.lock().await;
                remove_attachment_binding_if_matches(&mut bindings, attachment_id, &record);
                subtract_attachment_usage(
                    &mut usage,
                    &record.owner_code_id,
                    record.blob.bytes.len(),
                );
            } else {
                bindings.remove(&key);
            }
            Ok(None)
        }
        3 => Err("duplicate attachment message binding".to_string()),
        _ => Ok(Some(attachment_id)),
    }
}

pub(super) async fn publish_staged_attachment_checked(
    state: &AppState,
    attachment_id: Uuid,
    owner_code_id: &CodeId,
    chat_id: &str,
    message_id: &str,
) -> Result<(), String> {
    let key = AttachmentBindingKey::new(owner_code_id, chat_id, message_id);
    let mut bindings = state.attachment_bindings.lock().await;
    let Some(indexed_id) = bindings.get(&key).copied() else {
        return Err("staged attachment unavailable".to_string());
    };
    if indexed_id != attachment_id {
        bindings.remove(&key);
        return Err("staged attachment binding mismatch".to_string());
    }
    let mut attachments = state.attachments.lock().await;
    let now = now_ms();
    let action = match attachments.get(&attachment_id) {
        Some(record) if key.matches_record(record) && record.published => 0_u8,
        Some(record)
            if key.matches_record(record)
                && record
                    .staged_expires_at_ms
                    .is_some_and(|expires| now < expires)
                && record.expires_at_ms.is_none_or(|expires| now < expires) =>
        {
            1
        }
        Some(record) if key.matches_record(record) => 2,
        _ => 3,
    };
    match action {
        0 => Ok(()),
        1 => {
            if let Some(record) = attachments.get_mut(&attachment_id) {
                record.published = true;
                record.staged_expires_at_ms = None;
            }
            Ok(())
        }
        2 => {
            if let Some(record) = attachments.remove(&attachment_id) {
                let mut usage = state.attachment_bytes_by_code.lock().await;
                remove_attachment_binding_if_matches(&mut bindings, attachment_id, &record);
                subtract_attachment_usage(
                    &mut usage,
                    &record.owner_code_id,
                    record.blob.bytes.len(),
                );
            }
            Err("staged attachment expired".to_string())
        }
        _ => {
            let orphaned_record = attachments.get(&attachment_id).is_some_and(|record| {
                !key.matches_record(record)
                    && !bindings.iter().any(|(candidate_key, candidate_id)| {
                        candidate_key != &key && *candidate_id == attachment_id
                    })
            });
            bindings.remove(&key);
            if orphaned_record {
                if let Some(record) = attachments.remove(&attachment_id) {
                    let mut usage = state.attachment_bytes_by_code.lock().await;
                    subtract_attachment_usage(
                        &mut usage,
                        &record.owner_code_id,
                        record.blob.bytes.len(),
                    );
                }
            }
            Err("staged attachment unavailable".to_string())
        }
    }
}

pub(super) async fn publish_staged_attachment(
    state: &AppState,
    attachment_id: Uuid,
    owner_code_id: &CodeId,
    chat_id: &str,
    message_id: &str,
) {
    let _ =
        publish_staged_attachment_checked(state, attachment_id, owner_code_id, chat_id, message_id)
            .await;
}

pub(super) async fn rebind_staged_attachment_recipients(
    state: &AppState,
    attachment_id: Uuid,
    recipients: &HashSet<CodeId>,
) -> Result<StagedAttachmentRollback, String> {
    let mut attachments = state.attachments.lock().await;
    let record = attachments
        .get_mut(&attachment_id)
        .ok_or_else(|| "staged attachment unavailable".to_string())?;
    if record.published {
        return Err("staged attachment already published".to_string());
    }
    if (record.one_time || record.delete_after_download) && recipients.is_empty() {
        return Err("attachment recipient roster rejected".to_string());
    }
    let rollback = StagedAttachmentRollback {
        attachment_id,
        owner_code_id: record.owner_code_id,
        chat_id: record.chat_id.clone(),
        message_id: record.message_id.clone(),
        eligible_recipient_code_ids: record.eligible_recipient_code_ids.clone(),
        published: record.published,
        staged_expires_at_ms: record.staged_expires_at_ms,
    };
    if record.one_time || record.delete_after_download {
        record.eligible_recipient_code_ids = recipients.clone();
    }
    Ok(rollback)
}

pub(super) async fn rollback_staged_attachment(
    state: &AppState,
    mut rollback: StagedAttachmentRollback,
) {
    let attachment_id = rollback.attachment_id;
    let key = AttachmentBindingKey::new(
        &rollback.owner_code_id,
        &rollback.chat_id,
        &rollback.message_id,
    );
    let mut bindings = state.attachment_bindings.lock().await;
    let mut attachments = state.attachments.lock().await;
    let restored = if let Some(record) = attachments.get_mut(&rollback.attachment_id) {
        if key.matches_record(record) {
            record.eligible_recipient_code_ids =
                std::mem::take(&mut rollback.eligible_recipient_code_ids);
            record.published = rollback.published;
            record.staged_expires_at_ms = rollback.staged_expires_at_ms;
            true
        } else {
            false
        }
    } else {
        false
    };
    if restored {
        bindings.insert(key, attachment_id);
    }
}

pub(super) fn attachment_record_capacity_allows(
    used_total: usize,
    used_account: usize,
    total_limit: usize,
    account_limit: usize,
) -> bool {
    used_total < total_limit && used_account < account_limit
}

pub(super) async fn attachment_record_capacity_available(
    state: &AppState,
    owner_code_id: &CodeId,
) -> bool {
    prune_expired_attachments(state).await;
    let attachments = state.attachments.lock().await;
    attachment_record_capacity_allows(
        attachments.len(),
        current_attachment_records_for_owner(&attachments, owner_code_id),
        state.attachment_record_limit,
        state.attachment_account_record_limit,
    )
}

pub(super) fn subtract_attachment_usage(
    usage: &mut HashMap<CodeId, usize>,
    owner_code_id: &CodeId,
    bytes: usize,
) {
    let Some(current) = usage.get_mut(owner_code_id) else {
        return;
    };
    if *current <= bytes {
        if let Some((mut removed_code_id, _)) = usage.remove_entry(owner_code_id) {
            removed_code_id.zeroize();
        }
    } else {
        *current -= bytes;
    }
}

pub(super) fn attachment_capacity_allows(
    used_total: usize,
    used_account: usize,
    incoming: usize,
    total_limit: usize,
    account_limit: usize,
) -> bool {
    used_total
        .checked_add(incoming)
        .is_some_and(|total| total <= total_limit)
        && used_account
            .checked_add(incoming)
            .is_some_and(|account| account <= account_limit)
}

pub(super) fn acquire_attachment_download_permit(
    downloads: &Arc<Semaphore>,
) -> Result<OwnedSemaphorePermit, StatusCode> {
    downloads
        .clone()
        .try_acquire_owned()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)
}

pub(super) fn acquire_attachment_upload_permit(
    uploads: &Arc<Semaphore>,
) -> Result<OwnedSemaphorePermit, StatusCode> {
    uploads
        .clone()
        .try_acquire_owned()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)
}

pub(super) async fn acquire_account_attachment_upload_permit(
    state: &AppState,
    code_id: &CodeId,
) -> Result<OwnedSemaphorePermit, StatusCode> {
    let uploads = state
        .accounts
        .lock()
        .await
        .get(code_id)
        .map(|account| Arc::clone(&account.attachment_uploads))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    uploads
        .try_acquire_owned()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)
}

pub(super) fn acquire_attachment_memory_permit(
    memory: &Arc<Semaphore>,
    bytes: usize,
) -> Result<OwnedSemaphorePermit, StatusCode> {
    if bytes == 0 || bytes > u32::MAX as usize {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    memory
        .clone()
        .try_acquire_many_owned(bytes as u32)
        .map_err(|_| StatusCode::from_u16(507).unwrap_or(StatusCode::SERVICE_UNAVAILABLE))
}

pub(super) struct AttachmentDownloadReservation {
    pub(super) blob: Arc<AttachmentBlob>,
    pub(super) claim_id: Option<Uuid>,
    pub(super) epoch: u64,
}

pub(super) async fn reserve_attachment_download(
    state: &AppState,
    attachment_id: Uuid,
    requester_code_id: &CodeId,
) -> Result<AttachmentDownloadReservation, StatusCode> {
    prune_expired_attachments_locked(state).await;
    let requester_platform = state
        .accounts
        .lock()
        .await
        .get(requester_code_id)
        .and_then(|account| account.client_platform);
    let mut bindings = state.attachment_bindings.lock().await;
    let mut attachments = state.attachments.lock().await;
    let mut usage = state.attachment_bytes_by_code.lock().await;
    let Some(record) = attachments.get_mut(&attachment_id) else {
        return Err(StatusCode::NOT_FOUND);
    };
    // Staged ciphertext is deliberately indistinguishable from a missing
    // attachment to download callers.
    if !record.published {
        return Err(StatusCode::NOT_FOUND);
    }
    if record
        .expires_at_ms
        .is_some_and(|expires| now_ms() >= expires)
    {
        if !record.download_claims.is_empty() {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        let owner_code_id = record.owner_code_id;
        let encrypted_len = record.blob.bytes.len();
        let Some(record) = attachments.remove(&attachment_id) else {
            return Err(StatusCode::NOT_FOUND);
        };
        remove_attachment_binding_if_matches(&mut bindings, attachment_id, &record);
        subtract_attachment_usage(&mut usage, &owner_code_id, encrypted_len);
        return Err(StatusCode::NOT_FOUND);
    }

    let owner = *requester_code_id == record.owner_code_id;
    if !owner {
        let Some(requester_platform) = requester_platform else {
            return Err(StatusCode::FORBIDDEN);
        };
        if !record
            .eligible_recipient_code_ids
            .contains(requester_code_id)
            || !state
                .interop_policy
                .allows(record.sender_platform, requester_platform)
        {
            return Err(StatusCode::FORBIDDEN);
        }
    }
    let destructive = record.one_time || record.delete_after_download;
    let claim_id = if !destructive || owner {
        None
    } else {
        if record
            .completed_recipient_code_ids
            .contains(requester_code_id)
        {
            return Err(StatusCode::NOT_FOUND);
        }
        if record
            .download_claims
            .values()
            .any(|claim| claim.recipient_code_id == *requester_code_id)
        {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        let claim_id = loop {
            let candidate = Uuid::new_v4();
            if !record.download_claims.contains_key(&candidate) {
                break candidate;
            }
        };
        record.download_claims.insert(
            claim_id,
            AttachmentDownloadClaim {
                recipient_code_id: *requester_code_id,
                created_at_ms: now_ms(),
            },
        );
        Some(claim_id)
    };
    Ok(AttachmentDownloadReservation {
        blob: Arc::clone(&record.blob),
        claim_id,
        epoch: state.attachment_epoch.load(Ordering::Acquire),
    })
}

pub(super) async fn complete_attachment_download_claim(
    state: &AppState,
    attachment_id: Uuid,
    requester_code_id: &CodeId,
    claim_id: Uuid,
) -> Result<(), StatusCode> {
    let mut bindings = state.attachment_bindings.lock().await;
    let mut attachments = state.attachments.lock().await;
    let mut usage = state.attachment_bytes_by_code.lock().await;
    let Some(record) = attachments.get_mut(&attachment_id) else {
        return Err(StatusCode::NOT_FOUND);
    };
    let Some(claim) = record.download_claims.get(&claim_id) else {
        return Err(StatusCode::NOT_FOUND);
    };
    let claim_recipient_code_id = claim.recipient_code_id;
    if claim_recipient_code_id != *requester_code_id {
        return Err(StatusCode::FORBIDDEN);
    }
    if now_ms().saturating_sub(claim.created_at_ms) >= ATTACHMENT_CLAIM_TTL_MS {
        record.download_claims.remove(&claim_id);
        return Err(StatusCode::NOT_FOUND);
    }
    record.download_claims.remove(&claim_id);
    record
        .completed_recipient_code_ids
        .insert(claim_recipient_code_id);
    if record
        .eligible_recipient_code_ids
        .is_subset(&record.completed_recipient_code_ids)
    {
        let Some(record) = attachments.remove(&attachment_id) else {
            return Err(StatusCode::NOT_FOUND);
        };
        remove_attachment_binding_if_matches(&mut bindings, attachment_id, &record);
        subtract_attachment_usage(&mut usage, &record.owner_code_id, record.blob.bytes.len());
    }
    Ok(())
}

pub(super) async fn release_attachment_download_claim(
    state: &AppState,
    attachment_id: Uuid,
    requester_code_id: &CodeId,
    claim_id: Uuid,
) -> Result<(), StatusCode> {
    let mut attachments = state.attachments.lock().await;
    let Some(record) = attachments.get_mut(&attachment_id) else {
        return Err(StatusCode::NOT_FOUND);
    };
    let Some(claim) = record.download_claims.get(&claim_id) else {
        return Err(StatusCode::NOT_FOUND);
    };
    if claim.recipient_code_id != *requester_code_id {
        return Err(StatusCode::FORBIDDEN);
    }
    record.download_claims.remove(&claim_id);
    Ok(())
}

#[cfg(test)]
pub(super) fn attachment_download_response(
    bytes: Vec<u8>,
    permit: OwnedSemaphorePermit,
    claim_id: Option<Uuid>,
) -> Response {
    attachment_download_response_with_timeout(
        bytes,
        permit,
        claim_id,
        ATTACHMENT_DOWNLOAD_STALL_TIMEOUT,
    )
}

#[cfg(test)]
pub(super) fn attachment_download_response_with_timeout(
    bytes: Vec<u8>,
    permit: OwnedSemaphorePermit,
    claim_id: Option<Uuid>,
    stall_timeout: Duration,
) -> Response {
    attachment_download_response_with_epoch(
        Arc::new(AttachmentBlob {
            bytes: Zeroizing::new(bytes),
            _memory_permit: None,
        }),
        permit,
        claim_id,
        Arc::new(AtomicU64::new(0)),
        0,
        stall_timeout,
    )
}

pub(super) fn attachment_download_response_with_epoch(
    blob: Arc<AttachmentBlob>,
    permit: OwnedSemaphorePermit,
    claim_id: Option<Uuid>,
    epoch: Arc<AtomicU64>,
    captured_epoch: u64,
    stall_timeout: Duration,
) -> Response {
    let content_length = blob.bytes.len().to_string();
    let (sender, receiver) = mpsc::channel(1);
    let stream_epoch = Arc::clone(&epoch);
    tokio::spawn(async move {
        let mut offset = 0usize;
        while offset < blob.bytes.len() {
            if epoch.load(Ordering::Acquire) != captured_epoch {
                return;
            }
            let end = offset
                .saturating_add(ATTACHMENT_DOWNLOAD_CHUNK_BYTES)
                .min(blob.bytes.len());
            let chunk = Bytes::copy_from_slice(&blob.bytes[offset..end]);
            let sent = tokio::time::timeout(stall_timeout, sender.send(chunk)).await;
            if !matches!(sent, Ok(Ok(()))) {
                return;
            }
            offset = end;
        }
        drop(sender);
        drop(permit);
    });
    let stream = futures_util::stream::unfold(
        (receiver, stream_epoch, captured_epoch),
        |(mut receiver, epoch, captured_epoch)| async move {
            let chunk = receiver.recv().await?;
            if epoch.load(Ordering::Acquire) != captured_epoch {
                return None;
            }
            Some((
                Ok::<Bytes, Infallible>(chunk),
                (receiver, epoch, captured_epoch),
            ))
        },
    );
    let mut response = Response::new(Body::from_stream(stream));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Ok(value) = HeaderValue::from_str(&content_length) {
        response.headers_mut().insert(header::CONTENT_LENGTH, value);
    }
    if let Some(claim_id) = claim_id {
        if let Ok(value) = HeaderValue::from_str(&claim_id.to_string()) {
            response.headers_mut().insert(
                header::HeaderName::from_static(ATTACHMENT_CLAIM_HEADER),
                value,
            );
        }
    }
    response
}

pub(super) async fn upload_attachment(
    State(state): State<AppState>,
    Query(query): Query<AttachmentQuery>,
    headers: HeaderMap,
    body: Body,
) -> impl IntoResponse {
    let upload_epoch = state.attachment_epoch.load(Ordering::Acquire);
    let initial_auth = match auth_from_headers(&state, &headers).await {
        Ok(auth) => auth,
        Err(status) => return status.into_response(),
    };
    let chat_id = query.chat_id.trim().to_string();
    let message_id = query.message_id.trim().to_string();
    if !valid_chat_id(&message_id) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let media_type = normalize_media_type(query.media_type.as_deref());
    let _initial_access =
        match attachment_conversation_access(&state, &initial_auth.username, &chat_id, &media_type)
            .await
        {
            Ok(access) => access,
            Err(status) => return status.into_response(),
        };
    let max_bytes = encrypted_attachment_limit_bytes(&media_type);
    let declared_length = match declared_attachment_length(&headers, max_bytes) {
        Ok(length) => length,
        Err(status) => return status.into_response(),
    };
    if !attachment_record_capacity_available(&state, &initial_auth.code_id).await {
        return StatusCode::from_u16(507)
            .unwrap_or(StatusCode::SERVICE_UNAVAILABLE)
            .into_response();
    }
    let _account_upload_permit =
        match acquire_account_attachment_upload_permit(&state, &initial_auth.code_id).await {
            Ok(permit) => permit,
            Err(status) => return status.into_response(),
        };
    let memory_permit =
        match acquire_attachment_memory_permit(&state.attachment_memory, declared_length) {
            Ok(permit) => permit,
            Err(status) => return status.into_response(),
        };
    let _upload_permit = match acquire_attachment_upload_permit(&state.attachment_uploads) {
        Ok(permit) => permit,
        Err(status) => return status.into_response(),
    };
    let mut encrypted_body =
        match read_bounded_attachment_body(body, max_bytes, Some(declared_length)).await {
            Ok(body) => body,
            Err(status) => return status.into_response(),
        };
    let _conversation_guard = state.conversation_ops.lock().await;
    if state.attachment_epoch.load(Ordering::Acquire) != upload_epoch {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let auth = match auth_from_headers(&state, &headers).await {
        Ok(auth) if auth.code_id == initial_auth.code_id => auth,
        Ok(_) | Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };
    let sender_platform = match state
        .accounts
        .lock()
        .await
        .get(&auth.code_id)
        .and_then(|account| account.client_platform)
    {
        Some(platform) => platform,
        None => return StatusCode::FORBIDDEN.into_response(),
    };
    if !valid_encrypted_attachment_body(&media_type, &encrypted_body) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let access =
        match attachment_conversation_access(&state, &auth.username, &chat_id, &media_type).await {
            Ok(access) => access,
            Err(status) => return status.into_response(),
        };
    let ttl_ms = effective_attachment_ttl_sec(
        query.ttl_sec,
        &access,
        &media_type,
        state.attachment_max_lifetime_sec,
    );
    let retention_expires_at_ms =
        (ttl_ms > 0).then(|| now_ms().saturating_add(ttl_ms.saturating_mul(1000)));
    let staged_expires_at_ms = Some(
        now_ms()
            .saturating_add(ATTACHMENT_STAGING_TTL_MS)
            .min(retention_expires_at_ms.unwrap_or(u64::MAX)),
    );
    let one_time = query.one_time.unwrap_or(false);
    let delete_after_download = query.delete_after_download.unwrap_or(one_time);
    let destructive = one_time || delete_after_download;
    let eligible_recipient_code_ids =
        snapshot_attachment_recipients(&state, &access, &chat_id, &auth.username, &auth.code_id)
            .await;
    if destructive && eligible_recipient_code_ids.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    prune_expired_attachments_locked(&state).await;
    let binding_key = AttachmentBindingKey::new(&auth.code_id, &chat_id, &message_id);
    let mut bindings = state.attachment_bindings.lock().await;
    let mut attachments = state.attachments.lock().await;
    let mut usage = state.attachment_bytes_by_code.lock().await;
    let used_bytes = current_attachment_bytes(&attachments);
    let account_used = usage.get(&auth.code_id).copied().unwrap_or_default();
    let used_records = attachments.len();
    let account_records = current_attachment_records_for_owner(&attachments, &auth.code_id);
    let encrypted_len = encrypted_body.len();
    if !attachment_capacity_allows(
        used_bytes,
        account_used,
        encrypted_len,
        state.attachment_ram_limit_bytes,
        state.attachment_account_limit_bytes,
    ) {
        warn!(
            "attachment_upload_rejected reason=ram_limit used={} account_used={} incoming={} limit={} account_limit={}",
            used_bytes,
            account_used,
            encrypted_len,
            state.attachment_ram_limit_bytes,
            state.attachment_account_limit_bytes,
        );
        return StatusCode::from_u16(507)
            .unwrap_or(StatusCode::SERVICE_UNAVAILABLE)
            .into_response();
    }
    if !attachment_record_capacity_allows(
        used_records,
        account_records,
        state.attachment_record_limit,
        state.attachment_account_record_limit,
    ) {
        warn!(
            "attachment_upload_rejected reason=record_limit used={} account_used={} limit={} account_limit={}",
            used_records,
            account_records,
            state.attachment_record_limit,
            state.attachment_account_record_limit,
        );
        return StatusCode::from_u16(507)
            .unwrap_or(StatusCode::SERVICE_UNAVAILABLE)
            .into_response();
    }
    if let Some(existing_id) = bindings.get(&binding_key).copied() {
        let live_binding = attachments
            .get(&existing_id)
            .is_some_and(|record| binding_key.matches_record(record));
        if live_binding {
            return StatusCode::CONFLICT.into_response();
        }
        bindings.remove(&binding_key);
    }
    let id = Uuid::new_v4();
    attachments.insert(
        id,
        AttachmentRecord {
            blob: Arc::new(AttachmentBlob {
                bytes: std::mem::take(&mut encrypted_body),
                _memory_permit: Some(memory_permit),
            }),
            chat_id,
            message_id,
            media_type,
            owner_code_id: auth.code_id,
            sender_platform,
            published: false,
            staged_expires_at_ms,
            one_time,
            delete_after_download,
            expires_at_ms: retention_expires_at_ms,
            eligible_recipient_code_ids,
            download_claims: HashMap::new(),
            completed_recipient_code_ids: HashSet::new(),
        },
    );
    bindings.insert(binding_key, id);
    usage.insert(auth.code_id, account_used.saturating_add(encrypted_len));
    drop(attachments);
    drop(usage);
    touch_activity(&state).await;

    Json(serde_json::json!({
        "accepted": true,
        "attachment_id": id,
        "storage": "ram-only"
    }))
    .into_response()
}

pub(super) async fn download_attachment(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = match auth_from_headers(&state, &headers).await {
        Ok(auth) => auth,
        Err(status) => return status.into_response(),
    };
    let _conversation_guard = state.conversation_ops.lock().await;
    let download_permit = match acquire_attachment_download_permit(&state.attachment_downloads) {
        Ok(permit) => permit,
        Err(status) => return status.into_response(),
    };

    let chat_id = {
        let attachments = state.attachments.lock().await;
        let Some(record) = attachments.get(&id) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        if !record.published {
            return StatusCode::NOT_FOUND.into_response();
        }
        record.chat_id.clone()
    };
    if conversation_access(&state, &auth.username, &chat_id)
        .await
        .is_none()
    {
        return StatusCode::FORBIDDEN.into_response();
    }

    let reservation = match reserve_attachment_download(&state, id, &auth.code_id).await {
        Ok(reservation) => reservation,
        Err(status) => return status.into_response(),
    };
    info!(
        "attachment_downloaded bytes={}",
        reservation.blob.bytes.len()
    );
    touch_activity(&state).await;

    attachment_download_response_with_epoch(
        Arc::clone(&reservation.blob),
        download_permit,
        reservation.claim_id,
        Arc::clone(&state.attachment_epoch),
        reservation.epoch,
        ATTACHMENT_DOWNLOAD_STALL_TIMEOUT,
    )
}

pub(super) fn attachment_claim_id(headers: &HeaderMap) -> Result<Uuid, StatusCode> {
    headers
        .get(ATTACHMENT_CLAIM_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value.trim()).ok())
        .ok_or(StatusCode::BAD_REQUEST)
}

pub(super) async fn complete_attachment_claim(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> StatusCode {
    let auth = match auth_from_headers(&state, &headers).await {
        Ok(auth) => auth,
        Err(status) => return status,
    };
    let claim_id = match attachment_claim_id(&headers) {
        Ok(claim_id) => claim_id,
        Err(status) => return status,
    };
    let _conversation_guard = state.conversation_ops.lock().await;
    match complete_attachment_download_claim(&state, id, &auth.code_id, claim_id).await {
        Ok(()) => {
            touch_activity(&state).await;
            StatusCode::NO_CONTENT
        }
        Err(status) => status,
    }
}

pub(super) async fn release_attachment_claim(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> StatusCode {
    let auth = match auth_from_headers(&state, &headers).await {
        Ok(auth) => auth,
        Err(status) => return status,
    };
    let claim_id = match attachment_claim_id(&headers) {
        Ok(claim_id) => claim_id,
        Err(status) => return status,
    };
    let _conversation_guard = state.conversation_ops.lock().await;
    match release_attachment_download_claim(&state, id, &auth.code_id, claim_id).await {
        Ok(()) => {
            touch_activity(&state).await;
            StatusCode::NO_CONTENT
        }
        Err(status) => status,
    }
}

pub(super) async fn delete_attachment(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> StatusCode {
    let auth = match auth_from_headers(&state, &headers).await {
        Ok(auth) => auth,
        Err(status) => return status,
    };
    let _conversation_guard = state.conversation_ops.lock().await;
    let status = delete_owned_attachment(&state, id, &auth.code_id).await;
    if status == StatusCode::NO_CONTENT {
        touch_activity(&state).await;
    }
    status
}

pub(super) async fn delete_owned_attachment(
    state: &AppState,
    id: Uuid,
    owner_code_id: &CodeId,
) -> StatusCode {
    let mut bindings = state.attachment_bindings.lock().await;
    let mut attachments = state.attachments.lock().await;
    let Some(record) = attachments.get(&id) else {
        return StatusCode::NOT_FOUND;
    };
    if record.owner_code_id != *owner_code_id {
        return StatusCode::FORBIDDEN;
    }
    let Some(record) = attachments.remove(&id) else {
        return StatusCode::NOT_FOUND;
    };
    remove_attachment_binding_if_matches(&mut bindings, id, &record);

    let mut usage = state.attachment_bytes_by_code.lock().await;
    subtract_attachment_usage(&mut usage, &record.owner_code_id, record.blob.bytes.len());
    StatusCode::NO_CONTENT
}
