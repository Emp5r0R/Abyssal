//! Attachment-v3 policy and lifecycle actions.

use super::*;
use abyssal_core::secure_protocol::ATTACHMENT_BLOB_VERSION;
use abyssal_transport::{
    attachment_bucket_frame_count, attachment_data_frame_count, AttachmentAction,
    AttachmentMediaType, AttachmentResult,
};

pub(super) struct UploadAdmission {
    action: AttachmentAction,
    pub(super) expected_digest: [u8; 32],
    pub(super) ciphertext_len: usize,
    pub(super) epoch: u64,
    memory_permit: OwnedSemaphorePermit,
    _account_permit: OwnedSemaphorePermit,
    _global_permit: OwnedSemaphorePermit,
}

pub(super) struct DownloadExecution {
    pub(super) result: AttachmentResult,
    pub(super) blob: Arc<AttachmentBlob>,
    pub(super) permit: OwnedSemaphorePermit,
    pub(super) epoch: u64,
}

pub(super) async fn admit_upload(
    state: &AppState,
    token: &str,
    auth: &AuthSession,
    action: AttachmentAction,
    expected_epoch: u64,
) -> Result<UploadAdmission, ()> {
    if state.attachment_epoch.load(Ordering::Acquire) != expected_epoch {
        return Err(());
    }
    if active_session(state, token, false)
        .await
        .is_none_or(|current| current.code_id != auth.code_id)
    {
        return Err(());
    }
    let AttachmentAction::BeginUpload {
        ref chat_id,
        ref message_id,
        media_type,
        cipher_version,
        ciphertext_len,
        ciphertext_sha256,
        ..
    } = &action
    else {
        return Err(());
    };
    if *cipher_version != ATTACHMENT_BLOB_VERSION
        || !valid_chat_id(chat_id)
        || !valid_chat_id(message_id)
    {
        return Err(());
    }
    let media_type = media_type_name(*media_type);
    let ciphertext_len = usize::try_from(*ciphertext_len).map_err(|_| ())?;
    if ciphertext_len == 0 || ciphertext_len > encrypted_attachment_limit_bytes(media_type) {
        return Err(());
    }
    attachment_conversation_access(state, &auth.username, chat_id, media_type)
        .await
        .map_err(|_| ())?;
    if !attachment_record_capacity_available(state, &auth.code_id).await {
        return Err(());
    }
    let account_permit = acquire_account_attachment_upload_permit(state, &auth.code_id)
        .await
        .map_err(|_| ())?;
    let global_permit =
        acquire_attachment_upload_permit(&state.attachment_uploads).map_err(|_| ())?;
    let memory_permit = acquire_attachment_memory_permit(&state.attachment_memory, ciphertext_len)
        .map_err(|_| ())?;
    Ok(UploadAdmission {
        expected_digest: *ciphertext_sha256,
        ciphertext_len,
        epoch: expected_epoch,
        action,
        memory_permit,
        _account_permit: account_permit,
        _global_permit: global_permit,
    })
}

pub(super) async fn commit_upload(
    state: &AppState,
    token: &str,
    initial_auth: &AuthSession,
    admission: UploadAdmission,
    ciphertext: Zeroizing<Vec<u8>>,
) -> Result<AttachmentResult, ()> {
    let UploadAdmission {
        action,
        epoch,
        memory_permit,
        ..
    } = admission;
    let AttachmentAction::BeginUpload {
        ref chat_id,
        ref message_id,
        media_type,
        one_time,
        delete_after_download,
        requested_ttl_sec,
        ..
    } = action
    else {
        return Err(());
    };
    let media_type = media_type_name(media_type).to_string();
    if !valid_encrypted_attachment_body(&media_type, &ciphertext) {
        return Err(());
    }
    let _account_guard = state.account_ops.lock().await;
    let _conversation_guard = state.conversation_ops.lock().await;
    if state.attachment_epoch.load(Ordering::Acquire) != epoch {
        return Err(());
    }
    let auth = active_session(state, token, false).await.ok_or(())?;
    if auth.code_id != initial_auth.code_id {
        return Err(());
    }
    let sender_platform = state
        .accounts
        .lock()
        .await
        .get(&auth.code_id)
        .and_then(|account| account.client_platform)
        .ok_or(())?;
    let access = attachment_conversation_access(state, &auth.username, chat_id, &media_type)
        .await
        .map_err(|_| ())?;
    let eligible_recipient_code_ids =
        snapshot_attachment_recipients(state, &access, chat_id, &auth.username, &auth.code_id)
            .await;
    if (one_time || delete_after_download) && eligible_recipient_code_ids.is_empty() {
        return Err(());
    }
    let ttl_sec = effective_attachment_ttl_sec(
        Some(u64::from(requested_ttl_sec)),
        &access,
        &media_type,
        state.attachment_max_lifetime_sec,
    );
    let expires_at_ms = now_ms().saturating_add(ttl_sec.saturating_mul(1000));
    let staged_expires_at_ms = Some(
        now_ms()
            .saturating_add(ATTACHMENT_STAGING_TTL_MS)
            .min(expires_at_ms),
    );
    prune_expired_attachments_locked(state).await;
    let key = AttachmentBindingKey::new(&auth.code_id, chat_id, message_id);
    let mut bindings = state.attachment_bindings.lock().await;
    let mut attachments = state.attachments.lock().await;
    let mut usage = state.attachment_bytes_by_code.lock().await;
    let account_used = usage.get(&auth.code_id).copied().unwrap_or_default();
    if !attachment_capacity_allows(
        current_attachment_bytes(&attachments),
        account_used,
        ciphertext.len(),
        state.attachment_ram_limit_bytes,
        state.attachment_account_limit_bytes,
    ) || !attachment_record_capacity_allows(
        attachments.len(),
        current_attachment_records_for_owner(&attachments, &auth.code_id),
        state.attachment_record_limit,
        state.attachment_account_record_limit,
    ) {
        return Err(());
    }
    if let Some(existing) = bindings.get(&key).copied() {
        if attachments
            .get(&existing)
            .is_some_and(|record| key.matches_record(record))
        {
            return Err(());
        }
        bindings.remove(&key);
    }
    let attachment_id = Uuid::new_v4();
    let encrypted_len = ciphertext.len();
    attachments.insert(
        attachment_id,
        AttachmentRecord {
            blob: Arc::new(AttachmentBlob {
                bytes: ciphertext,
                _memory_permit: Some(memory_permit),
            }),
            chat_id: chat_id.to_string(),
            message_id: message_id.to_string(),
            media_type,
            owner_code_id: auth.code_id,
            sender_platform,
            published: false,
            staged_expires_at_ms,
            one_time,
            delete_after_download,
            expires_at_ms: Some(expires_at_ms),
            eligible_recipient_code_ids,
            download_claims: HashMap::new(),
            completed_recipient_code_ids: HashSet::new(),
        },
    );
    bindings.insert(key, attachment_id);
    usage.insert(auth.code_id, account_used.saturating_add(encrypted_len));
    drop(usage);
    drop(attachments);
    drop(bindings);
    touch_activity(state).await;
    Ok(AttachmentResult::UploadAccepted {
        attachment_id: *attachment_id.as_bytes(),
    })
}

pub(super) async fn begin_download(
    state: &AppState,
    token: &str,
    auth: &AuthSession,
    attachment_id: [u8; 16],
    expected_epoch: u64,
) -> Result<DownloadExecution, ()> {
    if active_session(state, token, false)
        .await
        .is_none_or(|current| current.code_id != auth.code_id)
    {
        return Err(());
    }
    let attachment_id = Uuid::from_bytes(attachment_id);
    let reservation = {
        let _account_guard = state.account_ops.lock().await;
        let _conversation_guard = state.conversation_ops.lock().await;
        if state.attachment_epoch.load(Ordering::Acquire) != expected_epoch {
            return Err(());
        }
        let chat_id = state
            .attachments
            .lock()
            .await
            .get(&attachment_id)
            .filter(|record| record.published)
            .map(|record| record.chat_id.clone())
            .ok_or(())?;
        if conversation_access(state, &auth.username, &chat_id)
            .await
            .is_none()
        {
            return Err(());
        }
        if state.attachment_epoch.load(Ordering::Acquire) != expected_epoch
            || active_session(state, token, false)
                .await
                .is_none_or(|current| current.code_id != auth.code_id)
        {
            return Err(());
        }
        let permit =
            acquire_attachment_download_permit(&state.attachment_downloads).map_err(|_| ())?;
        reserve_attachment_download_retryable(state, attachment_id, &auth.code_id)
            .await
            .map_err(|_| ())
            .map(|reservation| (reservation, permit))?
    };
    let (reservation, permit) = reservation;
    let ciphertext_len = reservation.blob.bytes.len() as u64;
    let data_frame_count = attachment_data_frame_count(ciphertext_len).map_err(|_| ())?;
    let bucket_frame_count = attachment_bucket_frame_count(data_frame_count).map_err(|_| ())?;
    // Hashing a large blob is intentionally outside the lifecycle locks. The
    // Arc-held blob remains immutable even if a concurrent cleanup removes its
    // attachment record.
    let ciphertext_sha256 = Sha256::digest(reservation.blob.bytes.as_slice()).into();
    if state.attachment_epoch.load(Ordering::Acquire) != expected_epoch
        || active_session(state, token, false)
            .await
            .is_none_or(|current| current.code_id != auth.code_id)
    {
        if let Some(claim_id) = reservation.claim_id {
            let _ =
                release_attachment_download_claim(state, attachment_id, &auth.code_id, claim_id)
                    .await;
        }
        drop(permit);
        return Err(());
    }
    touch_activity(state).await;
    Ok(DownloadExecution {
        result: AttachmentResult::DownloadAccepted {
            claim_id: reservation.claim_id.map(|id| *id.as_bytes()),
            ciphertext_len,
            ciphertext_sha256,
            data_frame_count,
            bucket_frame_count,
        },
        blob: reservation.blob,
        permit,
        epoch: reservation.epoch,
    })
}

pub(super) async fn execute_command(
    state: &AppState,
    token: &str,
    auth: &AuthSession,
    action: AttachmentAction,
    expected_epoch: u64,
) -> AttachmentResult {
    let _account_guard = state.account_ops.lock().await;
    let _conversation_guard = state.conversation_ops.lock().await;
    if state.attachment_epoch.load(Ordering::Acquire) != expected_epoch
        || active_session(state, token, false)
            .await
            .is_none_or(|current| current.code_id != auth.code_id)
    {
        return AttachmentResult::Failure;
    }
    let status = match action {
        AttachmentAction::CompleteDownload {
            attachment_id,
            claim_id: Some(claim_id),
        } => {
            complete_attachment_download_claim(
                state,
                Uuid::from_bytes(attachment_id),
                &auth.code_id,
                Uuid::from_bytes(claim_id),
            )
            .await
        }
        AttachmentAction::ReleaseDownload {
            attachment_id,
            claim_id: Some(claim_id),
        } => {
            release_attachment_download_claim(
                state,
                Uuid::from_bytes(attachment_id),
                &auth.code_id,
                Uuid::from_bytes(claim_id),
            )
            .await
        }
        AttachmentAction::DeleteAttachment { attachment_id } => {
            let status =
                delete_owned_attachment(state, Uuid::from_bytes(attachment_id), &auth.code_id)
                    .await;
            if matches!(status, StatusCode::NO_CONTENT | StatusCode::NOT_FOUND) {
                Ok(())
            } else {
                Err(status)
            }
        }
        AttachmentAction::CompleteDownload { .. } | AttachmentAction::ReleaseDownload { .. } => {
            Err(StatusCode::BAD_REQUEST)
        }
        AttachmentAction::BeginUpload { .. } | AttachmentAction::BeginDownload { .. } => {
            Err(StatusCode::BAD_REQUEST)
        }
    };
    if status.is_ok() {
        touch_activity(state).await;
        AttachmentResult::Success
    } else {
        AttachmentResult::Failure
    }
}

fn media_type_name(media_type: AttachmentMediaType) -> &'static str {
    match media_type {
        AttachmentMediaType::Image => "IMAGE",
        AttachmentMediaType::Video => "VIDEO",
        AttachmentMediaType::File => "FILE",
    }
}
