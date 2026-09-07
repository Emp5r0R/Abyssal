use super::*;

async fn upload_state() -> AppState {
    let state = test_state();
    add_test_account(&state, "v2-upload-owner", "Alice").await;
    let owner = test_code_id("v2-upload-owner");
    state.room_catalog.lock().await.insert(
        "upload_room".to_string(),
        RoomEntry {
            room: test_room("upload_room"),
            owner_code_id: owner,
        },
    );
    state.sessions.lock().await.insert(
        SessionToken::new("v2-token".to_string()),
        AuthSession {
            code_id: owner,
            username: "Alice".to_string(),
            last_activity_ms: now_ms(),
        },
    );
    state
}

fn envelope(ciphertext: &[u8]) -> Vec<u8> {
    let json = br#"{"chat_id":"upload_room","message_id":"upload-message","media_type":"FILE","one_time":false,"delete_after_download":false,"ttl_sec":60}"#;
    let mut body = vec![0; 1024];
    body[..8].copy_from_slice(b"ABYUP001");
    body[8..10].copy_from_slice(&(json.len() as u16).to_be_bytes());
    body[10..10 + json.len()].copy_from_slice(json);
    body.extend_from_slice(ciphertext);
    body
}

fn request(body: Body, length: usize) -> Request {
    Request::builder()
        .method("POST")
        .uri("/v2/attachment")
        .header(header::AUTHORIZATION, "Bearer v2-token")
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, length)
        .body(body)
        .unwrap()
}

#[tokio::test]
async fn http_admission_rejects_before_reading_metadata_or_ciphertext() {
    let state = upload_state().await;
    for (case, status) in [
        ("query", StatusCode::BAD_REQUEST),
        ("content-type", StatusCode::BAD_REQUEST),
        ("auth", StatusCode::UNAUTHORIZED),
        ("length", StatusCode::LENGTH_REQUIRED),
        ("short", StatusCode::BAD_REQUEST),
        ("large", StatusCode::PAYLOAD_TOO_LARGE),
        ("busy", StatusCode::TOO_MANY_REQUESTS),
    ] {
        let polls = Arc::new(AtomicUsize::new(0));
        let body = Body::from_stream(futures_util::stream::once({
            let polls = Arc::clone(&polls);
            async move {
                polls.fetch_add(1, Ordering::Relaxed);
                Ok::<_, Infallible>(Bytes::from_static(b"unexpected"))
            }
        }));
        let mut request = request(body, 2048);
        let mut held = None;
        match case {
            "query" => *request.uri_mut() = "/v2/attachment?chat_id=secret".parse().unwrap(),
            "content-type" => {
                request.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
            }
            "auth" => {
                request.headers_mut().remove(header::AUTHORIZATION);
            }
            "length" => {
                request.headers_mut().remove(header::CONTENT_LENGTH);
            }
            "short" => {
                request
                    .headers_mut()
                    .insert(header::CONTENT_LENGTH, HeaderValue::from_static("1024"));
            }
            "large" => {
                request
                    .headers_mut()
                    .insert(header::CONTENT_LENGTH, HeaderValue::from(usize::MAX));
            }
            "busy" => {
                held = Some(
                    state
                        .attachment_uploads
                        .clone()
                        .try_acquire_many_owned(state.attachment_uploads.available_permits() as u32)
                        .unwrap(),
                );
            }
            _ => unreachable!(),
        }
        let response = attachment_upload::upload_attachment_v2(State(state.clone()), request).await;
        assert_eq!(response.status(), status, "{case}");
        assert_eq!(polls.load(Ordering::Relaxed), 0, "{case}");
        drop(held);
    }
    assert!(state.attachments.lock().await.is_empty());
}

#[tokio::test]
async fn framed_upload_stages_only_ciphertext_and_preserves_quotas() {
    let state = upload_state().await;
    let upload_capacity = state.attachment_uploads.available_permits();
    let ciphertext = test_valid_encrypted_attachment_body(1);
    let body = envelope(&ciphertext);
    let response = attachment_upload::upload_attachment_v2(
        State(state.clone()),
        request(Body::from(body.clone()), body.len()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    {
        let records = state.attachments.lock().await;
        assert_eq!(records.len(), 1);
        let record = records.values().next().unwrap();
        assert_eq!(record.blob.bytes.as_slice(), ciphertext.as_slice());
        assert_eq!(record.chat_id, "upload_room");
        assert_eq!(record.message_id, "upload-message");
        assert!(!record.published);
    }
    assert_eq!(
        state
            .attachment_bytes_by_code
            .lock()
            .await
            .get(&test_code_id("v2-upload-owner")),
        Some(&ciphertext.len())
    );
    let response = attachment_upload::upload_attachment_v2(
        State(state.clone()),
        request(Body::from(body.clone()), body.len()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(state.attachments.lock().await.len(), 1);
    assert_eq!(
        state.attachment_uploads.available_permits(),
        upload_capacity
    );
}

#[tokio::test]
async fn malformed_prefix_and_wrong_length_leave_no_records_or_permits() {
    let state = upload_state().await;
    let upload_capacity = state.attachment_uploads.available_permits();
    let ciphertext = test_valid_encrypted_attachment_body(1);
    for case in ["magic", "padding", "length", "truncated"] {
        let mut body = envelope(&ciphertext);
        let mut length = body.len();
        match case {
            "magic" => body[0] = 0,
            "padding" => body[1023] = 1,
            "length" => length += 1,
            "truncated" => body.truncate(100),
            _ => unreachable!(),
        }
        let response = attachment_upload::upload_attachment_v2(
            State(state.clone()),
            request(Body::from(body), length),
        )
        .await;
        assert!(!response.status().is_success(), "{case}");
        assert!(state.attachments.lock().await.is_empty());
        assert!(state.attachment_bindings.lock().await.is_empty());
        assert_eq!(
            state.attachment_uploads.available_permits(),
            upload_capacity
        );
        assert_eq!(state.attachment_memory.available_permits(), 8 * 1024 * 1024);
    }
}

#[tokio::test]
async fn logout_or_wipe_during_prefix_read_prevents_ciphertext_reads() {
    for wipe in [false, true] {
        let state = upload_state().await;
        let capacity = state.attachment_uploads.available_permits();
        let polls = Arc::new(AtomicUsize::new(0));
        let prefix = futures_util::stream::once({
            let state = state.clone();
            async move {
                if wipe {
                    state.attachment_epoch.fetch_add(1, Ordering::AcqRel);
                } else {
                    state.sessions.lock().await.clear();
                }
                Ok::<_, Infallible>(Bytes::from(envelope(&[])))
            }
        });
        let ciphertext = futures_util::stream::once({
            let polls = polls.clone();
            async move {
                polls.fetch_add(1, Ordering::Relaxed);
                Ok::<_, Infallible>(Bytes::from_static(b"unread"))
            }
        });
        let response = attachment_upload::upload_attachment_v2(
            State(state.clone()),
            request(Body::from_stream(prefix.chain(ciphertext)), 1030),
        )
        .await;
        assert_eq!(
            response.status(),
            if wipe {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::UNAUTHORIZED
            }
        );
        assert_eq!(polls.load(Ordering::Relaxed), 0);
        assert!(state.attachments.lock().await.is_empty());
        assert_eq!(state.attachment_uploads.available_permits(), capacity);
    }
}

#[tokio::test]
async fn cancelling_a_prefix_reader_releases_account_and_global_slots() {
    let state = upload_state().await;
    let capacity = state.attachment_uploads.available_permits();
    let (ready, polled) = oneshot::channel();
    let body = Body::from_stream(futures_util::stream::once(async move {
        let _ = ready.send(());
        std::future::pending::<Result<Bytes, Infallible>>().await
    }));
    let task = tokio::spawn(attachment_upload::upload_attachment_v2(
        State(state.clone()),
        request(body, 2048),
    ));
    tokio::time::timeout(Duration::from_secs(1), polled)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state.attachment_uploads.available_permits(), capacity - 1);
    assert!(
        acquire_account_attachment_upload_permit(&state, &test_code_id("v2-upload-owner"))
            .await
            .is_err()
    );
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(state.attachment_uploads.available_permits(), capacity);
    assert!(
        acquire_account_attachment_upload_permit(&state, &test_code_id("v2-upload-owner"))
            .await
            .is_ok()
    );
    assert!(state.attachments.lock().await.is_empty());
}
