use super::*;
use ed25519_dalek::{Signer, SigningKey};

#[test]
fn healthcheck_accepts_only_a_successful_json_health_response() {
    assert!(healthcheck_response_is_healthy(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true,\"storage\":\"ram-only\"}"
        ));
    assert!(!healthcheck_response_is_healthy(
        b"HTTP/1.1 503 Service Unavailable\r\n\r\n{\"ok\":false}"
    ));
    assert!(!healthcheck_response_is_healthy(
        b"HTTP/1.1 200 OK\r\n\r\n{\"storage\":\"ram-only\"}"
    ));
}

#[test]
fn content_security_policy_allows_wasm_without_javascript_eval() {
    assert!(CONTENT_SECURITY_POLICY.contains("script-src 'self' 'wasm-unsafe-eval'"));
    assert!(!CONTENT_SECURITY_POLICY.contains("'unsafe-eval'"));
    assert!(CONTENT_SECURITY_POLICY.contains("connect-src 'self' https: wss:"));
    assert!(CONTENT_SECURITY_POLICY.contains("http://127.0.0.1:*"));
    assert!(CONTENT_SECURITY_POLICY.contains("ws://localhost:*"));
    assert!(!CONTENT_SECURITY_POLICY.contains(" wss: http: ws:;"));
}

#[test]
fn cache_policy_forbids_storage_and_edge_transformation() {
    let directives = CACHE_CONTROL_POLICY.split(", ").collect::<HashSet<_>>();
    assert!(directives.contains("no-store"));
    assert!(directives.contains("no-cache"));
    assert!(directives.contains("no-transform"));
    assert!(directives.contains("max-age=0"));
    assert!(directives.contains("must-revalidate"));
    assert!(!directives.contains("public"));
}

#[test]
fn attachment_limits_budget_fixed_authenticated_chunks() {
    let image_limit = max_serialized_attachment_bytes("IMAGE");
    let video_limit = max_serialized_attachment_bytes("VIDEO");
    let file_limit = max_serialized_attachment_bytes("FILE");
    assert_eq!(
        image_limit,
        attachment_encrypted_size("IMAGE".to_string(), IMAGE_ATTACHMENT_LIMIT_BYTES as u64)
            .expect("image wire limit") as usize
    );
    assert_eq!(
        video_limit,
        attachment_encrypted_size("VIDEO".to_string(), VIDEO_ATTACHMENT_LIMIT_BYTES as u64)
            .expect("video wire limit") as usize
    );
    assert_eq!(
        file_limit,
        attachment_encrypted_size("FILE".to_string(), FILE_ATTACHMENT_LIMIT_BYTES as u64)
            .expect("file wire limit") as usize
    );
    assert!(file_limit > FILE_ATTACHMENT_LIMIT_BYTES);
}

#[test]
fn generated_codes_are_at_least_minimum_length() {
    let mut rng = OsRng;
    for len in 12..=20 {
        let code = generate_code(&mut rng, len);
        assert_eq!(len, code.len());
        assert!(valid_code_shape(&code));
    }
}

#[test]
fn generated_code_lengths_are_unique() {
    let mut codes = HashSet::new();
    let mut lengths = HashSet::new();
    generate_codes(&mut codes, &mut lengths, 11, 12, 24);

    let unique_lengths = codes.iter().map(|code| code.len()).collect::<HashSet<_>>();
    assert_eq!(codes.len(), unique_lengths.len());
}

#[test]
fn boot_code_writer_flushes_only_the_one_time_startup_output() {
    let codes = vec!["ABCD-12345678".to_string(), "XYZ-123456789".to_string()];
    let mut output = Vec::new();
    write_boot_codes(&mut output, &codes).expect("startup output writes");
    let output = String::from_utf8(output).expect("startup output is utf8");
    assert!(output.starts_with("ABYSSAL RAM-ONLY ACCESS CODES"));
    assert!(output.contains("ABYSSAL_CODE code=ABCD-12345678"));
    assert!(output.contains("ABYSSAL_CODE code=XYZ-123456789"));
}

#[test]
fn invite_code_ids_are_keyed_and_do_not_embed_plaintext() {
    let code = "ABYS-PRIVATE-0001";
    let first = derive_code_id(&[1_u8; 32], code);
    let repeated = derive_code_id(&[1_u8; 32], code);
    let different_process = derive_code_id(&[2_u8; 32], code);

    assert_eq!(first, repeated);
    assert_ne!(first, different_process);
    assert!(!first
        .windows(code.len())
        .any(|window| window == code.as_bytes()));
}

#[test]
fn code_parser_accepts_variable_lengths() {
    assert!(valid_code_shape("ABCD-1234-WXYZ"));
    assert!(valid_code_shape("ABC-12345678"));
    assert!(!valid_code_shape("SHORT-1"));
    assert!(!valid_code_shape("-ABCD12345678"));
    assert!(!valid_code_shape("ABCD12345678-"));
    assert!(!valid_code_shape("ABCD_12345678"));
    assert!(!valid_code_shape(&"A".repeat(MAX_CODE_BYTES + 1)));
}

#[test]
fn directory_node_ids_match_the_client_protocol_boundary() {
    assert!(valid_node_id("abyssal-node_1:primary"));
    assert!(!valid_node_id(""));
    assert!(!valid_node_id("node with spaces"));
    assert!(!valid_node_id(&"n".repeat(MAX_NODE_ID_BYTES + 1)));
}

#[test]
fn rate_windows_enforce_limit_and_reset_at_boundary() {
    let mut state = RateState {
        window_start_ms: 1_000,
        count: 0,
        bytes: 99,
    };
    assert!(record_rate_attempt(&mut state, 1_001, 100, 2));
    assert!(record_rate_attempt(&mut state, 1_002, 100, 2));
    assert!(!record_rate_attempt(&mut state, 1_003, 100, 2));
    assert!(record_rate_attempt(&mut state, 1_100, 100, 2));
    assert_eq!(state.count, 1);
    assert_eq!(state.bytes, 0);
}

#[tokio::test]
async fn login_limiter_prunes_stale_entries_and_fails_closed_at_capacity() {
    let state = test_state();
    let now = now_ms();
    let oldest = test_code_id(&format!("login-code-{}", MAX_LOGIN_LIMIT_ENTRIES - 1));
    {
        let mut limits = state.login_limits.lock().await;
        for index in 0..MAX_LOGIN_LIMIT_ENTRIES {
            let code_id = test_code_id(&format!("login-code-{index}"));
            limits.insert(
                code_id,
                RateState {
                    window_start_ms: now.saturating_sub(index as u64),
                    count: 1,
                    bytes: 0,
                },
            );
        }
        limits.insert(
            test_code_id("stale-login-code"),
            RateState {
                window_start_ms: now.saturating_sub(LOGIN_RATE_WINDOW_MS + 1),
                count: 1,
                bytes: 0,
            },
        );
    }

    let fresh = test_code_id("fresh-login-code");
    assert!(!login_attempt_allowed(&state, &fresh).await);
    let limits = state.login_limits.lock().await;
    assert_eq!(limits.len(), MAX_LOGIN_LIMIT_ENTRIES);
    assert!(limits.contains_key(&oldest));
    assert!(!limits.contains_key(&test_code_id("stale-login-code")));
    assert!(!limits.contains_key(&fresh));
}

#[tokio::test]
async fn unknown_code_flood_cannot_consume_known_code_limiter_capacity() {
    let state = test_state();
    let known = test_code_id("known-invite-code");
    state.available_codes.lock().await.insert(known);

    for index in 0..(MAX_LOGIN_LIMIT_ENTRIES * 2) {
        let unknown = test_code_id(&format!("unknown-invite-{index}"));
        assert!(!known_code_id(&state, &unknown).await);
        // This mirrors start_opaque_account: unknown IDs return before
        // login_attempt_allowed and therefore never allocate a slot.
    }
    assert!(state.login_limits.lock().await.is_empty());
    assert!(known_code_id(&state, &known).await);

    for _ in 0..LOGIN_MAX_ATTEMPTS_PER_WINDOW {
        assert!(login_attempt_allowed(&state, &known).await);
    }
    assert!(!login_attempt_allowed(&state, &known).await);
}

#[tokio::test]
async fn opaque_handshakes_are_bounded_in_ram() {
    let state = test_state();
    let first_id = Uuid::new_v4();
    for index in 0..MAX_OPAQUE_HANDSHAKES {
        let id = if index == 0 { first_id } else { Uuid::new_v4() };
        assert!(
            store_opaque_handshake(
                &state,
                id,
                OpaqueHandshake::Registration {
                    code_id: test_code_id("handshake"),
                    challenge: Zeroizing::new(vec![0; REGISTRATION_CHALLENGE_BYTES_V9]),
                    created_at_ms: now_ms(),
                },
            )
            .await
        );
    }
    assert!(
        !store_opaque_handshake(
            &state,
            Uuid::new_v4(),
            OpaqueHandshake::Registration {
                code_id: test_code_id("overflow-handshake"),
                challenge: Zeroizing::new(vec![0; REGISTRATION_CHALLENGE_BYTES_V9]),
                created_at_ms: now_ms(),
            },
        )
        .await
    );
    assert_eq!(
        state.opaque_handshakes.lock().await.len(),
        MAX_OPAQUE_HANDSHAKES
    );
    assert!(state.opaque_handshakes.lock().await.contains_key(&first_id));
}

#[tokio::test]
async fn global_wipe_serializes_with_opaque_start_and_clears_new_handshake() {
    let state = test_state();
    let code = "ABCD-12345678";
    let code_id = derive_code_id(&state.invite_code_pepper[..], code);
    state.available_codes.lock().await.insert(code_id);
    let opaque = abyssal_core::secure_protocol::opaque_client_start(b"correct-password".to_vec())
        .expect("opaque start");
    let request = OpaqueAccountStartRequest {
        code: code.to_string(),
        registration_request_b64: URL_SAFE_NO_PAD.encode(opaque.registration_request),
        credential_request_b64: URL_SAFE_NO_PAD.encode(opaque.credential_request),
    };

    let account_guard = state.account_ops.lock().await;
    let start_task = tokio::spawn(start_opaque_account(State(state.clone()), Json(request)));
    tokio::task::yield_now().await;
    let wipe_state = state.clone();
    let mut wipe_task = tokio::spawn(async move {
        wipe_relay_state(&wipe_state, false).await;
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut wipe_task)
            .await
            .is_err(),
        "wipe must wait for an in-flight account operation"
    );
    drop(account_guard);

    tokio::time::timeout(Duration::from_secs(2), start_task)
        .await
        .expect("opaque start should finish")
        .expect("opaque start task should not panic");
    tokio::time::timeout(Duration::from_secs(2), wipe_task)
        .await
        .expect("wipe should finish")
        .expect("wipe task should not panic");

    assert!(state.accounts.lock().await.is_empty());
    assert!(state.sessions.lock().await.is_empty());
    assert!(state.opaque_handshakes.lock().await.is_empty());
    assert!(state.available_codes.lock().await.is_empty());
}

#[tokio::test]
async fn global_wipe_serializes_with_opaque_finish_and_clears_new_account() {
    let state = test_state();
    let code = "ABCD-12345678";
    let code_id = derive_code_id(&state.invite_code_pepper[..], code);
    state.available_codes.lock().await.insert(code_id);
    let opaque = abyssal_core::secure_protocol::opaque_client_start(b"correct-password".to_vec())
        .expect("opaque start");
    let registration_response = opaque_server_registration_response(
        &state.opaque_setup,
        &opaque.registration_request,
        code.as_bytes(),
    )
    .expect("registration response");
    let registration = abyssal_core::secure_protocol::opaque_client_finish_registration(
        b"correct-password".to_vec(),
        opaque.registration_state,
        registration_response,
    )
    .expect("registration finish");
    let handshake_id = Uuid::new_v4();
    state.opaque_handshakes.lock().await.insert(
        handshake_id,
        OpaqueHandshake::Registration {
            code_id,
            challenge: Zeroizing::new(vec![0; REGISTRATION_CHALLENGE_BYTES_V9]),
            created_at_ms: now_ms(),
        },
    );
    let request = OpaqueAccountFinishRequest {
        handshake_id,
        registration_upload_b64: Some(URL_SAFE_NO_PAD.encode(registration.registration_upload)),
        credential_finalization_b64: None,
        identity_public_b64: Some(test_identity_public_b64(b'A')),
        identity_prekey_id: Some(test_prekey_id(b'A')),
        identity_envelope_b64: Some(URL_SAFE_NO_PAD.encode({
            let mut envelope = vec![0_u8; 256];
            envelope[0] = IDENTITY_ENVELOPE_VERSION;
            envelope
        })),
        identity_proof_b64: None,
    };

    let account_guard = state.account_ops.lock().await;
    let finish_task = tokio::spawn(finish_opaque_account(State(state.clone()), Json(request)));
    tokio::task::yield_now().await;
    let wipe_state = state.clone();
    let mut wipe_task = tokio::spawn(async move {
        wipe_relay_state(&wipe_state, false).await;
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut wipe_task)
            .await
            .is_err(),
        "wipe must wait for an in-flight account operation"
    );
    drop(account_guard);

    tokio::time::timeout(Duration::from_secs(2), finish_task)
        .await
        .expect("opaque finish should complete")
        .expect("opaque finish task should not panic");
    tokio::time::timeout(Duration::from_secs(2), wipe_task)
        .await
        .expect("wipe should finish")
        .expect("wipe task should not panic");

    assert!(state.accounts.lock().await.is_empty());
    assert!(state.sessions.lock().await.is_empty());
    assert!(state.opaque_handshakes.lock().await.is_empty());
    assert!(state.available_codes.lock().await.is_empty());
}

#[test]
fn attachment_capacity_enforces_global_and_per_account_limits_without_overflow() {
    assert!(attachment_capacity_allows(0, 0, 4, 10, 4));
    assert!(!attachment_capacity_allows(0, 0, 5, 10, 4));
    assert!(!attachment_capacity_allows(9, 0, 2, 10, 4));
    assert!(!attachment_capacity_allows(
        usize::MAX,
        0,
        1,
        usize::MAX,
        usize::MAX
    ));
}

#[test]
fn attachment_record_limits_are_clamped_and_account_bound() {
    assert_eq!(
        attachment_record_limits_from_values(None, None),
        (
            DEFAULT_ATTACHMENT_RECORD_LIMIT,
            DEFAULT_ATTACHMENT_ACCOUNT_RECORD_LIMIT
        )
    );
    assert_eq!(
        attachment_record_limits_from_values(Some("0"), Some("999999")),
        (MIN_ATTACHMENT_RECORD_LIMIT, MIN_ATTACHMENT_RECORD_LIMIT)
    );
    assert_eq!(
        attachment_record_limits_from_values(Some("999999"), Some("999999")),
        (MAX_ATTACHMENT_RECORD_LIMIT, MAX_ATTACHMENT_RECORD_LIMIT)
    );
    assert_eq!(
        attachment_record_limits_from_values(Some("2"), Some("3")),
        (2, 2)
    );
    assert_eq!(
        attachment_record_limits_from_values(Some("2"), None),
        (2, 2)
    );
    assert_eq!(
        attachment_record_limits_from_values(Some("-1"), Some("")),
        (
            DEFAULT_ATTACHMENT_RECORD_LIMIT,
            DEFAULT_ATTACHMENT_ACCOUNT_RECORD_LIMIT
        )
    );
    assert_eq!(
        attachment_record_limits_from_values(Some("not-a-number"), Some("also-invalid")),
        (
            DEFAULT_ATTACHMENT_RECORD_LIMIT,
            DEFAULT_ATTACHMENT_ACCOUNT_RECORD_LIMIT
        )
    );
}

#[test]
fn attachment_record_capacity_isolated_and_boundary_safe() {
    assert!(attachment_record_capacity_allows(0, 0, 1, 1));
    assert!(!attachment_record_capacity_allows(1, 1, 2, 1));
    assert!(!attachment_record_capacity_allows(0, 1, 2, 1));
    assert!(!attachment_record_capacity_allows(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        usize::MAX,
    ));
    assert!(attachment_record_capacity_allows(1, 0, 2, 1));
}

#[test]
fn attachment_content_length_must_be_positive_and_bounded() {
    let headers = HeaderMap::new();
    assert_eq!(
        declared_attachment_length(&headers, 10),
        Err(StatusCode::LENGTH_REQUIRED)
    );
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    assert_eq!(
        declared_attachment_length(&headers, 10),
        Err(StatusCode::LENGTH_REQUIRED)
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("invalid"));
    assert_eq!(
        declared_attachment_length(&headers, 10),
        Err(StatusCode::LENGTH_REQUIRED)
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("11"));
    assert_eq!(
        declared_attachment_length(&headers, 10),
        Err(StatusCode::PAYLOAD_TOO_LARGE)
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("7"));
    assert_eq!(declared_attachment_length(&headers, 10), Ok(7));
}

#[test]
fn attachment_memory_permit_is_weighted_and_released() {
    let memory = Arc::new(Semaphore::new(10));
    let permit = acquire_attachment_memory_permit(&memory, 7).expect("weighted permit");
    assert_eq!(memory.available_permits(), 3);
    assert!(acquire_attachment_memory_permit(&memory, 4).is_err());
    drop(permit);
    assert_eq!(memory.available_permits(), 10);
    let permit = acquire_attachment_memory_permit(&memory, 10).expect("full budget");
    drop(permit);
    assert_eq!(memory.available_permits(), 10);
}

#[test]
fn encrypted_attachment_body_requires_complete_ordered_v2_records() {
    assert!(!valid_encrypted_attachment_body("FILE", &[]));
    assert!(!valid_encrypted_attachment_body(
        "FILE",
        &[ATTACHMENT_BLOB_VERSION; ATTACHMENT_CHUNK_RECORD_BYTES - 1]
    ));
    assert!(!valid_encrypted_attachment_body(
        "FILE",
        &[0; ATTACHMENT_CHUNK_RECORD_BYTES]
    ));
    let valid = test_valid_encrypted_attachment_body(1);
    assert!(valid_encrypted_attachment_body("FILE", &valid));
    let mut bad_index = valid.clone();
    bad_index[4] = 1;
    assert!(!valid_encrypted_attachment_body("FILE", &bad_index));
}

#[tokio::test]
async fn staged_attachment_rebind_rejects_empty_roster_without_mutation() {
    let state = test_state();
    let owner = test_code_id("rebind-empty-owner");
    let recipient = test_code_id("rebind-empty-recipient");
    let attachment_id = Uuid::new_v4();
    {
        let mut attachments = state.attachments.lock().await;
        attachments.insert(
            attachment_id,
            AttachmentRecord {
                blob: test_attachment_blob(vec![1]),
                chat_id: "mls-rebind".to_string(),
                message_id: "application-1".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                sender_platform: ClientPlatform::Android,
                published: false,
                staged_expires_at_ms: Some(now_ms().saturating_add(60_000)),
                one_time: true,
                delete_after_download: false,
                expires_at_ms: None,
                eligible_recipient_code_ids: HashSet::from([recipient]),
                download_claims: HashMap::new(),
                completed_recipient_code_ids: HashSet::new(),
            },
        );
    }
    assert!(
        rebind_staged_attachment_recipients(&state, attachment_id, &HashSet::new())
            .await
            .is_err()
    );
    assert_eq!(
        state
            .attachments
            .lock()
            .await
            .get(&attachment_id)
            .expect("staged attachment")
            .eligible_recipient_code_ids,
        HashSet::from([recipient])
    );
}

#[tokio::test]
async fn staged_attachment_requires_a_live_deadline_for_publication() {
    let state = test_state();
    let owner = test_code_id("staged-deadline-owner");
    let now = now_ms();
    let missing_deadline = Uuid::new_v4();
    let expired_deadline = Uuid::new_v4();
    let valid_deadline = Uuid::new_v4();
    let records = [
        (missing_deadline, "missing-deadline", None, vec![1_u8, 2]),
        (
            expired_deadline,
            "expired-deadline",
            Some(now.saturating_sub(1)),
            vec![3_u8, 4],
        ),
        (
            valid_deadline,
            "valid-deadline",
            Some(now.saturating_add(60_000)),
            vec![5_u8, 6],
        ),
    ];
    {
        let mut bindings = state.attachment_bindings.lock().await;
        let mut attachments = state.attachments.lock().await;
        for (id, message_id, staged_expires_at_ms, bytes) in records {
            attachments.insert(
                id,
                AttachmentRecord {
                    blob: test_attachment_blob(bytes),
                    chat_id: "dm_staged".to_string(),
                    message_id: message_id.to_string(),
                    media_type: "FILE".to_string(),
                    owner_code_id: owner,
                    sender_platform: ClientPlatform::Android,
                    published: false,
                    staged_expires_at_ms,
                    one_time: false,
                    delete_after_download: false,
                    expires_at_ms: Some(now.saturating_add(60_000)),
                    eligible_recipient_code_ids: HashSet::new(),
                    download_claims: HashMap::new(),
                    completed_recipient_code_ids: HashSet::new(),
                },
            );
            bindings.insert(
                AttachmentBindingKey::new(&owner, "dm_staged", message_id),
                id,
            );
        }
    }
    state.attachment_bytes_by_code.lock().await.insert(owner, 6);

    prune_expired_attachments(&state).await;
    let attachments = state.attachments.lock().await;
    assert!(!attachments.contains_key(&missing_deadline));
    assert!(!attachments.contains_key(&expired_deadline));
    assert!(attachments.contains_key(&valid_deadline));
    drop(attachments);
    let bindings = state.attachment_bindings.lock().await;
    assert!(!bindings.contains_key(&AttachmentBindingKey::new(
        &owner,
        "dm_staged",
        "missing-deadline",
    )));
    assert!(!bindings.contains_key(&AttachmentBindingKey::new(
        &owner,
        "dm_staged",
        "expired-deadline",
    )));
    assert_eq!(
        bindings.get(&AttachmentBindingKey::new(
            &owner,
            "dm_staged",
            "valid-deadline",
        )),
        Some(&valid_deadline)
    );
    drop(bindings);

    assert_eq!(
        staged_attachment_for_message(&state, &owner, "dm_staged", "valid-deadline").await,
        Ok(Some(valid_deadline))
    );
    publish_staged_attachment(
        &state,
        valid_deadline,
        &owner,
        "dm_staged",
        "valid-deadline",
    )
    .await;
    let attachments = state.attachments.lock().await;
    let published = attachments
        .get(&valid_deadline)
        .expect("valid staged record");
    assert!(published.published);
    assert_eq!(published.staged_expires_at_ms, None);
    assert_eq!(
        state.attachment_bytes_by_code.lock().await.get(&owner),
        Some(&2)
    );
}

#[tokio::test]
async fn staged_message_lookup_only_expires_the_exact_indexed_record() {
    let state = test_state();
    let owner = test_code_id("staged-exact-lookup-owner");
    let exact_id = Uuid::new_v4();
    let unrelated_id = Uuid::new_v4();
    let now = now_ms();
    {
        let mut bindings = state.attachment_bindings.lock().await;
        let mut attachments = state.attachments.lock().await;
        attachments.insert(
            exact_id,
            AttachmentRecord {
                blob: Arc::new(AttachmentBlob {
                    bytes: Zeroizing::new(vec![1, 2, 3]),
                    _memory_permit: Some(
                        acquire_attachment_memory_permit(&state.attachment_memory, 3)
                            .expect("exact attachment memory permit"),
                    ),
                }),
                chat_id: "dm_exact_lookup".to_string(),
                message_id: "exact-message".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                sender_platform: ClientPlatform::Android,
                published: false,
                staged_expires_at_ms: Some(now.saturating_add(60_000)),
                one_time: false,
                delete_after_download: false,
                expires_at_ms: Some(now.saturating_add(60_000)),
                eligible_recipient_code_ids: HashSet::new(),
                download_claims: HashMap::new(),
                completed_recipient_code_ids: HashSet::new(),
            },
        );
        attachments.insert(
            unrelated_id,
            AttachmentRecord {
                blob: test_attachment_blob(vec![4, 5, 6]),
                chat_id: "dm_exact_lookup".to_string(),
                message_id: "unrelated-message".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                sender_platform: ClientPlatform::Android,
                published: false,
                staged_expires_at_ms: Some(now.saturating_sub(1)),
                one_time: false,
                delete_after_download: false,
                expires_at_ms: Some(now.saturating_add(60_000)),
                eligible_recipient_code_ids: HashSet::new(),
                download_claims: HashMap::new(),
                completed_recipient_code_ids: HashSet::new(),
            },
        );
        bindings.insert(
            AttachmentBindingKey::new(&owner, "dm_exact_lookup", "exact-message"),
            exact_id,
        );
        bindings.insert(
            AttachmentBindingKey::new(&owner, "dm_exact_lookup", "unrelated-message"),
            unrelated_id,
        );
    }
    state.attachment_bytes_by_code.lock().await.insert(owner, 6);

    assert_eq!(
        staged_attachment_for_message(&state, &owner, "dm_exact_lookup", "exact-message").await,
        Ok(Some(exact_id))
    );
    assert_eq!(
        state.attachment_memory.available_permits(),
        8 * 1024 * 1024 - 3
    );
    assert!(state.attachments.lock().await.contains_key(&unrelated_id));
    assert_eq!(
        state
            .attachment_bindings
            .lock()
            .await
            .get(&AttachmentBindingKey::new(
                &owner,
                "dm_exact_lookup",
                "unrelated-message",
            )),
        Some(&unrelated_id)
    );

    state
        .attachments
        .lock()
        .await
        .get_mut(&exact_id)
        .expect("exact staged record")
        .staged_expires_at_ms = Some(now_ms().saturating_sub(1));
    assert_eq!(
        staged_attachment_for_message(&state, &owner, "dm_exact_lookup", "exact-message").await,
        Ok(None)
    );
    assert!(!state.attachments.lock().await.contains_key(&exact_id));
    assert!(state.attachments.lock().await.contains_key(&unrelated_id));
    assert_eq!(
        state
            .attachment_bindings
            .lock()
            .await
            .get(&AttachmentBindingKey::new(
                &owner,
                "dm_exact_lookup",
                "unrelated-message",
            )),
        Some(&unrelated_id)
    );
    assert_eq!(
        state.attachment_bytes_by_code.lock().await.get(&owner),
        Some(&3)
    );
    assert_eq!(state.attachment_memory.available_permits(), 8 * 1024 * 1024);
}

#[tokio::test]
async fn attachment_upload_requires_message_binding_and_rejects_live_duplicate() {
    let state = test_state();
    add_test_account(&state, "staged-upload-owner", "Alice").await;
    let owner = test_code_id("staged-upload-owner");
    let room_id = "staged_upload_room";
    state.room_catalog.lock().await.insert(
        room_id.to_string(),
        RoomEntry {
            room: test_room(room_id),
            owner_code_id: owner,
        },
    );
    state.sessions.lock().await.insert(
        SessionToken::new("staged-upload-token".to_string()),
        AuthSession {
            code_id: owner,
            username: "Alice".to_string(),
            last_activity_ms: now_ms(),
        },
    );

    let upload = |message_id: &'static str| {
        let body = test_valid_encrypted_attachment_body(1);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer staged-upload-token"),
        );
        headers.insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&body.len().to_string()).expect("content length"),
        );
        upload_attachment(
            State(state.clone()),
            Query(AttachmentQuery {
                chat_id: room_id.to_string(),
                message_id: message_id.to_string(),
                media_type: Some("FILE".to_string()),
                one_time: Some(false),
                delete_after_download: Some(false),
                ttl_sec: Some(1),
            }),
            headers,
            Body::from(body),
        )
    };

    assert_eq!(
        upload("").await.into_response().status(),
        StatusCode::BAD_REQUEST
    );
    assert!(state.attachments.lock().await.is_empty());
    assert_eq!(
        upload("staged-upload-message")
            .await
            .into_response()
            .status(),
        StatusCode::OK
    );
    let (attachment_id, original_expiry) = {
        let attachments = state.attachments.lock().await;
        let (id, record) = attachments.iter().next().expect("staged upload");
        assert!(!record.published);
        assert!(
            record.staged_expires_at_ms.expect("staging deadline")
                <= record.expires_at_ms.expect("retention deadline")
        );
        (*id, record.expires_at_ms)
    };
    assert_eq!(
        upload("staged-upload-message")
            .await
            .into_response()
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(state.attachments.lock().await.len(), 1);

    publish_staged_attachment(
        &state,
        attachment_id,
        &owner,
        room_id,
        "staged-upload-message",
    )
    .await;
    let attachments = state.attachments.lock().await;
    let published = attachments.get(&attachment_id).expect("published upload");
    assert!(published.published);
    assert_eq!(published.expires_at_ms, original_expiry);
}

#[tokio::test]
async fn staged_attachment_is_a_generic_not_found_to_owner_and_recipient() {
    let state = test_state();
    add_test_account(&state, "staged-download-owner", "Alice").await;
    add_test_account(&state, "staged-download-recipient", "Bob").await;
    let owner = test_code_id("staged-download-owner");
    let room_id = "staged_download_room";
    state.room_catalog.lock().await.insert(
        room_id.to_string(),
        RoomEntry {
            room: test_room(room_id),
            owner_code_id: owner,
        },
    );
    state.sessions.lock().await.extend([
        (
            SessionToken::new("staged-owner-token".to_string()),
            AuthSession {
                code_id: owner,
                username: "Alice".to_string(),
                last_activity_ms: now_ms(),
            },
        ),
        (
            SessionToken::new("staged-recipient-token".to_string()),
            AuthSession {
                code_id: test_code_id("staged-download-recipient"),
                username: "Bob".to_string(),
                last_activity_ms: now_ms(),
            },
        ),
    ]);
    let attachment_id = Uuid::new_v4();
    state.attachments.lock().await.insert(
        attachment_id,
        AttachmentRecord {
            blob: test_attachment_blob(test_valid_encrypted_attachment_body(1)),
            chat_id: room_id.to_string(),
            message_id: "staged-download-message".to_string(),
            media_type: "FILE".to_string(),
            owner_code_id: owner,
            sender_platform: ClientPlatform::Android,
            published: false,
            staged_expires_at_ms: Some(now_ms().saturating_add(60_000)),
            one_time: false,
            delete_after_download: false,
            expires_at_ms: Some(now_ms().saturating_add(60_000)),
            eligible_recipient_code_ids: HashSet::new(),
            download_claims: HashMap::new(),
            completed_recipient_code_ids: HashSet::new(),
        },
    );
    state.attachment_bindings.lock().await.insert(
        AttachmentBindingKey::new(&owner, room_id, "staged-download-message"),
        attachment_id,
    );

    for token in ["staged-owner-token", "staged-recipient-token"] {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).expect("test bearer"),
        );
        let response = download_attachment(State(state.clone()), Path(attachment_id), headers)
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn staged_publication_is_exactly_bound_and_rejected_or_rolled_back_admission_never_promotes()
{
    let state = test_state();
    add_test_account(&state, "publication-owner", "Alice").await;
    add_test_account(&state, "publication-other", "Bob").await;
    let (alice_id, _) = add_test_client(&state, "publication-owner", "Alice").await;
    let room_id = "staged_publication_room";
    state.room_catalog.lock().await.insert(
        room_id.to_string(),
        RoomEntry {
            room: test_room(room_id),
            owner_code_id: test_code_id("publication-owner"),
        },
    );
    let now = now_ms();
    let bindings = [
        (
            "matching",
            test_code_id("publication-owner"),
            room_id,
            "publication-message",
        ),
        (
            "wrong-owner",
            test_code_id("publication-other"),
            room_id,
            "publication-message",
        ),
        (
            "wrong-chat",
            test_code_id("publication-owner"),
            "other-publication-room",
            "publication-message",
        ),
        (
            "wrong-message",
            test_code_id("publication-owner"),
            room_id,
            "other-publication-message",
        ),
    ];
    let mut ids = HashMap::new();
    {
        let mut attachment_bindings = state.attachment_bindings.lock().await;
        let mut attachments = state.attachments.lock().await;
        for (label, owner, chat_id, message_id) in bindings {
            let id = Uuid::new_v4();
            ids.insert(label, id);
            attachments.insert(
                id,
                AttachmentRecord {
                    blob: test_attachment_blob(vec![1, 2]),
                    chat_id: chat_id.to_string(),
                    message_id: message_id.to_string(),
                    media_type: "FILE".to_string(),
                    owner_code_id: owner,
                    sender_platform: ClientPlatform::Android,
                    published: false,
                    staged_expires_at_ms: Some(now.saturating_add(60_000)),
                    one_time: false,
                    delete_after_download: false,
                    expires_at_ms: Some(now.saturating_add(60_000)),
                    eligible_recipient_code_ids: HashSet::new(),
                    download_claims: HashMap::new(),
                    completed_recipient_code_ids: HashSet::new(),
                },
            );
            attachment_bindings.insert(AttachmentBindingKey::new(&owner, chat_id, message_id), id);
        }
    }

    assert!(route_test_message_with_envelopes(
        &state,
        alice_id,
        room_id,
        E2EE_PROTOCOL_VERSION,
        "publication-message",
        Vec::new(),
    )
    .await
    .is_err());
    assert!(state
        .attachments
        .lock()
        .await
        .values()
        .all(|record| !record.published));

    state.replay_ids.lock().await.insert(
        ReplayKey {
            chat_id: room_id.to_string(),
            sender_username: "Alice".to_string(),
            message_id: "publication-message".to_string(),
        },
        now_ms(),
    );
    assert!(
        route_test_message_with_id(&state, alice_id, room_id, &["Bob"], "publication-message",)
            .await
            .is_err()
    );
    assert!(state
        .attachments
        .lock()
        .await
        .values()
        .all(|record| !record.published));
    state.replay_ids.lock().await.clear();

    route_test_message_with_id(&state, alice_id, room_id, &["Bob"], "publication-message")
        .await
        .expect("exact accepted message publishes attachment");
    let attachments = state.attachments.lock().await;
    assert!(attachments[&ids["matching"]].published);
    assert!(!attachments[&ids["wrong-owner"]].published);
    assert!(!attachments[&ids["wrong-chat"]].published);
    assert!(!attachments[&ids["wrong-message"]].published);
}

#[tokio::test]
async fn uploaded_attachment_cleanup_is_owner_only_and_releases_usage() {
    let mut state = test_state();
    state.attachment_record_limit = 1;
    state.attachment_account_record_limit = 1;
    let owner = test_code_id("cleanup-owner");
    let other = test_code_id("cleanup-other");
    let attachment_id = Uuid::new_v4();
    state.attachments.lock().await.insert(
        attachment_id,
        AttachmentRecord {
            blob: test_attachment_blob(vec![1, 2, 3, 4]),
            chat_id: "dm_cleanup".to_string(),
            message_id: "test-message".to_string(),
            media_type: "FILE".to_string(),
            owner_code_id: owner,
            sender_platform: ClientPlatform::Android,
            published: true,
            staged_expires_at_ms: None,
            one_time: false,
            delete_after_download: false,
            expires_at_ms: None,
            eligible_recipient_code_ids: HashSet::new(),
            download_claims: HashMap::new(),
            completed_recipient_code_ids: HashSet::new(),
        },
    );
    state.attachment_bindings.lock().await.insert(
        AttachmentBindingKey::new(&owner, "dm_cleanup", "test-message"),
        attachment_id,
    );
    state.attachment_bytes_by_code.lock().await.insert(owner, 4);
    {
        let attachments = state.attachments.lock().await;
        assert!(!attachment_record_capacity_allows(
            attachments.len(),
            current_attachment_records_for_owner(&attachments, &owner),
            1,
            1,
        ));
    }

    assert_eq!(
        delete_owned_attachment(&state, attachment_id, &other).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        delete_owned_attachment(&state, attachment_id, &owner).await,
        StatusCode::NO_CONTENT
    );
    assert!(!state.attachments.lock().await.contains_key(&attachment_id));
    assert!(state.attachment_bindings.lock().await.is_empty());
    assert!(state.attachment_bytes_by_code.lock().await.is_empty());
    assert!(attachment_record_capacity_available(&state, &owner).await);
}

#[tokio::test]
async fn attachment_binding_index_cleans_destructive_completion() {
    let state = test_state();
    let owner = test_code_id("binding-completion-owner");
    let recipient = test_code_id("binding-completion-recipient");
    let attachment_id = Uuid::new_v4();
    let claim_id = Uuid::new_v4();
    {
        let mut bindings = state.attachment_bindings.lock().await;
        let mut attachments = state.attachments.lock().await;
        attachments.insert(
            attachment_id,
            AttachmentRecord {
                blob: test_attachment_blob(vec![1, 2, 3]),
                chat_id: "dm_binding_completion".to_string(),
                message_id: "binding-completion-message".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                sender_platform: ClientPlatform::Android,
                published: true,
                staged_expires_at_ms: None,
                one_time: true,
                delete_after_download: true,
                expires_at_ms: None,
                eligible_recipient_code_ids: HashSet::from([recipient]),
                download_claims: HashMap::from([(
                    claim_id,
                    AttachmentDownloadClaim {
                        recipient_code_id: recipient,
                        created_at_ms: now_ms(),
                    },
                )]),
                completed_recipient_code_ids: HashSet::new(),
            },
        );
        bindings.insert(
            AttachmentBindingKey::new(
                &owner,
                "dm_binding_completion",
                "binding-completion-message",
            ),
            attachment_id,
        );
    }
    state.attachment_bytes_by_code.lock().await.insert(owner, 3);

    complete_attachment_download_claim(&state, attachment_id, &recipient, claim_id)
        .await
        .expect("destructive completion");
    assert!(!state.attachments.lock().await.contains_key(&attachment_id));
    assert!(state.attachment_bindings.lock().await.is_empty());
    assert!(state.attachment_bytes_by_code.lock().await.is_empty());
}

#[tokio::test]
async fn expired_staged_publication_removes_record_binding_and_usage() {
    let state = test_state();
    let owner = test_code_id("expired-publication-owner");
    let attachment_id = Uuid::new_v4();
    {
        let mut bindings = state.attachment_bindings.lock().await;
        let mut attachments = state.attachments.lock().await;
        attachments.insert(
            attachment_id,
            AttachmentRecord {
                blob: test_attachment_blob(vec![1, 2, 3]),
                chat_id: "dm_expired_publication".to_string(),
                message_id: "expired-publication-message".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                sender_platform: ClientPlatform::Android,
                published: false,
                staged_expires_at_ms: Some(now_ms().saturating_sub(1)),
                one_time: false,
                delete_after_download: false,
                expires_at_ms: Some(now_ms().saturating_add(60_000)),
                eligible_recipient_code_ids: HashSet::new(),
                download_claims: HashMap::new(),
                completed_recipient_code_ids: HashSet::new(),
            },
        );
        bindings.insert(
            AttachmentBindingKey::new(
                &owner,
                "dm_expired_publication",
                "expired-publication-message",
            ),
            attachment_id,
        );
    }
    state.attachment_bytes_by_code.lock().await.insert(owner, 3);

    publish_staged_attachment(
        &state,
        attachment_id,
        &owner,
        "dm_expired_publication",
        "expired-publication-message",
    )
    .await;
    assert!(!state.attachments.lock().await.contains_key(&attachment_id));
    assert!(state.attachment_bindings.lock().await.is_empty());
    assert!(state.attachment_bytes_by_code.lock().await.is_empty());
}

#[tokio::test]
async fn mismatched_attachment_binding_cannot_leave_an_orphan_record() {
    let state = test_state();
    let owner = test_code_id("mismatch-binding-owner");
    let attachment_id = Uuid::new_v4();
    {
        let mut bindings = state.attachment_bindings.lock().await;
        let mut attachments = state.attachments.lock().await;
        attachments.insert(
            attachment_id,
            AttachmentRecord {
                blob: test_attachment_blob(vec![1, 2, 3]),
                chat_id: "dm_mismatch_binding".to_string(),
                message_id: "actual-message".to_string(),
                media_type: "FILE".to_string(),
                owner_code_id: owner,
                sender_platform: ClientPlatform::Android,
                published: false,
                staged_expires_at_ms: Some(now_ms().saturating_add(60_000)),
                one_time: false,
                delete_after_download: false,
                expires_at_ms: Some(now_ms().saturating_add(60_000)),
                eligible_recipient_code_ids: HashSet::new(),
                download_claims: HashMap::new(),
                completed_recipient_code_ids: HashSet::new(),
            },
        );
        bindings.insert(
            AttachmentBindingKey::new(&owner, "dm_mismatch_binding", "indexed-message"),
            attachment_id,
        );
    }
    state.attachment_bytes_by_code.lock().await.insert(owner, 3);

    assert_eq!(
        staged_attachment_for_message(&state, &owner, "dm_mismatch_binding", "indexed-message",)
            .await,
        Ok(None)
    );
    assert!(!state.attachments.lock().await.contains_key(&attachment_id));
    assert!(state.attachment_bindings.lock().await.is_empty());
    assert!(state.attachment_bytes_by_code.lock().await.is_empty());
}

#[tokio::test]
async fn attachment_sweeper_pruning_serializes_with_message_admission() {
    let state = test_state();
    let conversation_guard = state.conversation_ops.lock().await;
    let prune_state = state.clone();
    let mut prune_task = tokio::spawn(async move {
        prune_expired_attachments(&prune_state).await;
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut prune_task)
            .await
            .is_err()
    );
    drop(conversation_guard);
    prune_task.await.expect("prune task");
}

#[tokio::test]
async fn attachment_download_permit_lives_with_response() {
    let downloads = Arc::new(Semaphore::new(1));
    let permit = acquire_attachment_download_permit(&downloads).expect("first download");
    let response = attachment_download_response(vec![1, 2, 3], permit, None);

    assert!(acquire_attachment_download_permit(&downloads).is_err());
    drop(response);
    for _ in 0..8 {
        if acquire_attachment_download_permit(&downloads).is_ok() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("download permit was not released after response drop");
}

#[tokio::test]
async fn abandoned_attachment_download_releases_buffer_and_permit_after_stall() {
    let downloads = Arc::new(Semaphore::new(1));
    let permit = acquire_attachment_download_permit(&downloads).expect("download permit");
    let bytes = vec![0xA5_u8; ATTACHMENT_DOWNLOAD_CHUNK_BYTES * 2];
    let response =
        attachment_download_response_with_timeout(bytes, permit, None, Duration::from_millis(5));
    assert!(acquire_attachment_download_permit(&downloads).is_err());
    let mut released = false;
    for _ in 0..20 {
        if let Ok(replacement) = acquire_attachment_download_permit(&downloads) {
            drop(replacement);
            released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(released, "stalled producer releases its permit");
    drop(response);
}

#[test]
fn attachment_claim_header_requires_a_uuid() {
    let mut headers = HeaderMap::new();
    assert_eq!(attachment_claim_id(&headers), Err(StatusCode::BAD_REQUEST));
    headers.insert(
        ATTACHMENT_CLAIM_HEADER,
        HeaderValue::from_static("not-a-claim"),
    );
    assert_eq!(attachment_claim_id(&headers), Err(StatusCode::BAD_REQUEST));
    let claim_id = Uuid::new_v4();
    headers.insert(
        ATTACHMENT_CLAIM_HEADER,
        HeaderValue::from_str(&claim_id.to_string()).expect("claim header"),
    );
    assert_eq!(attachment_claim_id(&headers), Ok(claim_id));
}

#[tokio::test]
async fn unauthorized_attachment_upload_does_not_poll_request_body() {
    let state = test_state();
    let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let body = Body::from_stream(futures_util::stream::once({
        let polls = Arc::clone(&polls);
        async move {
            polls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok::<Bytes, Infallible>(Bytes::from(vec![7_u8; 1024]))
        }
    }));
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer invalid"),
    );
    let response = upload_attachment(
        State(state),
        Query(AttachmentQuery {
            chat_id: "dm_unknown".to_string(),
            message_id: "test-message".to_string(),
            media_type: Some("FILE".to_string()),
            one_time: None,
            delete_after_download: None,
            ttl_sec: None,
        }),
        headers,
        body,
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(polls.load(std::sync::atomic::Ordering::Relaxed), 0);
}

#[tokio::test]
async fn revoked_session_cannot_commit_after_slow_attachment_upload() {
    let state = test_state();
    add_test_account(&state, "slow-owner", "Alice").await;
    let room = test_room("slow_upload_room");
    state.room_catalog.lock().await.insert(
        room.id.clone(),
        RoomEntry {
            room,
            owner_code_id: test_code_id("slow-owner"),
        },
    );
    state.sessions.lock().await.insert(
        SessionToken::new("slow-upload-token".to_string()),
        AuthSession {
            code_id: test_code_id("slow-owner"),
            username: "Alice".to_string(),
            last_activity_ms: now_ms(),
        },
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer slow-upload-token"),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("9"));
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let body = Body::from_stream(futures_util::stream::once(async move {
        ready_tx.send(()).expect("upload task is listening");
        release_rx.await.expect("release upload body");
        Ok::<Bytes, Infallible>(Bytes::from_static(b"encrypted"))
    }));
    let request_state = state.clone();
    let task = tokio::spawn(async move {
        upload_attachment(
            State(request_state),
            Query(AttachmentQuery {
                chat_id: "slow_upload_room".to_string(),
                message_id: "test-message".to_string(),
                media_type: Some("FILE".to_string()),
                one_time: None,
                delete_after_download: None,
                ttl_sec: None,
            }),
            headers,
            body,
        )
        .await
        .into_response()
    });
    ready_rx.await.expect("body was polled");
    state.sessions.lock().await.remove("slow-upload-token");
    release_tx.send(()).expect("release body");
    let response = task.await.expect("upload task");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(state.attachments.lock().await.is_empty());
}

#[tokio::test]
async fn global_wipe_rejects_upload_that_started_before_wipe() {
    let state = test_state();
    add_test_account(&state, "wipe-upload-owner", "Alice").await;
    let room = test_room("wipe_upload_room");
    state.room_catalog.lock().await.insert(
        room.id.clone(),
        RoomEntry {
            room,
            owner_code_id: test_code_id("wipe-upload-owner"),
        },
    );
    state.sessions.lock().await.insert(
        SessionToken::new("wipe-upload-token".to_string()),
        AuthSession {
            code_id: test_code_id("wipe-upload-owner"),
            username: "Alice".to_string(),
            last_activity_ms: now_ms(),
        },
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer wipe-upload-token"),
    );
    let body_bytes = test_valid_encrypted_attachment_body(1);
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&body_bytes.len().to_string()).expect("content length"),
    );
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let body = Body::from_stream(futures_util::stream::once(async move {
        ready_tx.send(()).expect("upload task is listening");
        release_rx.await.expect("release upload body");
        Ok::<Bytes, Infallible>(Bytes::from(body_bytes))
    }));
    let request_state = state.clone();
    let task = tokio::spawn(async move {
        upload_attachment(
            State(request_state),
            Query(AttachmentQuery {
                chat_id: "wipe_upload_room".to_string(),
                message_id: "test-message".to_string(),
                media_type: Some("FILE".to_string()),
                one_time: None,
                delete_after_download: None,
                ttl_sec: None,
            }),
            headers,
            body,
        )
        .await
        .into_response()
    });
    ready_rx.await.expect("body was polled");
    wipe_relay_state(&state, false).await;
    release_tx.send(()).expect("release body");
    let response = task.await.expect("upload task");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(state.attachments.lock().await.is_empty());
    assert_eq!(state.attachment_memory.available_permits(), 8 * 1024 * 1024);
}

#[tokio::test]
async fn global_wipe_stops_download_stream_before_first_chunk() {
    let downloads = Arc::new(Semaphore::new(1));
    let permit = acquire_attachment_download_permit(&downloads).expect("download permit");
    let bytes = test_attachment_blob(vec![0xA5_u8; ATTACHMENT_DOWNLOAD_CHUNK_BYTES]);
    let epoch = Arc::new(AtomicU64::new(0));
    let response = attachment_download_response_with_epoch(
        bytes,
        permit,
        None,
        Arc::clone(&epoch),
        0,
        Duration::from_millis(5),
    );
    tokio::time::sleep(Duration::from_millis(1)).await;
    epoch.fetch_add(1, Ordering::AcqRel);
    let mut stream = response.into_body().into_data_stream();
    assert!(stream.next().await.is_none());
    assert!(acquire_attachment_download_permit(&downloads).is_ok());
}

#[tokio::test]
async fn attachment_download_reservation_shares_owned_bytes_without_copy() {
    let state = test_state();
    let attachment_id = Uuid::new_v4();
    let owner = test_code_id("shared-owner");
    let bytes = test_attachment_blob(vec![1, 2, 3, 4]);
    state.attachments.lock().await.insert(
        attachment_id,
        AttachmentRecord {
            blob: Arc::clone(&bytes),
            chat_id: "dm_shared".to_string(),
            message_id: "test-message".to_string(),
            media_type: "FILE".to_string(),
            owner_code_id: owner,
            sender_platform: ClientPlatform::Android,
            published: true,
            staged_expires_at_ms: None,
            one_time: false,
            delete_after_download: false,
            expires_at_ms: None,
            eligible_recipient_code_ids: HashSet::new(),
            download_claims: HashMap::new(),
            completed_recipient_code_ids: HashSet::new(),
        },
    );
    let reservation = reserve_attachment_download(&state, attachment_id, &owner)
        .await
        .expect("download reservation");
    assert!(Arc::ptr_eq(&bytes, &reservation.blob));
    assert_eq!(Arc::strong_count(&bytes), 3);
}

#[tokio::test]
async fn attachment_memory_permit_lives_until_final_download_blob_reference() {
    let state = test_state();
    let attachment_id = Uuid::new_v4();
    let owner = test_code_id("blob-owner");
    let permit = acquire_attachment_memory_permit(&state.attachment_memory, 4)
        .expect("attachment memory permit");
    let blob = Arc::new(AttachmentBlob {
        bytes: Zeroizing::new(vec![1, 2, 3, 4]),
        _memory_permit: Some(permit),
    });
    state.attachments.lock().await.insert(
        attachment_id,
        AttachmentRecord {
            blob: Arc::clone(&blob),
            chat_id: "dm_blob_lifetime".to_string(),
            message_id: "test-message".to_string(),
            media_type: "FILE".to_string(),
            owner_code_id: owner,
            sender_platform: ClientPlatform::Android,
            published: true,
            staged_expires_at_ms: None,
            one_time: false,
            delete_after_download: false,
            expires_at_ms: None,
            eligible_recipient_code_ids: HashSet::new(),
            download_claims: HashMap::new(),
            completed_recipient_code_ids: HashSet::new(),
        },
    );
    drop(blob);

    let reservation = reserve_attachment_download(&state, attachment_id, &owner)
        .await
        .expect("download reservation");
    assert_eq!(
        state.attachment_memory.available_permits(),
        8 * 1024 * 1024 - 4
    );
    let download_permit =
        acquire_attachment_download_permit(&state.attachment_downloads).expect("download permit");
    let response = attachment_download_response_with_epoch(
        Arc::clone(&reservation.blob),
        download_permit,
        None,
        Arc::clone(&state.attachment_epoch),
        reservation.epoch,
        ATTACHMENT_DOWNLOAD_STALL_TIMEOUT,
    );
    assert_eq!(
        delete_owned_attachment(&state, attachment_id, &owner).await,
        StatusCode::NO_CONTENT
    );
    drop(reservation);
    assert_eq!(
        state.attachment_memory.available_permits(),
        8 * 1024 * 1024 - 4
    );

    let mut stream = response.into_body().into_data_stream();
    while stream.next().await.is_some() {}
    for _ in 0..20 {
        if state.attachment_memory.available_permits() == 8 * 1024 * 1024 {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("attachment memory permit released only after final blob reference");
}

#[tokio::test]
async fn full_data_queue_does_not_block_global_wipe_control_channel() {
    let state = test_state();
    let client_id = Uuid::new_v4();
    let (tx, rx) = mpsc::channel(CLIENT_OUTBOUND_QUEUE_CAPACITY);
    let (control_tx, mut control_rx) = mpsc::channel(CLIENT_CONTROL_QUEUE_CAPACITY);
    let (result_tx, _result_rx) = mpsc::channel(CLIENT_RESULT_QUEUE_CAPACITY);
    state.clients.lock().await.insert(
        client_id,
        ClientHandle {
            code_id: test_code_id("queue-client"),
            username: "Alice".to_string(),
            platform: ClientPlatform::Android,
            tx,
            control_tx,
            result_tx,
            queued_bytes: Arc::new(AtomicUsize::new(0)),
        },
    );
    let frame = test_message_frame("dm_queue", "queued-secret", "Alice", "", false);
    for _ in 0..CLIENT_OUTBOUND_QUEUE_CAPACITY {
        send_to_client(&state, client_id, &frame).await;
    }
    assert_eq!(rx.len(), CLIENT_OUTBOUND_QUEUE_CAPACITY);

    send_control_to_client(&state, client_id, ClientControl::GlobalWipe).await;
    assert!(matches!(
        control_rx.try_recv(),
        Ok(ClientControl::GlobalWipe)
    ));
    drop(rx);
    assert!(control_rx.try_recv().is_err());
}

#[tokio::test]
async fn bounded_attachment_body_rejects_overflow_empty_and_truncation() {
    assert_eq!(
        read_bounded_attachment_body(Body::from(vec![1_u8, 2, 3]), 2, None)
            .await
            .expect_err("body exceeds limit"),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        read_bounded_attachment_body(Body::from(Vec::<u8>::new()), 2, None)
            .await
            .expect_err("empty body"),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        read_bounded_attachment_body(Body::from(vec![1_u8, 2]), 4, Some(3))
            .await
            .expect_err("truncated declared body"),
        StatusCode::BAD_REQUEST
    );
    let body = read_bounded_attachment_body(Body::from(vec![1_u8, 2, 3]), 4, Some(3))
        .await
        .expect("bounded body");
    assert_eq!(&*body, &[1_u8, 2, 3]);
    assert_eq!(body.capacity(), 3);
}

#[tokio::test]
async fn stalled_attachment_body_times_out_without_waiting_forever() {
    let body = Body::from_stream(futures_util::stream::once(async {
        std::future::pending::<Result<Bytes, Infallible>>().await
    }));
    assert_eq!(
        read_bounded_attachment_body_with_timeout(body, 4, None, Duration::from_millis(5))
            .await
            .expect_err("idle body should time out"),
        StatusCode::REQUEST_TIMEOUT
    );
}

#[tokio::test]
async fn total_attachment_upload_deadline_bounds_slow_chunked_body() {
    let body = Body::from_stream(futures_util::stream::once(async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok::<Bytes, Infallible>(Bytes::from_static(b"encrypted"))
    }));
    assert_eq!(
        read_bounded_attachment_body_with_timeouts(
            body,
            32,
            None,
            Duration::from_millis(100),
            Duration::from_millis(5),
        )
        .await
        .expect_err("total upload deadline should win over idle timeout"),
        StatusCode::REQUEST_TIMEOUT
    );
}

#[tokio::test]
async fn attachment_download_response_preserves_exact_bytes() {
    let downloads = Arc::new(Semaphore::new(1));
    let permit = acquire_attachment_download_permit(&downloads).expect("download permit");
    let expected = (0..(ATTACHMENT_DOWNLOAD_CHUNK_BYTES * 2 + 17))
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let expected_length = expected.len().to_string();
    let claim_id = Uuid::new_v4();
    let response = attachment_download_response(expected.clone(), permit, Some(claim_id));
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok()),
        Some(expected_length.as_str())
    );
    assert_eq!(
        response
            .headers()
            .get(ATTACHMENT_CLAIM_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some(claim_id.to_string().as_str())
    );

    let mut stream = response.into_body().into_data_stream();
    let mut received = Vec::new();
    while let Some(chunk) = stream.next().await {
        received.extend_from_slice(&chunk.expect("attachment body chunk"));
    }
    assert_eq!(received, expected);
}

#[tokio::test]
async fn destructive_attachment_requires_explicit_completion_after_stream_eof() {
    let mut state = test_state();
    state.attachment_record_limit = 1;
    state.attachment_account_record_limit = 1;
    let attachment_id = Uuid::new_v4();
    let owner = test_code_id("download-owner");
    let recipient = test_code_id("download-recipient");
    add_test_account_with_id(
        &state,
        recipient,
        "DownloadRecipient",
        ClientPlatform::Android,
    )
    .await;
    let expected = vec![11_u8, 22, 33, 44];
    state.attachments.lock().await.insert(
        attachment_id,
        AttachmentRecord {
            blob: test_attachment_blob(expected.clone()),
            chat_id: "dm_alice_bob".to_string(),
            message_id: "test-message".to_string(),
            media_type: "FILE".to_string(),
            owner_code_id: owner,
            sender_platform: ClientPlatform::Android,
            published: true,
            staged_expires_at_ms: None,
            one_time: true,
            delete_after_download: true,
            expires_at_ms: None,
            eligible_recipient_code_ids: HashSet::from([recipient]),
            download_claims: HashMap::new(),
            completed_recipient_code_ids: HashSet::new(),
        },
    );
    state
        .attachment_bytes_by_code
        .lock()
        .await
        .insert(owner, expected.len());
    assert!(!attachment_record_capacity_available(&state, &owner).await);

    let reservation = reserve_attachment_download(&state, attachment_id, &recipient)
        .await
        .expect("first download reservation");
    let claim_id = reservation.claim_id.expect("destructive claim");
    let permit =
        acquire_attachment_download_permit(&state.attachment_downloads).expect("download permit");
    let response = attachment_download_response_with_epoch(
        Arc::clone(&reservation.blob),
        permit,
        Some(claim_id),
        Arc::clone(&state.attachment_epoch),
        reservation.epoch,
        ATTACHMENT_DOWNLOAD_STALL_TIMEOUT,
    );
    let mut stream = response.into_body().into_data_stream();
    let mut received = Vec::new();
    while let Some(chunk) = stream.next().await {
        received.extend_from_slice(&chunk.expect("attachment body chunk"));
    }
    assert_eq!(received, expected);
    assert!(state.attachments.lock().await.contains_key(&attachment_id));
    assert!(matches!(
        reserve_attachment_download(&state, attachment_id, &recipient).await,
        Err(StatusCode::TOO_MANY_REQUESTS)
    ));
    complete_attachment_download_claim(&state, attachment_id, &recipient, claim_id)
        .await
        .expect("explicit completion");
    assert!(!state.attachments.lock().await.contains_key(&attachment_id));
    assert!(state.attachment_bytes_by_code.lock().await.is_empty());
    assert!(attachment_record_capacity_available(&state, &owner).await);
}

#[tokio::test]
async fn interrupted_destructive_attachment_download_requires_explicit_release() {
    let state = test_state();
    let attachment_id = Uuid::new_v4();
    let owner = test_code_id("interrupted-owner");
    let recipient = test_code_id("interrupted-recipient");
    add_test_account_with_id(
        &state,
        recipient,
        "InterruptedRecipient",
        ClientPlatform::Android,
    )
    .await;
    let expected = vec![55_u8; ATTACHMENT_DOWNLOAD_CHUNK_BYTES + 1];
    state.attachments.lock().await.insert(
        attachment_id,
        AttachmentRecord {
            blob: test_attachment_blob(expected.clone()),
            chat_id: "dm_alice_bob".to_string(),
            message_id: "test-message".to_string(),
            media_type: "FILE".to_string(),
            owner_code_id: owner,
            sender_platform: ClientPlatform::Android,
            published: true,
            staged_expires_at_ms: None,
            one_time: true,
            delete_after_download: false,
            expires_at_ms: None,
            eligible_recipient_code_ids: HashSet::from([recipient]),
            download_claims: HashMap::new(),
            completed_recipient_code_ids: HashSet::new(),
        },
    );
    state
        .attachment_bytes_by_code
        .lock()
        .await
        .insert(owner, expected.len());

    let reservation = reserve_attachment_download(&state, attachment_id, &recipient)
        .await
        .expect("first download reservation");
    let claim_id = reservation.claim_id.expect("destructive claim");
    let permit =
        acquire_attachment_download_permit(&state.attachment_downloads).expect("download permit");
    let response = attachment_download_response_with_epoch(
        Arc::clone(&reservation.blob),
        permit,
        Some(claim_id),
        Arc::clone(&state.attachment_epoch),
        reservation.epoch,
        ATTACHMENT_DOWNLOAD_STALL_TIMEOUT,
    );
    let mut stream = response.into_body().into_data_stream();
    let first = stream
        .next()
        .await
        .expect("first attachment chunk")
        .expect("attachment body chunk");
    assert!(!first.is_empty());
    drop(stream);

    assert!(matches!(
        reserve_attachment_download(&state, attachment_id, &recipient).await,
        Err(StatusCode::TOO_MANY_REQUESTS)
    ));
    release_attachment_download_claim(&state, attachment_id, &recipient, claim_id)
        .await
        .expect("explicit release");
    let retry = reserve_attachment_download(&state, attachment_id, &recipient)
        .await
        .expect("retry after release");
    assert_ne!(retry.claim_id, Some(claim_id));
    assert_eq!(&*retry.blob.bytes, &expected);
    release_attachment_download_claim(
        &state,
        attachment_id,
        &recipient,
        retry.claim_id.expect("retry claim"),
    )
    .await
    .expect("release retry claim");
}

#[tokio::test]
async fn expired_attachment_claim_is_pruned_and_can_retry() {
    let state = test_state();
    let attachment_id = Uuid::new_v4();
    let owner = test_code_id("expired-owner");
    let recipient = test_code_id("expired-recipient");
    add_test_account_with_id(
        &state,
        recipient,
        "ExpiredRecipient",
        ClientPlatform::Android,
    )
    .await;
    state.attachments.lock().await.insert(
        attachment_id,
        AttachmentRecord {
            blob: test_attachment_blob(vec![8, 9]),
            chat_id: "dm_alice_bob".to_string(),
            message_id: "test-message".to_string(),
            media_type: "FILE".to_string(),
            owner_code_id: owner,
            sender_platform: ClientPlatform::Android,
            published: true,
            staged_expires_at_ms: None,
            one_time: true,
            delete_after_download: false,
            expires_at_ms: None,
            eligible_recipient_code_ids: HashSet::from([recipient]),
            download_claims: HashMap::new(),
            completed_recipient_code_ids: HashSet::new(),
        },
    );
    let first = reserve_attachment_download(&state, attachment_id, &recipient)
        .await
        .expect("initial claim");
    let first_claim = first.claim_id.expect("initial claim id");
    state
        .attachments
        .lock()
        .await
        .get_mut(&attachment_id)
        .expect("attachment")
        .download_claims
        .get_mut(&first_claim)
        .expect("claim")
        .created_at_ms = now_ms().saturating_sub(ATTACHMENT_CLAIM_TTL_MS + 1);

    let retry = reserve_attachment_download(&state, attachment_id, &recipient)
        .await
        .expect("expired claim is retryable");
    assert_ne!(retry.claim_id, Some(first_claim));
    release_attachment_download_claim(
        &state,
        attachment_id,
        &recipient,
        retry.claim_id.expect("retry claim"),
    )
    .await
    .expect("release retry claim");
}

#[tokio::test]
async fn destructive_attachment_downloads_allow_only_one_claim() {
    let state = test_state();
    let attachment_id = Uuid::new_v4();
    let owner = test_code_id("concurrent-owner");
    let recipient = test_code_id("concurrent-recipient");
    add_test_account_with_id(
        &state,
        recipient,
        "ConcurrentRecipient",
        ClientPlatform::Android,
    )
    .await;
    state.attachments.lock().await.insert(
        attachment_id,
        AttachmentRecord {
            blob: test_attachment_blob(vec![1, 2, 3]),
            chat_id: "dm_alice_bob".to_string(),
            message_id: "test-message".to_string(),
            media_type: "FILE".to_string(),
            owner_code_id: owner,
            sender_platform: ClientPlatform::Android,
            published: true,
            staged_expires_at_ms: None,
            one_time: false,
            delete_after_download: true,
            expires_at_ms: None,
            eligible_recipient_code_ids: HashSet::from([recipient]),
            download_claims: HashMap::new(),
            completed_recipient_code_ids: HashSet::new(),
        },
    );

    let first = reserve_attachment_download(&state, attachment_id, &recipient)
        .await
        .expect("first download reservation");
    let first_claim = first.claim_id.expect("first claim");
    assert!(matches!(
        reserve_attachment_download(&state, attachment_id, &recipient).await,
        Err(StatusCode::TOO_MANY_REQUESTS)
    ));
    release_attachment_download_claim(&state, attachment_id, &recipient, first_claim)
        .await
        .expect("release first claim");
    assert!(
        reserve_attachment_download(&state, attachment_id, &recipient)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn attachment_claim_rejects_wrong_user_and_claim() {
    let state = test_state();
    let attachment_id = Uuid::new_v4();
    let owner = test_code_id("claim-owner");
    let recipient = test_code_id("claim-recipient");
    let other = test_code_id("claim-other");
    add_test_account_with_id(&state, recipient, "ClaimRecipient", ClientPlatform::Android).await;
    state.attachments.lock().await.insert(
        attachment_id,
        AttachmentRecord {
            blob: test_attachment_blob(vec![4, 5, 6]),
            chat_id: "dm_alice_bob".to_string(),
            message_id: "test-message".to_string(),
            media_type: "FILE".to_string(),
            owner_code_id: owner,
            sender_platform: ClientPlatform::Android,
            published: true,
            staged_expires_at_ms: None,
            one_time: true,
            delete_after_download: true,
            expires_at_ms: None,
            eligible_recipient_code_ids: HashSet::from([recipient]),
            download_claims: HashMap::new(),
            completed_recipient_code_ids: HashSet::new(),
        },
    );
    let reservation = reserve_attachment_download(&state, attachment_id, &recipient)
        .await
        .expect("claim");
    let claim_id = reservation.claim_id.expect("claim id");
    assert_eq!(
        complete_attachment_download_claim(&state, attachment_id, &other, claim_id).await,
        Err(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        complete_attachment_download_claim(&state, attachment_id, &recipient, Uuid::new_v4()).await,
        Err(StatusCode::NOT_FOUND)
    );
    complete_attachment_download_claim(&state, attachment_id, &recipient, claim_id)
        .await
        .expect("matching user and claim");
}

#[tokio::test]
async fn attachment_owner_preview_does_not_consume_recipient_download() {
    let state = test_state();
    let attachment_id = Uuid::new_v4();
    let owner = test_code_id("dm-owner");
    let recipient = test_code_id("dm-recipient");
    add_test_account_with_id(&state, recipient, "DmRecipient", ClientPlatform::Android).await;
    state.attachments.lock().await.insert(
        attachment_id,
        AttachmentRecord {
            blob: test_attachment_blob(vec![7, 8, 9]),
            chat_id: "dm_alice_bob".to_string(),
            message_id: "test-message".to_string(),
            media_type: "IMAGE".to_string(),
            owner_code_id: owner,
            sender_platform: ClientPlatform::Android,
            published: true,
            staged_expires_at_ms: None,
            one_time: true,
            delete_after_download: true,
            expires_at_ms: None,
            eligible_recipient_code_ids: HashSet::from([recipient]),
            download_claims: HashMap::new(),
            completed_recipient_code_ids: HashSet::new(),
        },
    );
    state.attachment_bytes_by_code.lock().await.insert(owner, 3);

    let owner_preview = reserve_attachment_download(&state, attachment_id, &owner)
        .await
        .expect("owner preview");
    assert!(owner_preview.claim_id.is_none());

    let recipient_download = reserve_attachment_download(&state, attachment_id, &recipient)
        .await
        .expect("recipient download");
    let claim_id = recipient_download.claim_id.expect("recipient claim");
    complete_attachment_download_claim(&state, attachment_id, &recipient, claim_id)
        .await
        .expect("recipient completion");
    assert!(!state.attachments.lock().await.contains_key(&attachment_id));
}

#[tokio::test]
async fn room_attachment_completes_once_for_each_recipient() {
    let state = test_state();
    let attachment_id = Uuid::new_v4();
    let owner = test_code_id("room-owner");
    let bob = test_code_id("room-bob");
    let carol = test_code_id("room-carol");
    add_test_account_with_id(&state, bob, "RoomBob", ClientPlatform::Android).await;
    add_test_account_with_id(&state, carol, "RoomCarol", ClientPlatform::Android).await;
    state.attachments.lock().await.insert(
        attachment_id,
        AttachmentRecord {
            blob: test_attachment_blob(vec![10, 11, 12]),
            chat_id: "forum_shared".to_string(),
            message_id: "test-message".to_string(),
            media_type: "FILE".to_string(),
            owner_code_id: owner,
            sender_platform: ClientPlatform::Android,
            published: true,
            staged_expires_at_ms: None,
            one_time: false,
            delete_after_download: true,
            expires_at_ms: None,
            eligible_recipient_code_ids: HashSet::from([bob, carol]),
            download_claims: HashMap::new(),
            completed_recipient_code_ids: HashSet::new(),
        },
    );
    state.attachment_bytes_by_code.lock().await.insert(owner, 3);

    let bob_download = reserve_attachment_download(&state, attachment_id, &bob)
        .await
        .expect("Bob download");
    complete_attachment_download_claim(
        &state,
        attachment_id,
        &bob,
        bob_download.claim_id.expect("Bob claim"),
    )
    .await
    .expect("Bob completion");
    assert!(state.attachments.lock().await.contains_key(&attachment_id));

    let carol_download = reserve_attachment_download(&state, attachment_id, &carol)
        .await
        .expect("Carol download");
    complete_attachment_download_claim(
        &state,
        attachment_id,
        &carol,
        carol_download.claim_id.expect("Carol claim"),
    )
    .await
    .expect("Carol completion");
    assert!(!state.attachments.lock().await.contains_key(&attachment_id));
}

#[tokio::test]
async fn attachment_download_requires_recipient_membership_and_platform_policy() {
    let mut state = test_state();
    let attachment_id = Uuid::new_v4();
    let owner = test_code_id("policy-owner");
    let android_recipient = test_code_id("policy-android");
    let web_recipient = test_code_id("policy-web");
    let unrelated_recipient = test_code_id("policy-unrelated");
    add_test_account_with_id(
        &state,
        android_recipient,
        "PolicyAndroid",
        ClientPlatform::Android,
    )
    .await;
    add_test_account_with_id(&state, web_recipient, "PolicyWeb", ClientPlatform::Web).await;
    add_test_account_with_id(
        &state,
        unrelated_recipient,
        "PolicyUnrelated",
        ClientPlatform::Android,
    )
    .await;
    state.attachments.lock().await.insert(
        attachment_id,
        AttachmentRecord {
            blob: test_attachment_blob(vec![1, 2, 3]),
            chat_id: "forum_policy".to_string(),
            message_id: "policy-message".to_string(),
            media_type: "FILE".to_string(),
            owner_code_id: owner,
            sender_platform: ClientPlatform::Android,
            published: true,
            staged_expires_at_ms: None,
            one_time: false,
            delete_after_download: false,
            expires_at_ms: None,
            eligible_recipient_code_ids: HashSet::from([android_recipient, web_recipient]),
            download_claims: HashMap::new(),
            completed_recipient_code_ids: HashSet::new(),
        },
    );

    assert!(
        reserve_attachment_download(&state, attachment_id, &android_recipient)
            .await
            .is_ok()
    );
    assert_eq!(
        reserve_attachment_download(&state, attachment_id, &unrelated_recipient)
            .await
            .map(|_| ()),
        Err(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        reserve_attachment_download(&state, attachment_id, &web_recipient)
            .await
            .map(|_| ()),
        Err(StatusCode::FORBIDDEN)
    );

    state.interop_policy = InteropPolicy::new(true, true);
    assert!(
        reserve_attachment_download(&state, attachment_id, &web_recipient)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn destructive_attachment_recipient_snapshot_is_conversation_scoped() {
    let state = test_state();
    add_test_account(&state, "snapshot-a", "Alice").await;
    add_test_account(&state, "snapshot-b", "Bob").await;
    add_test_account(&state, "snapshot-c", "Carol").await;
    state.direct_catalog.lock().await.insert(
        "dm_snapshot".to_string(),
        DirectEntry {
            id: "dm_snapshot".to_string(),
            user_a: "Alice".to_string(),
            user_b: "Bob".to_string(),
        },
    );
    let direct_access = conversation_access(&state, "Alice", "dm_snapshot")
        .await
        .expect("direct access");
    assert_eq!(
        snapshot_attachment_recipients(
            &state,
            &direct_access,
            "dm_snapshot",
            "Alice",
            &test_code_id("snapshot-a"),
        )
        .await,
        HashSet::from([test_code_id("snapshot-b")])
    );

    let room = test_room("forum_snapshot");
    state.room_catalog.lock().await.insert(
        room.id.clone(),
        RoomEntry {
            room: room.clone(),
            owner_code_id: test_code_id("snapshot-a"),
        },
    );
    let room_access = conversation_access(&state, "Alice", &room.id)
        .await
        .expect("room access");
    assert_eq!(
        snapshot_attachment_recipients(
            &state,
            &room_access,
            &room.id,
            "Alice",
            &test_code_id("snapshot-a"),
        )
        .await,
        HashSet::from([test_code_id("snapshot-b"), test_code_id("snapshot-c")])
    );
}

#[tokio::test]
async fn invalid_account_handshakes_do_not_refresh_dead_man_activity() {
    let state = test_state();
    *state.last_activity_ms.lock().await = 123;
    let _ = start_opaque_account(
        State(state.clone()),
        Json(OpaqueAccountStartRequest {
            code: "not-a-code".to_string(),
            registration_request_b64: String::new(),
            credential_request_b64: String::new(),
        }),
    )
    .await;
    assert_eq!(*state.last_activity_ms.lock().await, 123);

    let _ = finish_opaque_account(
        State(state.clone()),
        Json(OpaqueAccountFinishRequest {
            handshake_id: Uuid::new_v4(),
            registration_upload_b64: None,
            credential_finalization_b64: None,
            identity_public_b64: None,
            identity_prekey_id: None,
            identity_envelope_b64: None,
            identity_proof_b64: None,
        }),
    )
    .await;
    assert_eq!(*state.last_activity_ms.lock().await, 123);
}

#[tokio::test]
async fn rejected_ws_operations_do_not_refresh_dead_man_activity() {
    let state = test_state();
    add_test_account(&state, "activity-a", "Alice").await;
    let (client_id, _receiver) = add_test_client(&state, "activity-a", "Alice").await;
    let room = test_room("activity-room");
    state.room_catalog.lock().await.insert(
        room.id.clone(),
        RoomEntry {
            room,
            owner_code_id: test_code_id("activity-a"),
        },
    );

    *state.last_activity_ms.lock().await = 123;
    assert!(handle_frame(
            &state,
            client_id,
            r#"{"type":"message","chat_id":"activity-room","version":0,"message_id":"","nonce_b64":"","ciphertext_b64":"","envelopes":[],"state_revision":0,"identity_envelope_b64":"","identity_public_b64":"","prekey_id":"","state_signature_b64":""}"#,
        )
        .await
        .is_err());
    assert_eq!(*state.last_activity_ms.lock().await, 123);

    *state.last_activity_ms.lock().await = 123;
    assert!(handle_frame(
            &state,
            client_id,
            r#"{"type":"message_ack","chat_id":"activity-room","message_id":"","sender_username":"","state_revision":0,"identity_envelope_b64":"","identity_public_b64":"","prekey_id":"","state_signature_b64":"","ack_signature_b64":"","used_prekey_id":""}"#,
        )
        .await
        .is_err());
    assert_eq!(*state.last_activity_ms.lock().await, 123);

    assert!(handle_frame(
        &state,
        client_id,
        r#"{"type":"join","chat_id":"activity-room"}"#,
    )
    .await
    .is_err());
    assert_eq!(*state.last_activity_ms.lock().await, 123);

    *state.last_activity_ms.lock().await = 123;
    assert!(handle_frame(&state, client_id, r#"{"type":"activity"}"#)
        .await
        .is_ok());
    assert!(*state.last_activity_ms.lock().await > 123);
}

#[tokio::test]
async fn destructive_attachment_upload_requires_an_eligible_recipient() {
    let state = test_state();
    add_test_account(&state, "solo-owner", "Alice").await;
    let room = test_room("forum_solo");
    state.room_catalog.lock().await.insert(
        room.id.clone(),
        RoomEntry {
            room,
            owner_code_id: test_code_id("solo-owner"),
        },
    );
    state.sessions.lock().await.insert(
        SessionToken::new("solo-token".to_string()),
        AuthSession {
            code_id: test_code_id("solo-owner"),
            username: "Alice".to_string(),
            last_activity_ms: now_ms(),
        },
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer solo-token"),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("9"));
    let response = upload_attachment(
        State(state),
        Query(AttachmentQuery {
            chat_id: "forum_solo".to_string(),
            message_id: "test-message".to_string(),
            media_type: Some("FILE".to_string()),
            one_time: Some(true),
            delete_after_download: Some(true),
            ttl_sec: None,
        }),
        headers,
        Body::from(Bytes::from_static(b"encrypted")),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn attachment_record_limit_rejects_before_body_allocation() {
    let mut state = test_state();
    state.attachment_record_limit = 1;
    state.attachment_account_record_limit = 1;
    add_test_account(&state, "record-limit-owner", "Alice").await;
    let owner = test_code_id("record-limit-owner");
    let room = test_room("record_limit_room");
    state.room_catalog.lock().await.insert(
        room.id.clone(),
        RoomEntry {
            room,
            owner_code_id: owner,
        },
    );
    state.sessions.lock().await.insert(
        SessionToken::new("record-limit-token".to_string()),
        AuthSession {
            code_id: owner,
            username: "Alice".to_string(),
            last_activity_ms: now_ms(),
        },
    );
    state.attachments.lock().await.insert(
        Uuid::new_v4(),
        AttachmentRecord {
            blob: test_attachment_blob(test_valid_encrypted_attachment_body(1)),
            chat_id: "record_limit_room".to_string(),
            message_id: "test-message".to_string(),
            media_type: "FILE".to_string(),
            owner_code_id: owner,
            sender_platform: ClientPlatform::Android,
            published: true,
            staged_expires_at_ms: None,
            one_time: false,
            delete_after_download: false,
            expires_at_ms: None,
            eligible_recipient_code_ids: HashSet::new(),
            download_claims: HashMap::new(),
            completed_recipient_code_ids: HashSet::new(),
        },
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer record-limit-token"),
    );
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&ATTACHMENT_CHUNK_RECORD_BYTES.to_string()).expect("content length"),
    );
    let body = Body::from_stream(futures_util::stream::once(async {
        panic!("a saturated attachment record limit must reject before reading the body");
        #[allow(unreachable_code)]
        Ok::<Bytes, Infallible>(Bytes::new())
    }));
    let response = upload_attachment(
        State(state.clone()),
        Query(AttachmentQuery {
            chat_id: "record_limit_room".to_string(),
            message_id: "test-message".to_string(),
            media_type: Some("FILE".to_string()),
            one_time: None,
            delete_after_download: None,
            ttl_sec: None,
        }),
        headers,
        body,
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::from_u16(507).unwrap());
    assert_eq!(state.attachments.lock().await.len(), 1);
    assert_eq!(state.attachment_memory.available_permits(), 8 * 1024 * 1024);
}

#[tokio::test]
async fn concurrent_attachment_admission_rechecks_global_record_limit_atomically() {
    let mut state = test_state();
    state.attachment_record_limit = 1;
    state.attachment_account_record_limit = 1;
    state.attachment_uploads = Arc::new(Semaphore::new(2));
    add_test_account(&state, "record-race-a", "Alice").await;
    add_test_account(&state, "record-race-b", "Bob").await;
    let room = test_room("record_race_room");
    state.room_catalog.lock().await.insert(
        room.id.clone(),
        RoomEntry {
            room,
            owner_code_id: test_code_id("record-race-a"),
        },
    );
    for (token, code_id, username) in [
        ("record-race-token-a", "record-race-a", "Alice"),
        ("record-race-token-b", "record-race-b", "Bob"),
    ] {
        state.sessions.lock().await.insert(
            SessionToken::new(token.to_string()),
            AuthSession {
                code_id: test_code_id(code_id),
                username: username.to_string(),
                last_activity_ms: now_ms(),
            },
        );
    }

    let gate = Arc::new(tokio::sync::Barrier::new(3));
    let request_state = state.clone();
    let make_request = move |token: &'static str, gate: Arc<tokio::sync::Barrier>| {
        let state = request_state.clone();
        async move {
            let body = test_valid_encrypted_attachment_body(1);
            let mut headers = HeaderMap::new();
            headers.insert(
                header::AUTHORIZATION,
                HeaderValue::from_static(match token {
                    "record-race-token-a" => "Bearer record-race-token-a",
                    _ => "Bearer record-race-token-b",
                }),
            );
            headers.insert(
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&body.len().to_string()).expect("content length"),
            );
            let body_gate = gate;
            upload_attachment(
                State(state.clone()),
                Query(AttachmentQuery {
                    chat_id: "record_race_room".to_string(),
                    message_id: "test-message".to_string(),
                    media_type: Some("FILE".to_string()),
                    one_time: None,
                    delete_after_download: None,
                    ttl_sec: None,
                }),
                headers,
                Body::from_stream(futures_util::stream::once(async move {
                    body_gate.wait().await;
                    Ok::<Bytes, Infallible>(Bytes::from(body))
                })),
            )
            .await
        }
    };
    let release_gate = Arc::clone(&gate);
    let (first, second, _) = tokio::join!(
        make_request("record-race-token-a", Arc::clone(&gate)),
        make_request("record-race-token-b", Arc::clone(&gate)),
        async move {
            release_gate.wait().await;
        }
    );
    let statuses = [
        first.into_response().status(),
        second.into_response().status(),
    ];
    assert!(statuses.contains(&StatusCode::OK));
    assert!(statuses.contains(&StatusCode::from_u16(507).unwrap()));
    assert_eq!(state.attachments.lock().await.len(), 1);
    assert_eq!(
        state.attachment_memory.available_permits(),
        8 * 1024 * 1024 - ATTACHMENT_CHUNK_RECORD_BYTES
    );
    let usage = state.attachment_bytes_by_code.lock().await;
    assert_eq!(
        usage.values().copied().sum::<usize>(),
        ATTACHMENT_CHUNK_RECORD_BYTES
    );
    assert_eq!(usage.len(), 1);
}

#[tokio::test]
async fn attachment_record_limits_enforce_account_then_global_boundaries() {
    let mut state = test_state();
    state.attachment_record_limit = 2;
    state.attachment_account_record_limit = 1;
    add_test_account(&state, "record-boundary-a", "Alice").await;
    add_test_account(&state, "record-boundary-b", "Bob").await;
    let room_id = "record_boundary_room";
    state.room_catalog.lock().await.insert(
        room_id.to_string(),
        RoomEntry {
            room: test_room(room_id),
            owner_code_id: test_code_id("record-boundary-a"),
        },
    );
    for (token, code, username) in [
        ("record-boundary-token-a", "record-boundary-a", "Alice"),
        ("record-boundary-token-b", "record-boundary-b", "Bob"),
    ] {
        state.sessions.lock().await.insert(
            SessionToken::new(token.to_string()),
            AuthSession {
                code_id: test_code_id(code),
                username: username.to_string(),
                last_activity_ms: now_ms(),
            },
        );
    }

    let upload = |token: &'static str| {
        let body = test_valid_encrypted_attachment_body(1);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).expect("test bearer token"),
        );
        headers.insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&body.len().to_string()).expect("content length"),
        );
        upload_attachment(
            State(state.clone()),
            Query(AttachmentQuery {
                chat_id: room_id.to_string(),
                message_id: "test-message".to_string(),
                media_type: Some("FILE".to_string()),
                one_time: None,
                delete_after_download: None,
                ttl_sec: None,
            }),
            headers,
            Body::from(body),
        )
    };

    assert_eq!(
        upload("record-boundary-token-a")
            .await
            .into_response()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        upload("record-boundary-token-a")
            .await
            .into_response()
            .status(),
        StatusCode::from_u16(507).unwrap(),
        "the per-account limit rejects the exact next record"
    );
    assert_eq!(
        upload("record-boundary-token-b")
            .await
            .into_response()
            .status(),
        StatusCode::OK,
        "another account can use remaining global capacity"
    );
    assert_eq!(
        upload("record-boundary-token-b")
            .await
            .into_response()
            .status(),
        StatusCode::from_u16(507).unwrap(),
        "the global limit rejects the exact next record"
    );
    assert_eq!(state.attachments.lock().await.len(), 2);
    assert_eq!(
        state.attachment_memory.available_permits(),
        8 * 1024 * 1024 - 2 * ATTACHMENT_CHUNK_RECORD_BYTES
    );
    let usage = state.attachment_bytes_by_code.lock().await;
    assert_eq!(
        usage.get(&test_code_id("record-boundary-a")),
        Some(&ATTACHMENT_CHUNK_RECORD_BYTES)
    );
    assert_eq!(
        usage.get(&test_code_id("record-boundary-b")),
        Some(&ATTACHMENT_CHUNK_RECORD_BYTES)
    );
    drop(usage);

    remove_chat_attachments(&state, room_id).await;
    assert!(state.attachments.lock().await.is_empty());
    assert!(state.attachment_bindings.lock().await.is_empty());
    assert!(state.attachment_bytes_by_code.lock().await.is_empty());
    assert_eq!(state.attachment_memory.available_permits(), 8 * 1024 * 1024);
    assert_eq!(
        upload("record-boundary-token-a")
            .await
            .into_response()
            .status(),
        StatusCode::OK,
        "room deletion cleanup releases record and byte capacity"
    );
}

#[tokio::test]
async fn global_wipe_releases_attachment_record_and_byte_capacity_for_reuse() {
    let mut state = test_state();
    state.attachment_record_limit = 1;
    state.attachment_account_record_limit = 1;
    add_test_account(&state, "record-wipe-owner", "Alice").await;
    let room_id = "record_wipe_room";
    state.room_catalog.lock().await.insert(
        room_id.to_string(),
        RoomEntry {
            room: test_room(room_id),
            owner_code_id: test_code_id("record-wipe-owner"),
        },
    );
    state.sessions.lock().await.insert(
        SessionToken::new("record-wipe-token".to_string()),
        AuthSession {
            code_id: test_code_id("record-wipe-owner"),
            username: "Alice".to_string(),
            last_activity_ms: now_ms(),
        },
    );
    let upload = |state: AppState| async move {
        let body = test_valid_encrypted_attachment_body(1);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer record-wipe-token"),
        );
        headers.insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&body.len().to_string()).expect("content length"),
        );
        upload_attachment(
            State(state),
            Query(AttachmentQuery {
                chat_id: room_id.to_string(),
                message_id: "test-message".to_string(),
                media_type: Some("FILE".to_string()),
                one_time: None,
                delete_after_download: None,
                ttl_sec: None,
            }),
            headers,
            Body::from(body),
        )
        .await
        .into_response()
        .status()
    };

    assert_eq!(upload(state.clone()).await, StatusCode::OK);
    assert_eq!(state.attachments.lock().await.len(), 1);
    wipe_relay_state(&state, false).await;
    assert!(state.attachments.lock().await.is_empty());
    assert!(state.attachment_bindings.lock().await.is_empty());
    assert!(state.attachment_bytes_by_code.lock().await.is_empty());
    assert_eq!(state.attachment_memory.available_permits(), 8 * 1024 * 1024);

    add_test_account(&state, "record-wipe-owner", "Alice").await;
    state.room_catalog.lock().await.insert(
        room_id.to_string(),
        RoomEntry {
            room: test_room(room_id),
            owner_code_id: test_code_id("record-wipe-owner"),
        },
    );
    state.sessions.lock().await.insert(
        SessionToken::new("record-wipe-token".to_string()),
        AuthSession {
            code_id: test_code_id("record-wipe-owner"),
            username: "Alice".to_string(),
            last_activity_ms: now_ms(),
        },
    );
    assert_eq!(upload(state.clone()).await, StatusCode::OK);
}

#[test]
fn attachment_upload_permit_rejects_excess_body_readers() {
    let uploads = Arc::new(Semaphore::new(1));
    let permit = acquire_attachment_upload_permit(&uploads).expect("first upload");
    assert!(acquire_attachment_upload_permit(&uploads).is_err());
    drop(permit);
    assert!(acquire_attachment_upload_permit(&uploads).is_ok());
}

#[tokio::test]
async fn account_attachment_upload_permit_isolated_and_bounded() {
    let state = test_state();
    add_test_account(&state, "upload-account", "Alice").await;
    let code_id = test_code_id("upload-account");
    let first = acquire_account_attachment_upload_permit(&state, &code_id)
        .await
        .expect("first account upload");
    let second = acquire_account_attachment_upload_permit(&state, &code_id).await;
    assert!(matches!(second, Err(StatusCode::TOO_MANY_REQUESTS)));
    drop(first);
    assert!(acquire_account_attachment_upload_permit(&state, &code_id)
        .await
        .is_ok());
    assert!(matches!(
        acquire_account_attachment_upload_permit(&state, &test_code_id("missing")).await,
        Err(StatusCode::UNAUTHORIZED)
    ));
}

#[test]
fn protocol_base64_requires_exact_unpadded_lengths() {
    let url_safe_bytes = [0xfb_u8, 0xff, 0x00];
    let url_safe = URL_SAFE_NO_PAD.encode(url_safe_bytes);
    assert_eq!(url_safe, "-_8A");
    assert_eq!(
        decode_bounded(&url_safe, url_safe_bytes.len()).unwrap(),
        url_safe_bytes
    );

    let encoded = URL_SAFE_NO_PAD.encode([7_u8; MESSAGE_NONCE_BYTES]);
    assert_eq!(
        decode_exact(&encoded, MESSAGE_NONCE_BYTES).unwrap(),
        vec![7; 12]
    );
    assert!(decode_exact(&encoded, MESSAGE_NONCE_BYTES + 1).is_err());
    assert!(decode_exact(&encoded[..encoded.len() - 1], MESSAGE_NONCE_BYTES).is_err());

    // URL_SAFE_NO_PAD must reject the padded form and non-canonical
    // trailing bits rather than accepting alternate encodings of bytes.
    assert!(decode_bounded("AQ==", 1).is_err());
    assert!(decode_bounded("AB", 1).is_err());
    assert!(decode_bounded("AA+_", 3).is_err());
    assert!(decode_bounded("", 128).is_err());
    assert!(decode_bounded("not base64!", 128).is_err());

    let oversized = "A".repeat(2 * 4 + 1);
    assert!(decode_bounded(&oversized, 4).is_err());
    assert_eq!(decode_bounded_allow_empty("", 4).unwrap(), Vec::<u8>::new());
    assert!(decode_bounded_allow_empty("AQ==", 4).is_err());
}

#[test]
fn session_expiration_uses_strict_boundary() {
    let session = AuthSession {
        code_id: test_code_id("ABCD-1234-WXYZ"),
        username: "SilentNode123".to_string(),
        last_activity_ms: 1_000,
    };

    assert!(!session_is_expired(&session, 5_999, 5_000));
    assert!(session_is_expired(&session, 6_000, 5_000));
}

#[test]
fn room_quota_is_counted_per_owner() {
    let mut catalog = HashMap::new();
    for (id, owner_code) in [
        ("room-a", "code-a"),
        ("room-b", "code-a"),
        ("room-c", "code-b"),
    ] {
        catalog.insert(
            id.to_string(),
            RoomEntry {
                room: test_room(id),
                owner_code_id: test_code_id(owner_code),
            },
        );
    }

    assert_eq!(owned_room_count(&catalog, &test_code_id("code-a")), 2);
    assert!(!has_room_capacity(&catalog, &test_code_id("code-a"), 2));
    assert!(has_room_capacity(&catalog, &test_code_id("code-b"), 2));
}

#[tokio::test]
async fn room_catalog_is_capped_and_catalog_send_is_bounded() {
    let state = test_state();
    add_test_account(&state, "catalog-owner", "Alice").await;
    let (client_id, mut rx) = add_test_client(&state, "catalog-owner", "Alice").await;
    for index in 0..MAX_ROOM_CATALOG_ENTRIES {
        let mut room = test_room("forum_catalog");
        room.id = format!("forum_catalog_{index}");
        state.room_catalog.lock().await.insert(
            room.id.clone(),
            RoomEntry {
                room,
                owner_code_id: test_code_id("catalog-owner"),
            },
        );
    }
    send_room_catalog(&state, client_id).await;
    let frame = rx.try_recv().expect("bounded room catalog");
    assert!(matches!(
        &frame,
        OutboundFrame::Rooms { rooms } if rooms.len() <= MAX_ROOM_CATALOG_ENTRIES
    ));

    let mut extra = test_room("forum_catalog_extra");
    extra.id = "forum_catalog_extra".to_string();
    assert_eq!(
        create_room(&state, client_id, extra).await,
        Err("room catalog limit reached".to_string())
    );
    assert_eq!(
        state.room_catalog.lock().await.len(),
        MAX_ROOM_CATALOG_ENTRIES
    );
}

#[tokio::test]
async fn room_catalog_rejects_case_colliding_ids() {
    let state = test_state();
    add_test_account(&state, "case-owner", "Alice").await;
    let (client_id, _) = add_test_client(&state, "case-owner", "Alice").await;

    let mut first = test_room("forum_case");
    first.id = "forum_case".to_string();
    create_room(&state, client_id, first)
        .await
        .expect("first room should be created");

    let mut collision = test_room("forum_case_upper");
    collision.id = "forum_CASE".to_string();
    assert_eq!(
        create_room(&state, client_id, collision).await,
        Err("room id rejected".to_string())
    );
    assert_eq!(state.room_catalog.lock().await.len(), 1);
}

#[test]
fn pending_message_ttl_defaults_and_clamps_to_safe_bounds() {
    let hour_ms = HOURS_TO_MILLISECONDS;
    assert_eq!(
        pending_message_ttl_ms_from_value(None),
        DEFAULT_PENDING_MESSAGE_TTL_HOURS as u64 * hour_ms
    );
    assert_eq!(pending_message_ttl_ms_from_value(Some("0")), hour_ms);
    assert_eq!(
        pending_message_ttl_ms_from_value(Some("999999")),
        MAX_PENDING_MESSAGE_TTL_HOURS as u64 * hour_ms
    );
    assert_eq!(
        pending_message_ttl_ms_from_value(Some("not-a-number")),
        DEFAULT_PENDING_MESSAGE_TTL_HOURS as u64 * hour_ms
    );
}

#[test]
fn websocket_ticket_requires_protocol_v2_and_rejects_bearer() {
    let raw_ticket = URL_SAFE_NO_PAD.encode([7_u8; WS_TICKET_BYTES]);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SEC_WEBSOCKET_PROTOCOL,
        HeaderValue::from_str(&format!("abyssal-v2, ticket.{raw_ticket}"))
            .expect("valid subprotocol"),
    );

    assert_eq!(
        websocket_ticket_header(&headers).as_deref(),
        Some(&raw_ticket)
    );
    headers.insert(
        header::SEC_WEBSOCKET_PROTOCOL,
        HeaderValue::from_str(&format!("abyssal-v2, bearer.{raw_ticket}"))
            .expect("valid subprotocol"),
    );
    assert!(websocket_ticket_header(&headers).is_none());
    headers.insert(
        header::SEC_WEBSOCKET_PROTOCOL,
        HeaderValue::from_str(&format!("ticket.{raw_ticket}")).expect("valid subprotocol"),
    );
    assert!(websocket_ticket_header(&headers).is_none());
    headers.insert(
        header::SEC_WEBSOCKET_PROTOCOL,
        HeaderValue::from_static("abyssal-v2, ticket.invalid"),
    );
    assert!(websocket_ticket_header(&headers).is_none());
}

#[test]
fn websocket_ticket_digest_requires_canonical_url_safe_no_pad() {
    let canonical = URL_SAFE_NO_PAD.encode([0_u8; WS_TICKET_BYTES]);
    assert_eq!(canonical.len(), WS_TICKET_B64_LEN);
    assert!(ws_ticket_digest(&canonical).is_some());

    let padded = format!("{canonical}=");
    assert!(ws_ticket_digest(&padded).is_none());

    let mut noncanonical = canonical.clone();
    noncanonical.replace_range((WS_TICKET_B64_LEN - 1).., "B");
    assert!(ws_ticket_digest(&noncanonical).is_none());

    let mut standard_alphabet = canonical;
    standard_alphabet.replace_range((WS_TICKET_B64_LEN - 1).., "/");
    assert!(ws_ticket_digest(&standard_alphabet).is_none());
}

fn ticket_auth_headers(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).expect("valid authorization header"),
    );
    headers
}

fn ticket_build_attestation_for(platform: &str) -> BuildAttestationRequest {
    BuildAttestationRequest {
        platform: platform.to_string(),
        version: "2.1.0".to_string(),
        build_signature_b64: URL_SAFE_NO_PAD.encode([2_u8; 64]),
    }
}

fn ticket_build_attestation() -> BuildAttestationRequest {
    ticket_build_attestation_for("web")
}

async fn issue_test_ticket(state: &AppState, token: &str) -> (StatusCode, WsTicketResponse) {
    let response = issue_ws_ticket(
        State(state.clone()),
        ticket_auth_headers(token),
        Json(ticket_build_attestation()),
    )
    .await;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .expect("ticket response body");
    let ticket = serde_json::from_slice(&body).expect("ticket response JSON");
    (status, ticket)
}

async fn add_test_session(state: &AppState, token: &str, code: &str, username: &str) {
    if !state
        .accounts
        .lock()
        .await
        .contains_key(&test_code_id(code))
    {
        add_test_account(state, code, username).await;
    }
    state
        .accounts
        .lock()
        .await
        .get_mut(&test_code_id(code))
        .expect("test account")
        .client_platform = None;
    state.sessions.lock().await.insert(
        SessionToken::new(token.to_string()),
        AuthSession {
            code_id: test_code_id(code),
            username: username.to_string(),
            last_activity_ms: now_ms(),
        },
    );
}

#[tokio::test]
async fn websocket_ticket_is_hash_only_no_store_and_single_use() {
    let state = test_state();
    add_test_session(&state, "ticket-session", "ticket-code", "Alice").await;

    let (status, response) = issue_test_ticket(&state, "ticket-session").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response.ticket.len(), WS_TICKET_B64_LEN);
    assert_eq!(response.expires_in_sec, WS_TICKET_TTL_MS / 1000);
    let digest = ws_ticket_digest(&response.ticket).expect("valid issued ticket");
    let tickets = state.ws_tickets.lock().await;
    assert_eq!(tickets.len(), 1);
    assert!(tickets.contains_key(&digest));
    assert!(!tickets.contains_key(&[0_u8; WS_TICKET_BYTES]));
    drop(tickets);

    let (token, session, platform) = consume_ws_ticket(&state, &response.ticket)
        .await
        .expect("first consumption");
    assert_eq!(token.as_str(), "ticket-session");
    assert_eq!(session.username, "Alice");
    assert_eq!(platform, ClientPlatform::Web);
    assert_eq!(
        state
            .accounts
            .lock()
            .await
            .get(&test_code_id("ticket-code"))
            .and_then(|account| account.client_platform),
        Some(ClientPlatform::Web)
    );
    assert!(consume_ws_ticket(&state, &response.ticket).await.is_none());
    assert!(state.ws_tickets.lock().await.is_empty());
}

#[tokio::test]
async fn release_admission_rejects_before_ticket_or_session_access() {
    let mut state = test_state();
    state.release_admission = Arc::new(ReleaseAdmissionStore::new());
    add_test_session(&state, "attestation-session", "attestation-code", "Alice").await;

    let response = issue_ws_ticket(
        State(state.clone()),
        ticket_auth_headers("attestation-session"),
        Json(ticket_build_attestation()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UPGRADE_REQUIRED);
    assert!(state.ws_tickets.lock().await.is_empty());

    let response = issue_ws_ticket(
        State(state.clone()),
        ticket_auth_headers("missing-session"),
        Json(BuildAttestationRequest {
            platform: "web".to_string(),
            version: "2.0.0".to_string(),
            build_signature_b64: URL_SAFE_NO_PAD.encode([2_u8; 64]),
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UPGRADE_REQUIRED);
    assert!(state.ws_tickets.lock().await.is_empty());
}

#[tokio::test]
async fn release_material_endpoints_are_absent_until_install_and_serve_exact_bytes() {
    let mut absent = test_state();
    absent.release_admission = Arc::new(ReleaseAdmissionStore::new());
    let response = release_manifest_endpoint(State(absent.clone())).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = release_signature_endpoint(State(absent)).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let state = test_state();
    let response = release_manifest_endpoint(State(state.clone())).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE),
        Some(&HeaderValue::from_static("application/json"))
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
    assert_eq!(
        response.headers().get(header::X_CONTENT_TYPE_OPTIONS),
        Some(&HeaderValue::from_static("nosniff"))
    );
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .expect("manifest response body");
    assert_eq!(body.as_ref(), b"test");

    let response = release_signature_endpoint(State(state)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE),
        Some(&HeaderValue::from_static("application/octet-stream"))
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
    assert_eq!(
        response.headers().get(header::X_CONTENT_TYPE_OPTIONS),
        Some(&HeaderValue::from_static("nosniff"))
    );
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .expect("signature response body");
    assert_eq!(body.as_ref(), &[3; 64]);
}

#[tokio::test]
async fn websocket_ticket_rotation_keeps_one_outstanding_and_replays_fail() {
    let state = test_state();
    add_test_session(&state, "rotation-session", "rotation-code", "Alice").await;

    let (_, first) = issue_test_ticket(&state, "rotation-session").await;
    let (_, second) = issue_test_ticket(&state, "rotation-session").await;
    assert_ne!(first.ticket, second.ticket);
    assert_eq!(state.ws_tickets.lock().await.len(), 1);
    assert!(consume_ws_ticket(&state, &first.ticket).await.is_none());
    assert!(consume_ws_ticket(&state, &second.ticket).await.is_some());
}

#[tokio::test]
async fn websocket_ticket_cannot_reclassify_an_authenticated_session() {
    let state = test_state();
    add_test_session(&state, "platform-session", "platform-code", "Alice").await;

    let (status, _) = issue_test_ticket(&state, "platform-session").await;
    assert_eq!(status, StatusCode::OK);
    let response = issue_ws_ticket(
        State(state.clone()),
        ticket_auth_headers("platform-session"),
        Json(ticket_build_attestation_for("android")),
    )
    .await;

    assert_eq!(response.status(), StatusCode::UPGRADE_REQUIRED);
    assert_eq!(state.ws_tickets.lock().await.len(), 1);
    assert_eq!(
        state
            .accounts
            .lock()
            .await
            .get(&test_code_id("platform-code"))
            .and_then(|account| account.client_platform),
        Some(ClientPlatform::Web)
    );
}

#[tokio::test]
async fn new_authenticated_session_requires_fresh_platform_attestation() {
    let state = test_state();
    add_test_account(&state, "fresh-platform-code", "Alice").await;
    state
        .accounts
        .lock()
        .await
        .get_mut(&test_code_id("fresh-platform-code"))
        .expect("Alice account")
        .client_platform = Some(ClientPlatform::Web);

    let (status, response) = issue_session(
        &state,
        test_code_id("fresh-platform-code"),
        "Alice".to_string(),
        false,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(response.accepted);
    assert_eq!(
        state
            .accounts
            .lock()
            .await
            .get(&test_code_id("fresh-platform-code"))
            .and_then(|account| account.client_platform),
        None
    );
}

#[tokio::test]
async fn websocket_ticket_expiry_is_pruned_before_session_validation() {
    let state = test_state();
    let digest =
        ws_ticket_digest(&URL_SAFE_NO_PAD.encode([9_u8; WS_TICKET_BYTES])).expect("test digest");
    state.ws_tickets.lock().await.insert(
        digest,
        WsTicket {
            session_token: Zeroizing::new("expired-session".to_string()),
            expires_at_ms: now_ms().saturating_sub(1),
            client_platform: ClientPlatform::Web,
        },
    );
    assert!(
        consume_ws_ticket(&state, &URL_SAFE_NO_PAD.encode([9_u8; WS_TICKET_BYTES]))
            .await
            .is_none()
    );
    assert!(state.ws_tickets.lock().await.is_empty());
}

#[tokio::test]
async fn websocket_ticket_cap_fails_closed_without_eviction() {
    let state = test_state();
    add_test_session(&state, "cap-session", "cap-code", "Alice").await;
    let mut tickets = state.ws_tickets.lock().await;
    for index in 0..MAX_WS_TICKETS {
        let mut digest = [0_u8; WS_TICKET_BYTES];
        digest.copy_from_slice(&Sha256::digest(format!("cap-{index}").as_bytes()));
        tickets.insert(
            digest,
            WsTicket {
                session_token: Zeroizing::new(format!("other-session-{index}")),
                expires_at_ms: now_ms().saturating_add(WS_TICKET_TTL_MS),
                client_platform: ClientPlatform::Web,
            },
        );
    }
    drop(tickets);

    let response = issue_ws_ticket(
        State(state.clone()),
        ticket_auth_headers("cap-session"),
        Json(ticket_build_attestation()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(state.ws_tickets.lock().await.len(), MAX_WS_TICKETS);
}

#[tokio::test]
async fn logout_clears_outstanding_websocket_tickets() {
    let state = test_state();
    add_test_session(&state, "logout-session", "logout-code", "Alice").await;
    let (_, response) = issue_test_ticket(&state, "logout-session").await;
    assert_eq!(state.ws_tickets.lock().await.len(), 1);

    assert_eq!(
        logout_account(State(state.clone()), ticket_auth_headers("logout-session")).await,
        StatusCode::NO_CONTENT
    );
    assert!(state.ws_tickets.lock().await.is_empty());
    assert!(consume_ws_ticket(&state, &response.ticket).await.is_none());
}

#[tokio::test]
async fn global_wipe_clears_outstanding_websocket_tickets() {
    let state = test_state();
    add_test_session(&state, "wipe-session", "wipe-code", "Alice").await;
    let (_, response) = issue_test_ticket(&state, "wipe-session").await;
    assert_eq!(state.ws_tickets.lock().await.len(), 1);

    wipe_relay_state(&state, false).await;

    assert!(state.ws_tickets.lock().await.is_empty());
    assert!(consume_ws_ticket(&state, &response.ticket).await.is_none());
}

#[test]
fn websocket_origin_requires_same_host_or_allow_list() {
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, HeaderValue::from_static("abyssal.example"));
    headers.insert(
        header::ORIGIN,
        HeaderValue::from_static("https://abyssal.example"),
    );
    assert!(websocket_origin_allowed(&headers, &[]));

    headers.insert(
        header::ORIGIN,
        HeaderValue::from_static("https://web.example"),
    );
    assert!(!websocket_origin_allowed(&headers, &[]));
    assert!(websocket_origin_allowed(
        &headers,
        &["https://web.example".to_string()]
    ));

    headers.insert(
        header::ORIGIN,
        HeaderValue::from_static("HTTPS://WEB.EXAMPLE"),
    );
    headers.insert(header::HOST, HeaderValue::from_static("web.example"));
    assert!(websocket_origin_allowed(&headers, &[]));

    headers.insert(
        header::ORIGIN,
        HeaderValue::from_static("http://127.0.0.1:4020"),
    );
    headers.insert(header::HOST, HeaderValue::from_static("127.0.0.1:4020"));
    assert!(websocket_origin_allowed(&headers, &[]));

    headers.insert(
        header::ORIGIN,
        HeaderValue::from_static("https://abyssal.example/path"),
    );
    assert!(!websocket_origin_allowed(&headers, &[]));
    headers.insert(
        header::ORIGIN,
        HeaderValue::from_static("file://abyssal.example"),
    );
    assert!(!websocket_origin_allowed(&headers, &[]));
}

#[test]
fn connection_reservation_does_not_overwrite_existing_owner() {
    let code_id = [3_u8; 32];
    let old_client = Uuid::from_u128(1);
    let new_client = Uuid::from_u128(2);
    let mut active = HashMap::new();

    assert!(reserve_connection(&mut active, code_id, old_client));
    assert!(!reserve_connection(&mut active, code_id, new_client));
    assert_eq!(active.get(&code_id), Some(&old_client));
}

#[test]
fn bearer_tokens_are_bounded_before_allocation() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer 12345678"),
    );
    assert_eq!(bearer_token(&headers).as_deref(), Some("12345678"));
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", "a".repeat(129))).unwrap(),
    );
    assert!(bearer_token(&headers).is_none());
}

#[test]
fn outbound_frames_are_bounded_before_websocket_send() {
    let frame = OutboundFrame::Message {
        chat_id: "forum_test".to_string(),
        version: E2EE_PROTOCOL_VERSION,
        message_id: "message_test".to_string(),
        nonce_b64: "nonce".to_string(),
        ciphertext_b64: "x".repeat(WS_MAX_FRAME_BYTES),
        signature_b64: "signature".to_string(),
        wrapped_key_b64: "wrapped".to_string(),
        prekey_id: "prekey".to_string(),
        is_prekey: false,
        sender_username: "Alice".to_string(),
        sender_public_key_b64: "public".to_string(),
        identity_public_b64: "public".to_string(),
        directory_node_id: "test-node".to_string(),
        directory_revision: 1,
        directory_digest: URL_SAFE_NO_PAD.encode([0_u8; 32]),
        padding_bucket: 0,
        padding: String::new(),
    };
    assert!(serialize_outbound_frame(&frame).is_none());
}

#[test]
fn outbound_queue_ceiling_is_selected_by_protocol() {
    let mls_global = AtomicUsize::new(0);
    let mls_local = AtomicUsize::new(0);
    assert!(reserve_outbound_bytes(
        &mls_global,
        &mls_local,
        WS_MAX_FRAME_BYTES + 1,
        MLS_CLIENT_OUTBOUND_BYTES,
    ));

    let legacy_global = AtomicUsize::new(0);
    let legacy_local = AtomicUsize::new(0);
    assert!(reserve_outbound_bytes(
        &legacy_global,
        &legacy_local,
        CLIENT_OUTBOUND_BYTES,
        CLIENT_OUTBOUND_BYTES,
    ));
    assert!(!reserve_outbound_bytes(
        &legacy_global,
        &legacy_local,
        1,
        CLIENT_OUTBOUND_BYTES,
    ));
}

#[tokio::test]
async fn send_to_client_allows_mls_frames_above_legacy_one_megabyte_limit() {
    let state = test_state();
    let (client_id, mut rx) = add_test_client(&state, "code-a", "Alice").await;
    let frame = OutboundFrame::MlsApplication {
        protocol_version: rooms::MLS_PROTOCOL_VERSION,
        room_id: "room-1".to_string(),
        message_id: "message-1".to_string(),
        sender_username: "Bob".to_string(),
        epoch: 1,
        revision: 1,
        membership_digest_b64: "digest".to_string(),
        ciphertext_b64: "x".repeat(WS_MAX_FRAME_BYTES + 1024),
        authenticated_data_b64: "aad".to_string(),
    };
    assert!(serialize_outbound_frame(&frame)
        .as_ref()
        .is_some_and(|serialized| serialized.len() > WS_MAX_FRAME_BYTES));
    send_to_client(&state, client_id, &frame).await;
    assert!(rx.try_recv().is_ok());
}

#[test]
fn message_transport_padding_hits_bucket_boundaries_exactly() {
    let first_randomized = test_message_frame("forum_test", "random-a", "Alice", "", false);
    let second_randomized = test_message_frame("forum_test", "random-a", "Alice", "", false);
    assert!(matches!(
        (&first_randomized, &second_randomized),
        (
            OutboundFrame::Message { padding: left, .. },
            OutboundFrame::Message { padding: right, .. }
        ) if !left.is_empty() && left != right
    ));

    let mut at_boundary = test_message_frame("forum_test", "boundary", "Alice", "", false);
    let current_ciphertext_len = match &at_boundary {
        OutboundFrame::Message { ciphertext_b64, .. } => ciphertext_b64.len(),
        _ => unreachable!("test message frame"),
    };
    let empty_len = outbound_message_wire_len(&at_boundary, MESSAGE_TRANSPORT_BUCKETS[0], "")
        .expect("empty message wire length");
    if let OutboundFrame::Message {
        ciphertext_b64,
        padding_bucket,
        padding,
        ..
    } = &mut at_boundary
    {
        *ciphertext_b64 = "x".repeat(
            MESSAGE_TRANSPORT_BUCKETS[0]
                .checked_sub(empty_len)
                .expect("boundary capacity")
                .saturating_add(current_ciphertext_len),
        );
        padding.zeroize();
        *padding_bucket = 0;
    }
    prepare_outbound_message_padding(&mut at_boundary).expect("exact first bucket");
    assert!(matches!(
        at_boundary,
        OutboundFrame::Message {
            padding_bucket: 4096,
            ref padding,
            ..
        } if padding.is_empty()
    ));
    assert_eq!(
        serialize_outbound_frame(&at_boundary)
            .expect("boundary frame")
            .len(),
        MESSAGE_TRANSPORT_BUCKETS[0]
    );

    let mut next_bucket = at_boundary.clone();
    if let OutboundFrame::Message {
        ciphertext_b64,
        padding_bucket,
        padding,
        ..
    } = &mut next_bucket
    {
        ciphertext_b64.push('x');
        padding.zeroize();
        *padding_bucket = 0;
    }
    prepare_outbound_message_padding(&mut next_bucket).expect("next bucket");
    assert!(matches!(
        next_bucket,
        OutboundFrame::Message {
            padding_bucket: 16_384,
            ..
        }
    ));
    assert_eq!(
        serialize_outbound_frame(&next_bucket)
            .expect("next bucket frame")
            .len(),
        MESSAGE_TRANSPORT_BUCKETS[1]
    );
}

#[test]
fn message_transport_padding_rejects_tampering_and_noncanonical_input() {
    let envelopes = Vec::new();
    let empty_len = inbound_message_wire_len(
        "dm_a_b",
        E2EE_PROTOCOL_VERSION,
        "message-1",
        "nonce",
        "ciphertext",
        &envelopes,
        1,
        "identity-envelope",
        "identity-public",
        "fallback",
        "state-signature",
        "test-node",
        1,
        &URL_SAFE_NO_PAD.encode([7_u8; DIRECTORY_DIGEST_BYTES]),
        MESSAGE_TRANSPORT_BUCKETS[0],
        "",
    )
    .expect("inbound empty wire length");
    let padding = "A".repeat(
        MESSAGE_TRANSPORT_BUCKETS[0]
            .checked_sub(empty_len)
            .expect("inbound bucket capacity"),
    );
    let directory_digest = URL_SAFE_NO_PAD.encode([7_u8; DIRECTORY_DIGEST_BYTES]);
    let text = serde_json::to_string(&InboundMessageWire {
        frame_type: "message",
        chat_id: "dm_a_b",
        version: E2EE_PROTOCOL_VERSION,
        message_id: "message-1",
        nonce_b64: "nonce",
        ciphertext_b64: "ciphertext",
        envelopes: &envelopes,
        state_revision: 1,
        identity_envelope_b64: "identity-envelope",
        identity_public_b64: "identity-public",
        prekey_id: "fallback",
        state_signature_b64: "state-signature",
        directory_node_id: "test-node",
        directory_revision: 1,
        directory_digest: &directory_digest,
        padding_bucket: MESSAGE_TRANSPORT_BUCKETS[0],
        padding: &padding,
    })
    .expect("inbound padded frame");
    let frame: InboundFrame = serde_json::from_str(&text).expect("inbound message");
    validate_inbound_message_padding(&text, &frame).expect("canonical inbound padding");

    let mut wrong_bucket = serde_json::from_str::<InboundFrame>(&text).expect("inbound message");
    if let InboundFrame::Message { padding_bucket, .. } = &mut wrong_bucket {
        *padding_bucket = MESSAGE_TRANSPORT_BUCKETS[1];
    }
    assert!(validate_inbound_message_padding(&text, &wrong_bucket).is_err());

    let mut shortened = serde_json::from_str::<InboundFrame>(&text).expect("inbound message");
    if let InboundFrame::Message { padding, .. } = &mut shortened {
        padding.pop();
    }
    assert!(validate_inbound_message_padding(&text, &shortened).is_err());

    let mut tampered = frame;
    if let InboundFrame::Message { padding, .. } = &mut tampered {
        padding.replace_range(0..1, "!");
    }
    assert!(validate_inbound_message_padding(&text, &tampered).is_err());

    let mut noncanonical = text.clone();
    noncanonical.push(' ');
    let parsed: InboundFrame = serde_json::from_str(&noncanonical).expect("whitespace parse");
    assert!(validate_inbound_message_padding(&noncanonical, &parsed).is_err());
}

#[test]
fn dummy_padding_hint_saturates_without_overflow() {
    assert_eq!(
        discarded_dummy_hint(Some("padding"), Some(usize::MAX)),
        usize::MAX
    );
}

#[tokio::test]
async fn pending_accounting_uses_complete_padded_message_frame() {
    let state = test_state();
    let frame = test_message_frame("dm_a_b", "accounted", "Alice", "", false);
    let expected = serialize_outbound_frame(&frame)
        .expect("padded message serialization")
        .len();
    queue_pending_frame(&state, "dm_a_b", "Bob".to_string(), frame)
        .await
        .expect("pending admission");
    assert_eq!(*state.pending_bytes.lock().await, expected);
}

#[test]
fn web_origin_normalization_rejects_paths_and_non_http_schemes() {
    assert_eq!(
        normalize_web_origin("https://web.example/").as_deref(),
        Ok("https://web.example")
    );
    assert_eq!(
        normalize_web_origin("HTTPS://WEB.EXAMPLE:8443/").as_deref(),
        Ok("https://web.example:8443")
    );
    assert!(normalize_web_origin("http://web.example").is_err());
    assert_eq!(
        normalize_web_origin("http://127.0.0.1:4020").as_deref(),
        Ok("http://127.0.0.1:4020")
    );
    assert_eq!(
        normalize_web_origin("http://localhost:4173/").as_deref(),
        Ok("http://localhost:4173")
    );
    assert!(normalize_web_origin("https://web.example/path").is_err());
    assert!(normalize_web_origin("file://web.example").is_err());
    assert!(normalize_web_origin("https://user:password@web.example").is_err());
    assert!(normalize_web_origin("https:///missing-host").is_err());
}

#[test]
fn chat_ids_and_room_metadata_are_strictly_normalized() {
    assert!(valid_chat_id("forum_alpha-1"));
    assert!(!valid_chat_id("forum/alpha"));
    assert!(!valid_chat_id("forum_alpha\nmessage"));
    assert!(!valid_chat_id(&"a".repeat(MAX_CHAT_ID_BYTES + 1)));

    let mut room = test_room("forum_safe");
    room.name = "  Ops\nRoom\u{0000}  ".to_string();
    normalize_room_record(&mut room).expect("room should normalize");
    assert_eq!(room.name, "OpsRoom");

    room.self_destruct_timer_sec = 0;
    room.image_read_timer_sec = 0;
    normalize_room_record(&mut room).expect("never-expire policy should normalize");
    assert_eq!(room.self_destruct_timer_sec, 0);
    assert_eq!(room.image_read_timer_sec, 0);

    room.id = "forum/unsafe".to_string();
    assert!(normalize_room_record(&mut room).is_err());
}

#[tokio::test]
async fn replay_window_rejects_duplicate_sender_message_ids() {
    let state = test_state();
    register_message_id(&state, "forum_alpha", "Alice", "message-1")
        .await
        .expect("first message should register");
    assert!(
        register_message_id(&state, "forum_alpha", "Alice", "message-1")
            .await
            .is_err()
    );
    assert!(
        register_message_id(&state, "forum_alpha", "Bob", "message-1")
            .await
            .is_ok()
    );
    assert!(
        register_message_id(&state, "forum_beta", "Alice", "message-1")
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn replay_window_never_evicts_live_entries_when_full() {
    let state = test_state();
    let now = now_ms();
    let mut replay_ids = state.replay_ids.lock().await;
    for index in 0..MAX_REPLAY_IDS {
        replay_ids.insert(
            ReplayKey {
                chat_id: "forum_full".to_string(),
                sender_username: "Alice".to_string(),
                message_id: format!("message-{index}"),
            },
            now,
        );
    }
    drop(replay_ids);

    assert!(
        register_message_id(&state, "forum_full", "Alice", "new-message")
            .await
            .is_err()
    );
    assert_eq!(state.replay_ids.lock().await.len(), MAX_REPLAY_IDS);
    assert!(state.replay_ids.lock().await.contains_key(&ReplayKey {
        chat_id: "forum_full".to_string(),
        sender_username: "Alice".to_string(),
        message_id: "message-0".to_string(),
    }));
}

#[tokio::test]
async fn one_time_prekey_leases_are_single_use_and_bound_to_recipient_state() {
    let state = test_state();
    add_test_account(&state, "code-a", "Alice").await;
    add_test_account(&state, "code-b", "Bob").await;
    let expected = HashSet::from(["Bob".to_string()]);
    let envelope = InboundRecipientEnvelope {
        recipient_username: "Bob".to_string(),
        wrapped_key_b64: URL_SAFE_NO_PAD.encode([7_u8; 32]),
        prekey_id: test_prekey_id(b'B'),
        is_prekey: true,
        signature_b64: test_signature_b64(b'S'),
    };
    let envelopes = HashMap::from([("Bob".to_string(), envelope)]);
    state.prekey_leases.lock().await.insert(
        PrekeyLeaseKey {
            code_id: test_code_id("code-b"),
            prekey_id: test_prekey_id(b'B'),
        },
        PrekeyLease {
            chat_id: "dm_alice_bob".to_string(),
            message_id: "message-1".to_string(),
            sender_username: "Alice".to_string(),
            recipient_username: "Bob".to_string(),
            created_at_ms: now_ms(),
        },
    );

    admit_prekey_leases(
        &state,
        &expected,
        &envelopes,
        "dm_alice_bob",
        "message-1",
        "Alice",
    )
    .await
    .expect("exact lease");
    assert!(admit_prekey_leases(
        &state,
        &expected,
        &envelopes,
        "dm_alice_bob",
        "message-2",
        "Alice",
    )
    .await
    .is_err());

    let mut mismatched = envelopes;
    mismatched.get_mut("Bob").expect("Bob envelope").prekey_id = "other-key".to_string();
    assert!(admit_prekey_leases(
        &state,
        &expected,
        &mismatched,
        "dm_alice_bob",
        "message-3",
        "Alice",
    )
    .await
    .is_err());
}

#[tokio::test]
async fn authenticated_prekey_lease_is_idempotent_exactly_releasable_and_pending_safe() {
    let state = test_state();
    add_test_account(&state, "code-a", "Alice").await;
    add_test_account(&state, "code-b", "Bob").await;
    let (alice_id, _) = add_test_client(&state, "code-a", "Alice").await;
    open_direct(&state, alice_id, "Bob")
        .await
        .expect("direct conversation");
    let chat_id = state
        .direct_catalog
        .lock()
        .await
        .keys()
        .next()
        .expect("direct id")
        .clone();

    let first = lease_prekey(&state, alice_id, &chat_id, "lease-message", "Bob")
        .await
        .expect("first lease");
    let second = lease_prekey(&state, alice_id, &chat_id, "lease-message", "Bob")
        .await
        .expect("idempotent lease");
    let leased_id = match (&first, &second) {
        (
            OutboundFrame::PrekeyLease {
                prekey_id: first, ..
            },
            OutboundFrame::PrekeyLease {
                prekey_id: second, ..
            },
        ) if first == second => first.clone(),
        _ => panic!("expected identical lease responses"),
    };
    assert_eq!(state.prekey_leases.lock().await.len(), 1);
    assert!(release_unused_prekey_lease(
        &state,
        alice_id,
        &chat_id,
        "wrong-message",
        "Bob",
        &leased_id,
    )
    .await
    .is_err());

    state.pending.lock().await.insert(
        PendingKey {
            chat_id: chat_id.clone(),
            recipient_username: "Bob".to_string(),
        },
        vec![PendingFrame::new(
            test_message_frame(&chat_id, "lease-message", "Alice", &leased_id, true),
            now_ms(),
        )],
    );
    assert!(release_unused_prekey_lease(
        &state,
        alice_id,
        &chat_id,
        "lease-message",
        "Bob",
        &leased_id,
    )
    .await
    .is_err());
    state.pending.lock().await.clear();
    release_unused_prekey_lease(
        &state,
        alice_id,
        &chat_id,
        "lease-message",
        "Bob",
        &leased_id,
    )
    .await
    .expect("exact unused release");
    assert!(state.prekey_leases.lock().await.is_empty());
}

#[tokio::test]
async fn concurrent_prekey_leases_are_distinct_bounded_expiring_and_purged() {
    let state = test_state();
    add_test_account(&state, "code-a", "Alice").await;
    add_test_account(&state, "code-b", "Bob").await;
    let (alice_id, _) = add_test_client(&state, "code-a", "Alice").await;
    open_direct(&state, alice_id, "Bob")
        .await
        .expect("direct conversation");
    let chat_id = state
        .direct_catalog
        .lock()
        .await
        .keys()
        .next()
        .expect("direct id")
        .clone();
    let tasks = (0..PREKEY_POOL_SIZE_V9)
        .map(|index| {
            let state = state.clone();
            let chat_id = chat_id.clone();
            tokio::spawn(async move {
                lease_prekey(
                    &state,
                    alice_id,
                    &chat_id,
                    &format!("concurrent-{index}"),
                    "Bob",
                )
                .await
            })
        })
        .collect::<Vec<_>>();
    let mut ids = HashSet::new();
    for task in tasks {
        let frame = task.await.expect("lease task").expect("bounded lease");
        let OutboundFrame::PrekeyLease { ref prekey_id, .. } = frame else {
            panic!("expected lease frame")
        };
        assert!(ids.insert(prekey_id.clone()));
    }
    assert_eq!(ids.len(), PREKEY_POOL_SIZE_V9);
    assert!(lease_prekey(&state, alice_id, &chat_id, "exhausted", "Bob")
        .await
        .is_err());

    let now = now_ms();
    for lease in state.prekey_leases.lock().await.values_mut() {
        lease.created_at_ms = now.saturating_sub(PREKEY_LEASE_TTL_MS);
    }
    let refreshed = lease_prekey(&state, alice_id, &chat_id, "after-expiry", "Bob")
        .await
        .expect("expired leases release capacity");
    assert!(matches!(refreshed, OutboundFrame::PrekeyLease { .. }));
    assert_eq!(state.prekey_leases.lock().await.len(), 1);

    {
        let mut leases = state.prekey_leases.lock().await;
        for index in 1..MAX_PREKEY_LEASES {
            let mut code_id = [0_u8; 32];
            code_id[..8].copy_from_slice(&(index as u64).to_be_bytes());
            leases.insert(
                PrekeyLeaseKey {
                    code_id,
                    prekey_id: format!("global-{index}"),
                },
                PrekeyLease {
                    chat_id: "global-bound".to_string(),
                    message_id: format!("message-{index}"),
                    sender_username: "Other".to_string(),
                    recipient_username: "OtherRecipient".to_string(),
                    created_at_ms: now,
                },
            );
        }
    }
    assert_eq!(state.prekey_leases.lock().await.len(), MAX_PREKEY_LEASES);
    assert!(
        lease_prekey(&state, alice_id, &chat_id, "global-full", "Bob")
            .await
            .is_err()
    );

    wipe_relay_state(&state, false).await;
    assert!(state.prekey_leases.lock().await.is_empty());
}

#[test]
fn prekey_pool_transition_is_exact_and_preserves_other_live_leases() {
    let previous = test_identity_public(b'B');
    let consumed = test_prekey_id(b'B');
    let (next, _) = test_identity_public_after_consumption(b'B', &consumed);
    validate_prekey_pool_transition(&previous, &next, Some(&consumed))
        .expect("one-for-one transition");
    assert!(validate_prekey_pool_transition(&previous, &next, None).is_err());
    assert!(validate_prekey_pool_transition(&previous, &previous, Some(&consumed)).is_err());
    validate_prekey_pool_transition(&previous, &previous, None)
        .expect("established pool preservation");

    let preserved_id = prekey_ids_from_identity_public_v9(&previous)
        .expect("pool")
        .into_iter()
        .find(|id| id != &consumed)
        .expect("other key");
    let leases = HashMap::from([(
        PrekeyLeaseKey {
            code_id: test_code_id("code-b"),
            prekey_id: preserved_id,
        },
        PrekeyLease {
            chat_id: "dm_alice_bob".to_string(),
            message_id: "other-message".to_string(),
            sender_username: "Carol".to_string(),
            recipient_username: "Bob".to_string(),
            created_at_ms: now_ms(),
        },
    )]);
    let next_pool = prekey_ids_from_identity_public_v9(&next).expect("next pool");
    assert!(!leases_for_recipient_missing_from_pool(
        &leases,
        &test_code_id("code-b"),
        &next_pool,
        Some(&consumed),
    ));
}

#[tokio::test]
async fn queued_prekey_frame_keeps_lease_alive_until_queue_is_removed() {
    let state = test_state();
    let code_id = test_code_id("code-b");
    let prekey_id = test_prekey_id(b'B');
    let key = PrekeyLeaseKey {
        code_id,
        prekey_id: prekey_id.clone(),
    };
    let claim = PrekeyLease {
        chat_id: "dm_alice_bob".to_string(),
        message_id: "message-1".to_string(),
        sender_username: "Alice".to_string(),
        recipient_username: "Bob".to_string(),
        created_at_ms: now_ms().saturating_sub(PREKEY_LEASE_TTL_MS + 1),
    };
    state.prekey_leases.lock().await.insert(key.clone(), claim);
    state.pending.lock().await.insert(
        PendingKey {
            chat_id: "dm_alice_bob".to_string(),
            recipient_username: "Bob".to_string(),
        },
        vec![PendingFrame::new(
            test_message_frame("dm_alice_bob", "message-1", "Alice", &prekey_id, true),
            now_ms(),
        )],
    );

    {
        let pending = state.pending.lock().await;
        let mut claims = state.prekey_leases.lock().await;
        prune_prekey_leases(&mut claims, &pending, now_ms());
        assert!(claims.contains_key(&key));
    }

    state.pending.lock().await.clear();
    let pending = state.pending.lock().await;
    let mut claims = state.prekey_leases.lock().await;
    prune_prekey_leases(&mut claims, &pending, now_ms());
    assert!(!claims.contains_key(&key));
}

#[tokio::test]
async fn expired_pending_prekey_frame_releases_lease_and_bytes_together() {
    let mut state = test_state();
    state.pending_message_ttl_ms = MIN_PENDING_MESSAGE_TTL_HOURS as u64 * HOURS_TO_MILLISECONDS;
    let now = now_ms();
    let prekey_id = test_prekey_id(b'B');
    let frame = test_message_frame("dm_alice_bob", "expired-prekey", "Alice", &prekey_id, true);
    let frame_bytes = outbound_frame_bytes(&frame);
    let claim_key = PrekeyLeaseKey {
        code_id: test_code_id("code-b"),
        prekey_id: prekey_id.clone(),
    };
    state.prekey_leases.lock().await.insert(
        claim_key.clone(),
        PrekeyLease {
            chat_id: "dm_alice_bob".to_string(),
            message_id: "expired-prekey".to_string(),
            sender_username: "Alice".to_string(),
            recipient_username: "Bob".to_string(),
            created_at_ms: now,
        },
    );
    state.pending.lock().await.insert(
        PendingKey {
            chat_id: "dm_alice_bob".to_string(),
            recipient_username: "Bob".to_string(),
        },
        vec![PendingFrame::new(
            frame,
            now.saturating_sub(state.pending_message_ttl_ms + 1),
        )],
    );
    *state.pending_bytes.lock().await = frame_bytes;

    prune_pending_queues(&state, now).await;

    assert!(state.pending.lock().await.is_empty());
    assert_eq!(*state.pending_bytes.lock().await, 0);
    assert!(!state.prekey_leases.lock().await.contains_key(&claim_key));
}

#[tokio::test]
async fn expired_non_prekey_frame_subtracts_pending_bytes() {
    let mut state = test_state();
    state.pending_message_ttl_ms = MIN_PENDING_MESSAGE_TTL_HOURS as u64 * HOURS_TO_MILLISECONDS;
    let now = now_ms();
    let frame = test_message_frame("dm_alice_bob", "expired-message", "Alice", "", false);
    let frame_bytes = outbound_frame_bytes(&frame);
    state.pending.lock().await.insert(
        PendingKey {
            chat_id: "dm_alice_bob".to_string(),
            recipient_username: "Bob".to_string(),
        },
        vec![PendingFrame::new(
            frame,
            now.saturating_sub(state.pending_message_ttl_ms + 1),
        )],
    );
    *state.pending_bytes.lock().await = frame_bytes;

    prune_pending_queues(&state, now).await;

    assert!(state.pending.lock().await.is_empty());
    assert_eq!(*state.pending_bytes.lock().await, 0);
}

#[tokio::test]
async fn unexpired_pending_frame_is_replayed_and_bytes_are_retained() {
    let mut state = test_state();
    state.pending_message_ttl_ms = MIN_PENDING_MESSAGE_TTL_HOURS as u64 * HOURS_TO_MILLISECONDS;
    add_test_account(&state, "code-a", "Alice").await;
    add_test_account(&state, "code-b", "Bob").await;
    let (bob_id, mut bob_rx) = add_test_client(&state, "code-b", "Bob").await;
    let room = test_room("pending_replay");
    state.room_catalog.lock().await.insert(
        room.id.clone(),
        RoomEntry {
            room: room.clone(),
            owner_code_id: test_code_id("code-a"),
        },
    );
    let now = now_ms();
    let frame = test_message_frame(&room.id, "retained-message", "Alice", "", false);
    let frame_bytes = outbound_frame_bytes(&frame);
    state.pending.lock().await.insert(
        PendingKey {
            chat_id: room.id.clone(),
            recipient_username: "Bob".to_string(),
        },
        vec![PendingFrame::new(
            frame,
            // Keep a real margin below the expiry boundary. A one-ms
            // margin made this test depend on scheduler timing.
            now.saturating_sub(state.pending_message_ttl_ms - 60_000),
        )],
    );
    *state.pending_bytes.lock().await = frame_bytes;

    join_room(&state, bob_id, room.id)
        .await
        .expect("peer can replay an unexpired frame");

    assert!(bob_rx.try_recv().is_ok());
    assert_eq!(*state.pending_bytes.lock().await, frame_bytes);
    assert_eq!(state.pending.lock().await.len(), 1);
}

#[tokio::test]
async fn pending_queue_never_evicts_the_required_prekey_frame() {
    let state = test_state();
    let prekey_id = test_prekey_id(b'B');
    let mut frames = vec![PendingFrame::new(
        test_message_frame("dm_alice_bob", "first-contact", "Alice", &prekey_id, true),
        now_ms(),
    )];
    frames.extend((0..MAX_PENDING_FRAMES_PER_ROOM - 1).map(|index| {
        PendingFrame::new(
            test_message_frame(
                "dm_alice_bob",
                &format!("message-{index}"),
                "Alice",
                "",
                false,
            ),
            now_ms(),
        )
    }));
    state.pending.lock().await.insert(
        PendingKey {
            chat_id: "dm_alice_bob".to_string(),
            recipient_username: "Bob".to_string(),
        },
        frames,
    );

    let _ = queue_pending_frame(
        &state,
        "dm_alice_bob",
        "Bob".to_string(),
        test_message_frame("dm_alice_bob", "new-message", "Alice", "", false),
    )
    .await;

    let pending = state.pending.lock().await;
    let queue = pending
        .get(&PendingKey {
            chat_id: "dm_alice_bob".to_string(),
            recipient_username: "Bob".to_string(),
        })
        .expect("pending queue");
    assert_eq!(queue.len(), MAX_PENDING_FRAMES_PER_ROOM);
    assert!(queue.iter().any(|frame| {
        matches!(
            &frame.frame,
            OutboundFrame::Message {
                message_id,
                is_prekey: true,
                ..
            } if message_id == "first-contact"
        )
    }));
}

#[tokio::test]
async fn pending_preflight_is_all_or_none_when_one_recipient_is_full() {
    let state = test_state();
    let prekey_id = test_prekey_id(b'B');
    let key = PendingKey {
        chat_id: "room_atomic".to_string(),
        recipient_username: "Bob".to_string(),
    };
    let queue = (0..MAX_PENDING_FRAMES_PER_ROOM)
        .map(|index| {
            PendingFrame::new(
                test_message_frame(
                    "room_atomic",
                    &format!("prekey-{index}"),
                    "Alice",
                    &prekey_id,
                    true,
                ),
                now_ms(),
            )
        })
        .collect::<Vec<_>>();
    let queue_bytes = queue
        .iter()
        .map(|pending_frame| outbound_frame_bytes(&pending_frame.frame))
        .sum::<usize>();
    state.pending.lock().await.insert(key.clone(), queue);
    *state.pending_bytes.lock().await = queue_bytes;
    let frames = vec![
        (
            "Bob".to_string(),
            test_message_frame("room_atomic", "rejected-bob", "Alice", "", false),
        ),
        (
            "Carol".to_string(),
            test_message_frame("room_atomic", "rejected-carol", "Alice", "", false),
        ),
    ];

    assert!(preflight_pending_frames(&state, &frames).await.is_err());
    assert_eq!(
        state.pending.lock().await[&key].len(),
        MAX_PENDING_FRAMES_PER_ROOM
    );
    assert!(!state.pending.lock().await.contains_key(&PendingKey {
        chat_id: "room_atomic".to_string(),
        recipient_username: "Carol".to_string(),
    }));
    assert!(state.prekey_leases.lock().await.is_empty());
    assert!(state.replay_ids.lock().await.is_empty());
}

#[tokio::test]
async fn pending_preflight_rejects_transient_fanout_above_global_budget() {
    let state = test_state();
    // Force every otherwise-valid frame into the 1 MiB transport bucket,
    // then exceed the 64 MiB transient fanout budget by exactly one frame.
    let payload = "x".repeat(300_000);
    let frame_count = MAX_TRANSIENT_FANOUT_BYTES / WS_MAX_FRAME_BYTES + 1;
    let frames = (0..frame_count)
        .map(|index| {
            let mut frame = test_message_frame(
                "transient_fanout",
                &format!("message-{index}"),
                "Alice",
                "",
                false,
            );
            if let OutboundFrame::Message { ciphertext_b64, .. } = &mut frame {
                *ciphertext_b64 = payload.clone();
            }
            prepare_outbound_message_padding(&mut frame)
                .expect("large test frame remains canonically pad-able");
            (format!("recipient-{index}"), frame)
        })
        .collect::<Vec<_>>();

    assert!(preflight_pending_frames(&state, &frames)
        .await
        .is_err_and(|error| error == "fanout preparation budget full"));
    assert!(state.pending.lock().await.is_empty());
    assert_eq!(*state.pending_bytes.lock().await, 0);
}

#[tokio::test]
async fn rollback_removes_newest_duplicate_and_restores_evicted_frame() {
    let state = test_state();
    let key = PendingKey {
        chat_id: "rollback_duplicate".to_string(),
        recipient_username: "Bob".to_string(),
    };
    let mut old_duplicate =
        test_message_frame("rollback_duplicate", "same-message-id", "Alice", "", false);
    if let OutboundFrame::Message { nonce_b64, .. } = &mut old_duplicate {
        *nonce_b64 = "old-frame".to_string();
    }
    prepare_outbound_message_padding(&mut old_duplicate).expect("old duplicate padding");
    let mut queue = vec![PendingFrame::new(old_duplicate, now_ms())];
    queue.extend((0..MAX_PENDING_FRAMES_PER_ROOM - 1).map(|index| {
        PendingFrame::new(
            test_message_frame(
                "rollback_duplicate",
                &format!("other-{index}"),
                "Alice",
                "",
                false,
            ),
            now_ms(),
        )
    }));
    let original_bytes = queue
        .iter()
        .map(|pending_frame| outbound_frame_bytes(&pending_frame.frame))
        .sum::<usize>();
    state.pending.lock().await.insert(key.clone(), queue);
    *state.pending_bytes.lock().await = original_bytes;

    let mut new_duplicate =
        test_message_frame("rollback_duplicate", "same-message-id", "Alice", "", false);
    if let OutboundFrame::Message { nonce_b64, .. } = &mut new_duplicate {
        *nonce_b64 = "new-frame".to_string();
    }
    prepare_outbound_message_padding(&mut new_duplicate).expect("new duplicate padding");
    let frames = vec![("Bob".to_string(), new_duplicate)];
    let mut plan = preflight_pending_frames(&state, &frames)
        .await
        .expect("duplicate admission preflight");
    commit_pending_frames(&state, &frames, &mut plan, ClientPlatform::Android)
        .await
        .expect("duplicate admission commit");
    assert_eq!(
        state.pending.lock().await[&key].len(),
        MAX_PENDING_FRAMES_PER_ROOM
    );
    rollback_pending_frames(&state, &frames, &mut plan).await;

    let pending = state.pending.lock().await;
    let queue = pending.get(&key).expect("restored queue");
    assert_eq!(queue.len(), MAX_PENDING_FRAMES_PER_ROOM);
    assert_eq!(*state.pending_bytes.lock().await, original_bytes);
    assert!(queue.iter().any(|pending_frame| {
        matches!(
            &pending_frame.frame,
            OutboundFrame::Message { nonce_b64, .. } if nonce_b64 == "old-frame"
        )
    }));
    assert!(!queue.iter().any(|pending_frame| {
        matches!(
            &pending_frame.frame,
            OutboundFrame::Message { nonce_b64, .. } if nonce_b64 == "new-frame"
        )
    }));
}

#[tokio::test]
async fn message_result_uses_dedicated_channel_and_waits_for_sink_delivery() {
    let state = test_state();
    let client_id = Uuid::new_v4();
    let (tx, _rx) = mpsc::channel(CLIENT_OUTBOUND_QUEUE_CAPACITY);
    let (control_tx, _control_rx) = mpsc::channel(CLIENT_CONTROL_QUEUE_CAPACITY);
    let (result_tx, mut result_rx) = mpsc::channel(CLIENT_RESULT_QUEUE_CAPACITY);
    state.clients.lock().await.insert(
        client_id,
        ClientHandle {
            code_id: test_code_id("result-client"),
            username: "Alice".to_string(),
            platform: ClientPlatform::Android,
            tx,
            control_tx,
            result_tx,
            queued_bytes: Arc::new(AtomicUsize::new(0)),
        },
    );

    let result_task = tokio::spawn({
        let state = state.clone();
        async move { send_message_result(&state, client_id, "message-1", true).await }
    });
    let result = result_rx.recv().await.expect("dedicated result");
    assert!(matches!(
        result.frame,
        OutboundFrame::MessageResult {
            ref message_id,
            accepted: true
        } if message_id == "message-1"
    ));
    assert!(result.delivered.send(true).is_ok());
    assert!(result_task.await.expect("result task").is_ok());
}

#[tokio::test]
async fn ack_result_reports_success_and_rejection_on_the_dedicated_channel() {
    let state = test_state();
    let client_id = Uuid::new_v4();
    let (tx, _rx) = mpsc::channel(CLIENT_OUTBOUND_QUEUE_CAPACITY);
    let (control_tx, _control_rx) = mpsc::channel(CLIENT_CONTROL_QUEUE_CAPACITY);
    let (result_tx, mut result_rx) = mpsc::channel(CLIENT_RESULT_QUEUE_CAPACITY);
    state.clients.lock().await.insert(
        client_id,
        ClientHandle {
            code_id: test_code_id("ack-result-client"),
            username: "Alice".to_string(),
            platform: ClientPlatform::Android,
            tx,
            control_tx,
            result_tx,
            queued_bytes: Arc::new(AtomicUsize::new(0)),
        },
    );

    for (message_id, accepted) in [("ack-success", true), ("ack-rejected", false)] {
        let result_task = tokio::spawn({
            let state = state.clone();
            async move { send_ack_result(&state, client_id, message_id, accepted).await }
        });
        let result = result_rx.recv().await.expect("dedicated ack result");
        assert_eq!(
            serde_json::to_value(&result.frame).expect("ack result JSON"),
            serde_json::json!({
                "type": "ack_result",
                "message_id": message_id,
                "accepted": accepted,
            })
        );
        assert!(result.delivered.send(true).is_ok());
        assert!(result_task.await.expect("ack result task").is_ok());
    }
}

#[tokio::test]
async fn ack_result_sink_failure_closes_transport_but_preserves_session() {
    let state = test_state();
    let client_id = Uuid::new_v4();
    let code_id = test_code_id("ack-sink-failure");
    let (tx, _rx) = mpsc::channel(CLIENT_OUTBOUND_QUEUE_CAPACITY);
    let (control_tx, mut control_rx) = mpsc::channel(CLIENT_CONTROL_QUEUE_CAPACITY);
    let (result_tx, mut result_rx) = mpsc::channel(CLIENT_RESULT_QUEUE_CAPACITY);
    state.clients.lock().await.insert(
        client_id,
        ClientHandle {
            code_id,
            username: "Alice".to_string(),
            platform: ClientPlatform::Android,
            tx,
            control_tx,
            result_tx,
            queued_bytes: Arc::new(AtomicUsize::new(0)),
        },
    );
    state.sessions.lock().await.insert(
        SessionToken::new("ack-sink-token".to_string()),
        AuthSession {
            code_id,
            username: "Alice".to_string(),
            last_activity_ms: now_ms(),
        },
    );

    let result_task = tokio::spawn({
        let state = state.clone();
        async move { send_ack_result(&state, client_id, "ack-sink", true).await }
    });
    let result = result_rx.recv().await.expect("dedicated ack result");
    assert!(result.delivered.send(false).is_ok());
    assert!(result_task.await.expect("ack result task").is_err());
    assert_eq!(state.sessions.lock().await.len(), 1);
    assert!(matches!(control_rx.try_recv(), Ok(ClientControl::Close)));
}

#[tokio::test]
async fn rejected_safe_ack_reports_false_without_refreshing_activity() {
    let state = test_state();
    let client_id = Uuid::new_v4();
    let (tx, _rx) = mpsc::channel(CLIENT_OUTBOUND_QUEUE_CAPACITY);
    let (control_tx, _control_rx) = mpsc::channel(CLIENT_CONTROL_QUEUE_CAPACITY);
    let (result_tx, mut result_rx) = mpsc::channel(CLIENT_RESULT_QUEUE_CAPACITY);
    state.clients.lock().await.insert(
        client_id,
        ClientHandle {
            code_id: test_code_id("ack-activity"),
            username: "Alice".to_string(),
            platform: ClientPlatform::Android,
            tx,
            control_tx,
            result_tx,
            queued_bytes: Arc::new(AtomicUsize::new(0)),
        },
    );
    *state.last_activity_ms.lock().await = 123;
    let frame = serde_json::json!({
        "type": "message_ack",
        "chat_id": "",
        "message_id": "ack-rejected",
        "sender_username": "",
        "state_revision": 0,
        "identity_envelope_b64": "",
        "identity_public_b64": "",
        "prekey_id": "",
        "state_signature_b64": "",
        "ack_signature_b64": "",
        "used_prekey_id": "",
    });
    let handle_task = tokio::spawn({
        let state = state.clone();
        async move { handle_frame(&state, client_id, &frame.to_string()).await }
    });
    let result = result_rx.recv().await.expect("rejected ack result");
    assert!(matches!(
        result.frame,
        OutboundFrame::AckResult {
            ref message_id,
            accepted: false
        } if message_id == "ack-rejected"
    ));
    assert!(result.delivered.send(true).is_ok());
    assert!(handle_task.await.expect("frame task").is_err());
    assert_eq!(*state.last_activity_ms.lock().await, 123);
}

#[tokio::test]
async fn unsafe_ack_id_does_not_emit_a_result_or_refresh_activity() {
    let state = test_state();
    let client_id = Uuid::new_v4();
    let (tx, _rx) = mpsc::channel(CLIENT_OUTBOUND_QUEUE_CAPACITY);
    let (control_tx, _control_rx) = mpsc::channel(CLIENT_CONTROL_QUEUE_CAPACITY);
    let (result_tx, mut result_rx) = mpsc::channel(CLIENT_RESULT_QUEUE_CAPACITY);
    state.clients.lock().await.insert(
        client_id,
        ClientHandle {
            code_id: test_code_id("unsafe-ack"),
            username: "Alice".to_string(),
            platform: ClientPlatform::Android,
            tx,
            control_tx,
            result_tx,
            queued_bytes: Arc::new(AtomicUsize::new(0)),
        },
    );
    *state.last_activity_ms.lock().await = 123;
    let frame = serde_json::json!({
        "type": "message_ack",
        "chat_id": "",
        "message_id": "",
        "sender_username": "",
        "state_revision": 0,
        "identity_envelope_b64": "",
        "identity_public_b64": "",
        "prekey_id": "",
        "state_signature_b64": "",
        "ack_signature_b64": "",
        "used_prekey_id": "",
    });
    assert!(handle_frame(&state, client_id, &frame.to_string())
        .await
        .is_err());
    assert!(result_rx.try_recv().is_err());
    assert_eq!(*state.last_activity_ms.lock().await, 123);
}

#[tokio::test]
async fn accepted_ack_result_follows_atomic_state_and_pending_mutation() {
    let state = test_state();
    add_test_account(&state, "ack-atomic-sender", "Alice").await;
    add_test_account(&state, "ack-atomic-recipient", "Bob").await;
    let (alice_id, _) = add_test_client(&state, "ack-atomic-sender", "Alice").await;
    let bob_id = Uuid::new_v4();
    let (tx, _rx) = mpsc::channel(CLIENT_OUTBOUND_QUEUE_CAPACITY);
    let (control_tx, _control_rx) = mpsc::channel(CLIENT_CONTROL_QUEUE_CAPACITY);
    let (result_tx, mut result_rx) = mpsc::channel(CLIENT_RESULT_QUEUE_CAPACITY);
    state.clients.lock().await.insert(
        bob_id,
        ClientHandle {
            code_id: test_code_id("ack-atomic-recipient"),
            username: "Bob".to_string(),
            platform: ClientPlatform::Android,
            tx,
            control_tx,
            result_tx,
            queued_bytes: Arc::new(AtomicUsize::new(0)),
        },
    );
    let room = test_room("ack_result_atomic");
    state.room_catalog.lock().await.insert(
        room.id.clone(),
        RoomEntry {
            room: room.clone(),
            owner_code_id: test_code_id("ack-atomic-sender"),
        },
    );
    join_room(&state, alice_id, room.id.clone())
        .await
        .expect("Alice joins room");
    join_room(&state, bob_id, room.id.clone())
        .await
        .expect("Bob joins room");

    let message_id = "ack-atomic-message";
    route_test_message_with_id(&state, alice_id, &room.id, &["Bob"], message_id)
        .await
        .expect("message queues");
    assert!(state.pending.lock().await.contains_key(&PendingKey {
        chat_id: room.id.clone(),
        recipient_username: "Bob".to_string(),
    }));
    *state.last_activity_ms.lock().await = 123;

    let identity_envelope_b64 = test_identity_envelope_b64(0);
    let identity_public_b64 = test_identity_public_b64(b'B');
    let prekey_id = test_prekey_id(b'B');
    let frame = serde_json::json!({
        "type": "message_ack",
        "chat_id": room.id,
        "message_id": message_id,
        "sender_username": "Alice",
        "state_revision": 1,
        "identity_envelope_b64": identity_envelope_b64,
        "identity_public_b64": identity_public_b64,
        "prekey_id": prekey_id,
        "state_signature_b64": test_valid_state_signature_b64(
            b'B',
            1,
            &test_identity_envelope_b64(0),
            &test_identity_public_b64(b'B'),
            &test_prekey_id(b'B'),
        ),
        "ack_signature_b64": test_valid_ack_signature_b64(
            b'B',
            "ack_result_atomic",
            message_id,
            "Alice",
            "",
        ),
        "used_prekey_id": "",
    });
    let exact_frame = frame.to_string();
    let handle_task = tokio::spawn({
        let state = state.clone();
        let exact_frame = exact_frame.clone();
        async move { handle_frame(&state, bob_id, &exact_frame).await }
    });
    let result = result_rx.recv().await.expect("ack result");
    assert_eq!(
        serde_json::to_value(&result.frame).expect("ack result JSON"),
        serde_json::json!({
            "type": "ack_result",
            "message_id": message_id,
            "accepted": true,
        })
    );
    // The result is not enqueued until acknowledge_message has committed
    // both the signed state and pending-frame removal.
    assert!(state.pending.lock().await.is_empty());
    assert_eq!(*state.pending_bytes.lock().await, 0);
    assert_eq!(
        state
            .accounts
            .lock()
            .await
            .get(&test_code_id("ack-atomic-recipient"))
            .expect("Bob account")
            .state_revision,
        1
    );
    assert!(result.delivered.send(true).is_ok());
    assert!(handle_task.await.expect("ACK handler").is_ok());
    assert!(*state.last_activity_ms.lock().await > 123);

    let replay_task = tokio::spawn({
        let state = state.clone();
        let exact_frame = exact_frame.clone();
        async move { handle_frame(&state, bob_id, &exact_frame).await }
    });
    let replay = result_rx.recv().await.expect("replayed ack result");
    assert!(matches!(
        replay.frame,
        OutboundFrame::AckResult {
            ref message_id,
            accepted: true
        } if message_id == "ack-atomic-message"
    ));
    assert!(state.pending.lock().await.is_empty());
    assert_eq!(
        state
            .accounts
            .lock()
            .await
            .get(&test_code_id("ack-atomic-recipient"))
            .expect("Bob account")
            .state_revision,
        1
    );
    assert!(replay.delivered.send(true).is_ok());
    assert!(replay_task.await.expect("replayed ACK handler").is_ok());
}

#[tokio::test]
async fn ack_result_queue_overflow_closes_transport_but_preserves_session() {
    let state = test_state();
    let client_id = Uuid::new_v4();
    let code_id = test_code_id("ack-queue-overflow");
    let (tx, _rx) = mpsc::channel(CLIENT_OUTBOUND_QUEUE_CAPACITY);
    let (control_tx, mut control_rx) = mpsc::channel(CLIENT_CONTROL_QUEUE_CAPACITY);
    let (result_tx, result_rx) = mpsc::channel(CLIENT_RESULT_QUEUE_CAPACITY);
    state.clients.lock().await.insert(
        client_id,
        ClientHandle {
            code_id,
            username: "Alice".to_string(),
            platform: ClientPlatform::Android,
            tx,
            control_tx,
            result_tx: result_tx.clone(),
            queued_bytes: Arc::new(AtomicUsize::new(0)),
        },
    );
    state.sessions.lock().await.insert(
        SessionToken::new("ack-queue-token".to_string()),
        AuthSession {
            code_id,
            username: "Alice".to_string(),
            last_activity_ms: now_ms(),
        },
    );
    for index in 0..CLIENT_RESULT_QUEUE_CAPACITY {
        let (delivered, _completion) = oneshot::channel();
        result_tx
            .try_send(ClientResult {
                frame: OutboundFrame::AckResult {
                    message_id: format!("queued-{index}"),
                    accepted: false,
                },
                delivered,
            })
            .expect("result queue capacity");
    }

    let error = send_ack_result(&state, client_id, "overflow", true)
        .await
        .expect_err("full result queue must fail closed");
    assert_eq!(error, "client result channel unavailable");
    assert_eq!(result_rx.len(), CLIENT_RESULT_QUEUE_CAPACITY);
    assert_eq!(state.sessions.lock().await.len(), 1);
    assert!(matches!(control_rx.try_recv(), Ok(ClientControl::Close)));
}

#[tokio::test]
async fn purge_epoch_changes_even_when_no_control_slot_is_available() {
    let state = test_state();
    let mut purge_rx = state.purge_epoch.subscribe();
    let (control_tx, _control_rx) = mpsc::channel(CLIENT_CONTROL_QUEUE_CAPACITY);
    let _ = control_tx.try_send(ClientControl::Close);
    wipe_relay_state(&state, false).await;
    assert!(purge_rx.changed().await.is_ok());
    assert_eq!(*purge_rx.borrow(), 1);
}

#[tokio::test]
async fn deleting_room_releases_prekey_leases() {
    let state = test_state();
    add_test_account(&state, "code-a", "Alice").await;
    let (alice_id, _) = add_test_client(&state, "code-a", "Alice").await;
    let room = test_room("forum_claim_cleanup");
    state.room_catalog.lock().await.insert(
        room.id.clone(),
        RoomEntry {
            room: room.clone(),
            owner_code_id: test_code_id("code-a"),
        },
    );

    let removed_prekey_id = test_prekey_id(b'B');
    let retained_prekey_id = test_prekey_id(b'C');
    let removed_key = PrekeyLeaseKey {
        code_id: test_code_id("code-b"),
        prekey_id: removed_prekey_id.clone(),
    };
    let retained_key = PrekeyLeaseKey {
        code_id: test_code_id("code-c"),
        prekey_id: retained_prekey_id.clone(),
    };
    let claim = |recipient_username: &str| PrekeyLease {
        chat_id: room.id.clone(),
        message_id: "message-1".to_string(),
        sender_username: "Alice".to_string(),
        recipient_username: recipient_username.to_string(),
        created_at_ms: now_ms(),
    };
    state.prekey_leases.lock().await.extend([
        (removed_key.clone(), claim("Bob")),
        (retained_key.clone(), claim("Carol")),
    ]);
    state.pending.lock().await.insert(
        PendingKey {
            chat_id: room.id.clone(),
            recipient_username: "Bob".to_string(),
        },
        vec![PendingFrame::new(
            test_message_frame(&room.id, "message-1", "Alice", &removed_prekey_id, true),
            now_ms(),
        )],
    );
    let attachment_id = Uuid::new_v4();
    state.attachments.lock().await.insert(
        attachment_id,
        AttachmentRecord {
            blob: test_attachment_blob(vec![1, 2, 3]),
            chat_id: room.id.clone(),
            message_id: "test-message".to_string(),
            media_type: "FILE".to_string(),
            owner_code_id: test_code_id("code-a"),
            sender_platform: ClientPlatform::Android,
            published: true,
            staged_expires_at_ms: None,
            one_time: false,
            delete_after_download: false,
            expires_at_ms: None,
            eligible_recipient_code_ids: HashSet::new(),
            download_claims: HashMap::new(),
            completed_recipient_code_ids: HashSet::new(),
        },
    );
    state
        .attachment_bytes_by_code
        .lock()
        .await
        .insert(test_code_id("code-a"), 3);

    delete_room(&state, alice_id, &room.id)
        .await
        .expect("owner can delete room");
    let claims = state.prekey_leases.lock().await;
    assert!(!claims.contains_key(&removed_key));
    assert!(!claims.contains_key(&retained_key));
    drop(claims);
    assert!(state.attachments.lock().await.is_empty());
    assert!(state.attachment_bytes_by_code.lock().await.is_empty());
}

#[test]
fn identity_bundle_rejects_empty_prekey_id_and_zero_one_time_key() {
    let public = test_identity_public(7);
    let prekey_id = test_prekey_id(7);
    assert!(valid_identity_public_bundle(&public, &prekey_id));
    assert!(!valid_identity_public_bundle(&public, ""));

    let mut zero_one_time = public;
    zero_one_time[ONE_TIME_KEY_OFFSET..FALLBACK_KEY_OFFSET].fill(0);
    assert!(!valid_identity_public_bundle(&zero_one_time, &prekey_id));
}

#[test]
fn relay_registration_validation_rejects_low_order_keys_in_every_x25519_slot() {
    let valid = test_identity_public(b'A');
    let prekey_id = test_prekey_id(b'A');
    assert!(valid_identity_public_bundle(&valid, &prekey_id));

    for range in [
        0..32,
        ONE_TIME_KEY_OFFSET..FALLBACK_KEY_OFFSET,
        FALLBACK_KEY_OFFSET..IDENTITY_PUBLIC_BYTES,
    ] {
        let mut malformed = valid.clone();
        malformed[range.clone()].fill(0);
        malformed[range.start] = 1;
        assert!(
            !valid_identity_public_bundle(&malformed, &prekey_id),
            "relay registration accepted a low-order key in {:?}",
            range
        );
    }
}

#[tokio::test]
async fn registration_endpoint_rejects_low_order_fallback_before_consuming_code() {
    let state = test_state();
    let code = "ABCD-12345678";
    let code_id = test_code_id(code);
    state.available_codes.lock().await.insert(code_id);
    let password = b"correct horse battery staple".to_vec();
    let start = abyssal_core::secure_protocol::opaque_client_start(password.clone())
        .expect("OPAQUE client start");
    let response = abyssal_core::secure_protocol::opaque_server_registration_response(
        &state.opaque_setup,
        &start.registration_request,
        code.as_bytes(),
    )
    .expect("OPAQUE server response");
    let finish = abyssal_core::secure_protocol::opaque_client_finish_registration(
        password,
        start.registration_state,
        response,
    )
    .expect("OPAQUE client finish");
    let valid = test_identity_public(b'A');
    let mut low_order_fallback = valid;
    low_order_fallback[FALLBACK_KEY_OFFSET..IDENTITY_PUBLIC_BYTES].fill(0);
    low_order_fallback[FALLBACK_KEY_OFFSET] = 1;
    let handshake_id = Uuid::new_v4();
    state.opaque_handshakes.lock().await.insert(
        handshake_id,
        OpaqueHandshake::Registration {
            code_id,
            challenge: Zeroizing::new(vec![0; REGISTRATION_CHALLENGE_BYTES_V9]),
            created_at_ms: now_ms(),
        },
    );

    let response = finish_opaque_account(
        State(state.clone()),
        Json(OpaqueAccountFinishRequest {
            handshake_id,
            registration_upload_b64: Some(URL_SAFE_NO_PAD.encode(finish.registration_upload)),
            credential_finalization_b64: None,
            identity_public_b64: Some(URL_SAFE_NO_PAD.encode(low_order_fallback)),
            identity_prekey_id: Some(test_prekey_id(b'A')),
            identity_envelope_b64: Some(URL_SAFE_NO_PAD.encode({
                let mut envelope = [0_u8; 256];
                envelope[0] = IDENTITY_ENVELOPE_VERSION;
                envelope
            })),
            // The proof only needs to satisfy the mode-exclusive request
            // shape here. The malformed fallback key must be rejected
            // before proof verification, without consuming the code.
            identity_proof_b64: Some(URL_SAFE_NO_PAD.encode([0_u8; MESSAGE_SIGNATURE_BYTES])),
        }),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(state.accounts.lock().await.is_empty());
    assert!(state.available_codes.lock().await.contains(&code_id));
}

#[tokio::test]
async fn registration_identity_proof_rejects_copied_key_and_tampering() {
    let state = test_state();
    let code = "ABCD-12345678";
    let code_id = test_code_id(code);
    state.available_codes.lock().await.insert(code_id);
    let password = b"correct horse battery staple".to_vec();
    let start = abyssal_core::secure_protocol::opaque_client_start(password.clone())
        .expect("OPAQUE client start");
    let response = opaque_server_registration_response(
        &state.opaque_setup,
        &start.registration_request,
        code.as_bytes(),
    )
    .expect("OPAQUE server response");
    let finish = abyssal_core::secure_protocol::opaque_client_finish_registration(
        password,
        start.registration_state,
        response,
    )
    .expect("OPAQUE client finish");
    let owner =
        abyssal_core::secure_protocol::E2eeSession::create(vec![71; 64]).expect("owner identity");
    let attacker = abyssal_core::secure_protocol::E2eeSession::create(vec![72; 64])
        .expect("attacker identity");
    let owner_public = owner.public_key();
    let owner_prekey = owner.prekey_id();
    let owner_envelope = owner
        .seal_identity(vec![71; 64], b"registration-context".to_vec())
        .expect("owner envelope");
    let challenge = vec![17; REGISTRATION_CHALLENGE_BYTES_V9];
    let handshake_id = Uuid::new_v4();
    state.opaque_handshakes.lock().await.insert(
        handshake_id,
        OpaqueHandshake::Registration {
            code_id,
            challenge: Zeroizing::new(challenge.clone()),
            created_at_ms: now_ms(),
        },
    );
    let copied_proof = attacker
        .sign_registration_identity_proof(
            state.node_id.clone(),
            handshake_id.to_string(),
            challenge,
            finish.registration_upload.clone(),
            owner_public.clone(),
            owner_prekey.clone(),
            owner_envelope.clone(),
        )
        .expect("copied-key proof");
    let response = finish_opaque_account(
        State(state.clone()),
        Json(OpaqueAccountFinishRequest {
            handshake_id,
            registration_upload_b64: Some(URL_SAFE_NO_PAD.encode(&finish.registration_upload)),
            credential_finalization_b64: None,
            identity_public_b64: Some(URL_SAFE_NO_PAD.encode(&owner_public)),
            identity_prekey_id: Some(owner_prekey),
            identity_envelope_b64: Some(URL_SAFE_NO_PAD.encode(&owner_envelope)),
            identity_proof_b64: Some(URL_SAFE_NO_PAD.encode(copied_proof)),
        }),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(state.accounts.lock().await.is_empty());
    assert!(state.available_codes.lock().await.contains(&code_id));
}

#[tokio::test]
async fn registration_identity_proof_accepts_once_and_replay_fails() {
    let state = test_state();
    let code = "ABCD-12345678";
    let code_id = test_code_id(code);
    state.available_codes.lock().await.insert(code_id);
    let password = b"correct horse battery staple".to_vec();
    let start = abyssal_core::secure_protocol::opaque_client_start(password.clone())
        .expect("OPAQUE client start");
    let response = opaque_server_registration_response(
        &state.opaque_setup,
        &start.registration_request,
        code.as_bytes(),
    )
    .expect("OPAQUE server response");
    let finish = abyssal_core::secure_protocol::opaque_client_finish_registration(
        password,
        start.registration_state,
        response,
    )
    .expect("OPAQUE client finish");
    let session =
        abyssal_core::secure_protocol::E2eeSession::create(vec![73; 64]).expect("identity");
    let public = session.public_key();
    let prekey_id = session.prekey_id();
    let envelope = session
        .seal_identity(vec![73; 64], b"registration-context".to_vec())
        .expect("identity envelope");
    let challenge = vec![18; REGISTRATION_CHALLENGE_BYTES_V9];
    let handshake_id = Uuid::new_v4();
    state.opaque_handshakes.lock().await.insert(
        handshake_id,
        OpaqueHandshake::Registration {
            code_id,
            challenge: Zeroizing::new(challenge.clone()),
            created_at_ms: now_ms(),
        },
    );
    let proof = session
        .sign_registration_identity_proof(
            state.node_id.clone(),
            handshake_id.to_string(),
            challenge,
            finish.registration_upload.clone(),
            public.clone(),
            prekey_id.clone(),
            envelope.clone(),
        )
        .expect("identity proof");
    let request = OpaqueAccountFinishRequest {
        handshake_id,
        registration_upload_b64: Some(URL_SAFE_NO_PAD.encode(&finish.registration_upload)),
        credential_finalization_b64: None,
        identity_public_b64: Some(URL_SAFE_NO_PAD.encode(&public)),
        identity_prekey_id: Some(prekey_id),
        identity_envelope_b64: Some(URL_SAFE_NO_PAD.encode(&envelope)),
        identity_proof_b64: Some(URL_SAFE_NO_PAD.encode(&proof)),
    };
    let response = finish_opaque_account(State(state.clone()), Json(request))
        .await
        .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(state.accounts.lock().await.contains_key(&code_id));
    assert!(!state.available_codes.lock().await.contains(&code_id));

    let replay = finish_opaque_account(
        State(state.clone()),
        Json(OpaqueAccountFinishRequest {
            handshake_id,
            registration_upload_b64: None,
            credential_finalization_b64: None,
            identity_public_b64: None,
            identity_prekey_id: None,
            identity_envelope_b64: None,
            identity_proof_b64: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn identity_state_update_rejects_low_order_fallback_without_mutating_account() {
    let state = test_state();
    add_test_account(&state, "code-a", "Alice").await;
    let code_id = test_code_id("code-a");
    let (valid, prekey_id, previous_revision) = {
        let accounts = state.accounts.lock().await;
        let account = accounts.get(&code_id).expect("Alice account");
        (
            account.identity_public.clone(),
            account.prekey_id.clone(),
            account.state_revision,
        )
    };
    let mut low_order_fallback = valid.clone();
    low_order_fallback[FALLBACK_KEY_OFFSET..IDENTITY_PUBLIC_BYTES].fill(0);
    low_order_fallback[FALLBACK_KEY_OFFSET] = 1;

    let result = apply_identity_state(
        &state,
        &code_id,
        previous_revision + 1,
        &URL_SAFE_NO_PAD.encode({
            let mut envelope = [0_u8; 256];
            envelope[0] = IDENTITY_ENVELOPE_VERSION;
            envelope
        }),
        &URL_SAFE_NO_PAD.encode(low_order_fallback),
        &prekey_id,
        &test_signature_b64(0),
        true,
    )
    .await;
    assert!(result.is_err());

    let accounts = state.accounts.lock().await;
    let account = accounts.get(&code_id).expect("Alice account");
    assert_eq!(account.state_revision, previous_revision);
    assert_eq!(account.identity_public, valid);
    assert_eq!(account.prekey_id, prekey_id);
}

#[tokio::test]
async fn fanout_rejects_low_order_sender_bundle_before_recipient_delivery() {
    let state = test_state();
    add_test_account(&state, "code-a", "Alice").await;
    add_test_account(&state, "code-b", "Bob").await;
    let (alice_id, _) = add_test_client(&state, "code-a", "Alice").await;
    let (bob_id, mut bob_rx) = add_test_client(&state, "code-b", "Bob").await;
    open_direct(&state, alice_id, "Bob")
        .await
        .expect("direct should open");
    let direct_id = state
        .direct_catalog
        .lock()
        .await
        .values()
        .next()
        .expect("direct")
        .id
        .clone();
    join_room(&state, alice_id, direct_id.clone())
        .await
        .expect("Alice joins direct");
    join_room(&state, bob_id, direct_id.clone())
        .await
        .expect("Bob joins direct");
    while bob_rx.try_recv().is_ok() {}

    let (valid, prekey_id) = {
        let accounts = state.accounts.lock().await;
        let account = accounts
            .get(&test_code_id("code-a"))
            .expect("Alice account");
        (account.identity_public.clone(), account.prekey_id.clone())
    };
    let mut low_order_fallback = valid.clone();
    low_order_fallback[FALLBACK_KEY_OFFSET..IDENTITY_PUBLIC_BYTES].fill(0);
    low_order_fallback[FALLBACK_KEY_OFFSET] = 1;

    let result = route_encrypted_message(
        &state,
        alice_id,
        direct_id,
        E2EE_PROTOCOL_VERSION,
        "low-order-fanout".to_string(),
        URL_SAFE_NO_PAD.encode([2_u8; MESSAGE_NONCE_BYTES]),
        URL_SAFE_NO_PAD.encode(b"ciphertext"),
        Vec::new(),
        1,
        URL_SAFE_NO_PAD.encode({
            let mut envelope = [0_u8; 256];
            envelope[0] = IDENTITY_ENVELOPE_VERSION;
            envelope
        }),
        URL_SAFE_NO_PAD.encode(low_order_fallback),
        prekey_id,
        test_signature_b64(0),
    )
    .await;
    assert!(result.is_err());
    assert!(bob_rx.try_recv().is_err());
    assert!(state.pending.lock().await.is_empty());
}

#[tokio::test]
async fn expired_attachment_pruning_decrements_owner_usage() {
    let mut state = test_state();
    state.attachment_record_limit = 1;
    state.attachment_account_record_limit = 1;
    let owner = test_code_id("code-a");
    let attachment_id = Uuid::new_v4();
    state.attachments.lock().await.insert(
        attachment_id,
        AttachmentRecord {
            blob: test_attachment_blob(vec![1, 2, 3]),
            chat_id: "dm_alice_bob".to_string(),
            message_id: "test-message".to_string(),
            media_type: "FILE".to_string(),
            owner_code_id: owner,
            sender_platform: ClientPlatform::Android,
            published: true,
            staged_expires_at_ms: None,
            one_time: false,
            delete_after_download: false,
            expires_at_ms: Some(0),
            eligible_recipient_code_ids: HashSet::new(),
            download_claims: HashMap::new(),
            completed_recipient_code_ids: HashSet::new(),
        },
    );
    state.attachment_bytes_by_code.lock().await.insert(owner, 3);
    {
        let attachments = state.attachments.lock().await;
        assert!(!attachment_record_capacity_allows(
            attachments.len(),
            current_attachment_records_for_owner(&attachments, &owner),
            state.attachment_record_limit,
            state.attachment_account_record_limit,
        ));
    }

    prune_expired_attachments(&state).await;
    assert!(state.attachments.lock().await.is_empty());
    assert!(state.attachment_bytes_by_code.lock().await.is_empty());
    assert!(attachment_record_capacity_available(&state, &owner).await);
}

#[tokio::test]
async fn expired_claimed_attachment_waits_for_claim_release() {
    let state = test_state();
    let owner = test_code_id("claimed-expired-owner");
    let recipient = test_code_id("claimed-expired-recipient");
    let attachment_id = Uuid::new_v4();
    state.attachments.lock().await.insert(
        attachment_id,
        AttachmentRecord {
            blob: test_attachment_blob(vec![4, 5, 6]),
            chat_id: "dm_alice_bob".to_string(),
            message_id: "test-message".to_string(),
            media_type: "FILE".to_string(),
            owner_code_id: owner,
            sender_platform: ClientPlatform::Android,
            published: true,
            staged_expires_at_ms: None,
            one_time: true,
            delete_after_download: false,
            expires_at_ms: Some(0),
            eligible_recipient_code_ids: HashSet::from([recipient]),
            download_claims: HashMap::from([(
                Uuid::new_v4(),
                AttachmentDownloadClaim {
                    recipient_code_id: recipient,
                    created_at_ms: now_ms(),
                },
            )]),
            completed_recipient_code_ids: HashSet::new(),
        },
    );
    state.attachment_bytes_by_code.lock().await.insert(owner, 3);
    let claim_id = state
        .attachments
        .lock()
        .await
        .get(&attachment_id)
        .and_then(|record| record.download_claims.keys().next().copied())
        .expect("claim id");

    prune_expired_attachments(&state).await;
    assert!(state.attachments.lock().await.contains_key(&attachment_id));
    assert_eq!(
        state.attachment_bytes_by_code.lock().await.get(&owner),
        Some(&3)
    );
    assert!(matches!(
        reserve_attachment_download(&state, attachment_id, &recipient).await,
        Err(StatusCode::TOO_MANY_REQUESTS)
    ));

    release_attachment_download_claim(&state, attachment_id, &recipient, claim_id)
        .await
        .expect("release expired claim");
    prune_expired_attachments(&state).await;
    assert!(!state.attachments.lock().await.contains_key(&attachment_id));
    assert!(state.attachment_bytes_by_code.lock().await.is_empty());
}

#[tokio::test]
async fn identity_directory_checkpoint_is_order_independent_and_long_term_bound() {
    let state = test_state();
    add_test_account(&state, "code-a", "Alice").await;
    add_test_account(&state, "code-b", "Bob").await;
    let first = {
        let accounts = state.accounts.lock().await;
        identity_directory_digest(&accounts)
    };
    {
        let mut accounts = state.accounts.lock().await;
        let bob_id = test_code_id("code-b");
        accounts.get_mut(&bob_id).expect("Bob").prekey_id = "rotated-key".to_string();
    }
    let after_prekey_rotation = {
        let accounts = state.accounts.lock().await;
        identity_directory_digest(&accounts)
    };
    assert_eq!(first, after_prekey_rotation);
    {
        let mut accounts = state.accounts.lock().await;
        let bob_id = test_code_id("code-b");
        accounts.get_mut(&bob_id).expect("Bob").identity_public[0] ^= 1;
    }
    let after_identity_change = {
        let accounts = state.accounts.lock().await;
        identity_directory_digest(&accounts)
    };
    assert_ne!(first, after_identity_change);
}

#[tokio::test]
async fn directory_checkpoint_v2_binds_node_revision_and_rejects_stale_evidence() {
    let state = test_state();
    add_test_account(&state, "directory-a", "Alice").await;
    let first = current_directory_evidence(&state).await;
    assert_eq!(first.node_id, state.node_id);
    assert_eq!(first.revision, 1);
    assert_eq!(
        validate_directory_evidence(&state, Some(first.clone())).await,
        Ok(first.clone())
    );

    {
        let mut accounts = state.accounts.lock().await;
        accounts
            .get_mut(&test_code_id("directory-a"))
            .expect("Alice")
            .connected = false;
    }
    assert_eq!(current_directory_evidence(&state).await, first);

    add_test_account(&state, "directory-b", "Bob").await;
    let second = current_directory_evidence(&state).await;
    assert_eq!(second.revision, 2);
    assert_ne!(second.digest, first.digest);
    assert!(validate_directory_evidence(&state, Some(first))
        .await
        .is_err());
    assert!(validate_directory_evidence(&state, None).await.is_err());
    assert_eq!(
        validate_directory_evidence(&state, Some(second.clone())).await,
        Ok(second.clone())
    );
    for malformed in [
        DirectoryStamp {
            node_id: "node with spaces".to_string(),
            ..second.clone()
        },
        DirectoryStamp {
            revision: 0,
            ..second.clone()
        },
        DirectoryStamp {
            digest: format!("{}=", second.digest),
            ..second.clone()
        },
    ] {
        assert!(validate_directory_evidence(&state, Some(malformed))
            .await
            .is_err());
    }

    let accounts = state.accounts.lock().await;
    let other_node = directory_stamp_at_revision("other-node", second.revision, &accounts);
    assert_ne!(other_node.digest, second.digest);
}

#[tokio::test]
async fn concurrent_presence_broadcasts_emit_only_post_lock_directory_snapshots() {
    let state = test_state();
    add_test_account(&state, "presence-a", "Alice").await;
    let (_, mut receiver) = add_test_client(&state, "presence-a", "Alice").await;
    let guard = state.presence_broadcast_ops.lock().await;

    let first_state = state.clone();
    let first = tokio::spawn(async move { broadcast_presence(&first_state).await });
    tokio::task::yield_now().await;
    add_test_account(&state, "presence-b", "Bob").await;
    let second_state = state.clone();
    let second = tokio::spawn(async move { broadcast_presence(&second_state).await });
    tokio::task::yield_now().await;
    drop(guard);

    first.await.expect("first broadcast");
    second.await.expect("second broadcast");
    for _ in 0..2 {
        let frame = receiver.recv().await.expect("presence frame");
        let OutboundFrame::Presence { ref users } = frame else {
            panic!("expected presence frame");
        };
        assert_eq!(users.len(), 2);
        assert!(users.iter().all(|user| user.directory_revision == 2));
        assert_eq!(
            users
                .iter()
                .map(|user| user.directory_digest.as_str())
                .collect::<HashSet<_>>()
                .len(),
            1
        );
    }
}

#[test]
fn attachment_ttl_cannot_exceed_enforced_room_policy() {
    let mut room = test_room("forum_policy");
    room.enforce_text_absolute_expiry = true;
    room.overall_expiry_sec = 60;
    room.enforce_video_absolute_expiry = true;
    room.video_overall_expiry_sec = 20;
    let access = ConversationAccess::Room(room);

    assert_eq!(
        effective_attachment_ttl_sec(Some(100), &access, "VIDEO", 604_800),
        20
    );
    assert_eq!(
        effective_attachment_ttl_sec(None, &access, "VIDEO", 604_800),
        20
    );
    assert_eq!(
        effective_attachment_ttl_sec(Some(10), &access, "VIDEO", 604_800),
        10
    );
    assert_eq!(
        effective_attachment_ttl_sec(Some(u64::MAX), &ConversationAccess::Direct, "FILE", 604_800,),
        86_400
    );
    assert_eq!(
        effective_attachment_ttl_sec(None, &ConversationAccess::Direct, "FILE", 604_800),
        604_800
    );
    assert_eq!(
        effective_attachment_ttl_sec(Some(100), &ConversationAccess::Direct, "FILE", 60,),
        60
    );
}

#[test]
fn mls_attachment_policy_preserves_media_and_absolute_retention_rules() {
    let access = ConversationAccess::MlsRoom(rooms::RoomPolicy {
        allow_images: false,
        enforce_text_absolute_expiry: true,
        overall_expiry_sec: 60,
        enforce_video_absolute_expiry: true,
        video_overall_expiry_sec: 20,
        ..rooms::RoomPolicy::default()
    });
    assert!(!matches!(
        &access,
        ConversationAccess::MlsRoom(policy) if policy_allows_media(policy, "IMAGE")
    ));
    assert!(matches!(
        &access,
        ConversationAccess::MlsRoom(policy) if policy_allows_media(policy, "VIDEO")
    ));
    assert_eq!(
        effective_attachment_ttl_sec(Some(100), &access, "VIDEO", 604_800),
        20
    );
}

#[test]
fn mls_owner_join_notification_omits_private_recovery_envelope() {
    let frame = OutboundFrame::MlsJoinRequested {
        protocol_version: rooms::MLS_PROTOCOL_VERSION,
        room_id: "room-1".to_string(),
        request_id: "request-1".to_string(),
        username: "Bob".to_string(),
        stable_identity_b64: "identity".to_string(),
        key_package_b64: "key-package".to_string(),
    };
    let wire = serde_json::to_value(&frame).unwrap();
    assert_eq!(wire["type"], "mls_join_requested");
    assert!(wire.get("state_envelope_b64").is_none());
    assert!(wire.get("recovery_snapshot").is_none());
}

#[tokio::test]
async fn every_inbound_mls_frame_rejects_wrong_or_missing_protocol_version_first() {
    let frames = vec![
        serde_json::json!({"type":"mls_create_room","protocol_version":9,"room_id":"r","group_id_b64":"x","epoch":"0","revision":"0","membership_digest_b64":"x","stable_identity_b64":"x","state_envelope_b64":"x"}),
        serde_json::json!({"type":"mls_discover_room","protocol_version":9,"room_id":"r"}),
        serde_json::json!({"type":"mls_join_request","protocol_version":9,"room_id":"r","request_id":"q","stable_identity_b64":"x","key_package_b64":"x","state_envelope_b64":"x"}),
        serde_json::json!({"type":"mls_join_reject","protocol_version":9,"room_id":"r","request_id":"q"}),
        serde_json::json!({"type":"mls_leave_request","protocol_version":9,"room_id":"r","request_id":"q"}),
        serde_json::json!({"type":"mls_leave_reject","protocol_version":9,"room_id":"r","request_id":"q"}),
        serde_json::json!({"type":"mls_membership_commit","protocol_version":9,"room_id":"r","message_id":"m","request_id":null,"from_epoch":"0","to_epoch":"1","revision":"1","group_id_b64":"x","from_membership_digest_b64":"x","membership_digest_b64":"x","roster":[],"control_b64":"x","welcome_b64":"x","authenticated_data_b64":"x","state_envelope_b64":"x"}),
        serde_json::json!({"type":"mls_application","protocol_version":9,"room_id":"r","message_id":"m","group_id_b64":"x","epoch":"0","revision":"1","membership_digest_b64":"x","ciphertext_b64":"x","authenticated_data_b64":"x","state_envelope_b64":"x"}),
        serde_json::json!({"type":"mls_state_snapshot","protocol_version":9,"room_id":"r","message_id":"m","epoch":"0","revision":"0","membership_digest_b64":"x","state_envelope_b64":"x"}),
        serde_json::json!({"type":"mls_delete_room","protocol_version":9,"room_id":"r"}),
    ];
    let state = test_state();
    for frame in frames {
        let encoded = serde_json::to_string(&frame).unwrap();
        assert_eq!(
            handle_frame(&state, Uuid::new_v4(), &encoded)
                .await
                .unwrap_err(),
            "Wrong information"
        );
        let mut unknown = frame.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_string(), serde_json::json!(true));
        assert!(serde_json::from_value::<InboundFrame>(unknown).is_err());
        let mut missing = frame;
        missing.as_object_mut().unwrap().remove("protocol_version");
        assert!(serde_json::from_value::<InboundFrame>(missing).is_err());
    }
}

#[test]
fn protocol_v10_counters_and_policy_durations_are_decimal_strings() {
    let max = u64::MAX;
    let policy = rooms::RoomPolicy {
        self_destruct_timer_sec: max,
        overall_expiry_sec: max,
        image_read_timer_sec: max,
        image_overall_expiry_sec: max,
        video_read_timer_sec: max,
        video_overall_expiry_sec: max,
        file_read_timer_sec: max,
        file_overall_expiry_sec: max,
        ..rooms::RoomPolicy::default()
    };
    let room = MlsRoomWire {
        room_id: "room".to_string(),
        owner_username: "owner".to_string(),
        group_id_b64: "group".to_string(),
        active: true,
        synchronized: true,
        epoch: max,
        revision: max,
        membership_digest_b64: "digest".to_string(),
        roster: Vec::new(),
        recovery_snapshot: Some(MlsRecoverySnapshotWire {
            active: true,
            epoch: max,
            revision: max,
            membership_digest_b64: "digest".to_string(),
            state_envelope_b64: "state".to_string(),
            roster: vec![MlsRosterWire {
                username: "alice".to_string(),
                stable_identity_b64: "identity".to_string(),
            }],
        }),
        policy,
    };
    let wire = serde_json::to_value(OutboundFrame::MlsRoomCreated {
        protocol_version: rooms::MLS_PROTOCOL_VERSION,
        room: room.clone(),
    })
    .expect("MLS room JSON");
    let max_string = max.to_string();
    assert_eq!(wire["room"]["epoch"], max_string);
    assert_eq!(wire["room"]["revision"], max_string);
    assert_eq!(wire["room"]["recovery_snapshot"]["epoch"], max_string);
    assert_eq!(wire["room"]["recovery_snapshot"]["revision"], max_string);
    assert_eq!(wire["room"]["synchronized"], true);
    assert_eq!(
        wire["room"]["recovery_snapshot"]["roster"][0]["username"],
        "alice"
    );
    for field in [
        "self_destruct_timer_sec",
        "overall_expiry_sec",
        "image_read_timer_sec",
        "image_overall_expiry_sec",
        "video_read_timer_sec",
        "video_overall_expiry_sec",
        "file_read_timer_sec",
        "file_overall_expiry_sec",
    ] {
        assert_eq!(wire["room"]["policy"][field], max_string);
    }

    let inbound = serde_json::json!({
        "type": "mls_create_room",
        "protocol_version": rooms::MLS_PROTOCOL_VERSION,
        "room_id": "room",
        "group_id_b64": "group",
        "epoch": max_string,
        "revision": max_string,
        "membership_digest_b64": "digest",
        "stable_identity_b64": "identity",
        "state_envelope_b64": "state",
        "policy": wire["room"]["policy"].clone(),
    });
    assert!(serde_json::from_value::<InboundFrame>(inbound).is_ok());
}

#[test]
fn every_mls_counter_field_accepts_only_canonical_decimal_strings() {
    let max = u64::MAX;
    let max_string = max.to_string();
    let policy = rooms::RoomPolicy {
        self_destruct_timer_sec: max,
        overall_expiry_sec: max,
        image_read_timer_sec: max,
        image_overall_expiry_sec: max,
        video_read_timer_sec: max,
        video_overall_expiry_sec: max,
        file_read_timer_sec: max,
        file_overall_expiry_sec: max,
        ..rooms::RoomPolicy::default()
    };
    let policy_json = serde_json::to_value(policy).unwrap();
    let room = || MlsRoomWire {
        room_id: "room".to_string(),
        owner_username: "owner".to_string(),
        group_id_b64: "group".to_string(),
        active: true,
        synchronized: true,
        epoch: max,
        revision: max,
        membership_digest_b64: "digest".to_string(),
        roster: Vec::new(),
        recovery_snapshot: Some(MlsRecoverySnapshotWire {
            active: true,
            epoch: max,
            revision: max,
            membership_digest_b64: "digest".to_string(),
            state_envelope_b64: "state".to_string(),
            roster: Vec::new(),
        }),
        policy,
    };
    let outbound = vec![
        (
            OutboundFrame::MlsRooms {
                protocol_version: rooms::MLS_PROTOCOL_VERSION,
                rooms: vec![room()],
            },
            vec![
                "/rooms/0/epoch",
                "/rooms/0/revision",
                "/rooms/0/recovery_snapshot/epoch",
                "/rooms/0/recovery_snapshot/revision",
                "/rooms/0/policy/self_destruct_timer_sec",
                "/rooms/0/policy/overall_expiry_sec",
                "/rooms/0/policy/image_read_timer_sec",
                "/rooms/0/policy/image_overall_expiry_sec",
                "/rooms/0/policy/video_read_timer_sec",
                "/rooms/0/policy/video_overall_expiry_sec",
                "/rooms/0/policy/file_read_timer_sec",
                "/rooms/0/policy/file_overall_expiry_sec",
            ],
        ),
        (
            OutboundFrame::MlsRoomCreated {
                protocol_version: rooms::MLS_PROTOCOL_VERSION,
                room: room(),
            },
            vec![
                "/room/epoch",
                "/room/revision",
                "/room/recovery_snapshot/epoch",
                "/room/recovery_snapshot/revision",
                "/room/policy/self_destruct_timer_sec",
                "/room/policy/overall_expiry_sec",
                "/room/policy/image_read_timer_sec",
                "/room/policy/image_overall_expiry_sec",
                "/room/policy/video_read_timer_sec",
                "/room/policy/video_overall_expiry_sec",
                "/room/policy/file_read_timer_sec",
                "/room/policy/file_overall_expiry_sec",
            ],
        ),
        (
            OutboundFrame::MlsMembership {
                protocol_version: rooms::MLS_PROTOCOL_VERSION,
                room_id: "room".to_string(),
                message_id: "message".to_string(),
                from_epoch: max,
                to_epoch: max,
                revision: max,
                from_membership_digest_b64: "from".to_string(),
                group_id_b64: "group".to_string(),
                membership_digest_b64: "digest".to_string(),
                roster: Vec::new(),
                control_b64: "control".to_string(),
                welcome_b64: "welcome".to_string(),
                authenticated_data_b64: "aad".to_string(),
            },
            vec!["/from_epoch", "/to_epoch", "/revision"],
        ),
        (
            OutboundFrame::MlsApplication {
                protocol_version: rooms::MLS_PROTOCOL_VERSION,
                room_id: "room".to_string(),
                message_id: "message".to_string(),
                sender_username: "sender".to_string(),
                epoch: max,
                revision: max,
                membership_digest_b64: "digest".to_string(),
                ciphertext_b64: "ciphertext".to_string(),
                authenticated_data_b64: "aad".to_string(),
            },
            vec!["/epoch", "/revision"],
        ),
        (
            OutboundFrame::MlsRoomResult {
                protocol_version: rooms::MLS_PROTOCOL_VERSION,
                room_id: "room".to_string(),
                message_id: "message".to_string(),
                revision: max,
                accepted: true,
            },
            vec!["/revision"],
        ),
        (
            OutboundFrame::MlsSnapshotResult {
                protocol_version: rooms::MLS_PROTOCOL_VERSION,
                room_id: "room".to_string(),
                message_id: "message".to_string(),
                revision: max,
                accepted: true,
            },
            vec!["/revision"],
        ),
    ];
    for (frame, fields) in outbound {
        let wire = serde_json::to_value(frame).unwrap();
        for field in fields {
            assert_eq!(
                wire.pointer(field),
                Some(&serde_json::json!(max_string)),
                "{field}"
            );
        }
    }

    let inbound = vec![
        (
            serde_json::json!({
                "type": "mls_create_room",
                "protocol_version": rooms::MLS_PROTOCOL_VERSION,
                "room_id": "room",
                "group_id_b64": "group",
                "epoch": max_string,
                "revision": max_string,
                "membership_digest_b64": "digest",
                "stable_identity_b64": "identity",
                "state_envelope_b64": "state",
                "policy": policy_json,
            }),
            vec![
                "epoch",
                "revision",
                "policy.self_destruct_timer_sec",
                "policy.overall_expiry_sec",
                "policy.image_read_timer_sec",
                "policy.image_overall_expiry_sec",
                "policy.video_read_timer_sec",
                "policy.video_overall_expiry_sec",
                "policy.file_read_timer_sec",
                "policy.file_overall_expiry_sec",
            ],
        ),
        (
            serde_json::json!({
                "type": "mls_membership_commit",
                "protocol_version": rooms::MLS_PROTOCOL_VERSION,
                "room_id": "room",
                "message_id": "message",
                "request_id": null,
                "from_epoch": max_string,
                "to_epoch": max_string,
                "revision": max_string,
                "group_id_b64": "group",
                "from_membership_digest_b64": "from",
                "membership_digest_b64": "digest",
                "roster": [],
                "control_b64": "control",
                "welcome_b64": "welcome",
                "authenticated_data_b64": "aad",
                "state_envelope_b64": "state",
            }),
            vec!["from_epoch", "to_epoch", "revision"],
        ),
        (
            serde_json::json!({
                "type": "mls_application",
                "protocol_version": rooms::MLS_PROTOCOL_VERSION,
                "room_id": "room",
                "message_id": "message",
                "group_id_b64": "group",
                "epoch": max_string,
                "revision": max_string,
                "membership_digest_b64": "digest",
                "ciphertext_b64": "ciphertext",
                "authenticated_data_b64": "aad",
                "state_envelope_b64": "state",
            }),
            vec!["epoch", "revision"],
        ),
        (
            serde_json::json!({
                "type": "mls_state_snapshot",
                "protocol_version": rooms::MLS_PROTOCOL_VERSION,
                "room_id": "room",
                "message_id": "message",
                "epoch": max_string,
                "revision": max_string,
                "membership_digest_b64": "digest",
                "state_envelope_b64": "state",
            }),
            vec!["epoch", "revision"],
        ),
    ];
    let invalid_values = [
        serde_json::json!(1),
        serde_json::json!("01"),
        serde_json::json!("+1"),
        serde_json::json!("-1"),
        serde_json::json!(" 1"),
        serde_json::json!("1 "),
        serde_json::json!("not-a-number"),
        serde_json::json!("18446744073709551616"),
    ];
    for (frame, fields) in inbound {
        let parsed = serde_json::from_value::<InboundFrame>(frame.clone());
        assert!(parsed.is_ok(), "{frame}: {:?}", parsed.err());
        for field in fields {
            for invalid in &invalid_values {
                let mut rejected = frame.clone();
                let mut cursor = &mut rejected;
                for segment in field.split('.') {
                    cursor = cursor
                        .get_mut(segment)
                        .unwrap_or_else(|| panic!("missing JSON field {field}"));
                }
                *cursor = invalid.clone();
                assert!(
                    serde_json::from_value::<InboundFrame>(rejected).is_err(),
                    "accepted invalid {invalid} for {field}"
                );
            }
        }
    }
}

#[test]
fn non_mls_counters_remain_json_numbers() {
    let outbound = OutboundFrame::Message {
        chat_id: "chat".to_string(),
        version: 9,
        message_id: "message".to_string(),
        nonce_b64: "nonce".to_string(),
        ciphertext_b64: "ciphertext".to_string(),
        signature_b64: "signature".to_string(),
        wrapped_key_b64: "wrapped".to_string(),
        prekey_id: "prekey".to_string(),
        is_prekey: false,
        sender_username: "sender".to_string(),
        sender_public_key_b64: "public".to_string(),
        identity_public_b64: "identity".to_string(),
        directory_node_id: "node".to_string(),
        directory_revision: u64::MAX,
        directory_digest: "digest".to_string(),
        padding_bucket: 1,
        padding: "padding".to_string(),
    };
    let wire = serde_json::to_value(outbound).unwrap();
    assert!(wire["directory_revision"].is_u64());

    let inbound = serde_json::json!({
        "type": "message",
        "chat_id": "chat",
        "version": 9,
        "message_id": "message",
        "nonce_b64": "nonce",
        "ciphertext_b64": "ciphertext",
        "envelopes": [],
        "state_revision": u64::MAX,
        "identity_envelope_b64": "identity-envelope",
        "identity_public_b64": "identity",
        "prekey_id": "prekey",
        "state_signature_b64": "state-signature",
        "directory_node_id": "node",
        "directory_revision": u64::MAX,
        "directory_digest": "digest",
        "padding_bucket": 1,
        "padding": "padding",
    });
    assert!(serde_json::from_value::<InboundFrame>(inbound).is_ok());
}

#[test]
fn mls_create_room_omitted_policy_uses_default_policy() {
    let frame = serde_json::json!({
        "type": "mls_create_room",
        "protocol_version": rooms::MLS_PROTOCOL_VERSION,
        "room_id": "room",
        "group_id_b64": "group",
        "epoch": "0",
        "revision": "0",
        "membership_digest_b64": "digest",
        "stable_identity_b64": "identity",
        "state_envelope_b64": "state",
    });
    let InboundFrame::MlsCreateRoom { policy, .. } =
        serde_json::from_value(frame).expect("MLS create room")
    else {
        panic!("expected MLS create room frame");
    };
    assert_eq!(policy, rooms::RoomPolicy::default());
}

#[test]
fn mls_create_room_rejects_unknown_nested_policy_fields() {
    let frame = serde_json::json!({
        "type": "mls_create_room",
        "protocol_version": rooms::MLS_PROTOCOL_VERSION,
        "room_id": "room-1",
        "group_id_b64": "group",
        "epoch": "0",
        "revision": "0",
        "membership_digest_b64": "digest",
        "stable_identity_b64": "identity",
        "state_envelope_b64": "state",
        "policy": {"unexpected": true}
    });

    assert!(serde_json::from_value::<InboundFrame>(frame).is_err());
}

#[test]
fn every_outbound_mls_frame_carries_protocol_v10() {
    let room = || MlsRoomWire {
        room_id: "room-1".to_string(),
        owner_username: "Alice".to_string(),
        group_id_b64: "group".to_string(),
        active: true,
        synchronized: true,
        epoch: 1,
        revision: 1,
        membership_digest_b64: "digest".to_string(),
        roster: Vec::new(),
        recovery_snapshot: None,
        policy: rooms::RoomPolicy::default(),
    };
    let frames = vec![
        OutboundFrame::MlsRooms {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            rooms: vec![room()],
        },
        OutboundFrame::MlsRoomDiscovered {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id: "r".to_string(),
            group_id_b64: "g".to_string(),
            owner_username: "u".to_string(),
        },
        OutboundFrame::MlsRoomCreated {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room: room(),
        },
        OutboundFrame::MlsJoinRequested {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id: "r".to_string(),
            request_id: "q".to_string(),
            username: "u".to_string(),
            stable_identity_b64: "s".to_string(),
            key_package_b64: "k".to_string(),
        },
        OutboundFrame::MlsJoinRejected {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id: "r".to_string(),
            request_id: "q".to_string(),
        },
        OutboundFrame::MlsLeaveRequested {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id: "r".to_string(),
            request_id: "q".to_string(),
            username: "u".to_string(),
            stable_identity_b64: "s".to_string(),
        },
        OutboundFrame::MlsLeavePending {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id: "r".to_string(),
            request_id: "q".to_string(),
        },
        OutboundFrame::MlsLeaveRejected {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id: "r".to_string(),
            request_id: "q".to_string(),
        },
        OutboundFrame::MlsLeft {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id: "r".to_string(),
        },
        OutboundFrame::MlsMembership {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id: "r".to_string(),
            message_id: "m".to_string(),
            from_epoch: 0,
            to_epoch: 1,
            revision: 1,
            group_id_b64: "g".to_string(),
            from_membership_digest_b64: "f".to_string(),
            membership_digest_b64: "d".to_string(),
            roster: Vec::new(),
            control_b64: "c".to_string(),
            welcome_b64: "w".to_string(),
            authenticated_data_b64: "a".to_string(),
        },
        OutboundFrame::MlsApplication {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id: "r".to_string(),
            message_id: "m".to_string(),
            sender_username: "u".to_string(),
            epoch: 1,
            revision: 1,
            membership_digest_b64: "d".to_string(),
            ciphertext_b64: "c".to_string(),
            authenticated_data_b64: "a".to_string(),
        },
        OutboundFrame::MlsRoomResult {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id: "r".to_string(),
            message_id: "m".to_string(),
            revision: 1,
            accepted: true,
        },
        OutboundFrame::MlsRoomDeleted {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id: "r".to_string(),
        },
        OutboundFrame::MlsSnapshotResult {
            protocol_version: rooms::MLS_PROTOCOL_VERSION,
            room_id: "r".to_string(),
            message_id: "m".to_string(),
            revision: 1,
            accepted: true,
        },
    ];
    for frame in frames {
        assert!(frame.is_mls());
        let wire = serde_json::to_value(&frame).unwrap();
        assert_eq!(wire["protocol_version"], rooms::MLS_PROTOCOL_VERSION);
    }
}

#[test]
fn mls_delivery_preserves_authenticated_data_for_core_aad_verification() {
    let authenticated_data = vec![0_u8, 1, 127, 255];
    let delivery = rooms::PendingDelivery {
        room_id: "room-1".to_string(),
        message_id: "message-1".to_string(),
        recipient_code_id: [2_u8; rooms::GROUP_ID_BYTES],
        epoch: 3,
        membership_digest: vec![8_u8; rooms::MEMBERSHIP_DIGEST_BYTES],
        revision: 4,
        payload: rooms::DeliveryPayload::Application {
            sender_code_id: [1_u8; rooms::GROUP_ID_BYTES],
            sender_username: "Alice".to_string(),
            sender_platform: ClientPlatform::Android,
            ciphertext: vec![9_u8],
            authenticated_data: authenticated_data.clone(),
        },
        created_at_ms: 0,
        expires_at_ms: 1,
    };

    let wire = serde_json::to_value(mls_delivery_frame(&delivery)).unwrap();
    assert_eq!(
        wire["authenticated_data_b64"],
        URL_SAFE_NO_PAD.encode(authenticated_data)
    );
    assert_eq!(wire["protocol_version"], rooms::MLS_PROTOCOL_VERSION);
}

#[test]
fn mls_membership_delivery_preserves_prior_membership_digest() {
    let prior_digest = vec![1_u8; rooms::MEMBERSHIP_DIGEST_BYTES];
    let post_digest = vec![2_u8; rooms::MEMBERSHIP_DIGEST_BYTES];
    let delivery = rooms::PendingDelivery {
        room_id: "room-1".to_string(),
        message_id: "membership-1".to_string(),
        recipient_code_id: [2_u8; rooms::GROUP_ID_BYTES],
        epoch: 4,
        membership_digest: post_digest.clone(),
        revision: 5,
        payload: rooms::DeliveryPayload::Membership {
            from_epoch: 3,
            from_membership_digest: prior_digest.clone(),
            group_id: vec![3_u8; rooms::GROUP_ID_BYTES],
            roster: Vec::new(),
            control: vec![4],
            welcome: Vec::new(),
            authenticated_data: vec![5],
        },
        created_at_ms: 0,
        expires_at_ms: 1,
    };

    let wire = serde_json::to_value(mls_delivery_frame(&delivery)).unwrap();
    assert_eq!(
        wire["from_membership_digest_b64"],
        URL_SAFE_NO_PAD.encode(prior_digest)
    );
    assert_eq!(
        wire["membership_digest_b64"],
        URL_SAFE_NO_PAD.encode(post_digest)
    );
    assert_ne!(
        wire["from_membership_digest_b64"],
        wire["membership_digest_b64"]
    );
}

#[test]
fn oversized_inbound_frames_allow_only_canonical_large_mls_families() {
    let oversized = |prefix: &str| {
        format!(
            "{prefix}{}",
            "x".repeat(WS_MAX_FRAME_BYTES + 1 - prefix.len())
        )
    };
    for prefix in LARGE_MLS_INBOUND_PREFIXES {
        let frame = oversized(prefix);
        assert_eq!(frame.len(), WS_MAX_FRAME_BYTES + 1);
        assert!(validate_inbound_frame_size_before_parse(&frame).is_ok());
    }

    for frame in [
        oversized(r#"{"type":"mls_discover_room","protocol_version":10,"#),
        oversized(r#"{"type":"mls_unknown","protocol_version":10,"#),
        oversized(r#"{"type":"mls_application","protocol_version":9,"#),
        oversized(r#" {"type":"mls_application","protocol_version":10,"#),
        oversized(r#"{"protocol_version":10,"type":"mls_application","#),
        oversized(r#"{"type":"message","protocol_version":10,"#),
    ] {
        assert!(validate_inbound_frame_size_before_parse(&frame).is_err());
    }
}

#[test]
fn oversized_mls_prefix_does_not_bypass_full_json_schema_validation() {
    let prefix = LARGE_MLS_INBOUND_PREFIXES[3];
    let suffix = "\"type\":\"message\",\"ciphertext_b64\":\"";
    let filler_len = WS_MAX_FRAME_BYTES + 1 - prefix.len() - suffix.len() - 2;
    let frame = format!("{prefix}{suffix}{}\"}}", "x".repeat(filler_len));
    assert!(frame.len() > WS_MAX_FRAME_BYTES);
    assert!(validate_inbound_frame_size_before_parse(&frame).is_ok());
    assert!(serde_json::from_str::<InboundFrame>(&frame).is_err());
}

#[test]
fn websocket_admission_errors_are_terminal_but_schema_errors_are_not() {
    assert!(validate_inbound_text_socket_admission(r#"{"type":"activity"}"#, Ok(())).is_ok());
    assert!(validate_inbound_text_socket_admission(
        r#"{"type":"activity"}"#,
        Err("rate limit exceeded".to_string()),
    )
    .is_err());

    let oversized_legacy = format!(
        "{{\"type\":\"dummy\",\"padding_b64\":\"{}\"}}",
        "x".repeat(WS_MAX_FRAME_BYTES)
    );
    assert!(validate_inbound_text_socket_admission(&oversized_legacy, Ok(())).is_err());

    // Ordinary malformed or unauthorized frames at the legacy ceiling
    // remain non-terminal; handle_frame reports their schema error after
    // this admission function returns success.
    assert!(validate_inbound_text_socket_admission(r#"{"type":"unknown"}"#, Ok(())).is_ok());
}

#[test]
fn exact_mls_frame_ceiling_is_admitted_but_one_byte_over_is_rejected() {
    let prefix = LARGE_MLS_INBOUND_PREFIXES[4];
    let exact = format!(
        "{prefix}{}",
        "x".repeat(MLS_WS_MAX_FRAME_BYTES - prefix.len())
    );
    assert_eq!(exact.len(), MLS_WS_MAX_FRAME_BYTES);
    assert!(validate_inbound_frame_size_before_parse(&exact).is_ok());

    let over = format!(
        "{prefix}{}",
        "x".repeat(MLS_WS_MAX_FRAME_BYTES + 1 - prefix.len())
    );
    assert_eq!(over.len(), MLS_WS_MAX_FRAME_BYTES + 1);
    assert!(validate_inbound_frame_size_before_parse(&over).is_err());
}

#[tokio::test]
async fn mls_frame_ceiling_fits_bounded_records_but_legacy_frames_stay_small() {
    fn base64_len(bytes: usize) -> usize {
        bytes.checked_add(2).unwrap() / 3 * 4
    }
    let worst_membership = base64_len(rooms::MAX_CONTROL_BYTES)
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(base64_len(rooms::MAX_STATE_BYTES)))
        .and_then(|bytes| bytes.checked_add(base64_len(rooms::MAX_AUTHENTICATED_DATA_BYTES)))
        .and_then(|bytes| bytes.checked_add(256 * 1024))
        .unwrap();
    assert!(worst_membership < MLS_WS_MAX_FRAME_BYTES);

    let state = test_state();
    let client_id = Uuid::new_v4();
    assert!(
        check_ws_frame_allowed(&state, client_id, MLS_WS_MAX_FRAME_BYTES)
            .await
            .is_ok()
    );
    assert!(check_ws_frame_allowed(
        &test_state(),
        Uuid::new_v4(),
        CONTROL_TRANSPORT_MAX_BUCKET + 1
    )
    .await
    .is_err());

    let oversized_legacy =
        serde_json::json!({"type":"dummy","padding_b64":"x".repeat(WS_MAX_FRAME_BYTES),"bytes":1})
            .to_string();
    assert!(
        handle_frame(&test_state(), Uuid::new_v4(), &oversized_legacy)
            .await
            .is_err()
    );
    let large_mls = OutboundFrame::MlsApplication {
        protocol_version: rooms::MLS_PROTOCOL_VERSION,
        room_id: "r".to_string(),
        message_id: "m".to_string(),
        sender_username: "u".to_string(),
        epoch: 1,
        revision: 1,
        membership_digest_b64: "d".to_string(),
        ciphertext_b64: "x".repeat(WS_MAX_FRAME_BYTES),
        authenticated_data_b64: "a".to_string(),
    };
    assert!(serialize_outbound_frame(&large_mls).is_some());
}

#[tokio::test]
async fn websocket_byte_rate_budget_rejects_only_after_exact_boundary() {
    let state = test_state();
    let client_id = Uuid::new_v4();
    assert!(
        check_ws_frame_allowed(&state, client_id, MLS_WS_MAX_FRAME_BYTES)
            .await
            .is_ok()
    );
    assert!(
        check_ws_frame_allowed(&state, client_id, MLS_WS_MAX_FRAME_BYTES)
            .await
            .is_ok()
    );
    assert!(check_ws_frame_allowed(&state, client_id, 1).await.is_err());
}

#[tokio::test]
async fn removed_mls_member_loses_attachment_and_claim_access() {
    let state = test_state();
    let owner = test_code_id("mls-owner");
    let removed = test_code_id("mls-removed");
    let retained = test_code_id("mls-retained");
    let attachment_id = Uuid::new_v4();
    let removed_claim = Uuid::new_v4();
    let retained_claim = Uuid::new_v4();
    state.attachments.lock().await.insert(
        attachment_id,
        AttachmentRecord {
            blob: test_attachment_blob(vec![1]),
            chat_id: "mls-room".to_string(),
            message_id: "message-1".to_string(),
            media_type: "FILE".to_string(),
            owner_code_id: owner,
            sender_platform: ClientPlatform::Android,
            published: true,
            staged_expires_at_ms: None,
            one_time: false,
            delete_after_download: false,
            expires_at_ms: None,
            eligible_recipient_code_ids: HashSet::from([removed, retained]),
            download_claims: HashMap::from([
                (
                    removed_claim,
                    AttachmentDownloadClaim {
                        recipient_code_id: removed,
                        created_at_ms: now_ms(),
                    },
                ),
                (
                    retained_claim,
                    AttachmentDownloadClaim {
                        recipient_code_id: retained,
                        created_at_ms: now_ms(),
                    },
                ),
            ]),
            completed_recipient_code_ids: HashSet::from([removed, retained]),
        },
    );
    revoke_mls_attachment_access(&state, "mls-room", &removed).await;
    let attachments = state.attachments.lock().await;
    let record = attachments.get(&attachment_id).unwrap();
    assert!(!record.eligible_recipient_code_ids.contains(&removed));
    assert!(record.eligible_recipient_code_ids.contains(&retained));
    assert!(!record.completed_recipient_code_ids.contains(&removed));
    assert!(record.completed_recipient_code_ids.contains(&retained));
    assert!(!record.download_claims.contains_key(&removed_claim));
    assert!(record.download_claims.contains_key(&retained_claim));
}

#[tokio::test]
async fn inactive_mls_joiner_has_no_message_or_attachment_access() {
    let state = test_state();
    add_test_account(&state, "code-a", "Alice").await;
    add_test_account(&state, "code-b", "Bob").await;
    let owner = test_code_id("code-a");
    let joiner = test_code_id("code-b");
    let mut authority = state.mls_rooms.lock().await;
    authority
        .create(
            owner,
            "Alice".to_string(),
            "room-inactive".to_string(),
            vec![7; rooms::GROUP_ID_BYTES],
            0,
            0,
            vec![8; rooms::MEMBERSHIP_DIGEST_BYTES],
            vec![1; rooms::STABLE_IDENTITY_BYTES],
        )
        .unwrap();
    let request = authority
        .request_join(
            joiner,
            "Bob".to_string(),
            "room-inactive",
            "request-1".to_string(),
            vec![2; rooms::STABLE_IDENTITY_BYTES],
            vec![5],
            vec![9],
        )
        .unwrap();
    authority
        .begin_membership(
            owner,
            rooms::MembershipTransition {
                room_id: "room-inactive".to_string(),
                message_id: "commit-1".to_string(),
                request_id: Some(request.request_id.clone()),
                from_epoch: 0,
                to_epoch: 1,
                revision: 1,
                group_id: vec![7; rooms::GROUP_ID_BYTES],
                from_membership_digest: vec![8; rooms::MEMBERSHIP_DIGEST_BYTES],
                membership_digest: vec![8; rooms::MEMBERSHIP_DIGEST_BYTES],
                roster: vec![
                    rooms::RosterMember {
                        username: "Alice".to_string(),
                        stable_identity: vec![1; rooms::STABLE_IDENTITY_BYTES],
                    },
                    rooms::RosterMember {
                        username: "Bob".to_string(),
                        stable_identity: vec![2; rooms::STABLE_IDENTITY_BYTES],
                    },
                ],
                control: vec![1],
                welcome: vec![2],
                authenticated_data: vec![3],
                state_envelope: vec![4],
                created_at_ms: 0,
                expires_at_ms: 0,
            },
        )
        .unwrap();
    authority
        .accept_membership(owner, "room-inactive", "commit-1", 1)
        .unwrap();
    drop(authority);

    assert!(conversation_access(&state, "Bob", "room-inactive")
        .await
        .is_none());
    assert!(
        attachment_conversation_access(&state, "Bob", "room-inactive", "FILE")
            .await
            .is_err()
    );
    let access = ConversationAccess::MlsRoom(rooms::RoomPolicy::default());
    assert!(
        snapshot_attachment_recipients(&state, &access, "room-inactive", "Alice", &owner,)
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn authenticated_mls_transaction_rejections_are_exactly_correlated() {
    let group = URL_SAFE_NO_PAD.encode([7_u8; rooms::GROUP_ID_BYTES]);
    let digest = URL_SAFE_NO_PAD.encode([8_u8; rooms::MEMBERSHIP_DIGEST_BYTES]);
    let frames = [
        serde_json::json!({
            "type": "mls_membership_commit",
            "protocol_version": rooms::MLS_PROTOCOL_VERSION,
            "room_id": "missing-room",
            "message_id": "membership-reject",
            "request_id": null,
            "from_epoch": "0",
            "to_epoch": "1",
            "revision": "1",
            "group_id_b64": group,
            "from_membership_digest_b64": digest,
            "membership_digest_b64": digest,
            "roster": [],
            "control_b64": "AQ",
            "welcome_b64": "",
            "authenticated_data_b64": "AQ",
            "state_envelope_b64": "AQ"
        }),
        serde_json::json!({
            "type": "mls_application",
            "protocol_version": rooms::MLS_PROTOCOL_VERSION,
            "room_id": "missing-room",
            "message_id": "application-reject",
            "group_id_b64": group,
            "epoch": "0",
            "revision": "1",
            "membership_digest_b64": digest,
            "ciphertext_b64": "AQ",
            "authenticated_data_b64": "AQ",
            "state_envelope_b64": "AQ"
        }),
    ];
    for (index, frame) in frames.into_iter().enumerate() {
        let state = test_state();
        let code = format!("mls-reject-{index}");
        add_test_account(&state, &code, "Alice").await;
        let (client_id, mut rx, mut result_rx) =
            add_test_client_with_result(&state, &code, "Alice").await;
        let frame_text = frame.to_string();
        let handle_task = tokio::spawn({
            let state = state.clone();
            async move { handle_frame(&state, client_id, &frame_text).await }
        });
        let result = result_rx.recv().await.expect("negative transaction result");
        assert!(matches!(
            result.frame,
            OutboundFrame::MlsRoomResult {
                accepted: false,
                revision: 1,
                ..
            }
        ));
        assert!(result.delivered.send(true).is_ok());
        handle_task
            .await
            .expect("MLS rejection task")
            .expect("safe authenticated rejection is acknowledged");
        assert!(rx.try_recv().is_err());
    }

    let state = test_state();
    add_test_account(&state, "snapshot-reject", "Alice").await;
    let (client_id, mut rx, mut result_rx) =
        add_test_client_with_result(&state, "snapshot-reject", "Alice").await;
    let snapshot = serde_json::json!({
        "type": "mls_state_snapshot",
        "protocol_version": rooms::MLS_PROTOCOL_VERSION,
        "room_id": "missing-room",
        "message_id": "snapshot-reject",
        "epoch": "0",
        "revision": "1",
        "membership_digest_b64": digest,
        "state_envelope_b64": "AQ"
    });
    let snapshot_text = snapshot.to_string();
    let handle_task = tokio::spawn({
        let state = state.clone();
        async move { handle_frame(&state, client_id, &snapshot_text).await }
    });
    let result = result_rx.recv().await.expect("negative snapshot result");
    assert!(matches!(
        result.frame,
        OutboundFrame::MlsSnapshotResult {
            ref message_id,
            revision: 1,
            accepted: false,
            ..
        } if message_id == "snapshot-reject"
    ));
    assert!(result.delivered.send(true).is_ok());
    handle_task
        .await
        .expect("snapshot rejection task")
        .expect("safe authenticated snapshot rejection is acknowledged");
    assert!(rx.try_recv().is_err());

    let state = test_state();
    add_test_account(&state, "unsafe-reject", "Alice").await;
    let (client_id, mut rx) = add_test_client(&state, "unsafe-reject", "Alice").await;
    let unsafe_frame = serde_json::json!({
        "type": "mls_application",
        "protocol_version": rooms::MLS_PROTOCOL_VERSION,
        "room_id": "bad room",
        "message_id": "unsafe-reject",
        "group_id_b64": group,
        "epoch": "0",
        "revision": "1",
        "membership_digest_b64": digest,
        "ciphertext_b64": "AQ",
        "authenticated_data_b64": "AQ",
        "state_envelope_b64": "AQ"
    });
    assert!(handle_frame(&state, client_id, &unsafe_frame.to_string())
        .await
        .is_err());
    assert!(rx.try_recv().is_err());
}

#[test]
fn mls_wire_activates_joiner_only_after_welcome_snapshot() {
    let owner = [1_u8; 32];
    let joiner = [2_u8; 32];
    let mut authority = rooms::RoomAuthority::new(2);
    authority
        .create(
            owner,
            "Alice".to_string(),
            "room-1".to_string(),
            vec![7; rooms::GROUP_ID_BYTES],
            0,
            0,
            vec![8; rooms::MEMBERSHIP_DIGEST_BYTES],
            vec![1; rooms::STABLE_IDENTITY_BYTES],
        )
        .unwrap();
    let request = authority
        .request_join(
            joiner,
            "Bob".to_string(),
            "room-1",
            "request-1".to_string(),
            vec![2; rooms::STABLE_IDENTITY_BYTES],
            vec![5],
            vec![9],
        )
        .unwrap();
    authority
        .begin_membership(
            owner,
            rooms::MembershipTransition {
                room_id: "room-1".to_string(),
                message_id: "commit-1".to_string(),
                request_id: Some(request.request_id.clone()),
                from_epoch: 0,
                to_epoch: 1,
                revision: 1,
                group_id: vec![7; rooms::GROUP_ID_BYTES],
                from_membership_digest: vec![8; rooms::MEMBERSHIP_DIGEST_BYTES],
                membership_digest: vec![8; rooms::MEMBERSHIP_DIGEST_BYTES],
                roster: vec![
                    rooms::RosterMember {
                        username: "Alice".to_string(),
                        stable_identity: vec![1; rooms::STABLE_IDENTITY_BYTES],
                    },
                    rooms::RosterMember {
                        username: "Bob".to_string(),
                        stable_identity: vec![2; rooms::STABLE_IDENTITY_BYTES],
                    },
                ],
                control: vec![1],
                welcome: vec![2],
                authenticated_data: vec![3],
                state_envelope: vec![4],
                created_at_ms: 0,
                expires_at_ms: 0,
            },
        )
        .unwrap();
    authority
        .accept_membership(owner, "room-1", "commit-1", 1)
        .unwrap();
    let before = mls_room_wire(authority.member_info("room-1", &joiner).unwrap());
    assert!(!before.active);
    assert!(!before.recovery_snapshot.as_ref().unwrap().active);

    let welcome = authority
        .deliveries_for_member("room-1", &joiner)
        .unwrap()
        .pop()
        .unwrap();
    authority
        .store_snapshot(
            joiner,
            "room-1",
            &welcome.message_id,
            welcome.epoch,
            welcome.revision,
            welcome.membership_digest.clone(),
            vec![6],
        )
        .unwrap();
    let after = mls_room_wire(authority.member_info("room-1", &joiner).unwrap());
    assert!(after.active);
    assert!(after.recovery_snapshot.as_ref().unwrap().active);
}

#[tokio::test]
async fn active_mls_snapshot_ack_refreshes_catalog_without_domain_result_or_queue_replay() {
    let state = test_state();
    add_test_account(&state, "code-a", "Alice").await;
    add_test_account(&state, "code-b", "Bob").await;
    let owner = test_code_id("code-a");
    let recipient = test_code_id("code-b");
    {
        let mut authority = state.mls_rooms.lock().await;
        authority
            .create(
                owner,
                "Alice".to_string(),
                "room-ack".to_string(),
                vec![7; rooms::GROUP_ID_BYTES],
                0,
                0,
                vec![8; rooms::MEMBERSHIP_DIGEST_BYTES],
                vec![1; rooms::STABLE_IDENTITY_BYTES],
            )
            .unwrap();
        let join = authority
            .request_join(
                recipient,
                "Bob".to_string(),
                "room-ack",
                "request-1".to_string(),
                vec![2; rooms::STABLE_IDENTITY_BYTES],
                vec![5],
                vec![9],
            )
            .unwrap();
        authority
            .begin_membership(
                owner,
                rooms::MembershipTransition {
                    room_id: "room-ack".to_string(),
                    message_id: "commit-1".to_string(),
                    request_id: Some(join.request_id.clone()),
                    from_epoch: 0,
                    to_epoch: 1,
                    revision: 1,
                    group_id: vec![7; rooms::GROUP_ID_BYTES],
                    from_membership_digest: vec![8; rooms::MEMBERSHIP_DIGEST_BYTES],
                    membership_digest: vec![8; rooms::MEMBERSHIP_DIGEST_BYTES],
                    roster: vec![
                        rooms::RosterMember {
                            username: "alice".to_string(),
                            stable_identity: vec![1; rooms::STABLE_IDENTITY_BYTES],
                        },
                        rooms::RosterMember {
                            username: "bob".to_string(),
                            stable_identity: vec![2; rooms::STABLE_IDENTITY_BYTES],
                        },
                    ],
                    control: vec![1],
                    welcome: vec![2],
                    authenticated_data: vec![3],
                    state_envelope: vec![4],
                    created_at_ms: 0,
                    expires_at_ms: 0,
                },
            )
            .unwrap();
        authority
            .accept_membership(owner, "room-ack", "commit-1", 1)
            .unwrap();
        let welcome = authority
            .deliveries_for_member("room-ack", &recipient)
            .unwrap()
            .pop()
            .unwrap();
        authority
            .store_snapshot(
                recipient,
                "room-ack",
                &welcome.message_id,
                welcome.epoch,
                welcome.revision,
                welcome.membership_digest.clone(),
                vec![6],
            )
            .unwrap();
        authority
            .admit_application(
                owner,
                "room-ack",
                "application-1".to_string(),
                vec![7; rooms::GROUP_ID_BYTES],
                1,
                2,
                vec![8; rooms::MEMBERSHIP_DIGEST_BYTES],
                vec![10],
                vec![11],
                vec![12],
            )
            .unwrap();
        authority
            .commit_application("room-ack", "application-1")
            .unwrap();
    }
    let client_id = Uuid::new_v4();
    let (data_tx, mut data_rx) = mpsc::channel(CLIENT_OUTBOUND_QUEUE_CAPACITY);
    let (control_tx, _control_rx) = mpsc::channel(CLIENT_CONTROL_QUEUE_CAPACITY);
    let (result_tx, mut result_rx) = mpsc::channel(CLIENT_RESULT_QUEUE_CAPACITY);
    state.clients.lock().await.insert(
        client_id,
        ClientHandle {
            code_id: recipient,
            username: "Bob".to_string(),
            platform: ClientPlatform::Android,
            tx: data_tx,
            control_tx,
            result_tx,
            queued_bytes: Arc::new(AtomicUsize::new(0)),
        },
    );

    mls_state_snapshot(
        &state,
        client_id,
        "room-ack".to_string(),
        "application-1".to_string(),
        1,
        1,
        URL_SAFE_NO_PAD.encode([8_u8; rooms::MEMBERSHIP_DIGEST_BYTES]),
        URL_SAFE_NO_PAD.encode([13_u8]),
    )
    .await
    .unwrap();
    let catalog = data_rx.recv().await.expect("fresh MLS catalog");
    assert!(matches!(
        catalog,
        OutboundFrame::MlsRooms { ref rooms, .. }
            if rooms.len() == 1 && rooms[0].synchronized
    ));
    assert!(data_rx.try_recv().is_err());
    assert!(result_rx.try_recv().is_err());
}

#[tokio::test]
async fn direct_conversations_are_canonical_and_participant_restricted() {
    let state = test_state();
    add_test_account(&state, "code-a", "Alice").await;
    add_test_account(&state, "code-b", "Bob").await;
    add_test_account(&state, "code-e", "Eve").await;
    let (alice_id, mut alice_rx) = add_test_client(&state, "code-a", "Alice").await;
    let (bob_id, mut bob_rx) = add_test_client(&state, "code-b", "Bob").await;
    let (eve_id, mut eve_rx) = add_test_client(&state, "code-e", "Eve").await;

    open_direct(&state, alice_id, "Bob")
        .await
        .expect("direct should open");
    open_direct(&state, bob_id, "Alice")
        .await
        .expect("opening the same pair should be idempotent");

    let catalog = state.direct_catalog.lock().await;
    assert_eq!(catalog.len(), 1);
    let direct_id = catalog.values().next().expect("direct").id.clone();
    drop(catalog);
    assert!(join_room(&state, alice_id, direct_id.clone()).await.is_ok());
    assert!(join_room(&state, bob_id, direct_id.clone()).await.is_ok());
    assert!(join_room(&state, eve_id, direct_id.clone()).await.is_err());
    assert!(join_room(&state, eve_id, "dm_guessed".to_string())
        .await
        .is_err());

    while alice_rx.try_recv().is_ok() {}
    while bob_rx.try_recv().is_ok() {}
    while eve_rx.try_recv().is_ok() {}
    route_test_message(&state, alice_id, &direct_id, &["Bob"])
        .await
        .expect("participant message should route");

    let delivered = bob_rx.try_recv().expect("Bob receives the DM");
    assert!(matches!(
        &delivered,
        OutboundFrame::Message {
            ciphertext_b64,
            wrapped_key_b64,
            ..
        } if !ciphertext_b64.is_empty() && !wrapped_key_b64.is_empty()
    ));
    assert!(eve_rx.try_recv().is_err());
    assert!(conversation_access(&state, "Eve", &direct_id)
        .await
        .is_none());
    assert!(conversation_access(&state, "Alice", &direct_id)
        .await
        .is_some());
}

#[tokio::test]
async fn direct_catalog_is_private_to_each_participant() {
    let state = test_state();
    state.direct_catalog.lock().await.insert(
        "dm_private".to_string(),
        DirectEntry {
            id: "dm_private".to_string(),
            user_a: "Alice".to_string(),
            user_b: "Bob".to_string(),
        },
    );
    let records_for_alice = state
        .direct_catalog
        .lock()
        .await
        .values()
        .filter_map(|direct| direct.record_for("Alice"))
        .collect::<Vec<_>>();
    let records_for_eve = state
        .direct_catalog
        .lock()
        .await
        .values()
        .filter_map(|direct| direct.record_for("Eve"))
        .collect::<Vec<_>>();

    assert_eq!(records_for_alice.len(), 1);
    assert_eq!(records_for_alice[0].peer_username, "Bob");
    assert!(records_for_eve.is_empty());
}

#[tokio::test]
async fn direct_catalog_enforces_global_and_per_user_caps() {
    let state = test_state();
    add_test_account(&state, "direct-owner", "Alice").await;
    add_test_account(&state, "direct-peer", "Bob").await;
    let (alice_id, _) = add_test_client(&state, "direct-owner", "Alice").await;

    for index in 0..MAX_DIRECT_CATALOG_PER_USER {
        add_test_account(
            &state,
            &format!("direct-peer-{index}"),
            &format!("Peer{index}"),
        )
        .await;
        open_direct(&state, alice_id, &format!("Peer{index}"))
            .await
            .expect("direct should fit per-user cap");
    }
    assert!(open_direct(&state, alice_id, "Bob").await.is_err());

    let global_state = test_state();
    add_test_account(&global_state, "global-owner", "Alice").await;
    add_test_account(&global_state, "global-peer", "Bob").await;
    let (global_alice_id, _) = add_test_client(&global_state, "global-owner", "Alice").await;
    {
        let mut catalog = global_state.direct_catalog.lock().await;
        for index in 0..MAX_DIRECT_CATALOG_ENTRIES {
            catalog.insert(
                format!("dm_filled_{index}"),
                DirectEntry {
                    id: format!("dm_filled_{index}"),
                    user_a: format!("UserA{index}"),
                    user_b: format!("UserB{index}"),
                },
            );
        }
    }
    assert!(open_direct(&global_state, global_alice_id, "Bob")
        .await
        .is_err());

    let victim_state = test_state();
    add_test_account(&victim_state, "victim-owner", "Alice").await;
    add_test_account(&victim_state, "victim-peer", "Victim").await;
    let (victim_alice_id, _) = add_test_client(&victim_state, "victim-owner", "Alice").await;
    {
        let mut catalog = victim_state.direct_catalog.lock().await;
        for index in 0..MAX_DIRECT_CATALOG_PER_USER {
            catalog.insert(
                format!("dm_victim_{index}"),
                DirectEntry {
                    id: format!("dm_victim_{index}"),
                    user_a: "Victim".to_string(),
                    user_b: format!("ExistingPeer{index}"),
                },
            );
        }
    }
    assert!(open_direct(&victim_state, victim_alice_id, "Victim")
        .await
        .is_err());
}

#[test]
fn opaque_finish_request_shape_is_exclusive_to_handshake_mode() {
    let registration = OpaqueAccountFinishRequest {
        handshake_id: Uuid::new_v4(),
        registration_upload_b64: Some("upload".to_string()),
        credential_finalization_b64: None,
        identity_public_b64: Some("public".to_string()),
        identity_prekey_id: Some("prekey".to_string()),
        identity_envelope_b64: Some("envelope".to_string()),
        identity_proof_b64: Some("proof".to_string()),
    };
    assert!(opaque_finish_request_is_registration(&registration));

    let mut registration_with_login_field = registration;
    registration_with_login_field.credential_finalization_b64 = Some("finalization".to_string());
    assert!(!opaque_finish_request_is_registration(
        &registration_with_login_field
    ));

    let login = OpaqueAccountFinishRequest {
        handshake_id: Uuid::new_v4(),
        registration_upload_b64: None,
        credential_finalization_b64: Some("finalization".to_string()),
        identity_public_b64: None,
        identity_prekey_id: None,
        identity_envelope_b64: None,
        identity_proof_b64: None,
    };
    assert!(opaque_finish_request_is_login(&login));

    let mut login_with_identity_field = login;
    login_with_identity_field.identity_proof_b64 = Some("proof".to_string());
    assert!(!opaque_finish_request_is_login(&login_with_identity_field));
}

#[tokio::test]
async fn relay_rejects_missing_duplicate_and_unauthorized_recipient_envelopes() {
    let state = test_state();
    add_test_account(&state, "code-a", "Alice").await;
    add_test_account(&state, "code-b", "Bob").await;
    add_test_account(&state, "code-e", "Eve").await;
    let (alice_id, _) = add_test_client(&state, "code-a", "Alice").await;
    open_direct(&state, alice_id, "Bob")
        .await
        .expect("direct should open");
    let direct_id = state
        .direct_catalog
        .lock()
        .await
        .values()
        .next()
        .expect("direct")
        .id
        .clone();

    assert!(route_test_message(&state, alice_id, &direct_id, &[])
        .await
        .is_err());
    assert!(
        route_test_message(&state, alice_id, &direct_id, &["Bob", "Bob"])
            .await
            .is_err()
    );
    assert!(route_test_message(&state, alice_id, &direct_id, &["Eve"])
        .await
        .is_err());
}

#[tokio::test]
async fn relay_requires_v9_signature_on_each_recipient_envelope() {
    let state = test_state();
    add_test_account(&state, "code-a", "Alice").await;
    add_test_account(&state, "code-b", "Bob").await;
    let (alice_id, _) = add_test_client(&state, "code-a", "Alice").await;
    open_direct(&state, alice_id, "Bob")
        .await
        .expect("direct should open");
    let direct_id = state
        .direct_catalog
        .lock()
        .await
        .values()
        .next()
        .expect("direct")
        .id
        .clone();
    let envelope = |signature_b64: &str| InboundRecipientEnvelope {
        recipient_username: "Bob".to_string(),
        wrapped_key_b64: URL_SAFE_NO_PAD.encode([4_u8; 256]),
        prekey_id: String::new(),
        is_prekey: false,
        signature_b64: signature_b64.to_string(),
    };

    assert!(route_test_message_with_envelopes(
        &state,
        alice_id,
        &direct_id,
        E2EE_PROTOCOL_VERSION,
        "missing-envelope-signature",
        vec![envelope("")],
    )
    .await
    .is_err());
    assert!(route_test_message_with_envelopes(
        &state,
        alice_id,
        &direct_id,
        E2EE_PROTOCOL_VERSION,
        "malformed-envelope-signature",
        vec![envelope("not-base64")],
    )
    .await
    .is_err());
    assert!(route_test_message_with_envelopes(
        &state,
        alice_id,
        &direct_id,
        E2EE_PROTOCOL_VERSION,
        "duplicate-recipient-envelope",
        vec![
            envelope(&test_signature_b64(b'A')),
            envelope(&test_signature_b64(b'B')),
        ],
    )
    .await
    .is_err());
    assert!(route_test_message_with_envelopes(
        &state,
        alice_id,
        &direct_id,
        E2EE_PROTOCOL_VERSION - 1,
        "legacy-v5-message",
        vec![envelope(&test_signature_b64(b'C'))],
    )
    .await
    .is_err());

    let (bob_id, mut bob_rx) = add_test_client(&state, "code-b", "Bob").await;
    join_room(&state, alice_id, direct_id.clone())
        .await
        .expect("Alice joins direct");
    join_room(&state, bob_id, direct_id.clone())
        .await
        .expect("Bob joins direct");
    let identity_public = state
        .accounts
        .lock()
        .await
        .get(&test_code_id("code-a"))
        .expect("Alice account")
        .identity_public
        .clone();
    let wrapped_key = [4_u8; 256];
    let valid_signature = test_valid_message_signature_b64(
        b'A',
        &direct_id,
        "forward-envelope-signature",
        "Alice",
        &identity_public,
        "Bob",
        &wrapped_key,
        "",
        false,
    );
    route_test_message_with_envelopes(
        &state,
        alice_id,
        &direct_id,
        E2EE_PROTOCOL_VERSION,
        "forward-envelope-signature",
        vec![InboundRecipientEnvelope {
            recipient_username: "Bob".to_string(),
            wrapped_key_b64: URL_SAFE_NO_PAD.encode(wrapped_key),
            prekey_id: String::new(),
            is_prekey: false,
            signature_b64: valid_signature.clone(),
        }],
    )
    .await
    .expect("valid v9 message should route");
    let OutboundFrame::Message {
        signature_b64,
        identity_public_b64,
        sender_public_key_b64,
        ..
    } = &bob_rx.try_recv().expect("Bob receives v9 message")
    else {
        panic!("expected text frame");
    };
    assert_eq!(signature_b64, &valid_signature);
    assert_eq!(identity_public_b64, sender_public_key_b64);
}

#[tokio::test]
async fn forged_signature_cannot_lease_prekey_or_mutate_relay_state() {
    let state = test_state();
    add_test_account(&state, "code-a", "Alice").await;
    add_test_account(&state, "code-b", "Bob").await;
    let (alice_id, _) = add_test_client(&state, "code-a", "Alice").await;
    let (bob_id, mut bob_rx) = add_test_client(&state, "code-b", "Bob").await;
    open_direct(&state, alice_id, "Bob")
        .await
        .expect("direct should open");
    let direct_id = state
        .direct_catalog
        .lock()
        .await
        .values()
        .next()
        .expect("direct")
        .id
        .clone();
    join_room(&state, alice_id, direct_id.clone())
        .await
        .expect("Alice joins direct");
    join_room(&state, bob_id, direct_id.clone())
        .await
        .expect("Bob joins direct");
    while bob_rx.try_recv().is_ok() {}

    let identity_public = state
        .accounts
        .lock()
        .await
        .get(&test_code_id("code-a"))
        .expect("Alice account")
        .identity_public
        .clone();
    let wrapped_key = [9_u8; 256];
    let mut signature = URL_SAFE_NO_PAD
        .decode(test_valid_message_signature_b64(
            b'A',
            &direct_id,
            "forged-message",
            "Alice",
            &identity_public,
            "Bob",
            &wrapped_key,
            &test_prekey_id(b'B'),
            true,
        ))
        .expect("valid signature");
    signature[0] ^= 1;
    let result = route_test_message_with_envelopes(
        &state,
        alice_id,
        &direct_id,
        E2EE_PROTOCOL_VERSION,
        "forged-message",
        vec![InboundRecipientEnvelope {
            recipient_username: "Bob".to_string(),
            wrapped_key_b64: URL_SAFE_NO_PAD.encode(wrapped_key),
            prekey_id: test_prekey_id(b'B'),
            is_prekey: true,
            signature_b64: URL_SAFE_NO_PAD.encode(signature),
        }],
    )
    .await;
    assert!(result.is_err());
    assert!(state.prekey_leases.lock().await.is_empty());
    assert!(state.replay_ids.lock().await.is_empty());
    assert!(state.pending.lock().await.is_empty());
    assert_eq!(*state.pending_bytes.lock().await, 0);
    assert_eq!(
        state
            .accounts
            .lock()
            .await
            .get(&test_code_id("code-a"))
            .expect("Alice account")
            .state_revision,
        0
    );
    assert!(bob_rx.try_recv().is_err());
}

#[test]
fn inbound_frames_reject_missing_envelope_signature_field() {
    let frame = serde_json::json!({
        "type": "message",
        "chat_id": "dm_a_b",
        "version": E2EE_PROTOCOL_VERSION,
        "message_id": "message-1",
        "nonce_b64": URL_SAFE_NO_PAD.encode([1_u8; MESSAGE_NONCE_BYTES]),
        "ciphertext_b64": URL_SAFE_NO_PAD.encode([2_u8; 16]),
        "envelopes": [{
            "recipient_username": "Bob",
            "wrapped_key_b64": URL_SAFE_NO_PAD.encode([3_u8; 32]),
            "prekey_id": "",
            "is_prekey": false
        }],
        "state_revision": 1,
        "identity_envelope_b64": URL_SAFE_NO_PAD.encode([IDENTITY_ENVELOPE_VERSION; 256]),
        "identity_public_b64": URL_SAFE_NO_PAD.encode([4_u8; IDENTITY_PUBLIC_BYTES]),
        "prekey_id": "fallback"
    });
    assert!(serde_json::from_value::<InboundFrame>(frame).is_err());
}

#[test]
fn inbound_message_requires_complete_directory_evidence() {
    let frame = serde_json::json!({
        "type": "message",
        "chat_id": "dm_a_b",
        "version": E2EE_PROTOCOL_VERSION,
        "message_id": "message-directory-1",
        "nonce_b64": URL_SAFE_NO_PAD.encode([1_u8; MESSAGE_NONCE_BYTES]),
        "ciphertext_b64": URL_SAFE_NO_PAD.encode([2_u8; 16]),
        "envelopes": [{
            "recipient_username": "Bob",
            "wrapped_key_b64": URL_SAFE_NO_PAD.encode([3_u8; 32]),
            "prekey_id": "",
            "is_prekey": false,
            "signature_b64": URL_SAFE_NO_PAD.encode([4_u8; MESSAGE_SIGNATURE_BYTES])
        }],
        "state_revision": 1,
        "identity_envelope_b64": URL_SAFE_NO_PAD.encode([IDENTITY_ENVELOPE_VERSION; 256]),
        "identity_public_b64": URL_SAFE_NO_PAD.encode([5_u8; IDENTITY_PUBLIC_BYTES]),
        "prekey_id": "fallback",
        "state_signature_b64": URL_SAFE_NO_PAD.encode([6_u8; MESSAGE_SIGNATURE_BYTES]),
        "directory_node_id": "test-node",
        "directory_revision": 1,
        "directory_digest": URL_SAFE_NO_PAD.encode([7_u8; DIRECTORY_DIGEST_BYTES]),
        "padding_bucket": 4096,
        "padding": ""
    });
    assert!(serde_json::from_value::<InboundFrame>(frame.clone()).is_ok());
    for field in [
        "directory_node_id",
        "directory_revision",
        "directory_digest",
    ] {
        let mut incomplete = frame.clone();
        incomplete
            .as_object_mut()
            .expect("message object")
            .remove(field);
        assert!(
            serde_json::from_value::<InboundFrame>(incomplete).is_err(),
            "missing {field} must fail closed"
        );
    }
}

#[tokio::test]
async fn acknowledgement_without_pending_frame_does_not_mutate_state() {
    let state = test_state();
    add_test_account(&state, "code-a", "Alice").await;
    add_test_account(&state, "code-b", "Bob").await;
    let (bob_id, _) = add_test_client(&state, "code-b", "Bob").await;
    let room = test_room("ack_without_pending");
    state.room_catalog.lock().await.insert(
        room.id.clone(),
        RoomEntry {
            room: room.clone(),
            owner_code_id: test_code_id("code-a"),
        },
    );

    let envelope_b64 = test_identity_envelope_b64(3);
    let identity_public_b64 = test_identity_public_b64(b'B');
    let prekey_id = test_prekey_id(b'B');
    let state_signature_b64 =
        test_valid_state_signature_b64(b'B', 1, &envelope_b64, &identity_public_b64, &prekey_id);
    let ack_signature_b64 =
        test_valid_ack_signature_b64(b'B', &room.id, "missing-message", "Alice", "");
    let before = state
        .accounts
        .lock()
        .await
        .get(&test_code_id("code-b"))
        .map(|account| {
            (
                account.state_revision,
                account.state_revision_window,
                account.identity_envelope.clone(),
                account.identity_public.clone(),
                account.prekey_id.clone(),
            )
        })
        .expect("Bob account");
    let pending_bytes_before = *state.pending_bytes.lock().await;
    let replay_before = state.replay_ids.lock().await.len();
    let claims_before = state.prekey_leases.lock().await.len();

    let result = acknowledge_message(
        &state,
        bob_id,
        &room.id,
        "missing-message",
        "Alice",
        1,
        &envelope_b64,
        &identity_public_b64,
        &prekey_id,
        &state_signature_b64,
        &ack_signature_b64,
        "",
    )
    .await;
    assert!(result.is_err());

    let after = state
        .accounts
        .lock()
        .await
        .get(&test_code_id("code-b"))
        .map(|account| {
            (
                account.state_revision,
                account.state_revision_window,
                account.identity_envelope.clone(),
                account.identity_public.clone(),
                account.prekey_id.clone(),
            )
        })
        .expect("Bob account");
    assert_eq!(after, before);
    assert_eq!(*state.pending_bytes.lock().await, pending_bytes_before);
    assert_eq!(state.replay_ids.lock().await.len(), replay_before);
    assert_eq!(state.prekey_leases.lock().await.len(), claims_before);
    assert!(state.pending.lock().await.is_empty());
}

#[tokio::test]
async fn acknowledgement_requires_exact_pending_tuple_and_rejects_duplicate() {
    let state = test_state();
    add_test_account(&state, "code-a", "Alice").await;
    add_test_account(&state, "code-b", "Bob").await;
    let (alice_id, _) = add_test_client(&state, "code-a", "Alice").await;
    let (bob_id, _) = add_test_client(&state, "code-b", "Bob").await;
    let room = test_room("ack_exact_pending");
    state.room_catalog.lock().await.insert(
        room.id.clone(),
        RoomEntry {
            room: room.clone(),
            owner_code_id: test_code_id("code-a"),
        },
    );
    let wrong_chat = test_room("ack_exact_other");
    state.room_catalog.lock().await.insert(
        wrong_chat.id.clone(),
        RoomEntry {
            room: wrong_chat.clone(),
            owner_code_id: test_code_id("code-a"),
        },
    );
    let message_id = "exact-message";
    let prekey_id = test_prekey_id(b'B');
    let wrapped_key = [4_u8; 256];
    state.prekey_leases.lock().await.insert(
        PrekeyLeaseKey {
            code_id: test_code_id("code-b"),
            prekey_id: prekey_id.clone(),
        },
        PrekeyLease {
            chat_id: room.id.clone(),
            message_id: message_id.to_string(),
            sender_username: "Alice".to_string(),
            recipient_username: "Bob".to_string(),
            created_at_ms: now_ms(),
        },
    );
    route_test_message_with_envelopes(
        &state,
        alice_id,
        &room.id,
        E2EE_PROTOCOL_VERSION,
        message_id,
        vec![InboundRecipientEnvelope {
            recipient_username: "Bob".to_string(),
            wrapped_key_b64: URL_SAFE_NO_PAD.encode(wrapped_key),
            prekey_id: prekey_id.clone(),
            is_prekey: true,
            signature_b64: test_valid_message_signature_b64(
                b'A',
                &room.id,
                message_id,
                "Alice",
                &test_identity_public(b'A'),
                "Bob",
                &wrapped_key,
                &prekey_id,
                true,
            ),
        }],
    )
    .await
    .expect("prekey message queues");

    let envelope_b64 = test_identity_envelope_b64(4);
    let (identity_public, current_prekey_id) =
        test_identity_public_after_consumption(b'B', &prekey_id);
    let identity_public_b64 = URL_SAFE_NO_PAD.encode(identity_public);
    let state_signature_b64 = test_valid_state_signature_b64(
        b'B',
        1,
        &envelope_b64,
        &identity_public_b64,
        &current_prekey_id,
    );
    let pending_key = PendingKey {
        chat_id: room.id.clone(),
        recipient_username: "Bob".to_string(),
    };
    let before = ack_test_snapshot(&state, &test_code_id("code-b"), &pending_key).await;
    assert!(!before.3.is_empty(), "prekey lease should be pending");

    let wrong_chat_ack_signature_b64 =
        test_valid_ack_signature_b64(b'B', &wrong_chat.id, message_id, "Alice", &prekey_id);
    assert!(acknowledge_message(
        &state,
        bob_id,
        &wrong_chat.id,
        message_id,
        "Alice",
        1,
        &envelope_b64,
        &identity_public_b64,
        &current_prekey_id,
        &state_signature_b64,
        &wrong_chat_ack_signature_b64,
        &prekey_id,
    )
    .await
    .is_err());
    let after_wrong_chat = ack_test_snapshot(&state, &test_code_id("code-b"), &pending_key).await;
    assert_eq!(after_wrong_chat, before);

    let wrong_prekey_id = test_prekey_id(b'X');
    let wrong_prekey_ack_signature_b64 =
        test_valid_ack_signature_b64(b'B', &room.id, message_id, "Alice", &wrong_prekey_id);
    assert!(acknowledge_message(
        &state,
        bob_id,
        &room.id,
        message_id,
        "Alice",
        1,
        &envelope_b64,
        &identity_public_b64,
        &current_prekey_id,
        &state_signature_b64,
        &wrong_prekey_ack_signature_b64,
        &wrong_prekey_id,
    )
    .await
    .is_err());
    let after_wrong_prekey = ack_test_snapshot(&state, &test_code_id("code-b"), &pending_key).await;
    assert_eq!(after_wrong_prekey, before);

    let wrong_message_id = "wrong-message";
    let wrong_ack_signature_b64 =
        test_valid_ack_signature_b64(b'B', &room.id, wrong_message_id, "Alice", &prekey_id);
    assert!(acknowledge_message(
        &state,
        bob_id,
        &room.id,
        wrong_message_id,
        "Alice",
        1,
        &envelope_b64,
        &identity_public_b64,
        &current_prekey_id,
        &state_signature_b64,
        &wrong_ack_signature_b64,
        &prekey_id,
    )
    .await
    .is_err());
    let after_wrong = ack_test_snapshot(&state, &test_code_id("code-b"), &pending_key).await;
    assert_eq!(after_wrong, before);

    let ack_signature_b64 =
        test_valid_ack_signature_b64(b'B', &room.id, message_id, "Alice", &prekey_id);
    acknowledge_message(
        &state,
        bob_id,
        &room.id,
        message_id,
        "Alice",
        1,
        &envelope_b64,
        &identity_public_b64,
        &current_prekey_id,
        &state_signature_b64,
        &ack_signature_b64,
        &prekey_id,
    )
    .await
    .expect("matching acknowledgement");
    let after_matching = state
        .accounts
        .lock()
        .await
        .get(&test_code_id("code-b"))
        .map(|account| {
            (
                account.state_revision,
                account.state_revision_window,
                account.identity_envelope.clone(),
                account.identity_public.clone(),
                account.prekey_id.clone(),
            )
        })
        .expect("Bob account");
    let pending_bytes_after_matching = *state.pending_bytes.lock().await;
    assert_eq!(pending_bytes_after_matching, 0);

    assert!(acknowledge_message(
        &state,
        bob_id,
        &room.id,
        message_id,
        "Alice",
        1,
        &envelope_b64,
        &identity_public_b64,
        &prekey_id,
        &state_signature_b64,
        &ack_signature_b64,
        &prekey_id,
    )
    .await
    .is_err());
    let after_duplicate = state
        .accounts
        .lock()
        .await
        .get(&test_code_id("code-b"))
        .map(|account| {
            (
                account.state_revision,
                account.state_revision_window,
                account.identity_envelope.clone(),
                account.identity_public.clone(),
                account.prekey_id.clone(),
            )
        })
        .expect("Bob account");
    assert_eq!(after_duplicate, after_matching);
    assert_eq!(
        *state.pending_bytes.lock().await,
        pending_bytes_after_matching
    );
    assert!(state.pending.lock().await.is_empty());
    assert!(state.prekey_leases.lock().await.is_empty());
}

#[tokio::test]
async fn acknowledgement_signature_is_required_and_binds_metadata() {
    let state = test_state();
    add_test_account(&state, "code-a", "Alice").await;
    add_test_account(&state, "code-b", "Bob").await;
    let (alice_id, _) = add_test_client(&state, "code-a", "Alice").await;
    let (bob_id, _) = add_test_client(&state, "code-b", "Bob").await;
    let room = test_room("ack_signature_binding");
    state.room_catalog.lock().await.insert(
        room.id.clone(),
        RoomEntry {
            room: room.clone(),
            owner_code_id: test_code_id("code-a"),
        },
    );
    join_room(&state, alice_id, room.id.clone())
        .await
        .expect("Alice joins room");
    join_room(&state, bob_id, room.id.clone())
        .await
        .expect("Bob joins room");
    let message_id = "ack-signature-message";
    route_test_message_with_id(&state, alice_id, &room.id, &["Bob"], message_id)
        .await
        .expect("message queues");

    let envelope_b64 = test_identity_envelope_b64(0);
    let identity_public_b64 = test_identity_public_b64(b'B');
    let prekey_id = test_prekey_id(b'B');
    let state_signature_b64 =
        test_valid_state_signature_b64(b'B', 1, &envelope_b64, &identity_public_b64, &prekey_id);
    let valid_ack_signature_b64 =
        test_valid_ack_signature_b64(b'B', &room.id, message_id, "Alice", "");

    assert!(acknowledge_message(
        &state,
        bob_id,
        &room.id,
        message_id,
        "Alice",
        1,
        &envelope_b64,
        &identity_public_b64,
        &prekey_id,
        &state_signature_b64,
        "",
        "",
    )
    .await
    .is_err());
    assert!(state.pending.lock().await.contains_key(&PendingKey {
        chat_id: room.id.clone(),
        recipient_username: "Bob".to_string(),
    }));

    let mut forged_ack = URL_SAFE_NO_PAD
        .decode(&valid_ack_signature_b64)
        .expect("ack signature encoding");
    forged_ack[0] ^= 1;
    assert!(acknowledge_message(
        &state,
        bob_id,
        &room.id,
        message_id,
        "Alice",
        1,
        &envelope_b64,
        &identity_public_b64,
        &prekey_id,
        &state_signature_b64,
        &URL_SAFE_NO_PAD.encode(forged_ack),
        "",
    )
    .await
    .is_err());

    assert!(acknowledge_message(
        &state,
        bob_id,
        &room.id,
        "different-message",
        "Alice",
        1,
        &envelope_b64,
        &identity_public_b64,
        &prekey_id,
        &state_signature_b64,
        &valid_ack_signature_b64,
        "",
    )
    .await
    .is_err());
    assert!(state.pending.lock().await.contains_key(&PendingKey {
        chat_id: room.id.clone(),
        recipient_username: "Bob".to_string(),
    }));
}

#[tokio::test]
async fn acknowledgement_action_signature_survives_a_later_state_snapshot() {
    let state = test_state();
    add_test_account(&state, "code-a", "Alice").await;
    add_test_account(&state, "code-b", "Bob").await;
    let (alice_id, _) = add_test_client(&state, "code-a", "Alice").await;
    let (bob_id, _) = add_test_client(&state, "code-b", "Bob").await;
    let room = test_room("ack_later_state");
    state.room_catalog.lock().await.insert(
        room.id.clone(),
        RoomEntry {
            room: room.clone(),
            owner_code_id: test_code_id("code-a"),
        },
    );
    join_room(&state, alice_id, room.id.clone())
        .await
        .expect("Alice joins room");
    join_room(&state, bob_id, room.id.clone())
        .await
        .expect("Bob joins room");
    let message_id = "ack-later-state-message";
    route_test_message_with_id(&state, alice_id, &room.id, &["Bob"], message_id)
        .await
        .expect("message queues");

    let identity_envelope_b64 = test_identity_envelope_b64(9);
    let identity_public_b64 = test_identity_public_b64(b'B');
    let prekey_id = test_prekey_id(b'B');
    let later_state_signature_b64 = test_valid_state_signature_b64(
        b'B',
        2,
        &identity_envelope_b64,
        &identity_public_b64,
        &prekey_id,
    );
    // This signature proves only the acknowledgement action.  It remains
    // valid even though the separately signed identity snapshot advanced
    // after the message was decrypted.
    let action_signature_b64 =
        test_valid_ack_signature_b64(b'B', &room.id, message_id, "Alice", "");

    acknowledge_message(
        &state,
        bob_id,
        &room.id,
        message_id,
        "Alice",
        2,
        &identity_envelope_b64,
        &identity_public_b64,
        &prekey_id,
        &later_state_signature_b64,
        &action_signature_b64,
        "",
    )
    .await
    .expect("action signature accepts later state");
    assert!(state.pending.lock().await.is_empty());
    assert_eq!(
        state
            .accounts
            .lock()
            .await
            .get(&test_code_id("code-b"))
            .expect("Bob account")
            .state_revision,
        2
    );
}

#[tokio::test]
async fn offline_direct_frames_are_consumed_only_by_the_peer() {
    let state = test_state();
    add_test_account(&state, "code-a", "Alice").await;
    add_test_account(&state, "code-b", "Bob").await;
    let (alice_id, mut alice_rx) = add_test_client(&state, "code-a", "Alice").await;
    open_direct(&state, alice_id, "Bob")
        .await
        .expect("direct should open");
    while alice_rx.try_recv().is_ok() {}

    let direct_id = state
        .direct_catalog
        .lock()
        .await
        .values()
        .next()
        .expect("direct")
        .id
        .clone();
    route_test_message(&state, alice_id, &direct_id, &["Bob"])
        .await
        .expect("offline direct should queue");

    join_room(&state, alice_id, direct_id.clone())
        .await
        .expect("sender can join");
    assert!(alice_rx.try_recv().is_err());
    assert_eq!(state.pending.lock().await.len(), 1);

    let (bob_id, mut bob_rx) = add_test_client(&state, "code-b", "Bob").await;
    join_room(&state, bob_id, direct_id.clone())
        .await
        .expect("peer can join");
    let delivered = bob_rx.try_recv().expect("peer receives queued frame");
    let OutboundFrame::Message {
        message_id,
        ciphertext_b64,
        ..
    } = &delivered
    else {
        panic!("expected text frame")
    };
    assert!(!ciphertext_b64.is_empty());
    assert_eq!(state.pending.lock().await.len(), 1);
    acknowledge_message(
        &state,
        bob_id,
        &direct_id,
        message_id,
        "Alice",
        1,
        &URL_SAFE_NO_PAD.encode({
            let mut envelope = [0_u8; 256];
            envelope[0] = IDENTITY_ENVELOPE_VERSION;
            envelope
        }),
        &test_identity_public_b64(b'B'),
        &test_prekey_id(b'B'),
        &test_valid_state_signature_b64(
            b'B',
            1,
            &test_identity_envelope_b64(0),
            &test_identity_public_b64(b'B'),
            &test_prekey_id(b'B'),
        ),
        &test_valid_ack_signature_b64(b'B', &direct_id, message_id, "Alice", ""),
        "",
    )
    .await
    .expect("recipient acknowledgement");
    assert!(state.pending.lock().await.is_empty());
}

#[tokio::test]
async fn room_frames_wait_for_each_existing_account_to_join() {
    let state = test_state();
    add_test_account(&state, "code-a", "Alice").await;
    add_test_account(&state, "code-b", "Bob").await;
    let (alice_id, mut alice_rx) = add_test_client(&state, "code-a", "Alice").await;
    let (bob_id, mut bob_rx) = add_test_client(&state, "code-b", "Bob").await;
    let room = test_room("forum_replay");
    state.room_catalog.lock().await.insert(
        room.id.clone(),
        RoomEntry {
            room: room.clone(),
            owner_code_id: test_code_id("code-a"),
        },
    );
    join_room(&state, alice_id, room.id.clone())
        .await
        .expect("owner joins room");

    route_test_message(&state, alice_id, &room.id, &["Bob"])
        .await
        .expect("room frame should queue");
    assert!(alice_rx.try_recv().is_err());
    assert!(bob_rx.try_recv().is_err());

    join_room(&state, bob_id, room.id.clone())
        .await
        .expect("peer joins room");
    let delivered = bob_rx.try_recv().expect("peer receives queued room frame");
    let OutboundFrame::Message {
        message_id,
        ciphertext_b64,
        ..
    } = &delivered
    else {
        panic!("expected text frame")
    };
    assert!(!ciphertext_b64.is_empty());
    assert_eq!(state.pending.lock().await.len(), 1);
    acknowledge_message(
        &state,
        bob_id,
        &room.id,
        message_id,
        "Alice",
        1,
        &URL_SAFE_NO_PAD.encode({
            let mut envelope = [0_u8; 256];
            envelope[0] = IDENTITY_ENVELOPE_VERSION;
            envelope
        }),
        &test_identity_public_b64(b'B'),
        &test_prekey_id(b'B'),
        &test_valid_state_signature_b64(
            b'B',
            1,
            &test_identity_envelope_b64(0),
            &test_identity_public_b64(b'B'),
            &test_prekey_id(b'B'),
        ),
        &test_valid_ack_signature_b64(b'B', &room.id, message_id, "Alice", ""),
        "",
    )
    .await
    .expect("recipient acknowledgement");
    assert!(state.pending.lock().await.is_empty());
}

#[tokio::test]
async fn acknowledgement_removes_only_matching_sender_and_message() {
    let state = test_state();
    add_test_account(&state, "code-a", "Alice").await;
    add_test_account(&state, "code-b", "Bob").await;
    add_test_account(&state, "code-e", "Eve").await;
    let (alice_id, _) = add_test_client(&state, "code-a", "Alice").await;
    let (bob_id, _) = add_test_client(&state, "code-b", "Bob").await;
    let (eve_id, _) = add_test_client(&state, "code-e", "Eve").await;
    let room = test_room("forum_ack_binding");
    state.room_catalog.lock().await.insert(
        room.id.clone(),
        RoomEntry {
            room: room.clone(),
            owner_code_id: test_code_id("code-a"),
        },
    );
    let shared_message_id = "shared-message-id";

    route_test_message_with_id(
        &state,
        alice_id,
        &room.id,
        &["Bob", "Eve"],
        shared_message_id,
    )
    .await
    .expect("Alice message should queue");
    route_test_message_with_id(
        &state,
        eve_id,
        &room.id,
        &["Alice", "Bob"],
        shared_message_id,
    )
    .await
    .expect("Eve message should queue");

    assert!(acknowledge_message(
        &state,
        bob_id,
        &room.id,
        shared_message_id,
        "Mallory",
        1,
        &URL_SAFE_NO_PAD.encode({
            let mut envelope = [0_u8; 256];
            envelope[0] = IDENTITY_ENVELOPE_VERSION;
            envelope
        }),
        &test_identity_public_b64(b'B'),
        &test_prekey_id(b'B'),
        &test_signature_b64(0),
        &test_signature_b64(0),
        "",
    )
    .await
    .is_err());

    acknowledge_message(
        &state,
        bob_id,
        &room.id,
        shared_message_id,
        "Alice",
        1,
        &URL_SAFE_NO_PAD.encode({
            let mut envelope = [0_u8; 256];
            envelope[0] = IDENTITY_ENVELOPE_VERSION;
            envelope
        }),
        &test_identity_public_b64(b'B'),
        &test_prekey_id(b'B'),
        &test_valid_state_signature_b64(
            b'B',
            1,
            &test_identity_envelope_b64(0),
            &test_identity_public_b64(b'B'),
            &test_prekey_id(b'B'),
        ),
        &test_valid_ack_signature_b64(b'B', &room.id, shared_message_id, "Alice", ""),
        "",
    )
    .await
    .expect("Bob should acknowledge Alice only");

    let pending = state.pending.lock().await;
    let bob_queue = pending
        .get(&PendingKey {
            chat_id: room.id.clone(),
            recipient_username: "Bob".to_string(),
        })
        .expect("Eve message must remain queued for Bob");
    assert_eq!(bob_queue.len(), 1);
    assert!(matches!(
        &bob_queue[0].frame,
        OutboundFrame::Message {
            sender_username,
            message_id,
            ..
        } if sender_username == "Eve" && message_id == shared_message_id
    ));
    drop(pending);

    acknowledge_message(
        &state,
        bob_id,
        &room.id,
        shared_message_id,
        "Eve",
        1,
        &URL_SAFE_NO_PAD.encode({
            let mut envelope = [0_u8; 256];
            envelope[0] = IDENTITY_ENVELOPE_VERSION;
            envelope
        }),
        &test_identity_public_b64(b'B'),
        &test_prekey_id(b'B'),
        &test_valid_state_signature_b64(
            b'B',
            1,
            &test_identity_envelope_b64(0),
            &test_identity_public_b64(b'B'),
            &test_prekey_id(b'B'),
        ),
        &test_valid_ack_signature_b64(b'B', &room.id, shared_message_id, "Eve", ""),
        "",
    )
    .await
    .expect("retry with an older state revision must not roll state backward");
    assert!(!state.pending.lock().await.contains_key(&PendingKey {
        chat_id: room.id,
        recipient_username: "Bob".to_string(),
    }));
}

#[tokio::test]
async fn mismatched_prekey_ack_does_not_advance_recipient_identity_state() {
    let state = test_state();
    add_test_account(&state, "code-a", "Alice").await;
    add_test_account(&state, "code-b", "Bob").await;
    let (bob_id, _) = add_test_client(&state, "code-b", "Bob").await;
    let room = test_room("prekey_ack_order");
    state.room_catalog.lock().await.insert(
        room.id.clone(),
        RoomEntry {
            room,
            owner_code_id: test_code_id("code-a"),
        },
    );
    let prekey_id = test_prekey_id(b'B');
    state.prekey_leases.lock().await.insert(
        PrekeyLeaseKey {
            code_id: test_code_id("code-b"),
            prekey_id: prekey_id.clone(),
        },
        PrekeyLease {
            chat_id: "prekey_ack_order".to_string(),
            message_id: "claimed-message".to_string(),
            sender_username: "Alice".to_string(),
            recipient_username: "Bob".to_string(),
            created_at_ms: now_ms(),
        },
    );

    let result = acknowledge_message(
        &state,
        bob_id,
        "prekey_ack_order",
        "different-message",
        "Alice",
        5,
        &URL_SAFE_NO_PAD.encode({
            let mut envelope = [0_u8; 256];
            envelope[0] = IDENTITY_ENVELOPE_VERSION;
            envelope
        }),
        &test_identity_public_b64(b'B'),
        &prekey_id,
        &test_signature_b64(0),
        &test_signature_b64(0),
        &prekey_id,
    )
    .await;
    assert!(result.is_err());

    let account = state
        .accounts
        .lock()
        .await
        .get(&test_code_id("code-b"))
        .cloned()
        .expect("Bob account");
    assert_eq!(account.state_revision, 0);
    assert_eq!(account.state_revision_window, 1);
    assert!(state
        .prekey_leases
        .lock()
        .await
        .contains_key(&PrekeyLeaseKey {
            code_id: test_code_id("code-b"),
            prekey_id,
        }));
}

#[tokio::test]
async fn prekey_ack_requires_a_matching_lease_before_mutating_state() {
    let state = test_state();
    add_test_account(&state, "code-a", "Alice").await;
    add_test_account(&state, "code-b", "Bob").await;
    let (bob_id, _) = add_test_client(&state, "code-b", "Bob").await;
    let room = test_room("prekey_ack_requires_claim");
    state.room_catalog.lock().await.insert(
        room.id.clone(),
        RoomEntry {
            room,
            owner_code_id: test_code_id("code-a"),
        },
    );

    let result = acknowledge_message(
        &state,
        bob_id,
        "prekey_ack_requires_claim",
        "unclaimed-message",
        "Alice",
        5,
        &URL_SAFE_NO_PAD.encode({
            let mut envelope = [0_u8; 256];
            envelope[0] = IDENTITY_ENVELOPE_VERSION;
            envelope
        }),
        &test_identity_public_b64(b'B'),
        &test_prekey_id(b'B'),
        &test_signature_b64(0),
        &test_signature_b64(0),
        &test_prekey_id(b'B'),
    )
    .await;
    assert!(result.is_err());
    let account = state
        .accounts
        .lock()
        .await
        .get(&test_code_id("code-b"))
        .cloned()
        .expect("Bob account");
    assert_eq!(account.state_revision, 0);
    assert_eq!(account.state_revision_window, 1);
    assert!(state.pending.lock().await.is_empty());
}

#[tokio::test]
async fn replay_sender_quota_does_not_block_another_sender() {
    let state = test_state();
    for index in 0..MAX_REPLAY_IDS_PER_SENDER {
        register_message_id(
            &state,
            "forum_sender_quota",
            "Alice",
            &format!("message-{index}"),
        )
        .await
        .expect("sender quota should fill with unique messages");
    }
    assert!(
        register_message_id(&state, "forum_sender_quota", "Alice", "message-overflow")
            .await
            .is_err()
    );
    assert!(
        register_message_id(&state, "forum_sender_quota", "Bob", "message-1")
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn identity_revision_window_accepts_reordering_once_without_rollback() {
    let state = test_state();
    add_test_account(&state, "code-a", "Alice").await;
    let code_id = test_code_id("code-a");
    let mut revision_two = [2_u8; 256];
    revision_two[0] = IDENTITY_ENVELOPE_VERSION;
    revision_two[1] = 22;
    let mut revision_one = [2_u8; 256];
    revision_one[0] = IDENTITY_ENVELOPE_VERSION;
    revision_one[1] = 11;
    let revision_two_b64 = URL_SAFE_NO_PAD.encode(revision_two);
    let revision_one_b64 = URL_SAFE_NO_PAD.encode(revision_one);
    let identity_public_b64 = test_identity_public_b64(b'A');
    let prekey_id = test_prekey_id(b'A');
    let revision_two_signature = test_valid_state_signature_b64(
        b'A',
        2,
        &revision_two_b64,
        &identity_public_b64,
        &prekey_id,
    );
    let revision_one_signature = test_valid_state_signature_b64(
        b'A',
        1,
        &revision_one_b64,
        &identity_public_b64,
        &prekey_id,
    );

    apply_identity_state(
        &state,
        &code_id,
        2,
        &revision_two_b64,
        &identity_public_b64,
        &prekey_id,
        &revision_two_signature,
        false,
    )
    .await
    .expect("newer revision");
    apply_identity_state(
        &state,
        &code_id,
        1,
        &revision_one_b64,
        &identity_public_b64,
        &prekey_id,
        &revision_one_signature,
        false,
    )
    .await
    .expect("bounded out-of-order revision");
    assert!(apply_identity_state(
        &state,
        &code_id,
        1,
        &revision_one_b64,
        &identity_public_b64,
        &prekey_id,
        &revision_one_signature,
        false,
    )
    .await
    .is_err());

    let accounts = state.accounts.lock().await;
    let account = accounts.get(&code_id).expect("Alice account");
    assert_eq!(account.state_revision, 2);
    assert_eq!(account.identity_envelope, revision_two);
}

#[tokio::test]
async fn identity_state_signature_binds_all_fields_and_limits_revision_jump() {
    let state = test_state();
    add_test_account(&state, "code-a", "Alice").await;
    let code_id = test_code_id("code-a");
    let identity_public_b64 = test_identity_public_b64(b'A');
    let prekey_id = test_prekey_id(b'A');
    let envelope_one_b64 = test_identity_envelope_b64(1);
    let signature_one = test_valid_state_signature_b64(
        b'A',
        1,
        &envelope_one_b64,
        &identity_public_b64,
        &prekey_id,
    );
    apply_identity_state(
        &state,
        &code_id,
        1,
        &envelope_one_b64,
        &identity_public_b64,
        &prekey_id,
        &signature_one,
        false,
    )
    .await
    .expect("valid signed state");

    let envelope_two_b64 = test_identity_envelope_b64(2);
    let signature_two = test_valid_state_signature_b64(
        b'A',
        2,
        &envelope_two_b64,
        &identity_public_b64,
        &prekey_id,
    );
    let mut forged_signature = URL_SAFE_NO_PAD
        .decode(&signature_two)
        .expect("signature encoding");
    forged_signature[0] ^= 1;
    assert!(apply_identity_state(
        &state,
        &code_id,
        2,
        &envelope_two_b64,
        &identity_public_b64,
        &prekey_id,
        &URL_SAFE_NO_PAD.encode(forged_signature),
        false,
    )
    .await
    .is_err());

    let mut tampered_envelope = URL_SAFE_NO_PAD
        .decode(&envelope_two_b64)
        .expect("envelope encoding");
    tampered_envelope[1] ^= 1;
    assert!(apply_identity_state(
        &state,
        &code_id,
        2,
        &URL_SAFE_NO_PAD.encode(tampered_envelope),
        &identity_public_b64,
        &prekey_id,
        &signature_two,
        false,
    )
    .await
    .is_err());

    let mut tampered_public = URL_SAFE_NO_PAD
        .decode(&identity_public_b64)
        .expect("public encoding");
    tampered_public[0] ^= 1;
    assert!(apply_identity_state(
        &state,
        &code_id,
        2,
        &envelope_two_b64,
        &URL_SAFE_NO_PAD.encode(tampered_public),
        &prekey_id,
        &signature_two,
        false,
    )
    .await
    .is_err());

    assert!(apply_identity_state(
        &state,
        &code_id,
        2,
        &envelope_two_b64,
        &identity_public_b64,
        "wrong-prekey",
        &signature_two,
        false,
    )
    .await
    .is_err());
    assert!(apply_identity_state(
        &state,
        &code_id,
        3,
        &envelope_two_b64,
        &identity_public_b64,
        &prekey_id,
        &signature_two,
        false,
    )
    .await
    .is_err());

    let huge_revision = 1 + MAX_STATE_REVISION_ADVANCE + 1;
    let huge_signature = test_valid_state_signature_b64(
        b'A',
        huge_revision,
        &envelope_two_b64,
        &identity_public_b64,
        &prekey_id,
    );
    assert!(apply_identity_state(
        &state,
        &code_id,
        huge_revision,
        &envelope_two_b64,
        &identity_public_b64,
        &prekey_id,
        &huge_signature,
        false,
    )
    .await
    .is_err());

    let account = state
        .accounts
        .lock()
        .await
        .get(&code_id)
        .cloned()
        .expect("Alice account");
    assert_eq!(account.state_revision, 1);
    assert_eq!(
        account.identity_envelope,
        URL_SAFE_NO_PAD.decode(envelope_one_b64).unwrap()
    );
}

#[tokio::test]
async fn stale_reusable_state_requires_the_current_public_bundle() {
    let state = test_state();
    add_test_account(&state, "code-a", "Alice").await;
    let code_id = test_code_id("code-a");
    let current_public_b64 = test_identity_public_b64(b'A');
    let current_prekey_id = test_prekey_id(b'A');
    let current_envelope_b64 = test_identity_envelope_b64(7);
    let current_signature = test_valid_state_signature_b64(
        b'A',
        129,
        &current_envelope_b64,
        &current_public_b64,
        &current_prekey_id,
    );
    apply_identity_state(
        &state,
        &code_id,
        129,
        &current_envelope_b64,
        &current_public_b64,
        &current_prekey_id,
        &current_signature,
        false,
    )
    .await
    .expect("current state");

    let mut stale_public = test_identity_public(b'A');
    for (index, (_, public)) in test_prekey_pool(b'Z').into_iter().enumerate() {
        let start = ONE_TIME_KEY_OFFSET + (index * ONE_TIME_KEY_BYTES);
        stale_public[start..start + ONE_TIME_KEY_BYTES].copy_from_slice(&public);
    }
    let stale_public_b64 = URL_SAFE_NO_PAD.encode(&stale_public);
    let stale_prekey_id = test_prekey_id(b'Z');
    let stale_envelope_b64 = test_identity_envelope_b64(8);
    let stale_signature = test_valid_state_signature_b64(
        b'A',
        1,
        &stale_envelope_b64,
        &stale_public_b64,
        &stale_prekey_id,
    );

    assert!(apply_identity_state(
        &state,
        &code_id,
        1,
        &stale_envelope_b64,
        &stale_public_b64,
        &stale_prekey_id,
        &stale_signature,
        true,
    )
    .await
    .is_err());
    let account = state
        .accounts
        .lock()
        .await
        .get(&code_id)
        .cloned()
        .expect("Alice account");
    assert_eq!(account.state_revision, 129);
    assert_eq!(
        account.identity_public,
        URL_SAFE_NO_PAD.decode(current_public_b64).unwrap()
    );
    assert_eq!(account.prekey_id, current_prekey_id);
}

#[tokio::test]
async fn account_code_allows_only_one_unexpired_session() {
    let state = test_state();
    let code = "ABYS-SESSION-0001";
    let code_id = test_code_id(code);
    state.sessions.lock().await.insert(
        SessionToken::new("active-token".to_string()),
        AuthSession {
            code_id,
            username: "Alice".to_string(),
            last_activity_ms: now_ms(),
        },
    );
    assert!(code_has_active_session(&state, &code_id).await);

    state
        .sessions
        .lock()
        .await
        .get_mut("active-token")
        .expect("session")
        .last_activity_ms = 0;
    assert!(!code_has_active_session(&state, &code_id).await);
    assert!(state.sessions.lock().await.is_empty());
}

#[tokio::test]
async fn stale_socket_cleanup_cannot_release_new_active_connection() {
    let state = test_state();
    add_test_account(&state, "code-a", "Alice").await;
    let (old_client, _) = add_test_client(&state, "code-a", "Alice").await;
    let code_id = test_code_id("code-a");
    state
        .active_connections
        .lock()
        .await
        .insert(code_id, old_client);

    replace_connected_clients_for_code(&state, &code_id).await;
    let (new_client, _) = add_test_client(&state, "code-a", "Alice").await;
    state
        .active_connections
        .lock()
        .await
        .insert(code_id, new_client);

    cleanup_client(&state, old_client).await;

    assert_eq!(
        state.active_connections.lock().await.get(&code_id).copied(),
        Some(new_client)
    );
}

#[tokio::test]
async fn interop_policy_requires_a_known_allowed_recipient_platform() {
    let state = test_state();
    add_test_account(&state, "code-b", "Bob").await;
    let recipients = HashSet::from(["Bob".to_string()]);

    state
        .accounts
        .lock()
        .await
        .get_mut(&test_code_id("code-b"))
        .expect("Bob account")
        .client_platform = Some(ClientPlatform::Web);
    assert!(
        require_recipient_platforms(&state, ClientPlatform::Android, &recipients)
            .await
            .is_err()
    );
    assert!(
        require_recipient_platforms(&state, ClientPlatform::Web, &recipients)
            .await
            .is_ok()
    );

    state
        .accounts
        .lock()
        .await
        .get_mut(&test_code_id("code-b"))
        .expect("Bob account")
        .client_platform = None;
    assert!(
        require_recipient_platforms(&state, ClientPlatform::Web, &recipients)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn pending_android_ciphertext_is_not_delivered_to_a_web_connection() {
    let state = test_state();
    add_test_account(&state, "code-a", "Alice").await;
    add_test_account(&state, "code-b", "Bob").await;
    let (alice_id, _alice_rx) = add_test_client(&state, "code-a", "Alice").await;
    let (bob_id, mut bob_rx) = add_test_client(&state, "code-b", "Bob").await;
    state
        .clients
        .lock()
        .await
        .get_mut(&bob_id)
        .expect("Bob client")
        .platform = ClientPlatform::Web;
    state
        .accounts
        .lock()
        .await
        .get_mut(&test_code_id("code-b"))
        .expect("Bob account")
        .client_platform = Some(ClientPlatform::Web);

    open_direct(&state, alice_id, "Bob")
        .await
        .expect("direct opens");
    let direct_id = state
        .direct_catalog
        .lock()
        .await
        .values()
        .next()
        .expect("direct catalog entry")
        .id
        .clone();
    while bob_rx.try_recv().is_ok() {}
    let frame = test_message_frame(&direct_id, "android-only", "Alice", "", false);
    state.pending.lock().await.insert(
        PendingKey {
            chat_id: direct_id.clone(),
            recipient_username: "Bob".to_string(),
        },
        vec![PendingFrame::new_for_platform(
            frame,
            now_ms(),
            ClientPlatform::Android,
        )],
    );

    join_room(&state, bob_id, direct_id)
        .await
        .expect("authorized peer joins");
    assert!(bob_rx.try_recv().is_err());
}

fn test_state() -> AppState {
    AppState {
        node_id: "test-node".to_string(),
        release_admission: Arc::new(ReleaseAdmissionStore::ready_for_tests()),
        attachment_ram_limit_bytes: 8 * 1024 * 1024,
        attachment_account_limit_bytes: 4 * 1024 * 1024,
        attachment_record_limit: DEFAULT_ATTACHMENT_RECORD_LIMIT,
        attachment_account_record_limit: DEFAULT_ATTACHMENT_ACCOUNT_RECORD_LIMIT,
        attachment_max_lifetime_sec: DEFAULT_ATTACHMENT_MAX_LIFETIME_HOURS as u64 * 60 * 60,
        max_rooms_per_user: 2,
        interop_policy: InteropPolicy::new(false, true),
        conversation_ops: Arc::new(Mutex::new(())),
        presence_broadcast_ops: Arc::new(Mutex::new(())),
        pending_message_ttl_ms: pending_message_ttl_ms_from_value(None),
        web_origins: Vec::new(),
        session_inactivity_ms: 60_000,
        inactivity_limit_ms: None,
        last_activity_ms: Arc::new(Mutex::new(now_ms())),
        account_ops: Arc::new(Mutex::new(())),
        opaque_setup: Arc::new(Zeroizing::new(opaque_server_setup())),
        opaque_handshakes: Arc::new(Mutex::new(HashMap::new())),
        invite_code_pepper: Arc::new(Zeroizing::new([7_u8; 32])),
        boot_codes: Arc::new(Mutex::new(None)),
        available_codes: Arc::new(Mutex::new(HashSet::new())),
        accounts: Arc::new(Mutex::new(HashMap::new())),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        ws_tickets: Arc::new(Mutex::new(HashMap::new())),
        clients: Arc::new(Mutex::new(HashMap::new())),
        purge_epoch: watch::channel(0_u64).0,
        outbound_bytes: Arc::new(AtomicUsize::new(0)),
        active_connections: Arc::new(Mutex::new(HashMap::new())),
        frame_limits: Arc::new(Mutex::new(HashMap::new())),
        login_limits: Arc::new(Mutex::new(HashMap::new())),
        replay_ids: Arc::new(Mutex::new(HashMap::new())),
        transaction_receipts: Arc::new(Mutex::new(TransactionReceiptStore::new(
            pending_message_ttl_ms_from_value(None),
        ))),
        mls_rooms: Arc::new(Mutex::new(rooms::RoomAuthority::new(2))),
        rooms: Arc::new(Mutex::new(HashMap::new())),
        room_catalog: Arc::new(Mutex::new(HashMap::new())),
        direct_catalog: Arc::new(Mutex::new(HashMap::new())),
        pending: Arc::new(Mutex::new(HashMap::new())),
        pending_bytes: Arc::new(Mutex::new(0)),
        attachment_bindings: Arc::new(Mutex::new(HashMap::new())),
        attachments: Arc::new(Mutex::new(HashMap::new())),
        attachment_bytes_by_code: Arc::new(Mutex::new(HashMap::new())),
        attachment_downloads: Arc::new(Semaphore::new(DEFAULT_ATTACHMENT_DOWNLOAD_CONCURRENCY)),
        attachment_uploads: Arc::new(Semaphore::new(1)),
        attachment_memory: Arc::new(Semaphore::new(8 * 1024 * 1024)),
        attachment_epoch: Arc::new(AtomicU64::new(0)),
        prekey_leases: Arc::new(Mutex::new(HashMap::new())),
    }
}

async fn add_test_account(state: &AppState, code: &str, username: &str) {
    add_test_account_with_id(state, test_code_id(code), username, ClientPlatform::Android).await;
}

async fn add_test_account_with_id(
    state: &AppState,
    code_id: CodeId,
    username: &str,
    client_platform: ClientPlatform,
) {
    let identity_fill = username.as_bytes()[0];
    let mut identity_envelope = vec![0; 256];
    identity_envelope[0] = IDENTITY_ENVELOPE_VERSION;
    state.accounts.lock().await.insert(
        code_id,
        Account {
            username: username.to_string(),
            password_file: vec![1; 192],
            identity_public: test_identity_public(identity_fill),
            prekey_id: test_prekey_id(identity_fill),
            identity_envelope,
            state_revision: 0,
            state_revision_window: 1,
            connected: true,
            client_platform: Some(client_platform),
            attachment_uploads: Arc::new(Semaphore::new(1)),
        },
    );
}

type AckTestAccountState = (u64, u128, Vec<u8>, Vec<u8>, String);
type AckTestFrameState = (u64, serde_json::Value);
type AckTestClaimState = ([u8; 32], String, String, String, String, String, u64);

async fn ack_test_snapshot(
    state: &AppState,
    code_id: &CodeId,
    pending_key: &PendingKey,
) -> (
    AckTestAccountState,
    usize,
    Vec<AckTestFrameState>,
    Vec<AckTestClaimState>,
) {
    let account = state
        .accounts
        .lock()
        .await
        .get(code_id)
        .map(|account| {
            (
                account.state_revision,
                account.state_revision_window,
                account.identity_envelope.clone(),
                account.identity_public.clone(),
                account.prekey_id.clone(),
            )
        })
        .expect("ack test account");
    let pending_bytes = *state.pending_bytes.lock().await;
    let pending_frames = state
        .pending
        .lock()
        .await
        .get(pending_key)
        .expect("ack test pending queue")
        .iter()
        .map(|pending_frame| {
            (
                pending_frame.enqueued_at_ms,
                serde_json::to_value(&pending_frame.frame).expect("ack test frame JSON"),
            )
        })
        .collect();
    let mut claims = state
        .prekey_leases
        .lock()
        .await
        .iter()
        .map(|(key, claim)| {
            (
                key.code_id,
                key.prekey_id.clone(),
                claim.chat_id.clone(),
                claim.message_id.clone(),
                claim.sender_username.clone(),
                claim.recipient_username.clone(),
                claim.created_at_ms,
            )
        })
        .collect::<Vec<_>>();
    claims.sort_by(|left, right| left.1.cmp(&right.1));
    (account, pending_bytes, pending_frames, claims)
}

async fn route_test_message(
    state: &AppState,
    sender_id: Uuid,
    chat_id: &str,
    recipients: &[&str],
) -> Result<(), String> {
    route_test_message_with_id(
        state,
        sender_id,
        chat_id,
        recipients,
        &Uuid::new_v4().to_string(),
    )
    .await
}

async fn route_test_message_with_id(
    state: &AppState,
    sender_id: Uuid,
    chat_id: &str,
    recipients: &[&str],
    message_id: &str,
) -> Result<(), String> {
    let (code_id, sender_username) = client_identity(state, sender_id).await?;
    let (state_revision, identity_public, identity_public_b64, prekey_id) = state
        .accounts
        .lock()
        .await
        .get(&code_id)
        .map(|account| {
            (
                account.state_revision + 1,
                account.identity_public.clone(),
                URL_SAFE_NO_PAD.encode(&account.identity_public),
                account.prekey_id.clone(),
            )
        })
        .ok_or_else(|| "missing test account".to_string())?;
    let identity_envelope_b64 = test_identity_envelope_b64(0);
    let state_signature_b64 = test_valid_state_signature_b64(
        sender_username.as_bytes()[0],
        state_revision,
        &identity_envelope_b64,
        &identity_public_b64,
        &prekey_id,
    );
    route_encrypted_message(
        state,
        sender_id,
        chat_id.to_string(),
        E2EE_PROTOCOL_VERSION,
        message_id.to_string(),
        URL_SAFE_NO_PAD.encode([2_u8; MESSAGE_NONCE_BYTES]),
        URL_SAFE_NO_PAD.encode(b"ciphertext"),
        recipients
            .iter()
            .map(|username| {
                let wrapped_key = [4_u8; 256];
                InboundRecipientEnvelope {
                    recipient_username: (*username).to_string(),
                    wrapped_key_b64: URL_SAFE_NO_PAD.encode(wrapped_key),
                    prekey_id: String::new(),
                    is_prekey: false,
                    signature_b64: test_valid_message_signature_b64(
                        sender_username.as_bytes()[0],
                        chat_id,
                        message_id,
                        &sender_username,
                        &identity_public,
                        username,
                        &wrapped_key,
                        "",
                        false,
                    ),
                }
            })
            .collect(),
        state_revision,
        identity_envelope_b64,
        identity_public_b64,
        prekey_id,
        state_signature_b64,
    )
    .await
}

async fn route_test_message_with_envelopes(
    state: &AppState,
    sender_id: Uuid,
    chat_id: &str,
    version: u32,
    message_id: &str,
    envelopes: Vec<InboundRecipientEnvelope>,
) -> Result<(), String> {
    let (code_id, sender_username) = client_identity(state, sender_id).await?;
    let state_revision = state
        .accounts
        .lock()
        .await
        .get(&code_id)
        .map(|account| account.state_revision + 1)
        .ok_or_else(|| "missing test account".to_string())?;
    let (identity_public_b64, prekey_id) = state
        .accounts
        .lock()
        .await
        .get(&code_id)
        .map(|account| {
            (
                URL_SAFE_NO_PAD.encode(&account.identity_public),
                account.prekey_id.clone(),
            )
        })
        .ok_or_else(|| "missing test account".to_string())?;
    let identity_envelope_b64 = test_identity_envelope_b64(0);
    let state_signature_b64 = test_valid_state_signature_b64(
        sender_username.as_bytes()[0],
        state_revision,
        &identity_envelope_b64,
        &identity_public_b64,
        &prekey_id,
    );
    route_encrypted_message(
        state,
        sender_id,
        chat_id.to_string(),
        version,
        message_id.to_string(),
        URL_SAFE_NO_PAD.encode([2_u8; MESSAGE_NONCE_BYTES]),
        URL_SAFE_NO_PAD.encode(b"ciphertext"),
        envelopes,
        state_revision,
        identity_envelope_b64,
        identity_public_b64,
        prekey_id,
        state_signature_b64,
    )
    .await
}

async fn add_test_client(
    state: &AppState,
    code: &str,
    username: &str,
) -> (Uuid, mpsc::Receiver<OutboundFrame>) {
    let client_id = Uuid::new_v4();
    let (tx, rx) = mpsc::channel(CLIENT_OUTBOUND_QUEUE_CAPACITY);
    let (control_tx, _control_rx) = mpsc::channel(CLIENT_CONTROL_QUEUE_CAPACITY);
    let (result_tx, _result_rx) = mpsc::channel(CLIENT_RESULT_QUEUE_CAPACITY);
    state.clients.lock().await.insert(
        client_id,
        ClientHandle {
            code_id: test_code_id(code),
            username: username.to_string(),
            platform: ClientPlatform::Android,
            tx,
            control_tx,
            result_tx,
            queued_bytes: Arc::new(AtomicUsize::new(0)),
        },
    );
    (client_id, rx)
}

async fn add_test_client_with_result(
    state: &AppState,
    code: &str,
    username: &str,
) -> (
    Uuid,
    mpsc::Receiver<OutboundFrame>,
    mpsc::Receiver<ClientResult>,
) {
    let client_id = Uuid::new_v4();
    let (tx, rx) = mpsc::channel(CLIENT_OUTBOUND_QUEUE_CAPACITY);
    let (control_tx, _control_rx) = mpsc::channel(CLIENT_CONTROL_QUEUE_CAPACITY);
    let (result_tx, result_rx) = mpsc::channel(CLIENT_RESULT_QUEUE_CAPACITY);
    state.clients.lock().await.insert(
        client_id,
        ClientHandle {
            code_id: test_code_id(code),
            username: username.to_string(),
            platform: ClientPlatform::Android,
            tx,
            control_tx,
            result_tx,
            queued_bytes: Arc::new(AtomicUsize::new(0)),
        },
    );
    (client_id, rx, result_rx)
}

fn test_code_id(code: &str) -> CodeId {
    derive_code_id(&[7_u8; 32], code)
}

fn test_attachment_blob(bytes: Vec<u8>) -> Arc<AttachmentBlob> {
    Arc::new(AttachmentBlob {
        bytes: Zeroizing::new(bytes),
        _memory_permit: None,
    })
}

fn test_valid_encrypted_attachment_body(plaintext_bytes: usize) -> Vec<u8> {
    abyssal_core::secure_protocol::encrypt_attachment(
        "test_room".to_string(),
        "test-message".to_string(),
        "Alice".to_string(),
        "FILE".to_string(),
        vec![0x5a; plaintext_bytes],
    )
    .expect("test attachment encryption")
    .blob
}

fn test_identity_public_b64(fill: u8) -> String {
    URL_SAFE_NO_PAD.encode(test_identity_public(fill))
}

fn test_identity_public(fill: u8) -> Vec<u8> {
    let signing_key = test_signing_key(fill);
    let mut identity_public = vec![fill; IDENTITY_PUBLIC_BYTES];
    identity_public[IDENTITY_FINGERPRINT_BYTES - 32..IDENTITY_FINGERPRINT_BYTES]
        .copy_from_slice(signing_key.verifying_key().as_bytes());
    for (index, (_, public)) in test_prekey_pool(fill).into_iter().enumerate() {
        let start = ONE_TIME_KEY_OFFSET + (index * ONE_TIME_KEY_BYTES);
        identity_public[start..start + ONE_TIME_KEY_BYTES].copy_from_slice(&public);
    }
    identity_public
}

fn test_signing_key(fill: u8) -> SigningKey {
    SigningKey::from_bytes(&[fill; 32])
}

fn test_prekey_id(fill: u8) -> String {
    test_prekey_pool(fill)
        .into_iter()
        .next()
        .expect("test prekey pool")
        .0
}

fn test_prekey_pool(fill: u8) -> Vec<(String, [u8; ONE_TIME_KEY_BYTES])> {
    let mut pool = (0..PREKEY_POOL_SIZE_V9)
        .map(|index| {
            let public = [fill.wrapping_add(index as u8); ONE_TIME_KEY_BYTES];
            (
                abyssal_core::secure_protocol::prekey_id_for_public(&public),
                public,
            )
        })
        .collect::<Vec<_>>();
    pool.sort_by(|left, right| left.0.cmp(&right.0));
    pool
}

fn test_identity_public_after_consumption(fill: u8, consumed_prekey_id: &str) -> (Vec<u8>, String) {
    let mut pool = test_prekey_pool(fill);
    pool.retain(|(id, _)| id != consumed_prekey_id);
    let replacement = (1_u16..=u8::MAX as u16)
        .map(|offset| [fill.wrapping_add(offset as u8); ONE_TIME_KEY_BYTES])
        .map(|public| {
            (
                abyssal_core::secure_protocol::prekey_id_for_public(&public),
                public,
            )
        })
        .find(|(id, _)| {
            id != consumed_prekey_id && !pool.iter().any(|(existing, _)| existing == id)
        })
        .expect("replacement prekey");
    pool.push(replacement);
    pool.sort_by(|left, right| left.0.cmp(&right.0));
    let current_prekey_id = pool.first().expect("rotated pool").0.clone();
    let mut identity_public = test_identity_public(fill);
    for (index, (_, public)) in pool.into_iter().enumerate() {
        let start = ONE_TIME_KEY_OFFSET + (index * ONE_TIME_KEY_BYTES);
        identity_public[start..start + ONE_TIME_KEY_BYTES].copy_from_slice(&public);
    }
    (identity_public, current_prekey_id)
}

fn test_signature_b64(fill: u8) -> String {
    URL_SAFE_NO_PAD.encode([fill; MESSAGE_SIGNATURE_BYTES])
}

fn test_identity_envelope_b64(fill: u8) -> String {
    let mut envelope = [fill; 256];
    envelope[0] = IDENTITY_ENVELOPE_VERSION;
    URL_SAFE_NO_PAD.encode(envelope)
}

fn test_valid_state_signature_b64(
    fill: u8,
    revision: u64,
    identity_envelope_b64: &str,
    identity_public_b64: &str,
    prekey_id: &str,
) -> String {
    let envelope = URL_SAFE_NO_PAD
        .decode(identity_envelope_b64)
        .expect("test identity envelope");
    let identity_public = URL_SAFE_NO_PAD
        .decode(identity_public_b64)
        .expect("test identity public");
    let transcript = abyssal_core::secure_protocol::identity_state_signature_input_v9(
        E2EE_PROTOCOL_VERSION,
        revision,
        &envelope,
        &identity_public,
        prekey_id,
    )
    .expect("test identity state transcript");
    let signature = test_signing_key(fill).sign(&transcript);
    URL_SAFE_NO_PAD.encode(signature.to_bytes())
}

fn test_valid_ack_signature_b64(
    fill: u8,
    chat_id: &str,
    message_id: &str,
    sender_username: &str,
    used_prekey_id: &str,
) -> String {
    let transcript = abyssal_core::secure_protocol::ack_signature_input_v9(
        E2EE_PROTOCOL_VERSION,
        chat_id,
        message_id,
        sender_username,
        used_prekey_id,
    )
    .expect("test acknowledgement transcript");
    let signature = test_signing_key(fill).sign(&transcript);
    URL_SAFE_NO_PAD.encode(signature.to_bytes())
}

#[allow(clippy::too_many_arguments)]
fn test_valid_message_signature_b64(
    fill: u8,
    chat_id: &str,
    message_id: &str,
    sender_username: &str,
    identity_public: &[u8],
    recipient_username: &str,
    wrapped_key: &[u8],
    prekey_id: &str,
    is_prekey: bool,
) -> String {
    let transcript = abyssal_core::secure_protocol::message_signature_input_v9(
        E2EE_PROTOCOL_VERSION,
        chat_id,
        message_id,
        sender_username,
        identity_public,
        &[2_u8; MESSAGE_NONCE_BYTES],
        b"ciphertext",
        recipient_username,
        wrapped_key,
        prekey_id,
        is_prekey,
    )
    .expect("test transcript");
    let signature = test_signing_key(fill).sign(&transcript);
    URL_SAFE_NO_PAD.encode(signature.to_bytes())
}

fn test_message_frame(
    chat_id: &str,
    message_id: &str,
    sender_username: &str,
    prekey_id: &str,
    is_prekey: bool,
) -> OutboundFrame {
    let mut frame = OutboundFrame::Message {
        chat_id: chat_id.to_string(),
        version: E2EE_PROTOCOL_VERSION,
        message_id: message_id.to_string(),
        nonce_b64: "nonce".to_string(),
        ciphertext_b64: "ciphertext".to_string(),
        signature_b64: "signature".to_string(),
        wrapped_key_b64: "wrapped".to_string(),
        prekey_id: prekey_id.to_string(),
        is_prekey,
        sender_username: sender_username.to_string(),
        sender_public_key_b64: "public".to_string(),
        identity_public_b64: "public".to_string(),
        directory_node_id: "test-node".to_string(),
        directory_revision: 1,
        directory_digest: URL_SAFE_NO_PAD.encode([0_u8; 32]),
        padding_bucket: 0,
        padding: String::new(),
    };
    prepare_outbound_message_padding(&mut frame).expect("test message transport padding");
    frame
}

fn test_room(id: &str) -> RoomRecord {
    RoomRecord {
        id: id.to_string(),
        name: id.to_string(),
        owner_username: "SilentNode123".to_string(),
        self_destruct_timer_sec: 5,
        overall_expiry_sec: 0,
        allow_images: true,
        allow_videos: true,
        allow_files: true,
        enforce_text_absolute_expiry: false,
        image_read_timer_sec: 5,
        image_overall_expiry_sec: 0,
        enforce_image_absolute_expiry: false,
        video_read_timer_sec: 5,
        video_overall_expiry_sec: 0,
        enforce_video_absolute_expiry: false,
        file_read_timer_sec: 5,
        file_overall_expiry_sec: 0,
        enforce_file_absolute_expiry: false,
    }
}

#[test]
fn hmac_sha256_matches_rfc_4231_known_answer() {
    // RFC 4231, test case 2.
    let mut mac = HmacSha256::new_from_slice(b"Jefe").expect("HMAC accepts any key length");
    mac.update(b"what do ya want for nothing?");
    let mut output = [0_u8; 32];
    output.copy_from_slice(&mac.finalize().into_bytes());
    assert_eq!(
        output,
        [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
            0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
            0x64, 0xec, 0x38, 0x43,
        ]
    );
}
