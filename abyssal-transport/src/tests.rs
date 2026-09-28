use crate::{
    bootstrap::decode_for_test,
    derive_opaque_transport_root, generate_bootstrap_keypair, inspect_bootstrap_request,
    inspect_http_record, open_ws_server_hello,
    records::{decode_http_for_test, decode_ws_for_test},
    seal_bootstrap_request, seal_ws_server_hello, BootstrapContext, BootstrapPrivateKey,
    BootstrapReplayGuard, ConnectionNonce, Direction, HttpSessionBinding, TransportError,
    WsConnectionBinding, MAX_AAD_BYTES, MAX_BOOTSTRAP_PLAINTEXT_BYTES, MAX_BOOTSTRAP_REPLAY_TTL_MS,
    MAX_HTTP_HANDLES, MAX_RECORD_PLAINTEXT_BYTES, MAX_WS_RECORD_PLAINTEXT_BYTES,
    MIN_BOOTSTRAP_REPLAY_TTL_MS,
};
use zeroize::Zeroizing;

const TEST_REPLAY_TTL_MS: u64 = 100;

fn bootstrap_context(public_key: [u8; 32], request_id: [u8; 32]) -> BootstrapContext {
    BootstrapContext::new([7; 32], public_key, b"opaque-login".to_vec(), request_id).unwrap()
}

fn ws_binding(session: u8, client: u8, server: u8) -> WsConnectionBinding {
    WsConnectionBinding::new(
        [session; 32],
        ConnectionNonce::new([client; 32]).unwrap(),
        ConnectionNonce::new([server; 32]).unwrap(),
    )
    .unwrap()
}

#[test]
fn bootstrap_secret_debug_is_redacted() {
    let keys = generate_bootstrap_keypair();
    assert_eq!(
        format!("{:?}", keys.private_key()),
        "BootstrapPrivateKey(<redacted>)"
    );
    let debug = format!("{keys:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("private_key: ["));
}

#[test]
fn hpke_request_exporter_response_and_replay_guard_round_trip() {
    let keys = generate_bootstrap_keypair();
    let context = bootstrap_context(keys.public_key, [9; 32]);
    let client = seal_bootstrap_request(&context, b"request").unwrap();
    let mut guard = BootstrapReplayGuard::new(TEST_REPLAY_TTL_MS).unwrap();
    let server = guard
        .open_request(keys.private_key(), &context, &client.request, 100)
        .unwrap();
    assert_eq!(server.plaintext.as_slice(), b"request");
    let response = server.response_sealer.seal(b"response").unwrap();
    assert_eq!(
        client.response_opener.open(&response).unwrap().as_slice(),
        b"response"
    );
    assert_eq!(
        guard
            .open_request(keys.private_key(), &context, &client.request, 100)
            .err(),
        Some(TransportError::Replay)
    );
    let wrong_keys = generate_bootstrap_keypair();
    assert_eq!(
        guard
            .open_request(wrong_keys.private_key(), &context, &client.request, 100)
            .err(),
        Some(TransportError::Replay)
    );
    let mut forged_replay = client.request;
    *forged_replay.last_mut().unwrap() ^= 1;
    assert_eq!(
        guard
            .open_request(keys.private_key(), &context, &forged_replay, 100)
            .err(),
        Some(TransportError::Replay)
    );
}

#[test]
fn failed_bootstrap_authentication_does_not_consume_request_id() {
    let keys = generate_bootstrap_keypair();
    let context = bootstrap_context(keys.public_key, [10; 32]);
    let client = seal_bootstrap_request(&context, b"request").unwrap();
    let mut tampered = client.request.clone();
    *tampered.last_mut().unwrap() ^= 1;
    let mut guard = BootstrapReplayGuard::new(TEST_REPLAY_TTL_MS).unwrap();
    assert_eq!(
        guard
            .open_request(keys.private_key(), &context, &tampered, 100)
            .err(),
        Some(TransportError::AuthenticationFailed)
    );
    assert!(guard
        .open_request(keys.private_key(), &context, &client.request, 100)
        .is_ok());

    let next_context = bootstrap_context(keys.public_key, [11; 32]);
    let next = seal_bootstrap_request(&next_context, b"next").unwrap();
    let mut full = BootstrapReplayGuard::new(TEST_REPLAY_TTL_MS).unwrap();
    full.fill_to_capacity_for_test();
    let wrong_keys = generate_bootstrap_keypair();
    assert_eq!(
        full.open_request(wrong_keys.private_key(), &next_context, &next.request, 1)
            .err(),
        Some(TransportError::CapacityExhausted)
    );
    assert_eq!(
        full.open_request(keys.private_key(), &next_context, &next.request, 1)
            .err(),
        Some(TransportError::CapacityExhausted)
    );
}

#[test]
fn discarded_bootstrap_request_is_timestamp_bound_to_its_own_id() {
    let keys = generate_bootstrap_keypair();
    let first_context = bootstrap_context(keys.public_key, [30; 32]);
    let first = seal_bootstrap_request(&first_context, b"first").unwrap();
    let second_context = bootstrap_context(keys.public_key, [31; 32]);
    let second = seal_bootstrap_request(&second_context, b"second").unwrap();
    let mut guard = BootstrapReplayGuard::new(TEST_REPLAY_TTL_MS).unwrap();
    assert!(guard
        .open_request(keys.private_key(), &first_context, &first.request, 100)
        .is_ok());
    assert!(guard
        .open_request(keys.private_key(), &second_context, &second.request, 101)
        .is_ok());
    assert!(!guard.discard_authenticated_request(first_context.request_id, 101));
    assert_eq!(
        guard
            .open_request(keys.private_key(), &first_context, &first.request, 102)
            .err(),
        Some(TransportError::Replay)
    );
    assert!(guard.discard_authenticated_request(first_context.request_id, 100));
    assert!(guard
        .open_request(keys.private_key(), &first_context, &first.request, 102)
        .is_ok());
    assert_eq!(
        guard
            .open_request(keys.private_key(), &second_context, &second.request, 102)
            .err(),
        Some(TransportError::Replay)
    );
}

#[test]
fn replay_guard_expires_ids_and_recovers_capacity() {
    let keys = generate_bootstrap_keypair();
    let context = bootstrap_context(keys.public_key, [12; 32]);
    let client = seal_bootstrap_request(&context, b"request").unwrap();
    let mut guard = BootstrapReplayGuard::new(TEST_REPLAY_TTL_MS).unwrap();
    assert!(guard
        .open_request(keys.private_key(), &context, &client.request, 10)
        .is_ok());
    assert_eq!(
        guard
            .open_request(keys.private_key(), &context, &client.request, 109)
            .err(),
        Some(TransportError::Replay)
    );
    assert!(guard
        .open_request(keys.private_key(), &context, &client.request, 110)
        .is_ok());

    let next_context = bootstrap_context(keys.public_key, [13; 32]);
    let next = seal_bootstrap_request(&next_context, b"next").unwrap();
    let mut full = BootstrapReplayGuard::new(TEST_REPLAY_TTL_MS).unwrap();
    full.fill_to_capacity_for_test();
    assert!(full
        .open_request(
            keys.private_key(),
            &next_context,
            &next.request,
            TEST_REPLAY_TTL_MS
        )
        .is_ok());
}

#[test]
fn replay_guard_rejects_invalid_ttl_and_clock_rollback() {
    assert!(BootstrapReplayGuard::new(MIN_BOOTSTRAP_REPLAY_TTL_MS).is_ok());
    assert!(BootstrapReplayGuard::new(MAX_BOOTSTRAP_REPLAY_TTL_MS).is_ok());
    assert_eq!(
        BootstrapReplayGuard::new(MIN_BOOTSTRAP_REPLAY_TTL_MS - 1).err(),
        Some(TransportError::InvalidInput)
    );
    assert_eq!(
        BootstrapReplayGuard::new(MAX_BOOTSTRAP_REPLAY_TTL_MS + 1).err(),
        Some(TransportError::InvalidInput)
    );

    let keys = generate_bootstrap_keypair();
    let context = bootstrap_context(keys.public_key, [14; 32]);
    let client = seal_bootstrap_request(&context, b"request").unwrap();
    let mut guard = BootstrapReplayGuard::new(TEST_REPLAY_TTL_MS).unwrap();
    assert!(guard
        .open_request(keys.private_key(), &context, &client.request, 100)
        .is_ok());
    assert_eq!(
        guard
            .open_request(keys.private_key(), &context, &client.request, 99)
            .err(),
        Some(TransportError::ClockRollback)
    );
}

#[test]
fn hpke_rejects_wrong_key_context_tamper_and_bad_frames() {
    let keys = generate_bootstrap_keypair();
    let context = bootstrap_context(keys.public_key, [9; 32]);
    let client = seal_bootstrap_request(&context, b"request").unwrap();
    let wrong = generate_bootstrap_keypair();
    let mut guard = BootstrapReplayGuard::new(TEST_REPLAY_TTL_MS).unwrap();
    assert!(guard
        .open_request(wrong.private_key(), &context, &client.request, 100)
        .is_err());
    for changed in [
        BootstrapContext::new([6; 32], keys.public_key, b"opaque-login".to_vec(), [9; 32]).unwrap(),
        BootstrapContext::new(
            [7; 32],
            keys.public_key,
            b"different-operation".to_vec(),
            [9; 32],
        )
        .unwrap(),
        bootstrap_context(keys.public_key, [8; 32]),
    ] {
        assert!(guard
            .open_request(keys.private_key(), &changed, &client.request, 100)
            .is_err());
    }
    let mut trailing = client.request;
    trailing.push(0);
    assert_eq!(
        decode_for_test(&trailing),
        Err(TransportError::NonCanonical)
    );
    assert!(decode_for_test(&vec![0; MAX_BOOTSTRAP_PLAINTEXT_BYTES + 100]).is_err());
}

#[test]
fn bootstrap_routing_header_is_bounded_and_context_bound() {
    let keys = generate_bootstrap_keypair();
    let context = bootstrap_context(keys.public_key, [15; 32]);
    let client = seal_bootstrap_request(&context, b"request").unwrap();
    let header = inspect_bootstrap_request(&client.request).unwrap();
    assert_eq!(header.request_id, context.request_id);
    assert_eq!(header.ciphertext_len, b"request".len() + 16);

    let mut tampered = client.request.clone();
    tampered[5] ^= 1;
    let tampered_header = inspect_bootstrap_request(&tampered).unwrap();
    assert_ne!(tampered_header.request_id, context.request_id);
    let mut guard = BootstrapReplayGuard::new(TEST_REPLAY_TTL_MS).unwrap();
    assert_eq!(
        guard
            .open_request(keys.private_key(), &context, &tampered, 100)
            .err(),
        Some(TransportError::AuthenticationFailed)
    );
    assert!(guard
        .open_request(keys.private_key(), &context, &client.request, 100)
        .is_ok());

    let mut trailing = client.request;
    trailing.push(0);
    assert_eq!(
        inspect_bootstrap_request(&trailing),
        Err(TransportError::NonCanonical)
    );
    assert!(inspect_bootstrap_request(&vec![0; MAX_BOOTSTRAP_PLAINTEXT_BYTES + 100]).is_err());
}

#[test]
fn inspectors_are_untrusted_and_truncation_cannot_be_routed() {
    let marker = b"semantic payload: opaque-password=not-for-routing";
    let keys = generate_bootstrap_keypair();
    let context = bootstrap_context(keys.public_key, [16; 32]);
    let client = seal_bootstrap_request(&context, marker).unwrap();
    assert!(!client
        .request
        .windows(marker.len())
        .any(|window| window == marker));

    let mut forged_bootstrap = client.request.clone();
    *forged_bootstrap.last_mut().unwrap() ^= 1;
    assert!(inspect_bootstrap_request(&forged_bootstrap).is_ok());
    let mut guard = BootstrapReplayGuard::new(TEST_REPLAY_TTL_MS).unwrap();
    assert_eq!(
        guard
            .open_request(keys.private_key(), &context, &forged_bootstrap, 100)
            .err(),
        Some(TransportError::AuthenticationFailed)
    );
    for end in 0..client.request.len() {
        assert!(inspect_bootstrap_request(&client.request[..end]).is_err());
    }

    let root = [17; 32];
    let handle = [18; 16];
    let mut http_sealer = HttpSessionBinding::new([19; 32], [20; 32])
        .unwrap()
        .into_client(&root)
        .unwrap()
        .sealer;
    let record = http_sealer.seal(handle, b"POST /login", marker).unwrap();
    assert!(!record.windows(marker.len()).any(|window| window == marker));
    let mut forged_http = record.clone();
    *forged_http.last_mut().unwrap() ^= 1;
    assert!(inspect_http_record(&forged_http).is_ok());
    let mut opener = HttpSessionBinding::new([19; 32], [20; 32])
        .unwrap()
        .into_server(&root)
        .unwrap()
        .opener;
    assert_eq!(
        opener.open(handle, b"POST /login", &forged_http).err(),
        Some(TransportError::AuthenticationFailed)
    );
    for end in 0..record.len() {
        assert!(inspect_http_record(&record[..end]).is_err());
    }

    let mut ws_sealer = ws_binding(21, 22, 23).into_server(&root).unwrap().sealer;
    let ws_record = ws_sealer.seal(b"chat", marker).unwrap();
    assert!(!ws_record
        .windows(marker.len())
        .any(|window| window == marker));
}

#[test]
fn http_records_bind_direction_handle_aad_and_reject_replay() {
    let root = [3; 32];
    let handle = [4; 16];
    assert!(HttpSessionBinding::new([0; 32], [8; 32]).is_err());
    assert!(HttpSessionBinding::new([7; 32], [0; 32]).is_err());
    let mut sealer = HttpSessionBinding::new([7; 32], [8; 32])
        .unwrap()
        .into_client(&root)
        .unwrap()
        .sealer;
    let mut opener = HttpSessionBinding::new([7; 32], [8; 32])
        .unwrap()
        .into_server(&root)
        .unwrap()
        .opener;
    let record = sealer.seal(handle, b"POST /login", b"body").unwrap();
    let header = inspect_http_record(&record).unwrap();
    assert_eq!(header.direction, Direction::ClientToServer);
    assert_eq!(header.session_id, [8; 32]);
    assert_eq!(header.handle, handle);
    assert_eq!(header.ciphertext_len, b"body".len() + 16);
    assert_eq!(
        opener
            .open(handle, b"POST /login", &record)
            .unwrap()
            .as_slice(),
        b"body"
    );
    assert_eq!(
        opener.open(handle, b"POST /login", &record),
        Err(TransportError::Replay)
    );
    assert!(HttpSessionBinding::new([7; 32], [8; 32])
        .unwrap()
        .into_client(&root)
        .unwrap()
        .opener
        .open(handle, b"POST /login", &record)
        .is_err());
    let mut wrong_session = HttpSessionBinding::new([7; 32], [9; 32])
        .unwrap()
        .into_server(&root)
        .unwrap()
        .opener;
    assert_eq!(
        wrong_session.open(handle, b"POST /login", &record),
        Err(TransportError::AuthenticationFailed)
    );
    let mut wrong_node = HttpSessionBinding::new([6; 32], [8; 32])
        .unwrap()
        .into_server(&root)
        .unwrap()
        .opener;
    assert_eq!(
        wrong_node.open(handle, b"POST /login", &record),
        Err(TransportError::AuthenticationFailed)
    );
    let mut tampered = record.clone();
    tampered[6] ^= 1;
    assert_ne!(inspect_http_record(&tampered).unwrap().session_id, [8; 32]);
    let mut same_session = HttpSessionBinding::new([7; 32], [8; 32])
        .unwrap()
        .into_server(&root)
        .unwrap()
        .opener;
    assert_eq!(
        same_session.open(handle, b"POST /login", &tampered),
        Err(TransportError::AuthenticationFailed)
    );
    let mut trailing = record;
    trailing.push(0);
    assert_eq!(
        decode_http_for_test(&trailing),
        Err(TransportError::NonCanonical)
    );
    assert_eq!(
        inspect_http_record(&trailing),
        Err(TransportError::NonCanonical)
    );
    assert!(inspect_http_record(&vec![0; MAX_RECORD_PLAINTEXT_BYTES + 100]).is_err());
}

#[test]
fn http_sealer_rejects_duplicate_handles_and_enforces_capacity() {
    let root = [6; 32];
    let mut sealer = HttpSessionBinding::new([7; 32], [8; 32])
        .unwrap()
        .into_client(&root)
        .unwrap()
        .sealer;
    let duplicate = [7; 16];
    assert!(sealer.seal(duplicate, b"POST /login", b"first").is_ok());
    assert_eq!(
        sealer.seal(duplicate, b"POST /login", b"second"),
        Err(TransportError::Replay)
    );
    for index in 1..MAX_HTTP_HANDLES {
        assert!(sealer
            .seal((index as u128).to_be_bytes(), b"POST /login", b"body")
            .is_ok());
    }
    assert_eq!(
        sealer.seal([8; 16], b"POST /login", b"body"),
        Err(TransportError::CapacityExhausted)
    );
}

#[test]
fn websocket_binding_separates_connections_and_rejects_replay() {
    let root = [5; 32];
    let mut first_server = ws_binding(1, 2, 3).into_server(&root).unwrap();
    let record = first_server.sealer.seal(b"chat", b"one").unwrap();
    let mut wrong = ws_binding(1, 2, 4).into_client(&root).unwrap().opener;
    assert_eq!(
        wrong.open(b"chat", &record),
        Err(TransportError::AuthenticationFailed)
    );
    let mut wrong_session = ws_binding(9, 2, 3).into_client(&root).unwrap().opener;
    assert_eq!(
        wrong_session.open(b"chat", &record),
        Err(TransportError::AuthenticationFailed)
    );
    let mut wrong_root = ws_binding(1, 2, 3).into_client(&[6; 32]).unwrap().opener;
    assert_eq!(
        wrong_root.open(b"chat", &record),
        Err(TransportError::AuthenticationFailed)
    );
    let mut opener = ws_binding(1, 2, 3).into_client(&root).unwrap().opener;
    assert_eq!(opener.open(b"chat", &record).unwrap().as_slice(), b"one");
    assert_eq!(opener.open(b"chat", &record), Err(TransportError::Replay));
    assert!(WsConnectionBinding::new(
        [0; 32],
        ConnectionNonce::new([2; 32]).unwrap(),
        ConnectionNonce::new([3; 32]).unwrap(),
    )
    .is_err());
    assert!(WsConnectionBinding::new(
        [1; 32],
        ConnectionNonce::new([2; 32]).unwrap(),
        ConnectionNonce::new([2; 32]).unwrap(),
    )
    .is_err());
    assert!(ConnectionNonce::new([0; 32]).is_err());
    let generated = ConnectionNonce::generate().unwrap();
    assert_eq!(
        ConnectionNonce::new(generated.to_bytes()).unwrap(),
        generated
    );
}

#[test]
fn websocket_server_hello_rejects_payload_and_context_tampering() {
    let root = [0x31; 32];
    let node = [0x32; 32];
    let session = [0x33; 32];
    let client_nonce = [0x34; 32];
    let server_nonce = [0x35; 32];
    let hello = seal_ws_server_hello(&root, node, session, client_nonce, server_nonce).unwrap();

    assert_eq!(
        open_ws_server_hello(&root, node, session, client_nonce, &hello)
            .unwrap()
            .to_bytes(),
        server_nonce
    );
    assert!(open_ws_server_hello(&root, [0x36; 32], session, client_nonce, &hello).is_err());
    assert!(open_ws_server_hello(&root, node, session, [0x37; 32], &hello).is_err());

    for offset in [0, 4, 5, 6, 38, 70, hello.len() - 1] {
        let mut forged = hello.to_vec();
        forged[offset] ^= 1;
        assert!(
            open_ws_server_hello(&root, node, session, client_nonce, &forged).is_err(),
            "server hello tamper at byte {offset} must fail closed"
        );
    }
}

#[test]
fn websocket_records_enforce_gap_direction_size_and_exhaustion() {
    let root = [10; 32];
    let mut client = ws_binding(1, 2, 3).into_client(&root).unwrap();
    let first = client.sealer.seal(b"chat", b"one").unwrap();
    let second = client.sealer.seal(b"chat", b"two").unwrap();
    let mut opener = ws_binding(1, 2, 3).into_server(&root).unwrap().opener;
    assert_eq!(
        opener.open(b"chat", &second),
        Err(TransportError::CounterGap)
    );
    assert!(opener.open(b"chat", &first).is_ok());
    assert!(opener.open(b"chat", &second).is_ok());
    let mut wrong = client.opener;
    assert_eq!(
        wrong.open(b"chat", &first),
        Err(TransportError::AuthenticationFailed)
    );
    let mut trailing = second;
    trailing.push(0);
    assert_eq!(
        decode_ws_for_test(&trailing),
        Err(TransportError::NonCanonical)
    );
    assert_eq!(
        client
            .sealer
            .seal(b"chat", &vec![0; MAX_WS_RECORD_PLAINTEXT_BYTES + 1]),
        Err(TransportError::TooLarge)
    );
    assert_eq!(
        client.sealer.seal(&vec![0; MAX_AAD_BYTES + 1], b"message"),
        Err(TransportError::TooLarge)
    );
    client.sealer.exhaust_for_test();
    opener.exhaust_for_test();
    assert_eq!(
        client.sealer.seal(b"chat", b"exhausted"),
        Err(TransportError::CounterExhausted)
    );
    assert_eq!(
        opener.open(b"chat", &first),
        Err(TransportError::CounterExhausted)
    );
}

#[test]
fn opaque_root_schedule_is_deterministic_and_context_separated() {
    let first = derive_opaque_transport_root(&[0x42; 64], b"account-a").unwrap();
    let again = derive_opaque_transport_root(&[0x42; 64], b"account-a").unwrap();
    let other = derive_opaque_transport_root(&[0x42; 64], b"account-b").unwrap();
    assert_eq!(first, again);
    assert_eq!(
        *first,
        [
            187, 239, 13, 70, 128, 145, 50, 191, 142, 50, 30, 79, 56, 11, 221, 124, 9, 37, 104, 71,
            150, 198, 177, 95, 48, 221, 117, 81, 91, 227, 9, 241,
        ]
    );
    assert_ne!(first, other);
    assert_eq!(
        derive_opaque_transport_root(&[0; 32], b"account-a").err(),
        Some(TransportError::InvalidInput)
    );
}

#[test]
fn bootstrap_context_and_private_keys_reject_zero_material() {
    assert_eq!(
        BootstrapPrivateKey::from_bytes(Zeroizing::new([0; 32])).err(),
        Some(TransportError::InvalidInput)
    );
    assert!(BootstrapContext::new([0; 32], [1; 32], b"op".to_vec(), [2; 32]).is_err());
    assert!(BootstrapContext::new([1; 32], [0; 32], b"op".to_vec(), [2; 32]).is_err());
    assert!(BootstrapContext::new([1; 32], [2; 32], b"op".to_vec(), [0; 32]).is_err());
}

#[test]
fn hostile_records_never_panic_and_limits_fail_closed() {
    for length in 0..128 {
        let input = vec![0xff; length];
        let _ = decode_for_test(&input);
        let _ = decode_http_for_test(&input);
        let _ = decode_ws_for_test(&input);
        let _ = inspect_bootstrap_request(&input);
        let _ = inspect_http_record(&input);
    }
    assert!(seal_bootstrap_request(
        &bootstrap_context(generate_bootstrap_keypair().public_key, [9; 32]),
        &vec![0; MAX_BOOTSTRAP_PLAINTEXT_BYTES + 1],
    )
    .is_err());
}
