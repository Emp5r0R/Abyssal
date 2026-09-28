use abyssal_core::transport_protocol::{
    AccountBootstrapExchange, AccountBootstrapResponse, BootstrapContext, BootstrapReplayGuard,
    WsClientConnection, MAX_BOOTSTRAP_PLAINTEXT_BYTES,
};
use abyssal_transport::{
    decode_account_bootstrap_result, encode_account_bootstrap_result, generate_bootstrap_keypair,
    inspect_bootstrap_request, inspect_ws_client_hello, seal_ws_server_hello,
    AccountBootstrapResult, ConnectionNonce, WsConnectionBinding, ACCOUNT_BOOTSTRAP_HEADER_BYTES,
    ACCOUNT_BOOTSTRAP_OPERATION, WS_FRAME_AAD,
};

#[test]
fn full_size_random_response_does_not_consume_retry_state() {
    let server = generate_bootstrap_keypair();
    let exchange = AccountBootstrapExchange::start(
        vec![3; 32],
        server.public_key.to_vec(),
        vec![4; 32],
        vec![5; 32],
        vec![6; 32],
    )
    .unwrap();
    let request = exchange.request_bytes().unwrap();
    let header = inspect_bootstrap_request(&request).unwrap();
    let context = BootstrapContext::new(
        [3; 32],
        server.public_key,
        ACCOUNT_BOOTSTRAP_OPERATION.to_vec(),
        header.request_id,
    )
    .unwrap();
    let mut guard = BootstrapReplayGuard::new(30_000).unwrap();
    let opened = guard
        .open_request(server.private_key(), &context, &request, 1)
        .unwrap();
    let plaintext = encode_account_bootstrap_result(&AccountBootstrapResult::Failure).unwrap();
    let response = opened.response_sealer.seal(&plaintext).unwrap();
    let request_before_failure = exchange.request_bytes().unwrap();

    let random_response = (0..MAX_BOOTSTRAP_PLAINTEXT_BYTES + 16)
        .map(|index| (index as u8).wrapping_mul(31).wrapping_add(17))
        .collect::<Vec<_>>();
    assert!(exchange.open_response(random_response).is_err());
    assert_eq!(exchange.request_bytes().unwrap(), request_before_failure);
    assert!(exchange.open_response(response).is_ok());
}

#[test]
fn session_policy_boundaries_and_tampering_are_rejected_or_preserved() {
    for (max_rooms_per_user, session_inactivity_sec) in [(1, 60), (100, 86_400)] {
        let result = AccountBootstrapResult::Session {
            session_id: zeroize::Zeroizing::new([1; 32]),
            created: false,
            max_rooms_per_user,
            session_inactivity_sec,
            username: zeroize::Zeroizing::new("user".to_owned()),
            identity_public: zeroize::Zeroizing::new(vec![2; 32]),
            identity_prekey_id: zeroize::Zeroizing::new("key".to_owned()),
            identity_envelope: zeroize::Zeroizing::new(vec![3; 32]),
        };
        let encoded = encode_account_bootstrap_result(&result).unwrap();
        assert!(decode_account_bootstrap_result(&encoded).is_ok());

        let mut bad_created = encoded.to_vec();
        bad_created[ACCOUNT_BOOTSTRAP_HEADER_BYTES + 32] = 2;
        assert!(decode_account_bootstrap_result(&bad_created).is_err());

        for (offset, value) in [
            (ACCOUNT_BOOTSTRAP_HEADER_BYTES + 33, 0_u32),
            (ACCOUNT_BOOTSTRAP_HEADER_BYTES + 33, 101_u32),
            (ACCOUNT_BOOTSTRAP_HEADER_BYTES + 37, 59_u32),
            (ACCOUNT_BOOTSTRAP_HEADER_BYTES + 37, 86_401_u32),
        ] {
            let mut tampered = encoded.to_vec();
            tampered[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
            assert!(decode_account_bootstrap_result(&tampered).is_err());
        }
    }
}

#[test]
fn sealed_session_response_preserves_created_and_policy_fields() {
    for created in [false, true] {
        let server = generate_bootstrap_keypair();
        let exchange = AccountBootstrapExchange::start(
            vec![3; 32],
            server.public_key.to_vec(),
            vec![4; 32],
            vec![5; 32],
            vec![6; 32],
        )
        .unwrap();
        let request = exchange.request_bytes().unwrap();
        let header = inspect_bootstrap_request(&request).unwrap();
        let context = BootstrapContext::new(
            [3; 32],
            server.public_key,
            ACCOUNT_BOOTSTRAP_OPERATION.to_vec(),
            header.request_id,
        )
        .unwrap();
        let mut guard = BootstrapReplayGuard::new(30_000).unwrap();
        let opened = guard
            .open_request(server.private_key(), &context, &request, 1)
            .unwrap();
        let plaintext = encode_account_bootstrap_result(&AccountBootstrapResult::Session {
            session_id: zeroize::Zeroizing::new([7; 32]),
            created,
            max_rooms_per_user: 100,
            session_inactivity_sec: 86_400,
            username: zeroize::Zeroizing::new("user".to_owned()),
            identity_public: zeroize::Zeroizing::new(vec![8; 32]),
            identity_prekey_id: zeroize::Zeroizing::new("key".to_owned()),
            identity_envelope: zeroize::Zeroizing::new(vec![9; 32]),
        })
        .unwrap();
        let response = opened.response_sealer.seal(&plaintext).unwrap();
        let AccountBootstrapResponse::Session {
            created: actual_created,
            max_rooms_per_user,
            session_inactivity_sec,
            ..
        } = exchange.open_response(response).unwrap()
        else {
            panic!("session response was not preserved");
        };
        assert_eq!(actual_created, created);
        assert_eq!(max_rooms_per_user, 100);
        assert_eq!(session_inactivity_sec, 86_400);
    }
}

#[test]
fn websocket_client_facade_requires_server_proof_and_binds_directional_records() {
    let node = [8_u8; 32];
    let session = [9_u8; 32];
    let root = [7_u8; 32];
    let ticket = b"ticket-hidden-from-client-hello";
    let client = WsClientConnection::new(
        node.to_vec(),
        session.to_vec(),
        root.to_vec(),
        ticket.to_vec(),
    )
    .unwrap();
    assert!(!client.ready());
    let client_hello = client.client_hello_bytes().unwrap();
    assert_eq!(client_hello.len(), abyssal_transport::WS_CLIENT_HELLO_BYTES);
    assert!(!client_hello
        .windows(ticket.len())
        .any(|window| window == ticket));
    let header = inspect_ws_client_hello(&client_hello).unwrap();
    assert_eq!(header.session_id, session);

    let server_nonce = [11_u8; 32];
    let bad_server_hello = seal_ws_server_hello(
        &root,
        [6_u8; 32],
        session,
        header.client_nonce,
        server_nonce,
    )
    .unwrap();
    assert!(client.open_server_hello(bad_server_hello.to_vec()).is_err());
    assert!(!client.ready());
    let server_hello =
        seal_ws_server_hello(&root, node, session, header.client_nonce, server_nonce).unwrap();
    client.open_server_hello(server_hello.to_vec()).unwrap();
    assert!(client.ready());
    assert!(client.client_hello_bytes().is_err());

    let mut server_records = WsConnectionBinding::new(
        session,
        ConnectionNonce::new(header.client_nonce).unwrap(),
        ConnectionNonce::new(server_nonce).unwrap(),
    )
    .unwrap()
    .into_server(&root)
    .unwrap();
    let outbound = client.seal_frame(b"client-frame".to_vec()).unwrap();
    assert_eq!(
        server_records
            .opener
            .open(WS_FRAME_AAD, &outbound)
            .unwrap()
            .as_slice(),
        b"client-frame"
    );
    let response = server_records
        .sealer
        .seal(WS_FRAME_AAD, b"server-frame")
        .unwrap();
    assert_eq!(client.open_frame(response).unwrap(), b"server-frame");
    assert!(client.open_frame(outbound).is_err());

    client.destroy();
    assert!(!client.ready());
    assert!(client.seal_frame(b"after-destroy".to_vec()).is_err());
    assert!(client.open_frame(Vec::new()).is_err());
}
