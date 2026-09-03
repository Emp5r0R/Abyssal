use abyssal_invite::{
    account_context_v1, decode_invite_text, derive_node_id, encode_deep_link, encode_manual,
    locator_from_public_url, node_key_fingerprint, InviteCapsuleV1, InviteError, NodeDescriptorV1,
    NodeLocator, SignedInviteCapsule, SignedNodeDescriptor, DIRECT_PROTOCOL_VERSION,
    ROOM_PROTOCOL_VERSION,
};
use ed25519_dalek::SigningKey;
use rand::{rngs::StdRng, RngCore, SeedableRng};

fn fixture() -> (SigningKey, SignedInviteCapsule) {
    let key = SigningKey::from_bytes(&[0x11; 32]);
    let capsule = InviteCapsuleV1::abyssal(
        key.verifying_key().to_bytes(),
        vec![locator_from_public_url("https://node.example.com").unwrap()],
        [0x22; 32],
        DIRECT_PROTOCOL_VERSION,
        ROOM_PROTOCOL_VERSION,
        Some(2_100_000_000),
    )
    .unwrap();
    let invite = SignedInviteCapsule::sign(capsule, &key).unwrap();
    (key, invite)
}

#[test]
fn signed_capsule_and_descriptor_verify_for_same_node_and_locator() {
    let (key, invite) = fixture();
    invite.verify(Some(2_000_000_000)).unwrap();
    let descriptor = NodeDescriptorV1::abyssal(
        key.verifying_key().to_bytes(),
        invite.capsule.locators.clone(),
    )
    .unwrap();
    let signed = SignedNodeDescriptor::sign(descriptor, &key).unwrap();
    let binary = signed.canonical_binary().unwrap();
    let decoded = SignedNodeDescriptor::decode_for_invite(
        &binary,
        &invite.capsule.node_public_key,
        &invite.capsule.locators[0],
    )
    .unwrap();
    assert_eq!(decoded, signed);
}

#[test]
fn same_hostname_with_wrong_node_key_is_rejected() {
    let (key, invite) = fixture();
    let attacker = SigningKey::from_bytes(&[0x33; 32]);
    let descriptor = NodeDescriptorV1::abyssal(
        attacker.verifying_key().to_bytes(),
        invite.capsule.locators.clone(),
    )
    .unwrap();
    let binary = SignedNodeDescriptor::sign(descriptor, &attacker)
        .unwrap()
        .canonical_binary()
        .unwrap();
    assert_eq!(
        SignedNodeDescriptor::decode_for_invite(
            &binary,
            &key.verifying_key().to_bytes(),
            &invite.capsule.locators[0]
        ),
        Err(InviteError::NodeIdentityMismatch)
    );
}

#[test]
fn every_signed_field_rejects_bit_tampering() {
    let (_, invite) = fixture();
    let binary = invite.canonical_binary().unwrap();
    for index in 0..binary.len() {
        let mut tampered = binary.clone();
        tampered[index] ^= 1;
        assert!(
            SignedInviteCapsule::decode(&tampered, None).is_err(),
            "byte {index}"
        );
    }
}

#[test]
fn truncated_and_noncanonical_cbor_fail_closed() {
    let (_, invite) = fixture();
    let binary = invite.canonical_binary().unwrap();
    for length in 0..binary.len() {
        assert!(SignedInviteCapsule::decode(&binary[..length], None).is_err());
    }
    let mut trailing = binary;
    trailing.push(0);
    assert_eq!(
        SignedInviteCapsule::decode(&trailing, None),
        Err(InviteError::Invalid)
    );
}

#[test]
fn node_ids_contexts_and_text_vectors_are_stable() {
    let (_, invite) = fixture();
    assert_eq!(
        derive_node_id(&invite.capsule.node_public_key),
        "abyssal-node-v1:zlLjZjAl8CVJZ5l9jVgQUhve1mxyTiVNmey5lQsROLU"
    );
    assert_eq!(
        node_key_fingerprint(&invite.capsule.node_public_key),
        "8B29:06F2:6BEB:F064:5291:2E7D:B96A:EE1D"
    );
    assert_eq!(
        hex(&account_context_v1(
            &invite.capsule.node_public_key,
            &invite.capsule.capability
        )),
        "f5145cdbee41235643f64efca7a605d19ebce805cdb66295ff479414856f2734"
    );
    let deep = encode_deep_link(&invite).unwrap();
    let manual = encode_manual(&invite).unwrap();
    let descriptor = SignedNodeDescriptor::sign(
        NodeDescriptorV1::abyssal(
            invite.capsule.node_public_key,
            invite.capsule.locators.clone(),
        )
        .unwrap(),
        &SigningKey::from_bytes(&[0x11; 32]),
    )
    .unwrap()
    .canonical_binary()
    .unwrap();
    assert_eq!(
        hex(&descriptor),
        "8258508801706f72672e6162797373616c2e636861745820d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737818301706e6f64652e6578616d706c652e636f6d1901bb01090a00584011d674f2075930853f2ae2ea008d7787de469c3d1e954ea8aea6ae5a19e31a2c7d790ce0c473036e3bb016c3bc50c96e85b214659d994da7a8a43dfcff383401"
    );
    assert_eq!(
        hex(&invite.canonical_binary().unwrap()),
        "8258778a01706f72672e6162797373616c2e63686174015820d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737818301706e6f64652e6578616d706c652e636f6d1901bb58202222222222222222222222222222222222222222222222222222222222222222090a001a7d2b750058403819271558265aed8002418f855b77292a629ca66c3593358d14cfed7c7ce3b11b38ba7f02933f312756427a42575b7f2634a65d4925c84d26fdd3927913f90b"
    );
    assert_eq!(
        deep,
        "abyssal:invite:glh3igFwb3JnLmFieXNzYWwuY2hhdAFYINBKsjJ0K7SrOhNovUYV5ObQIkq3GgFrr4UgozLJd4c3gYMBcG5vZGUuZXhhbXBsZS5jb20ZAbtYICIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiCQoAGn0rdQBYQDgZJxVYJlrtgAJBj4VbdykqYpymbDWTNY0Uz-18fOOxGzi6fwKTPzEnVkJ6QldbfyY0pl1JJchNJv3TknkT-Qs"
    );
    assert_eq!(
        manual,
        "ABY1-G9C7F-2G1E1-QQ4SS-EC5H7-JWVKC-5P2WR-V8C5T-02P10-T15B4-CKM5E-TAPEG-KD2YM-C5F4W-V824J-NQ380-PQBW5-42HK5-JBQGW-VR30R-1E1Q6-YS355-SJQGR-BDE1P-6ABK3-DXPHJ-0DVB0-G248H-248H2-48H24-8H248-H248H-248H2-48H24-8H248-H248H-248H2-48G91-801MZ-9BEM0-5GG1R-34KHA-P16BB-PR00J-1HY2N-PXS95-9H9S9-KC6P9-KB38M-SZPQR-Z73P4-DKHEK-Z0A9K-YC97A-S17MG-JQBDZ-JCD56-BN4JB-J2D4V-YX74K-S2FWG-PB8D2-V6G"
    );
    assert_eq!(
        hex(&invite.signature),
        "3819271558265aed8002418f855b77292a629ca66c3593358d14cfed7c7ce3b11b38ba7f02933f312756427a42575b7f2634a65d4925c84d26fdd3927913f90b"
    );
    assert_eq!(decode_invite_text(&deep, None).unwrap(), invite);
    assert_eq!(decode_invite_text(&manual, None).unwrap(), invite);
}

#[test]
fn full_attacker_replacement_is_valid_but_a_distinct_trust_root() {
    let (_, original) = fixture();
    let attacker = SigningKey::from_bytes(&[0x44; 32]);
    let replacement = SignedInviteCapsule::sign(
        InviteCapsuleV1::abyssal(
            attacker.verifying_key().to_bytes(),
            vec![NodeLocator::Https {
                host: "evil.example.com".to_owned(),
                port: 443,
            }],
            [0x55; 32],
            DIRECT_PROTOCOL_VERSION,
            ROOM_PROTOCOL_VERSION,
            None,
        )
        .unwrap(),
        &attacker,
    )
    .unwrap();
    replacement.verify(None).unwrap();
    assert_ne!(
        replacement.capsule.node_public_key,
        original.capsule.node_public_key
    );
}

#[test]
fn bounded_hostile_binary_and_text_inputs_never_panic() {
    let mut rng = StdRng::seed_from_u64(0xAB155A1);
    for length in 0..=1_100 {
        let mut binary = vec![0_u8; length];
        rng.fill_bytes(&mut binary);
        let _ = SignedInviteCapsule::decode(&binary, Some(2_000_000_000));
    }
    for length in 0..=2_100 {
        let mut text = vec![0_u8; length];
        rng.fill_bytes(&mut text);
        for byte in &mut text {
            *byte = b'!' + (*byte % 94);
        }
        let text = String::from_utf8(text).unwrap();
        let _ = decode_invite_text(&text, Some(2_000_000_000));
    }
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
