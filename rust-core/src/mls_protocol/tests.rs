use super::*;
use crate::secure_protocol::E2eeSession;
use ed25519_dalek::Signer;
use mls_rs::{GroupStateStorage, KeyPackageStorage};
use mls_rs_core::{
    group::{EpochRecord, GroupState},
    key_package::KeyPackageData,
};
use std::{sync::mpsc, time::Duration};

fn identity_for(
    seed: u8,
    username: &str,
    room_id: &str,
    node_context: &[u8],
    group_id: &[u8; 32],
) -> ([u8; 64], Vec<u8>, Vec<u8>) {
    let stable_key = SigningKey::from_bytes(&[seed; 32]);
    let mut stable = [0_u8; 64];
    stable[..32].copy_from_slice(&[seed.wrapping_add(1); 32]);
    stable[32..].copy_from_slice(&stable_key.verifying_key().to_bytes());
    let export_key = vec![seed; 32];
    let root = [seed; 32];
    let public = mls_public_for_root(&root, username, node_context, room_id, group_id).unwrap();
    let transcript =
        credential_transcript(username, room_id, node_context, group_id, &stable, &public).unwrap();
    let signature = stable_key.sign(&transcript).to_bytes().to_vec();
    (stable, export_key, signature)
}

fn identity(seed: u8, username: &str) -> ([u8; 64], Vec<u8>, Vec<u8>) {
    identity_for(seed, username, "test-room", b"node=local", &[3_u8; 32])
}

fn roster(username: &str, stable: &[u8]) -> MlsRosterMember {
    MlsRosterMember {
        username: username.to_string(),
        stable_identity: stable.to_vec(),
    }
}

#[test]
fn create_pending_recover_and_credential_tamper() {
    let (alice, export, signature) = identity(7, "alice");
    let room = MlsRoom::create(
        export.clone(),
        "test-room".to_string(),
        "alice".to_string(),
        b"node=local".to_vec(),
        alice.to_vec(),
        vec![3_u8; 32],
        signature.clone(),
    )
    .unwrap();
    assert_eq!(room.room_info().unwrap().member_count, 1);
    let envelope = room.seal_state().unwrap();
    let info = room.room_info().unwrap();
    let recovered = MlsRoom::recover(
        export.clone(),
        "test-room".to_string(),
        "alice".to_string(),
        b"node=local".to_vec(),
        alice.to_vec(),
        vec![3_u8; 32],
        signature.clone(),
        envelope.clone(),
        true,
        info.epoch,
        info.revision,
        vec![roster("alice", &alice)],
        info.membership_digest.clone(),
    )
    .unwrap();
    assert_eq!(recovered.room_info().unwrap(), info);
    let mut bad_signature = signature;
    bad_signature[0] ^= 1;
    assert!(MlsRoom::create(
        export,
        "test-room".to_string(),
        "alice".to_string(),
        b"node=local".to_vec(),
        alice.to_vec(),
        vec![3_u8; 32],
        bad_signature,
    )
    .is_err());
}

#[test]
fn pending_recovery_preserves_issued_key_package_state() {
    let (alice, export, signature) = identity(27, "alice");
    let pending = MlsRoom::pending_join(
        export.clone(),
        "test-room".to_string(),
        "alice".to_string(),
        b"node=local".to_vec(),
        alice.to_vec(),
        vec![3_u8; 32],
        signature.clone(),
    )
    .unwrap();
    pending.key_package().unwrap();
    let before = pending.room_info().unwrap();
    let envelope = pending.seal_state().unwrap();
    let recovered = MlsRoom::recover(
        export,
        "test-room".to_string(),
        "alice".to_string(),
        b"node=local".to_vec(),
        alice.to_vec(),
        vec![3_u8; 32],
        signature,
        envelope,
        false,
        0,
        before.revision,
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    assert_eq!(recovered.room_info().unwrap(), before);
    recovered.key_package().unwrap();
}

#[test]
fn add_welcome_and_remove_by_identity() {
    let (alice, export_a, sig_a) = identity(11, "alice");
    let (bob, export_b, sig_b) = identity(12, "bob");
    let alice_room = MlsRoom::create(
        export_a,
        "test-room".to_string(),
        "alice".to_string(),
        b"node=local".to_vec(),
        alice.to_vec(),
        vec![3_u8; 32],
        sig_a,
    )
    .unwrap();
    let bob_room = MlsRoom::pending_join(
        export_b,
        "test-room".to_string(),
        "bob".to_string(),
        b"node=local".to_vec(),
        bob.to_vec(),
        vec![3_u8; 32],
        sig_b,
    )
    .unwrap();
    let before_add = alice_room.room_info().unwrap();
    let add = alice_room
        .add_member(
            bob_room.key_package().unwrap(),
            "bob".to_string(),
            bob.to_vec(),
            "add-bob".to_string(),
        )
        .unwrap();
    assert_eq!(add.from_epoch + 1, add.to_epoch);
    assert_eq!(add.from_membership_digest, before_add.membership_digest);
    alice_room
        .rollback_outbound(add.message_id.clone(), add.revision)
        .unwrap();
    assert_eq!(alice_room.room_info().unwrap(), before_add);
    let add = alice_room
        .add_member(
            bob_room.key_package().unwrap(),
            "bob".to_string(),
            bob.to_vec(),
            "add-bob-retry".to_string(),
        )
        .unwrap();
    assert_eq!(add.revision, before_add.revision + 1);
    assert_eq!(add.from_membership_digest, before_add.membership_digest);
    alice_room
        .commit_outbound(add.message_id.clone(), add.revision)
        .unwrap();
    bob_room
        .join_welcome(add.welcome, add.roster, add.membership_digest)
        .unwrap();
    let before_remove = alice_room.room_info().unwrap();
    let remove = alice_room
        .remove_member("bob".to_string(), bob.to_vec(), "remove-bob".to_string())
        .unwrap();
    assert_eq!(remove.from_epoch + 1, remove.to_epoch);
    assert_eq!(
        remove.from_membership_digest,
        before_remove.membership_digest
    );
    alice_room
        .rollback_outbound(remove.message_id.clone(), remove.revision)
        .unwrap();
    assert_eq!(alice_room.room_info().unwrap(), before_remove);

    let retry = alice_room
        .remove_member(
            "bob".to_string(),
            bob.to_vec(),
            "remove-bob-retry".to_string(),
        )
        .unwrap();
    assert_eq!(
        retry.from_membership_digest, before_remove.membership_digest,
        "rollback must restore the exact pre-remove membership digest"
    );
    alice_room
        .rollback_outbound(retry.message_id, retry.revision)
        .unwrap();
    assert_eq!(alice_room.room_info().unwrap(), before_remove);
}

#[test]
fn application_checkpoint_replay_and_tamper() {
    let (alice, export_a, sig_a) = identity(21, "alice");
    let (bob, export_b, sig_b) = identity(22, "bob");
    let alice_room = MlsRoom::create(
        export_a,
        "test-room".to_string(),
        "alice".to_string(),
        b"node=local".to_vec(),
        alice.to_vec(),
        vec![3_u8; 32],
        sig_a,
    )
    .unwrap();
    let bob_room = MlsRoom::pending_join(
        export_b,
        "test-room".to_string(),
        "bob".to_string(),
        b"node=local".to_vec(),
        bob.to_vec(),
        vec![3_u8; 32],
        sig_b,
    )
    .unwrap();
    let add = alice_room
        .add_member(
            bob_room.key_package().unwrap(),
            "bob".to_string(),
            bob.to_vec(),
            "app-add".to_string(),
        )
        .unwrap();
    alice_room
        .commit_outbound(add.message_id.clone(), add.revision)
        .unwrap();
    bob_room
        .join_welcome(add.welcome, add.roster, add.membership_digest)
        .unwrap();
    let app = alice_room
        .encrypt_application("app-1".to_string(), b"hello".to_vec(), b"aad".to_vec())
        .unwrap();
    alice_room
        .commit_outbound(app.message_id.clone(), app.revision)
        .unwrap();
    let mut tampered = app.ciphertext.clone();
    tampered[0] ^= 1;
    assert!(bob_room
        .decrypt_application(
            tampered,
            app.epoch,
            app.message_id.clone(),
            app.authenticated_data.clone(),
        )
        .is_err());
    let mut wrong_authenticated_data = app.authenticated_data.clone();
    wrong_authenticated_data[0] ^= 1;
    assert!(bob_room
        .decrypt_application(
            app.ciphertext.clone(),
            app.epoch,
            app.message_id.clone(),
            wrong_authenticated_data,
        )
        .is_err());
    let received = bob_room
        .decrypt_application(
            app.ciphertext.clone(),
            app.epoch,
            app.message_id.clone(),
            app.authenticated_data.clone(),
        )
        .unwrap();
    assert_eq!(received.plaintext, b"hello");
    bob_room
        .commit_outbound(app.message_id.clone(), received.revision)
        .unwrap();
    assert!(bob_room
        .decrypt_application(
            app.ciphertext,
            app.epoch,
            app.message_id,
            app.authenticated_data,
        )
        .is_err());
}

#[test]
fn outbound_rollback_restores_exact_state_and_requires_exact_checkpoint() {
    let (alice, export, signature) = identity(25, "alice");
    let room = MlsRoom::create(
        export,
        "test-room".to_string(),
        "alice".to_string(),
        b"node=local".to_vec(),
        alice.to_vec(),
        vec![3_u8; 32],
        signature,
    )
    .unwrap();
    let before = room.room_info().unwrap();
    let application = room
        .encrypt_application(
            "rollback-message".to_string(),
            b"hello".to_vec(),
            b"aad".to_vec(),
        )
        .unwrap();
    assert!(room.seal_state().is_err());
    assert!(room
        .commit_outbound("wrong-message".to_string(), application.revision)
        .is_err());
    assert!(room
        .rollback_outbound("wrong-message".to_string(), application.revision)
        .is_err());
    let pending_info = room.room_info().unwrap();
    assert!(room.seal_state().is_err());
    assert_eq!(room.room_info().unwrap(), pending_info);
    room.rollback_outbound("rollback-message".to_string(), application.revision)
        .unwrap();
    assert_eq!(room.room_info().unwrap(), before);
    let retry = room
        .encrypt_application(
            "rollback-message".to_string(),
            b"hello".to_vec(),
            b"aad".to_vec(),
        )
        .unwrap();
    assert_eq!(retry.revision, before.revision + 1);
    room.commit_outbound(retry.message_id, retry.revision)
        .unwrap();
    assert!(room.seal_state().is_ok());
}

#[test]
fn control_commit_requires_exact_checkpoint_and_can_rollback() {
    let (alice, export_a, sig_a) = identity(31, "alice");
    let (bob, export_b, sig_b) = identity(32, "bob");
    let alice_room = MlsRoom::create(
        export_a,
        "test-room".to_string(),
        "alice".to_string(),
        b"node=local".to_vec(),
        alice.to_vec(),
        vec![3_u8; 32],
        sig_a,
    )
    .unwrap();
    let bob_room = MlsRoom::pending_join(
        export_b,
        "test-room".to_string(),
        "bob".to_string(),
        b"node=local".to_vec(),
        bob.to_vec(),
        vec![3_u8; 32],
        sig_b,
    )
    .unwrap();
    let add = alice_room
        .add_member(
            bob_room.key_package().unwrap(),
            "bob".to_string(),
            bob.to_vec(),
            "control-add".to_string(),
        )
        .unwrap();
    alice_room
        .commit_outbound(add.message_id.clone(), add.revision)
        .unwrap();
    assert!(bob_room
        .process_control(
            add.commit.clone(),
            add.from_epoch + 1,
            add.to_epoch,
            add.roster.clone(),
            add.membership_digest.clone(),
            add.message_id.clone(),
            add.authenticated_data.clone(),
        )
        .is_err());
    bob_room
        .join_welcome(add.welcome, add.roster, add.membership_digest)
        .unwrap();
}

#[test]
fn directory_rejects_duplicate_identity_and_context() {
    let (alice, export_a, sig_a) = identity(41, "alice");
    let (bob, export_b, sig_b) = identity(42, "bob");
    let alice_room = MlsRoom::create(
        export_a,
        "test-room".to_string(),
        "alice".to_string(),
        b"node=local".to_vec(),
        alice.to_vec(),
        vec![3_u8; 32],
        sig_a,
    )
    .unwrap();
    let bob_room = MlsRoom::pending_join(
        export_b,
        "test-room".to_string(),
        "bob".to_string(),
        b"node=local".to_vec(),
        bob.to_vec(),
        vec![3_u8; 32],
        sig_b,
    )
    .unwrap();
    let key_package = bob_room.key_package().unwrap();
    assert!(alice_room
        .add_member(
            key_package.clone(),
            "bob".to_string(),
            alice.to_vec(),
            "wrong-identity".to_string(),
        )
        .is_err());
    assert!(alice_room
        .add_member(
            key_package,
            "bob".to_string(),
            bob.to_vec(),
            "valid-add".to_string(),
        )
        .is_ok());
}

#[test]
fn malformed_state_and_key_package_records_fail_closed() {
    let (alice, export, sig) = identity(51, "alice");
    let room = MlsRoom::create(
        export.clone(),
        "test-room".to_string(),
        "alice".to_string(),
        b"node=local".to_vec(),
        alice.to_vec(),
        vec![3_u8; 32],
        sig.clone(),
    )
    .unwrap();
    let info = room.room_info().unwrap();
    let envelope = room.seal_state().unwrap();
    let mut trailing = envelope.clone();
    trailing.push(0);
    assert!(MlsRoom::recover(
        export.clone(),
        "test-room".to_string(),
        "alice".to_string(),
        b"node=local".to_vec(),
        alice.to_vec(),
        vec![3_u8; 32],
        sig.clone(),
        trailing,
        true,
        info.epoch,
        info.revision,
        vec![roster("alice", &alice)],
        info.membership_digest.clone(),
    )
    .is_err());
    let (bob, export_b, sig_b) = identity(52, "bob");
    let bob_room = MlsRoom::pending_join(
        export_b,
        "test-room".to_string(),
        "bob".to_string(),
        b"node=local".to_vec(),
        bob.to_vec(),
        vec![3_u8; 32],
        sig_b,
    )
    .unwrap();
    let mut key_package = bob_room.key_package().unwrap();
    key_package.push(0);
    assert!(room
        .add_member(
            key_package,
            "bob".to_string(),
            bob.to_vec(),
            "trailing-key-package".to_string(),
        )
        .is_err());
}

#[test]
fn every_public_mls_message_decoder_rejects_trailing_bytes() {
    let (alice, export_a, sig_a) = identity(81, "alice");
    let (bob, export_b, sig_b) = identity(82, "bob");
    let alice_room = MlsRoom::create(
        export_a,
        "test-room".to_string(),
        "alice".to_string(),
        b"node=local".to_vec(),
        alice.to_vec(),
        vec![3_u8; 32],
        sig_a,
    )
    .unwrap();
    let bob_room = MlsRoom::pending_join(
        export_b,
        "test-room".to_string(),
        "bob".to_string(),
        b"node=local".to_vec(),
        bob.to_vec(),
        vec![3_u8; 32],
        sig_b,
    )
    .unwrap();
    let add = alice_room
        .add_member(
            bob_room.key_package().unwrap(),
            "bob".to_string(),
            bob.to_vec(),
            "suffix-welcome".to_string(),
        )
        .unwrap();
    alice_room
        .commit_outbound(add.message_id.clone(), add.revision)
        .unwrap();
    let mut welcome = add.welcome.clone();
    welcome.push(0);
    assert!(bob_room
        .join_welcome(welcome, add.roster.clone(), add.membership_digest.clone())
        .is_err());
    bob_room
        .join_welcome(add.welcome, add.roster, add.membership_digest)
        .unwrap();
    let app = alice_room
        .encrypt_application(
            "suffix-application".to_string(),
            b"hello".to_vec(),
            b"aad".to_vec(),
        )
        .unwrap();
    alice_room
        .commit_outbound(app.message_id.clone(), app.revision)
        .unwrap();
    let mut ciphertext = app.ciphertext.clone();
    ciphertext.push(0);
    assert!(bob_room
        .decrypt_application(
            ciphertext,
            app.epoch,
            app.message_id,
            app.authenticated_data,
        )
        .is_err());
}

#[test]
fn control_decoder_rejects_trailing_bytes() {
    let (alice, export_a, sig_a) = identity(91, "alice");
    let (bob, export_b, sig_b) = identity(92, "bob");
    let (charlie, export_c, sig_c) = identity(93, "charlie");
    let alice_room = MlsRoom::create(
        export_a,
        "test-room".to_string(),
        "alice".to_string(),
        b"node=local".to_vec(),
        alice.to_vec(),
        vec![3_u8; 32],
        sig_a,
    )
    .unwrap();
    let bob_room = MlsRoom::pending_join(
        export_b,
        "test-room".to_string(),
        "bob".to_string(),
        b"node=local".to_vec(),
        bob.to_vec(),
        vec![3_u8; 32],
        sig_b,
    )
    .unwrap();
    let add_bob = alice_room
        .add_member(
            bob_room.key_package().unwrap(),
            "bob".to_string(),
            bob.to_vec(),
            "control-add-bob".to_string(),
        )
        .unwrap();
    alice_room
        .commit_outbound(add_bob.message_id.clone(), add_bob.revision)
        .unwrap();
    bob_room
        .join_welcome(add_bob.welcome, add_bob.roster, add_bob.membership_digest)
        .unwrap();
    let charlie_room = MlsRoom::pending_join(
        export_c,
        "test-room".to_string(),
        "charlie".to_string(),
        b"node=local".to_vec(),
        charlie.to_vec(),
        vec![3_u8; 32],
        sig_c,
    )
    .unwrap();
    let add_charlie = alice_room
        .add_member(
            charlie_room.key_package().unwrap(),
            "charlie".to_string(),
            charlie.to_vec(),
            "control-add-charlie".to_string(),
        )
        .unwrap();
    alice_room
        .commit_outbound(add_charlie.message_id.clone(), add_charlie.revision)
        .unwrap();
    let mut wrong_aad = add_charlie.authenticated_data.clone();
    wrong_aad[0] ^= 1;
    assert!(bob_room
        .process_control(
            add_charlie.commit.clone(),
            add_charlie.from_epoch,
            add_charlie.to_epoch,
            add_charlie.roster.clone(),
            add_charlie.membership_digest.clone(),
            add_charlie.message_id.clone(),
            wrong_aad,
        )
        .is_err());
    let mut trailing = add_charlie.commit.clone();
    trailing.push(0);
    assert!(bob_room
        .process_control(
            trailing,
            add_charlie.from_epoch,
            add_charlie.to_epoch,
            add_charlie.roster.clone(),
            add_charlie.membership_digest.clone(),
            add_charlie.message_id.clone(),
            add_charlie.authenticated_data.clone(),
        )
        .is_err());
    let info = bob_room
        .process_control(
            add_charlie.commit,
            add_charlie.from_epoch,
            add_charlie.to_epoch,
            add_charlie.roster,
            add_charlie.membership_digest,
            add_charlie.message_id.clone(),
            add_charlie.authenticated_data,
        )
        .unwrap();
    assert_eq!(info.message_id, add_charlie.message_id);
    assert_eq!(info.room_id, "test-room");
    assert!(!info.state_envelope.is_empty());
    bob_room
        .commit_outbound(add_charlie.message_id, info.revision)
        .unwrap();
}

#[test]
fn sealed_state_rejects_wrong_context_and_tampering() {
    let (alice, export, signature) = identity(101, "alice");
    let room = MlsRoom::create(
        export.clone(),
        "test-room".to_string(),
        "alice".to_string(),
        b"node=local".to_vec(),
        alice.to_vec(),
        vec![3_u8; 32],
        signature.clone(),
    )
    .unwrap();
    let info = room.room_info().unwrap();
    let mut envelope = room.seal_state().unwrap();
    let last = envelope.len() - 1;
    envelope[last] ^= 1;
    assert!(MlsRoom::recover(
        export.clone(),
        "test-room".to_string(),
        "alice".to_string(),
        b"node=local".to_vec(),
        alice.to_vec(),
        vec![3_u8; 32],
        signature.clone(),
        envelope,
        true,
        info.epoch,
        info.revision,
        vec![roster("alice", &alice)],
        info.membership_digest.clone(),
    )
    .is_err());
    assert!(MlsRoom::recover(
        export,
        "test-room".to_string(),
        "alice".to_string(),
        b"node=other".to_vec(),
        alice.to_vec(),
        vec![3_u8; 32],
        signature,
        room.seal_state().unwrap(),
        true,
        info.epoch,
        info.revision,
        vec![roster("alice", &alice)],
        info.membership_digest,
    )
    .is_err());
}

#[test]
fn state_envelope_accounts_for_authenticated_overhead_exactly() {
    let key = [7_u8; 32];
    let stable = [8_u8; 64];
    let group_id = [9_u8; 32];
    let plaintext = vec![0xA5_u8; MAX_STATE_PLAINTEXT_BYTES];
    let envelope = super::state::seal_state(
        &key,
        "alice",
        "test-room",
        b"node=local",
        &stable,
        &group_id,
        &plaintext,
    )
    .unwrap();
    assert_eq!(
        envelope.len(),
        MAX_STATE_BYTES,
        "the exact overhead must fit within the relay cap"
    );
    assert!(super::state::seal_state(
        &key,
        "alice",
        "test-room",
        b"node=local",
        &stable,
        &group_id,
        &vec![0_u8; MAX_STATE_PLAINTEXT_BYTES + 1],
    )
    .is_err());
}

#[test]
fn ram_storage_rejects_epoch_and_key_package_aggregate_overflow() {
    let storage = RamGroupStateStorage::default();
    let group_id = vec![9_u8; 32];
    let mut writable = storage.clone();
    assert!(writable
        .write(
            GroupState {
                id: group_id.clone(),
                data: Zeroizing::new(vec![1_u8; MAX_STATE_BYTES - 1]),
            },
            vec![EpochRecord::new(1, Zeroizing::new(vec![2_u8; 2]))],
            Vec::new(),
        )
        .is_err());
    let key_packages = RamKeyPackageStorage::default();
    let (alice, export, sig) = identity(61, "alice");
    let room = MlsRoom::pending_join(
        export,
        "test-room".to_string(),
        "alice".to_string(),
        b"node=local".to_vec(),
        alice.to_vec(),
        vec![3_u8; 32],
        sig,
    )
    .unwrap();
    room.key_package().unwrap();
    let state = room.state.lock().unwrap();
    let data = state
        .key_packages
        .inner
        .lock()
        .unwrap()
        .values()
        .next()
        .cloned()
        .unwrap();
    let mut pending = key_packages.clone();
    assert!(pending
        .insert(
            vec![8_u8],
            KeyPackageData::new(
                vec![0_u8; MAX_KEY_PACKAGE_BYTES + 1],
                data.init_key,
                data.leaf_node_key,
                data.expiration,
            ),
        )
        .is_err());
}

#[test]
fn removed_member_is_closed_and_wiped_after_self_removal_control() {
    let (alice, export_a, sig_a) = identity(71, "alice");
    let (bob, export_b, sig_b) = identity(72, "bob");
    let alice_room = MlsRoom::create(
        export_a,
        "test-room".to_string(),
        "alice".to_string(),
        b"node=local".to_vec(),
        alice.to_vec(),
        vec![3_u8; 32],
        sig_a,
    )
    .unwrap();
    let bob_room = MlsRoom::pending_join(
        export_b,
        "test-room".to_string(),
        "bob".to_string(),
        b"node=local".to_vec(),
        bob.to_vec(),
        vec![3_u8; 32],
        sig_b,
    )
    .unwrap();
    let add = alice_room
        .add_member(
            bob_room.key_package().unwrap(),
            "bob".to_string(),
            bob.to_vec(),
            "self-remove-add".to_string(),
        )
        .unwrap();
    alice_room
        .commit_outbound(add.message_id.clone(), add.revision)
        .unwrap();
    bob_room
        .join_welcome(add.welcome, add.roster, add.membership_digest)
        .unwrap();
    let remove = alice_room
        .remove_member("bob".to_string(), bob.to_vec(), "self-remove".to_string())
        .unwrap();
    alice_room
        .commit_outbound(remove.message_id.clone(), remove.revision)
        .unwrap();
    assert!(bob_room
        .process_control(
            remove.commit,
            remove.from_epoch,
            remove.to_epoch,
            remove.roster,
            remove.membership_digest,
            remove.message_id,
            remove.authenticated_data,
        )
        .is_err());
    assert!(bob_room.room_info().is_err());
    assert!(bob_room.seal_state().is_err());
    assert!(bob_room.key_package().is_err());
}

#[test]
fn replay_ids_are_message_bound_and_domain_separated() {
    let message_id = "same-logical-id";
    assert_eq!(
        replay_digest_from_message_id(MEMBERSHIP_REPLAY_DOMAIN, message_id),
        replay_digest_from_message_id(MEMBERSHIP_REPLAY_DOMAIN, message_id)
    );
    assert_ne!(
        replay_digest_from_message_id(MEMBERSHIP_REPLAY_DOMAIN, message_id),
        replay_digest_from_message_id(APPLICATION_REPLAY_DOMAIN, message_id)
    );
    assert_ne!(
        replay_digest_from_message_id(b"application", message_id),
        replay_digest_from_message_id(b"application", "other-id")
    );
}

#[test]
fn replay_window_rolls_transactionally_at_capacity_and_survives_recovery() {
    let (alice, export_a, sig_a) = identity(112, "alice");
    let (bob, export_b, sig_b) = identity(113, "bob");
    let alice_room = MlsRoom::create(
        export_a,
        "test-room".to_string(),
        "alice".to_string(),
        b"node=local".to_vec(),
        alice.to_vec(),
        vec![3_u8; 32],
        sig_a,
    )
    .unwrap();
    let bob_room = MlsRoom::pending_join(
        export_b.clone(),
        "test-room".to_string(),
        "bob".to_string(),
        b"node=local".to_vec(),
        bob.to_vec(),
        vec![3_u8; 32],
        sig_b.clone(),
    )
    .unwrap();
    let add = alice_room
        .add_member(
            bob_room.key_package().unwrap(),
            "bob".to_string(),
            bob.to_vec(),
            "rolling-add".to_string(),
        )
        .unwrap();
    alice_room
        .commit_outbound(add.message_id.clone(), add.revision)
        .unwrap();
    let expected_roster = add.roster.clone();
    bob_room
        .join_welcome(add.welcome, add.roster, add.membership_digest)
        .unwrap();

    let original_window: VecDeque<_> = (0..MAX_REPLAY_IDS)
        .map(|index| {
            replay_digest_from_message_id(APPLICATION_REPLAY_DOMAIN, &format!("old-{index}"))
        })
        .collect();
    bob_room.lock_state_mut().unwrap().replay_ids = original_window.clone();

    let application = alice_room
        .encrypt_application(
            "rolling-application".to_string(),
            b"latest".to_vec(),
            b"aad".to_vec(),
        )
        .unwrap();
    alice_room
        .commit_outbound(application.message_id.clone(), application.revision)
        .unwrap();
    let received = bob_room
        .decrypt_application(
            application.ciphertext.clone(),
            application.epoch,
            application.message_id.clone(),
            application.authenticated_data.clone(),
        )
        .unwrap();
    assert_eq!(bob_room.lock_state().unwrap().replay_ids, original_window);
    bob_room
        .rollback_outbound(application.message_id.clone(), received.revision)
        .unwrap();
    assert_eq!(bob_room.lock_state().unwrap().replay_ids, original_window);

    let received = bob_room
        .decrypt_application(
            application.ciphertext.clone(),
            application.epoch,
            application.message_id.clone(),
            application.authenticated_data.clone(),
        )
        .unwrap();
    bob_room
        .commit_outbound(application.message_id.clone(), received.revision)
        .unwrap();
    let latest = replay_digest_from_message_id(APPLICATION_REPLAY_DOMAIN, &application.message_id);
    {
        let state = bob_room.lock_state().unwrap();
        assert_eq!(state.replay_ids.len(), MAX_REPLAY_IDS);
        assert_eq!(state.replay_ids.front(), original_window.get(1));
        assert_eq!(state.replay_ids.back(), Some(&latest));
    }
    assert!(bob_room
        .decrypt_application(
            application.ciphertext,
            application.epoch,
            application.message_id,
            application.authenticated_data,
        )
        .is_err());

    let info = bob_room.room_info().unwrap();
    let envelope = bob_room.seal_state().unwrap();
    let recovered = MlsRoom::recover(
        export_b,
        "test-room".to_string(),
        "bob".to_string(),
        b"node=local".to_vec(),
        bob.to_vec(),
        vec![3_u8; 32],
        sig_b,
        envelope,
        true,
        info.epoch,
        info.revision,
        expected_roster,
        info.membership_digest,
    )
    .unwrap();
    let recovered_state = recovered.lock_state().unwrap();
    assert_eq!(recovered_state.replay_ids.len(), MAX_REPLAY_IDS);
    assert_eq!(recovered_state.replay_ids.front(), original_window.get(1));
    assert_eq!(recovered_state.replay_ids.back(), Some(&latest));
}

#[test]
fn out_of_order_application_within_library_window_decrypts() {
    let (alice, export_a, sig_a) = identity(114, "alice");
    let (bob, export_b, sig_b) = identity(115, "bob");
    let alice_room = MlsRoom::create(
        export_a,
        "test-room".to_string(),
        "alice".to_string(),
        b"node=local".to_vec(),
        alice.to_vec(),
        vec![3_u8; 32],
        sig_a,
    )
    .unwrap();
    let bob_room = MlsRoom::pending_join(
        export_b,
        "test-room".to_string(),
        "bob".to_string(),
        b"node=local".to_vec(),
        bob.to_vec(),
        vec![3_u8; 32],
        sig_b,
    )
    .unwrap();
    let add = alice_room
        .add_member(
            bob_room.key_package().unwrap(),
            "bob".to_string(),
            bob.to_vec(),
            "out-of-order-add".to_string(),
        )
        .unwrap();
    alice_room
        .commit_outbound(add.message_id.clone(), add.revision)
        .unwrap();
    bob_room
        .join_welcome(add.welcome, add.roster, add.membership_digest)
        .unwrap();

    let first = alice_room
        .encrypt_application(
            "out-of-order-1".to_string(),
            b"first".to_vec(),
            b"aad".to_vec(),
        )
        .unwrap();
    alice_room
        .commit_outbound(first.message_id, first.revision)
        .unwrap();
    let second = alice_room
        .encrypt_application(
            "out-of-order-2".to_string(),
            b"second".to_vec(),
            b"aad".to_vec(),
        )
        .unwrap();
    alice_room
        .commit_outbound(second.message_id.clone(), second.revision)
        .unwrap();
    let received = bob_room
        .decrypt_application(
            second.ciphertext,
            second.epoch,
            second.message_id.clone(),
            second.authenticated_data,
        )
        .unwrap();
    assert_eq!(received.plaintext, b"second");
    bob_room
        .commit_outbound(second.message_id, received.revision)
        .unwrap();
}

#[test]
fn account_revocation_waits_for_inflight_room_guard() {
    let session = E2eeSession::create(vec![121_u8; 64]).expect("account");
    let room = session
        .create_mls_room(
            "concurrency-room".to_string(),
            "alice".to_string(),
            b"node=local".to_vec(),
            vec![122_u8; 32],
        )
        .expect("room");
    let state_guard = room.lock_state().expect("state guard");
    let (started_tx, started_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();
    let drop_thread = std::thread::spawn(move || {
        started_tx.send(()).expect("started");
        drop(session);
        finished_tx.send(()).expect("finished");
    });
    started_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("drop started");
    assert!(finished_rx.recv_timeout(Duration::from_millis(50)).is_err());
    drop(state_guard);
    finished_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("drop completed");
    drop_thread.join().expect("drop thread");
    assert!(room.room_info().is_err());
    assert!(room.key_package().is_err());
}

#[test]
fn revoked_room_rejects_every_mls_operation() {
    let room = {
        let session = E2eeSession::create(vec![123_u8; 64]).expect("account");
        session
            .create_mls_room(
                "all-operations-room".to_string(),
                "alice".to_string(),
                b"node=local".to_vec(),
                vec![124_u8; 32],
            )
            .expect("room")
    };
    let stable = vec![1_u8; 64];
    let failures = [
        ("room_info", room.room_info().map(|_| ())),
        ("key_package", room.key_package().map(|_| ())),
        (
            "add_member",
            room.add_member(
                vec![1],
                "bob".to_string(),
                stable.clone(),
                "add".to_string(),
            )
            .map(|_| ()),
        ),
        (
            "remove_member",
            room.remove_member("bob".to_string(), stable, "remove".to_string())
                .map(|_| ()),
        ),
        (
            "commit_outbound",
            room.commit_outbound("commit".to_string(), 0),
        ),
        (
            "rollback_outbound",
            room.rollback_outbound("rollback".to_string(), 0),
        ),
        (
            "join_welcome",
            room.join_welcome(vec![1], Vec::new(), vec![1_u8; 32])
                .map(|_| ()),
        ),
        (
            "process_control",
            room.process_control(
                vec![1],
                0,
                1,
                Vec::new(),
                vec![1_u8; 32],
                "control".to_string(),
                vec![1],
            )
            .map(|_| ()),
        ),
        (
            "encrypt_application",
            room.encrypt_application("encrypt".to_string(), vec![1], vec![1])
                .map(|_| ()),
        ),
        (
            "decrypt_application",
            room.decrypt_application(vec![1], 0, "decrypt".to_string(), vec![1])
                .map(|_| ()),
        ),
        ("seal_state", room.seal_state().map(|_| ())),
    ];
    for (operation, result) in failures {
        assert!(
            result.is_err(),
            "stale room operation unexpectedly succeeded: {operation}"
        );
    }
}

#[test]
fn poisoned_account_lifetime_and_room_state_fail_closed() {
    let session = E2eeSession::create(vec![127_u8; 64]).expect("account");
    let room = session
        .create_mls_room(
            "poisoned-state-room".to_string(),
            "alice".to_string(),
            b"node=local".to_vec(),
            vec![128_u8; 32],
        )
        .expect("room");
    let room_for_thread = Arc::clone(&room);
    let state_thread = std::thread::spawn(move || {
        let _guard = room_for_thread.state.lock().expect("state lock");
        panic!("poison room state lock for fail-closed test");
    });
    assert!(state_thread.join().is_err());
    assert!(room.room_info().is_err());
    assert!(room.key_package().is_err());
    assert!(room.seal_state().is_err());
}

#[test]
fn application_plaintext_and_ciphertext_limits_fail_before_state_mutation() {
    let (alice, export, signature) = identity(111, "alice");
    let room = MlsRoom::create(
        export,
        "test-room".to_string(),
        "alice".to_string(),
        b"node=local".to_vec(),
        alice.to_vec(),
        vec![3_u8; 32],
        signature,
    )
    .unwrap();
    let before = room.room_info().unwrap();
    assert!(room
        .encrypt_application(
            "plaintext-too-large".to_string(),
            vec![0; MAX_APPLICATION_PLAINTEXT_BYTES + 1],
            b"aad".to_vec(),
        )
        .is_err());
    assert_eq!(room.room_info().unwrap(), before);

    let boundary = room
        .encrypt_application(
            "plaintext-boundary".to_string(),
            vec![0; MAX_APPLICATION_PLAINTEXT_BYTES],
            b"aad".to_vec(),
        )
        .unwrap();
    assert!(boundary.ciphertext.len() <= MAX_APPLICATION_CIPHERTEXT_BYTES);
    room.rollback_outbound(boundary.message_id, boundary.revision)
        .unwrap();
    assert_eq!(room.room_info().unwrap(), before);

    assert!(room
        .decrypt_application(
            vec![0; MAX_APPLICATION_CIPHERTEXT_BYTES + 1],
            before.epoch,
            "ciphertext-too-large".to_string(),
            b"aad".to_vec(),
        )
        .is_err());
    assert_eq!(room.room_info().unwrap(), before);
}
