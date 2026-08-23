/* tslint:disable */
/* eslint-disable */

export class WasmE2eeSession {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    commitOutbound(message_id: string, revision: bigint): void;
    static create(export_key: Uint8Array): WasmE2eeSession;
    decrypt(chat_id: string, message_id: string, sender_username: string, sender_public_key: Uint8Array, version: number, identity_public: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, signature: Uint8Array, wrapped_key: Uint8Array, recipient_prekey_id: string, is_prekey: boolean, recipient_username: string): string;
    encrypt(chat_id: string, message_id: string, sender_username: string, plaintext: Uint8Array, recipients_json: string): string;
    mlsCreateRoom(room_id: string, username: string, node_context: Uint8Array, group_id: Uint8Array): WasmMlsRoom;
    mlsPendingJoin(room_id: string, username: string, node_context: Uint8Array, group_id: Uint8Array): WasmMlsRoom;
    mlsRecoverRoom(room_id: string, username: string, node_context: Uint8Array, group_id: Uint8Array, envelope: Uint8Array, expected_active: boolean, expected_epoch: bigint, expected_revision: bigint, expected_members_json: string, expected_digest: Uint8Array): WasmMlsRoom;
    prekeyId(): string;
    publicKey(): Uint8Array;
    static recover(export_key: Uint8Array, context: Uint8Array, envelope: Uint8Array, expected_public_key: Uint8Array): WasmE2eeSession;
    requiresPrekey(peer: string): boolean;
    rollbackOutbound(message_id: string, revision: bigint): void;
    sealIdentity(export_key: Uint8Array, context: Uint8Array): Uint8Array;
    signAcknowledgement(chat_id: string, message_id: string, original_sender_username: string, used_prekey_id: string): Uint8Array;
    signRegistrationIdentityProof(node_id: string, handshake_id: string, challenge: Uint8Array, registration_upload: Uint8Array, identity_public: Uint8Array, prekey_id: string, identity_envelope: Uint8Array): Uint8Array;
}

export class WasmMlsApplicationMessage {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly authenticatedData: Uint8Array;
    readonly epoch: bigint;
    readonly groupId: Uint8Array;
    readonly membershipDigest: Uint8Array;
    readonly messageId: string;
    readonly plaintext: Uint8Array;
    readonly revision: bigint;
    readonly senderIndex: number;
    readonly stateEnvelope: Uint8Array;
}

export class WasmMlsCommit {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly authenticatedData: Uint8Array;
    readonly commit: Uint8Array;
    readonly fromEpoch: bigint;
    readonly fromMembershipDigest: Uint8Array;
    readonly groupId: Uint8Array;
    readonly membershipDigest: Uint8Array;
    readonly messageId: string;
    readonly revision: bigint;
    readonly rosterJson: string;
    readonly stateEnvelope: Uint8Array;
    readonly toEpoch: bigint;
    readonly welcome: Uint8Array;
}

export class WasmMlsEncryptedApplication {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly authenticatedData: Uint8Array;
    readonly ciphertext: Uint8Array;
    readonly epoch: bigint;
    readonly groupId: Uint8Array;
    readonly membershipDigest: Uint8Array;
    readonly messageId: string;
    readonly revision: bigint;
    readonly senderIndex: number;
    readonly stateEnvelope: Uint8Array;
}

export class WasmMlsProcessedControl {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly epoch: bigint;
    readonly groupId: Uint8Array;
    readonly memberCount: number;
    readonly membershipDigest: Uint8Array;
    readonly messageId: string;
    readonly revision: bigint;
    readonly roomId: string;
    readonly stateEnvelope: Uint8Array;
}

export class WasmMlsRoom {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    addMember(key_package: Uint8Array, expected_username: string, expected_stable_identity: Uint8Array, message_id: string): WasmMlsCommit;
    commitOutbound(message_id: string, revision: bigint): void;
    decryptApplication(ciphertext: Uint8Array, expected_epoch: bigint, message_id: string, expected_authenticated_data: Uint8Array): WasmMlsApplicationMessage;
    encryptApplication(message_id: string, plaintext: Uint8Array, authenticated_data: Uint8Array): WasmMlsEncryptedApplication;
    joinWelcome(welcome: Uint8Array, expected_members_json: string, expected_digest: Uint8Array): WasmMlsRoomInfo;
    keyPackage(): Uint8Array;
    processControl(control: Uint8Array, expected_from_epoch: bigint, expected_to_epoch: bigint, expected_members_json: string, expected_digest: Uint8Array, message_id: string, expected_authenticated_data: Uint8Array): WasmMlsProcessedControl;
    removeMember(expected_username: string, expected_stable_identity: Uint8Array, message_id: string): WasmMlsCommit;
    rollbackOutbound(message_id: string, revision: bigint): void;
    roomInfo(): WasmMlsRoomInfo;
    sealState(): Uint8Array;
}

export class WasmMlsRoomInfo {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly epoch: bigint;
    readonly groupId: Uint8Array;
    readonly memberCount: number;
    readonly membershipDigest: Uint8Array;
    readonly revision: bigint;
    readonly roomId: string;
}

export function conversationSafetyNumber(first_public_key: Uint8Array, second_public_key: Uint8Array): string;

export function decryptAttachment(chat_id: string, message_id: string, sender_username: string, media_type: string, key: Uint8Array, blob: Uint8Array): Uint8Array;

export function encryptAttachment(chat_id: string, message_id: string, sender_username: string, media_type: string, plaintext: Uint8Array): string;

export function inspectReleaseManifest(manifest_json: Uint8Array, signature: Uint8Array): string;

export function opaqueClientFinishLogin(password: Uint8Array, login_state: Uint8Array, credential_response: Uint8Array): string;

export function opaqueClientFinishRegistration(password: Uint8Array, registration_state: Uint8Array, registration_response: Uint8Array): string;

export function opaqueClientStart(password: Uint8Array): string;

export function parseReleaseBuildId(build_id: string): string;

export function releaseSha256(data: Uint8Array): Uint8Array;

export function releaseTrustAnchorConfigured(): boolean;

export function verifyReleaseBuildSignature(build_id: string, source_commit: string, signature: Uint8Array): void;

export function verifyReleaseManifest(manifest_json: Uint8Array, signature: Uint8Array, now_ms: bigint): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_wasme2eesession_free: (a: number, b: number) => void;
    readonly __wbg_wasmmlsapplicationmessage_free: (a: number, b: number) => void;
    readonly __wbg_wasmmlscommit_free: (a: number, b: number) => void;
    readonly __wbg_wasmmlsprocessedcontrol_free: (a: number, b: number) => void;
    readonly __wbg_wasmmlsroom_free: (a: number, b: number) => void;
    readonly __wbg_wasmmlsroominfo_free: (a: number, b: number) => void;
    readonly conversationSafetyNumber: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly decryptAttachment: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => [number, number, number, number];
    readonly encryptAttachment: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number, number];
    readonly ffi_abyssal_core_rust_future_cancel_f32: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_complete_f32: (a: bigint, b: number) => number;
    readonly ffi_abyssal_core_rust_future_complete_f64: (a: bigint, b: number) => number;
    readonly ffi_abyssal_core_rust_future_complete_i16: (a: bigint, b: number) => number;
    readonly ffi_abyssal_core_rust_future_complete_i32: (a: bigint, b: number) => number;
    readonly ffi_abyssal_core_rust_future_complete_i64: (a: bigint, b: number) => bigint;
    readonly ffi_abyssal_core_rust_future_complete_i8: (a: bigint, b: number) => number;
    readonly ffi_abyssal_core_rust_future_complete_rust_buffer: (a: number, b: bigint, c: number) => void;
    readonly ffi_abyssal_core_rust_future_complete_u16: (a: bigint, b: number) => number;
    readonly ffi_abyssal_core_rust_future_complete_u8: (a: bigint, b: number) => number;
    readonly ffi_abyssal_core_rust_future_complete_void: (a: bigint, b: number) => void;
    readonly ffi_abyssal_core_rust_future_free_f32: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_poll_f32: (a: bigint, b: number, c: bigint) => void;
    readonly ffi_abyssal_core_rust_future_poll_f64: (a: bigint, b: number, c: bigint) => void;
    readonly ffi_abyssal_core_rust_future_poll_i16: (a: bigint, b: number, c: bigint) => void;
    readonly ffi_abyssal_core_rust_future_poll_i32: (a: bigint, b: number, c: bigint) => void;
    readonly ffi_abyssal_core_rust_future_poll_i64: (a: bigint, b: number, c: bigint) => void;
    readonly ffi_abyssal_core_rust_future_poll_i8: (a: bigint, b: number, c: bigint) => void;
    readonly ffi_abyssal_core_rust_future_poll_rust_buffer: (a: bigint, b: number, c: bigint) => void;
    readonly ffi_abyssal_core_rust_future_poll_u16: (a: bigint, b: number, c: bigint) => void;
    readonly ffi_abyssal_core_rust_future_poll_u32: (a: bigint, b: number, c: bigint) => void;
    readonly ffi_abyssal_core_rust_future_poll_u64: (a: bigint, b: number, c: bigint) => void;
    readonly ffi_abyssal_core_rust_future_poll_u8: (a: bigint, b: number, c: bigint) => void;
    readonly ffi_abyssal_core_rust_future_poll_void: (a: bigint, b: number, c: bigint) => void;
    readonly ffi_abyssal_core_rustbuffer_alloc: (a: number, b: bigint, c: number) => void;
    readonly ffi_abyssal_core_rustbuffer_free: (a: number, b: number) => void;
    readonly ffi_abyssal_core_rustbuffer_from_bytes: (a: number, b: number, c: number) => void;
    readonly ffi_abyssal_core_rustbuffer_reserve: (a: number, b: number, c: bigint, d: number) => void;
    readonly ffi_abyssal_core_uniffi_contract_version: () => number;
    readonly inspectReleaseManifest: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly opaqueClientFinishLogin: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly opaqueClientFinishRegistration: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly opaqueClientStart: (a: number, b: number) => [number, number, number, number];
    readonly parseReleaseBuildId: (a: number, b: number) => [number, number, number, number];
    readonly releaseSha256: (a: number, b: number) => [number, number];
    readonly releaseTrustAnchorConfigured: () => number;
    readonly uniffi_abyssal_core_checksum_constructor_e2eesession_create: () => number;
    readonly uniffi_abyssal_core_checksum_constructor_e2eesession_recover: () => number;
    readonly uniffi_abyssal_core_checksum_func_conversation_safety_number: () => number;
    readonly uniffi_abyssal_core_checksum_func_decrypt_attachment: () => number;
    readonly uniffi_abyssal_core_checksum_func_encrypt_attachment: () => number;
    readonly uniffi_abyssal_core_checksum_func_inspect_release_manifest: () => number;
    readonly uniffi_abyssal_core_checksum_func_opaque_client_finish_login: () => number;
    readonly uniffi_abyssal_core_checksum_func_opaque_client_finish_registration: () => number;
    readonly uniffi_abyssal_core_checksum_func_opaque_client_start: () => number;
    readonly uniffi_abyssal_core_checksum_func_parse_release_build_id: () => number;
    readonly uniffi_abyssal_core_checksum_func_release_sha256: () => number;
    readonly uniffi_abyssal_core_checksum_func_release_trust_anchor_configured: () => number;
    readonly uniffi_abyssal_core_checksum_func_verify_release_build_signature: () => number;
    readonly uniffi_abyssal_core_checksum_func_verify_release_manifest: () => number;
    readonly uniffi_abyssal_core_checksum_method_e2eesession_commit_outbound: () => number;
    readonly uniffi_abyssal_core_checksum_method_e2eesession_create_mls_room: () => number;
    readonly uniffi_abyssal_core_checksum_method_e2eesession_decrypt: () => number;
    readonly uniffi_abyssal_core_checksum_method_e2eesession_encrypt: () => number;
    readonly uniffi_abyssal_core_checksum_method_e2eesession_pending_mls_join: () => number;
    readonly uniffi_abyssal_core_checksum_method_e2eesession_prekey_id: () => number;
    readonly uniffi_abyssal_core_checksum_method_e2eesession_public_key: () => number;
    readonly uniffi_abyssal_core_checksum_method_e2eesession_recover_mls_room: () => number;
    readonly uniffi_abyssal_core_checksum_method_e2eesession_requires_prekey: () => number;
    readonly uniffi_abyssal_core_checksum_method_e2eesession_rollback_outbound: () => number;
    readonly uniffi_abyssal_core_checksum_method_e2eesession_seal_identity: () => number;
    readonly uniffi_abyssal_core_checksum_method_e2eesession_sign_acknowledgement: () => number;
    readonly uniffi_abyssal_core_checksum_method_e2eesession_sign_registration_identity_proof: () => number;
    readonly uniffi_abyssal_core_checksum_method_mlsprocessedcontrol_epoch: () => number;
    readonly uniffi_abyssal_core_checksum_method_mlsprocessedcontrol_group_id: () => number;
    readonly uniffi_abyssal_core_checksum_method_mlsprocessedcontrol_member_count: () => number;
    readonly uniffi_abyssal_core_checksum_method_mlsprocessedcontrol_membership_digest: () => number;
    readonly uniffi_abyssal_core_checksum_method_mlsprocessedcontrol_message_id: () => number;
    readonly uniffi_abyssal_core_checksum_method_mlsprocessedcontrol_revision: () => number;
    readonly uniffi_abyssal_core_checksum_method_mlsprocessedcontrol_room_id: () => number;
    readonly uniffi_abyssal_core_checksum_method_mlsprocessedcontrol_state_envelope: () => number;
    readonly uniffi_abyssal_core_checksum_method_mlsroom_add_member: () => number;
    readonly uniffi_abyssal_core_checksum_method_mlsroom_commit_outbound: () => number;
    readonly uniffi_abyssal_core_checksum_method_mlsroom_decrypt_application: () => number;
    readonly uniffi_abyssal_core_checksum_method_mlsroom_encrypt_application: () => number;
    readonly uniffi_abyssal_core_checksum_method_mlsroom_join_welcome: () => number;
    readonly uniffi_abyssal_core_checksum_method_mlsroom_key_package: () => number;
    readonly uniffi_abyssal_core_checksum_method_mlsroom_process_control: () => number;
    readonly uniffi_abyssal_core_checksum_method_mlsroom_remove_member: () => number;
    readonly uniffi_abyssal_core_checksum_method_mlsroom_rollback_outbound: () => number;
    readonly uniffi_abyssal_core_checksum_method_mlsroom_room_info: () => number;
    readonly uniffi_abyssal_core_checksum_method_mlsroom_seal_state: () => number;
    readonly uniffi_abyssal_core_fn_clone_e2eesession: (a: bigint, b: number) => bigint;
    readonly uniffi_abyssal_core_fn_constructor_e2eesession_create: (a: number, b: number) => bigint;
    readonly uniffi_abyssal_core_fn_constructor_e2eesession_recover: (a: number, b: number, c: number, d: number, e: number) => bigint;
    readonly uniffi_abyssal_core_fn_free_e2eesession: (a: bigint, b: number) => void;
    readonly uniffi_abyssal_core_fn_free_mlsprocessedcontrol: (a: bigint, b: number) => void;
    readonly uniffi_abyssal_core_fn_free_mlsroom: (a: bigint, b: number) => void;
    readonly uniffi_abyssal_core_fn_func_conversation_safety_number: (a: number, b: number, c: number, d: number) => void;
    readonly uniffi_abyssal_core_fn_func_decrypt_attachment: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => void;
    readonly uniffi_abyssal_core_fn_func_encrypt_attachment: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly uniffi_abyssal_core_fn_func_inspect_release_manifest: (a: number, b: number, c: number, d: number) => void;
    readonly uniffi_abyssal_core_fn_func_opaque_client_finish_login: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly uniffi_abyssal_core_fn_func_opaque_client_finish_registration: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly uniffi_abyssal_core_fn_func_opaque_client_start: (a: number, b: number, c: number) => void;
    readonly uniffi_abyssal_core_fn_func_parse_release_build_id: (a: number, b: number, c: number) => void;
    readonly uniffi_abyssal_core_fn_func_release_sha256: (a: number, b: number, c: number) => void;
    readonly uniffi_abyssal_core_fn_func_release_trust_anchor_configured: (a: number) => number;
    readonly uniffi_abyssal_core_fn_func_verify_release_build_signature: (a: number, b: number, c: number, d: number) => void;
    readonly uniffi_abyssal_core_fn_func_verify_release_manifest: (a: number, b: number, c: number, d: bigint, e: number) => void;
    readonly uniffi_abyssal_core_fn_method_e2eesession_commit_outbound: (a: bigint, b: number, c: bigint, d: number) => void;
    readonly uniffi_abyssal_core_fn_method_e2eesession_create_mls_room: (a: bigint, b: number, c: number, d: number, e: number, f: number) => bigint;
    readonly uniffi_abyssal_core_fn_method_e2eesession_decrypt: (a: number, b: bigint, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number) => void;
    readonly uniffi_abyssal_core_fn_method_e2eesession_encrypt: (a: number, b: bigint, c: number, d: number, e: number, f: number, g: number, h: number) => void;
    readonly uniffi_abyssal_core_fn_method_e2eesession_pending_mls_join: (a: bigint, b: number, c: number, d: number, e: number, f: number) => bigint;
    readonly uniffi_abyssal_core_fn_method_e2eesession_prekey_id: (a: number, b: bigint, c: number) => void;
    readonly uniffi_abyssal_core_fn_method_e2eesession_public_key: (a: number, b: bigint, c: number) => void;
    readonly uniffi_abyssal_core_fn_method_e2eesession_recover_mls_room: (a: bigint, b: number, c: number, d: number, e: number, f: number, g: number, h: bigint, i: bigint, j: number, k: number, l: number) => bigint;
    readonly uniffi_abyssal_core_fn_method_e2eesession_requires_prekey: (a: bigint, b: number, c: number) => number;
    readonly uniffi_abyssal_core_fn_method_e2eesession_rollback_outbound: (a: bigint, b: number, c: bigint, d: number) => void;
    readonly uniffi_abyssal_core_fn_method_e2eesession_seal_identity: (a: number, b: bigint, c: number, d: number, e: number) => void;
    readonly uniffi_abyssal_core_fn_method_e2eesession_sign_acknowledgement: (a: number, b: bigint, c: number, d: number, e: number, f: number, g: number) => void;
    readonly uniffi_abyssal_core_fn_method_e2eesession_sign_registration_identity_proof: (a: number, b: bigint, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => void;
    readonly uniffi_abyssal_core_fn_method_mlsprocessedcontrol_epoch: (a: bigint, b: number) => bigint;
    readonly uniffi_abyssal_core_fn_method_mlsprocessedcontrol_group_id: (a: number, b: bigint, c: number) => void;
    readonly uniffi_abyssal_core_fn_method_mlsprocessedcontrol_member_count: (a: bigint, b: number) => number;
    readonly uniffi_abyssal_core_fn_method_mlsprocessedcontrol_membership_digest: (a: number, b: bigint, c: number) => void;
    readonly uniffi_abyssal_core_fn_method_mlsprocessedcontrol_message_id: (a: number, b: bigint, c: number) => void;
    readonly uniffi_abyssal_core_fn_method_mlsprocessedcontrol_revision: (a: bigint, b: number) => bigint;
    readonly uniffi_abyssal_core_fn_method_mlsprocessedcontrol_room_id: (a: number, b: bigint, c: number) => void;
    readonly uniffi_abyssal_core_fn_method_mlsprocessedcontrol_state_envelope: (a: number, b: bigint, c: number) => void;
    readonly uniffi_abyssal_core_fn_method_mlsroom_add_member: (a: number, b: bigint, c: number, d: number, e: number, f: number, g: number) => void;
    readonly uniffi_abyssal_core_fn_method_mlsroom_commit_outbound: (a: bigint, b: number, c: bigint, d: number) => void;
    readonly uniffi_abyssal_core_fn_method_mlsroom_decrypt_application: (a: number, b: bigint, c: number, d: bigint, e: number, f: number, g: number) => void;
    readonly uniffi_abyssal_core_fn_method_mlsroom_encrypt_application: (a: number, b: bigint, c: number, d: number, e: number, f: number) => void;
    readonly uniffi_abyssal_core_fn_method_mlsroom_join_welcome: (a: number, b: bigint, c: number, d: number, e: number, f: number) => void;
    readonly uniffi_abyssal_core_fn_method_mlsroom_key_package: (a: number, b: bigint, c: number) => void;
    readonly uniffi_abyssal_core_fn_method_mlsroom_process_control: (a: bigint, b: number, c: bigint, d: bigint, e: number, f: number, g: number, h: number, i: number) => bigint;
    readonly uniffi_abyssal_core_fn_method_mlsroom_remove_member: (a: number, b: bigint, c: number, d: number, e: number, f: number) => void;
    readonly uniffi_abyssal_core_fn_method_mlsroom_rollback_outbound: (a: bigint, b: number, c: bigint, d: number) => void;
    readonly uniffi_abyssal_core_fn_method_mlsroom_room_info: (a: number, b: bigint, c: number) => void;
    readonly uniffi_abyssal_core_fn_method_mlsroom_seal_state: (a: number, b: bigint, c: number) => void;
    readonly verifyReleaseBuildSignature: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number];
    readonly verifyReleaseManifest: (a: number, b: number, c: number, d: number, e: bigint) => [number, number, number, number];
    readonly wasme2eesession_commitOutbound: (a: number, b: number, c: number, d: bigint) => [number, number];
    readonly wasme2eesession_create: (a: number, b: number) => [number, number, number];
    readonly wasme2eesession_decrypt: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number, r: number, s: number, t: number, u: number, v: number, w: number, x: number, y: number) => [number, number, number, number];
    readonly wasme2eesession_encrypt: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number) => [number, number, number, number];
    readonly wasme2eesession_mlsCreateRoom: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number, number];
    readonly wasme2eesession_mlsPendingJoin: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number, number];
    readonly wasme2eesession_mlsRecoverRoom: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: bigint, n: bigint, o: number, p: number, q: number, r: number) => [number, number, number];
    readonly wasme2eesession_prekeyId: (a: number) => [number, number];
    readonly wasme2eesession_publicKey: (a: number) => [number, number];
    readonly wasme2eesession_recover: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly wasme2eesession_requiresPrekey: (a: number, b: number, c: number) => [number, number, number];
    readonly wasme2eesession_rollbackOutbound: (a: number, b: number, c: number, d: bigint) => [number, number];
    readonly wasme2eesession_sealIdentity: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly wasme2eesession_signAcknowledgement: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number, number, number];
    readonly wasme2eesession_signRegistrationIdentityProof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number) => [number, number, number, number];
    readonly wasmmlsapplicationmessage_authenticatedData: (a: number) => [number, number];
    readonly wasmmlsapplicationmessage_epoch: (a: number) => bigint;
    readonly wasmmlsapplicationmessage_groupId: (a: number) => [number, number];
    readonly wasmmlsapplicationmessage_membershipDigest: (a: number) => [number, number];
    readonly wasmmlsapplicationmessage_messageId: (a: number) => [number, number];
    readonly wasmmlsapplicationmessage_plaintext: (a: number) => [number, number];
    readonly wasmmlsapplicationmessage_revision: (a: number) => bigint;
    readonly wasmmlsapplicationmessage_senderIndex: (a: number) => number;
    readonly wasmmlsapplicationmessage_stateEnvelope: (a: number) => [number, number];
    readonly wasmmlscommit_authenticatedData: (a: number) => [number, number];
    readonly wasmmlscommit_commit: (a: number) => [number, number];
    readonly wasmmlscommit_fromMembershipDigest: (a: number) => [number, number];
    readonly wasmmlscommit_groupId: (a: number) => [number, number];
    readonly wasmmlscommit_membershipDigest: (a: number) => [number, number];
    readonly wasmmlscommit_messageId: (a: number) => [number, number];
    readonly wasmmlscommit_rosterJson: (a: number) => [number, number, number, number];
    readonly wasmmlscommit_stateEnvelope: (a: number) => [number, number];
    readonly wasmmlscommit_toEpoch: (a: number) => bigint;
    readonly wasmmlscommit_welcome: (a: number) => [number, number];
    readonly wasmmlsprocessedcontrol_epoch: (a: number) => bigint;
    readonly wasmmlsprocessedcontrol_groupId: (a: number) => [number, number];
    readonly wasmmlsprocessedcontrol_memberCount: (a: number) => number;
    readonly wasmmlsprocessedcontrol_membershipDigest: (a: number) => [number, number];
    readonly wasmmlsprocessedcontrol_messageId: (a: number) => [number, number];
    readonly wasmmlsprocessedcontrol_revision: (a: number) => bigint;
    readonly wasmmlsprocessedcontrol_roomId: (a: number) => [number, number];
    readonly wasmmlsprocessedcontrol_stateEnvelope: (a: number) => [number, number];
    readonly wasmmlsroom_addMember: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number, number];
    readonly wasmmlsroom_commitOutbound: (a: number, b: number, c: number, d: bigint) => [number, number];
    readonly wasmmlsroom_decryptApplication: (a: number, b: number, c: number, d: bigint, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly wasmmlsroom_encryptApplication: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number];
    readonly wasmmlsroom_joinWelcome: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number];
    readonly wasmmlsroom_keyPackage: (a: number) => [number, number, number, number];
    readonly wasmmlsroom_processControl: (a: number, b: number, c: number, d: bigint, e: bigint, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number) => [number, number, number];
    readonly wasmmlsroom_removeMember: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number];
    readonly wasmmlsroom_rollbackOutbound: (a: number, b: number, c: number, d: bigint) => [number, number];
    readonly wasmmlsroom_roomInfo: (a: number) => [number, number, number];
    readonly wasmmlsroom_sealState: (a: number) => [number, number, number, number];
    readonly wasmmlsroominfo_groupId: (a: number) => [number, number];
    readonly wasmmlsroominfo_membershipDigest: (a: number) => [number, number];
    readonly wasmmlsroominfo_roomId: (a: number) => [number, number];
    readonly uniffi_abyssal_core_fn_clone_mlsprocessedcontrol: (a: bigint, b: number) => bigint;
    readonly uniffi_abyssal_core_fn_clone_mlsroom: (a: bigint, b: number) => bigint;
    readonly wasmmlscommit_fromEpoch: (a: number) => bigint;
    readonly wasmmlscommit_revision: (a: number) => bigint;
    readonly wasmmlsencryptedapplication_epoch: (a: number) => bigint;
    readonly wasmmlsencryptedapplication_revision: (a: number) => bigint;
    readonly wasmmlsencryptedapplication_senderIndex: (a: number) => number;
    readonly wasmmlsroominfo_epoch: (a: number) => bigint;
    readonly wasmmlsroominfo_memberCount: (a: number) => number;
    readonly wasmmlsroominfo_revision: (a: number) => bigint;
    readonly ffi_abyssal_core_rust_future_cancel_f64: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_cancel_i16: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_cancel_i32: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_cancel_i64: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_cancel_i8: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_cancel_rust_buffer: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_cancel_u16: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_cancel_u32: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_cancel_u64: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_cancel_u8: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_cancel_void: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_complete_u32: (a: bigint, b: number) => number;
    readonly ffi_abyssal_core_rust_future_complete_u64: (a: bigint, b: number) => bigint;
    readonly __wbg_wasmmlsencryptedapplication_free: (a: number, b: number) => void;
    readonly ffi_abyssal_core_rust_future_free_rust_buffer: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_free_i8: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_free_f64: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_free_u8: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_free_i32: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_free_u32: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_free_i16: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_free_u16: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_free_void: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_free_i64: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_free_u64: (a: bigint) => void;
    readonly wasmmlsencryptedapplication_stateEnvelope: (a: number) => [number, number];
    readonly wasmmlsencryptedapplication_messageId: (a: number) => [number, number];
    readonly wasmmlsencryptedapplication_membershipDigest: (a: number) => [number, number];
    readonly wasmmlsencryptedapplication_groupId: (a: number) => [number, number];
    readonly wasmmlsencryptedapplication_ciphertext: (a: number) => [number, number];
    readonly wasmmlsencryptedapplication_authenticatedData: (a: number) => [number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
