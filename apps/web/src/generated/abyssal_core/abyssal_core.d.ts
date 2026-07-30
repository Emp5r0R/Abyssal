/* tslint:disable */
/* eslint-disable */

export class WasmE2eeSession {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    static create(export_key: Uint8Array): WasmE2eeSession;
    decrypt(chat_id: string, message_id: string, sender_username: string, sender_public_key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, signature: Uint8Array, wrapped_key: Uint8Array, recipient_username: string): Uint8Array;
    encrypt(chat_id: string, message_id: string, sender_username: string, plaintext: Uint8Array, recipients_json: string): string;
    publicKey(): Uint8Array;
    static recover(export_key: Uint8Array, context: Uint8Array, envelope: Uint8Array, expected_public_key: Uint8Array): WasmE2eeSession;
    sealIdentity(export_key: Uint8Array, context: Uint8Array): Uint8Array;
}

export function conversationSafetyNumber(first_public_key: Uint8Array, second_public_key: Uint8Array): string;

export function opaqueClientFinishLogin(password: Uint8Array, login_state: Uint8Array, credential_response: Uint8Array): string;

export function opaqueClientFinishRegistration(password: Uint8Array, registration_state: Uint8Array, registration_response: Uint8Array): string;

export function opaqueClientStart(password: Uint8Array): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_wasme2eesession_free: (a: number, b: number) => void;
    readonly conversationSafetyNumber: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly opaqueClientFinishLogin: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly opaqueClientFinishRegistration: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly opaqueClientStart: (a: number, b: number) => [number, number, number, number];
    readonly uniffi_abyssal_core_checksum_constructor_e2eesession_create: () => number;
    readonly uniffi_abyssal_core_checksum_constructor_e2eesession_recover: () => number;
    readonly uniffi_abyssal_core_checksum_func_conversation_safety_number: () => number;
    readonly uniffi_abyssal_core_checksum_func_opaque_client_finish_login: () => number;
    readonly uniffi_abyssal_core_checksum_func_opaque_client_finish_registration: () => number;
    readonly uniffi_abyssal_core_checksum_func_opaque_client_start: () => number;
    readonly uniffi_abyssal_core_checksum_method_e2eesession_decrypt: () => number;
    readonly uniffi_abyssal_core_checksum_method_e2eesession_encrypt: () => number;
    readonly uniffi_abyssal_core_checksum_method_e2eesession_public_key: () => number;
    readonly uniffi_abyssal_core_checksum_method_e2eesession_seal_identity: () => number;
    readonly uniffi_abyssal_core_fn_clone_e2eesession: (a: number, b: number) => number;
    readonly uniffi_abyssal_core_fn_constructor_e2eesession_create: (a: number, b: number) => number;
    readonly uniffi_abyssal_core_fn_constructor_e2eesession_recover: (a: number, b: number, c: number, d: number, e: number) => number;
    readonly uniffi_abyssal_core_fn_free_e2eesession: (a: number, b: number) => void;
    readonly uniffi_abyssal_core_fn_func_conversation_safety_number: (a: number, b: number, c: number, d: number) => void;
    readonly uniffi_abyssal_core_fn_func_opaque_client_finish_login: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly uniffi_abyssal_core_fn_func_opaque_client_finish_registration: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly uniffi_abyssal_core_fn_func_opaque_client_start: (a: number, b: number, c: number) => void;
    readonly uniffi_abyssal_core_fn_method_e2eesession_decrypt: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => void;
    readonly uniffi_abyssal_core_fn_method_e2eesession_encrypt: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => void;
    readonly uniffi_abyssal_core_fn_method_e2eesession_public_key: (a: number, b: number, c: number) => void;
    readonly uniffi_abyssal_core_fn_method_e2eesession_seal_identity: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly wasme2eesession_create: (a: number, b: number) => [number, number, number];
    readonly wasme2eesession_decrypt: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number, r: number, s: number) => [number, number, number, number];
    readonly wasme2eesession_encrypt: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number) => [number, number, number, number];
    readonly wasme2eesession_publicKey: (a: number) => [number, number];
    readonly wasme2eesession_recover: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly wasme2eesession_sealIdentity: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly ffi_abyssal_core_rust_future_cancel_f32: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_cancel_f64: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_cancel_i16: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_cancel_i32: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_cancel_i64: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_cancel_i8: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_cancel_pointer: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_cancel_rust_buffer: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_cancel_u16: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_cancel_u32: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_cancel_u64: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_cancel_u8: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_cancel_void: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_complete_f32: (a: bigint, b: number) => number;
    readonly ffi_abyssal_core_rust_future_complete_f64: (a: bigint, b: number) => number;
    readonly ffi_abyssal_core_rust_future_complete_i16: (a: bigint, b: number) => number;
    readonly ffi_abyssal_core_rust_future_complete_i32: (a: bigint, b: number) => number;
    readonly ffi_abyssal_core_rust_future_complete_i64: (a: bigint, b: number) => bigint;
    readonly ffi_abyssal_core_rust_future_complete_i8: (a: bigint, b: number) => number;
    readonly ffi_abyssal_core_rust_future_complete_pointer: (a: bigint, b: number) => number;
    readonly ffi_abyssal_core_rust_future_complete_rust_buffer: (a: number, b: bigint, c: number) => void;
    readonly ffi_abyssal_core_rust_future_complete_u16: (a: bigint, b: number) => number;
    readonly ffi_abyssal_core_rust_future_complete_u32: (a: bigint, b: number) => number;
    readonly ffi_abyssal_core_rust_future_complete_u64: (a: bigint, b: number) => bigint;
    readonly ffi_abyssal_core_rust_future_complete_u8: (a: bigint, b: number) => number;
    readonly ffi_abyssal_core_rust_future_complete_void: (a: bigint, b: number) => void;
    readonly ffi_abyssal_core_rust_future_free_f32: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_free_f64: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_free_i16: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_free_i32: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_free_i64: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_free_i8: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_free_pointer: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_free_rust_buffer: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_free_u16: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_free_u32: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_free_u64: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_free_u8: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_free_void: (a: bigint) => void;
    readonly ffi_abyssal_core_rust_future_poll_f32: (a: bigint, b: number, c: bigint) => void;
    readonly ffi_abyssal_core_rust_future_poll_f64: (a: bigint, b: number, c: bigint) => void;
    readonly ffi_abyssal_core_rust_future_poll_i16: (a: bigint, b: number, c: bigint) => void;
    readonly ffi_abyssal_core_rust_future_poll_i32: (a: bigint, b: number, c: bigint) => void;
    readonly ffi_abyssal_core_rust_future_poll_i64: (a: bigint, b: number, c: bigint) => void;
    readonly ffi_abyssal_core_rust_future_poll_i8: (a: bigint, b: number, c: bigint) => void;
    readonly ffi_abyssal_core_rust_future_poll_pointer: (a: bigint, b: number, c: bigint) => void;
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
    readonly uniffi_abyssal_core_checksum_constructor_cryptoengine_new: () => number;
    readonly uniffi_abyssal_core_checksum_constructor_identitymanager_new: () => number;
    readonly uniffi_abyssal_core_checksum_constructor_inmemorystore_new: () => number;
    readonly uniffi_abyssal_core_checksum_constructor_securekey_from_bytes: () => number;
    readonly uniffi_abyssal_core_checksum_method_cryptoengine_decrypt: () => number;
    readonly uniffi_abyssal_core_checksum_method_cryptoengine_derive_shared_secret: () => number;
    readonly uniffi_abyssal_core_checksum_method_cryptoengine_encrypt: () => number;
    readonly uniffi_abyssal_core_checksum_method_identitymanager_generate_username: () => number;
    readonly uniffi_abyssal_core_checksum_method_identitymanager_validate_invite_code: () => number;
    readonly uniffi_abyssal_core_checksum_method_inmemorystore_add_message: () => number;
    readonly uniffi_abyssal_core_checksum_method_inmemorystore_admin_clear_all_data: () => number;
    readonly uniffi_abyssal_core_checksum_method_inmemorystore_get_messages: () => number;
    readonly uniffi_abyssal_core_checksum_method_inmemorystore_mark_as_read: () => number;
    readonly uniffi_abyssal_core_checksum_method_inmemorystore_purge_expired_messages: () => number;
    readonly uniffi_abyssal_core_fn_clone_cryptoengine: (a: number, b: number) => number;
    readonly uniffi_abyssal_core_fn_constructor_cryptoengine_new: (a: number) => number;
    readonly uniffi_abyssal_core_fn_constructor_identitymanager_new: (a: number) => number;
    readonly uniffi_abyssal_core_fn_constructor_inmemorystore_new: (a: number) => number;
    readonly uniffi_abyssal_core_fn_constructor_securekey_from_bytes: (a: number, b: number) => number;
    readonly uniffi_abyssal_core_fn_free_cryptoengine: (a: number, b: number) => void;
    readonly uniffi_abyssal_core_fn_free_identitymanager: (a: number, b: number) => void;
    readonly uniffi_abyssal_core_fn_free_inmemorystore: (a: number, b: number) => void;
    readonly uniffi_abyssal_core_fn_free_securekey: (a: number, b: number) => void;
    readonly uniffi_abyssal_core_fn_method_cryptoengine_decrypt: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly uniffi_abyssal_core_fn_method_cryptoengine_derive_shared_secret: (a: number, b: number, c: number, d: number) => number;
    readonly uniffi_abyssal_core_fn_method_cryptoengine_encrypt: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly uniffi_abyssal_core_fn_method_identitymanager_generate_username: (a: number, b: number, c: number) => void;
    readonly uniffi_abyssal_core_fn_method_identitymanager_validate_invite_code: (a: number, b: number, c: number) => number;
    readonly uniffi_abyssal_core_fn_method_inmemorystore_add_message: (a: number, b: number, c: number, d: number) => void;
    readonly uniffi_abyssal_core_fn_method_inmemorystore_admin_clear_all_data: (a: number, b: number) => void;
    readonly uniffi_abyssal_core_fn_method_inmemorystore_get_messages: (a: number, b: number, c: number, d: number) => void;
    readonly uniffi_abyssal_core_fn_method_inmemorystore_mark_as_read: (a: number, b: number, c: number, d: bigint, e: number) => void;
    readonly uniffi_abyssal_core_fn_method_inmemorystore_purge_expired_messages: (a: number, b: bigint, c: number) => void;
    readonly uniffi_abyssal_core_fn_clone_identitymanager: (a: number, b: number) => number;
    readonly uniffi_abyssal_core_fn_clone_inmemorystore: (a: number, b: number) => number;
    readonly uniffi_abyssal_core_fn_clone_securekey: (a: number, b: number) => number;
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
