use crate::AbyssalError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, AeadCore, Payload},
    ChaCha20Poly1305, KeyInit, Nonce, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use opaque_ke::argon2::Argon2;
use opaque_ke::rand::{rngs::OsRng, RngCore};
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, RegistrationRequest, RegistrationResponse, RegistrationUpload, ServerLogin,
    ServerLoginParameters, ServerRegistration, ServerSetup,
};
use sha2::{Digest, Sha256};
use sha2_legacy::Sha512;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard,
    },
};
use vodozemac::{
    olm::{Account, AccountPickle, OlmMessage, Session, SessionConfig, SessionPickle},
    Curve25519PublicKey, Curve25519SecretKey, Ed25519PublicKey, Ed25519Signature,
};
use zeroize::{Zeroize, Zeroizing};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
use crate::mls_protocol::WasmMlsRoom;

const IDENTITY_FINGERPRINT_BYTES: usize = 64;
const ONE_TIME_KEY_BYTES: usize = 32;
pub const PREKEY_POOL_SIZE_V9: usize = 16;
const ONE_TIME_KEY_OFFSET: usize = IDENTITY_FINGERPRINT_BYTES;
const FALLBACK_KEY_OFFSET: usize = ONE_TIME_KEY_OFFSET + (PREKEY_POOL_SIZE_V9 * ONE_TIME_KEY_BYTES);
const IDENTITY_PUBLIC_BYTES: usize = FALLBACK_KEY_OFFSET + 32;
const NONCE_BYTES: usize = 12;
const MAX_CONTEXT_BYTES: usize = 512;
const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
const PAYLOAD_FORMAT_VERSION: u8 = 1;
const PAYLOAD_HEADER_BYTES: usize = 1 + 4;
const PAYLOAD_PADDING_BUCKET_BYTES: usize = 256;
const PAYLOAD_TAG_BYTES: usize = 16;
const MAX_PADDED_PAYLOAD_BYTES: usize = (MAX_PAYLOAD_BYTES + PAYLOAD_HEADER_BYTES)
    .div_ceil(PAYLOAD_PADDING_BUCKET_BYTES)
    * PAYLOAD_PADDING_BUCKET_BYTES;
const MAX_PAYLOAD_CIPHERTEXT_BYTES: usize = MAX_PADDED_PAYLOAD_BYTES + PAYLOAD_TAG_BYTES;
const IMAGE_ATTACHMENT_LIMIT_BYTES: usize = 20 * 1024 * 1024;
const VIDEO_ATTACHMENT_LIMIT_BYTES: usize = 100 * 1024 * 1024;
const MAX_ATTACHMENT_PLAINTEXT_BYTES: usize = 200 * 1024 * 1024;
const ATTACHMENT_BLOB_VERSION: u8 = 1;
const ATTACHMENT_NONCE_BYTES: usize = 24;
const ATTACHMENT_KEY_BYTES: usize = 32;
const ATTACHMENT_TAG_BYTES: usize = 16;
const ATTACHMENT_BLOB_HEADER_BYTES: usize = 1 + ATTACHMENT_NONCE_BYTES;
const MAX_ATTACHMENT_BLOB_BYTES: usize =
    ATTACHMENT_BLOB_HEADER_BYTES + MAX_ATTACHMENT_PLAINTEXT_BYTES + ATTACHMENT_TAG_BYTES;
const MAX_IDENTITY_STATE_BYTES: usize = 512 * 1024;
const MAX_RATCHET_ENVELOPE_BYTES: usize = 4096;
const MAX_PEERS: usize = 256;
const MAX_SESSIONS_PER_PEER: usize = 4;
const IDENTITY_STATE_SIGNATURE_BYTES: usize = 64;
const REGISTRATION_CHALLENGE_BYTES: usize = 32;
const PROTOCOL_VERSION: u32 = 9;
const IDENTITY_ENVELOPE_VERSION: u8 = 5;
const KEY_VALIDATION_SCALAR: [u8; 32] = [0x42; 32];
const MLS_ROOT_DOMAIN: &[u8] = b"ABYSSAL-MLS-V10-ACCOUNT-ROOT";

pub struct AbyssalOpaqueSuite;

impl CipherSuite for AbyssalOpaqueSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, Sha512>;
    type Ksf = Argon2<'static>;
}

// UniFFI lowers records by moving their fields, so a record-level Drop
// implementation is incompatible with the generated converter (E0509).
// Sensitive OPAQUE result material is therefore wiped before copying into
// these FFI records, and each client wipes the returned byte arrays after use.
#[derive(serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct OpaqueClientStart {
    pub registration_state: Vec<u8>,
    pub registration_request: Vec<u8>,
    pub login_state: Vec<u8>,
    pub credential_request: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct OpaqueRegistrationFinish {
    pub registration_upload: Vec<u8>,
    pub export_key: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct OpaqueLoginFinish {
    pub credential_finalization: Vec<u8>,
    pub export_key: Vec<u8>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct RecipientPublicKey {
    pub username: String,
    pub public_key: Vec<u8>,
    pub prekey_id: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct RecipientEnvelope {
    pub username: String,
    pub wrapped_key: Vec<u8>,
    pub prekey_id: String,
    pub is_prekey: bool,
    pub signature: Vec<u8>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct E2eePayload {
    pub version: u32,
    pub message_id: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub envelopes: Vec<RecipientEnvelope>,
    pub state_revision: u64,
    pub identity_envelope: Vec<u8>,
    pub identity_public: Vec<u8>,
    pub prekey_id: String,
    pub state_signature: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct E2eeDecryption {
    pub plaintext: Vec<u8>,
    pub state_revision: u64,
    pub identity_envelope: Vec<u8>,
    pub identity_public: Vec<u8>,
    pub prekey_id: String,
    pub state_signature: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct AttachmentCiphertext {
    pub version: u32,
    pub key: Vec<u8>,
    pub blob: Vec<u8>,
}

pub const REGISTRATION_CHALLENGE_BYTES_V9: usize = REGISTRATION_CHALLENGE_BYTES;
pub const IDENTITY_PUBLIC_BYTES_V9: usize = IDENTITY_PUBLIC_BYTES;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct StoredPrekey {
    id: String,
    public: [u8; ONE_TIME_KEY_BYTES],
}

#[derive(serde::Deserialize)]
struct AccountMaterialView {
    one_time_keys: OneTimeKeyMaterialView,
}

#[derive(serde::Deserialize)]
struct OneTimeKeyMaterialView {
    private_keys: BTreeMap<String, Curve25519SecretKey>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredPeerSessions {
    peer: String,
    sessions: Vec<SessionPickle>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredE2eeState {
    revision: u64,
    fallback_public: [u8; 32],
    prekeys: Vec<StoredPrekey>,
    account: AccountPickle,
    peers: Vec<StoredPeerSessions>,
    session_prekeys: HashMap<String, String>,
}

/// A serialized pre-send snapshot. The owned serialized bytes are wiped when
/// the transaction finishes. Temporary pickle/serde values used to create or
/// restore the snapshot are short-lived but cannot be guaranteed zeroized by
/// this crate because their fields are owned by vodozemac/serde.
struct PendingOutbound {
    message_id: String,
    revision: u64,
    checkpoint: Zeroizing<Vec<u8>>,
}

struct E2eeState {
    revision: u64,
    fallback_public: [u8; 32],
    prekeys: Vec<StoredPrekey>,
    account: Account,
    sessions: HashMap<String, Vec<Session>>,
    session_prekeys: HashMap<String, String>,
    pending_outbound: Option<PendingOutbound>,
}

struct SealingMaterial {
    key: [u8; 32],
    context: Vec<u8>,
}

pub(crate) struct AccountLifetime {
    revoked: AtomicBool,
    gate: RwLock<()>,
}

impl AccountLifetime {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            revoked: AtomicBool::new(false),
            gate: RwLock::new(()),
        })
    }

    pub(crate) fn revoke(&self) {
        match self.gate.write() {
            Ok(_guard) => self.revoked.store(true, Ordering::Release),
            Err(_) => self.revoked.store(true, Ordering::Release),
        }
    }

    pub(crate) fn operation(&self) -> Result<RwLockReadGuard<'_, ()>, ()> {
        let guard = self.gate.read().map_err(|_| ())?;
        if self.revoked.load(Ordering::Acquire) {
            return Err(());
        }
        Ok(guard)
    }
}

impl Drop for SealingMaterial {
    fn drop(&mut self) {
        self.key.zeroize();
        self.context.zeroize();
    }
}

#[derive(uniffi::Object)]
pub struct E2eeSession {
    state: Mutex<E2eeState>,
    sealing: Mutex<Option<SealingMaterial>>,
    mls_root: Zeroizing<[u8; 32]>,
    account_lifetime: Arc<AccountLifetime>,
}

#[uniffi::export]
pub fn opaque_client_start(password: Vec<u8>) -> Result<OpaqueClientStart, AbyssalError> {
    let password = Zeroizing::new(password);
    validate_password_bytes(&password).map_err(AbyssalError::from)?;
    let mut rng = OsRng;
    let registration = ClientRegistration::<AbyssalOpaqueSuite>::start(&mut rng, &password)
        .map_err(|error| AbyssalError::from(protocol_error(error)))?;
    let login = ClientLogin::<AbyssalOpaqueSuite>::start(&mut rng, &password)
        .map_err(|error| AbyssalError::from(protocol_error(error)))?;
    Ok(OpaqueClientStart {
        registration_state: registration.state.serialize().to_vec(),
        registration_request: registration.message.serialize().to_vec(),
        login_state: login.state.serialize().to_vec(),
        credential_request: login.message.serialize().to_vec(),
    })
}

#[uniffi::export]
pub fn opaque_client_finish_registration(
    password: Vec<u8>,
    registration_state: Vec<u8>,
    registration_response: Vec<u8>,
) -> Result<OpaqueRegistrationFinish, AbyssalError> {
    let password = Zeroizing::new(password);
    let registration_state = Zeroizing::new(registration_state);
    validate_password_bytes(&password).map_err(AbyssalError::from)?;
    let state = ClientRegistration::<AbyssalOpaqueSuite>::deserialize(&registration_state)
        .map_err(|error| AbyssalError::from(protocol_error(error)))?;
    let response = RegistrationResponse::<AbyssalOpaqueSuite>::deserialize(&registration_response)
        .map_err(|error| AbyssalError::from(protocol_error(error)))?;
    let mut rng = OsRng;
    let mut result = state
        .finish(
            &mut rng,
            &password,
            response,
            ClientRegistrationFinishParameters::default(),
        )
        .map_err(|error| AbyssalError::from(protocol_error(error)))?;
    let registration_upload = result.message.serialize().to_vec();
    let export_key = result.export_key.to_vec();
    result.export_key.zeroize();
    Ok(OpaqueRegistrationFinish {
        registration_upload,
        export_key,
    })
}

#[uniffi::export]
pub fn opaque_client_finish_login(
    password: Vec<u8>,
    login_state: Vec<u8>,
    credential_response: Vec<u8>,
) -> Result<OpaqueLoginFinish, AbyssalError> {
    let password = Zeroizing::new(password);
    let login_state = Zeroizing::new(login_state);
    validate_password_bytes(&password).map_err(AbyssalError::from)?;
    let state = ClientLogin::<AbyssalOpaqueSuite>::deserialize(&login_state)
        .map_err(|error| AbyssalError::from(protocol_error(error)))?;
    let response = CredentialResponse::<AbyssalOpaqueSuite>::deserialize(&credential_response)
        .map_err(|error| AbyssalError::from(protocol_error(error)))?;
    let mut rng = OsRng;
    let mut result = state
        .finish(
            &mut rng,
            &password,
            response,
            ClientLoginFinishParameters::default(),
        )
        .map_err(|error| AbyssalError::from(protocol_error(error)))?;
    let credential_finalization = result.message.serialize().to_vec();
    let export_key = result.export_key.to_vec();
    result.export_key.zeroize();
    result.session_key.zeroize();
    Ok(OpaqueLoginFinish {
        credential_finalization,
        export_key,
    })
}

#[uniffi::export]
pub fn conversation_safety_number(
    first_public_key: Vec<u8>,
    second_public_key: Vec<u8>,
) -> Result<String, AbyssalError> {
    validate_identity_public_bundle(&first_public_key, None).map_err(AbyssalError::from)?;
    validate_identity_public_bundle(&second_public_key, None).map_err(AbyssalError::from)?;
    let first_identity = &first_public_key[..IDENTITY_FINGERPRINT_BYTES];
    let second_identity = &second_public_key[..IDENTITY_FINGERPRINT_BYTES];
    let (first, second) = if first_identity <= second_identity {
        (first_identity, second_identity)
    } else {
        (second_identity, first_identity)
    };
    let mut hasher = Sha256::new();
    hasher.update(b"ABYSSAL_SAFETY_NUMBER_V2");
    hasher.update(first);
    hasher.update(second);
    let digest = hasher.finalize();
    let compact = digest[..10]
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    Ok(compact
        .as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join(" "))
}

/// Canonical out-of-band verification token for one direct conversation.
///
/// Both participants derive the same token locally. The transcript binds the
/// relay process identity, direct-chat identifier, canonical usernames, and
/// stable long-term identity keys. One-time prekeys are deliberately excluded
/// so routine prekey rotation does not invalidate a completed comparison.
#[uniffi::export]
pub fn conversation_verification_token(
    node_id: String,
    chat_id: String,
    first_username: String,
    first_public_key: Vec<u8>,
    second_username: String,
    second_public_key: Vec<u8>,
) -> Result<String, AbyssalError> {
    if !valid_node_identifier(&node_id) || !valid_context_identifier(&chat_id) {
        return Err("Verification unavailable".to_string().into());
    }
    validate_username(&first_username).map_err(AbyssalError::from)?;
    validate_username(&second_username).map_err(AbyssalError::from)?;
    validate_identity_public_bundle(&first_public_key, None).map_err(AbyssalError::from)?;
    validate_identity_public_bundle(&second_public_key, None).map_err(AbyssalError::from)?;

    let first_name = first_username.to_ascii_lowercase();
    let second_name = second_username.to_ascii_lowercase();
    if first_name == second_name {
        return Err("Verification unavailable".to_string().into());
    }
    let first_identity = &first_public_key[..IDENTITY_FINGERPRINT_BYTES];
    let second_identity = &second_public_key[..IDENTITY_FINGERPRINT_BYTES];
    let ((first_name, first_identity), (second_name, second_identity)) =
        if (first_name.as_bytes(), first_identity) <= (second_name.as_bytes(), second_identity) {
            (
                (first_name.as_str(), first_identity),
                (second_name.as_str(), second_identity),
            )
        } else {
            (
                (second_name.as_str(), second_identity),
                (first_name.as_str(), first_identity),
            )
        };

    let mut hasher = Sha256::new();
    hasher.update(b"ABYSSAL_DIRECT_VERIFICATION_V1");
    update_length_delimited(&mut hasher, node_id.as_bytes())?;
    update_length_delimited(&mut hasher, chat_id.as_bytes())?;
    update_length_delimited(&mut hasher, first_name.as_bytes())?;
    update_length_delimited(&mut hasher, first_identity)?;
    update_length_delimited(&mut hasher, second_name.as_bytes())?;
    update_length_delimited(&mut hasher, second_identity)?;
    Ok(format!(
        "abyssal:verify:v1:{}",
        URL_SAFE_NO_PAD.encode(hasher.finalize())
    ))
}

fn update_length_delimited(hasher: &mut Sha256, value: &[u8]) -> Result<(), AbyssalError> {
    let length = u32::try_from(value.len())
        .map_err(|_| AbyssalError::from("Verification unavailable".to_string()))?;
    hasher.update(length.to_be_bytes());
    hasher.update(value);
    Ok(())
}

#[uniffi::export]
pub fn encrypt_attachment(
    chat_id: String,
    message_id: String,
    sender_username: String,
    media_type: String,
    plaintext: Vec<u8>,
) -> Result<AttachmentCiphertext, AbyssalError> {
    let plaintext = Zeroizing::new(plaintext);
    validate_attachment_context(&chat_id, &message_id, &sender_username, &media_type)
        .map_err(AbyssalError::from)?;
    let plaintext_limit = attachment_plaintext_limit(&media_type).map_err(AbyssalError::from)?;
    if plaintext.is_empty() || plaintext.len() > plaintext_limit {
        return Err("Payload unavailable".to_string().into());
    }
    let aad = attachment_aad(&chat_id, &message_id, &sender_username, &media_type);
    let mut key = Zeroizing::new([0_u8; ATTACHMENT_KEY_BYTES]);
    let mut nonce = [0_u8; ATTACHMENT_NONCE_BYTES];
    OsRng.fill_bytes(key.as_mut());
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| "Payload unavailable".to_string())?;
    let ciphertext = match cipher.encrypt(
        XNonce::from_slice(&nonce),
        Payload {
            msg: &plaintext,
            aad: &aad,
        },
    ) {
        Ok(ciphertext) => ciphertext,
        Err(_) => {
            return Err("Payload unavailable".to_string().into());
        }
    };
    let mut blob = Vec::with_capacity(ATTACHMENT_BLOB_HEADER_BYTES + ciphertext.len());
    blob.push(ATTACHMENT_BLOB_VERSION);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(AttachmentCiphertext {
        version: u32::from(ATTACHMENT_BLOB_VERSION),
        key: key.to_vec(),
        blob,
    })
}

#[uniffi::export]
pub fn decrypt_attachment(
    chat_id: String,
    message_id: String,
    sender_username: String,
    media_type: String,
    key: Vec<u8>,
    blob: Vec<u8>,
) -> Result<Vec<u8>, AbyssalError> {
    let key = Zeroizing::new(key);
    let blob = Zeroizing::new(blob);
    validate_attachment_context(&chat_id, &message_id, &sender_username, &media_type)
        .map_err(AbyssalError::from)?;
    let blob_limit = attachment_blob_limit(&media_type);
    if key.len() != ATTACHMENT_KEY_BYTES
        || blob.len() < ATTACHMENT_BLOB_HEADER_BYTES + ATTACHMENT_TAG_BYTES
        || blob.len() > blob_limit
        || blob.first() != Some(&ATTACHMENT_BLOB_VERSION)
    {
        return Err("Payload unavailable".to_string().into());
    }
    let aad = attachment_aad(&chat_id, &message_id, &sender_username, &media_type);
    let cipher =
        XChaCha20Poly1305::new_from_slice(&key).map_err(|_| "Payload unavailable".to_string())?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&blob[1..ATTACHMENT_BLOB_HEADER_BYTES]),
            Payload {
                msg: &blob[ATTACHMENT_BLOB_HEADER_BYTES..],
                aad: &aad,
            },
        )
        .map_err(|_| "Payload unavailable".to_string());
    let plaintext = Zeroizing::new(plaintext?);
    let plaintext_limit = attachment_plaintext_limit(&media_type).map_err(AbyssalError::from)?;
    if plaintext.is_empty() || plaintext.len() > plaintext_limit {
        return Err("Payload unavailable".to_string().into());
    }
    Ok(plaintext.to_vec())
}

pub fn opaque_server_setup() -> Vec<u8> {
    ServerSetup::<AbyssalOpaqueSuite>::new(&mut OsRng)
        .serialize()
        .to_vec()
}

pub fn opaque_server_registration_response(
    setup: &[u8],
    request: &[u8],
    credential_identifier: &[u8],
) -> Result<Vec<u8>, String> {
    validate_identifier(credential_identifier)?;
    let setup = ServerSetup::<AbyssalOpaqueSuite>::deserialize(setup).map_err(protocol_error)?;
    let request =
        RegistrationRequest::<AbyssalOpaqueSuite>::deserialize(request).map_err(protocol_error)?;
    let result =
        ServerRegistration::<AbyssalOpaqueSuite>::start(&setup, request, credential_identifier)
            .map_err(protocol_error)?;
    Ok(result.message.serialize().to_vec())
}

pub fn opaque_server_finish_registration(upload: &[u8]) -> Result<Vec<u8>, String> {
    let upload =
        RegistrationUpload::<AbyssalOpaqueSuite>::deserialize(upload).map_err(protocol_error)?;
    Ok(ServerRegistration::<AbyssalOpaqueSuite>::finish(upload)
        .serialize()
        .to_vec())
}

pub fn opaque_server_start_login(
    setup: &[u8],
    password_file: &[u8],
    request: &[u8],
    credential_identifier: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    validate_identifier(credential_identifier)?;
    let setup = ServerSetup::<AbyssalOpaqueSuite>::deserialize(setup).map_err(protocol_error)?;
    let password_file = ServerRegistration::<AbyssalOpaqueSuite>::deserialize(password_file)
        .map_err(protocol_error)?;
    let request =
        CredentialRequest::<AbyssalOpaqueSuite>::deserialize(request).map_err(protocol_error)?;
    let result = ServerLogin::<AbyssalOpaqueSuite>::start(
        &mut OsRng,
        &setup,
        Some(password_file),
        request,
        credential_identifier,
        ServerLoginParameters::default(),
    )
    .map_err(protocol_error)?;
    Ok((
        result.state.serialize().to_vec(),
        result.message.serialize().to_vec(),
    ))
}

pub fn opaque_server_finish_login(state: &[u8], finalization: &[u8]) -> Result<(), String> {
    let state = ServerLogin::<AbyssalOpaqueSuite>::deserialize(state).map_err(protocol_error)?;
    let finalization = CredentialFinalization::<AbyssalOpaqueSuite>::deserialize(finalization)
        .map_err(protocol_error)?;
    let mut result = state
        .finish(finalization, ServerLoginParameters::default())
        .map_err(protocol_error)?;
    result.session_key.zeroize();
    Ok(())
}

#[uniffi::export]
impl E2eeSession {
    #[uniffi::constructor]
    pub fn create(export_key: Vec<u8>) -> Result<Arc<Self>, AbyssalError> {
        let export_key = Zeroizing::new(export_key);
        validate_export_key(&export_key)?;
        let mls_root = derive_mls_root(&export_key).map_err(AbyssalError::from)?;
        let mut account = Account::new();
        account.generate_fallback_key();
        account.generate_one_time_keys(PREKEY_POOL_SIZE_V9);
        let prekeys = canonical_prekeys(&account).map_err(AbyssalError::from)?;
        let fallback_public = account
            .fallback_key()
            .into_values()
            .next()
            .ok_or_else(|| AbyssalError::from("Identity unavailable".to_string()))?
            .to_bytes();
        account.mark_keys_as_published();
        Ok(Arc::new(Self {
            state: Mutex::new(E2eeState {
                revision: 0,
                fallback_public,
                prekeys,
                account,
                sessions: HashMap::new(),
                session_prekeys: HashMap::new(),
                pending_outbound: None,
            }),
            sealing: Mutex::new(None),
            mls_root,
            account_lifetime: AccountLifetime::new(),
        }))
    }

    #[uniffi::constructor]
    pub fn recover(
        export_key: Vec<u8>,
        context: Vec<u8>,
        envelope: Vec<u8>,
        expected_public_key: Vec<u8>,
    ) -> Result<Arc<Self>, AbyssalError> {
        let export_key = Zeroizing::new(export_key);
        validate_export_key(&export_key)?;
        let mls_root = derive_mls_root(&export_key).map_err(AbyssalError::from)?;
        validate_context(&context)?;
        if envelope.len() <= 1 + NONCE_BYTES
            || envelope.len() > MAX_IDENTITY_STATE_BYTES
            || envelope.first() != Some(&IDENTITY_ENVELOPE_VERSION)
        {
            return Err("Identity unavailable".to_string().into());
        }
        let key = Zeroizing::new(identity_wrap_key(&export_key, &context)?);
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| "Identity unavailable".to_string())?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&envelope[1..1 + NONCE_BYTES]),
                    Payload {
                        msg: &envelope[1 + NONCE_BYTES..],
                        aad: &context,
                    },
                )
                .map_err(|_| "Identity unavailable".to_string())?,
        );
        if plain.len() > MAX_IDENTITY_STATE_BYTES {
            return Err("Identity unavailable".to_string().into());
        }
        let stored: StoredE2eeState = serde_json::from_slice(&plain)
            .map_err(|_| AbyssalError::from("Identity unavailable".to_string()))?;
        if stored.peers.len() > MAX_PEERS {
            return Err("Identity unavailable".to_string().into());
        }
        validate_prekey_pool(&stored.prekeys).map_err(AbyssalError::from)?;
        validate_account_prekey_material(&stored.account, &stored.prekeys)
            .map_err(AbyssalError::from)?;
        let mut sessions = HashMap::with_capacity(stored.peers.len());
        let mut session_ids = HashSet::new();
        for peer in stored.peers {
            validate_username(&peer.peer)?;
            if peer.sessions.is_empty() || peer.sessions.len() > MAX_SESSIONS_PER_PEER {
                return Err("Identity unavailable".to_string().into());
            }
            let peer_key = peer_key(&peer.peer);
            let peer_sessions = peer
                .sessions
                .into_iter()
                .map(Session::from_pickle)
                .collect::<Vec<_>>();
            if peer_sessions
                .iter()
                .any(|session| !session_ids.insert(session.session_id()))
                || sessions.insert(peer_key, peer_sessions).is_some()
            {
                return Err("Identity unavailable".to_string().into());
            }
        }
        if stored.session_prekeys.len() != session_ids.len()
            || stored
                .session_prekeys
                .iter()
                .any(|(session_id, prekey_id)| {
                    !session_ids.contains(session_id)
                        || prekey_id.is_empty()
                        || prekey_id.len() > 32
                        || !prekey_id.is_ascii()
                        || !prekey_id.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
                        })
                })
        {
            return Err("Identity unavailable".to_string().into());
        }
        let session = Arc::new(Self {
            state: Mutex::new(E2eeState {
                revision: stored.revision,
                fallback_public: stored.fallback_public,
                prekeys: stored.prekeys,
                account: Account::from_pickle(stored.account),
                sessions,
                session_prekeys: stored.session_prekeys,
                pending_outbound: None,
            }),
            sealing: Mutex::new(Some(SealingMaterial { key: *key, context })),
            mls_root,
            account_lifetime: AccountLifetime::new(),
        });
        let actual_public_key = session.public_key();
        validate_identity_public_bundle(&actual_public_key, Some(&session.prekey_id()))
            .map_err(AbyssalError::from)?;
        if !constant_time_eq(&actual_public_key, &expected_public_key) {
            return Err("Identity unavailable".to_string().into());
        }
        Ok(session)
    }

    /// Create an account-scoped MLS room. MLS identity material is derived
    /// and signed here so no root, stable private key, or detached credential
    /// proof crosses the public API.
    #[allow(clippy::too_many_arguments)]
    pub fn create_mls_room(
        &self,
        room_id: String,
        username: String,
        node_context: Vec<u8>,
        group_id: Vec<u8>,
    ) -> Result<Arc<crate::mls_protocol::MlsRoom>, AbyssalError> {
        let (stable, proof) = self.mls_material(&room_id, &username, &node_context, &group_id)?;
        crate::mls_protocol::MlsRoom::create_from_account(
            &self.mls_root,
            self.account_lifetime.clone(),
            room_id,
            username,
            node_context,
            stable.to_vec(),
            proof,
            group_id,
        )
    }

    /// Recover an account-scoped MLS room from its authenticated state.
    #[allow(clippy::too_many_arguments)]
    pub fn recover_mls_room(
        &self,
        room_id: String,
        username: String,
        node_context: Vec<u8>,
        group_id: Vec<u8>,
        envelope: Vec<u8>,
        expected_active: bool,
        expected_epoch: u64,
        expected_revision: u64,
        expected_members: Vec<crate::mls_protocol::MlsRosterMember>,
        expected_digest: Vec<u8>,
    ) -> Result<Arc<crate::mls_protocol::MlsRoom>, AbyssalError> {
        let (stable, proof) = self.mls_material(&room_id, &username, &node_context, &group_id)?;
        crate::mls_protocol::MlsRoom::recover_from_account(
            &self.mls_root,
            self.account_lifetime.clone(),
            room_id,
            username,
            node_context,
            stable.to_vec(),
            proof,
            group_id,
            envelope,
            expected_active,
            expected_epoch,
            expected_revision,
            expected_members,
            expected_digest,
        )
    }

    /// Create a pending account-scoped MLS join room.
    pub fn pending_mls_join(
        &self,
        room_id: String,
        username: String,
        node_context: Vec<u8>,
        group_id: Vec<u8>,
    ) -> Result<Arc<crate::mls_protocol::MlsRoom>, AbyssalError> {
        let (stable, proof) = self.mls_material(&room_id, &username, &node_context, &group_id)?;
        crate::mls_protocol::MlsRoom::pending_from_account(
            &self.mls_root,
            self.account_lifetime.clone(),
            room_id,
            username,
            node_context,
            stable.to_vec(),
            proof,
            group_id,
        )
    }

    pub fn public_key(&self) -> Vec<u8> {
        let Ok(state) = self.state.lock() else {
            return Vec::new();
        };
        let identity = state.account.identity_keys();
        let mut result = Vec::with_capacity(IDENTITY_PUBLIC_BYTES);
        result.extend_from_slice(identity.curve25519.as_bytes());
        result.extend_from_slice(identity.ed25519.as_bytes());
        for prekey in &state.prekeys {
            result.extend_from_slice(&prekey.public);
        }
        result.extend_from_slice(&state.fallback_public);
        result
    }

    pub fn prekey_id(&self) -> String {
        let Ok(state) = self.state.lock() else {
            return String::new();
        };
        state
            .prekeys
            .first()
            .map_or_else(String::new, |key| key.id.clone())
    }

    /// Returns whether the next outbound message to `peer` must use an
    /// authenticated leased prekey. Established reciprocal sessions do not
    /// require a lease.
    pub fn requires_prekey(&self, peer: String) -> Result<bool, AbyssalError> {
        validate_username(&peer)?;
        let state = lock(&self.state, "Identity unavailable")?;
        if state.pending_outbound.is_some() {
            return Err("Identity unavailable".to_string().into());
        }
        Ok(state
            .sessions
            .get(&peer_key(&peer))
            .and_then(|sessions| sessions.last())
            .is_none_or(|session| !session.has_received_message()))
    }

    /// Sign an acknowledgement as an independent action proof.
    ///
    /// The transcript contains only the protocol domain/version, conversation,
    /// message, original sender, and the prekey consumed by that message. It
    /// deliberately does not include the recipient's ratchet revision or
    /// identity-state signature so a duplicate delivery can be acknowledged
    /// after the state has advanced.
    pub fn sign_acknowledgement(
        &self,
        chat_id: String,
        message_id: String,
        original_sender_username: String,
        used_prekey_id: String,
    ) -> Result<Vec<u8>, AbyssalError> {
        let state = lock(&self.state, "Identity unavailable")?;
        sign_ack_signature_v9(
            PROTOCOL_VERSION,
            &chat_id,
            &message_id,
            &original_sender_username,
            &used_prekey_id,
            &state.account,
        )
        .map_err(AbyssalError::from)
    }

    /// Prove possession of the Ed25519 identity key during account creation.
    ///
    /// The server-issued challenge and every registration input are bound into
    /// one canonical transcript.  This prevents registering a copied public
    /// identity without also controlling its private key.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_registration_identity_proof(
        &self,
        node_id: String,
        handshake_id: String,
        challenge: Vec<u8>,
        registration_upload: Vec<u8>,
        identity_public: Vec<u8>,
        prekey_id: String,
        identity_envelope: Vec<u8>,
    ) -> Result<Vec<u8>, AbyssalError> {
        let transcript = registration_identity_proof_input_v9(
            &node_id,
            &handshake_id,
            &challenge,
            &registration_upload,
            &identity_public,
            &prekey_id,
            &identity_envelope,
        )
        .map_err(AbyssalError::from)?;
        let state = lock(&self.state, "Identity unavailable")?;
        Ok(state.account.sign(&transcript).to_bytes().to_vec())
    }

    pub fn seal_identity(
        &self,
        export_key: Vec<u8>,
        context: Vec<u8>,
    ) -> Result<Vec<u8>, AbyssalError> {
        let export_key = Zeroizing::new(export_key);
        validate_export_key(&export_key)?;
        validate_context(&context)?;
        let key = Zeroizing::new(identity_wrap_key(&export_key, &context)?);
        let mut sealing = lock(&self.sealing, "Identity unavailable")?;
        let state = lock(&self.state, "Identity unavailable")?;
        if state.pending_outbound.is_some() {
            return Err("Identity unavailable".to_string().into());
        }
        *sealing = Some(SealingMaterial { key: *key, context });
        let sealing = sealing
            .as_ref()
            .ok_or_else(|| AbyssalError::from("Identity unavailable".to_string()))?;
        seal_state(&state, sealing).map_err(AbyssalError::from)
    }

    pub fn encrypt(
        &self,
        chat_id: String,
        message_id: String,
        sender_username: String,
        plaintext: Vec<u8>,
        recipients: Vec<RecipientPublicKey>,
    ) -> Result<E2eePayload, AbyssalError> {
        let plaintext = Zeroizing::new(plaintext);
        validate_message_context(&chat_id, &message_id, &sender_username)?;
        if plaintext.is_empty() || plaintext.len() > MAX_PAYLOAD_BYTES {
            return Err("Payload unavailable".to_string().into());
        }
        if recipients.is_empty() || recipients.len() > MAX_PEERS {
            return Err("Recipient unavailable".to_string().into());
        }
        let mut seen = HashSet::with_capacity(recipients.len());
        for recipient in &recipients {
            validate_username(&recipient.username)?;
            if validate_identity_public_bundle(&recipient.public_key, Some(&recipient.prekey_id))
                .is_err()
                || !seen.insert(peer_key(&recipient.username))
            {
                return Err("Recipient unavailable".to_string().into());
            }
        }
        let aad = message_aad(&chat_id, &message_id, &sender_username);
        let content_key: Zeroizing<[u8; 32]> =
            Zeroizing::new(ChaCha20Poly1305::generate_key(&mut OsRng).into());
        let nonce: [u8; NONCE_BYTES] = ChaCha20Poly1305::generate_nonce(&mut OsRng).into();
        let cipher = ChaCha20Poly1305::new_from_slice(content_key.as_ref())
            .map_err(|_| "Payload unavailable".to_string())?;
        let padded_plaintext = pad_payload(&plaintext).map_err(AbyssalError::from)?;
        let ciphertext_result = cipher.encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &padded_plaintext,
                aad: &aad,
            },
        );
        drop(plaintext);
        drop(padded_plaintext);
        let ciphertext = ciphertext_result.map_err(|_| "Payload unavailable".to_string())?;

        let sealing = lock(&self.sealing, "Identity unavailable")?;
        let sealing = sealing
            .as_ref()
            .ok_or_else(|| AbyssalError::from("Identity unavailable".to_string()))?;
        let mut state = lock(&self.state, "Identity unavailable")?;
        let outbound_revision =
            begin_outbound(&mut state, &message_id).map_err(AbyssalError::from)?;
        let result = (|| -> Result<E2eePayload, AbyssalError> {
            let mut envelopes = Vec::with_capacity(recipients.len());
            for recipient in recipients {
                let wrapped_key = ratchet_wrap_content_key(
                    &mut state,
                    &content_key,
                    &recipient.public_key,
                    &aad,
                    &recipient.username,
                    &recipient.prekey_id,
                )
                .map_err(AbyssalError::from)?;
                envelopes.push(RecipientEnvelope {
                    username: recipient.username,
                    wrapped_key: wrapped_key.bytes,
                    prekey_id: wrapped_key.prekey_id,
                    is_prekey: wrapped_key.is_prekey,
                    signature: Vec::new(),
                });
            }
            validate_recipient_envelopes(&envelopes).map_err(AbyssalError::from)?;
            state.revision = state
                .revision
                .checked_add(1)
                .ok_or_else(|| AbyssalError::from("Identity unavailable".to_string()))?;
            let identity_envelope = seal_state(&state, sealing).map_err(AbyssalError::from)?;
            let identity_public = public_key_from_state(&state);
            let prekey_id = state
                .prekeys
                .first()
                .map_or_else(String::new, |key| key.id.clone());
            let state_signature = sign_identity_state_v9(
                PROTOCOL_VERSION,
                state.revision,
                &identity_envelope,
                &identity_public,
                &prekey_id,
                &state.account,
            )
            .map_err(AbyssalError::from)?;
            for envelope in &mut envelopes {
                let signature_input = signature_input_v9(
                    PROTOCOL_VERSION,
                    &aad,
                    &nonce,
                    &ciphertext,
                    &identity_public,
                    envelope,
                )
                .map_err(AbyssalError::from)?;
                envelope.signature = state.account.sign(&signature_input).to_bytes().to_vec();
            }
            Ok(E2eePayload {
                version: PROTOCOL_VERSION,
                message_id,
                nonce: nonce.to_vec(),
                ciphertext,
                envelopes,
                state_revision: state.revision,
                identity_envelope,
                identity_public,
                prekey_id,
                state_signature,
            })
        })();
        if result.is_err() {
            rollback_pending_outbound(&mut state).map_err(AbyssalError::from)?;
        } else if state.revision != outbound_revision {
            rollback_pending_outbound(&mut state).map_err(AbyssalError::from)?;
            return Err("Identity unavailable".to_string().into());
        }
        result
    }

    /// Commit the exact ratchet revision after the relay confirms admission.
    /// Until this is called, all other stateful cryptographic operations are
    /// rejected and the caller may roll the session back on an explicit NACK.
    pub fn commit_outbound(&self, message_id: String, revision: u64) -> Result<(), AbyssalError> {
        validate_outbound_message_id(&message_id).map_err(AbyssalError::from)?;
        let mut state = lock(&self.state, "Identity unavailable")?;
        let pending = state
            .pending_outbound
            .as_ref()
            .ok_or_else(|| AbyssalError::from("Identity unavailable".to_string()))?;
        if pending.message_id != message_id
            || pending.revision != revision
            || state.revision != revision
        {
            return Err("Identity unavailable".to_string().into());
        }
        state.pending_outbound.take();
        Ok(())
    }

    /// Restore the pre-send snapshot for an explicitly rejected message.
    /// Revision matching is strict so a stale result cannot roll back a newer
    /// transaction.
    pub fn rollback_outbound(&self, message_id: String, revision: u64) -> Result<(), AbyssalError> {
        validate_outbound_message_id(&message_id).map_err(AbyssalError::from)?;
        let mut state = lock(&self.state, "Identity unavailable")?;
        let pending = state
            .pending_outbound
            .as_ref()
            .ok_or_else(|| AbyssalError::from("Identity unavailable".to_string()))?;
        if pending.message_id != message_id
            || pending.revision != revision
            || state.revision != revision
        {
            return Err("Identity unavailable".to_string().into());
        }
        rollback_pending_outbound(&mut state).map_err(AbyssalError::from)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn decrypt(
        &self,
        chat_id: String,
        message_id: String,
        sender_username: String,
        sender_public_key: Vec<u8>,
        version: u32,
        identity_public: Vec<u8>,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        signature: Vec<u8>,
        wrapped_key: Vec<u8>,
        recipient_prekey_id: String,
        is_prekey: bool,
        recipient_username: String,
    ) -> Result<E2eeDecryption, AbyssalError> {
        validate_message_context(&chat_id, &message_id, &sender_username)?;
        validate_username(&recipient_username)?;
        if version != PROTOCOL_VERSION
            || identity_public.len() != IDENTITY_PUBLIC_BYTES
            || nonce.len() != NONCE_BYTES
            || ciphertext.len() < PAYLOAD_TAG_BYTES
            || ciphertext.len() > MAX_PAYLOAD_CIPHERTEXT_BYTES
            || signature.len() != 64
        {
            return Err("Payload unavailable".to_string().into());
        }
        validate_identity_public_bundle(&sender_public_key, None).map_err(AbyssalError::from)?;
        validate_identity_public_bundle(&identity_public, None).map_err(AbyssalError::from)?;
        if !constant_time_eq(&sender_public_key, &identity_public) {
            return Err("Payload unavailable".to_string().into());
        }
        let envelope = RecipientEnvelope {
            username: recipient_username.clone(),
            wrapped_key,
            prekey_id: recipient_prekey_id,
            is_prekey,
            signature,
        };
        validate_recipient_envelope(&envelope).map_err(AbyssalError::from)?;
        let aad = message_aad(&chat_id, &message_id, &sender_username);
        let signature_input = signature_input_v9(
            version,
            &aad,
            &nonce,
            &ciphertext,
            &identity_public,
            &envelope,
        )
        .map_err(AbyssalError::from)?;
        let verifying_key = Ed25519PublicKey::from_slice(
            sender_public_key[32..IDENTITY_FINGERPRINT_BYTES]
                .try_into()
                .map_err(|_| "Sender unavailable".to_string())?,
        )
        .map_err(|_| "Sender unavailable".to_string())?;
        let signature = Ed25519Signature::from_slice(&envelope.signature)
            .map_err(|_| "Payload unavailable".to_string())?;
        verifying_key
            .verify(&signature_input, &signature)
            .map_err(|_| "Payload unavailable".to_string())?;
        let sealing = lock(&self.sealing, "Identity unavailable")?;
        let sealing = sealing
            .as_ref()
            .ok_or_else(|| AbyssalError::from("Identity unavailable".to_string()))?;
        let mut state = lock(&self.state, "Identity unavailable")?;
        if state.pending_outbound.is_some() {
            return Err("Identity unavailable".to_string().into());
        }
        let checkpoint = checkpoint_state_bytes(&state).map_err(AbyssalError::from)?;
        let result = (|| -> Result<E2eeDecryption, AbyssalError> {
            let (content_key, used_prekey) = ratchet_unwrap_content_key(
                &mut state,
                &sender_username,
                &sender_public_key,
                &envelope.wrapped_key,
                &aad,
                RecipientEnvelopeContext {
                    prekey_id: &envelope.prekey_id,
                    is_prekey: envelope.is_prekey,
                    username: &recipient_username,
                },
            )
            .map_err(AbyssalError::from)?;
            let content_key = Zeroizing::new(content_key);
            let cipher = ChaCha20Poly1305::new_from_slice(content_key.as_ref())
                .map_err(|_| AbyssalError::from("Payload unavailable".to_string()))?;
            let padded_plaintext = Zeroizing::new(
                cipher
                    .decrypt(
                        Nonce::from_slice(&nonce),
                        Payload {
                            msg: &ciphertext,
                            aad: &aad,
                        },
                    )
                    .map_err(|_| AbyssalError::from("Payload unavailable".to_string()))?,
            );
            let plaintext = unpad_payload(&padded_plaintext).map_err(AbyssalError::from)?;
            if used_prekey {
                replenish_consumed_prekey(&mut state, &envelope.prekey_id)
                    .map_err(AbyssalError::from)?;
            }
            state.revision = state
                .revision
                .checked_add(1)
                .ok_or_else(|| AbyssalError::from("Identity unavailable".to_string()))?;
            let identity_envelope = seal_state(&state, sealing).map_err(AbyssalError::from)?;
            let identity_public = public_key_from_state(&state);
            let prekey_id = state
                .prekeys
                .first()
                .map_or_else(String::new, |key| key.id.clone());
            let state_signature = sign_identity_state_v9(
                PROTOCOL_VERSION,
                state.revision,
                &identity_envelope,
                &identity_public,
                &prekey_id,
                &state.account,
            )
            .map_err(AbyssalError::from)?;
            Ok(E2eeDecryption {
                plaintext,
                state_revision: state.revision,
                identity_envelope,
                identity_public,
                prekey_id,
                state_signature,
            })
        })();
        if result.is_err() {
            restore_state_from_checkpoint(&mut state, &checkpoint).map_err(AbyssalError::from)?;
        }
        result
    }
}

struct WrappedContentKey {
    bytes: Vec<u8>,
    prekey_id: String,
    is_prekey: bool,
}

struct RecipientEnvelopeContext<'a> {
    prekey_id: &'a str,
    is_prekey: bool,
    username: &'a str,
}

fn ratchet_wrap_content_key(
    state: &mut E2eeState,
    content_key: &[u8; 32],
    recipient_public: &[u8],
    aad: &[u8],
    recipient_username: &str,
    recipient_prekey_id: &str,
) -> Result<WrappedContentKey, String> {
    let key = peer_key(recipient_username);
    let needs_new_session = match state
        .sessions
        .get(&key)
        .and_then(|sessions| sessions.last())
    {
        Some(session) if session.has_received_message() => false,
        Some(session) => state
            .session_prekeys
            .get(&session.session_id())
            .is_none_or(|prekey_id| prekey_id != recipient_prekey_id),
        None => true,
    };
    if needs_new_session {
        if !state.sessions.contains_key(&key) && state.sessions.len() >= MAX_PEERS {
            return Err("Recipient unavailable".to_string());
        }
        let identity_key = Curve25519PublicKey::from_slice(&recipient_public[..32])
            .map_err(|_| "Recipient unavailable".to_string())?;
        let selected = selected_prekey_public(recipient_public, recipient_prekey_id)?;
        let one_time_key = Curve25519PublicKey::from_slice(selected)
            .map_err(|_| "Recipient unavailable".to_string())?;
        let session = state
            .account
            .create_outbound_session(SessionConfig::version_2(), identity_key, one_time_key)
            .map_err(|_| "Recipient unavailable".to_string())?;
        let session_id = session.session_id();
        let sessions = state.sessions.entry(key.clone()).or_default();
        let evicted = if sessions.len() >= MAX_SESSIONS_PER_PEER {
            Some(sessions.remove(0).session_id())
        } else {
            None
        };
        sessions.push(session);
        if let Some(evicted) = evicted {
            state.session_prekeys.remove(&evicted);
        }
        state
            .session_prekeys
            .insert(session_id, recipient_prekey_id.to_string());
    }
    let session_id = state
        .sessions
        .get(&key)
        .and_then(|sessions| sessions.last())
        .map(Session::session_id)
        .ok_or_else(|| "Recipient unavailable".to_string())?;
    let session_prekey_id = state
        .session_prekeys
        .get(&session_id)
        .cloned()
        .ok_or_else(|| "Recipient unavailable".to_string())?;
    let bound_key = Zeroizing::new(bound_content_key(content_key, aad, recipient_username));
    let message = state
        .sessions
        .get_mut(&key)
        .and_then(|sessions| sessions.last_mut())
        .ok_or_else(|| "Recipient unavailable".to_string())?
        .encrypt(bound_key.as_slice())
        .map_err(|_| "Recipient unavailable".to_string())?;
    let encoded = serde_json::to_vec(&message).map_err(|_| "Recipient unavailable".to_string())?;
    if encoded.len() > MAX_RATCHET_ENVELOPE_BYTES {
        return Err("Recipient unavailable".to_string());
    }
    let is_prekey = matches!(&message, OlmMessage::PreKey(_));
    Ok(WrappedContentKey {
        bytes: encoded,
        prekey_id: if is_prekey {
            session_prekey_id
        } else {
            String::new()
        },
        is_prekey,
    })
}

fn ratchet_unwrap_content_key(
    state: &mut E2eeState,
    sender_username: &str,
    sender_public: &[u8],
    wrapped: &[u8],
    aad: &[u8],
    recipient: RecipientEnvelopeContext<'_>,
) -> Result<([u8; 32], bool), String> {
    if wrapped.is_empty() || wrapped.len() > MAX_RATCHET_ENVELOPE_BYTES {
        return Err("Payload unavailable".to_string());
    }
    let message: OlmMessage =
        serde_json::from_slice(wrapped).map_err(|_| "Payload unavailable".to_string())?;
    let actual_is_prekey = matches!(&message, OlmMessage::PreKey(_));
    let valid_prekey_id = recipient.prekey_id.len() <= 32
        && recipient.prekey_id.is_ascii()
        && recipient
            .prekey_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    if !valid_prekey_id
        || actual_is_prekey != recipient.is_prekey
        || recipient.is_prekey == recipient.prekey_id.is_empty()
        || match &message {
            OlmMessage::PreKey(prekey) => {
                prekey_id_for_public(&prekey.one_time_key().to_bytes()) != recipient.prekey_id
            }
            OlmMessage::Normal(_) => false,
        }
    {
        return Err("Payload unavailable".to_string());
    }
    let sender_identity = Curve25519PublicKey::from_slice(&sender_public[..32])
        .map_err(|_| "Sender unavailable".to_string())?;
    let key = peer_key(sender_username);

    let (plain, used_prekey) = match &message {
        OlmMessage::PreKey(prekey) => {
            let existing = state.sessions.get_mut(&key).and_then(|sessions| {
                sessions
                    .iter_mut()
                    .find(|session| session.session_id() == prekey.session_id())
            });
            if let Some(session) = existing {
                let plain = session
                    .decrypt(&message)
                    .map_err(|_| "Payload unavailable".to_string())?;
                (plain, false)
            } else {
                if !state.sessions.contains_key(&key) && state.sessions.len() >= MAX_PEERS {
                    return Err("Payload unavailable".to_string());
                }
                let created = state
                    .account
                    .create_inbound_session(SessionConfig::version_2(), sender_identity, prekey)
                    .map_err(|_| "Payload unavailable".to_string())?;
                let plain = created.plaintext;
                let session_id = created.session.session_id();
                let sessions = state.sessions.entry(key).or_default();
                let evicted = if sessions.len() >= MAX_SESSIONS_PER_PEER {
                    Some(sessions.remove(0).session_id())
                } else {
                    None
                };
                sessions.push(created.session);
                if let Some(evicted) = evicted {
                    state.session_prekeys.remove(&evicted);
                }
                state
                    .session_prekeys
                    .insert(session_id, recipient.prekey_id.to_string());
                (plain, true)
            }
        }
        OlmMessage::Normal(_) => {
            let sessions = state
                .sessions
                .get_mut(&key)
                .ok_or_else(|| "Payload unavailable".to_string())?;
            let mut decrypted = None;
            for session in sessions.iter_mut().rev() {
                if let Ok(plain) = session.decrypt(&message) {
                    decrypted = Some(plain);
                    break;
                }
            }
            (
                decrypted.ok_or_else(|| "Payload unavailable".to_string())?,
                false,
            )
        }
    };
    let plain = Zeroizing::new(plain);
    if plain.len() != 64 {
        return Err("Payload unavailable".to_string());
    }
    let expected_binding = content_key_binding(aad, recipient.username);
    if plain[32..] != expected_binding {
        return Err("Payload unavailable".to_string());
    }
    Ok((
        plain[..32]
            .try_into()
            .map_err(|_| "Payload unavailable".to_string())?,
        used_prekey,
    ))
}

fn bound_content_key(content_key: &[u8; 32], aad: &[u8], recipient_username: &str) -> Vec<u8> {
    let mut result = Vec::with_capacity(64);
    result.extend_from_slice(content_key);
    result.extend_from_slice(&content_key_binding(aad, recipient_username));
    result
}

fn content_key_binding(aad: &[u8], recipient_username: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(canonical_parts(&[
        b"ABYSSAL_RATCHET_CONTENT_KEY_V1",
        aad,
        recipient_username.as_bytes(),
    ]));
    hasher.finalize().into()
}

fn seal_state(state: &E2eeState, sealing: &SealingMaterial) -> Result<Vec<u8>, String> {
    let stored = checkpoint_state(state);
    let plain = Zeroizing::new(
        serde_json::to_vec(&stored).map_err(|_| "Identity unavailable".to_string())?,
    );
    if plain.len() > MAX_IDENTITY_STATE_BYTES - NONCE_BYTES - 32 {
        return Err("Identity unavailable".to_string());
    }
    let cipher = ChaCha20Poly1305::new_from_slice(&sealing.key)
        .map_err(|_| "Identity unavailable".to_string())?;
    let mut nonce = [0u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: &sealing.context,
            },
        )
        .map_err(|_| "Identity unavailable".to_string())?;
    let mut result = Vec::with_capacity(1 + nonce.len() + encrypted.len());
    result.push(IDENTITY_ENVELOPE_VERSION);
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&encrypted);
    Ok(result)
}

fn checkpoint_state(state: &E2eeState) -> StoredE2eeState {
    StoredE2eeState {
        revision: state.revision,
        fallback_public: state.fallback_public,
        prekeys: state.prekeys.clone(),
        account: state.account.pickle(),
        session_prekeys: state.session_prekeys.clone(),
        peers: state
            .sessions
            .iter()
            .map(|(peer, sessions)| StoredPeerSessions {
                peer: peer.clone(),
                sessions: sessions.iter().map(Session::pickle).collect(),
            })
            .collect(),
    }
}

fn checkpoint_state_bytes(state: &E2eeState) -> Result<Zeroizing<Vec<u8>>, String> {
    serde_json::to_vec(&checkpoint_state(state))
        .map(Zeroizing::new)
        .map_err(|_| "Identity unavailable".to_string())
}

fn restore_state(state: &mut E2eeState, stored: StoredE2eeState) {
    state.revision = stored.revision;
    state.fallback_public = stored.fallback_public;
    state.prekeys = stored.prekeys;
    state.account = Account::from_pickle(stored.account);
    state.sessions = stored
        .peers
        .into_iter()
        .map(|peer| {
            (
                peer.peer,
                peer.sessions
                    .into_iter()
                    .map(Session::from_pickle)
                    .collect(),
            )
        })
        .collect();
    state.session_prekeys = stored.session_prekeys;
}

fn begin_outbound(state: &mut E2eeState, message_id: &str) -> Result<u64, String> {
    if state.pending_outbound.is_some() {
        return Err("Identity unavailable".to_string());
    }
    validate_outbound_message_id(message_id)?;
    let revision = state
        .revision
        .checked_add(1)
        .ok_or_else(|| "Identity unavailable".to_string())?;
    let checkpoint = checkpoint_state_bytes(state)?;
    state.pending_outbound = Some(PendingOutbound {
        message_id: message_id.to_string(),
        revision,
        checkpoint,
    });
    Ok(revision)
}

fn validate_outbound_message_id(message_id: &str) -> Result<(), String> {
    if valid_context_identifier(message_id) {
        Ok(())
    } else {
        Err("Identity unavailable".to_string())
    }
}

fn rollback_pending_outbound(state: &mut E2eeState) -> Result<(), String> {
    let pending = state
        .pending_outbound
        .take()
        .ok_or_else(|| "Identity unavailable".to_string())?;
    // Take ownership to avoid cloning secret checkpoint bytes. Deserialization
    // happens before ratchet state is mutated; on failure the same pending
    // transaction is reinserted so the session stays fail closed.
    match restore_state_from_checkpoint(state, &pending.checkpoint) {
        Ok(()) => Ok(()),
        Err(error) => {
            state.pending_outbound = Some(pending);
            Err(error)
        }
    }
}

fn restore_state_from_checkpoint(state: &mut E2eeState, checkpoint: &[u8]) -> Result<(), String> {
    let stored: StoredE2eeState =
        serde_json::from_slice(checkpoint).map_err(|_| "Identity unavailable".to_string())?;
    restore_state(state, stored);
    Ok(())
}

fn pad_payload(plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    if plaintext.is_empty() || plaintext.len() > MAX_PAYLOAD_BYTES {
        return Err("Payload unavailable".to_string());
    }
    let required = PAYLOAD_HEADER_BYTES
        .checked_add(plaintext.len())
        .ok_or_else(|| "Payload unavailable".to_string())?;
    let padded_len = required
        .div_ceil(PAYLOAD_PADDING_BUCKET_BYTES)
        .checked_mul(PAYLOAD_PADDING_BUCKET_BYTES)
        .ok_or_else(|| "Payload unavailable".to_string())?;
    if padded_len > MAX_PADDED_PAYLOAD_BYTES {
        return Err("Payload unavailable".to_string());
    }
    let mut padded = Zeroizing::new(vec![0_u8; padded_len]);
    padded[0] = PAYLOAD_FORMAT_VERSION;
    padded[1..PAYLOAD_HEADER_BYTES].copy_from_slice(&(plaintext.len() as u32).to_be_bytes());
    padded[PAYLOAD_HEADER_BYTES..required].copy_from_slice(plaintext);
    if padded_len > required {
        OsRng.fill_bytes(&mut padded[required..]);
    }
    Ok(padded)
}

fn unpad_payload(padded: &[u8]) -> Result<Vec<u8>, String> {
    if padded.len() < PAYLOAD_HEADER_BYTES
        || padded.len() > MAX_PADDED_PAYLOAD_BYTES
        || !padded.len().is_multiple_of(PAYLOAD_PADDING_BUCKET_BYTES)
        || padded[0] != PAYLOAD_FORMAT_VERSION
    {
        return Err("Payload unavailable".to_string());
    }
    let original_len = u32::from_be_bytes(
        padded[1..PAYLOAD_HEADER_BYTES]
            .try_into()
            .map_err(|_| "Payload unavailable".to_string())?,
    ) as usize;
    if original_len == 0 || original_len > MAX_PAYLOAD_BYTES {
        return Err("Payload unavailable".to_string());
    }
    let required = PAYLOAD_HEADER_BYTES
        .checked_add(original_len)
        .ok_or_else(|| "Payload unavailable".to_string())?;
    let canonical_len = required
        .div_ceil(PAYLOAD_PADDING_BUCKET_BYTES)
        .checked_mul(PAYLOAD_PADDING_BUCKET_BYTES)
        .ok_or_else(|| "Payload unavailable".to_string())?;
    if canonical_len != padded.len() {
        return Err("Payload unavailable".to_string());
    }
    Ok(padded[PAYLOAD_HEADER_BYTES..required].to_vec())
}

fn public_key_from_state(state: &E2eeState) -> Vec<u8> {
    let identity = state.account.identity_keys();
    let mut result = Vec::with_capacity(IDENTITY_PUBLIC_BYTES);
    result.extend_from_slice(identity.curve25519.as_bytes());
    result.extend_from_slice(identity.ed25519.as_bytes());
    for prekey in &state.prekeys {
        result.extend_from_slice(&prekey.public);
    }
    result.extend_from_slice(&state.fallback_public);
    result
}

fn replenish_consumed_prekey(state: &mut E2eeState, consumed_id: &str) -> Result<(), String> {
    let index = state
        .prekeys
        .iter()
        .position(|key| key.id == consumed_id)
        .ok_or_else(|| "Payload unavailable".to_string())?;
    let generated = state.account.generate_one_time_keys(1);
    if generated.created.len() != 1 || !generated.removed.is_empty() {
        return Err("Identity unavailable".to_string());
    }
    let public = generated
        .created
        .into_iter()
        .next()
        .ok_or_else(|| "Identity unavailable".to_string())?
        .to_bytes();
    let existing = state
        .prekeys
        .iter()
        .map(|key| key.id.as_str())
        .collect::<HashSet<_>>();
    let replacement = StoredPrekey {
        id: prekey_id_for_public(&public),
        public,
    };
    if replacement.id == consumed_id || existing.contains(replacement.id.as_str()) {
        return Err("Identity unavailable".to_string());
    }
    state.prekeys.remove(index);
    state.account.mark_keys_as_published();
    state.prekeys.push(replacement);
    state.prekeys.sort_by(|left, right| left.id.cmp(&right.id));
    validate_prekey_pool(&state.prekeys)?;
    validate_account_prekey_material(&state.account.pickle(), &state.prekeys)
}

fn canonical_prekeys(account: &Account) -> Result<Vec<StoredPrekey>, String> {
    let mut prekeys = account
        .one_time_keys()
        .into_values()
        .map(|public| public.to_bytes())
        .map(|public| StoredPrekey {
            id: prekey_id_for_public(&public),
            public,
        })
        .collect::<Vec<_>>();
    prekeys.sort_by(|left, right| left.id.cmp(&right.id));
    validate_prekey_pool(&prekeys)?;
    Ok(prekeys)
}

fn validate_prekey_pool(prekeys: &[StoredPrekey]) -> Result<(), String> {
    if prekeys.len() != PREKEY_POOL_SIZE_V9 {
        return Err("Identity unavailable".to_string());
    }
    let mut previous = None;
    for prekey in prekeys {
        validate_prekey_bundle(&prekey.id, &prekey.public)?;
        if previous.is_some_and(|id: &str| id >= prekey.id.as_str()) {
            return Err("Identity unavailable".to_string());
        }
        previous = Some(prekey.id.as_str());
    }
    Ok(())
}

fn validate_account_prekey_material(
    account: &AccountPickle,
    prekeys: &[StoredPrekey],
) -> Result<(), String> {
    let encoded = Zeroizing::new(
        serde_json::to_vec(account).map_err(|_| "Identity unavailable".to_string())?,
    );
    let material: AccountMaterialView =
        serde_json::from_slice(&encoded).map_err(|_| "Identity unavailable".to_string())?;
    let mut account_public = material
        .one_time_keys
        .private_keys
        .values()
        .map(Curve25519PublicKey::from)
        .map(|public| public.to_bytes())
        .collect::<Vec<_>>();
    account_public.sort_unstable();
    let mut sealed_public = prekeys.iter().map(|key| key.public).collect::<Vec<_>>();
    sealed_public.sort_unstable();
    if account_public != sealed_public {
        return Err("Identity unavailable".to_string());
    }
    Ok(())
}

pub fn prekey_id_for_public(public_key: &[u8; ONE_TIME_KEY_BYTES]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(canonical_parts(&[b"ABYSSAL_PREKEY_ID_V1", public_key]));
    let mut result = String::with_capacity(32);
    for byte in &digest[..16] {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

fn peer_key(username: &str) -> String {
    username.to_ascii_lowercase()
}

fn lock<'a, T>(mutex: &'a Mutex<T>, message: &str) -> Result<MutexGuard<'a, T>, AbyssalError> {
    mutex
        .lock()
        .map_err(|_| AbyssalError::from(message.to_string()))
}

impl Drop for E2eeSession {
    fn drop(&mut self) {
        self.account_lifetime.revoke();
        self.mls_root.zeroize();
    }
}

impl E2eeSession {
    fn mls_material(
        &self,
        room_id: &str,
        username: &str,
        node_context: &[u8],
        group_id: &[u8],
    ) -> Result<([u8; 64], Vec<u8>), AbyssalError> {
        let username = username.to_ascii_lowercase();
        let group_id: [u8; 32] = group_id
            .try_into()
            .map_err(|_| AbyssalError::from("Identity unavailable".to_string()))?;
        let stable_bundle = self.public_key();
        let stable: [u8; 64] = stable_bundle
            .get(..IDENTITY_FINGERPRINT_BYTES)
            .ok_or_else(|| AbyssalError::from("Identity unavailable".to_string()))?
            .try_into()
            .map_err(|_| AbyssalError::from("Identity unavailable".to_string()))?;
        let mls_public = crate::mls_protocol::mls_public_for_root(
            &self.mls_root,
            &username,
            node_context,
            room_id,
            &group_id,
        )
        .map_err(AbyssalError::from)?;
        let transcript = crate::mls_protocol::credential_transcript(
            &username,
            room_id,
            node_context,
            &group_id,
            &stable,
            &mls_public,
        )
        .map_err(AbyssalError::from)?;
        let state = lock(&self.state, "Identity unavailable")?;
        Ok((stable, state.account.sign(&transcript).to_bytes().to_vec()))
    }
}

fn identity_wrap_key(export_key: &[u8], context: &[u8]) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(context), export_key)
        .expand(b"ABYSSAL_IDENTITY_WRAP_V3", &mut key)
        .map_err(|_| "Identity unavailable".to_string())?;
    Ok(key)
}

pub(crate) fn derive_mls_root(export_key: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    validate_export_key(export_key)?;
    let mut root = Zeroizing::new([0_u8; 32]);
    Hkdf::<Sha256>::new(Some(MLS_ROOT_DOMAIN), export_key)
        .expand(MLS_ROOT_DOMAIN, root.as_mut())
        .map_err(|_| "Identity unavailable".to_string())?;
    Ok(root)
}

fn message_aad(chat_id: &str, message_id: &str, sender_username: &str) -> Vec<u8> {
    canonical_parts(&[
        b"ABYSSAL_E2EE_PAYLOAD_V9",
        chat_id.as_bytes(),
        message_id.as_bytes(),
        sender_username.as_bytes(),
    ])
}

fn validate_attachment_context(
    chat_id: &str,
    message_id: &str,
    sender_username: &str,
    media_type: &str,
) -> Result<(), String> {
    validate_message_context(chat_id, message_id, sender_username)?;
    attachment_plaintext_limit(media_type).map(|_| ())
}

fn attachment_plaintext_limit(media_type: &str) -> Result<usize, String> {
    match media_type {
        "IMAGE" => Ok(IMAGE_ATTACHMENT_LIMIT_BYTES),
        "VIDEO" => Ok(VIDEO_ATTACHMENT_LIMIT_BYTES),
        "FILE" => Ok(MAX_ATTACHMENT_PLAINTEXT_BYTES),
        _ => Err("Payload unavailable".to_string()),
    }
}

fn attachment_blob_limit(media_type: &str) -> usize {
    match media_type {
        "FILE" => MAX_ATTACHMENT_BLOB_BYTES,
        _ => {
            ATTACHMENT_BLOB_HEADER_BYTES
                + attachment_plaintext_limit(media_type).unwrap_or(MAX_ATTACHMENT_PLAINTEXT_BYTES)
                + ATTACHMENT_TAG_BYTES
        }
    }
}

fn attachment_aad(
    chat_id: &str,
    message_id: &str,
    sender_username: &str,
    media_type: &str,
) -> Vec<u8> {
    canonical_parts(&[
        b"ABYSSAL_ATTACHMENT_AEAD_V1",
        chat_id.as_bytes(),
        message_id.as_bytes(),
        sender_username.as_bytes(),
        media_type.as_bytes(),
    ])
}

fn sign_identity_state_v9(
    version: u32,
    state_revision: u64,
    identity_envelope: &[u8],
    identity_public: &[u8],
    prekey_id: &str,
    account: &Account,
) -> Result<Vec<u8>, String> {
    let transcript = Zeroizing::new(identity_state_signature_input_v9(
        version,
        state_revision,
        identity_envelope,
        identity_public,
        prekey_id,
    )?);
    Ok(account.sign(&transcript).to_bytes().to_vec())
}

/// Build the exact protocol-v9 signed identity-state transcript.
///
/// The transcript covers the complete sealed state envelope and the public
/// identity/prekey bundle returned with it.  The relay can use this helper to
/// verify the state signature without decrypting the envelope.
pub fn identity_state_signature_input_v9(
    version: u32,
    state_revision: u64,
    identity_envelope: &[u8],
    identity_public: &[u8],
    prekey_id: &str,
) -> Result<Vec<u8>, String> {
    validate_identity_state_signature_fields(
        version,
        state_revision,
        identity_envelope,
        identity_public,
        prekey_id,
    )?;
    let version = version.to_be_bytes();
    let revision = state_revision.to_be_bytes();
    Ok(canonical_parts(&[
        b"ABYSSAL_E2EE_IDENTITY_STATE_SIGNATURE_V9",
        &version,
        &revision,
        identity_envelope,
        identity_public,
        prekey_id.as_bytes(),
    ]))
}

/// Verify a protocol-v9 signed identity-state snapshot.
///
/// The caller must bind `identity_public` to the authenticated account before
/// accepting the snapshot.  This function verifies the Ed25519 signature and
/// validates every transcript field, including the prekey commitment.
pub fn verify_identity_state_signature_v9(
    version: u32,
    state_revision: u64,
    identity_envelope: &[u8],
    identity_public: &[u8],
    prekey_id: &str,
    state_signature: &[u8],
) -> Result<(), String> {
    if state_signature.len() != IDENTITY_STATE_SIGNATURE_BYTES {
        return Err("Payload unavailable".to_string());
    }
    let transcript = Zeroizing::new(identity_state_signature_input_v9(
        version,
        state_revision,
        identity_envelope,
        identity_public,
        prekey_id,
    )?);
    let verifying_key = Ed25519PublicKey::from_slice(
        identity_public[32..IDENTITY_FINGERPRINT_BYTES]
            .try_into()
            .map_err(|_| "Identity unavailable".to_string())?,
    )
    .map_err(|_| "Identity unavailable".to_string())?;
    let signature = Ed25519Signature::from_slice(state_signature)
        .map_err(|_| "Payload unavailable".to_string())?;
    verifying_key
        .verify(&transcript, &signature)
        .map_err(|_| "Payload unavailable".to_string())
}

/// Build the canonical protocol-v9 registration proof transcript.
///
/// Every variable-length field is length-prefixed with a big-endian u32. This
/// avoids concatenation ambiguity while keeping the transcript deterministic
/// across Rust, Kotlin, and WebAssembly clients.
pub fn registration_identity_proof_input_v9(
    node_id: &str,
    handshake_id: &str,
    challenge: &[u8],
    registration_upload: &[u8],
    identity_public: &[u8],
    prekey_id: &str,
    identity_envelope: &[u8],
) -> Result<Vec<u8>, String> {
    if node_id.is_empty()
        || node_id.len() > 128
        || !node_id.is_ascii()
        || handshake_id.is_empty()
        || handshake_id.len() > 128
        || !handshake_id.is_ascii()
        || challenge.len() != REGISTRATION_CHALLENGE_BYTES
        || registration_upload.is_empty()
        || registration_upload.len() > 16 * 1024
        || identity_public.len() != IDENTITY_PUBLIC_BYTES
        || !valid_prekey_id_for_protocol(prekey_id)
        || identity_envelope.len() <= 1 + NONCE_BYTES + ATTACHMENT_TAG_BYTES
        || identity_envelope.len() > MAX_IDENTITY_STATE_BYTES
        || identity_envelope.first() != Some(&IDENTITY_ENVELOPE_VERSION)
    {
        return Err("Identity proof rejected".to_string());
    }
    validate_identity_public_bundle(identity_public, Some(prekey_id))?;

    let mut transcript = Vec::with_capacity(
        64 + node_id.len()
            + handshake_id.len()
            + challenge.len()
            + registration_upload.len()
            + identity_public.len()
            + prekey_id.len()
            + identity_envelope.len(),
    );
    transcript.extend_from_slice(b"ABYSSAL_REGISTRATION_IDENTITY_PROOF_V9");
    transcript.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    append_transcript_field(&mut transcript, node_id.as_bytes());
    append_transcript_field(&mut transcript, handshake_id.as_bytes());
    append_transcript_field(&mut transcript, challenge);
    append_transcript_field(&mut transcript, registration_upload);
    append_transcript_field(&mut transcript, identity_public);
    append_transcript_field(&mut transcript, prekey_id.as_bytes());
    append_transcript_field(&mut transcript, identity_envelope);
    Ok(transcript)
}

/// Verify a registration proof against the Ed25519 key embedded in the exact
/// public identity bundle supplied by the client.
#[allow(clippy::too_many_arguments)]
pub fn verify_registration_identity_proof_v9(
    node_id: &str,
    handshake_id: &str,
    challenge: &[u8],
    registration_upload: &[u8],
    identity_public: &[u8],
    prekey_id: &str,
    identity_envelope: &[u8],
    proof: &[u8],
) -> Result<(), String> {
    if proof.len() != IDENTITY_STATE_SIGNATURE_BYTES {
        return Err("Identity proof rejected".to_string());
    }
    let transcript = Zeroizing::new(registration_identity_proof_input_v9(
        node_id,
        handshake_id,
        challenge,
        registration_upload,
        identity_public,
        prekey_id,
        identity_envelope,
    )?);
    let identity_ed: &[u8; 32] = identity_public
        [IDENTITY_FINGERPRINT_BYTES - 32..IDENTITY_FINGERPRINT_BYTES]
        .try_into()
        .map_err(|_| "Identity proof rejected".to_string())?;
    let verifying_key = Ed25519PublicKey::from_slice(identity_ed)
        .map_err(|_| "Identity proof rejected".to_string())?;
    let signature =
        Ed25519Signature::from_slice(proof).map_err(|_| "Identity proof rejected".to_string())?;
    verifying_key
        .verify(&transcript, &signature)
        .map_err(|_| "Identity proof rejected".to_string())
}

fn append_transcript_field(transcript: &mut Vec<u8>, field: &[u8]) {
    transcript.extend_from_slice(&(field.len() as u32).to_be_bytes());
    transcript.extend_from_slice(field);
}

fn valid_prekey_id_for_protocol(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

#[allow(clippy::too_many_arguments)]
fn sign_ack_signature_v9(
    version: u32,
    chat_id: &str,
    message_id: &str,
    sender_username: &str,
    used_prekey_id: &str,
    account: &Account,
) -> Result<Vec<u8>, String> {
    let transcript = Zeroizing::new(ack_signature_input_v9(
        version,
        chat_id,
        message_id,
        sender_username,
        used_prekey_id,
    )?);
    Ok(account.sign(&transcript).to_bytes().to_vec())
}

/// Build the exact protocol-v9 message acknowledgement transcript.
///
/// This proof covers only the acknowledgement action.  It intentionally does
/// not include the current ratchet revision or state signature, because a
/// duplicate delivery may be acknowledged after the recipient has advanced
/// its ratchet state.  The relay verifies the signed state separately.
pub fn ack_signature_input_v9(
    version: u32,
    chat_id: &str,
    message_id: &str,
    sender_username: &str,
    used_prekey_id: &str,
) -> Result<Vec<u8>, String> {
    validate_ack_signature_fields(
        version,
        chat_id,
        message_id,
        sender_username,
        used_prekey_id,
    )?;
    let version = version.to_be_bytes();
    Ok(canonical_parts(&[
        b"ABYSSAL_E2EE_ACK_SIGNATURE_V9",
        &version,
        chat_id.as_bytes(),
        message_id.as_bytes(),
        sender_username.as_bytes(),
        used_prekey_id.as_bytes(),
    ]))
}

/// Verify a protocol-v9 message acknowledgement signature.
pub fn verify_ack_signature_v9(
    version: u32,
    chat_id: &str,
    message_id: &str,
    sender_username: &str,
    used_prekey_id: &str,
    identity_public: &[u8],
    ack_signature: &[u8],
) -> Result<(), String> {
    if ack_signature.len() != IDENTITY_STATE_SIGNATURE_BYTES
        || identity_public.len() != IDENTITY_PUBLIC_BYTES
    {
        return Err("Payload unavailable".to_string());
    }
    let transcript = Zeroizing::new(ack_signature_input_v9(
        version,
        chat_id,
        message_id,
        sender_username,
        used_prekey_id,
    )?);
    let verifying_key = Ed25519PublicKey::from_slice(
        identity_public[32..IDENTITY_FINGERPRINT_BYTES]
            .try_into()
            .map_err(|_| "Identity unavailable".to_string())?,
    )
    .map_err(|_| "Identity unavailable".to_string())?;
    let signature = Ed25519Signature::from_slice(ack_signature)
        .map_err(|_| "Payload unavailable".to_string())?;
    verifying_key
        .verify(&transcript, &signature)
        .map_err(|_| "Payload unavailable".to_string())
}

fn validate_ack_signature_fields(
    version: u32,
    chat_id: &str,
    message_id: &str,
    sender_username: &str,
    used_prekey_id: &str,
) -> Result<(), String> {
    if version != PROTOCOL_VERSION
        || (!used_prekey_id.is_empty() && !valid_prekey_id(used_prekey_id))
    {
        return Err("Payload unavailable".to_string());
    }
    validate_message_context(chat_id, message_id, sender_username)
        .map_err(|_| "Payload unavailable".to_string())
}

fn validate_identity_state_signature_fields(
    version: u32,
    state_revision: u64,
    identity_envelope: &[u8],
    identity_public: &[u8],
    prekey_id: &str,
) -> Result<(), String> {
    if version != PROTOCOL_VERSION
        || state_revision == 0
        || identity_envelope.len() <= 1 + NONCE_BYTES + ATTACHMENT_TAG_BYTES
        || identity_envelope.len() > MAX_IDENTITY_STATE_BYTES
        || identity_envelope.first() != Some(&IDENTITY_ENVELOPE_VERSION)
        || !valid_prekey_id(prekey_id)
        || prekey_id.is_empty()
    {
        return Err("Payload unavailable".to_string());
    }
    validate_identity_public_bundle(identity_public, Some(prekey_id))
        .map_err(|_| "Payload unavailable".to_string())
}

fn signature_input_v9(
    version: u32,
    aad: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    identity_public: &[u8],
    envelope: &RecipientEnvelope,
) -> Result<Vec<u8>, String> {
    validate_recipient_envelope(envelope)?;
    let version = version.to_be_bytes();
    let is_prekey = [u8::from(envelope.is_prekey)];
    Ok(canonical_parts(&[
        b"ABYSSAL_E2EE_SIGNATURE_V9",
        &version,
        aad,
        nonce,
        ciphertext,
        identity_public,
        envelope.username.as_bytes(),
        envelope.prekey_id.as_bytes(),
        &is_prekey,
        &envelope.wrapped_key,
    ]))
}

/// Build the exact protocol-v9 recipient-envelope signature transcript.
///
/// This helper is intentionally kept outside the UniFFI surface. The relay
/// and its adversarial tests use the same canonical construction as clients.
#[allow(clippy::too_many_arguments)]
pub fn message_signature_input_v9(
    version: u32,
    chat_id: &str,
    message_id: &str,
    sender_username: &str,
    identity_public: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    recipient_username: &str,
    wrapped_key: &[u8],
    recipient_prekey_id: &str,
    is_prekey: bool,
) -> Result<Vec<u8>, String> {
    validate_message_context(chat_id, message_id, sender_username)?;
    if version != PROTOCOL_VERSION
        || identity_public.len() != IDENTITY_PUBLIC_BYTES
        || nonce.len() != NONCE_BYTES
    {
        return Err("Payload unavailable".to_string());
    }
    let envelope = RecipientEnvelope {
        username: recipient_username.to_string(),
        wrapped_key: wrapped_key.to_vec(),
        prekey_id: recipient_prekey_id.to_string(),
        is_prekey,
        signature: Vec::new(),
    };
    let result = signature_input_v9(
        version,
        &message_aad(chat_id, message_id, sender_username),
        nonce,
        ciphertext,
        identity_public,
        &envelope,
    );
    let mut envelope = envelope;
    envelope.wrapped_key.zeroize();
    envelope.signature.zeroize();
    result
}

/// Verify the exact protocol-v9 recipient-envelope signature transcript.
///
/// The relay must verify signatures with the same canonical transcript as the
/// clients, while still binding the long-term signing key to the account
/// identity authenticated by the relay before calling this helper.
#[allow(clippy::too_many_arguments)]
pub fn verify_message_signature_v9(
    version: u32,
    chat_id: &str,
    message_id: &str,
    sender_username: &str,
    identity_public: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    recipient_username: &str,
    wrapped_key: &[u8],
    recipient_prekey_id: &str,
    is_prekey: bool,
    signature: &[u8],
) -> Result<(), String> {
    if version != PROTOCOL_VERSION
        || identity_public.len() != IDENTITY_PUBLIC_BYTES
        || nonce.len() != NONCE_BYTES
        || signature.len() != 64
    {
        return Err("Payload unavailable".to_string());
    }
    let signature_input = Zeroizing::new(message_signature_input_v9(
        version,
        chat_id,
        message_id,
        sender_username,
        identity_public,
        nonce,
        ciphertext,
        recipient_username,
        wrapped_key,
        recipient_prekey_id,
        is_prekey,
    )?);
    let verifying_key = Ed25519PublicKey::from_slice(
        identity_public[32..IDENTITY_FINGERPRINT_BYTES]
            .try_into()
            .map_err(|_| "Sender unavailable".to_string())?,
    )
    .map_err(|_| "Sender unavailable".to_string())?;
    let signature =
        Ed25519Signature::from_slice(signature).map_err(|_| "Payload unavailable".to_string())?;
    verifying_key
        .verify(&signature_input, &signature)
        .map_err(|_| "Payload unavailable".to_string())
}

fn validate_recipient_envelope(envelope: &RecipientEnvelope) -> Result<(), String> {
    validate_username(&envelope.username).map_err(|_| "Payload unavailable".to_string())?;
    if !valid_prekey_id(&envelope.prekey_id)
        || envelope.is_prekey == envelope.prekey_id.is_empty()
        || envelope.wrapped_key.is_empty()
        || envelope.wrapped_key.len() > MAX_RATCHET_ENVELOPE_BYTES
    {
        return Err("Payload unavailable".to_string());
    }
    Ok(())
}

fn validate_recipient_envelopes(envelopes: &[RecipientEnvelope]) -> Result<(), String> {
    if envelopes.is_empty() || envelopes.len() > MAX_PEERS {
        return Err("Payload unavailable".to_string());
    }
    let mut seen = HashSet::with_capacity(envelopes.len());
    for envelope in envelopes {
        validate_recipient_envelope(envelope)?;
        if !seen.insert(peer_key(&envelope.username)) {
            return Err("Payload unavailable".to_string());
        }
    }
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

fn valid_prekey_id(prekey_id: &str) -> bool {
    prekey_id.len() <= 32
        && prekey_id.is_ascii()
        && prekey_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn canonical_parts(parts: &[&[u8]]) -> Vec<u8> {
    let size = parts.iter().map(|part| 4 + part.len()).sum();
    let mut result = Vec::with_capacity(size);
    for part in parts {
        result.extend_from_slice(&(part.len() as u32).to_be_bytes());
        result.extend_from_slice(part);
    }
    result
}

fn validate_password_bytes(password: &[u8]) -> Result<(), String> {
    if (8..=256).contains(&password.len()) {
        Ok(())
    } else {
        Err("Wrong information".to_string())
    }
}

fn validate_export_key(export_key: &[u8]) -> Result<(), String> {
    if export_key.len() >= 32 && export_key.len() <= 128 {
        Ok(())
    } else {
        Err("Identity unavailable".to_string())
    }
}

fn validate_context(context: &[u8]) -> Result<(), String> {
    if !context.is_empty() && context.len() <= MAX_CONTEXT_BYTES {
        Ok(())
    } else {
        Err("Identity unavailable".to_string())
    }
}

fn validate_prekey_bundle(prekey_id: &str, public_key: &[u8]) -> Result<(), String> {
    if public_key.len() != ONE_TIME_KEY_BYTES
        || prekey_id.is_empty()
        || prekey_id.len() > 32
        || !prekey_id.is_ascii()
        || !prekey_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err("Identity unavailable".to_string());
    }
    if public_key.iter().all(|byte| *byte == 0)
        || prekey_id
            != prekey_id_for_public(
                public_key
                    .try_into()
                    .map_err(|_| "Identity unavailable".to_string())?,
            )
    {
        return Err("Identity unavailable".to_string());
    }
    Ok(())
}

/// Validate the public identity bundle before storing or routing it.
///
/// This is intentionally shared by every protocol boundary.  Besides shape,
/// Ed25519 encoding and prekey commitments, it performs a real X25519
/// contribution check for the identity, every one-time key, and the fallback
/// key so known low-order/non-contributory keys cannot enter relay state.
pub fn validate_identity_public_bundle(
    public_key: &[u8],
    prekey_id: Option<&str>,
) -> Result<(), String> {
    if public_key.len() != IDENTITY_PUBLIC_BYTES {
        return Err("Identity unavailable".to_string());
    }
    let identity_curve = &public_key[..32];
    let identity_ed = &public_key[32..IDENTITY_FINGERPRINT_BYTES];
    let fallback = &public_key[FALLBACK_KEY_OFFSET..IDENTITY_PUBLIC_BYTES];
    if identity_curve.iter().all(|byte| *byte == 0)
        || identity_ed.iter().all(|byte| *byte == 0)
        || fallback.iter().all(|byte| *byte == 0)
    {
        return Err("Identity unavailable".to_string());
    }
    let identity_curve = Curve25519PublicKey::from_slice(identity_curve)
        .map_err(|_| "Identity unavailable".to_string())?;
    let fallback = Curve25519PublicKey::from_slice(fallback)
        .map_err(|_| "Identity unavailable".to_string())?;
    // This public, non-secret scalar is a deterministic contributory-behavior
    // probe. It is not key material used to protect application data.
    let validation_secret = Curve25519SecretKey::from_slice(&KEY_VALIDATION_SCALAR);
    if validation_secret.diffie_hellman(&identity_curve).is_none()
        || validation_secret.diffie_hellman(&fallback).is_none()
    {
        return Err("Identity unavailable".to_string());
    }
    let identity_ed: &[u8; 32] = identity_ed
        .try_into()
        .map_err(|_| "Identity unavailable".to_string())?;
    Ed25519PublicKey::from_slice(identity_ed).map_err(|_| "Identity unavailable".to_string())?;
    let mut previous = None;
    let mut selected = false;
    for public in
        public_key[ONE_TIME_KEY_OFFSET..FALLBACK_KEY_OFFSET].chunks_exact(ONE_TIME_KEY_BYTES)
    {
        let public: &[u8; ONE_TIME_KEY_BYTES] = public
            .try_into()
            .map_err(|_| "Identity unavailable".to_string())?;
        let id = prekey_id_for_public(public);
        if previous.as_ref().is_some_and(|value: &String| value >= &id) {
            return Err("Identity unavailable".to_string());
        }
        let curve = Curve25519PublicKey::from_slice(public)
            .map_err(|_| "Identity unavailable".to_string())?;
        if validation_secret.diffie_hellman(&curve).is_none() {
            return Err("Identity unavailable".to_string());
        }
        selected |= prekey_id.is_some_and(|expected| expected == id);
        previous = Some(id);
    }
    if prekey_id.is_some() && !selected {
        return Err("Identity unavailable".to_string());
    }
    Ok(())
}

/// Return every canonical prekey commitment from a protocol-v9 public bundle.
/// Validation is all-or-nothing so callers never lease from malformed pools.
pub fn prekey_ids_from_identity_public_v9(public_key: &[u8]) -> Result<Vec<String>, String> {
    validate_identity_public_bundle(public_key, None)?;
    Ok(public_key[ONE_TIME_KEY_OFFSET..FALLBACK_KEY_OFFSET]
        .chunks_exact(ONE_TIME_KEY_BYTES)
        .map(|public| {
            let public: &[u8; ONE_TIME_KEY_BYTES] = public
                .try_into()
                .expect("validated v9 bundle has exact prekey chunks");
            prekey_id_for_public(public)
        })
        .collect())
}

fn selected_prekey_public<'a>(public_key: &'a [u8], prekey_id: &str) -> Result<&'a [u8], String> {
    validate_identity_public_bundle(public_key, Some(prekey_id))?;
    public_key[ONE_TIME_KEY_OFFSET..FALLBACK_KEY_OFFSET]
        .chunks_exact(ONE_TIME_KEY_BYTES)
        .find(|public| {
            <&[u8; ONE_TIME_KEY_BYTES]>::try_from(*public)
                .is_ok_and(|key| prekey_id_for_public(key) == prekey_id)
        })
        .ok_or_else(|| "Recipient unavailable".to_string())
}

fn validate_identifier(identifier: &[u8]) -> Result<(), String> {
    if !identifier.is_empty() && identifier.len() <= MAX_CONTEXT_BYTES {
        Ok(())
    } else {
        Err("Wrong information".to_string())
    }
}

fn validate_username(username: &str) -> Result<(), String> {
    if !username.is_empty()
        && username.len() <= 80
        && username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        Ok(())
    } else {
        Err("Recipient unavailable".to_string())
    }
}

fn validate_message_context(chat_id: &str, message_id: &str, sender: &str) -> Result<(), String> {
    if !valid_context_identifier(chat_id) || !valid_context_identifier(message_id) {
        return Err("Payload unavailable".to_string());
    }
    validate_username(sender)
}

fn valid_context_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn valid_node_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

fn protocol_error<E: core::fmt::Debug>(_: E) -> String {
    "Wrong information".to_string()
}

#[cfg(target_arch = "wasm32")]
fn js_error(error: impl core::fmt::Display) -> JsValue {
    JsValue::from_str(&error.to_string())
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = opaqueClientStart)]
pub fn wasm_opaque_client_start(password: Vec<u8>) -> Result<String, JsValue> {
    let result = opaque_client_start(password).map_err(js_error)?;
    serde_json::to_string(&result).map_err(|_| js_error("Wrong information".to_string()))
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = conversationSafetyNumber)]
pub fn wasm_conversation_safety_number(
    first_public_key: Vec<u8>,
    second_public_key: Vec<u8>,
) -> Result<String, JsValue> {
    conversation_safety_number(first_public_key, second_public_key).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = conversationVerificationToken)]
pub fn wasm_conversation_verification_token(
    node_id: String,
    chat_id: String,
    first_username: String,
    first_public_key: Vec<u8>,
    second_username: String,
    second_public_key: Vec<u8>,
) -> Result<String, JsValue> {
    conversation_verification_token(
        node_id,
        chat_id,
        first_username,
        first_public_key,
        second_username,
        second_public_key,
    )
    .map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = encryptAttachment)]
pub fn wasm_encrypt_attachment(
    chat_id: String,
    message_id: String,
    sender_username: String,
    media_type: String,
    plaintext: Vec<u8>,
) -> Result<String, JsValue> {
    let result = encrypt_attachment(chat_id, message_id, sender_username, media_type, plaintext)
        .map_err(js_error)?;
    serde_json::to_string(&result).map_err(|_| js_error("Payload unavailable".to_string()))
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = decryptAttachment)]
pub fn wasm_decrypt_attachment(
    chat_id: String,
    message_id: String,
    sender_username: String,
    media_type: String,
    key: Vec<u8>,
    blob: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    decrypt_attachment(chat_id, message_id, sender_username, media_type, key, blob)
        .map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = opaqueClientFinishRegistration)]
pub fn wasm_opaque_client_finish_registration(
    password: Vec<u8>,
    registration_state: Vec<u8>,
    registration_response: Vec<u8>,
) -> Result<String, JsValue> {
    let result =
        opaque_client_finish_registration(password, registration_state, registration_response)
            .map_err(js_error)?;
    serde_json::to_string(&result).map_err(|_| js_error("Wrong information".to_string()))
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = opaqueClientFinishLogin)]
pub fn wasm_opaque_client_finish_login(
    password: Vec<u8>,
    login_state: Vec<u8>,
    credential_response: Vec<u8>,
) -> Result<String, JsValue> {
    let result =
        opaque_client_finish_login(password, login_state, credential_response).map_err(js_error)?;
    serde_json::to_string(&result).map_err(|_| js_error("Wrong information".to_string()))
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub struct WasmE2eeSession {
    inner: Arc<E2eeSession>,
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
impl WasmE2eeSession {
    #[wasm_bindgen(js_name = create)]
    pub fn wasm_create(export_key: Vec<u8>) -> Result<WasmE2eeSession, JsValue> {
        Ok(Self {
            inner: E2eeSession::create(export_key).map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = recover)]
    pub fn wasm_recover(
        export_key: Vec<u8>,
        context: Vec<u8>,
        envelope: Vec<u8>,
        expected_public_key: Vec<u8>,
    ) -> Result<WasmE2eeSession, JsValue> {
        Ok(Self {
            inner: E2eeSession::recover(export_key, context, envelope, expected_public_key)
                .map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = mlsCreateRoom)]
    pub fn wasm_mls_create_room(
        &self,
        room_id: String,
        username: String,
        node_context: Vec<u8>,
        group_id: Vec<u8>,
    ) -> Result<WasmMlsRoom, JsValue> {
        self.inner
            .create_mls_room(room_id, username, node_context, group_id)
            .map(WasmMlsRoom::from_inner)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = mlsRecoverRoom)]
    #[allow(clippy::too_many_arguments)]
    pub fn wasm_mls_recover_room(
        &self,
        room_id: String,
        username: String,
        node_context: Vec<u8>,
        group_id: Vec<u8>,
        envelope: Vec<u8>,
        expected_active: bool,
        expected_epoch: u64,
        expected_revision: u64,
        expected_members_json: String,
        expected_digest: Vec<u8>,
    ) -> Result<WasmMlsRoom, JsValue> {
        let expected_members = crate::mls_protocol::parse_roster_json(&expected_members_json)?;
        self.inner
            .recover_mls_room(
                room_id,
                username,
                node_context,
                group_id,
                envelope,
                expected_active,
                expected_epoch,
                expected_revision,
                expected_members,
                expected_digest,
            )
            .map(WasmMlsRoom::from_inner)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = mlsPendingJoin)]
    pub fn wasm_mls_pending_join(
        &self,
        room_id: String,
        username: String,
        node_context: Vec<u8>,
        group_id: Vec<u8>,
    ) -> Result<WasmMlsRoom, JsValue> {
        self.inner
            .pending_mls_join(room_id, username, node_context, group_id)
            .map(WasmMlsRoom::from_inner)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = publicKey)]
    pub fn wasm_public_key(&self) -> Vec<u8> {
        self.inner.public_key()
    }

    #[wasm_bindgen(js_name = prekeyId)]
    pub fn wasm_prekey_id(&self) -> String {
        self.inner.prekey_id()
    }

    #[wasm_bindgen(js_name = requiresPrekey)]
    pub fn wasm_requires_prekey(&self, peer: String) -> Result<bool, JsValue> {
        self.inner.requires_prekey(peer).map_err(js_error)
    }

    #[wasm_bindgen(js_name = signAcknowledgement)]
    pub fn wasm_sign_acknowledgement(
        &self,
        chat_id: String,
        message_id: String,
        original_sender_username: String,
        used_prekey_id: String,
    ) -> Result<Vec<u8>, JsValue> {
        self.inner
            .sign_acknowledgement(
                chat_id,
                message_id,
                original_sender_username,
                used_prekey_id,
            )
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = signRegistrationIdentityProof)]
    #[allow(clippy::too_many_arguments)]
    pub fn wasm_sign_registration_identity_proof(
        &self,
        node_id: String,
        handshake_id: String,
        challenge: Vec<u8>,
        registration_upload: Vec<u8>,
        identity_public: Vec<u8>,
        prekey_id: String,
        identity_envelope: Vec<u8>,
    ) -> Result<Vec<u8>, JsValue> {
        self.inner
            .sign_registration_identity_proof(
                node_id,
                handshake_id,
                challenge,
                registration_upload,
                identity_public,
                prekey_id,
                identity_envelope,
            )
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = sealIdentity)]
    pub fn wasm_seal_identity(
        &self,
        export_key: Vec<u8>,
        context: Vec<u8>,
    ) -> Result<Vec<u8>, JsValue> {
        self.inner
            .seal_identity(export_key, context)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = commitOutbound)]
    pub fn wasm_commit_outbound(&self, message_id: String, revision: u64) -> Result<(), JsValue> {
        self.inner
            .commit_outbound(message_id, revision)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = rollbackOutbound)]
    pub fn wasm_rollback_outbound(&self, message_id: String, revision: u64) -> Result<(), JsValue> {
        self.inner
            .rollback_outbound(message_id, revision)
            .map_err(js_error)
    }

    pub fn encrypt(
        &self,
        chat_id: String,
        message_id: String,
        sender_username: String,
        plaintext: Vec<u8>,
        recipients_json: String,
    ) -> Result<String, JsValue> {
        let recipients: Vec<RecipientPublicKey> = serde_json::from_str(&recipients_json)
            .map_err(|_| js_error("Recipient unavailable".to_string()))?;
        let result = self
            .inner
            .encrypt(chat_id, message_id, sender_username, plaintext, recipients)
            .map_err(js_error)?;
        serde_json::to_string(&result).map_err(|_| js_error("Payload unavailable".to_string()))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn decrypt(
        &self,
        chat_id: String,
        message_id: String,
        sender_username: String,
        sender_public_key: Vec<u8>,
        version: u32,
        identity_public: Vec<u8>,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        signature: Vec<u8>,
        wrapped_key: Vec<u8>,
        recipient_prekey_id: String,
        is_prekey: bool,
        recipient_username: String,
    ) -> Result<String, JsValue> {
        let result = self
            .inner
            .decrypt(
                chat_id,
                message_id,
                sender_username,
                sender_public_key,
                version,
                identity_public,
                nonce,
                ciphertext,
                signature,
                wrapped_key,
                recipient_prekey_id,
                is_prekey,
                recipient_username,
            )
            .map_err(js_error)?;
        serde_json::to_string(&result).map_err(|_| js_error("Payload unavailable".to_string()))
    }
}

#[cfg(test)]
impl E2eeSession {
    fn encrypt_for_test(
        &self,
        chat_id: String,
        message_id: String,
        sender_username: String,
        plaintext: Vec<u8>,
        recipients: Vec<RecipientPublicKey>,
    ) -> Result<E2eePayload, AbyssalError> {
        let payload = self.encrypt(chat_id, message_id, sender_username, plaintext, recipients)?;
        self.commit_outbound(payload.message_id.clone(), payload.state_revision)?;
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealed_session(fill: u8) -> Arc<E2eeSession> {
        let export_key = vec![fill; 64];
        let context = format!("node:INVITE-CODE-{fill:04}").into_bytes();
        let session = E2eeSession::create(export_key.clone()).expect("identity");
        session
            .seal_identity(export_key, context)
            .expect("seal identity");
        session
    }

    fn decrypt_payload(
        session: &E2eeSession,
        payload: &E2eePayload,
        chat_id: &str,
        sender_username: &str,
        sender_public_key: Vec<u8>,
        recipient_username: &str,
    ) -> Result<E2eeDecryption, AbyssalError> {
        let envelope = payload
            .envelopes
            .iter()
            .find(|envelope| envelope.username == recipient_username)
            .ok_or_else(|| AbyssalError::from("Payload unavailable".to_string()))?;
        session.decrypt(
            chat_id.to_string(),
            payload.message_id.clone(),
            sender_username.to_string(),
            sender_public_key,
            payload.version,
            payload.identity_public.clone(),
            payload.nonce.clone(),
            payload.ciphertext.clone(),
            envelope.signature.clone(),
            envelope.wrapped_key.clone(),
            envelope.prekey_id.clone(),
            envelope.is_prekey,
            recipient_username.to_string(),
        )
    }

    #[test]
    fn protocol_v9_bundle_is_exact_canonical_pool_and_v8_shapes_fail_closed() {
        let session = sealed_session(91);
        let public = session.public_key();
        let ids = prekey_ids_from_identity_public_v9(&public).expect("canonical v9 pool");
        assert_eq!(public.len(), IDENTITY_PUBLIC_BYTES_V9);
        assert_eq!(ids.len(), PREKEY_POOL_SIZE_V9);
        assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(session.prekey_id(), ids[0]);

        let v8_sized = &public[..IDENTITY_FINGERPRINT_BYTES + ONE_TIME_KEY_BYTES + 32];
        assert!(validate_identity_public_bundle(v8_sized, None).is_err());
        assert!(prekey_ids_from_identity_public_v9(v8_sized).is_err());

        let export_key = vec![91; 64];
        let context = b"node:INVITE-CODE-0091".to_vec();
        let mut v8_envelope = session
            .seal_identity(export_key.clone(), context.clone())
            .expect("v9 state");
        v8_envelope[0] = 4;
        assert!(E2eeSession::recover(export_key, context, v8_envelope, public).is_err());
    }

    #[test]
    fn sealed_pool_must_equal_account_material_and_requires_prekey_fails_closed() {
        let alice = sealed_session(92);
        let bob = sealed_session(93);
        {
            let state = bob.state.lock().expect("Bob state");
            validate_account_prekey_material(&state.account.pickle(), &state.prekeys)
                .expect("exact account material");
            let mut tampered = state.prekeys.clone();
            tampered[0].public[0] ^= 1;
            assert!(validate_account_prekey_material(&state.account.pickle(), &tampered).is_err());
        }
        assert!(alice
            .requires_prekey("Bob".to_string())
            .expect("initial state"));
        let staged = alice
            .encrypt(
                "dm_alice_bob".to_string(),
                "requires-prekey-pending".to_string(),
                "Alice".to_string(),
                b"hello".to_vec(),
                vec![RecipientPublicKey {
                    username: "Bob".to_string(),
                    public_key: bob.public_key(),
                    prekey_id: bob.prekey_id(),
                }],
            )
            .expect("stage outbound");
        assert!(alice.requires_prekey("Bob".to_string()).is_err());
        alice
            .rollback_outbound(staged.message_id, staged.state_revision)
            .expect("exact rollback");
        assert!(alice
            .requires_prekey("Bob".to_string())
            .expect("rolled back"));

        let incoming = alice
            .encrypt_for_test(
                "dm_alice_bob".to_string(),
                "requires-prekey-reciprocal".to_string(),
                "Alice".to_string(),
                b"hello again".to_vec(),
                vec![RecipientPublicKey {
                    username: "Bob".to_string(),
                    public_key: bob.public_key(),
                    prekey_id: bob.prekey_id(),
                }],
            )
            .expect("outbound");
        decrypt_payload(
            &bob,
            &incoming,
            "dm_alice_bob",
            "Alice",
            alice.public_key(),
            "Bob",
        )
        .expect("inbound session");
        assert!(!bob
            .requires_prekey("Alice".to_string())
            .expect("established"));
    }

    fn opaque_registration_and_login(password: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let setup = opaque_server_setup();
        let start = opaque_client_start(password.to_vec()).expect("client start");
        let response = opaque_server_registration_response(
            &setup,
            &start.registration_request,
            b"INVITE-CODE-1234",
        )
        .expect("registration response");
        let finish = opaque_client_finish_registration(
            password.to_vec(),
            start.registration_state,
            response,
        )
        .expect("client registration finish");
        let password_file = opaque_server_finish_registration(&finish.registration_upload)
            .expect("server registration finish");

        let login_start = opaque_client_start(password.to_vec()).expect("login start");
        let (server_state, login_response) = opaque_server_start_login(
            &setup,
            &password_file,
            &login_start.credential_request,
            b"INVITE-CODE-1234",
        )
        .expect("server login start");
        let login_finish =
            opaque_client_finish_login(password.to_vec(), login_start.login_state, login_response)
                .expect("client login finish");
        opaque_server_finish_login(&server_state, &login_finish.credential_finalization)
            .expect("server login finish");
        (finish.export_key, login_finish.export_key)
    }

    #[test]
    fn opaque_password_never_crosses_protocol_and_export_key_recovers() {
        let (registered_export, login_export) =
            opaque_registration_and_login(b"correct horse battery staple");
        assert_eq!(registered_export, login_export);
    }

    #[test]
    fn safety_number_is_symmetric_and_key_bound() {
        let alice = E2eeSession::create(vec![1; 64]).expect("alice");
        let bob = E2eeSession::create(vec![2; 64]).expect("bob");
        let eve = E2eeSession::create(vec![3; 64]).expect("eve");
        let alice_bob = conversation_safety_number(alice.public_key(), bob.public_key())
            .expect("safety number");
        assert_eq!(
            alice_bob,
            conversation_safety_number(bob.public_key(), alice.public_key())
                .expect("symmetric safety number")
        );
        assert_ne!(
            alice_bob,
            conversation_safety_number(alice.public_key(), eve.public_key())
                .expect("different safety number")
        );
    }

    #[test]
    fn verification_token_is_symmetric_and_binds_the_complete_direct_context() {
        let alice = E2eeSession::create(vec![1; 64]).expect("alice");
        let bob = E2eeSession::create(vec![2; 64]).expect("bob");
        let eve = E2eeSession::create(vec![3; 64]).expect("eve");
        let expected = conversation_verification_token(
            "abyssal-node:1".to_string(),
            "dm_alice_bob".to_string(),
            "Alice".to_string(),
            alice.public_key(),
            "Bob".to_string(),
            bob.public_key(),
        )
        .expect("verification token");
        assert!(expected.starts_with("abyssal:verify:v1:"));
        assert_eq!(expected.len(), "abyssal:verify:v1:".len() + 43);
        assert_eq!(
            expected,
            conversation_verification_token(
                "abyssal-node:1".to_string(),
                "dm_alice_bob".to_string(),
                "bob".to_string(),
                bob.public_key(),
                "ALICE".to_string(),
                alice.public_key(),
            )
            .expect("symmetric verification token")
        );

        let changed_inputs = [
            conversation_verification_token(
                "abyssal-node:2".to_string(),
                "dm_alice_bob".to_string(),
                "Alice".to_string(),
                alice.public_key(),
                "Bob".to_string(),
                bob.public_key(),
            ),
            conversation_verification_token(
                "abyssal-node:1".to_string(),
                "dm_alice_eve".to_string(),
                "Alice".to_string(),
                alice.public_key(),
                "Eve".to_string(),
                eve.public_key(),
            ),
        ];
        for changed in changed_inputs {
            assert_ne!(expected, changed.expect("changed verification token"));
        }
    }

    #[test]
    fn verification_token_rejects_ambiguous_or_malformed_context() {
        let alice = E2eeSession::create(vec![1; 64]).expect("alice");
        let bob = E2eeSession::create(vec![2; 64]).expect("bob");
        let valid = || {
            (
                "abyssal-node:1".to_string(),
                "dm_alice_bob".to_string(),
                "Alice".to_string(),
                alice.public_key(),
                "Bob".to_string(),
                bob.public_key(),
            )
        };
        let (_, chat, first_name, first_key, second_name, second_key) = valid();
        assert!(conversation_verification_token(
            "node/invalid".to_string(),
            chat,
            first_name,
            first_key,
            second_name,
            second_key,
        )
        .is_err());

        let (node, chat, first_name, first_key, _, second_key) = valid();
        assert!(conversation_verification_token(
            node,
            chat,
            first_name,
            first_key,
            "alice".to_string(),
            second_key,
        )
        .is_err());

        let (node, chat, first_name, first_key, second_name, _) = valid();
        assert!(conversation_verification_token(
            node,
            chat,
            first_name,
            first_key,
            second_name,
            vec![0; IDENTITY_PUBLIC_BYTES],
        )
        .is_err());
    }

    #[test]
    fn mls_account_root_is_deterministic_and_domain_separated() {
        let first = derive_mls_root(&[7_u8; 64]).expect("MLS root");
        let repeat = derive_mls_root(&[7_u8; 64]).expect("same MLS root");
        let second = derive_mls_root(&[8_u8; 64]).expect("different MLS root");
        assert_eq!(first, repeat);
        assert_ne!(first, second);
        assert_ne!(first.as_slice(), &[7_u8; 64][..32]);
    }

    #[test]
    fn recovered_account_can_recover_its_mls_room() {
        let export_key = vec![73_u8; 64];
        let context = b"node:MLS-RECOVERY".to_vec();
        let session = E2eeSession::create(export_key.clone()).expect("account");
        let identity_envelope = session
            .seal_identity(export_key.clone(), context.clone())
            .expect("identity envelope");
        let room = session
            .create_mls_room(
                "recovered-room".to_string(),
                "alice".to_string(),
                b"node=local".to_vec(),
                vec![19_u8; 32],
            )
            .expect("MLS room");
        let info = room.room_info().expect("room info");
        let envelope = room.seal_state().expect("room envelope");
        let recovered =
            E2eeSession::recover(export_key, context, identity_envelope, session.public_key())
                .expect("recovered account");
        let recovered_room = recovered
            .recover_mls_room(
                "recovered-room".to_string(),
                "alice".to_string(),
                b"node=local".to_vec(),
                vec![19_u8; 32],
                envelope,
                true,
                info.epoch,
                info.revision,
                vec![crate::mls_protocol::MlsRosterMember {
                    username: "alice".to_string(),
                    stable_identity: session.public_key()[..64].to_vec(),
                }],
                info.membership_digest.clone(),
            )
            .expect("recovered MLS room");
        assert_eq!(recovered_room.room_info().expect("recovered info"), info);
    }

    #[test]
    fn mls_recovery_is_bound_to_export_key_and_context() {
        let export_key = vec![76_u8; 64];
        let wrong_export_key = vec![77_u8; 64];
        let context = b"node:MLS-BOUND".to_vec();
        let identity = E2eeSession::create(export_key.clone()).expect("account");
        let identity_envelope = identity
            .seal_identity(export_key.clone(), context.clone())
            .expect("identity envelope");
        let expected_public_key = identity.public_key();

        let wrong_key = match E2eeSession::recover(
            wrong_export_key,
            context.clone(),
            identity_envelope.clone(),
            expected_public_key.clone(),
        ) {
            Ok(_) => panic!("a different OPAQUE export key recovered the account"),
            Err(error) => error,
        };
        assert_eq!(wrong_key.to_string(), "Identity unavailable");

        let wrong_context = match E2eeSession::recover(
            export_key.clone(),
            b"node:MLS-OTHER".to_vec(),
            identity_envelope.clone(),
            expected_public_key.clone(),
        ) {
            Ok(_) => panic!("a different OPAQUE context recovered the account"),
            Err(error) => error,
        };
        assert_eq!(wrong_context.to_string(), "Identity unavailable");

        let mut wrong_public_key = expected_public_key.clone();
        wrong_public_key[0] ^= 1;
        let wrong_public =
            match E2eeSession::recover(export_key, context, identity_envelope, wrong_public_key) {
                Ok(_) => panic!("a detached public identity recovered the account"),
                Err(error) => error,
            };
        assert_eq!(wrong_public.to_string(), "Identity unavailable");
    }

    #[test]
    fn mls_room_is_revoked_when_account_session_drops() {
        let room = {
            let session = E2eeSession::create(vec![74_u8; 64]).expect("account");
            session
                .create_mls_room(
                    "stale-room".to_string(),
                    "alice".to_string(),
                    b"node=local".to_vec(),
                    vec![20_u8; 32],
                )
                .expect("MLS room")
        };
        assert!(room.room_info().is_err());
        assert!(room.key_package().is_err());
        assert!(room.seal_state().is_err());
    }

    #[test]
    fn failed_mls_factory_returns_no_room_handle() {
        let session = E2eeSession::create(vec![75_u8; 64]).expect("account");
        let result = session.create_mls_room(
            "invalid room".to_string(),
            "alice".to_string(),
            b"node=local".to_vec(),
            vec![21_u8; 32],
        );
        assert!(result.is_err());
    }

    #[test]
    fn invalid_mls_factory_inputs_do_not_advance_account_or_leak_material() {
        let session = E2eeSession::create(vec![78_u8; 64]).expect("account");
        let before = session.public_key();

        let invalid_room = session.create_mls_room(
            "invalid room".to_string(),
            "alice".to_string(),
            b"node=local".to_vec(),
            vec![79_u8; 32],
        );
        let invalid_room_error = match invalid_room {
            Ok(_) => panic!("invalid room was accepted"),
            Err(error) => error,
        };
        assert_eq!(invalid_room_error.to_string(), "Room unavailable");

        let invalid_username = session.create_mls_room(
            "valid-room".to_string(),
            "alice/attacker".to_string(),
            b"node=local".to_vec(),
            vec![79_u8; 32],
        );
        let invalid_username_error = match invalid_username {
            Ok(_) => panic!("invalid username was accepted"),
            Err(error) => error,
        };
        assert_eq!(invalid_username_error.to_string(), "Identity unavailable");

        let invalid_context = session.create_mls_room(
            "valid-room".to_string(),
            "alice".to_string(),
            vec![0xff],
            vec![79_u8; 32],
        );
        let invalid_context_error = match invalid_context {
            Ok(_) => panic!("invalid context was accepted"),
            Err(error) => error,
        };
        assert_eq!(invalid_context_error.to_string(), "Identity unavailable");

        let invalid_group = session.create_mls_room(
            "valid-room".to_string(),
            "alice".to_string(),
            b"node=local".to_vec(),
            vec![79_u8; 31],
        );
        let invalid_group_error = match invalid_group {
            Ok(_) => panic!("invalid group id was accepted"),
            Err(error) => error,
        };
        assert_eq!(invalid_group_error.to_string(), "Identity unavailable");

        assert_eq!(session.public_key(), before);
        let room = session
            .create_mls_room(
                "valid-room".to_string(),
                "alice".to_string(),
                b"node=local".to_vec(),
                vec![79_u8; 32],
            )
            .expect("a valid factory call remains usable");
        assert_eq!(room.room_info().expect("room info").member_count, 1);
    }

    #[test]
    fn poisoned_account_lifetime_fails_closed() {
        let session = E2eeSession::create(vec![129_u8; 64]).expect("account");
        let room = session
            .create_mls_room(
                "poisoned-lifetime-room".to_string(),
                "alice".to_string(),
                b"node=local".to_vec(),
                vec![130_u8; 32],
            )
            .expect("room");
        let lifetime = session.account_lifetime.clone();
        let lifetime_thread = std::thread::spawn(move || {
            let _guard = lifetime.gate.write().expect("lifetime write lock");
            panic!("poison lifetime lock for fail-closed test");
        });
        assert!(lifetime_thread.join().is_err());
        assert!(room.room_info().is_err());
        assert!(room.key_package().is_err());
        assert!(room.seal_state().is_err());
    }

    #[test]
    fn opaque_rejects_wrong_password() {
        let setup = opaque_server_setup();
        let registration = opaque_client_start(b"correct-password".to_vec()).expect("start");
        let response = opaque_server_registration_response(
            &setup,
            &registration.registration_request,
            b"INVITE-CODE-1234",
        )
        .expect("response");
        let finish = opaque_client_finish_registration(
            b"correct-password".to_vec(),
            registration.registration_state,
            response,
        )
        .expect("finish");
        let file = opaque_server_finish_registration(&finish.registration_upload).expect("file");
        let wrong = opaque_client_start(b"wrong-password".to_vec()).expect("wrong start");
        let (_, response) = opaque_server_start_login(
            &setup,
            &file,
            &wrong.credential_request,
            b"INVITE-CODE-1234",
        )
        .expect("server start");
        assert!(opaque_client_finish_login(
            b"wrong-password".to_vec(),
            wrong.login_state,
            response,
        )
        .is_err());
    }

    #[test]
    fn stored_prekey_bundle_requires_a_nonempty_commitment() {
        let public_key = [7_u8; ONE_TIME_KEY_BYTES];
        let prekey_id = prekey_id_for_public(&public_key);
        assert!(validate_prekey_bundle(&prekey_id, &public_key).is_ok());
        assert!(validate_prekey_bundle("", &[0_u8; ONE_TIME_KEY_BYTES]).is_err());
        assert!(validate_prekey_bundle("", &public_key).is_err());
        assert!(validate_prekey_bundle("not-the-commitment", &public_key).is_err());
    }

    #[test]
    fn identity_bundle_rejects_malformed_long_term_and_fallback_keys() {
        let session = E2eeSession::create(vec![61; 64]).expect("identity");
        let public_key = session.public_key();
        assert!(validate_identity_public_bundle(&public_key, Some(&session.prekey_id())).is_ok());

        let mut zero_curve = public_key.clone();
        zero_curve[..32].fill(0);
        assert!(validate_identity_public_bundle(&zero_curve, None).is_err());

        let mut low_order_curve = public_key.clone();
        low_order_curve[..32].fill(0);
        low_order_curve[0] = 1;
        assert!(validate_identity_public_bundle(&low_order_curve, None).is_err());

        let mut low_order_one_time = public_key.clone();
        low_order_one_time[ONE_TIME_KEY_OFFSET..FALLBACK_KEY_OFFSET].fill(0);
        low_order_one_time[ONE_TIME_KEY_OFFSET] = 1;
        let mut low_order_one_time_key = [0_u8; ONE_TIME_KEY_BYTES];
        low_order_one_time_key[0] = 1;
        let low_order_prekey = prekey_id_for_public(&low_order_one_time_key);
        assert!(
            validate_identity_public_bundle(&low_order_one_time, Some(&low_order_prekey)).is_err()
        );

        let mut low_order_fallback = public_key.clone();
        low_order_fallback[FALLBACK_KEY_OFFSET..IDENTITY_PUBLIC_BYTES].fill(0);
        low_order_fallback[FALLBACK_KEY_OFFSET] = 1;
        assert!(validate_identity_public_bundle(&low_order_fallback, None).is_err());

        let mut zero_ed = public_key.clone();
        zero_ed[32..IDENTITY_FINGERPRINT_BYTES].fill(0);
        assert!(validate_identity_public_bundle(&zero_ed, None).is_err());

        let mut zero_fallback = public_key.clone();
        zero_fallback[FALLBACK_KEY_OFFSET..IDENTITY_PUBLIC_BYTES].fill(0);
        assert!(validate_identity_public_bundle(&zero_fallback, None).is_err());

        let mut bad_prekey = public_key;
        bad_prekey[ONE_TIME_KEY_OFFSET] ^= 1;
        assert!(validate_identity_public_bundle(&bad_prekey, Some(&session.prekey_id())).is_err());
    }

    #[test]
    fn context_usernames_reject_ambiguous_or_injection_prone_values() {
        assert!(validate_username("Alice_01").is_ok());
        assert!(validate_username("Alice Bob").is_err());
        assert!(validate_username("Alice\nBob").is_err());
        assert!(validate_username("Alice\"Bob").is_err());
        assert!(validate_message_context("room_1", "message-1", "Alice").is_ok());
        assert!(validate_message_context("room 1", "message-1", "Alice").is_err());
        assert!(validate_message_context("room_1", "message 1", "Alice").is_err());
    }

    #[test]
    fn stateless_attachment_aead_binds_context_and_rejects_invalid_blobs() {
        let encrypted = encrypt_attachment(
            "forum_media".to_string(),
            "attachment-1".to_string(),
            "Alice".to_string(),
            "FILE".to_string(),
            b"stateless attachment".to_vec(),
        )
        .expect("attachment encrypt");
        assert_eq!(encrypted.version, u32::from(ATTACHMENT_BLOB_VERSION));
        assert_eq!(encrypted.key.len(), ATTACHMENT_KEY_BYTES);
        assert_eq!(encrypted.blob[0], ATTACHMENT_BLOB_VERSION);
        assert_eq!(
            decrypt_attachment(
                "forum_media".to_string(),
                "attachment-1".to_string(),
                "Alice".to_string(),
                "FILE".to_string(),
                encrypted.key.clone(),
                encrypted.blob.clone(),
            )
            .expect("attachment decrypt"),
            b"stateless attachment"
        );
        assert!(decrypt_attachment(
            "other_forum".to_string(),
            "attachment-1".to_string(),
            "Alice".to_string(),
            "FILE".to_string(),
            encrypted.key.clone(),
            encrypted.blob.clone(),
        )
        .is_err());
        let mut tampered = encrypted.blob.clone();
        tampered[ATTACHMENT_BLOB_HEADER_BYTES] ^= 1;
        assert!(decrypt_attachment(
            "forum_media".to_string(),
            "attachment-1".to_string(),
            "Alice".to_string(),
            "FILE".to_string(),
            encrypted.key.clone(),
            tampered,
        )
        .is_err());
        let mut wrong_version = encrypted.blob.clone();
        wrong_version[0] = 0;
        assert!(decrypt_attachment(
            "forum_media".to_string(),
            "attachment-1".to_string(),
            "Alice".to_string(),
            "FILE".to_string(),
            encrypted.key.clone(),
            wrong_version,
        )
        .is_err());
        assert!(encrypt_attachment(
            "forum_media".to_string(),
            "attachment-1".to_string(),
            "Alice".to_string(),
            "FILE".to_string(),
            Vec::new(),
        )
        .is_err());
        let oversized = vec![0_u8; MAX_ATTACHMENT_PLAINTEXT_BYTES + 1];
        assert!(encrypt_attachment(
            "forum_media".to_string(),
            "attachment-1".to_string(),
            "Alice".to_string(),
            "FILE".to_string(),
            oversized,
        )
        .is_err());
    }

    #[test]
    fn attachment_media_limits_are_enforced_at_boundaries_and_in_aad() {
        assert_eq!(
            attachment_plaintext_limit("IMAGE").unwrap(),
            IMAGE_ATTACHMENT_LIMIT_BYTES
        );
        assert_eq!(
            attachment_plaintext_limit("VIDEO").unwrap(),
            VIDEO_ATTACHMENT_LIMIT_BYTES
        );
        assert_eq!(
            attachment_plaintext_limit("FILE").unwrap(),
            MAX_ATTACHMENT_PLAINTEXT_BYTES
        );
        assert!(attachment_plaintext_limit("AUDIO").is_err());

        let image_at_limit = encrypt_attachment(
            "forum_media".to_string(),
            "image-at-limit".to_string(),
            "Alice".to_string(),
            "IMAGE".to_string(),
            vec![7_u8; IMAGE_ATTACHMENT_LIMIT_BYTES],
        )
        .expect("image at limit encrypt");
        assert_eq!(
            decrypt_attachment(
                "forum_media".to_string(),
                "image-at-limit".to_string(),
                "Alice".to_string(),
                "IMAGE".to_string(),
                image_at_limit.key.clone(),
                image_at_limit.blob.clone(),
            )
            .expect("image at limit decrypt")
            .len(),
            IMAGE_ATTACHMENT_LIMIT_BYTES
        );
        assert!(encrypt_attachment(
            "forum_media".to_string(),
            "image-over-limit".to_string(),
            "Alice".to_string(),
            "IMAGE".to_string(),
            vec![7_u8; IMAGE_ATTACHMENT_LIMIT_BYTES + 1],
        )
        .is_err());
        assert!(encrypt_attachment(
            "forum_media".to_string(),
            "video-over-limit".to_string(),
            "Alice".to_string(),
            "VIDEO".to_string(),
            vec![7_u8; VIDEO_ATTACHMENT_LIMIT_BYTES + 1],
        )
        .is_err());

        assert!(decrypt_attachment(
            "forum_media".to_string(),
            "image-at-limit".to_string(),
            "Alice".to_string(),
            "VIDEO".to_string(),
            image_at_limit.key,
            image_at_limit.blob,
        )
        .is_err());
    }

    #[test]
    fn first_contact_attachment_metadata_ratchet_precedes_blob_decrypt() {
        let alice = sealed_session(61);
        let bob = sealed_session(62);
        let encrypted = encrypt_attachment(
            "dm_alice_bob".to_string(),
            "attachment-1".to_string(),
            "Alice".to_string(),
            "FILE".to_string(),
            b"first contact bytes".to_vec(),
        )
        .expect("attachment encrypt");
        let metadata = alice
            .encrypt_for_test(
                "dm_alice_bob".to_string(),
                "message-attachment-metadata".to_string(),
                "Alice".to_string(),
                b"attachment metadata".to_vec(),
                vec![RecipientPublicKey {
                    username: "Bob".to_string(),
                    public_key: bob.public_key(),
                    prekey_id: bob.prekey_id(),
                }],
            )
            .expect("metadata encrypt");
        let metadata_plain = decrypt_payload(
            &bob,
            &metadata,
            "dm_alice_bob",
            "Alice",
            alice.public_key(),
            "Bob",
        )
        .expect("metadata decrypt");
        assert_eq!(metadata_plain.plaintext, b"attachment metadata");
        assert_eq!(
            decrypt_attachment(
                "dm_alice_bob".to_string(),
                "attachment-1".to_string(),
                "Alice".to_string(),
                "FILE".to_string(),
                encrypted.key,
                encrypted.blob,
            )
            .expect("blob decrypt"),
            b"first contact bytes"
        );
    }

    #[test]
    fn identity_recovery_and_recipient_e2ee_round_trip() {
        let export_key = vec![42; 64];
        let context = b"node:INVITE-CODE-1234".to_vec();
        let alice = E2eeSession::create(export_key.clone()).expect("alice");
        let envelope = alice
            .seal_identity(export_key.clone(), context.clone())
            .expect("seal");
        let recovered = E2eeSession::recover(export_key, context, envelope, alice.public_key())
            .expect("recover");
        assert_eq!(alice.public_key(), recovered.public_key());

        let bob = sealed_session(7);
        let bob_initial_prekey = bob.prekey_id();
        let safety_before = conversation_safety_number(alice.public_key(), bob.public_key())
            .expect("safety number");
        let payload = alice
            .encrypt_for_test(
                "dm_alice_bob".to_string(),
                "message-1".to_string(),
                "Alice".to_string(),
                b"relay cannot read this".to_vec(),
                vec![RecipientPublicKey {
                    username: "Bob".to_string(),
                    public_key: bob.public_key(),
                    prekey_id: bob.prekey_id(),
                }],
            )
            .expect("encrypt");
        assert!(payload.envelopes[0].is_prekey);
        assert_eq!(payload.envelopes[0].prekey_id, bob_initial_prekey);
        assert!(!payload
            .ciphertext
            .windows(b"relay cannot read this".len())
            .any(|window| window == b"relay cannot read this"));
        let plain = decrypt_payload(
            &bob,
            &payload,
            "dm_alice_bob",
            "Alice",
            alice.public_key(),
            "Bob",
        )
        .expect("decrypt");
        assert_eq!(plain.plaintext, b"relay cannot read this");
        assert_ne!(bob.prekey_id(), bob_initial_prekey);
        let bob_rotated_prekey = bob.prekey_id();
        let follow_up = alice
            .encrypt_for_test(
                "dm_alice_bob".to_string(),
                "message-2".to_string(),
                "Alice".to_string(),
                b"new prekey session".to_vec(),
                vec![RecipientPublicKey {
                    username: "Bob".to_string(),
                    public_key: bob.public_key(),
                    prekey_id: bob_rotated_prekey.clone(),
                }],
            )
            .expect("encrypt after recipient prekey rotation");
        assert!(follow_up.envelopes[0].is_prekey);
        assert_eq!(follow_up.envelopes[0].prekey_id, bob_rotated_prekey);
        let follow_up_plain = decrypt_payload(
            &bob,
            &follow_up,
            "dm_alice_bob",
            "Alice",
            alice.public_key(),
            "Bob",
        )
        .expect("decrypt after recipient prekey rotation");
        assert_eq!(follow_up_plain.plaintext, b"new prekey session");
        assert_eq!(
            safety_before,
            conversation_safety_number(alice.public_key(), bob.public_key())
                .expect("stable safety number")
        );
    }

    #[test]
    fn registration_identity_proof_binds_every_registration_field() {
        let export_key = vec![91; 64];
        let context = b"node:INVITE-CODE-1234".to_vec();
        let session = E2eeSession::create(export_key.clone()).expect("identity");
        let identity_envelope = session
            .seal_identity(export_key, context)
            .expect("identity envelope");
        let identity_public = session.public_key();
        let prekey_id = session.prekey_id();
        let challenge = vec![7; REGISTRATION_CHALLENGE_BYTES];
        let upload = vec![8; 64];
        let proof = session
            .sign_registration_identity_proof(
                "node-1".to_string(),
                "11111111-1111-4111-8111-111111111111".to_string(),
                challenge.clone(),
                upload.clone(),
                identity_public.clone(),
                prekey_id.clone(),
                identity_envelope.clone(),
            )
            .expect("registration proof");
        verify_registration_identity_proof_v9(
            "node-1",
            "11111111-1111-4111-8111-111111111111",
            &challenge,
            &upload,
            &identity_public,
            &prekey_id,
            &identity_envelope,
            &proof,
        )
        .expect("valid proof");

        let mut tampered_upload = upload.clone();
        tampered_upload[0] ^= 1;
        assert!(verify_registration_identity_proof_v9(
            "node-1",
            "11111111-1111-4111-8111-111111111111",
            &challenge,
            &tampered_upload,
            &identity_public,
            &prekey_id,
            &identity_envelope,
            &proof,
        )
        .is_err());
        assert!(verify_registration_identity_proof_v9(
            "node-2",
            "11111111-1111-4111-8111-111111111111",
            &challenge,
            &upload,
            &identity_public,
            &prekey_id,
            &identity_envelope,
            &proof,
        )
        .is_err());
        assert!(verify_registration_identity_proof_v9(
            "node-1",
            "11111111-1111-4111-8111-111111111111",
            &challenge,
            &upload,
            &identity_public,
            &prekey_id,
            &identity_envelope,
            &proof[..proof.len() - 1],
        )
        .is_err());
    }

    #[test]
    fn protocol_v9_state_signatures_round_trip_and_reject_tampering() {
        let alice = sealed_session(73);
        let bob = sealed_session(74);
        let payload = alice
            .encrypt_for_test(
                "dm_alice_bob".to_string(),
                "state-signature-message".to_string(),
                "Alice".to_string(),
                b"signed state".to_vec(),
                vec![RecipientPublicKey {
                    username: "Bob".to_string(),
                    public_key: bob.public_key(),
                    prekey_id: bob.prekey_id(),
                }],
            )
            .expect("encrypt");
        assert_eq!(payload.version, PROTOCOL_VERSION);
        assert_eq!(
            payload.state_signature.len(),
            IDENTITY_STATE_SIGNATURE_BYTES
        );
        verify_identity_state_signature_v9(
            payload.version,
            payload.state_revision,
            &payload.identity_envelope,
            &payload.identity_public,
            &payload.prekey_id,
            &payload.state_signature,
        )
        .expect("valid payload state signature");

        let tampered_revision = payload.state_revision + 1;
        assert!(verify_identity_state_signature_v9(
            payload.version,
            tampered_revision,
            &payload.identity_envelope,
            &payload.identity_public,
            &payload.prekey_id,
            &payload.state_signature,
        )
        .is_err());

        let mut tampered_envelope = payload.identity_envelope.clone();
        tampered_envelope[1] ^= 1;
        assert!(verify_identity_state_signature_v9(
            payload.version,
            payload.state_revision,
            &tampered_envelope,
            &payload.identity_public,
            &payload.prekey_id,
            &payload.state_signature,
        )
        .is_err());

        let mut tampered_public = payload.identity_public.clone();
        tampered_public[IDENTITY_FINGERPRINT_BYTES - 1] ^= 1;
        assert!(verify_identity_state_signature_v9(
            payload.version,
            payload.state_revision,
            &payload.identity_envelope,
            &tampered_public,
            &payload.prekey_id,
            &payload.state_signature,
        )
        .is_err());

        let mut tampered_prekey = payload.prekey_id.clone().into_bytes();
        tampered_prekey[0] = if tampered_prekey[0] == b'a' {
            b'b'
        } else {
            b'a'
        };
        let tampered_prekey = String::from_utf8(tampered_prekey).expect("ascii prekey");
        assert!(verify_identity_state_signature_v9(
            payload.version,
            payload.state_revision,
            &payload.identity_envelope,
            &payload.identity_public,
            &tampered_prekey,
            &payload.state_signature,
        )
        .is_err());

        let mut tampered_signature = payload.state_signature.clone();
        tampered_signature[0] ^= 1;
        assert!(verify_identity_state_signature_v9(
            payload.version,
            payload.state_revision,
            &payload.identity_envelope,
            &payload.identity_public,
            &payload.prekey_id,
            &tampered_signature,
        )
        .is_err());

        assert!(identity_state_signature_input_v9(
            PROTOCOL_VERSION - 1,
            payload.state_revision,
            &payload.identity_envelope,
            &payload.identity_public,
            &payload.prekey_id,
        )
        .is_err());
        assert!(identity_state_signature_input_v9(
            PROTOCOL_VERSION,
            0,
            &payload.identity_envelope,
            &payload.identity_public,
            &payload.prekey_id,
        )
        .is_err());
        assert!(identity_state_signature_input_v9(
            PROTOCOL_VERSION,
            payload.state_revision,
            &[IDENTITY_ENVELOPE_VERSION],
            &payload.identity_public,
            &payload.prekey_id,
        )
        .is_err());
        assert!(identity_state_signature_input_v9(
            PROTOCOL_VERSION,
            payload.state_revision,
            &payload.identity_envelope,
            &payload.identity_public[..IDENTITY_PUBLIC_BYTES - 1],
            &payload.prekey_id,
        )
        .is_err());
        assert!(identity_state_signature_input_v9(
            PROTOCOL_VERSION,
            payload.state_revision,
            &payload.identity_envelope,
            &payload.identity_public,
            "",
        )
        .is_err());

        let decrypted = decrypt_payload(
            &bob,
            &payload,
            "dm_alice_bob",
            "Alice",
            alice.public_key(),
            "Bob",
        )
        .expect("decrypt");
        assert_eq!(decrypted.plaintext, b"signed state");
        assert_eq!(
            decrypted.state_signature.len(),
            IDENTITY_STATE_SIGNATURE_BYTES
        );
        verify_identity_state_signature_v9(
            PROTOCOL_VERSION,
            decrypted.state_revision,
            &decrypted.identity_envelope,
            &decrypted.identity_public,
            &decrypted.prekey_id,
            &decrypted.state_signature,
        )
        .expect("valid decryption state signature");
        let used_prekey_id = payload.envelopes[0].prekey_id.as_str();
        let ack_signature = bob
            .sign_acknowledgement(
                "dm_alice_bob".to_string(),
                "state-signature-message".to_string(),
                "Alice".to_string(),
                used_prekey_id.to_string(),
            )
            .expect("sign ACK");
        assert_eq!(ack_signature.len(), IDENTITY_STATE_SIGNATURE_BYTES);
        let verify_ack = |chat_id: &str,
                          message_id: &str,
                          sender_username: &str,
                          used_prekey_id: &str,
                          ack_signature: &[u8]| {
            verify_ack_signature_v9(
                PROTOCOL_VERSION,
                chat_id,
                message_id,
                sender_username,
                used_prekey_id,
                &bob.public_key(),
                ack_signature,
            )
        };
        verify_ack(
            "dm_alice_bob",
            "state-signature-message",
            "Alice",
            used_prekey_id,
            &ack_signature,
        )
        .expect("valid ACK signature");
        assert!(verify_ack(
            "dm_other",
            "state-signature-message",
            "Alice",
            used_prekey_id,
            &ack_signature,
        )
        .is_err());
        assert!(verify_ack(
            "dm_alice_bob",
            "other-message",
            "Alice",
            used_prekey_id,
            &ack_signature,
        )
        .is_err());
        assert!(verify_ack(
            "dm_alice_bob",
            "state-signature-message",
            "Mallory",
            used_prekey_id,
            &ack_signature,
        )
        .is_err());
        assert!(verify_ack(
            "dm_alice_bob",
            "state-signature-message",
            "Alice",
            "wrong-prekey",
            &ack_signature,
        )
        .is_err());
        let mut tampered_ack = ack_signature.clone();
        tampered_ack[0] ^= 1;
        assert!(verify_ack(
            "dm_alice_bob",
            "state-signature-message",
            "Alice",
            used_prekey_id,
            &tampered_ack,
        )
        .is_err());
        // ACK signing is independent of ratchet state.  Advancing state does
        // not change the action proof, so a duplicate can be acknowledged.
        let duplicate_ack = bob
            .sign_acknowledgement(
                "dm_alice_bob".to_string(),
                "state-signature-message".to_string(),
                "Alice".to_string(),
                used_prekey_id.to_string(),
            )
            .expect("sign duplicate ACK");
        assert_eq!(duplicate_ack, ack_signature);
        assert!(ack_signature_input_v9(
            PROTOCOL_VERSION,
            "dm_alice_bob",
            "state-signature-message",
            "Alice",
            used_prekey_id,
        )
        .is_ok());
    }

    #[test]
    fn ratchet_handles_reordering_replay_and_encrypted_state_recovery() {
        let alice = sealed_session(21);
        let bob_export = vec![22; 64];
        let bob_context = b"node:INVITE-CODE-0022".to_vec();
        let bob = E2eeSession::create(bob_export.clone()).expect("bob");
        bob.seal_identity(bob_export.clone(), bob_context.clone())
            .expect("seal bob");
        let recipient = RecipientPublicKey {
            username: "Bob".to_string(),
            public_key: bob.public_key(),
            prekey_id: bob.prekey_id(),
        };
        let first = alice
            .encrypt_for_test(
                "dm_alice_bob".to_string(),
                "message-early".to_string(),
                "Alice".to_string(),
                b"early".to_vec(),
                vec![recipient.clone()],
            )
            .expect("first encrypt");
        let second = alice
            .encrypt_for_test(
                "dm_alice_bob".to_string(),
                "message-late".to_string(),
                "Alice".to_string(),
                b"late".to_vec(),
                vec![recipient.clone()],
            )
            .expect("second encrypt");
        assert_eq!(
            alice
                .state
                .lock()
                .expect("Alice ratchet state")
                .sessions
                .get("bob")
                .and_then(|sessions| sessions.last())
                .expect("Alice-to-Bob session")
                .session_config()
                .version(),
            2
        );

        let late = decrypt_payload(
            &bob,
            &second,
            "dm_alice_bob",
            "Alice",
            alice.public_key(),
            "Bob",
        )
        .expect("late decrypt");
        assert_eq!(late.plaintext, b"late");
        let early = decrypt_payload(
            &bob,
            &first,
            "dm_alice_bob",
            "Alice",
            alice.public_key(),
            "Bob",
        )
        .expect("early decrypt");
        assert_eq!(early.plaintext, b"early");
        assert_eq!(early.state_revision, 2);

        assert!(decrypt_payload(
            &bob,
            &first,
            "dm_alice_bob",
            "Alice",
            alice.public_key(),
            "Bob",
        )
        .is_err());

        let reply = bob
            .encrypt_for_test(
                "dm_alice_bob".to_string(),
                "message-reply".to_string(),
                "Bob".to_string(),
                b"reply".to_vec(),
                vec![RecipientPublicKey {
                    username: "Alice".to_string(),
                    public_key: alice.public_key(),
                    prekey_id: alice.prekey_id(),
                }],
            )
            .expect("reply encrypt");
        let reply_olm: OlmMessage =
            serde_json::from_slice(&reply.envelopes[0].wrapped_key).expect("reply Olm envelope");
        assert!(matches!(reply_olm, OlmMessage::Normal(_)));
        let alice_reply = decrypt_payload(
            &alice,
            &reply,
            "dm_alice_bob",
            "Bob",
            bob.public_key(),
            "Alice",
        )
        .expect("reply decrypt");
        assert_eq!(alice_reply.plaintext, b"reply");

        let restored = E2eeSession::recover(
            bob_export,
            bob_context,
            reply.identity_envelope,
            bob.public_key(),
        )
        .expect("restore ratchet state");
        let third = alice
            .encrypt_for_test(
                "dm_alice_bob".to_string(),
                "message-after-restore".to_string(),
                "Alice".to_string(),
                b"restored".to_vec(),
                vec![recipient],
            )
            .expect("third encrypt");
        let third_olm: OlmMessage =
            serde_json::from_slice(&third.envelopes[0].wrapped_key).expect("third Olm envelope");
        assert!(matches!(third_olm, OlmMessage::Normal(_)));
        let plain = decrypt_payload(
            &restored,
            &third,
            "dm_alice_bob",
            "Alice",
            alice.public_key(),
            "Bob",
        )
        .expect("decrypt after state restore");
        assert_eq!(plain.plaintext, b"restored");
        assert_eq!(plain.state_revision, 4);
    }

    #[test]
    fn decrypt_restores_state_after_outer_aead_failure() {
        let alice = sealed_session(31);
        let bob = sealed_session(32);
        let initial_prekey = bob.prekey_id();
        let initial_public_key = bob.public_key();
        let initial_account = {
            let state = bob.state.lock().expect("initial Bob state");
            serde_json::to_vec(&state.account.pickle()).expect("initial account pickle")
        };
        let recipient = RecipientPublicKey {
            username: "Bob".to_string(),
            public_key: initial_public_key.clone(),
            prekey_id: initial_prekey.clone(),
        };
        let first = alice
            .encrypt_for_test(
                "dm_alice_bob".to_string(),
                "same-message-context".to_string(),
                "Alice".to_string(),
                b"first content key".to_vec(),
                vec![recipient.clone()],
            )
            .expect("first encrypt");
        let second = alice
            .encrypt_for_test(
                "dm_alice_bob".to_string(),
                "same-message-context".to_string(),
                "Alice".to_string(),
                b"second content key".to_vec(),
                vec![recipient],
            )
            .expect("second encrypt");

        let mut tampered_ciphertext = first.clone();
        tampered_ciphertext.ciphertext[0] ^= 1;
        let aad = message_aad("dm_alice_bob", &tampered_ciphertext.message_id, "Alice");
        let signature_input = signature_input_v9(
            PROTOCOL_VERSION,
            &aad,
            &tampered_ciphertext.nonce,
            &tampered_ciphertext.ciphertext,
            &tampered_ciphertext.identity_public,
            &tampered_ciphertext.envelopes[0],
        )
        .expect("tampered signature input");
        tampered_ciphertext.envelopes[0].signature = alice
            .state
            .lock()
            .expect("Alice state")
            .account
            .sign(&signature_input)
            .to_bytes()
            .to_vec();
        assert!(decrypt_payload(
            &bob,
            &tampered_ciphertext,
            "dm_alice_bob",
            "Alice",
            alice.public_key(),
            "Bob",
        )
        .is_err());
        assert_eq!(bob.prekey_id(), initial_prekey);
        assert_eq!(bob.public_key(), initial_public_key);
        {
            let state = bob.state.lock().expect("Bob ratchet state");
            assert_eq!(state.revision, 0);
            assert!(state.sessions.is_empty());
            assert!(state.session_prekeys.is_empty());
            assert_eq!(
                serde_json::to_vec(&state.account.pickle()).expect("restored account pickle"),
                initial_account
            );
        }

        let mut spliced = first.clone();
        spliced.envelopes[0].wrapped_key = second.envelopes[0].wrapped_key.clone();
        spliced.envelopes[0].prekey_id = second.envelopes[0].prekey_id.clone();
        spliced.envelopes[0].is_prekey = second.envelopes[0].is_prekey;
        assert!(decrypt_payload(
            &bob,
            &spliced,
            "dm_alice_bob",
            "Alice",
            alice.public_key(),
            "Bob",
        )
        .is_err());
        assert_eq!(bob.prekey_id(), initial_prekey);
        assert_eq!(bob.public_key(), initial_public_key);
        {
            let state = bob.state.lock().expect("Bob ratchet state");
            assert_eq!(state.revision, 0);
            assert!(state.sessions.is_empty());
            assert!(state.session_prekeys.is_empty());
            assert_eq!(
                serde_json::to_vec(&state.account.pickle()).expect("restored account pickle"),
                initial_account
            );
        }

        let first_plain = decrypt_payload(
            &bob,
            &first,
            "dm_alice_bob",
            "Alice",
            alice.public_key(),
            "Bob",
        )
        .expect("first legitimate payload");
        assert_eq!(first_plain.plaintext, b"first content key");
        let second_plain = decrypt_payload(
            &bob,
            &second,
            "dm_alice_bob",
            "Alice",
            alice.public_key(),
            "Bob",
        )
        .expect("second legitimate payload");
        assert_eq!(second_plain.plaintext, b"second content key");
    }

    #[test]
    fn decrypt_restores_state_after_content_binding_failure() {
        let alice = sealed_session(41);
        let bob = sealed_session(42);
        let initial_prekey = bob.prekey_id();
        let initial_public_key = bob.public_key();
        let recipient = RecipientPublicKey {
            username: "Bob".to_string(),
            public_key: initial_public_key.clone(),
            prekey_id: initial_prekey.clone(),
        };
        let first = alice
            .encrypt_for_test(
                "dm_alice_bob".to_string(),
                "binding-first".to_string(),
                "Alice".to_string(),
                b"binding first".to_vec(),
                vec![recipient.clone()],
            )
            .expect("first encrypt");
        let second = alice
            .encrypt_for_test(
                "dm_alice_bob".to_string(),
                "binding-second".to_string(),
                "Alice".to_string(),
                b"binding second".to_vec(),
                vec![recipient],
            )
            .expect("second encrypt");

        let mut spliced = first.clone();
        spliced.envelopes[0].wrapped_key = second.envelopes[0].wrapped_key.clone();
        spliced.envelopes[0].prekey_id = second.envelopes[0].prekey_id.clone();
        spliced.envelopes[0].is_prekey = second.envelopes[0].is_prekey;
        assert!(decrypt_payload(
            &bob,
            &spliced,
            "dm_alice_bob",
            "Alice",
            alice.public_key(),
            "Bob",
        )
        .is_err());
        assert_eq!(bob.prekey_id(), initial_prekey);
        assert_eq!(bob.public_key(), initial_public_key);
        {
            let state = bob.state.lock().expect("Bob ratchet state");
            assert_eq!(state.revision, 0);
            assert!(state.sessions.is_empty());
            assert!(state.session_prekeys.is_empty());
        }

        let first_plain = decrypt_payload(
            &bob,
            &first,
            "dm_alice_bob",
            "Alice",
            alice.public_key(),
            "Bob",
        )
        .expect("first legitimate payload");
        assert_eq!(first_plain.plaintext, b"binding first");
        let second_plain = decrypt_payload(
            &bob,
            &second,
            "dm_alice_bob",
            "Alice",
            alice.public_key(),
            "Bob",
        )
        .expect("second legitimate payload");
        assert_eq!(second_plain.plaintext, b"binding second");
    }

    #[test]
    fn encrypt_restores_state_after_late_recipient_failure() {
        let alice = sealed_session(51);
        let bob = sealed_session(52);
        let bob_recipient = RecipientPublicKey {
            username: "Bob".to_string(),
            public_key: bob.public_key(),
            prekey_id: bob.prekey_id(),
        };
        let mut invalid_public_key = vec![0_u8; IDENTITY_PUBLIC_BYTES];
        invalid_public_key[ONE_TIME_KEY_OFFSET..FALLBACK_KEY_OFFSET].fill(7);
        let invalid_recipient = RecipientPublicKey {
            username: "Mallory".to_string(),
            prekey_id: prekey_id_for_public(&[7_u8; ONE_TIME_KEY_BYTES]),
            public_key: invalid_public_key,
        };

        assert!(alice
            .encrypt_for_test(
                "dm_alice_bob".to_string(),
                "sender-transaction".to_string(),
                "Alice".to_string(),
                b"discarded".to_vec(),
                vec![bob_recipient.clone(), invalid_recipient],
            )
            .is_err());
        {
            let state = alice.state.lock().expect("Alice ratchet state");
            assert_eq!(state.revision, 0);
            assert!(state.sessions.is_empty());
            assert!(state.session_prekeys.is_empty());
        }

        let payload = alice
            .encrypt_for_test(
                "dm_alice_bob".to_string(),
                "sender-transaction-retry".to_string(),
                "Alice".to_string(),
                b"retry after failed recipient".to_vec(),
                vec![bob_recipient],
            )
            .expect("retry encrypt");
        let plain = decrypt_payload(
            &bob,
            &payload,
            "dm_alice_bob",
            "Alice",
            alice.public_key(),
            "Bob",
        )
        .expect("retry decrypt");
        assert_eq!(plain.plaintext, b"retry after failed recipient");
    }

    #[test]
    fn encrypt_rejects_early_invalid_input_without_advancing_state() {
        let alice = sealed_session(53);
        let initial_prekey = alice.prekey_id();
        let initial_public = alice.public_key();

        // These paths return before ratchet setup. The input is already owned
        // by Zeroizing at function entry, including malformed context and
        // oversized payload exits.
        assert!(alice
            .encrypt_for_test(
                "invalid chat".to_string(),
                "message-early-reject".to_string(),
                "Alice".to_string(),
                b"discarded".to_vec(),
                Vec::new(),
            )
            .is_err());
        assert!(alice
            .encrypt_for_test(
                "forum_early_reject".to_string(),
                "message-empty".to_string(),
                "Alice".to_string(),
                Vec::new(),
                Vec::new(),
            )
            .is_err());
        assert!(alice
            .encrypt_for_test(
                "forum_early_reject".to_string(),
                "message-oversized".to_string(),
                "Alice".to_string(),
                vec![0_u8; MAX_PAYLOAD_BYTES + 1],
                Vec::new(),
            )
            .is_err());

        assert_eq!(alice.public_key(), initial_public);
        let state = alice.state.lock().expect("Alice ratchet state");
        assert_eq!(state.revision, 0);
        assert!(state.sessions.is_empty());
        assert!(state.session_prekeys.is_empty());
        assert_eq!(
            state.prekeys.first().map(|key| key.id.as_str()),
            Some(initial_prekey.as_str())
        );
    }

    #[test]
    fn e2ee_rejects_tamper_wrong_recipient_and_sender_key() {
        let alice = sealed_session(1);
        let bob = sealed_session(2);
        let eve = sealed_session(3);
        let payload = alice
            .encrypt_for_test(
                "forum_one".to_string(),
                "message-1".to_string(),
                "Alice".to_string(),
                b"secret".to_vec(),
                vec![RecipientPublicKey {
                    username: "Bob".to_string(),
                    public_key: bob.public_key(),
                    prekey_id: bob.prekey_id(),
                }],
            )
            .expect("encrypt");
        assert!(decrypt_payload(
            &eve,
            &payload,
            "forum_one",
            "Alice",
            alice.public_key(),
            "Bob",
        )
        .is_err());
        let mut old_version = payload.clone();
        old_version.version = 5;
        assert!(decrypt_payload(
            &bob,
            &old_version,
            "forum_one",
            "Alice",
            alice.public_key(),
            "Bob",
        )
        .is_err());
        let mut mismatched_identity = payload.clone();
        mismatched_identity.identity_public[0] ^= 1;
        assert!(decrypt_payload(
            &bob,
            &mismatched_identity,
            "forum_one",
            "Alice",
            alice.public_key(),
            "Bob",
        )
        .is_err());
        let mut wrong_recipient = payload.clone();
        wrong_recipient.envelopes[0].username = "Mallory".to_string();
        assert!(decrypt_payload(
            &bob,
            &wrong_recipient,
            "forum_one",
            "Alice",
            alice.public_key(),
            "Mallory",
        )
        .is_err());
        let mut wrong_prekey = payload.clone();
        wrong_prekey.envelopes[0].prekey_id = "wrong-prekey".to_string();
        assert!(decrypt_payload(
            &bob,
            &wrong_prekey,
            "forum_one",
            "Alice",
            alice.public_key(),
            "Bob",
        )
        .is_err());
        let mut wrong_mode = payload.clone();
        wrong_mode.envelopes[0].is_prekey = false;
        wrong_mode.envelopes[0].prekey_id.clear();
        assert!(decrypt_payload(
            &bob,
            &wrong_mode,
            "forum_one",
            "Alice",
            alice.public_key(),
            "Bob",
        )
        .is_err());
        let mut tampered = payload.clone();
        tampered.ciphertext[0] ^= 1;
        assert!(decrypt_payload(
            &bob,
            &tampered,
            "forum_one",
            "Alice",
            alice.public_key(),
            "Bob",
        )
        .is_err());
    }

    #[test]
    fn outbound_ratchet_requires_exact_commit_or_rollback() {
        let alice = sealed_session(71);
        let bob = sealed_session(72);
        let recipient = RecipientPublicKey {
            username: "Bob".to_string(),
            public_key: bob.public_key(),
            prekey_id: bob.prekey_id(),
        };
        let bob_to_alice = bob
            .encrypt_for_test(
                "dm_alice_bob".to_string(),
                "bob-before-alice".to_string(),
                "Bob".to_string(),
                b"incoming while pending".to_vec(),
                vec![RecipientPublicKey {
                    username: "Alice".to_string(),
                    public_key: alice.public_key(),
                    prekey_id: alice.prekey_id(),
                }],
            )
            .expect("prepare incoming payload");

        let staged = alice
            .encrypt(
                "dm_alice_bob".to_string(),
                "alice-pending".to_string(),
                "Alice".to_string(),
                b"pending".to_vec(),
                vec![recipient.clone()],
            )
            .expect("stage outbound");
        assert_eq!(staged.state_revision, 1);
        assert!(alice
            .encrypt(
                "dm_alice_bob".to_string(),
                "alice-second".to_string(),
                "Alice".to_string(),
                b"blocked".to_vec(),
                vec![recipient.clone()],
            )
            .is_err());
        assert!(decrypt_payload(
            &alice,
            &bob_to_alice,
            "dm_alice_bob",
            "Bob",
            bob.public_key(),
            "Alice",
        )
        .is_err());
        assert!(alice
            .seal_identity(vec![71; 64], b"node:INVITE-CODE-0071".to_vec(),)
            .is_err());
        assert!(alice
            .commit_outbound("alice-pending".to_string(), 2)
            .is_err());
        assert!(alice
            .rollback_outbound("alice-pending".to_string(), 2)
            .is_err());
        assert!(alice
            .commit_outbound("wrong-message".to_string(), 1)
            .is_err());
        assert!(alice
            .rollback_outbound("wrong-message".to_string(), 1)
            .is_err());
        assert!(alice.commit_outbound(String::new(), 1).is_err());
        assert!(alice.rollback_outbound(String::new(), 1).is_err());
        {
            let state = alice.state.lock().expect("Alice state");
            assert_eq!(state.revision, 1);
            assert!(state.pending_outbound.is_some());
        }

        alice
            .rollback_outbound("alice-pending".to_string(), 1)
            .expect("rollback pending outbound");
        {
            let state = alice.state.lock().expect("Alice state");
            assert_eq!(state.revision, 0);
            assert!(state.pending_outbound.is_none());
            assert!(state.sessions.is_empty());
        }
        let retry = alice
            .encrypt(
                "dm_alice_bob".to_string(),
                "alice-retry".to_string(),
                "Alice".to_string(),
                b"retry".to_vec(),
                vec![recipient],
            )
            .expect("retry after rollback");
        assert_eq!(retry.state_revision, 1);
        alice
            .commit_outbound(retry.message_id.clone(), retry.state_revision)
            .expect("commit retry");
        assert!(alice
            .commit_outbound(retry.message_id.clone(), retry.state_revision)
            .is_err());
        let next = alice
            .encrypt_for_test(
                "dm_alice_bob".to_string(),
                "alice-after-commit".to_string(),
                "Alice".to_string(),
                b"after commit".to_vec(),
                vec![RecipientPublicKey {
                    username: "Bob".to_string(),
                    public_key: bob.public_key(),
                    prekey_id: bob.prekey_id(),
                }],
            )
            .expect("encrypt after commit");
        assert_eq!(next.state_revision, 2);
    }

    #[test]
    fn failed_checkpoint_restore_keeps_the_same_transaction_pending() {
        let alice = sealed_session(81);
        let bob = sealed_session(82);
        let staged = alice
            .encrypt(
                "dm_alice_bob".to_string(),
                "alice-corrupt-checkpoint".to_string(),
                "Alice".to_string(),
                b"pending".to_vec(),
                vec![RecipientPublicKey {
                    username: "Bob".to_string(),
                    public_key: bob.public_key(),
                    prekey_id: bob.prekey_id(),
                }],
            )
            .expect("stage outbound");
        let expected_checkpoint_digest = {
            let mut state = alice.state.lock().expect("Alice state");
            let pending = state.pending_outbound.as_mut().expect("pending outbound");
            pending.checkpoint[0] ^= 1;
            Sha256::digest(&pending.checkpoint)
        };

        assert!(alice
            .rollback_outbound(staged.message_id.clone(), staged.state_revision)
            .is_err());
        let state = alice.state.lock().expect("Alice state");
        let pending = state.pending_outbound.as_ref().expect("pending retained");
        assert_eq!(pending.message_id, staged.message_id);
        assert_eq!(pending.revision, staged.state_revision);
        assert_eq!(
            Sha256::digest(&pending.checkpoint),
            expected_checkpoint_digest
        );
        assert_eq!(state.revision, staged.state_revision);
    }

    #[test]
    fn payload_padding_is_canonical_bucketed_and_randomized() {
        let at_bucket = pad_payload(&vec![3_u8; 250]).expect("250-byte payload");
        let bucket_boundary = pad_payload(&vec![3_u8; 251]).expect("251-byte payload");
        let next_bucket = pad_payload(&vec![3_u8; 252]).expect("252-byte payload");
        assert_eq!(at_bucket.len(), PAYLOAD_PADDING_BUCKET_BYTES);
        assert_eq!(bucket_boundary.len(), PAYLOAD_PADDING_BUCKET_BYTES);
        assert_eq!(next_bucket.len(), PAYLOAD_PADDING_BUCKET_BYTES * 2);
        assert_eq!(unpad_payload(&at_bucket).expect("unpad 250").len(), 250);
        assert_eq!(
            unpad_payload(&bucket_boundary).expect("unpad 251").len(),
            251
        );
        assert_eq!(unpad_payload(&next_bucket).expect("unpad 252").len(), 252);
        // Use a large filler region so the randomization assertion cannot
        // become a practical 1-in-256 test flake at the 251-byte boundary.
        let randomized = pad_payload(&[3_u8]).expect("randomized payload");
        let second = pad_payload(&[3_u8]).expect("second randomized payload");
        assert_ne!(
            &randomized[PAYLOAD_HEADER_BYTES..],
            &second[PAYLOAD_HEADER_BYTES..]
        );
        assert!(pad_payload(&vec![4_u8; MAX_PAYLOAD_BYTES]).is_ok());
        assert!(pad_payload(&vec![4_u8; MAX_PAYLOAD_BYTES + 1]).is_err());
    }

    #[test]
    fn payload_padding_rejects_version_length_and_noncanonical_size() {
        let padded = pad_payload(b"strict payload").expect("pad payload");
        let mut bad_version = padded.to_vec();
        bad_version[0] ^= 1;
        assert!(unpad_payload(&bad_version).is_err());

        let mut bad_length = padded.to_vec();
        bad_length[1..PAYLOAD_HEADER_BYTES].copy_from_slice(&0_u32.to_be_bytes());
        assert!(unpad_payload(&bad_length).is_err());

        let mut noncanonical = padded.to_vec();
        noncanonical.extend_from_slice(&[0_u8; PAYLOAD_PADDING_BUCKET_BYTES]);
        assert!(unpad_payload(&noncanonical).is_err());

        let mut truncated = padded.to_vec();
        truncated.truncate(PAYLOAD_HEADER_BYTES);
        assert!(unpad_payload(&truncated).is_err());
    }

    #[test]
    fn rustcrypto_sha256_and_hkdf_sha256_match_known_answers() {
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&Sha256::digest(b"abc"));
        assert_eq!(
            digest,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );

        // RFC 5869, Appendix A.1 (SHA-256, 42-byte output).
        let ikm = [0x0b_u8; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [
            0xf0_u8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
        ];
        let mut okm = [0_u8; 42];
        Hkdf::<Sha256>::new(Some(&salt), &ikm)
            .expand(&info, &mut okm)
            .expect("RFC 5869 output length is valid");
        assert_eq!(
            okm,
            [
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
            ]
        );
    }
}
