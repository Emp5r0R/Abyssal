use crate::AbyssalError;
use chacha20poly1305::{
    aead::{Aead, Payload},
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
use sha2::{Digest, Sha256, Sha512};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, MutexGuard},
};
use vodozemac::{
    olm::{Account, AccountPickle, OlmMessage, Session, SessionConfig, SessionPickle},
    Curve25519PublicKey, Ed25519PublicKey, Ed25519Signature,
};
use zeroize::{Zeroize, Zeroizing};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

const IDENTITY_FINGERPRINT_BYTES: usize = 64;
const ONE_TIME_KEY_BYTES: usize = 32;
const ONE_TIME_KEY_OFFSET: usize = IDENTITY_FINGERPRINT_BYTES;
const FALLBACK_KEY_OFFSET: usize = ONE_TIME_KEY_OFFSET + ONE_TIME_KEY_BYTES;
const IDENTITY_PUBLIC_BYTES: usize = FALLBACK_KEY_OFFSET + 32;
const NONCE_BYTES: usize = 12;
const MAX_CONTEXT_BYTES: usize = 512;
const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
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
const PROTOCOL_VERSION: u32 = 6;
const IDENTITY_ENVELOPE_VERSION: u8 = 4;

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
}

#[derive(serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct E2eeDecryption {
    pub plaintext: Vec<u8>,
    pub state_revision: u64,
    pub identity_envelope: Vec<u8>,
    pub identity_public: Vec<u8>,
    pub prekey_id: String,
}

#[derive(serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct AttachmentCiphertext {
    pub version: u32,
    pub key: Vec<u8>,
    pub blob: Vec<u8>,
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
    one_time_public: [u8; ONE_TIME_KEY_BYTES],
    one_time_key_id: String,
    account: AccountPickle,
    peers: Vec<StoredPeerSessions>,
    session_prekeys: HashMap<String, String>,
}

struct E2eeState {
    revision: u64,
    fallback_public: [u8; 32],
    one_time_public: [u8; ONE_TIME_KEY_BYTES],
    one_time_key_id: String,
    account: Account,
    sessions: HashMap<String, Vec<Session>>,
    session_prekeys: HashMap<String, String>,
}

struct SealingMaterial {
    key: [u8; 32],
    context: Vec<u8>,
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
    if first_public_key.len() != IDENTITY_PUBLIC_BYTES
        || second_public_key.len() != IDENTITY_PUBLIC_BYTES
    {
        return Err("Identity unavailable".to_string().into());
    }
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
        let mut account = Account::new();
        account.generate_fallback_key();
        account.generate_one_time_keys(1);
        let one_time_public = account
            .one_time_keys()
            .into_iter()
            .next()
            .map(|(_, public)| public.to_bytes())
            .ok_or_else(|| AbyssalError::from("Identity unavailable".to_string()))?;
        let one_time_key_id = prekey_id_for_public(&one_time_public);
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
                one_time_public,
                one_time_key_id,
                account,
                sessions: HashMap::new(),
                session_prekeys: HashMap::new(),
            }),
            sealing: Mutex::new(None),
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
        validate_prekey_bundle(&stored.one_time_key_id, &stored.one_time_public)?;
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
                one_time_public: stored.one_time_public,
                one_time_key_id: stored.one_time_key_id,
                account: Account::from_pickle(stored.account),
                sessions,
                session_prekeys: stored.session_prekeys,
            }),
            sealing: Mutex::new(Some(SealingMaterial { key: *key, context })),
        });
        if session.public_key() != expected_public_key {
            return Err("Identity unavailable".to_string().into());
        }
        Ok(session)
    }

    pub fn public_key(&self) -> Vec<u8> {
        let Ok(state) = self.state.lock() else {
            return Vec::new();
        };
        let identity = state.account.identity_keys();
        let mut result = Vec::with_capacity(IDENTITY_PUBLIC_BYTES);
        result.extend_from_slice(identity.curve25519.as_bytes());
        result.extend_from_slice(identity.ed25519.as_bytes());
        result.extend_from_slice(&state.one_time_public);
        result.extend_from_slice(&state.fallback_public);
        result
    }

    pub fn prekey_id(&self) -> String {
        let Ok(state) = self.state.lock() else {
            return String::new();
        };
        state.one_time_key_id.clone()
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
        *sealing = Some(SealingMaterial { key: *key, context });
        let sealing = sealing
            .as_ref()
            .ok_or_else(|| AbyssalError::from("Identity unavailable".to_string()))?;
        let state = lock(&self.state, "Identity unavailable")?;
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
            if recipient.public_key.len() != IDENTITY_PUBLIC_BYTES
                || recipient.prekey_id.is_empty()
                || validate_prekey_bundle(
                    &recipient.prekey_id,
                    &recipient.public_key[ONE_TIME_KEY_OFFSET..FALLBACK_KEY_OFFSET],
                )
                .is_err()
                || !seen.insert(peer_key(&recipient.username))
            {
                return Err("Recipient unavailable".to_string().into());
            }
        }
        let aad = message_aad(&chat_id, &message_id, &sender_username);
        let mut content_key = Zeroizing::new([0u8; 32]);
        let mut nonce = [0u8; NONCE_BYTES];
        OsRng.fill_bytes(content_key.as_mut());
        OsRng.fill_bytes(&mut nonce);
        let cipher = ChaCha20Poly1305::new_from_slice(content_key.as_ref())
            .map_err(|_| "Payload unavailable".to_string())?;
        let ciphertext_result = cipher.encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        );
        drop(plaintext);
        let ciphertext = ciphertext_result.map_err(|_| "Payload unavailable".to_string())?;

        let sealing = lock(&self.sealing, "Identity unavailable")?;
        let sealing = sealing
            .as_ref()
            .ok_or_else(|| AbyssalError::from("Identity unavailable".to_string()))?;
        let mut state = lock(&self.state, "Identity unavailable")?;
        let checkpoint = checkpoint_state(&state);
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
            let prekey_id = state.one_time_key_id.clone();
            for envelope in &mut envelopes {
                let signature_input = signature_input_v6(
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
            })
        })();
        if result.is_err() {
            restore_state(&mut state, checkpoint);
        }
        result
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
            || sender_public_key.len() != IDENTITY_PUBLIC_BYTES
            || identity_public.len() != IDENTITY_PUBLIC_BYTES
            || nonce.len() != NONCE_BYTES
            || ciphertext.len() > MAX_PAYLOAD_BYTES + 16
            || signature.len() != 64
        {
            return Err("Payload unavailable".to_string().into());
        }
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
        let signature_input = signature_input_v6(
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
        let checkpoint = checkpoint_state(&state);
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
            let mut plaintext = Zeroizing::new(
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
            if used_prekey {
                rotate_one_time_key(&mut state).map_err(AbyssalError::from)?;
            }
            state.revision = state
                .revision
                .checked_add(1)
                .ok_or_else(|| AbyssalError::from("Identity unavailable".to_string()))?;
            let identity_envelope = seal_state(&state, sealing).map_err(AbyssalError::from)?;
            let plaintext = std::mem::take(&mut *plaintext);
            Ok(E2eeDecryption {
                plaintext,
                state_revision: state.revision,
                identity_envelope,
                identity_public: public_key_from_state(&state),
                prekey_id: state.one_time_key_id.clone(),
            })
        })();
        if result.is_err() {
            restore_state(&mut state, checkpoint);
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
        let one_time_key = Curve25519PublicKey::from_slice(
            &recipient_public[ONE_TIME_KEY_OFFSET..FALLBACK_KEY_OFFSET],
        )
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
        one_time_public: state.one_time_public,
        one_time_key_id: state.one_time_key_id.clone(),
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

fn restore_state(state: &mut E2eeState, stored: StoredE2eeState) {
    state.revision = stored.revision;
    state.fallback_public = stored.fallback_public;
    state.one_time_public = stored.one_time_public;
    state.one_time_key_id = stored.one_time_key_id;
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

fn public_key_from_state(state: &E2eeState) -> Vec<u8> {
    let identity = state.account.identity_keys();
    let mut result = Vec::with_capacity(IDENTITY_PUBLIC_BYTES);
    result.extend_from_slice(identity.curve25519.as_bytes());
    result.extend_from_slice(identity.ed25519.as_bytes());
    result.extend_from_slice(&state.one_time_public);
    result.extend_from_slice(&state.fallback_public);
    result
}

fn rotate_one_time_key(state: &mut E2eeState) -> Result<(), String> {
    state.account.generate_one_time_keys(1);
    let public = state
        .account
        .one_time_keys()
        .into_iter()
        .next()
        .map(|(_, public)| public.to_bytes())
        .ok_or_else(|| "Identity unavailable".to_string())?;
    state.account.mark_keys_as_published();
    state.one_time_key_id = prekey_id_for_public(&public);
    state.one_time_public = public;
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

fn identity_wrap_key(export_key: &[u8], context: &[u8]) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(context), export_key)
        .expand(b"ABYSSAL_IDENTITY_WRAP_V3", &mut key)
        .map_err(|_| "Identity unavailable".to_string())?;
    Ok(key)
}

fn message_aad(chat_id: &str, message_id: &str, sender_username: &str) -> Vec<u8> {
    canonical_parts(&[
        b"ABYSSAL_E2EE_PAYLOAD_V6",
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

fn signature_input_v6(
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
        b"ABYSSAL_E2EE_SIGNATURE_V6",
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

fn validate_identifier(identifier: &[u8]) -> Result<(), String> {
    if !identifier.is_empty() && identifier.len() <= MAX_CONTEXT_BYTES {
        Ok(())
    } else {
        Err("Wrong information".to_string())
    }
}

fn validate_username(username: &str) -> Result<(), String> {
    if !username.is_empty() && username.len() <= 80 && username.is_ascii() {
        Ok(())
    } else {
        Err("Recipient unavailable".to_string())
    }
}

fn validate_message_context(chat_id: &str, message_id: &str, sender: &str) -> Result<(), String> {
    if chat_id.is_empty() || chat_id.len() > 128 || message_id.is_empty() || message_id.len() > 128
    {
        return Err("Payload unavailable".to_string());
    }
    validate_username(sender)
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

    #[wasm_bindgen(js_name = publicKey)]
    pub fn wasm_public_key(&self) -> Vec<u8> {
        self.inner.public_key()
    }

    #[wasm_bindgen(js_name = prekeyId)]
    pub fn wasm_prekey_id(&self) -> String {
        self.inner.prekey_id()
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
            .encrypt(
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
            .encrypt(
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
            .encrypt(
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
            .encrypt(
                "dm_alice_bob".to_string(),
                "message-early".to_string(),
                "Alice".to_string(),
                b"early".to_vec(),
                vec![recipient.clone()],
            )
            .expect("first encrypt");
        let second = alice
            .encrypt(
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
            .encrypt(
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
            .encrypt(
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
        let recipient = RecipientPublicKey {
            username: "Bob".to_string(),
            public_key: initial_public_key.clone(),
            prekey_id: initial_prekey.clone(),
        };
        let first = alice
            .encrypt(
                "dm_alice_bob".to_string(),
                "same-message-context".to_string(),
                "Alice".to_string(),
                b"first content key".to_vec(),
                vec![recipient.clone()],
            )
            .expect("first encrypt");
        let second = alice
            .encrypt(
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
        let signature_input = signature_input_v6(
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
            .encrypt(
                "dm_alice_bob".to_string(),
                "binding-first".to_string(),
                "Alice".to_string(),
                b"binding first".to_vec(),
                vec![recipient.clone()],
            )
            .expect("first encrypt");
        let second = alice
            .encrypt(
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
            .encrypt(
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
            .encrypt(
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
            .encrypt(
                "invalid chat".to_string(),
                "message-early-reject".to_string(),
                "Alice".to_string(),
                b"discarded".to_vec(),
                Vec::new(),
            )
            .is_err());
        assert!(alice
            .encrypt(
                "forum_early_reject".to_string(),
                "message-empty".to_string(),
                "Alice".to_string(),
                Vec::new(),
                Vec::new(),
            )
            .is_err());
        assert!(alice
            .encrypt(
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
        assert_eq!(state.one_time_key_id, initial_prekey);
    }

    #[test]
    fn e2ee_rejects_tamper_wrong_recipient_and_sender_key() {
        let alice = sealed_session(1);
        let bob = sealed_session(2);
        let eve = sealed_session(3);
        let payload = alice
            .encrypt(
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
}
