use crate::AbyssalError;
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
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
const IDENTITY_PUBLIC_BYTES: usize = IDENTITY_FINGERPRINT_BYTES + 32;
const NONCE_BYTES: usize = 12;
const MAX_CONTEXT_BYTES: usize = 512;
const MAX_PAYLOAD_BYTES: usize = 220 * 1024 * 1024;
const MAX_IDENTITY_STATE_BYTES: usize = 512 * 1024;
const MAX_RATCHET_ENVELOPE_BYTES: usize = 4096;
const MAX_PEERS: usize = 256;
const MAX_SESSIONS_PER_PEER: usize = 4;
const PROTOCOL_VERSION: u32 = 4;
const IDENTITY_ENVELOPE_VERSION: u8 = 2;

pub struct AbyssalOpaqueSuite;

impl CipherSuite for AbyssalOpaqueSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, Sha512>;
    type Ksf = Argon2<'static>;
}

#[derive(Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct OpaqueClientStart {
    pub registration_state: Vec<u8>,
    pub registration_request: Vec<u8>,
    pub login_state: Vec<u8>,
    pub credential_request: Vec<u8>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct OpaqueRegistrationFinish {
    pub registration_upload: Vec<u8>,
    pub export_key: Vec<u8>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct OpaqueLoginFinish {
    pub credential_finalization: Vec<u8>,
    pub export_key: Vec<u8>,
    pub session_key: Vec<u8>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct RecipientPublicKey {
    pub username: String,
    pub public_key: Vec<u8>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct RecipientEnvelope {
    pub username: String,
    pub wrapped_key: Vec<u8>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct E2eePayload {
    pub version: u32,
    pub message_id: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
    pub envelopes: Vec<RecipientEnvelope>,
    pub state_revision: u64,
    pub identity_envelope: Vec<u8>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct E2eeDecryption {
    pub plaintext: Vec<u8>,
    pub state_revision: u64,
    pub identity_envelope: Vec<u8>,
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
    account: AccountPickle,
    peers: Vec<StoredPeerSessions>,
}

struct E2eeState {
    revision: u64,
    fallback_public: [u8; 32],
    account: Account,
    sessions: HashMap<String, Vec<Session>>,
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
    let result = state
        .finish(
            &mut rng,
            &password,
            response,
            ClientRegistrationFinishParameters::default(),
        )
        .map_err(|error| AbyssalError::from(protocol_error(error)))?;
    Ok(OpaqueRegistrationFinish {
        registration_upload: result.message.serialize().to_vec(),
        export_key: result.export_key.to_vec(),
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
    let result = state
        .finish(
            &mut rng,
            &password,
            response,
            ClientLoginFinishParameters::default(),
        )
        .map_err(|error| AbyssalError::from(protocol_error(error)))?;
    Ok(OpaqueLoginFinish {
        credential_finalization: result.message.serialize().to_vec(),
        export_key: result.export_key.to_vec(),
        session_key: result.session_key.to_vec(),
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
    let (first, second) = if first_public_key <= second_public_key {
        (&first_public_key, &second_public_key)
    } else {
        (&second_public_key, &first_public_key)
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

pub fn opaque_server_finish_login(state: &[u8], finalization: &[u8]) -> Result<Vec<u8>, String> {
    let state = ServerLogin::<AbyssalOpaqueSuite>::deserialize(state).map_err(protocol_error)?;
    let finalization = CredentialFinalization::<AbyssalOpaqueSuite>::deserialize(finalization)
        .map_err(protocol_error)?;
    let result = state
        .finish(finalization, ServerLoginParameters::default())
        .map_err(protocol_error)?;
    Ok(result.session_key.to_vec())
}

#[uniffi::export]
impl E2eeSession {
    #[uniffi::constructor]
    pub fn create(export_key: Vec<u8>) -> Result<Arc<Self>, AbyssalError> {
        let export_key = Zeroizing::new(export_key);
        validate_export_key(&export_key)?;
        let mut account = Account::new();
        account.generate_fallback_key();
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
                account,
                sessions: HashMap::new(),
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
        let mut sessions = HashMap::with_capacity(stored.peers.len());
        for peer in stored.peers {
            validate_username(&peer.peer)?;
            if peer.sessions.is_empty() || peer.sessions.len() > MAX_SESSIONS_PER_PEER {
                return Err("Identity unavailable".to_string().into());
            }
            let peer_key = peer_key(&peer.peer);
            if sessions
                .insert(
                    peer_key,
                    peer.sessions
                        .into_iter()
                        .map(Session::from_pickle)
                        .collect(),
                )
                .is_some()
            {
                return Err("Identity unavailable".to_string().into());
            }
        }
        let session = Arc::new(Self {
            state: Mutex::new(E2eeState {
                revision: stored.revision,
                fallback_public: stored.fallback_public,
                account: Account::from_pickle(stored.account),
                sessions,
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
        result.extend_from_slice(&state.fallback_public);
        result
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
        mut plaintext: Vec<u8>,
        recipients: Vec<RecipientPublicKey>,
    ) -> Result<E2eePayload, AbyssalError> {
        validate_message_context(&chat_id, &message_id, &sender_username)?;
        if plaintext.is_empty() || plaintext.len() > MAX_PAYLOAD_BYTES {
            return Err("Payload unavailable".to_string().into());
        }
        if recipients.len() > MAX_PEERS {
            return Err("Recipient unavailable".to_string().into());
        }
        let mut seen = HashSet::with_capacity(recipients.len());
        for recipient in &recipients {
            validate_username(&recipient.username)?;
            if recipient.public_key.len() != IDENTITY_PUBLIC_BYTES
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
        plaintext.zeroize();
        let ciphertext = ciphertext_result.map_err(|_| "Payload unavailable".to_string())?;

        let sealing = lock(&self.sealing, "Identity unavailable")?;
        let sealing = sealing
            .as_ref()
            .ok_or_else(|| AbyssalError::from("Identity unavailable".to_string()))?;
        let mut state = lock(&self.state, "Identity unavailable")?;
        let mut envelopes = Vec::with_capacity(recipients.len());
        for recipient in recipients {
            let wrapped_key = ratchet_wrap_content_key(
                &mut state,
                &content_key,
                &recipient.public_key,
                &aad,
                &recipient.username,
            )
            .map_err(AbyssalError::from)?;
            envelopes.push(RecipientEnvelope {
                username: recipient.username,
                wrapped_key,
            });
        }
        let signature_input = signature_input(&aad, &nonce, &ciphertext);
        let signature = state.account.sign(&signature_input).to_bytes().to_vec();
        state.revision = state
            .revision
            .checked_add(1)
            .ok_or_else(|| AbyssalError::from("Identity unavailable".to_string()))?;
        let identity_envelope = seal_state(&state, sealing).map_err(AbyssalError::from)?;
        Ok(E2eePayload {
            version: PROTOCOL_VERSION,
            message_id,
            nonce: nonce.to_vec(),
            ciphertext,
            signature,
            envelopes,
            state_revision: state.revision,
            identity_envelope,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn decrypt(
        &self,
        chat_id: String,
        message_id: String,
        sender_username: String,
        sender_public_key: Vec<u8>,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        signature: Vec<u8>,
        wrapped_key: Vec<u8>,
        recipient_username: String,
    ) -> Result<E2eeDecryption, AbyssalError> {
        validate_message_context(&chat_id, &message_id, &sender_username)?;
        validate_username(&recipient_username)?;
        if sender_public_key.len() != IDENTITY_PUBLIC_BYTES
            || nonce.len() != NONCE_BYTES
            || signature.len() != 64
            || ciphertext.len() > MAX_PAYLOAD_BYTES + 16
        {
            return Err("Payload unavailable".to_string().into());
        }
        let aad = message_aad(&chat_id, &message_id, &sender_username);
        let verifying_key = Ed25519PublicKey::from_slice(
            sender_public_key[32..IDENTITY_FINGERPRINT_BYTES]
                .try_into()
                .map_err(|_| "Sender unavailable".to_string())?,
        )
        .map_err(|_| "Sender unavailable".to_string())?;
        let signature = Ed25519Signature::from_slice(&signature)
            .map_err(|_| "Payload unavailable".to_string())?;
        verifying_key
            .verify(&signature_input(&aad, &nonce, &ciphertext), &signature)
            .map_err(|_| "Payload unavailable".to_string())?;
        let sealing = lock(&self.sealing, "Identity unavailable")?;
        let sealing = sealing
            .as_ref()
            .ok_or_else(|| AbyssalError::from("Identity unavailable".to_string()))?;
        let mut state = lock(&self.state, "Identity unavailable")?;
        let content_key = Zeroizing::new(ratchet_unwrap_content_key(
            &mut state,
            &sender_username,
            &sender_public_key,
            &wrapped_key,
            &aad,
            &recipient_username,
        )?);
        let cipher = ChaCha20Poly1305::new_from_slice(content_key.as_ref())
            .map_err(|_| "Payload unavailable".to_string())?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| AbyssalError::from("Payload unavailable".to_string()))?;
        state.revision = state
            .revision
            .checked_add(1)
            .ok_or_else(|| AbyssalError::from("Identity unavailable".to_string()))?;
        let identity_envelope = seal_state(&state, sealing).map_err(AbyssalError::from)?;
        Ok(E2eeDecryption {
            plaintext,
            state_revision: state.revision,
            identity_envelope,
        })
    }
}

fn ratchet_wrap_content_key(
    state: &mut E2eeState,
    content_key: &[u8; 32],
    recipient_public: &[u8],
    aad: &[u8],
    recipient_username: &str,
) -> Result<Vec<u8>, String> {
    let key = peer_key(recipient_username);
    if !state.sessions.contains_key(&key) {
        if state.sessions.len() >= MAX_PEERS {
            return Err("Recipient unavailable".to_string());
        }
        let identity_key = Curve25519PublicKey::from_slice(&recipient_public[..32])
            .map_err(|_| "Recipient unavailable".to_string())?;
        let fallback_key = Curve25519PublicKey::from_slice(
            &recipient_public[IDENTITY_FINGERPRINT_BYTES..IDENTITY_PUBLIC_BYTES],
        )
        .map_err(|_| "Recipient unavailable".to_string())?;
        let session = state
            .account
            .create_outbound_session(SessionConfig::version_2(), identity_key, fallback_key)
            .map_err(|_| "Recipient unavailable".to_string())?;
        state.sessions.insert(key.clone(), vec![session]);
    }
    let sessions = state
        .sessions
        .get_mut(&key)
        .ok_or_else(|| "Recipient unavailable".to_string())?;
    let session = sessions
        .last_mut()
        .ok_or_else(|| "Recipient unavailable".to_string())?;
    let bound_key = Zeroizing::new(bound_content_key(content_key, aad, recipient_username));
    let message = session
        .encrypt(bound_key.as_slice())
        .map_err(|_| "Recipient unavailable".to_string())?;
    let encoded = serde_json::to_vec(&message).map_err(|_| "Recipient unavailable".to_string())?;
    if encoded.len() > MAX_RATCHET_ENVELOPE_BYTES {
        return Err("Recipient unavailable".to_string());
    }
    Ok(encoded)
}

fn ratchet_unwrap_content_key(
    state: &mut E2eeState,
    sender_username: &str,
    sender_public: &[u8],
    wrapped: &[u8],
    aad: &[u8],
    recipient_username: &str,
) -> Result<[u8; 32], String> {
    if wrapped.is_empty() || wrapped.len() > MAX_RATCHET_ENVELOPE_BYTES {
        return Err("Payload unavailable".to_string());
    }
    let message: OlmMessage =
        serde_json::from_slice(wrapped).map_err(|_| "Payload unavailable".to_string())?;
    let sender_identity = Curve25519PublicKey::from_slice(&sender_public[..32])
        .map_err(|_| "Sender unavailable".to_string())?;
    let key = peer_key(sender_username);

    let plain = Zeroizing::new(match &message {
        OlmMessage::PreKey(prekey) => {
            let existing = state.sessions.get_mut(&key).and_then(|sessions| {
                sessions
                    .iter_mut()
                    .find(|session| session.session_id() == prekey.session_id())
            });
            if let Some(session) = existing {
                session
                    .decrypt(&message)
                    .map_err(|_| "Payload unavailable".to_string())?
            } else {
                if !state.sessions.contains_key(&key) && state.sessions.len() >= MAX_PEERS {
                    return Err("Payload unavailable".to_string());
                }
                let created = state
                    .account
                    .create_inbound_session(SessionConfig::version_2(), sender_identity, prekey)
                    .map_err(|_| "Payload unavailable".to_string())?;
                let plain = created.plaintext;
                let sessions = state.sessions.entry(key).or_default();
                if sessions.len() >= MAX_SESSIONS_PER_PEER {
                    sessions.remove(0);
                }
                sessions.push(created.session);
                plain
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
            decrypted.ok_or_else(|| "Payload unavailable".to_string())?
        }
    });
    if plain.len() != 64 {
        return Err("Payload unavailable".to_string());
    }
    let expected_binding = content_key_binding(aad, recipient_username);
    if plain[32..] != expected_binding {
        return Err("Payload unavailable".to_string());
    }
    plain[..32]
        .try_into()
        .map_err(|_| "Payload unavailable".to_string())
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
    let stored = StoredE2eeState {
        revision: state.revision,
        fallback_public: state.fallback_public,
        account: state.account.pickle(),
        peers: state
            .sessions
            .iter()
            .map(|(peer, sessions)| StoredPeerSessions {
                peer: peer.clone(),
                sessions: sessions.iter().map(Session::pickle).collect(),
            })
            .collect(),
    };
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
        .expand(b"ABYSSAL_IDENTITY_WRAP_V2", &mut key)
        .map_err(|_| "Identity unavailable".to_string())?;
    Ok(key)
}

fn message_aad(chat_id: &str, message_id: &str, sender_username: &str) -> Vec<u8> {
    canonical_parts(&[
        b"ABYSSAL_E2EE_PAYLOAD_V4",
        chat_id.as_bytes(),
        message_id.as_bytes(),
        sender_username.as_bytes(),
    ])
}

fn signature_input(aad: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    canonical_parts(&[aad, nonce, ciphertext])
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

    #[allow(clippy::too_many_arguments)]
    pub fn decrypt(
        &self,
        chat_id: String,
        message_id: String,
        sender_username: String,
        sender_public_key: Vec<u8>,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        signature: Vec<u8>,
        wrapped_key: Vec<u8>,
        recipient_username: String,
    ) -> Result<String, JsValue> {
        let result = self
            .inner
            .decrypt(
                chat_id,
                message_id,
                sender_username,
                sender_public_key,
                nonce,
                ciphertext,
                signature,
                wrapped_key,
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
        let server_key =
            opaque_server_finish_login(&server_state, &login_finish.credential_finalization)
                .expect("server login finish");
        assert_eq!(server_key, login_finish.session_key);
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
        let payload = alice
            .encrypt(
                "dm_alice_bob".to_string(),
                "message-1".to_string(),
                "Alice".to_string(),
                b"relay cannot read this".to_vec(),
                vec![RecipientPublicKey {
                    username: "Bob".to_string(),
                    public_key: bob.public_key(),
                }],
            )
            .expect("encrypt");
        assert!(!payload
            .ciphertext
            .windows(b"relay cannot read this".len())
            .any(|window| window == b"relay cannot read this"));
        let plain = bob
            .decrypt(
                "dm_alice_bob".to_string(),
                payload.message_id,
                "Alice".to_string(),
                alice.public_key(),
                payload.nonce,
                payload.ciphertext,
                payload.signature,
                payload.envelopes[0].wrapped_key.clone(),
                "Bob".to_string(),
            )
            .expect("decrypt");
        assert_eq!(plain.plaintext, b"relay cannot read this");
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

        let late = bob
            .decrypt(
                "dm_alice_bob".to_string(),
                second.message_id,
                "Alice".to_string(),
                alice.public_key(),
                second.nonce,
                second.ciphertext,
                second.signature,
                second.envelopes[0].wrapped_key.clone(),
                "Bob".to_string(),
            )
            .expect("late decrypt");
        assert_eq!(late.plaintext, b"late");
        let early = bob
            .decrypt(
                "dm_alice_bob".to_string(),
                first.message_id.clone(),
                "Alice".to_string(),
                alice.public_key(),
                first.nonce.clone(),
                first.ciphertext.clone(),
                first.signature.clone(),
                first.envelopes[0].wrapped_key.clone(),
                "Bob".to_string(),
            )
            .expect("early decrypt");
        assert_eq!(early.plaintext, b"early");
        assert_eq!(early.state_revision, 2);

        assert!(bob
            .decrypt(
                "dm_alice_bob".to_string(),
                first.message_id,
                "Alice".to_string(),
                alice.public_key(),
                first.nonce,
                first.ciphertext,
                first.signature,
                first.envelopes[0].wrapped_key.clone(),
                "Bob".to_string(),
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
                }],
            )
            .expect("reply encrypt");
        let reply_olm: OlmMessage =
            serde_json::from_slice(&reply.envelopes[0].wrapped_key).expect("reply Olm envelope");
        assert!(matches!(reply_olm, OlmMessage::Normal(_)));
        let alice_reply = alice
            .decrypt(
                "dm_alice_bob".to_string(),
                reply.message_id,
                "Bob".to_string(),
                bob.public_key(),
                reply.nonce,
                reply.ciphertext,
                reply.signature,
                reply.envelopes[0].wrapped_key.clone(),
                "Alice".to_string(),
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
        let plain = restored
            .decrypt(
                "dm_alice_bob".to_string(),
                third.message_id,
                "Alice".to_string(),
                alice.public_key(),
                third.nonce,
                third.ciphertext,
                third.signature,
                third.envelopes[0].wrapped_key.clone(),
                "Bob".to_string(),
            )
            .expect("decrypt after state restore");
        assert_eq!(plain.plaintext, b"restored");
        assert_eq!(plain.state_revision, 4);
    }

    #[test]
    fn e2ee_rejects_tamper_wrong_recipient_and_sender_key() {
        let alice = sealed_session(1);
        let bob = sealed_session(2);
        let eve = sealed_session(3);
        let mut payload = alice
            .encrypt(
                "forum_one".to_string(),
                "message-1".to_string(),
                "Alice".to_string(),
                b"secret".to_vec(),
                vec![RecipientPublicKey {
                    username: "Bob".to_string(),
                    public_key: bob.public_key(),
                }],
            )
            .expect("encrypt");
        assert!(eve
            .decrypt(
                "forum_one".to_string(),
                payload.message_id.clone(),
                "Alice".to_string(),
                alice.public_key(),
                payload.nonce.clone(),
                payload.ciphertext.clone(),
                payload.signature.clone(),
                payload.envelopes[0].wrapped_key.clone(),
                "Bob".to_string(),
            )
            .is_err());
        payload.ciphertext[0] ^= 1;
        assert!(bob
            .decrypt(
                "forum_one".to_string(),
                payload.message_id,
                "Alice".to_string(),
                alice.public_key(),
                payload.nonce,
                payload.ciphertext,
                payload.signature,
                payload.envelopes[0].wrapped_key.clone(),
                "Bob".to_string(),
            )
            .is_err());
    }
}
