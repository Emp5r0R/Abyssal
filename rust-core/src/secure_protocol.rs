use crate::AbyssalError;
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
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
use std::sync::Arc;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

const IDENTITY_SECRET_BYTES: usize = 64;
const IDENTITY_PUBLIC_BYTES: usize = 64;
const NONCE_BYTES: usize = 12;
const WRAPPED_KEY_BYTES: usize = 32 + NONCE_BYTES + 32 + 16;
const MAX_CONTEXT_BYTES: usize = 512;
const MAX_PAYLOAD_BYTES: usize = 220 * 1024 * 1024;

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
}

#[derive(uniffi::Object, Zeroize, ZeroizeOnDrop)]
pub struct E2eeSession {
    x25519_secret: [u8; 32],
    signing_secret: [u8; 32],
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
    hasher.update(b"ABYSSAL_SAFETY_NUMBER_V1");
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
        let mut x25519_secret = Zeroizing::new([0u8; 32]);
        let mut signing_secret = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(x25519_secret.as_mut());
        OsRng.fill_bytes(signing_secret.as_mut());
        Ok(Arc::new(Self {
            x25519_secret: *x25519_secret,
            signing_secret: *signing_secret,
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
        if envelope.len() <= 1 + NONCE_BYTES || envelope.first() != Some(&1) {
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
        if plain.len() != IDENTITY_SECRET_BYTES {
            return Err("Identity unavailable".to_string().into());
        }
        let mut x25519_secret = Zeroizing::new([0u8; 32]);
        let mut signing_secret = Zeroizing::new([0u8; 32]);
        x25519_secret.copy_from_slice(&plain[..32]);
        signing_secret.copy_from_slice(&plain[32..]);
        let session = Arc::new(Self {
            x25519_secret: *x25519_secret,
            signing_secret: *signing_secret,
        });
        if session.public_key() != expected_public_key {
            return Err("Identity unavailable".to_string().into());
        }
        Ok(session)
    }

    pub fn public_key(&self) -> Vec<u8> {
        let x_secret = StaticSecret::from(self.x25519_secret);
        let x_public = X25519PublicKey::from(&x_secret);
        let signing = SigningKey::from_bytes(&self.signing_secret);
        let mut result = Vec::with_capacity(IDENTITY_PUBLIC_BYTES);
        result.extend_from_slice(x_public.as_bytes());
        result.extend_from_slice(signing.verifying_key().as_bytes());
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
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| "Identity unavailable".to_string())?;
        let mut nonce = [0u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);
        let mut secret = Zeroizing::new(Vec::with_capacity(IDENTITY_SECRET_BYTES));
        secret.extend_from_slice(&self.x25519_secret);
        secret.extend_from_slice(&self.signing_secret);
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &secret,
                    aad: &context,
                },
            )
            .map_err(|_| "Identity unavailable".to_string())?;
        let mut result = Vec::with_capacity(1 + nonce.len() + encrypted.len());
        result.push(1);
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&encrypted);
        Ok(result)
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

        let mut envelopes = Vec::with_capacity(recipients.len());
        for recipient in recipients {
            validate_username(&recipient.username)?;
            if recipient.public_key.len() != IDENTITY_PUBLIC_BYTES {
                return Err("Recipient unavailable".to_string().into());
            }
            let wrapped_key = wrap_content_key(
                &content_key,
                &recipient.public_key[..32],
                &aad,
                &recipient.username,
            )?;
            envelopes.push(RecipientEnvelope {
                username: recipient.username,
                wrapped_key,
            });
        }
        let signature_input = signature_input(&aad, &nonce, &ciphertext);
        let signature = SigningKey::from_bytes(&self.signing_secret)
            .sign(&signature_input)
            .to_bytes()
            .to_vec();
        Ok(E2eePayload {
            version: 3,
            message_id,
            nonce: nonce.to_vec(),
            ciphertext,
            signature,
            envelopes,
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
    ) -> Result<Vec<u8>, AbyssalError> {
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
        let verifying_key = VerifyingKey::from_bytes(
            sender_public_key[32..]
                .try_into()
                .map_err(|_| "Sender unavailable".to_string())?,
        )
        .map_err(|_| "Sender unavailable".to_string())?;
        let signature =
            Signature::from_slice(&signature).map_err(|_| "Payload unavailable".to_string())?;
        verifying_key
            .verify(&signature_input(&aad, &nonce, &ciphertext), &signature)
            .map_err(|_| "Payload unavailable".to_string())?;
        let content_key = Zeroizing::new(unwrap_content_key(
            &self.x25519_secret,
            &wrapped_key,
            &aad,
            &recipient_username,
        )?);
        let cipher = ChaCha20Poly1305::new_from_slice(content_key.as_ref())
            .map_err(|_| "Payload unavailable".to_string())?;
        let result = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| "Payload unavailable".to_string());
        result.map_err(AbyssalError::from)
    }
}

fn wrap_content_key(
    content_key: &[u8; 32],
    recipient_x25519_public: &[u8],
    aad: &[u8],
    recipient_username: &str,
) -> Result<Vec<u8>, String> {
    let public_bytes: [u8; 32] = recipient_x25519_public
        .try_into()
        .map_err(|_| "Recipient unavailable".to_string())?;
    let recipient_public = X25519PublicKey::from(public_bytes);
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(&recipient_public);
    if !shared.was_contributory() {
        return Err("Recipient unavailable".to_string());
    }
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(aad), shared.as_bytes())
        .expand(recipient_username.as_bytes(), key.as_mut())
        .map_err(|_| "Recipient unavailable".to_string())?;
    let mut nonce = [0u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);
    let encrypted = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| "Recipient unavailable".to_string())?
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: content_key,
                aad,
            },
        )
        .map_err(|_| "Recipient unavailable".to_string())?;
    let mut result = Vec::with_capacity(WRAPPED_KEY_BYTES);
    result.extend_from_slice(ephemeral_public.as_bytes());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&encrypted);
    Ok(result)
}

fn unwrap_content_key(
    x25519_secret: &[u8; 32],
    wrapped: &[u8],
    aad: &[u8],
    recipient_username: &str,
) -> Result<[u8; 32], String> {
    if wrapped.len() != WRAPPED_KEY_BYTES {
        return Err("Payload unavailable".to_string());
    }
    let ephemeral_public = X25519PublicKey::from(
        <[u8; 32]>::try_from(&wrapped[..32]).map_err(|_| "Payload unavailable".to_string())?,
    );
    let secret = StaticSecret::from(*x25519_secret);
    let shared = secret.diffie_hellman(&ephemeral_public);
    if !shared.was_contributory() {
        return Err("Payload unavailable".to_string());
    }
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(aad), shared.as_bytes())
        .expand(recipient_username.as_bytes(), key.as_mut())
        .map_err(|_| "Payload unavailable".to_string())?;
    let plain = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| "Payload unavailable".to_string())?
        .decrypt(
            Nonce::from_slice(&wrapped[32..32 + NONCE_BYTES]),
            Payload {
                msg: &wrapped[32 + NONCE_BYTES..],
                aad,
            },
        )
        .map_err(|_| "Payload unavailable".to_string())?;
    plain
        .try_into()
        .map_err(|_| "Payload unavailable".to_string())
}

fn identity_wrap_key(export_key: &[u8], context: &[u8]) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(context), export_key)
        .expand(b"ABYSSAL_IDENTITY_WRAP_V1", &mut key)
        .map_err(|_| "Identity unavailable".to_string())?;
    Ok(key)
}

fn message_aad(chat_id: &str, message_id: &str, sender_username: &str) -> Vec<u8> {
    canonical_parts(&[
        b"ABYSSAL_E2EE_PAYLOAD_V3",
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
    ) -> Result<Vec<u8>, JsValue> {
        self.inner
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
            .map_err(js_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let bob = E2eeSession::create(vec![7; 64]).expect("bob");
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
        assert_eq!(plain, b"relay cannot read this");
    }

    #[test]
    fn e2ee_rejects_tamper_wrong_recipient_and_sender_key() {
        let alice = E2eeSession::create(vec![1; 64]).expect("alice");
        let bob = E2eeSession::create(vec![2; 64]).expect("bob");
        let eve = E2eeSession::create(vec![3; 64]).expect("eve");
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
