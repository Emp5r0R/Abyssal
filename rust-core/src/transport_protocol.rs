//! Shared client facade for transport protocol v11.

pub use abyssal_transport::{
    decode_control_action, decode_control_result, derive_opaque_transport_root,
    encode_control_action, encode_control_result, generate_bootstrap_keypair,
    inspect_bootstrap_request, inspect_http_record, BootstrapContext, BootstrapKeyPair,
    BootstrapPrivateKey, BootstrapReplayGuard, BootstrapRequestHeader, BootstrapResponseSealer,
    BootstrapServerExchange, ConnectionNonce, ControlAction, ControlResult, Direction,
    HttpClientRecords, HttpOpener, HttpRecordHeader, HttpSealer, HttpServerRecords,
    HttpSessionBinding, TransportError, WsClientRecords, WsConnectionBinding, WsOpener, WsSealer,
    WsServerRecords, CONTROL_AAD, CONTROL_OPERATION, CONTROL_PLAINTEXT_BYTES, CONTROL_RECORD_BYTES,
    MAX_AAD_BYTES, MAX_BOOTSTRAP_PLAINTEXT_BYTES, MAX_BOOTSTRAP_REPLAY_TTL_MS,
    MAX_BOOTSTRAP_REQUEST_IDS, MAX_CONTROL_PLATFORM_BYTES, MAX_CONTROL_SIGNATURE_BYTES,
    MAX_CONTROL_TICKET_BYTES, MAX_CONTROL_VERSION_BYTES, MAX_HTTP_HANDLES, MAX_OPERATION_BYTES,
    MAX_RECORD_PLAINTEXT_BYTES, MAX_SESSION_CONTEXT_BYTES, MAX_WS_RECORD_PLAINTEXT_BYTES,
    MIN_BOOTSTRAP_REPLAY_TTL_MS, TRANSPORT_VERSION, WS_CLIENT_HELLO_BYTES, WS_FRAME_AAD,
    WS_SERVER_HELLO_BYTES,
};

use crate::AbyssalError;
use abyssal_invite::{locator_from_public_url, InviteError, SignedNodeDescriptorV2};
use abyssal_transport::{
    decode_account_bootstrap_result, encode_account_bootstrap_action, seal_bootstrap_request,
    AccountBootstrapAction, AccountBootstrapResult, BootstrapResponseOpener,
    ACCOUNT_BOOTSTRAP_OPERATION,
};
use rand::{rngs::OsRng, RngCore};
use std::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

#[derive(uniffi::Record)]
pub struct ControlAttestationInput {
    pub platform: String,
    pub version: String,
    pub build_signature: String,
}

#[derive(uniffi::Enum)]
pub enum ControlResponse {
    Failure,
    WsTicket { ticket: String, expires_in_sec: u32 },
    LoggedOut,
}

struct ControlClientExchangeState {
    request: Zeroizing<Vec<u8>>,
    opener: Option<abyssal_transport::HttpOpener>,
    handle: [u8; 16],
    destroyed: bool,
}

impl Drop for ControlClientExchangeState {
    fn drop(&mut self) {
        self.request.zeroize();
        self.handle.zeroize();
        self.opener.take();
        self.destroyed = true;
    }
}

/// Retry-safe client exchange for the authenticated `/v1/control` record.
///
/// The exact sealed request remains available after network, length, and AEAD
/// failures.  It is consumed immediately after the first authenticated
/// result, before semantic result decoding.
#[derive(uniffi::Object)]
pub struct ControlClientExchange {
    state: Mutex<ControlClientExchangeState>,
}

#[uniffi::export]
impl ControlClientExchange {
    #[uniffi::constructor]
    pub fn issue_ws_ticket(
        node_public_key: Vec<u8>,
        session_id: Vec<u8>,
        transport_root: Vec<u8>,
        attestation: ControlAttestationInput,
    ) -> Result<Self, AbyssalError> {
        let ControlAttestationInput {
            platform,
            version,
            build_signature,
        } = attestation;
        let action = ControlAction::IssueWsTicket {
            platform: Zeroizing::new(platform),
            version: Zeroizing::new(version),
            build_signature: Zeroizing::new(build_signature),
        };
        Self::create(node_public_key, session_id, transport_root, action)
    }

    #[uniffi::constructor]
    pub fn logout(
        node_public_key: Vec<u8>,
        session_id: Vec<u8>,
        transport_root: Vec<u8>,
    ) -> Result<Self, AbyssalError> {
        Self::create(
            node_public_key,
            session_id,
            transport_root,
            ControlAction::Logout,
        )
    }

    pub fn request_bytes(&self) -> Result<Vec<u8>, AbyssalError> {
        let state = self
            .state
            .lock()
            .map_err(|_| failure("Transport unavailable"))?;
        if state.destroyed {
            return Err(failure("Transport unavailable"));
        }
        Ok(state.request.to_vec())
    }

    pub fn open_response(&self, response: Vec<u8>) -> Result<ControlResponse, AbyssalError> {
        let response = Zeroizing::new(response);
        if response.len() != CONTROL_RECORD_BYTES {
            return Err(failure("Transport unavailable"));
        }
        let plaintext = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| failure("Transport unavailable"))?;
            if state.destroyed {
                return Err(failure("Transport unavailable"));
            }
            let handle = state.handle;
            let opener = state
                .opener
                .as_mut()
                .ok_or_else(|| failure("Transport unavailable"))?;
            let plaintext = opener
                .open(handle, CONTROL_AAD, &response)
                .map_err(|_| failure("Transport unavailable"))?;
            state.opener.take();
            state.request.zeroize();
            state.handle.zeroize();
            state.destroyed = true;
            plaintext
        };
        decode_control_result(&plaintext)
            .map(public_control_response)
            .map_err(|_| failure("Transport unavailable"))
    }
}

struct WsClientConnectionState {
    hello: Zeroizing<Vec<u8>>,
    root: Zeroizing<[u8; 32]>,
    node_public_key: [u8; 32],
    session_id: [u8; 32],
    client_nonce: [u8; 32],
    records: Option<abyssal_transport::WsClientRecords>,
    destroyed: bool,
}

impl Drop for WsClientConnectionState {
    fn drop(&mut self) {
        self.hello.zeroize();
        self.root.zeroize();
        self.node_public_key.zeroize();
        self.session_id.zeroize();
        self.client_nonce.zeroize();
        self.records.take();
        self.destroyed = true;
    }
}

/// Client-side protocol-v11 WebSocket state. The OPAQUE-derived root and
/// directional record keys never cross the FFI boundary.
#[derive(uniffi::Object)]
pub struct WsClientConnection {
    state: Mutex<WsClientConnectionState>,
}

#[uniffi::export]
impl WsClientConnection {
    #[uniffi::constructor]
    pub fn new(
        node_public_key: Vec<u8>,
        session_id: Vec<u8>,
        transport_root: Vec<u8>,
        ticket: Vec<u8>,
    ) -> Result<Self, AbyssalError> {
        let node_public_key = Zeroizing::new(exact_array(
            Zeroizing::new(node_public_key),
            "Node identity mismatch",
        )?);
        let session_id = Zeroizing::new(exact_array(
            Zeroizing::new(session_id),
            "Session identity mismatch",
        )?);
        let root = Zeroizing::new(exact_array(
            Zeroizing::new(transport_root),
            "Transport unavailable",
        )?);
        let client_nonce = abyssal_transport::ConnectionNonce::generate()
            .map_err(|_| failure("Transport unavailable"))?;
        let hello = abyssal_transport::seal_ws_client_hello(
            &root,
            *node_public_key,
            *session_id,
            client_nonce.to_bytes(),
            &Zeroizing::new(ticket),
        )
        .map_err(|_| failure("Transport unavailable"))?;
        Ok(Self {
            state: Mutex::new(WsClientConnectionState {
                hello,
                root,
                node_public_key: *node_public_key,
                session_id: *session_id,
                client_nonce: client_nonce.to_bytes(),
                records: None,
                destroyed: false,
            }),
        })
    }

    pub fn client_hello_bytes(&self) -> Result<Vec<u8>, AbyssalError> {
        let state = self
            .state
            .lock()
            .map_err(|_| failure("Transport unavailable"))?;
        if state.destroyed || state.hello.len() != WS_CLIENT_HELLO_BYTES {
            return Err(failure("Transport unavailable"));
        }
        Ok(state.hello.to_vec())
    }

    pub fn open_server_hello(&self, response: Vec<u8>) -> Result<(), AbyssalError> {
        if response.len() != WS_SERVER_HELLO_BYTES {
            return Err(failure("Transport unavailable"));
        }
        let response = Zeroizing::new(response);
        let mut state = self
            .state
            .lock()
            .map_err(|_| failure("Transport unavailable"))?;
        if state.destroyed || state.records.is_some() {
            return Err(failure("Transport unavailable"));
        }
        let server_nonce = abyssal_transport::open_ws_server_hello(
            &state.root,
            state.node_public_key,
            state.session_id,
            state.client_nonce,
            &response,
        )
        .map_err(|_| failure("Transport unavailable"))?;
        let client_nonce = abyssal_transport::ConnectionNonce::new(state.client_nonce)
            .map_err(|_| failure("Transport unavailable"))?;
        let binding = WsConnectionBinding::new(state.session_id, client_nonce, server_nonce)
            .map_err(|_| failure("Transport unavailable"))?;
        state.records = Some(
            binding
                .into_client(&state.root)
                .map_err(|_| failure("Transport unavailable"))?,
        );
        state.hello.zeroize();
        Ok(())
    }

    pub fn seal_frame(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, AbyssalError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| failure("Transport unavailable"))?;
        if state.destroyed {
            return Err(failure("Transport unavailable"));
        }
        let records = state
            .records
            .as_mut()
            .ok_or_else(|| failure("Transport unavailable"))?;
        records
            .sealer
            .seal(WS_FRAME_AAD, &Zeroizing::new(plaintext))
            .map_err(|_| failure("Transport unavailable"))
    }

    pub fn open_frame(&self, record: Vec<u8>) -> Result<Vec<u8>, AbyssalError> {
        let record = Zeroizing::new(record);
        let mut state = self
            .state
            .lock()
            .map_err(|_| failure("Transport unavailable"))?;
        if state.destroyed {
            return Err(failure("Transport unavailable"));
        }
        let records = state
            .records
            .as_mut()
            .ok_or_else(|| failure("Transport unavailable"))?;
        records
            .opener
            .open(WS_FRAME_AAD, &record)
            .map(|plaintext| plaintext.to_vec())
            .map_err(|_| failure("Transport unavailable"))
    }

    pub fn ready(&self) -> bool {
        self.state
            .lock()
            .map(|state| !state.destroyed && state.records.is_some())
            .unwrap_or(false)
    }
}

impl WsClientConnection {
    pub fn destroy(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.hello.zeroize();
            state.records.take();
            state.root.zeroize();
            state.node_public_key.zeroize();
            state.session_id.zeroize();
            state.client_nonce.zeroize();
            state.destroyed = true;
        }
    }
}

impl ControlClientExchange {
    pub fn destroy(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.request.zeroize();
            state.handle.zeroize();
            state.opener.take();
            state.destroyed = true;
        }
    }

    fn create(
        node_public_key: Vec<u8>,
        session_id: Vec<u8>,
        transport_root: Vec<u8>,
        action: ControlAction,
    ) -> Result<Self, AbyssalError> {
        let node_public_key = Zeroizing::new(exact_array(
            Zeroizing::new(node_public_key),
            "Node identity mismatch",
        )?);
        let session_id = Zeroizing::new(exact_array(
            Zeroizing::new(session_id),
            "Session identity mismatch",
        )?);
        let transport_root = Zeroizing::new(exact_array(
            Zeroizing::new(transport_root),
            "Transport unavailable",
        )?);
        let plaintext =
            encode_control_action(&action).map_err(|_| failure("Transport unavailable"))?;
        let handle = random_nonzero_handle();
        let mut records = HttpSessionBinding::new(*node_public_key, *session_id)
            .map_err(|_| failure("Transport unavailable"))?
            .into_client(&transport_root)
            .map_err(|_| failure("Transport unavailable"))?;
        let request = records
            .sealer
            .seal(handle, CONTROL_AAD, &plaintext)
            .map_err(|_| failure("Transport unavailable"))?;
        Ok(Self {
            state: Mutex::new(ControlClientExchangeState {
                request: Zeroizing::new(request),
                opener: Some(records.opener),
                handle,
                destroyed: false,
            }),
        })
    }
}

fn public_control_response(result: ControlResult) -> ControlResponse {
    match result {
        ControlResult::Failure => ControlResponse::Failure,
        ControlResult::WsTicket {
            ticket,
            expires_in_sec,
        } => ControlResponse::WsTicket {
            ticket: ticket.to_string(),
            expires_in_sec,
        },
        ControlResult::LoggedOut => ControlResponse::LoggedOut,
    }
}

fn random_nonzero_handle() -> [u8; 16] {
    loop {
        let mut value = [0_u8; 16];
        OsRng.fill_bytes(&mut value);
        if value != [0_u8; 16] {
            return value;
        }
    }
}

#[derive(Clone, uniffi::Record)]
pub struct VerifiedTransportDescriptor {
    pub bootstrap_public_key: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct AccountBootstrapRegistrationFinishInput {
    pub handshake_id: Vec<u8>,
    pub registration_upload: Vec<u8>,
    pub identity_public: Vec<u8>,
    pub identity_prekey_id: String,
    pub identity_envelope: Vec<u8>,
    pub identity_proof: Vec<u8>,
}

#[derive(uniffi::Enum)]
pub enum AccountBootstrapResponse {
    Failure,
    LoginStart {
        handshake_id: Vec<u8>,
        credential_response: Vec<u8>,
        identity_public: Vec<u8>,
        identity_prekey_id: String,
        identity_envelope: Vec<u8>,
    },
    RegistrationStart {
        handshake_id: Vec<u8>,
        registration_response: Vec<u8>,
        challenge: Vec<u8>,
    },
    RegistrationContinuation {
        handshake_id: Vec<u8>,
        credential_response: Vec<u8>,
    },
    Session {
        session_id: Vec<u8>,
        created: bool,
        max_rooms_per_user: u32,
        session_inactivity_sec: u32,
        username: String,
        identity_public: Vec<u8>,
        identity_prekey_id: String,
        identity_envelope: Vec<u8>,
    },
}

struct ClientExchangeState {
    request: Zeroizing<Vec<u8>>,
    opener: Option<BootstrapResponseOpener>,
    destroyed: bool,
}

impl Drop for ClientExchangeState {
    fn drop(&mut self) {
        self.request.zeroize();
        self.opener.take();
        self.destroyed = true;
    }
}

/// One HPKE response key plus a retryable copy of its exact request bytes.
#[derive(uniffi::Object)]
pub struct AccountBootstrapExchange {
    state: Mutex<ClientExchangeState>,
}

#[uniffi::export]
impl AccountBootstrapExchange {
    #[uniffi::constructor]
    pub fn start(
        node_public_key: Vec<u8>,
        bootstrap_public_key: Vec<u8>,
        capability: Vec<u8>,
        registration_request: Vec<u8>,
        credential_request: Vec<u8>,
    ) -> Result<Self, AbyssalError> {
        let node_public_key = Zeroizing::new(node_public_key);
        let bootstrap_public_key = Zeroizing::new(bootstrap_public_key);
        let capability = Zeroizing::new(capability);
        let registration_request = Zeroizing::new(registration_request);
        let credential_request = Zeroizing::new(credential_request);
        Self::create(
            node_public_key,
            bootstrap_public_key,
            AccountBootstrapAction::Start {
                capability: Zeroizing::new(exact_array(capability, "Invalid capability")?),
                registration_request,
                credential_request,
            },
        )
    }

    #[uniffi::constructor]
    pub fn finish_registration(
        node_public_key: Vec<u8>,
        bootstrap_public_key: Vec<u8>,
        input: AccountBootstrapRegistrationFinishInput,
    ) -> Result<Self, AbyssalError> {
        let AccountBootstrapRegistrationFinishInput {
            handshake_id,
            registration_upload,
            identity_public,
            identity_prekey_id,
            identity_envelope,
            identity_proof,
        } = input;
        let node_public_key = Zeroizing::new(node_public_key);
        let bootstrap_public_key = Zeroizing::new(bootstrap_public_key);
        let handshake_id = Zeroizing::new(handshake_id);
        let registration_upload = Zeroizing::new(registration_upload);
        let identity_public = Zeroizing::new(identity_public);
        let identity_prekey_id = Zeroizing::new(identity_prekey_id);
        let identity_envelope = Zeroizing::new(identity_envelope);
        let identity_proof = Zeroizing::new(identity_proof);
        Self::create(
            node_public_key,
            bootstrap_public_key,
            AccountBootstrapAction::FinishRegistration {
                handshake_id: exact_array(handshake_id, "Invalid handshake")?,
                registration_upload,
                identity_public,
                identity_prekey_id,
                identity_envelope,
                identity_proof,
            },
        )
    }

    #[uniffi::constructor]
    pub fn finish_login(
        node_public_key: Vec<u8>,
        bootstrap_public_key: Vec<u8>,
        handshake_id: Vec<u8>,
        credential_finalization: Vec<u8>,
    ) -> Result<Self, AbyssalError> {
        let node_public_key = Zeroizing::new(node_public_key);
        let bootstrap_public_key = Zeroizing::new(bootstrap_public_key);
        let handshake_id = Zeroizing::new(handshake_id);
        let credential_finalization = Zeroizing::new(credential_finalization);
        Self::create(
            node_public_key,
            bootstrap_public_key,
            AccountBootstrapAction::FinishLogin {
                handshake_id: exact_array(handshake_id, "Invalid handshake")?,
                credential_finalization,
            },
        )
    }

    pub fn request_bytes(&self) -> Result<Vec<u8>, AbyssalError> {
        let state = self
            .state
            .lock()
            .map_err(|_| failure("Transport unavailable"))?;
        if state.destroyed {
            return Err(failure("Transport unavailable"));
        }
        Ok(state.request.to_vec())
    }

    /// Retains the request and opener until a response authenticates.
    pub fn open_response(
        &self,
        response: Vec<u8>,
    ) -> Result<AccountBootstrapResponse, AbyssalError> {
        let response = Zeroizing::new(response);
        if response.len() != MAX_BOOTSTRAP_PLAINTEXT_BYTES + 16 {
            return Err(failure("Transport unavailable"));
        }
        let plaintext = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| failure("Transport unavailable"))?;
            if state.destroyed {
                return Err(failure("Transport unavailable"));
            }
            let opener = state
                .opener
                .as_ref()
                .ok_or_else(|| failure("Transport unavailable"))?;
            let plaintext = opener
                .open(&response)
                .map_err(|_| failure("Transport unavailable"))?;
            // Authentication succeeded. Consume both retry state values before
            // decoding, so malformed authenticated plaintext cannot be retried.
            state.opener.take();
            state.request.zeroize();
            state.destroyed = true;
            plaintext
        };
        decode_account_bootstrap_result(&plaintext)
            .map(public_response)
            .map_err(|_| failure("Transport unavailable"))
    }
}

impl AccountBootstrapExchange {
    pub fn destroy(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.request.zeroize();
            state.opener.take();
            state.destroyed = true;
        }
    }

    fn create(
        node_public_key: Zeroizing<Vec<u8>>,
        bootstrap_public_key: Zeroizing<Vec<u8>>,
        action: AccountBootstrapAction,
    ) -> Result<Self, AbyssalError> {
        let node_public_key =
            Zeroizing::new(exact_array(node_public_key, "Node identity mismatch")?);
        let bootstrap_public_key =
            Zeroizing::new(exact_array(bootstrap_public_key, "Node identity mismatch")?);
        let context = BootstrapContext::new(
            *node_public_key,
            *bootstrap_public_key,
            ACCOUNT_BOOTSTRAP_OPERATION.to_vec(),
            random_nonzero_id(),
        )
        .map_err(|_| failure("Transport unavailable"))?;
        let plaintext = encode_account_bootstrap_action(&action)
            .map_err(|_| failure("Transport unavailable"))?;
        let exchange = seal_bootstrap_request(&context, &plaintext)
            .map_err(|_| failure("Transport unavailable"))?;
        Ok(Self {
            state: Mutex::new(ClientExchangeState {
                request: Zeroizing::new(exchange.request),
                opener: Some(exchange.response_opener),
                destroyed: false,
            }),
        })
    }
}

#[uniffi::export]
pub fn verify_transport_node_descriptor(
    descriptor: Vec<u8>,
    expected_node_public_key: Vec<u8>,
    expected_node_url: String,
) -> Result<VerifiedTransportDescriptor, AbyssalError> {
    let expected = Zeroizing::new(exact_array(
        Zeroizing::new(expected_node_public_key),
        "Node identity mismatch",
    )?);
    let bootstrap_public_key =
        verify_node_descriptor_v2(&descriptor, &expected, &expected_node_url)
            .map_err(|_| failure("Node identity mismatch"))?;
    Ok(VerifiedTransportDescriptor {
        bootstrap_public_key: bootstrap_public_key.to_vec(),
    })
}

pub fn verify_node_descriptor_v2(
    descriptor: &[u8],
    expected_node_public_key: &[u8; 32],
    expected_node_url: &str,
) -> Result<[u8; 32], InviteError> {
    let locator = locator_from_public_url(expected_node_url)?;
    SignedNodeDescriptorV2::decode_for_invite(descriptor, expected_node_public_key, &locator)
        .map(|signed| signed.descriptor.bootstrap_hpke_public_key)
}

fn public_response(result: AccountBootstrapResult) -> AccountBootstrapResponse {
    match result {
        AccountBootstrapResult::Failure => AccountBootstrapResponse::Failure,
        AccountBootstrapResult::LoginStart {
            handshake_id,
            credential_response,
            identity_public,
            identity_prekey_id,
            identity_envelope,
        } => AccountBootstrapResponse::LoginStart {
            handshake_id: handshake_id.to_vec(),
            credential_response: credential_response.to_vec(),
            identity_public: identity_public.to_vec(),
            identity_prekey_id: identity_prekey_id.to_string(),
            identity_envelope: identity_envelope.to_vec(),
        },
        AccountBootstrapResult::RegistrationStart {
            handshake_id,
            registration_response,
            challenge,
        } => AccountBootstrapResponse::RegistrationStart {
            handshake_id: handshake_id.to_vec(),
            registration_response: registration_response.to_vec(),
            challenge: challenge.to_vec(),
        },
        AccountBootstrapResult::RegistrationContinuation {
            handshake_id,
            credential_response,
        } => AccountBootstrapResponse::RegistrationContinuation {
            handshake_id: handshake_id.to_vec(),
            credential_response: credential_response.to_vec(),
        },
        AccountBootstrapResult::Session {
            session_id,
            created,
            max_rooms_per_user,
            session_inactivity_sec,
            username,
            identity_public,
            identity_prekey_id,
            identity_envelope,
        } => AccountBootstrapResponse::Session {
            session_id: session_id.to_vec(),
            created,
            max_rooms_per_user,
            session_inactivity_sec,
            username: username.to_string(),
            identity_public: identity_public.to_vec(),
            identity_prekey_id: identity_prekey_id.to_string(),
            identity_envelope: identity_envelope.to_vec(),
        },
    }
}

fn random_nonzero_id() -> [u8; 32] {
    loop {
        let mut value = [0_u8; 32];
        OsRng.fill_bytes(&mut value);
        if value != [0_u8; 32] {
            return value;
        }
    }
}

fn exact_array<const N: usize>(
    mut value: Zeroizing<Vec<u8>>,
    detail: &str,
) -> Result<[u8; N], AbyssalError> {
    if value.len() != N {
        value.zeroize();
        return Err(failure(detail));
    }
    let mut output = [0_u8; N];
    output.copy_from_slice(&value);
    value.zeroize();
    Ok(output)
}

fn failure(detail: &str) -> AbyssalError {
    AbyssalError::Failure {
        detail: detail.to_owned(),
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm;

#[cfg(test)]
mod tests {
    use super::*;
    use abyssal_invite::{
        node_signing_key_from_seed, NodeDescriptorV1, NodeDescriptorV2, SignedNodeDescriptor,
        SignedNodeDescriptorV2,
    };
    use abyssal_transport::{
        encode_account_bootstrap_result, encode_control_result, generate_bootstrap_keypair,
        ControlResult, HttpSessionBinding, CONTROL_AAD, CONTROL_RECORD_BYTES,
    };

    #[test]
    fn v2_returns_authenticated_key_and_v1_fails_closed() {
        let signing_key = node_signing_key_from_seed(&[3; 32]);
        let node_key = signing_key.verifying_key().to_bytes();
        let locator = locator_from_public_url("https://node.example.com").unwrap();
        let v2 = SignedNodeDescriptorV2::sign(
            NodeDescriptorV2::abyssal(node_key, [4; 32], vec![locator.clone()]).unwrap(),
            &signing_key,
        )
        .unwrap()
        .canonical_binary()
        .unwrap();
        assert_eq!(
            verify_node_descriptor_v2(&v2, &node_key, "https://node.example.com").unwrap(),
            [4; 32]
        );
        let v1 = SignedNodeDescriptor::sign(
            NodeDescriptorV1::abyssal(node_key, vec![locator]).unwrap(),
            &signing_key,
        )
        .unwrap()
        .canonical_binary()
        .unwrap();
        assert!(verify_node_descriptor_v2(&v1, &node_key, "https://node.example.com").is_err());
    }

    #[test]
    fn invalid_responses_are_retryable_until_authenticated() {
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
        assert_eq!(request, exchange.request_bytes().unwrap());
        let header = inspect_bootstrap_request(&request).unwrap();
        let context = BootstrapContext::new(
            [3; 32],
            server.public_key,
            ACCOUNT_BOOTSTRAP_OPERATION.to_vec(),
            header.request_id,
        )
        .unwrap();
        let opened = BootstrapReplayGuard::new(30_000)
            .unwrap()
            .open_request(server.private_key(), &context, &request, 1)
            .unwrap();
        let plaintext = encode_account_bootstrap_result(&AccountBootstrapResult::Failure).unwrap();
        let response = opened.response_sealer.seal(&plaintext).unwrap();
        let request_before_failure = exchange.request_bytes().unwrap();
        assert!(exchange.open_response(vec![0; 64]).is_err());
        assert_eq!(exchange.request_bytes().unwrap(), request_before_failure);
        let mut tampered = response.clone();
        tampered[0] ^= 1;
        assert!(exchange.open_response(tampered).is_err());
        assert_eq!(exchange.request_bytes().unwrap(), request_before_failure);
        assert!(matches!(
            exchange.open_response(response.clone()).unwrap(),
            AccountBootstrapResponse::Failure
        ));
        assert!(exchange.open_response(response).is_err());
    }

    #[test]
    fn authenticated_malformed_plaintext_consumes_exchange() {
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
        let malformed = vec![0_u8; MAX_BOOTSTRAP_PLAINTEXT_BYTES];
        let response = opened.response_sealer.seal(&malformed).unwrap();
        assert!(exchange.open_response(response).is_err());
        assert!(exchange.request_bytes().is_err());
    }

    #[test]
    fn concurrent_authenticated_open_has_one_success() {
        use std::sync::{Arc, Barrier};
        use std::thread;

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
        let exchange = Arc::new(exchange);
        let barrier = Arc::new(Barrier::new(8));
        let threads = (0..8)
            .map(|_| {
                let exchange = Arc::clone(&exchange);
                let barrier = Arc::clone(&barrier);
                let response = response.clone();
                thread::spawn(move || {
                    barrier.wait();
                    exchange.open_response(response).is_ok()
                })
            })
            .collect::<Vec<_>>();
        let successes = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .filter(|success| *success)
            .count();
        assert_eq!(successes, 1);
    }

    #[test]
    fn destroy_invalidates_exchange() {
        let server = generate_bootstrap_keypair();
        let exchange = AccountBootstrapExchange::finish_login(
            vec![3; 32],
            server.public_key.to_vec(),
            vec![4; 16],
            vec![5; 32],
        )
        .unwrap();
        exchange.destroy();
        assert!(exchange.request_bytes().is_err());
        assert!(exchange.open_response(vec![0; 64]).is_err());
    }

    #[test]
    fn control_exchange_preserves_exact_request_until_authenticated_result() {
        let node = [3_u8; 32];
        let session = [7_u8; 32];
        let root = [8_u8; 32];
        let exchange =
            ControlClientExchange::logout(node.to_vec(), session.to_vec(), root.to_vec()).unwrap();
        let request = exchange.request_bytes().unwrap();
        assert_eq!(request.len(), CONTROL_RECORD_BYTES);
        let header = inspect_http_record(&request).unwrap();
        let mut server = HttpSessionBinding::new(node, session)
            .unwrap()
            .into_server(&root)
            .unwrap();
        let opened = server
            .opener
            .open(header.handle, CONTROL_AAD, &request)
            .unwrap();
        assert!(matches!(
            decode_control_action(&opened).unwrap(),
            ControlAction::Logout
        ));
        let plain = encode_control_result(&ControlResult::Failure).unwrap();
        let response = server
            .sealer
            .seal(header.handle, CONTROL_AAD, &plain)
            .unwrap();
        let exact_before_failure = exchange.request_bytes().unwrap();
        assert!(exchange
            .open_response(vec![0; CONTROL_RECORD_BYTES - 1])
            .is_err());
        assert_eq!(exchange.request_bytes().unwrap(), exact_before_failure);
        let mut tampered = response.clone();
        tampered[0] ^= 1;
        assert!(exchange.open_response(tampered).is_err());
        assert_eq!(exchange.request_bytes().unwrap(), exact_before_failure);
        assert!(matches!(
            exchange.open_response(response).unwrap(),
            ControlResponse::Failure
        ));
        assert!(exchange.request_bytes().is_err());
    }

    #[test]
    fn websocket_client_binding_requires_authenticated_server_hello() {
        let node = [3_u8; 32];
        let session = [7_u8; 32];
        let root = [8_u8; 32];
        let client = WsClientConnection::new(
            node.to_vec(),
            session.to_vec(),
            root.to_vec(),
            b"opaque-ticket".to_vec(),
        )
        .unwrap();
        assert!(!client.ready());
        let client_hello = client.client_hello_bytes().unwrap();
        let opened = abyssal_transport::open_ws_client_hello(&root, node, &client_hello).unwrap();
        assert_eq!(opened.ticket.as_slice(), b"opaque-ticket");
        let server_nonce = [9_u8; 32];
        let server_hello = abyssal_transport::seal_ws_server_hello(
            &root,
            node,
            session,
            opened.header.client_nonce,
            server_nonce,
        )
        .unwrap();
        client.open_server_hello(server_hello.to_vec()).unwrap();
        assert!(client.ready());
        let outbound = client.seal_frame(b"frame".to_vec()).unwrap();
        let mut server = WsConnectionBinding::new(
            session,
            ConnectionNonce::new(opened.header.client_nonce).unwrap(),
            ConnectionNonce::new(server_nonce).unwrap(),
        )
        .unwrap()
        .into_server(&root)
        .unwrap();
        assert_eq!(
            server
                .opener
                .open(WS_FRAME_AAD, &outbound)
                .unwrap()
                .as_slice(),
            b"frame"
        );
        assert!(client
            .open_server_hello(vec![0; WS_SERVER_HELLO_BYTES])
            .is_err());
        client.destroy();
        assert!(client.seal_frame(b"after-destroy".to_vec()).is_err());
    }
}
