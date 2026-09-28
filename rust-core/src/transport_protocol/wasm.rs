use super::*;

fn js_error(error: impl core::fmt::Display) -> wasm_bindgen::JsValue {
    wasm_bindgen::JsValue::from_str(&error.to_string())
}

#[wasm_bindgen::prelude::wasm_bindgen]
pub struct WasmAttachmentExchange {
    inner: crate::attachment_transport::AttachmentClientExchange,
}

#[wasm_bindgen::prelude::wasm_bindgen]
impl WasmAttachmentExchange {
    #[wasm_bindgen::prelude::wasm_bindgen(js_name = beginUpload)]
    #[allow(clippy::too_many_arguments)]
    pub fn begin_upload(
        node_public_key: Vec<u8>,
        session_id: Vec<u8>,
        transport_root: Vec<u8>,
        chat_id: String,
        message_id: String,
        media_type: String,
        cipher_version: u8,
        ciphertext_len: u64,
        ciphertext_sha256: Vec<u8>,
        one_time: bool,
        delete_after_download: bool,
        requested_ttl_sec: u32,
    ) -> Result<WasmAttachmentExchange, wasm_bindgen::JsValue> {
        crate::attachment_transport::AttachmentClientExchange::begin_upload(
            node_public_key,
            session_id,
            transport_root,
            crate::attachment_transport::AttachmentUploadInput {
                chat_id,
                message_id,
                media_type,
                cipher_version,
                ciphertext_len,
                ciphertext_sha256,
                one_time,
                delete_after_download,
                requested_ttl_sec,
            },
        )
        .map(|inner| Self { inner })
        .map_err(js_error)
    }

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = beginDownload)]
    pub fn begin_download(
        node_public_key: Vec<u8>,
        session_id: Vec<u8>,
        transport_root: Vec<u8>,
        attachment_id: Vec<u8>,
    ) -> Result<WasmAttachmentExchange, wasm_bindgen::JsValue> {
        crate::attachment_transport::AttachmentClientExchange::begin_download(
            node_public_key,
            session_id,
            transport_root,
            attachment_id,
        )
        .map(|inner| Self { inner })
        .map_err(js_error)
    }

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = completeDownload)]
    pub fn complete_download(
        node_public_key: Vec<u8>,
        session_id: Vec<u8>,
        transport_root: Vec<u8>,
        attachment_id: Vec<u8>,
        claim_id: Vec<u8>,
    ) -> Result<WasmAttachmentExchange, wasm_bindgen::JsValue> {
        crate::attachment_transport::AttachmentClientExchange::complete_download(
            node_public_key,
            session_id,
            transport_root,
            attachment_id,
            (!claim_id.is_empty()).then_some(claim_id),
        )
        .map(|inner| Self { inner })
        .map_err(js_error)
    }

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = releaseDownload)]
    pub fn release_download(
        node_public_key: Vec<u8>,
        session_id: Vec<u8>,
        transport_root: Vec<u8>,
        attachment_id: Vec<u8>,
        claim_id: Vec<u8>,
    ) -> Result<WasmAttachmentExchange, wasm_bindgen::JsValue> {
        crate::attachment_transport::AttachmentClientExchange::release_download(
            node_public_key,
            session_id,
            transport_root,
            attachment_id,
            (!claim_id.is_empty()).then_some(claim_id),
        )
        .map(|inner| Self { inner })
        .map_err(js_error)
    }

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = deleteAttachment)]
    pub fn delete_attachment(
        node_public_key: Vec<u8>,
        session_id: Vec<u8>,
        transport_root: Vec<u8>,
        attachment_id: Vec<u8>,
    ) -> Result<WasmAttachmentExchange, wasm_bindgen::JsValue> {
        crate::attachment_transport::AttachmentClientExchange::delete_attachment(
            node_public_key,
            session_id,
            transport_root,
            attachment_id,
        )
        .map(|inner| Self { inner })
        .map_err(js_error)
    }

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = requestBytes)]
    pub fn request_bytes(&self) -> Result<Vec<u8>, wasm_bindgen::JsValue> {
        self.inner.request_bytes().map_err(js_error)
    }

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = uploadDataFrameCount)]
    pub fn upload_data_frame_count(&self) -> Result<u16, wasm_bindgen::JsValue> {
        self.inner.upload_data_frame_count().map_err(js_error)
    }

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = uploadBucketFrameCount)]
    pub fn upload_bucket_frame_count(&self) -> Result<u16, wasm_bindgen::JsValue> {
        self.inner.upload_bucket_frame_count().map_err(js_error)
    }

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = sealDataFrame)]
    pub fn seal_data_frame(&self, payload: Vec<u8>) -> Result<Vec<u8>, wasm_bindgen::JsValue> {
        self.inner.seal_data_frame(payload).map_err(js_error)
    }

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = sealPaddingFrame)]
    pub fn seal_padding_frame(&self) -> Result<Vec<u8>, wasm_bindgen::JsValue> {
        self.inner.seal_padding_frame().map_err(js_error)
    }

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = sealEndFrame)]
    pub fn seal_end_frame(&self) -> Result<Vec<u8>, wasm_bindgen::JsValue> {
        self.inner.seal_end_frame().map_err(js_error)
    }

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = openResponse)]
    pub fn open_response(
        &self,
        response: Vec<u8>,
    ) -> Result<WasmAttachmentResult, wasm_bindgen::JsValue> {
        self.inner
            .open_response(response)
            .map(|inner| WasmAttachmentResult { inner })
            .map_err(js_error)
    }

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = openStreamFrame)]
    pub fn open_stream_frame(
        &self,
        frame: Vec<u8>,
    ) -> Result<WasmAttachmentFrame, wasm_bindgen::JsValue> {
        self.inner
            .open_stream_frame(frame)
            .map(|inner| WasmAttachmentFrame { inner })
            .map_err(js_error)
    }

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = streamComplete)]
    pub fn stream_complete(&self) -> bool {
        self.inner.stream_complete()
    }

    pub fn destroy(&self) {
        self.inner.destroy();
    }
}

#[wasm_bindgen::prelude::wasm_bindgen]
pub struct WasmAttachmentResult {
    inner: crate::attachment_transport::AttachmentTransportResult,
}

#[wasm_bindgen::prelude::wasm_bindgen]
impl WasmAttachmentResult {
    #[wasm_bindgen::prelude::wasm_bindgen(getter)]
    pub fn kind(&self) -> u8 {
        use crate::attachment_transport::AttachmentTransportResult::*;
        match &self.inner {
            Failure => 0,
            Success => 1,
            UploadAccepted { .. } => 2,
            DownloadAccepted { .. } => 3,
        }
    }

    #[wasm_bindgen::prelude::wasm_bindgen(getter, js_name = attachmentId)]
    pub fn attachment_id(&self) -> Vec<u8> {
        match &self.inner {
            crate::attachment_transport::AttachmentTransportResult::UploadAccepted {
                attachment_id,
            } => attachment_id.clone(),
            _ => Vec::new(),
        }
    }

    #[wasm_bindgen::prelude::wasm_bindgen(getter, js_name = claimId)]
    pub fn claim_id(&self) -> Vec<u8> {
        match &self.inner {
            crate::attachment_transport::AttachmentTransportResult::DownloadAccepted {
                claim_id,
                ..
            } => claim_id.clone().unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    #[wasm_bindgen::prelude::wasm_bindgen(getter, js_name = ciphertextLen)]
    pub fn ciphertext_len(&self) -> u64 {
        match &self.inner {
            crate::attachment_transport::AttachmentTransportResult::DownloadAccepted {
                ciphertext_len,
                ..
            } => *ciphertext_len,
            _ => 0,
        }
    }

    #[wasm_bindgen::prelude::wasm_bindgen(getter, js_name = ciphertextSha256)]
    pub fn ciphertext_sha256(&self) -> Vec<u8> {
        match &self.inner {
            crate::attachment_transport::AttachmentTransportResult::DownloadAccepted {
                ciphertext_sha256,
                ..
            } => ciphertext_sha256.clone(),
            _ => Vec::new(),
        }
    }

    #[wasm_bindgen::prelude::wasm_bindgen(getter, js_name = dataFrameCount)]
    pub fn data_frame_count(&self) -> u16 {
        match &self.inner {
            crate::attachment_transport::AttachmentTransportResult::DownloadAccepted {
                data_frame_count,
                ..
            } => *data_frame_count,
            _ => 0,
        }
    }

    #[wasm_bindgen::prelude::wasm_bindgen(getter, js_name = bucketFrameCount)]
    pub fn bucket_frame_count(&self) -> u16 {
        match &self.inner {
            crate::attachment_transport::AttachmentTransportResult::DownloadAccepted {
                bucket_frame_count,
                ..
            } => *bucket_frame_count,
            _ => 0,
        }
    }
}

#[wasm_bindgen::prelude::wasm_bindgen]
pub struct WasmAttachmentFrame {
    inner: crate::attachment_transport::AttachmentTransportFrame,
}

#[wasm_bindgen::prelude::wasm_bindgen]
impl WasmAttachmentFrame {
    #[wasm_bindgen::prelude::wasm_bindgen(getter)]
    pub fn kind(&self) -> u8 {
        match &self.inner {
            crate::attachment_transport::AttachmentTransportFrame::Data { .. } => 1,
            crate::attachment_transport::AttachmentTransportFrame::Padding => 2,
            crate::attachment_transport::AttachmentTransportFrame::End => 3,
        }
    }

    #[wasm_bindgen::prelude::wasm_bindgen(getter)]
    pub fn payload(&self) -> Vec<u8> {
        match &self.inner {
            crate::attachment_transport::AttachmentTransportFrame::Data { payload } => {
                payload.clone()
            }
            _ => Vec::new(),
        }
    }
}

#[wasm_bindgen::prelude::wasm_bindgen]
pub struct WasmControlExchange {
    inner: ControlClientExchange,
}

#[wasm_bindgen::prelude::wasm_bindgen]
impl WasmControlExchange {
    #[wasm_bindgen::prelude::wasm_bindgen(js_name = issueWsTicket)]
    pub fn issue_ws_ticket(
        node_public_key: Vec<u8>,
        session_id: Vec<u8>,
        transport_root: Vec<u8>,
        platform: String,
        version: String,
        build_signature: String,
    ) -> Result<WasmControlExchange, wasm_bindgen::JsValue> {
        ControlClientExchange::issue_ws_ticket(
            node_public_key,
            session_id,
            transport_root,
            ControlAttestationInput {
                platform,
                version,
                build_signature,
            },
        )
        .map(|inner| Self { inner })
        .map_err(js_error)
    }

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = logout)]
    pub fn logout(
        node_public_key: Vec<u8>,
        session_id: Vec<u8>,
        transport_root: Vec<u8>,
    ) -> Result<WasmControlExchange, wasm_bindgen::JsValue> {
        ControlClientExchange::logout(node_public_key, session_id, transport_root)
            .map(|inner| Self { inner })
            .map_err(js_error)
    }

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = requestBytes)]
    pub fn request_bytes(&self) -> Result<Vec<u8>, wasm_bindgen::JsValue> {
        self.inner.request_bytes().map_err(js_error)
    }

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = openResponse)]
    pub fn open_response(
        &self,
        response: Vec<u8>,
    ) -> Result<WasmControlResponse, wasm_bindgen::JsValue> {
        self.inner
            .open_response(response)
            .map(|inner| WasmControlResponse { inner })
            .map_err(js_error)
    }

    pub fn destroy(&self) {
        self.inner.destroy();
    }
}

#[wasm_bindgen::prelude::wasm_bindgen]
pub struct WasmControlResponse {
    inner: ControlResponse,
}

#[wasm_bindgen::prelude::wasm_bindgen]
pub struct WasmWsClientConnection {
    inner: WsClientConnection,
}

#[wasm_bindgen::prelude::wasm_bindgen]
impl WasmWsClientConnection {
    #[wasm_bindgen::prelude::wasm_bindgen(constructor)]
    pub fn new(
        node_public_key: Vec<u8>,
        session_id: Vec<u8>,
        transport_root: Vec<u8>,
        ticket: Vec<u8>,
    ) -> Result<WasmWsClientConnection, wasm_bindgen::JsValue> {
        WsClientConnection::new(node_public_key, session_id, transport_root, ticket)
            .map(|inner| Self { inner })
            .map_err(js_error)
    }

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = clientHelloBytes)]
    pub fn client_hello_bytes(&self) -> Result<Vec<u8>, wasm_bindgen::JsValue> {
        self.inner.client_hello_bytes().map_err(js_error)
    }

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = openServerHello)]
    pub fn open_server_hello(&self, response: Vec<u8>) -> Result<(), wasm_bindgen::JsValue> {
        self.inner.open_server_hello(response).map_err(js_error)
    }

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = sealFrame)]
    pub fn seal_frame(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, wasm_bindgen::JsValue> {
        self.inner.seal_frame(plaintext).map_err(js_error)
    }

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = openFrame)]
    pub fn open_frame(&self, record: Vec<u8>) -> Result<Vec<u8>, wasm_bindgen::JsValue> {
        self.inner.open_frame(record).map_err(js_error)
    }

    pub fn ready(&self) -> bool {
        self.inner.ready()
    }

    pub fn destroy(&self) {
        self.inner.destroy();
    }
}

impl Drop for WasmControlResponse {
    fn drop(&mut self) {
        if let ControlResponse::WsTicket { ticket, .. } = &mut self.inner {
            ticket.zeroize();
        }
    }
}

#[wasm_bindgen::prelude::wasm_bindgen]
impl WasmControlResponse {
    #[wasm_bindgen::prelude::wasm_bindgen(getter)]
    pub fn kind(&self) -> u8 {
        match &self.inner {
            ControlResponse::Failure => 0,
            ControlResponse::WsTicket { .. } => 1,
            ControlResponse::LoggedOut => 2,
        }
    }

    #[wasm_bindgen::prelude::wasm_bindgen(getter)]
    pub fn ticket(&self) -> String {
        match &self.inner {
            ControlResponse::WsTicket { ticket, .. } => ticket.clone(),
            _ => String::new(),
        }
    }

    #[wasm_bindgen::prelude::wasm_bindgen(getter, js_name = expiresInSec)]
    pub fn expires_in_sec(&self) -> u32 {
        match &self.inner {
            ControlResponse::WsTicket { expires_in_sec, .. } => *expires_in_sec,
            _ => 0,
        }
    }
}

#[wasm_bindgen::prelude::wasm_bindgen]
pub struct WasmAccountBootstrapExchange {
    inner: AccountBootstrapExchange,
}

#[wasm_bindgen::prelude::wasm_bindgen]
impl WasmAccountBootstrapExchange {
    #[wasm_bindgen::prelude::wasm_bindgen(js_name = start)]
    pub fn start(
        node_public_key: Vec<u8>,
        bootstrap_public_key: Vec<u8>,
        capability: Vec<u8>,
        registration_request: Vec<u8>,
        credential_request: Vec<u8>,
    ) -> Result<WasmAccountBootstrapExchange, wasm_bindgen::JsValue> {
        AccountBootstrapExchange::start(
            node_public_key,
            bootstrap_public_key,
            capability,
            registration_request,
            credential_request,
        )
        .map(|inner| Self { inner })
        .map_err(js_error)
    }

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = finishRegistration)]
    #[allow(clippy::too_many_arguments)]
    pub fn finish_registration(
        node_public_key: Vec<u8>,
        bootstrap_public_key: Vec<u8>,
        handshake_id: Vec<u8>,
        registration_upload: Vec<u8>,
        identity_public: Vec<u8>,
        identity_prekey_id: String,
        identity_envelope: Vec<u8>,
        identity_proof: Vec<u8>,
    ) -> Result<WasmAccountBootstrapExchange, wasm_bindgen::JsValue> {
        AccountBootstrapExchange::finish_registration(
            node_public_key,
            bootstrap_public_key,
            AccountBootstrapRegistrationFinishInput {
                handshake_id,
                registration_upload,
                identity_public,
                identity_prekey_id,
                identity_envelope,
                identity_proof,
            },
        )
        .map(|inner| Self { inner })
        .map_err(js_error)
    }

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = finishLogin)]
    pub fn finish_login(
        node_public_key: Vec<u8>,
        bootstrap_public_key: Vec<u8>,
        handshake_id: Vec<u8>,
        credential_finalization: Vec<u8>,
    ) -> Result<WasmAccountBootstrapExchange, wasm_bindgen::JsValue> {
        AccountBootstrapExchange::finish_login(
            node_public_key,
            bootstrap_public_key,
            handshake_id,
            credential_finalization,
        )
        .map(|inner| Self { inner })
        .map_err(js_error)
    }

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = requestBytes)]
    pub fn request_bytes(&self) -> Result<Vec<u8>, wasm_bindgen::JsValue> {
        self.inner.request_bytes().map_err(js_error)
    }

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = openResponse)]
    pub fn open_response(
        &self,
        response: Vec<u8>,
    ) -> Result<WasmAccountBootstrapResponse, wasm_bindgen::JsValue> {
        self.inner
            .open_response(response)
            .map(|inner| WasmAccountBootstrapResponse { inner })
            .map_err(js_error)
    }

    pub fn destroy(&self) {
        self.inner.destroy();
    }
}

#[wasm_bindgen::prelude::wasm_bindgen]
pub struct WasmAccountBootstrapResponse {
    inner: AccountBootstrapResponse,
}

impl Drop for WasmAccountBootstrapResponse {
    fn drop(&mut self) {
        match &mut self.inner {
            AccountBootstrapResponse::Failure => {}
            AccountBootstrapResponse::LoginStart {
                handshake_id,
                credential_response,
                identity_public,
                identity_prekey_id,
                identity_envelope,
            } => {
                handshake_id.zeroize();
                credential_response.zeroize();
                identity_public.zeroize();
                identity_prekey_id.zeroize();
                identity_envelope.zeroize();
            }
            AccountBootstrapResponse::RegistrationStart {
                handshake_id,
                registration_response,
                challenge,
            } => {
                handshake_id.zeroize();
                registration_response.zeroize();
                challenge.zeroize();
            }
            AccountBootstrapResponse::RegistrationContinuation {
                handshake_id,
                credential_response,
            } => {
                handshake_id.zeroize();
                credential_response.zeroize();
            }
            AccountBootstrapResponse::Session {
                session_id,
                username,
                identity_public,
                identity_prekey_id,
                identity_envelope,
                ..
            } => {
                session_id.zeroize();
                username.zeroize();
                identity_public.zeroize();
                identity_prekey_id.zeroize();
                identity_envelope.zeroize();
            }
        }
    }
}

#[wasm_bindgen::prelude::wasm_bindgen]
impl WasmAccountBootstrapResponse {
    #[wasm_bindgen::prelude::wasm_bindgen(getter)]
    pub fn kind(&self) -> u8 {
        match &self.inner {
            AccountBootstrapResponse::Failure => 0,
            AccountBootstrapResponse::LoginStart { .. } => 1,
            AccountBootstrapResponse::RegistrationStart { .. } => 2,
            AccountBootstrapResponse::RegistrationContinuation { .. } => 3,
            AccountBootstrapResponse::Session { .. } => 4,
        }
    }

    #[wasm_bindgen::prelude::wasm_bindgen(getter, js_name = handshakeId)]
    pub fn handshake_id(&self) -> Vec<u8> {
        match &self.inner {
            AccountBootstrapResponse::LoginStart { handshake_id, .. }
            | AccountBootstrapResponse::RegistrationStart { handshake_id, .. }
            | AccountBootstrapResponse::RegistrationContinuation { handshake_id, .. } => {
                handshake_id.clone()
            }
            _ => Vec::new(),
        }
    }

    #[wasm_bindgen::prelude::wasm_bindgen(getter, js_name = opaqueResponse)]
    pub fn opaque_response(&self) -> Vec<u8> {
        match &self.inner {
            AccountBootstrapResponse::LoginStart {
                credential_response,
                ..
            }
            | AccountBootstrapResponse::RegistrationContinuation {
                credential_response,
                ..
            } => credential_response.clone(),
            AccountBootstrapResponse::RegistrationStart {
                registration_response,
                ..
            } => registration_response.clone(),
            _ => Vec::new(),
        }
    }

    #[wasm_bindgen::prelude::wasm_bindgen(getter)]
    pub fn challenge(&self) -> Vec<u8> {
        match &self.inner {
            AccountBootstrapResponse::RegistrationStart { challenge, .. } => challenge.clone(),
            _ => Vec::new(),
        }
    }

    #[wasm_bindgen::prelude::wasm_bindgen(getter, js_name = sessionId)]
    pub fn session_id(&self) -> Vec<u8> {
        match &self.inner {
            AccountBootstrapResponse::Session { session_id, .. } => session_id.clone(),
            _ => Vec::new(),
        }
    }

    #[wasm_bindgen::prelude::wasm_bindgen(getter)]
    pub fn username(&self) -> String {
        match &self.inner {
            AccountBootstrapResponse::Session { username, .. } => username.clone(),
            _ => String::new(),
        }
    }

    #[wasm_bindgen::prelude::wasm_bindgen(getter)]
    pub fn created(&self) -> bool {
        match &self.inner {
            AccountBootstrapResponse::Session { created, .. } => *created,
            _ => false,
        }
    }

    #[wasm_bindgen::prelude::wasm_bindgen(getter, js_name = maxRoomsPerUser)]
    pub fn max_rooms_per_user(&self) -> u32 {
        match &self.inner {
            AccountBootstrapResponse::Session {
                max_rooms_per_user, ..
            } => *max_rooms_per_user,
            _ => 0,
        }
    }

    #[wasm_bindgen::prelude::wasm_bindgen(getter, js_name = sessionInactivitySec)]
    pub fn session_inactivity_sec(&self) -> u32 {
        match &self.inner {
            AccountBootstrapResponse::Session {
                session_inactivity_sec,
                ..
            } => *session_inactivity_sec,
            _ => 0,
        }
    }

    #[wasm_bindgen::prelude::wasm_bindgen(getter, js_name = identityPublic)]
    pub fn identity_public(&self) -> Vec<u8> {
        match &self.inner {
            AccountBootstrapResponse::LoginStart {
                identity_public, ..
            }
            | AccountBootstrapResponse::Session {
                identity_public, ..
            } => identity_public.clone(),
            _ => Vec::new(),
        }
    }

    #[wasm_bindgen::prelude::wasm_bindgen(getter, js_name = identityPrekeyId)]
    pub fn identity_prekey_id(&self) -> String {
        match &self.inner {
            AccountBootstrapResponse::LoginStart {
                identity_prekey_id, ..
            }
            | AccountBootstrapResponse::Session {
                identity_prekey_id, ..
            } => identity_prekey_id.clone(),
            _ => String::new(),
        }
    }

    #[wasm_bindgen::prelude::wasm_bindgen(getter, js_name = identityEnvelope)]
    pub fn identity_envelope(&self) -> Vec<u8> {
        match &self.inner {
            AccountBootstrapResponse::LoginStart {
                identity_envelope, ..
            }
            | AccountBootstrapResponse::Session {
                identity_envelope, ..
            } => identity_envelope.clone(),
            _ => Vec::new(),
        }
    }
}

#[wasm_bindgen::prelude::wasm_bindgen(js_name = verifyTransportNodeDescriptor)]
pub fn verify_transport_node_descriptor_wasm(
    descriptor: Vec<u8>,
    expected_node_public_key: Vec<u8>,
    expected_node_url: String,
) -> Result<Vec<u8>, wasm_bindgen::JsValue> {
    verify_transport_node_descriptor(descriptor, expected_node_public_key, expected_node_url)
        .map(|verified| verified.bootstrap_public_key)
        .map_err(js_error)
}
