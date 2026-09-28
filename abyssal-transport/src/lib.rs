//! Pure cryptographic primitives for Abyssal transport protocol v11.
//!
//! This crate owns bounded canonical records and key schedules. It deliberately
//! performs no I/O, HTTP, WebSocket, authentication, or persistence.

mod account_bootstrap;
mod attachment;
mod bootstrap;
mod control;
mod handshake;
mod key_schedule;
mod records;

pub use bootstrap::{
    generate_bootstrap_keypair, inspect_bootstrap_request, seal_bootstrap_request,
    BootstrapClientExchange, BootstrapContext, BootstrapKeyPair, BootstrapPrivateKey,
    BootstrapReplayGuard, BootstrapRequestHeader, BootstrapResponseOpener, BootstrapResponseSealer,
    BootstrapServerExchange,
};
pub use handshake::{
    inspect_ws_client_hello, inspect_ws_server_hello, open_ws_client_hello, open_ws_server_hello,
    seal_ws_client_hello, seal_ws_server_hello, WsClientHelloHeader, WsServerHelloHeader,
    MAX_WS_TICKET_BYTES, WS_CLIENT_HELLO_BYTES, WS_HELLO_MAGIC, WS_HELLO_VERSION,
    WS_SERVER_HELLO_BYTES,
};
pub use key_schedule::derive_opaque_transport_root;
pub use records::{
    inspect_http_record, ConnectionNonce, HttpClientRecords, HttpOpener, HttpRecordHeader,
    HttpSealer, HttpServerRecords, HttpSessionBinding, WsClientRecords, WsConnectionBinding,
    WsOpener, WsSealer, WsServerRecords,
};

pub const TRANSPORT_VERSION: u8 = 11;
pub const MAX_BOOTSTRAP_PLAINTEXT_BYTES: usize = 64 * 1024;
pub const MAX_RECORD_PLAINTEXT_BYTES: usize = 1024 * 1024;
pub const MAX_WS_RECORD_PLAINTEXT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_AAD_BYTES: usize = 4 * 1024;
pub const MAX_OPERATION_BYTES: usize = 64;
pub const MAX_SESSION_CONTEXT_BYTES: usize = 512;
pub const WS_FRAME_AAD: &[u8] = b"ABYSSAL-TRANSPORT-V11-WS-FRAME";
pub const MAX_HTTP_HANDLES: usize = 4096;
pub const MAX_BOOTSTRAP_REQUEST_IDS: usize = 4096;
pub const MIN_BOOTSTRAP_REPLAY_TTL_MS: u64 = 1;
pub const MAX_BOOTSTRAP_REPLAY_TTL_MS: u64 = 24 * 60 * 60 * 1000;

pub(crate) const TAG_BYTES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TransportError {
    #[error("invalid transport input")]
    InvalidInput,
    #[error("transport input exceeds protocol limit")]
    TooLarge,
    #[error("transport authentication failed")]
    AuthenticationFailed,
    #[error("transport record is not canonical")]
    NonCanonical,
    #[error("transport record replayed")]
    Replay,
    #[error("transport record counter gap")]
    CounterGap,
    #[error("transport counter exhausted")]
    CounterExhausted,
    #[error("transport state capacity exhausted")]
    CapacityExhausted,
    #[error("transport timestamp moved backwards")]
    ClockRollback,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum Direction {
    ClientToServer = 1,
    ServerToClient = 2,
}

impl Direction {
    pub(crate) fn from_byte(value: u8) -> Result<Self, TransportError> {
        match value {
            1 => Ok(Self::ClientToServer),
            2 => Ok(Self::ServerToClient),
            _ => Err(TransportError::NonCanonical),
        }
    }
}

pub(crate) fn canonical_parts(parts: &[&[u8]]) -> Vec<u8> {
    let capacity = parts
        .iter()
        .fold(0_usize, |total, part| total.saturating_add(4 + part.len()));
    let mut output = Vec::with_capacity(capacity);
    for part in parts {
        output.extend_from_slice(&(part.len() as u32).to_be_bytes());
        output.extend_from_slice(part);
    }
    output
}

pub(crate) fn validate_aad(aad: &[u8]) -> Result<(), TransportError> {
    if aad.len() > MAX_AAD_BYTES {
        return Err(TransportError::TooLarge);
    }
    Ok(())
}

pub(crate) fn validate_plaintext(value: &[u8], maximum: usize) -> Result<(), TransportError> {
    if value.is_empty() {
        return Err(TransportError::InvalidInput);
    }
    if value.len() > maximum {
        return Err(TransportError::TooLarge);
    }
    Ok(())
}

pub(crate) fn read_u32(value: &[u8]) -> Result<usize, TransportError> {
    let bytes: [u8; 4] = value.try_into().map_err(|_| TransportError::NonCanonical)?;
    usize::try_from(u32::from_be_bytes(bytes)).map_err(|_| TransportError::TooLarge)
}

pub(crate) fn read_u64(value: &[u8]) -> Result<u64, TransportError> {
    let bytes: [u8; 8] = value.try_into().map_err(|_| TransportError::NonCanonical)?;
    Ok(u64::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests;
pub use account_bootstrap::{
    decode_account_bootstrap_action, decode_account_bootstrap_result,
    encode_account_bootstrap_action, encode_account_bootstrap_result, AccountBootstrapAction,
    AccountBootstrapResult, ACCOUNT_BOOTSTRAP_HEADER_BYTES, ACCOUNT_BOOTSTRAP_OPERATION,
    MAX_ACCOUNT_BOOTSTRAP_FIELD_BYTES,
};
pub use attachment::{
    attachment_bucket_frame_count, attachment_data_frame_count, decode_attachment_action,
    decode_attachment_result, encode_attachment_action, encode_attachment_result, AttachmentAction,
    AttachmentFrame, AttachmentMediaType, AttachmentResult, AttachmentStreamBinding,
    AttachmentStreamOpener, AttachmentStreamSealer, ATTACHMENT_ACTION_AAD,
    ATTACHMENT_ACTION_PLAINTEXT_BYTES, ATTACHMENT_ACTION_RECORD_BYTES,
    ATTACHMENT_STREAM_FRAME_BYTES, ATTACHMENT_STREAM_HEADER_BYTES, ATTACHMENT_STREAM_PAYLOAD_BYTES,
    ATTACHMENT_STREAM_PLAINTEXT_BYTES, MAX_ATTACHMENT_BUCKET_FRAMES, MAX_ATTACHMENT_CHAT_ID_BYTES,
    MAX_ATTACHMENT_CIPHERTEXT_BYTES, MAX_ATTACHMENT_MESSAGE_ID_BYTES, MAX_ATTACHMENT_TTL_SEC,
};
pub use control::{
    decode_control_action, decode_control_result, encode_control_action, encode_control_result,
    ControlAction, ControlResult, CONTROL_AAD, CONTROL_OPERATION, CONTROL_PLAINTEXT_BYTES,
    CONTROL_RECORD_BYTES, MAX_CONTROL_PLATFORM_BYTES, MAX_CONTROL_SIGNATURE_BYTES,
    MAX_CONTROL_TICKET_BYTES, MAX_CONTROL_VERSION_BYTES,
};
