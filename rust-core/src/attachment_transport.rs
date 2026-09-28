//! Platform-safe client facade for transport-v11 attachment operations.

use crate::AbyssalError;
use abyssal_transport::{
    decode_attachment_result, encode_attachment_action, AttachmentAction, AttachmentFrame,
    AttachmentMediaType, AttachmentResult, AttachmentStreamBinding, AttachmentStreamOpener,
    AttachmentStreamSealer, Direction, HttpOpener, HttpSessionBinding, ATTACHMENT_ACTION_AAD,
    ATTACHMENT_ACTION_RECORD_BYTES,
};
use rand::{rngs::OsRng, RngCore};
use std::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExchangeKind {
    Upload,
    Download,
    Command,
}

#[derive(uniffi::Record)]
pub struct AttachmentUploadInput {
    pub chat_id: String,
    pub message_id: String,
    pub media_type: String,
    pub cipher_version: u8,
    pub ciphertext_len: u64,
    pub ciphertext_sha256: Vec<u8>,
    pub one_time: bool,
    pub delete_after_download: bool,
    pub requested_ttl_sec: u32,
}

#[derive(uniffi::Enum)]
pub enum AttachmentTransportResult {
    Failure,
    Success,
    UploadAccepted {
        attachment_id: Vec<u8>,
    },
    DownloadAccepted {
        claim_id: Option<Vec<u8>>,
        ciphertext_len: u64,
        ciphertext_sha256: Vec<u8>,
        data_frame_count: u16,
        bucket_frame_count: u16,
    },
}

#[derive(uniffi::Enum)]
pub enum AttachmentTransportFrame {
    Data { payload: Vec<u8> },
    Padding,
    End,
}

struct AttachmentClientExchangeState {
    request: Zeroizing<Vec<u8>>,
    response_opener: Option<HttpOpener>,
    upload_sealer: Option<AttachmentStreamSealer>,
    download_opener: Option<AttachmentStreamOpener>,
    root: Zeroizing<[u8; 32]>,
    node_public_key: [u8; 32],
    session_id: [u8; 32],
    handle: [u8; 16],
    kind: ExchangeKind,
    response_authenticated: bool,
    destroyed: bool,
}

impl Drop for AttachmentClientExchangeState {
    fn drop(&mut self) {
        self.destroy();
    }
}

impl AttachmentClientExchangeState {
    fn destroy(&mut self) {
        self.request.zeroize();
        self.response_opener.take();
        self.upload_sealer.take();
        self.download_opener.take();
        self.root.zeroize();
        self.node_public_key.zeroize();
        self.session_id.zeroize();
        self.handle.zeroize();
        self.response_authenticated = false;
        self.destroyed = true;
    }
}

/// Retry-safe attachment action plus its operation-bound stream state.
///
/// Once any upload stream frame has been transmitted, an interrupted upload
/// must be abandoned and restarted with a fresh exchange/handle. Reusing a
/// handle with newly sealed stream bytes would reuse AEAD nonces. After a
/// complete End frame, the exact cached action request may be retried while
/// awaiting its authenticated relay receipt.
#[derive(uniffi::Object)]
pub struct AttachmentClientExchange {
    state: Mutex<AttachmentClientExchangeState>,
}

#[uniffi::export]
impl AttachmentClientExchange {
    #[uniffi::constructor]
    pub fn begin_upload(
        node_public_key: Vec<u8>,
        session_id: Vec<u8>,
        transport_root: Vec<u8>,
        input: AttachmentUploadInput,
    ) -> Result<Self, AbyssalError> {
        let AttachmentUploadInput {
            chat_id,
            message_id,
            media_type,
            cipher_version,
            ciphertext_len,
            ciphertext_sha256,
            one_time,
            delete_after_download,
            requested_ttl_sec,
        } = input;
        let action = AttachmentAction::BeginUpload {
            chat_id: Zeroizing::new(chat_id),
            message_id: Zeroizing::new(message_id),
            media_type: parse_media_type(&media_type)?,
            cipher_version,
            ciphertext_len,
            ciphertext_sha256: exact_array(
                Zeroizing::new(ciphertext_sha256),
                "Attachment unavailable",
            )?,
            one_time,
            delete_after_download,
            requested_ttl_sec,
        };
        Self::create(
            node_public_key,
            session_id,
            transport_root,
            action,
            ExchangeKind::Upload,
            Some(ciphertext_len),
        )
    }

    #[uniffi::constructor]
    pub fn begin_download(
        node_public_key: Vec<u8>,
        session_id: Vec<u8>,
        transport_root: Vec<u8>,
        attachment_id: Vec<u8>,
    ) -> Result<Self, AbyssalError> {
        Self::create(
            node_public_key,
            session_id,
            transport_root,
            AttachmentAction::BeginDownload {
                attachment_id: exact_array(
                    Zeroizing::new(attachment_id),
                    "Attachment unavailable",
                )?,
            },
            ExchangeKind::Download,
            None,
        )
    }

    #[uniffi::constructor]
    pub fn complete_download(
        node_public_key: Vec<u8>,
        session_id: Vec<u8>,
        transport_root: Vec<u8>,
        attachment_id: Vec<u8>,
        claim_id: Option<Vec<u8>>,
    ) -> Result<Self, AbyssalError> {
        Self::command(
            node_public_key,
            session_id,
            transport_root,
            attachment_id,
            claim_id,
            true,
        )
    }

    #[uniffi::constructor]
    pub fn release_download(
        node_public_key: Vec<u8>,
        session_id: Vec<u8>,
        transport_root: Vec<u8>,
        attachment_id: Vec<u8>,
        claim_id: Option<Vec<u8>>,
    ) -> Result<Self, AbyssalError> {
        Self::command(
            node_public_key,
            session_id,
            transport_root,
            attachment_id,
            claim_id,
            false,
        )
    }

    #[uniffi::constructor]
    pub fn delete_attachment(
        node_public_key: Vec<u8>,
        session_id: Vec<u8>,
        transport_root: Vec<u8>,
        attachment_id: Vec<u8>,
    ) -> Result<Self, AbyssalError> {
        Self::create(
            node_public_key,
            session_id,
            transport_root,
            AttachmentAction::DeleteAttachment {
                attachment_id: exact_array(
                    Zeroizing::new(attachment_id),
                    "Attachment unavailable",
                )?,
            },
            ExchangeKind::Command,
            None,
        )
    }

    pub fn request_bytes(&self) -> Result<Vec<u8>, AbyssalError> {
        let state = self.lock()?;
        if state.destroyed || state.response_authenticated {
            return Err(failure());
        }
        Ok(state.request.to_vec())
    }

    pub fn upload_data_frame_count(&self) -> Result<u16, AbyssalError> {
        let state = self.lock()?;
        state
            .upload_sealer
            .as_ref()
            .filter(|_| !state.destroyed)
            .map(AttachmentStreamSealer::data_frame_count)
            .ok_or_else(failure)
    }

    pub fn upload_bucket_frame_count(&self) -> Result<u16, AbyssalError> {
        let state = self.lock()?;
        state
            .upload_sealer
            .as_ref()
            .filter(|_| !state.destroyed)
            .map(AttachmentStreamSealer::bucket_frame_count)
            .ok_or_else(failure)
    }

    pub fn seal_data_frame(&self, payload: Vec<u8>) -> Result<Vec<u8>, AbyssalError> {
        let payload = Zeroizing::new(payload);
        let mut state = self.lock()?;
        if state.destroyed || state.response_authenticated {
            return Err(failure());
        }
        state
            .upload_sealer
            .as_mut()
            .ok_or_else(failure)?
            .seal_data(&payload)
            .map(|record| record.to_vec())
            .map_err(|_| failure())
    }

    pub fn seal_padding_frame(&self) -> Result<Vec<u8>, AbyssalError> {
        let mut state = self.lock()?;
        if state.destroyed || state.response_authenticated {
            return Err(failure());
        }
        state
            .upload_sealer
            .as_mut()
            .ok_or_else(failure)?
            .seal_padding()
            .map(|record| record.to_vec())
            .map_err(|_| failure())
    }

    pub fn seal_end_frame(&self) -> Result<Vec<u8>, AbyssalError> {
        let mut state = self.lock()?;
        if state.destroyed || state.response_authenticated {
            return Err(failure());
        }
        state
            .upload_sealer
            .as_mut()
            .ok_or_else(failure)?
            .seal_end()
            .map(|record| record.to_vec())
            .map_err(|_| failure())
    }

    /// Unauthenticated failures preserve the exact request and operation state.
    /// The first authenticated result consumes the request before semantic decode.
    pub fn open_response(
        &self,
        response: Vec<u8>,
    ) -> Result<AttachmentTransportResult, AbyssalError> {
        let response = Zeroizing::new(response);
        if response.len() != ATTACHMENT_ACTION_RECORD_BYTES {
            return Err(failure());
        }
        let mut state = self.lock()?;
        if state.destroyed || state.response_authenticated {
            return Err(failure());
        }
        let handle = state.handle;
        let plaintext = state
            .response_opener
            .as_mut()
            .ok_or_else(failure)?
            .open(handle, ATTACHMENT_ACTION_AAD, &response)
            .map_err(|_| failure())?;
        state.response_opener.take();
        state.request.zeroize();
        state.response_authenticated = true;

        let result = match decode_attachment_result(&plaintext) {
            Ok(result) if valid_result_for_kind(state.kind, &result) => result,
            _ => {
                state.destroy();
                return Err(failure());
            }
        };
        if state.kind == ExchangeKind::Upload
            && matches!(result, AttachmentResult::UploadAccepted { .. })
            && !state
                .upload_sealer
                .as_ref()
                .is_some_and(AttachmentStreamSealer::is_complete)
        {
            state.destroy();
            return Err(failure());
        }
        if let AttachmentResult::DownloadAccepted {
            ciphertext_len,
            data_frame_count,
            bucket_frame_count,
            ..
        } = &result
        {
            let opener =
                AttachmentStreamBinding::new(state.node_public_key, state.session_id, state.handle)
                    .and_then(|binding| {
                        binding.into_opener(
                            &state.root,
                            Direction::ServerToClient,
                            *ciphertext_len,
                            *data_frame_count,
                            *bucket_frame_count,
                        )
                    });
            let opener = match opener {
                Ok(opener) => opener,
                Err(_) => {
                    state.destroy();
                    return Err(failure());
                }
            };
            state.download_opener = Some(opener);
        }
        let public = public_result(result);
        if state.download_opener.is_none() {
            state.destroy();
            return Ok(public);
        }
        state.root.zeroize();
        state.node_public_key.zeroize();
        state.session_id.zeroize();
        state.handle.zeroize();
        state.upload_sealer.take();
        Ok(public)
    }

    pub fn open_stream_frame(
        &self,
        frame: Vec<u8>,
    ) -> Result<AttachmentTransportFrame, AbyssalError> {
        let frame = Zeroizing::new(frame);
        let mut state = self.lock()?;
        if state.destroyed || !state.response_authenticated {
            return Err(failure());
        }
        state
            .download_opener
            .as_mut()
            .ok_or_else(failure)?
            .open(&frame)
            .map(public_frame)
            .map_err(|_| failure())
    }

    pub fn stream_complete(&self) -> bool {
        self.state
            .lock()
            .ok()
            .and_then(|state| {
                state
                    .download_opener
                    .as_ref()
                    .map(AttachmentStreamOpener::is_complete)
            })
            .unwrap_or(false)
    }
}

impl AttachmentClientExchange {
    pub fn destroy(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.destroy();
        }
    }

    fn command(
        node_public_key: Vec<u8>,
        session_id: Vec<u8>,
        transport_root: Vec<u8>,
        attachment_id: Vec<u8>,
        claim_id: Option<Vec<u8>>,
        complete: bool,
    ) -> Result<Self, AbyssalError> {
        let attachment_id = exact_array(Zeroizing::new(attachment_id), "Attachment unavailable")?;
        let claim_id = claim_id
            .map(|id| exact_array(Zeroizing::new(id), "Attachment unavailable"))
            .transpose()?;
        let action = if complete {
            AttachmentAction::CompleteDownload {
                attachment_id,
                claim_id,
            }
        } else {
            AttachmentAction::ReleaseDownload {
                attachment_id,
                claim_id,
            }
        };
        Self::create(
            node_public_key,
            session_id,
            transport_root,
            action,
            ExchangeKind::Command,
            None,
        )
    }

    fn create(
        node_public_key: Vec<u8>,
        session_id: Vec<u8>,
        transport_root: Vec<u8>,
        action: AttachmentAction,
        kind: ExchangeKind,
        upload_ciphertext_len: Option<u64>,
    ) -> Result<Self, AbyssalError> {
        let node_public_key = Zeroizing::new(exact_array(
            Zeroizing::new(node_public_key),
            "Attachment unavailable",
        )?);
        let session_id = Zeroizing::new(exact_array(
            Zeroizing::new(session_id),
            "Attachment unavailable",
        )?);
        let root = Zeroizing::new(exact_array(
            Zeroizing::new(transport_root),
            "Attachment unavailable",
        )?);
        let plaintext = encode_attachment_action(&action).map_err(|_| failure())?;
        let handle = random_nonzero_handle();
        let mut records = HttpSessionBinding::new(*node_public_key, *session_id)
            .map_err(|_| failure())?
            .into_client(&root)
            .map_err(|_| failure())?;
        let request = records
            .sealer
            .seal(handle, ATTACHMENT_ACTION_AAD, &plaintext)
            .map_err(|_| failure())?;
        let upload_sealer =
            upload_ciphertext_len
                .map(|length| {
                    AttachmentStreamBinding::new(*node_public_key, *session_id, handle)?
                        .into_sealer(&root, Direction::ClientToServer, length)
                })
                .transpose()
                .map_err(|_| failure())?;
        Ok(Self {
            state: Mutex::new(AttachmentClientExchangeState {
                request: Zeroizing::new(request),
                response_opener: Some(records.opener),
                upload_sealer,
                download_opener: None,
                root,
                node_public_key: *node_public_key,
                session_id: *session_id,
                handle,
                kind,
                response_authenticated: false,
                destroyed: false,
            }),
        })
    }

    fn lock(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, AttachmentClientExchangeState>, AbyssalError> {
        self.state.lock().map_err(|_| failure())
    }
}

fn parse_media_type(value: &str) -> Result<AttachmentMediaType, AbyssalError> {
    match value {
        "IMAGE" => Ok(AttachmentMediaType::Image),
        "VIDEO" => Ok(AttachmentMediaType::Video),
        "FILE" => Ok(AttachmentMediaType::File),
        _ => Err(failure()),
    }
}

fn valid_result_for_kind(kind: ExchangeKind, result: &AttachmentResult) -> bool {
    matches!(result, AttachmentResult::Failure)
        || matches!(
            (kind, result),
            (
                ExchangeKind::Upload,
                AttachmentResult::UploadAccepted { .. }
            ) | (
                ExchangeKind::Download,
                AttachmentResult::DownloadAccepted { .. }
            ) | (ExchangeKind::Command, AttachmentResult::Success)
        )
}

fn public_result(result: AttachmentResult) -> AttachmentTransportResult {
    match result {
        AttachmentResult::Failure => AttachmentTransportResult::Failure,
        AttachmentResult::Success => AttachmentTransportResult::Success,
        AttachmentResult::UploadAccepted { attachment_id } => {
            AttachmentTransportResult::UploadAccepted {
                attachment_id: attachment_id.to_vec(),
            }
        }
        AttachmentResult::DownloadAccepted {
            claim_id,
            ciphertext_len,
            ciphertext_sha256,
            data_frame_count,
            bucket_frame_count,
        } => AttachmentTransportResult::DownloadAccepted {
            claim_id: claim_id.map(|id| id.to_vec()),
            ciphertext_len,
            ciphertext_sha256: ciphertext_sha256.to_vec(),
            data_frame_count,
            bucket_frame_count,
        },
    }
}

fn public_frame(frame: AttachmentFrame) -> AttachmentTransportFrame {
    match frame {
        AttachmentFrame::Data(payload) => AttachmentTransportFrame::Data {
            payload: payload.to_vec(),
        },
        AttachmentFrame::Padding => AttachmentTransportFrame::Padding,
        AttachmentFrame::End => AttachmentTransportFrame::End,
    }
}

fn random_nonzero_handle() -> [u8; 16] {
    loop {
        let mut handle = [0_u8; 16];
        OsRng.fill_bytes(&mut handle);
        if handle != [0; 16] {
            return handle;
        }
    }
}

fn exact_array<const N: usize>(
    mut value: Zeroizing<Vec<u8>>,
    _detail: &str,
) -> Result<[u8; N], AbyssalError> {
    if value.len() != N || value.iter().all(|byte| *byte == 0) {
        value.zeroize();
        return Err(failure());
    }
    let mut output = [0_u8; N];
    output.copy_from_slice(&value);
    value.zeroize();
    Ok(output)
}

fn failure() -> AbyssalError {
    AbyssalError::Failure {
        detail: "Attachment unavailable".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abyssal_transport::{
        decode_attachment_action, encode_attachment_result, AttachmentStreamBinding,
        HttpSessionBinding, ATTACHMENT_STREAM_FRAME_BYTES,
    };

    const NODE: [u8; 32] = [3; 32];
    const SESSION: [u8; 32] = [4; 32];
    const ROOT: [u8; 32] = [5; 32];

    fn upload_exchange(length: u64) -> AttachmentClientExchange {
        AttachmentClientExchange::begin_upload(
            NODE.to_vec(),
            SESSION.to_vec(),
            ROOT.to_vec(),
            AttachmentUploadInput {
                chat_id: "dm_Alice_Bob".to_owned(),
                message_id: "message-1".to_owned(),
                media_type: "FILE".to_owned(),
                cipher_version: 2,
                ciphertext_len: length,
                ciphertext_sha256: vec![9; 32],
                one_time: false,
                delete_after_download: false,
                requested_ttl_sec: 0,
            },
        )
        .unwrap()
    }

    fn server_records_for(
        exchange: &AttachmentClientExchange,
    ) -> ([u8; 16], abyssal_transport::HttpServerRecords, Vec<u8>) {
        let request = exchange.request_bytes().unwrap();
        let header = abyssal_transport::inspect_http_record(&request).unwrap();
        let mut server = HttpSessionBinding::new(NODE, SESSION)
            .unwrap()
            .into_server(&ROOT)
            .unwrap();
        let plaintext = server
            .opener
            .open(header.handle, ATTACHMENT_ACTION_AAD, &request)
            .unwrap();
        (header.handle, server, plaintext.to_vec())
    }

    fn response(
        server: &mut abyssal_transport::HttpServerRecords,
        handle: [u8; 16],
        result: &AttachmentResult,
    ) -> Vec<u8> {
        let plaintext = encode_attachment_result(result).unwrap();
        server
            .sealer
            .seal(handle, ATTACHMENT_ACTION_AAD, &plaintext)
            .unwrap()
    }

    #[test]
    fn facade_covers_all_action_constructors_and_public_result_fields() {
        for (media_type, expected_media_type) in [
            ("IMAGE", AttachmentMediaType::Image),
            ("VIDEO", AttachmentMediaType::Video),
            ("FILE", AttachmentMediaType::File),
        ] {
            let exchange = AttachmentClientExchange::begin_upload(
                NODE.to_vec(),
                SESSION.to_vec(),
                ROOT.to_vec(),
                AttachmentUploadInput {
                    chat_id: "chat".to_owned(),
                    message_id: "message".to_owned(),
                    media_type: media_type.to_owned(),
                    cipher_version: 1,
                    ciphertext_len: 1,
                    ciphertext_sha256: vec![9; 32],
                    one_time: true,
                    delete_after_download: true,
                    requested_ttl_sec: 3,
                },
            )
            .unwrap();
            let (_, _, action) = server_records_for(&exchange);
            let AttachmentAction::BeginUpload {
                media_type: decoded_media_type,
                one_time,
                delete_after_download,
                ..
            } = decode_attachment_action(&action).unwrap()
            else {
                panic!("expected upload action")
            };
            assert_eq!(decoded_media_type, expected_media_type);
            assert!(one_time);
            assert!(delete_after_download);
        }
        assert!(AttachmentClientExchange::begin_upload(
            NODE.to_vec(),
            SESSION.to_vec(),
            ROOT.to_vec(),
            AttachmentUploadInput {
                chat_id: "chat".to_owned(),
                message_id: "message".to_owned(),
                media_type: "file".to_owned(),
                cipher_version: 1,
                ciphertext_len: 1,
                ciphertext_sha256: vec![9; 32],
                one_time: false,
                delete_after_download: false,
                requested_ttl_sec: 0,
            },
        )
        .is_err());

        let complete = AttachmentClientExchange::complete_download(
            NODE.to_vec(),
            SESSION.to_vec(),
            ROOT.to_vec(),
            vec![7; 16],
            Some(vec![8; 16]),
        )
        .unwrap();
        let (handle, mut server, action) = server_records_for(&complete);
        assert!(matches!(
            decode_attachment_action(&action).unwrap(),
            AttachmentAction::CompleteDownload {
                attachment_id: [7, ..],
                claim_id: Some([8, ..]),
            }
        ));
        let reply = response(&mut server, handle, &AttachmentResult::Success);
        assert!(matches!(
            complete.open_response(reply).unwrap(),
            AttachmentTransportResult::Success
        ));

        let release = AttachmentClientExchange::release_download(
            NODE.to_vec(),
            SESSION.to_vec(),
            ROOT.to_vec(),
            vec![7; 16],
            None,
        )
        .unwrap();
        let (_, _, action) = server_records_for(&release);
        assert!(matches!(
            decode_attachment_action(&action).unwrap(),
            AttachmentAction::ReleaseDownload {
                attachment_id: [7, ..],
                claim_id: None,
            }
        ));

        let delete = AttachmentClientExchange::delete_attachment(
            NODE.to_vec(),
            SESSION.to_vec(),
            ROOT.to_vec(),
            vec![7; 16],
        )
        .unwrap();
        let (_, _, action) = server_records_for(&delete);
        assert!(matches!(
            decode_attachment_action(&action).unwrap(),
            AttachmentAction::DeleteAttachment {
                attachment_id: [7, ..],
            }
        ));

        let download = AttachmentClientExchange::begin_download(
            NODE.to_vec(),
            SESSION.to_vec(),
            ROOT.to_vec(),
            vec![7; 16],
        )
        .unwrap();
        let (handle, mut server, _) = server_records_for(&download);
        let reply = response(
            &mut server,
            handle,
            &AttachmentResult::DownloadAccepted {
                claim_id: None,
                ciphertext_len: 1,
                ciphertext_sha256: [9; 32],
                data_frame_count: 1,
                bucket_frame_count: 1,
            },
        );
        let AttachmentTransportResult::DownloadAccepted {
            claim_id,
            ciphertext_len,
            ciphertext_sha256,
            data_frame_count,
            bucket_frame_count,
        } = download.open_response(reply).unwrap()
        else {
            panic!("expected download result")
        };
        assert_eq!(claim_id, None);
        assert_eq!(ciphertext_len, 1);
        assert_eq!(ciphertext_sha256, vec![9; 32]);
        assert_eq!(data_frame_count, 1);
        assert_eq!(bucket_frame_count, 1);
    }

    #[test]
    fn unauthenticated_http_binding_failures_preserve_request_and_allow_retry() {
        for failure_kind in 0..=4 {
            let exchange = AttachmentClientExchange::delete_attachment(
                NODE.to_vec(),
                SESSION.to_vec(),
                ROOT.to_vec(),
                vec![7; 16],
            )
            .unwrap();
            let request = exchange.request_bytes().unwrap();
            let (handle, mut server, _) = server_records_for(&exchange);
            let bad = match failure_kind {
                0 => {
                    let mut wrong = HttpSessionBinding::new([9; 32], SESSION)
                        .unwrap()
                        .into_server(&ROOT)
                        .unwrap();
                    response(&mut wrong, handle, &AttachmentResult::Success)
                }
                1 => {
                    let mut wrong = HttpSessionBinding::new(NODE, [9; 32])
                        .unwrap()
                        .into_server(&ROOT)
                        .unwrap();
                    response(&mut wrong, handle, &AttachmentResult::Success)
                }
                2 => {
                    let mut wrong = HttpSessionBinding::new(NODE, SESSION)
                        .unwrap()
                        .into_server(&[9; 32])
                        .unwrap();
                    response(&mut wrong, handle, &AttachmentResult::Success)
                }
                3 => {
                    let mut wrong = HttpSessionBinding::new(NODE, SESSION)
                        .unwrap()
                        .into_server(&ROOT)
                        .unwrap();
                    response(&mut wrong, [8; 16], &AttachmentResult::Success)
                }
                4 => {
                    let mut wrong = HttpSessionBinding::new(NODE, SESSION)
                        .unwrap()
                        .into_server(&ROOT)
                        .unwrap();
                    let plain = encode_attachment_result(&AttachmentResult::Success).unwrap();
                    wrong.sealer.seal(handle, b"wrong-aad", &plain).unwrap()
                }
                _ => unreachable!(),
            };
            assert!(
                exchange.open_response(bad).is_err(),
                "failure kind {failure_kind}"
            );
            assert_eq!(exchange.request_bytes().unwrap(), request);
            let valid = response(&mut server, handle, &AttachmentResult::Success);
            assert!(matches!(
                exchange.open_response(valid).unwrap(),
                AttachmentTransportResult::Success
            ));
        }

        let exchange = AttachmentClientExchange::delete_attachment(
            NODE.to_vec(),
            SESSION.to_vec(),
            ROOT.to_vec(),
            vec![7; 16],
        )
        .unwrap();
        let request = exchange.request_bytes().unwrap();
        let (handle, mut server, _) = server_records_for(&exchange);
        let mut bad = response(&mut server, handle, &AttachmentResult::Success);
        bad[5] = Direction::ClientToServer as u8;
        assert!(exchange.open_response(bad).is_err());
        assert_eq!(exchange.request_bytes().unwrap(), request);
        let mut valid_server = HttpSessionBinding::new(NODE, SESSION)
            .unwrap()
            .into_server(&ROOT)
            .unwrap();
        let valid = response(&mut valid_server, handle, &AttachmentResult::Success);
        assert!(matches!(
            exchange.open_response(valid).unwrap(),
            AttachmentTransportResult::Success
        ));
    }

    #[test]
    fn upload_facade_seals_exact_bucket_and_authenticates_result() {
        let exchange = upload_exchange(7);
        assert_eq!(exchange.upload_data_frame_count().unwrap(), 1);
        assert_eq!(exchange.upload_bucket_frame_count().unwrap(), 1);
        let data = exchange.seal_data_frame(b"payload".to_vec()).unwrap();
        let end = exchange.seal_end_frame().unwrap();
        assert_eq!(data.len(), ATTACHMENT_STREAM_FRAME_BYTES);
        assert_eq!(end.len(), ATTACHMENT_STREAM_FRAME_BYTES);
        let (handle, mut server, action) = server_records_for(&exchange);
        assert!(matches!(
            decode_attachment_action(&action).unwrap(),
            AttachmentAction::BeginUpload {
                ciphertext_len: 7,
                ..
            }
        ));
        let reply = response(
            &mut server,
            handle,
            &AttachmentResult::UploadAccepted {
                attachment_id: [7; 16],
            },
        );
        let AttachmentTransportResult::UploadAccepted { attachment_id } =
            exchange.open_response(reply).unwrap()
        else {
            panic!("expected upload acceptance")
        };
        assert_eq!(attachment_id, vec![7; 16]);
        assert!(exchange.request_bytes().is_err());
        assert!(exchange.seal_data_frame(b"x".to_vec()).is_err());
    }

    #[test]
    fn early_authenticated_upload_failure_is_accepted_and_destroys_exchange() {
        let exchange = upload_exchange(7);
        let (handle, mut server, _) = server_records_for(&exchange);
        let reply = response(&mut server, handle, &AttachmentResult::Failure);
        assert!(matches!(
            exchange.open_response(reply).unwrap(),
            AttachmentTransportResult::Failure
        ));
        assert!(exchange.request_bytes().is_err());
        assert!(exchange.seal_data_frame(b"payload".to_vec()).is_err());
        assert!(exchange.seal_end_frame().is_err());
    }

    #[test]
    fn premature_authenticated_upload_acceptance_fails_and_destroys_exchange() {
        let exchange = upload_exchange(7);
        let (handle, mut server, _) = server_records_for(&exchange);
        let reply = response(
            &mut server,
            handle,
            &AttachmentResult::UploadAccepted {
                attachment_id: [7; 16],
            },
        );
        assert!(exchange.open_response(reply).is_err());
        assert!(exchange.request_bytes().is_err());
        assert!(exchange.seal_data_frame(b"payload".to_vec()).is_err());
    }

    #[test]
    fn partial_upload_requires_fresh_exchange_but_complete_action_retry_is_exact() {
        let length = abyssal_transport::ATTACHMENT_STREAM_PAYLOAD_BYTES as u64 + 1;
        let partial = upload_exchange(length);
        let request = partial.request_bytes().unwrap();
        let partial_handle = abyssal_transport::inspect_http_record(&request)
            .unwrap()
            .handle;
        partial
            .seal_data_frame(vec![1; abyssal_transport::ATTACHMENT_STREAM_PAYLOAD_BYTES])
            .unwrap();
        assert!(partial
            .open_response(vec![0; ATTACHMENT_ACTION_RECORD_BYTES])
            .is_err());
        assert_eq!(partial.request_bytes().unwrap(), request);
        partial.seal_data_frame(vec![2]).unwrap();
        partial.seal_end_frame().unwrap();
        partial.destroy();

        let fresh = upload_exchange(length);
        let fresh_handle = abyssal_transport::inspect_http_record(&fresh.request_bytes().unwrap())
            .unwrap()
            .handle;
        assert_ne!(fresh_handle, partial_handle);
        fresh
            .seal_data_frame(vec![1; abyssal_transport::ATTACHMENT_STREAM_PAYLOAD_BYTES])
            .unwrap();
        fresh.seal_data_frame(vec![2]).unwrap();
        fresh.seal_end_frame().unwrap();
        let exact = fresh.request_bytes().unwrap();
        assert!(fresh
            .open_response(vec![0; ATTACHMENT_ACTION_RECORD_BYTES])
            .is_err());
        assert_eq!(fresh.request_bytes().unwrap(), exact);
    }

    #[test]
    fn download_facade_authenticates_result_before_opening_bound_stream() {
        let exchange = AttachmentClientExchange::begin_download(
            NODE.to_vec(),
            SESSION.to_vec(),
            ROOT.to_vec(),
            vec![7; 16],
        )
        .unwrap();
        assert!(exchange
            .open_stream_frame(vec![0; ATTACHMENT_STREAM_FRAME_BYTES])
            .is_err());
        let (handle, mut server, action) = server_records_for(&exchange);
        assert!(matches!(
            decode_attachment_action(&action).unwrap(),
            AttachmentAction::BeginDownload { .. }
        ));
        let reply = response(
            &mut server,
            handle,
            &AttachmentResult::DownloadAccepted {
                claim_id: Some([8; 16]),
                ciphertext_len: 7,
                ciphertext_sha256: [9; 32],
                data_frame_count: 1,
                bucket_frame_count: 1,
            },
        );
        assert!(matches!(
            exchange.open_response(reply).unwrap(),
            AttachmentTransportResult::DownloadAccepted { .. }
        ));
        let mut stream = AttachmentStreamBinding::new(NODE, SESSION, handle)
            .unwrap()
            .into_sealer(&ROOT, Direction::ServerToClient, 7)
            .unwrap();
        let data = stream.seal_data(b"payload").unwrap();
        let end = stream.seal_end().unwrap();
        let AttachmentTransportFrame::Data { payload } =
            exchange.open_stream_frame(data.to_vec()).unwrap()
        else {
            panic!("expected data")
        };
        assert_eq!(payload, b"payload");
        assert!(!exchange.stream_complete());
        assert!(matches!(
            exchange.open_stream_frame(end.to_vec()).unwrap(),
            AttachmentTransportFrame::End
        ));
        assert!(exchange.stream_complete());
    }

    #[test]
    fn download_facade_maps_padding_and_end_frames() {
        let length = abyssal_transport::ATTACHMENT_STREAM_PAYLOAD_BYTES as u64 * 2 + 1;
        let exchange = AttachmentClientExchange::begin_download(
            NODE.to_vec(),
            SESSION.to_vec(),
            ROOT.to_vec(),
            vec![7; 16],
        )
        .unwrap();
        let (handle, mut server, _) = server_records_for(&exchange);
        let reply = response(
            &mut server,
            handle,
            &AttachmentResult::DownloadAccepted {
                claim_id: None,
                ciphertext_len: length,
                ciphertext_sha256: [9; 32],
                data_frame_count: 3,
                bucket_frame_count: 4,
            },
        );
        exchange.open_response(reply).unwrap();

        let mut stream = AttachmentStreamBinding::new(NODE, SESSION, handle)
            .unwrap()
            .into_sealer(&ROOT, Direction::ServerToClient, length)
            .unwrap();
        let first = stream
            .seal_data(&vec![1; abyssal_transport::ATTACHMENT_STREAM_PAYLOAD_BYTES])
            .unwrap();
        let second = stream
            .seal_data(&vec![2; abyssal_transport::ATTACHMENT_STREAM_PAYLOAD_BYTES])
            .unwrap();
        let third = stream.seal_data(&[3]).unwrap();
        let padding = stream.seal_padding().unwrap();
        let end = stream.seal_end().unwrap();
        assert!(matches!(
            exchange.open_stream_frame(first.to_vec()).unwrap(),
            AttachmentTransportFrame::Data { payload } if payload.len() == abyssal_transport::ATTACHMENT_STREAM_PAYLOAD_BYTES
        ));
        assert!(matches!(
            exchange.open_stream_frame(second.to_vec()).unwrap(),
            AttachmentTransportFrame::Data { payload }
                if payload.len() == abyssal_transport::ATTACHMENT_STREAM_PAYLOAD_BYTES
                    && payload.iter().all(|byte| *byte == 2)
        ));
        assert!(matches!(
            exchange.open_stream_frame(third.to_vec()).unwrap(),
            AttachmentTransportFrame::Data { payload } if payload == vec![3]
        ));
        assert!(matches!(
            exchange.open_stream_frame(padding.to_vec()).unwrap(),
            AttachmentTransportFrame::Padding
        ));
        assert!(matches!(
            exchange.open_stream_frame(end.to_vec()).unwrap(),
            AttachmentTransportFrame::End
        ));
        assert!(exchange.stream_complete());
    }

    #[test]
    fn unauthenticated_result_preserves_exact_request_and_authenticated_malformed_consumes() {
        let exchange = AttachmentClientExchange::delete_attachment(
            NODE.to_vec(),
            SESSION.to_vec(),
            ROOT.to_vec(),
            vec![7; 16],
        )
        .unwrap();
        let request = exchange.request_bytes().unwrap();
        assert!(exchange
            .open_response(vec![0; ATTACHMENT_ACTION_RECORD_BYTES - 1])
            .is_err());
        assert_eq!(exchange.request_bytes().unwrap(), request);
        let (handle, mut server, _) = server_records_for(&exchange);
        let valid = response(&mut server, handle, &AttachmentResult::Success);
        let mut tampered = valid.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(exchange.open_response(tampered).is_err());
        assert_eq!(exchange.request_bytes().unwrap(), request);

        let malformed_plaintext = vec![0_u8; abyssal_transport::ATTACHMENT_ACTION_PLAINTEXT_BYTES];
        let mut malformed_server = HttpSessionBinding::new(NODE, SESSION)
            .unwrap()
            .into_server(&ROOT)
            .unwrap();
        let malformed = malformed_server
            .sealer
            .seal(handle, ATTACHMENT_ACTION_AAD, &malformed_plaintext)
            .unwrap();
        assert!(exchange.open_response(malformed).is_err());
        assert!(exchange.request_bytes().is_err());
        assert!(exchange.open_response(valid).is_err());
    }

    #[test]
    fn authenticated_wrong_result_type_consumes_exchange() {
        let exchange = AttachmentClientExchange::delete_attachment(
            NODE.to_vec(),
            SESSION.to_vec(),
            ROOT.to_vec(),
            vec![7; 16],
        )
        .unwrap();
        let (handle, mut server, _) = server_records_for(&exchange);
        let wrong = response(
            &mut server,
            handle,
            &AttachmentResult::UploadAccepted {
                attachment_id: [8; 16],
            },
        );
        assert!(exchange.open_response(wrong).is_err());
        assert!(exchange.request_bytes().is_err());
    }

    #[test]
    fn authenticated_malformed_upload_result_consumes_stream_and_request() {
        let exchange = upload_exchange(7);
        let (handle, _, _) = server_records_for(&exchange);
        let malformed_plaintext = vec![0_u8; abyssal_transport::ATTACHMENT_ACTION_PLAINTEXT_BYTES];
        let mut server = HttpSessionBinding::new(NODE, SESSION)
            .unwrap()
            .into_server(&ROOT)
            .unwrap();
        let malformed = server
            .sealer
            .seal(handle, ATTACHMENT_ACTION_AAD, &malformed_plaintext)
            .unwrap();
        assert!(exchange.open_response(malformed).is_err());
        assert!(exchange.request_bytes().is_err());
        assert!(exchange.seal_data_frame(b"payload".to_vec()).is_err());
    }

    #[test]
    fn concurrent_response_open_is_one_shot() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let exchange = AttachmentClientExchange::delete_attachment(
            NODE.to_vec(),
            SESSION.to_vec(),
            ROOT.to_vec(),
            vec![7; 16],
        )
        .unwrap();
        let (handle, mut server, _) = server_records_for(&exchange);
        let reply = response(&mut server, handle, &AttachmentResult::Success);
        let exchange = Arc::new(exchange);
        let barrier = Arc::new(Barrier::new(8));
        let threads = (0..8)
            .map(|_| {
                let exchange = Arc::clone(&exchange);
                let barrier = Arc::clone(&barrier);
                let reply = reply.clone();
                thread::spawn(move || {
                    barrier.wait();
                    exchange.open_response(reply).is_ok()
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            threads
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .filter(|success| *success)
                .count(),
            1
        );
    }

    #[test]
    fn facade_rejects_invalid_inputs_and_destroy_invalidates_all_paths() {
        for invalid in [
            AttachmentClientExchange::begin_download(
                vec![0; 32],
                SESSION.to_vec(),
                ROOT.to_vec(),
                vec![7; 16],
            ),
            AttachmentClientExchange::begin_download(
                NODE.to_vec(),
                vec![0; 32],
                ROOT.to_vec(),
                vec![7; 16],
            ),
            AttachmentClientExchange::begin_download(
                NODE.to_vec(),
                SESSION.to_vec(),
                vec![0; 32],
                vec![7; 16],
            ),
            AttachmentClientExchange::begin_download(
                NODE.to_vec(),
                SESSION.to_vec(),
                ROOT.to_vec(),
                vec![0; 16],
            ),
        ] {
            assert!(invalid.is_err());
        }
        let exchange = upload_exchange(7);
        exchange.destroy();
        assert!(exchange.request_bytes().is_err());
        assert!(exchange.seal_data_frame(b"payload".to_vec()).is_err());
        assert!(exchange
            .open_response(vec![0; ATTACHMENT_ACTION_RECORD_BYTES])
            .is_err());
    }
}
