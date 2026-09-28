//! Fixed-size authenticated attachment control and streaming records.
//!
//! The HTTP action/result codecs deliberately carry every attachment semantic
//! inside the existing authenticated HTTP record. Stream records expose only a
//! protocol marker, direction, reserved bytes, and a monotonic counter.

use crate::{
    canonical_parts, key_schedule::derive_record_key, Direction, TransportError, TRANSPORT_VERSION,
};
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use zeroize::{Zeroize, Zeroizing};

pub const ATTACHMENT_ACTION_AAD: &[u8] = b"ABYSSAL-TRANSPORT-V11-ATTACHMENT-ACTION";
pub const ATTACHMENT_ACTION_PLAINTEXT_BYTES: usize = 4096;
pub const ATTACHMENT_ACTION_RECORD_BYTES: usize =
    4 + 1 + 1 + 32 + 16 + 4 + ATTACHMENT_ACTION_PLAINTEXT_BYTES + 16;
pub const ATTACHMENT_STREAM_PAYLOAD_BYTES: usize = 256 * 1024;
pub const ATTACHMENT_STREAM_PLAINTEXT_BYTES: usize = 8 + ATTACHMENT_STREAM_PAYLOAD_BYTES;
pub const ATTACHMENT_STREAM_HEADER_BYTES: usize = 16;
pub const ATTACHMENT_STREAM_FRAME_BYTES: usize =
    ATTACHMENT_STREAM_HEADER_BYTES + ATTACHMENT_STREAM_PLAINTEXT_BYTES + 16;
pub const MAX_ATTACHMENT_CHAT_ID_BYTES: usize = 128;
pub const MAX_ATTACHMENT_MESSAGE_ID_BYTES: usize = 128;
pub const MAX_ATTACHMENT_TTL_SEC: u32 = 30 * 24 * 60 * 60;
pub const MAX_ATTACHMENT_BUCKET_FRAMES: u16 = 1024;
// The current inner attachment cipher emits at most 800 records of 262,201
// bytes for a 200 MiB file. The transport treats those bytes as opaque.
pub const MAX_ATTACHMENT_CIPHERTEXT_BYTES: u64 = 800 * 262_201;

const CODEC_VERSION: u8 = 1;
const CODEC_HEADER_BYTES: usize = 8;
const ACTION_BEGIN_UPLOAD: u8 = 1;
const ACTION_BEGIN_DOWNLOAD: u8 = 2;
const ACTION_COMPLETE_DOWNLOAD: u8 = 3;
const ACTION_RELEASE_DOWNLOAD: u8 = 4;
const ACTION_DELETE_ATTACHMENT: u8 = 5;
const RESULT_FAILURE: u8 = 0;
const RESULT_SUCCESS: u8 = 1;
const RESULT_UPLOAD_ACCEPTED: u8 = 2;
const RESULT_DOWNLOAD_ACCEPTED: u8 = 3;
const FLAG_ONE_TIME: u8 = 1;
const FLAG_DELETE_AFTER_DOWNLOAD: u8 = 2;
const FLAG_HAS_CLAIM: u8 = 1;
const STREAM_MAGIC: &[u8; 4] = b"ABS1";
const STREAM_CONTEXT_DOMAIN: &[u8] = b"ABYSSAL-TRANSPORT-V11-ATTACHMENT-STREAM";
const STREAM_PROTOCOL: &[u8] = b"ATTACHMENT-STREAM";
const FRAME_DATA: u8 = 1;
const FRAME_PADDING: u8 = 2;
const FRAME_END: u8 = 3;

type DecodedStreamRecord<'a> = (&'a [u8], Direction, u64, &'a [u8]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AttachmentMediaType {
    Image = 1,
    Video = 2,
    File = 3,
}

impl AttachmentMediaType {
    fn from_byte(value: u8) -> Result<Self, TransportError> {
        match value {
            1 => Ok(Self::Image),
            2 => Ok(Self::Video),
            3 => Ok(Self::File),
            _ => Err(TransportError::NonCanonical),
        }
    }
}

pub enum AttachmentAction {
    BeginUpload {
        chat_id: Zeroizing<String>,
        message_id: Zeroizing<String>,
        media_type: AttachmentMediaType,
        cipher_version: u8,
        ciphertext_len: u64,
        ciphertext_sha256: [u8; 32],
        one_time: bool,
        delete_after_download: bool,
        requested_ttl_sec: u32,
    },
    BeginDownload {
        attachment_id: [u8; 16],
    },
    CompleteDownload {
        attachment_id: [u8; 16],
        claim_id: Option<[u8; 16]>,
    },
    ReleaseDownload {
        attachment_id: [u8; 16],
        claim_id: Option<[u8; 16]>,
    },
    DeleteAttachment {
        attachment_id: [u8; 16],
    },
}

impl Drop for AttachmentAction {
    fn drop(&mut self) {
        match self {
            Self::BeginUpload {
                ciphertext_sha256, ..
            } => ciphertext_sha256.zeroize(),
            Self::BeginDownload { attachment_id } | Self::DeleteAttachment { attachment_id } => {
                attachment_id.zeroize()
            }
            Self::CompleteDownload {
                attachment_id,
                claim_id,
            }
            | Self::ReleaseDownload {
                attachment_id,
                claim_id,
            } => {
                attachment_id.zeroize();
                if let Some(claim_id) = claim_id {
                    claim_id.zeroize();
                }
            }
        }
    }
}

pub enum AttachmentResult {
    Failure,
    Success,
    UploadAccepted {
        attachment_id: [u8; 16],
    },
    DownloadAccepted {
        claim_id: Option<[u8; 16]>,
        ciphertext_len: u64,
        ciphertext_sha256: [u8; 32],
        data_frame_count: u16,
        bucket_frame_count: u16,
    },
}

impl Drop for AttachmentResult {
    fn drop(&mut self) {
        match self {
            Self::UploadAccepted { attachment_id } => attachment_id.zeroize(),
            Self::DownloadAccepted {
                claim_id,
                ciphertext_sha256,
                ..
            } => {
                if let Some(claim_id) = claim_id {
                    claim_id.zeroize();
                }
                ciphertext_sha256.zeroize();
            }
            Self::Failure | Self::Success => {}
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum AttachmentFrame {
    Data(Zeroizing<Vec<u8>>),
    Padding,
    End,
}

pub fn attachment_data_frame_count(ciphertext_len: u64) -> Result<u16, TransportError> {
    if ciphertext_len == 0 || ciphertext_len > MAX_ATTACHMENT_CIPHERTEXT_BYTES {
        return Err(TransportError::InvalidInput);
    }
    let capacity = ATTACHMENT_STREAM_PAYLOAD_BYTES as u64;
    let count = ciphertext_len
        .checked_add(capacity - 1)
        .ok_or(TransportError::TooLarge)?
        / capacity;
    u16::try_from(count).map_err(|_| TransportError::TooLarge)
}

pub fn attachment_bucket_frame_count(data_frames: u16) -> Result<u16, TransportError> {
    if data_frames == 0 || data_frames > MAX_ATTACHMENT_BUCKET_FRAMES {
        return Err(TransportError::InvalidInput);
    }
    data_frames
        .checked_next_power_of_two()
        .filter(|count| *count <= MAX_ATTACHMENT_BUCKET_FRAMES)
        .ok_or(TransportError::TooLarge)
}

pub fn encode_attachment_action(
    action: &AttachmentAction,
) -> Result<Zeroizing<Vec<u8>>, TransportError> {
    let mut payload = Zeroizing::new(Vec::new());
    let (kind, flags) = match action {
        AttachmentAction::BeginUpload {
            chat_id,
            message_id,
            media_type,
            cipher_version,
            ciphertext_len,
            ciphertext_sha256,
            one_time,
            delete_after_download,
            requested_ttl_sec,
        } => {
            validate_upload(
                chat_id,
                message_id,
                *cipher_version,
                *ciphertext_len,
                ciphertext_sha256,
                *requested_ttl_sec,
            )?;
            put_identifier(&mut payload, chat_id, MAX_ATTACHMENT_CHAT_ID_BYTES)?;
            put_identifier(&mut payload, message_id, MAX_ATTACHMENT_MESSAGE_ID_BYTES)?;
            payload.push(*media_type as u8);
            payload.push(*cipher_version);
            payload.extend_from_slice(&0_u16.to_be_bytes());
            payload.extend_from_slice(&ciphertext_len.to_be_bytes());
            payload.extend_from_slice(ciphertext_sha256);
            payload.extend_from_slice(&requested_ttl_sec.to_be_bytes());
            let flags = (u8::from(*one_time) * FLAG_ONE_TIME)
                | (u8::from(*delete_after_download) * FLAG_DELETE_AFTER_DOWNLOAD);
            (ACTION_BEGIN_UPLOAD, flags)
        }
        AttachmentAction::BeginDownload { attachment_id } => {
            put_nonzero_id(&mut payload, attachment_id)?;
            (ACTION_BEGIN_DOWNLOAD, 0)
        }
        AttachmentAction::CompleteDownload {
            attachment_id,
            claim_id,
        } => {
            put_nonzero_id(&mut payload, attachment_id)?;
            put_optional_id(&mut payload, claim_id)?;
            (ACTION_COMPLETE_DOWNLOAD, 0)
        }
        AttachmentAction::ReleaseDownload {
            attachment_id,
            claim_id,
        } => {
            put_nonzero_id(&mut payload, attachment_id)?;
            put_optional_id(&mut payload, claim_id)?;
            (ACTION_RELEASE_DOWNLOAD, 0)
        }
        AttachmentAction::DeleteAttachment { attachment_id } => {
            put_nonzero_id(&mut payload, attachment_id)?;
            (ACTION_DELETE_ATTACHMENT, 0)
        }
    };
    encode_envelope(kind, flags, &payload)
}

pub fn decode_attachment_action(plaintext: &[u8]) -> Result<AttachmentAction, TransportError> {
    let (kind, flags, mut reader) = decode_envelope(plaintext)?;
    let action = match kind {
        ACTION_BEGIN_UPLOAD => {
            if flags & !(FLAG_ONE_TIME | FLAG_DELETE_AFTER_DOWNLOAD) != 0 {
                return Err(TransportError::NonCanonical);
            }
            let chat_id = Zeroizing::new(reader.take_identifier(MAX_ATTACHMENT_CHAT_ID_BYTES)?);
            let message_id =
                Zeroizing::new(reader.take_identifier(MAX_ATTACHMENT_MESSAGE_ID_BYTES)?);
            let media_type = AttachmentMediaType::from_byte(reader.take_u8()?)?;
            let cipher_version = reader.take_u8()?;
            if reader.take_u16()? != 0 {
                return Err(TransportError::NonCanonical);
            }
            let ciphertext_len = reader.take_u64()?;
            let ciphertext_sha256 = reader.take_array()?;
            let requested_ttl_sec = reader.take_u32()?;
            let one_time = flags & FLAG_ONE_TIME != 0;
            let delete_after_download = flags & FLAG_DELETE_AFTER_DOWNLOAD != 0;
            validate_upload(
                &chat_id,
                &message_id,
                cipher_version,
                ciphertext_len,
                &ciphertext_sha256,
                requested_ttl_sec,
            )
            .map_err(|_| TransportError::NonCanonical)?;
            AttachmentAction::BeginUpload {
                chat_id,
                message_id,
                media_type,
                cipher_version,
                ciphertext_len,
                ciphertext_sha256,
                one_time,
                delete_after_download,
                requested_ttl_sec,
            }
        }
        ACTION_BEGIN_DOWNLOAD => {
            require_zero_flags(flags)?;
            AttachmentAction::BeginDownload {
                attachment_id: reader.take_nonzero_id()?,
            }
        }
        ACTION_COMPLETE_DOWNLOAD | ACTION_RELEASE_DOWNLOAD => {
            require_zero_flags(flags)?;
            let attachment_id = reader.take_nonzero_id()?;
            let claim_id = reader.take_optional_id()?;
            if kind == ACTION_COMPLETE_DOWNLOAD {
                AttachmentAction::CompleteDownload {
                    attachment_id,
                    claim_id,
                }
            } else {
                AttachmentAction::ReleaseDownload {
                    attachment_id,
                    claim_id,
                }
            }
        }
        ACTION_DELETE_ATTACHMENT => {
            require_zero_flags(flags)?;
            AttachmentAction::DeleteAttachment {
                attachment_id: reader.take_nonzero_id()?,
            }
        }
        _ => return Err(TransportError::NonCanonical),
    };
    reader.finish()?;
    Ok(action)
}

pub fn encode_attachment_result(
    result: &AttachmentResult,
) -> Result<Zeroizing<Vec<u8>>, TransportError> {
    let mut payload = Zeroizing::new(Vec::new());
    let (kind, flags) = match result {
        AttachmentResult::Failure => (RESULT_FAILURE, 0),
        AttachmentResult::Success => (RESULT_SUCCESS, 0),
        AttachmentResult::UploadAccepted { attachment_id } => {
            put_nonzero_id(&mut payload, attachment_id)?;
            (RESULT_UPLOAD_ACCEPTED, 0)
        }
        AttachmentResult::DownloadAccepted {
            claim_id,
            ciphertext_len,
            ciphertext_sha256,
            data_frame_count,
            bucket_frame_count,
        } => {
            validate_download_result(
                *ciphertext_len,
                ciphertext_sha256,
                *data_frame_count,
                *bucket_frame_count,
            )?;
            if let Some(claim_id) = claim_id {
                put_nonzero_id(&mut payload, claim_id)?;
            }
            payload.extend_from_slice(&ciphertext_len.to_be_bytes());
            payload.extend_from_slice(ciphertext_sha256);
            payload.extend_from_slice(&data_frame_count.to_be_bytes());
            payload.extend_from_slice(&bucket_frame_count.to_be_bytes());
            (RESULT_DOWNLOAD_ACCEPTED, u8::from(claim_id.is_some()))
        }
    };
    encode_envelope(kind, flags, &payload)
}

pub fn decode_attachment_result(plaintext: &[u8]) -> Result<AttachmentResult, TransportError> {
    let (kind, flags, mut reader) = decode_envelope(plaintext)?;
    let result = match kind {
        RESULT_FAILURE => {
            require_zero_flags(flags)?;
            AttachmentResult::Failure
        }
        RESULT_SUCCESS => {
            require_zero_flags(flags)?;
            AttachmentResult::Success
        }
        RESULT_UPLOAD_ACCEPTED => {
            require_zero_flags(flags)?;
            AttachmentResult::UploadAccepted {
                attachment_id: reader.take_nonzero_id()?,
            }
        }
        RESULT_DOWNLOAD_ACCEPTED => {
            if flags & !FLAG_HAS_CLAIM != 0 {
                return Err(TransportError::NonCanonical);
            }
            let claim_id = if flags & FLAG_HAS_CLAIM != 0 {
                Some(reader.take_nonzero_id()?)
            } else {
                None
            };
            let ciphertext_len = reader.take_u64()?;
            let ciphertext_sha256 = reader.take_array()?;
            let data_frame_count = reader.take_u16()?;
            let bucket_frame_count = reader.take_u16()?;
            validate_download_result(
                ciphertext_len,
                &ciphertext_sha256,
                data_frame_count,
                bucket_frame_count,
            )
            .map_err(|_| TransportError::NonCanonical)?;
            AttachmentResult::DownloadAccepted {
                claim_id,
                ciphertext_len,
                ciphertext_sha256,
                data_frame_count,
                bucket_frame_count,
            }
        }
        _ => return Err(TransportError::NonCanonical),
    };
    reader.finish()?;
    Ok(result)
}

#[derive(Debug, Eq, PartialEq)]
pub struct AttachmentStreamBinding {
    node_public_key: [u8; 32],
    session_id: [u8; 32],
    operation_handle: [u8; 16],
}

impl Drop for AttachmentStreamBinding {
    fn drop(&mut self) {
        self.node_public_key.zeroize();
        self.session_id.zeroize();
        self.operation_handle.zeroize();
    }
}

impl AttachmentStreamBinding {
    pub fn new(
        node_public_key: [u8; 32],
        session_id: [u8; 32],
        operation_handle: [u8; 16],
    ) -> Result<Self, TransportError> {
        if node_public_key == [0; 32] || session_id == [0; 32] || operation_handle == [0; 16] {
            return Err(TransportError::InvalidInput);
        }
        Ok(Self {
            node_public_key,
            session_id,
            operation_handle,
        })
    }

    fn context(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(canonical_parts(&[
            STREAM_CONTEXT_DOMAIN,
            &self.node_public_key,
            &self.session_id,
            &self.operation_handle,
        ]))
    }

    pub fn into_sealer(
        self,
        transport_root: &[u8; 32],
        direction: Direction,
        ciphertext_len: u64,
    ) -> Result<AttachmentStreamSealer, TransportError> {
        let layout = StreamLayout::new(ciphertext_len)?;
        let context = self.context();
        Ok(AttachmentStreamSealer {
            key: derive_record_key(transport_root, STREAM_PROTOCOL, direction, &context)?,
            context,
            direction,
            layout,
            next_counter: 0,
            data_frames: 0,
            padding_frames: 0,
            bytes_seen: 0,
            ended: false,
        })
    }

    pub fn into_opener(
        self,
        transport_root: &[u8; 32],
        direction: Direction,
        ciphertext_len: u64,
        data_frame_count: u16,
        bucket_frame_count: u16,
    ) -> Result<AttachmentStreamOpener, TransportError> {
        let layout = StreamLayout::new(ciphertext_len)?;
        if layout.data_frames != data_frame_count || layout.bucket_frames != bucket_frame_count {
            return Err(TransportError::InvalidInput);
        }
        let context = self.context();
        Ok(AttachmentStreamOpener {
            key: derive_record_key(transport_root, STREAM_PROTOCOL, direction, &context)?,
            context,
            direction,
            layout,
            next_counter: 0,
            data_frames: 0,
            padding_frames: 0,
            bytes_seen: 0,
            ended: false,
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
struct StreamLayout {
    ciphertext_len: u64,
    data_frames: u16,
    bucket_frames: u16,
}

impl StreamLayout {
    fn new(ciphertext_len: u64) -> Result<Self, TransportError> {
        let data_frames = attachment_data_frame_count(ciphertext_len)?;
        Ok(Self {
            ciphertext_len,
            data_frames,
            bucket_frames: attachment_bucket_frame_count(data_frames)?,
        })
    }

    fn expected_data_len(&self, data_frames_seen: u16) -> Result<usize, TransportError> {
        if data_frames_seen >= self.data_frames {
            return Err(TransportError::CounterGap);
        }
        let seen = u64::from(data_frames_seen)
            .checked_mul(ATTACHMENT_STREAM_PAYLOAD_BYTES as u64)
            .ok_or(TransportError::TooLarge)?;
        usize::try_from(
            self.ciphertext_len
                .checked_sub(seen)
                .ok_or(TransportError::NonCanonical)?
                .min(ATTACHMENT_STREAM_PAYLOAD_BYTES as u64),
        )
        .map_err(|_| TransportError::TooLarge)
    }
}

pub struct AttachmentStreamSealer {
    key: Zeroizing<[u8; 32]>,
    context: Zeroizing<Vec<u8>>,
    direction: Direction,
    layout: StreamLayout,
    next_counter: u64,
    data_frames: u16,
    padding_frames: u16,
    bytes_seen: u64,
    ended: bool,
}

pub struct AttachmentStreamOpener {
    key: Zeroizing<[u8; 32]>,
    context: Zeroizing<Vec<u8>>,
    direction: Direction,
    layout: StreamLayout,
    next_counter: u64,
    data_frames: u16,
    padding_frames: u16,
    bytes_seen: u64,
    ended: bool,
}

impl AttachmentStreamSealer {
    pub fn data_frame_count(&self) -> u16 {
        self.layout.data_frames
    }

    pub fn bucket_frame_count(&self) -> u16 {
        self.layout.bucket_frames
    }

    pub fn is_complete(&self) -> bool {
        self.ended
    }

    pub fn seal_data(&mut self, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        if self.ended || self.padding_frames != 0 {
            return Err(TransportError::CounterGap);
        }
        let expected = self.layout.expected_data_len(self.data_frames)?;
        if payload.len() != expected {
            return Err(TransportError::InvalidInput);
        }
        let record = self.seal(FRAME_DATA, payload)?;
        self.data_frames = self
            .data_frames
            .checked_add(1)
            .ok_or(TransportError::CounterExhausted)?;
        self.bytes_seen = self
            .bytes_seen
            .checked_add(payload.len() as u64)
            .ok_or(TransportError::TooLarge)?;
        Ok(record)
    }

    pub fn seal_padding(&mut self) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        if self.ended
            || self.data_frames != self.layout.data_frames
            || self.data_frames + self.padding_frames >= self.layout.bucket_frames
        {
            return Err(TransportError::CounterGap);
        }
        let record = self.seal(FRAME_PADDING, &[])?;
        self.padding_frames += 1;
        Ok(record)
    }

    pub fn seal_end(&mut self) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        if self.ended
            || self.bytes_seen != self.layout.ciphertext_len
            || self.data_frames + self.padding_frames != self.layout.bucket_frames
        {
            return Err(TransportError::CounterGap);
        }
        let record = self.seal(FRAME_END, &[])?;
        self.ended = true;
        Ok(record)
    }

    fn seal(&mut self, kind: u8, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        if self.next_counter == u64::MAX {
            return Err(TransportError::CounterExhausted);
        }
        let counter = self.next_counter;
        let header = stream_header(self.direction, counter);
        let plaintext = frame_plaintext(kind, payload)?;
        let aad = Zeroizing::new(canonical_parts(&[
            &header,
            STREAM_CONTEXT_DOMAIN,
            &self.context,
        ]));
        let nonce = stream_nonce(self.direction, counter);
        let ciphertext = ChaCha20Poly1305::new(self.key.as_ref().into())
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| TransportError::AuthenticationFailed)?;
        let mut record = Zeroizing::new(Vec::with_capacity(ATTACHMENT_STREAM_FRAME_BYTES));
        record.extend_from_slice(&header);
        record.extend_from_slice(&ciphertext);
        if record.len() != ATTACHMENT_STREAM_FRAME_BYTES {
            return Err(TransportError::NonCanonical);
        }
        self.next_counter = self
            .next_counter
            .checked_add(1)
            .ok_or(TransportError::CounterExhausted)?;
        Ok(record)
    }
}

impl AttachmentStreamOpener {
    pub fn is_complete(&self) -> bool {
        self.ended
    }

    pub fn open(&mut self, record: &[u8]) -> Result<AttachmentFrame, TransportError> {
        if self.ended || self.next_counter == u64::MAX {
            return Err(if self.next_counter == u64::MAX {
                TransportError::CounterExhausted
            } else {
                TransportError::Replay
            });
        }
        let (header, direction, counter, ciphertext) = decode_stream_record(record)?;
        if direction != self.direction {
            return Err(TransportError::AuthenticationFailed);
        }
        if counter < self.next_counter {
            return Err(TransportError::Replay);
        }
        if counter > self.next_counter {
            return Err(TransportError::CounterGap);
        }
        let aad = Zeroizing::new(canonical_parts(&[
            header,
            STREAM_CONTEXT_DOMAIN,
            &self.context,
        ]));
        let nonce = stream_nonce(self.direction, counter);
        let plaintext = ChaCha20Poly1305::new(self.key.as_ref().into())
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| TransportError::AuthenticationFailed)?;
        let frame = decode_frame_plaintext(&plaintext)?;
        self.accept_frame(&frame)?;
        self.next_counter = self
            .next_counter
            .checked_add(1)
            .ok_or(TransportError::CounterExhausted)?;
        Ok(frame)
    }

    fn accept_frame(&mut self, frame: &AttachmentFrame) -> Result<(), TransportError> {
        match frame {
            AttachmentFrame::Data(payload) => {
                if self.padding_frames != 0
                    || payload.len() != self.layout.expected_data_len(self.data_frames)?
                {
                    return Err(TransportError::NonCanonical);
                }
                self.data_frames += 1;
                self.bytes_seen = self
                    .bytes_seen
                    .checked_add(payload.len() as u64)
                    .ok_or(TransportError::TooLarge)?;
            }
            AttachmentFrame::Padding => {
                if self.data_frames != self.layout.data_frames
                    || self.data_frames + self.padding_frames >= self.layout.bucket_frames
                {
                    return Err(TransportError::NonCanonical);
                }
                self.padding_frames += 1;
            }
            AttachmentFrame::End => {
                if self.bytes_seen != self.layout.ciphertext_len
                    || self.data_frames + self.padding_frames != self.layout.bucket_frames
                {
                    return Err(TransportError::NonCanonical);
                }
                self.ended = true;
            }
        }
        Ok(())
    }
}

fn validate_upload(
    chat_id: &str,
    message_id: &str,
    cipher_version: u8,
    ciphertext_len: u64,
    ciphertext_sha256: &[u8; 32],
    requested_ttl_sec: u32,
) -> Result<(), TransportError> {
    validate_identifier(chat_id, MAX_ATTACHMENT_CHAT_ID_BYTES)?;
    validate_identifier(message_id, MAX_ATTACHMENT_MESSAGE_ID_BYTES)?;
    if cipher_version == 0
        || ciphertext_sha256 == &[0; 32]
        || requested_ttl_sec > MAX_ATTACHMENT_TTL_SEC
    {
        return Err(TransportError::InvalidInput);
    }
    attachment_data_frame_count(ciphertext_len)?;
    Ok(())
}

fn validate_download_result(
    ciphertext_len: u64,
    ciphertext_sha256: &[u8; 32],
    data_frame_count: u16,
    bucket_frame_count: u16,
) -> Result<(), TransportError> {
    if ciphertext_sha256 == &[0; 32]
        || attachment_data_frame_count(ciphertext_len)? != data_frame_count
        || attachment_bucket_frame_count(data_frame_count)? != bucket_frame_count
    {
        return Err(TransportError::InvalidInput);
    }
    Ok(())
}

fn validate_identifier(value: &str, maximum: usize) -> Result<(), TransportError> {
    if value.is_empty() || value.len() > maximum {
        return Err(if value.len() > maximum {
            TransportError::TooLarge
        } else {
            TransportError::InvalidInput
        });
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(TransportError::InvalidInput);
    }
    Ok(())
}

fn put_identifier(output: &mut Vec<u8>, value: &str, maximum: usize) -> Result<(), TransportError> {
    validate_identifier(value, maximum)?;
    output.extend_from_slice(
        &u16::try_from(value.len())
            .map_err(|_| TransportError::TooLarge)?
            .to_be_bytes(),
    );
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_nonzero_id(output: &mut Vec<u8>, id: &[u8; 16]) -> Result<(), TransportError> {
    if id == &[0; 16] {
        return Err(TransportError::InvalidInput);
    }
    output.extend_from_slice(id);
    Ok(())
}

fn put_optional_id(output: &mut Vec<u8>, id: &Option<[u8; 16]>) -> Result<(), TransportError> {
    output.push(u8::from(id.is_some()));
    output.extend_from_slice(&[0; 3]);
    if let Some(id) = id {
        put_nonzero_id(output, id)?;
    }
    Ok(())
}

fn require_zero_flags(flags: u8) -> Result<(), TransportError> {
    if flags == 0 {
        Ok(())
    } else {
        Err(TransportError::NonCanonical)
    }
}

fn encode_envelope(
    kind: u8,
    flags: u8,
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, TransportError> {
    let payload_len = u16::try_from(payload.len()).map_err(|_| TransportError::TooLarge)?;
    if payload.len() > ATTACHMENT_ACTION_PLAINTEXT_BYTES - CODEC_HEADER_BYTES {
        return Err(TransportError::TooLarge);
    }
    let mut output = Zeroizing::new(vec![0_u8; ATTACHMENT_ACTION_PLAINTEXT_BYTES]);
    output[0] = CODEC_VERSION;
    output[1] = kind;
    output[2] = flags;
    output[3] = 0;
    output[4..6].copy_from_slice(&payload_len.to_be_bytes());
    output[6..8].fill(0);
    output[CODEC_HEADER_BYTES..CODEC_HEADER_BYTES + payload.len()].copy_from_slice(payload);
    getrandom::fill(&mut output[CODEC_HEADER_BYTES + payload.len()..])
        .map_err(|_| TransportError::InvalidInput)?;
    Ok(output)
}

fn decode_envelope(plaintext: &[u8]) -> Result<(u8, u8, Reader<'_>), TransportError> {
    if plaintext.len() != ATTACHMENT_ACTION_PLAINTEXT_BYTES
        || plaintext[0] != CODEC_VERSION
        || plaintext[3] != 0
        || plaintext[6..8] != [0, 0]
    {
        return Err(TransportError::NonCanonical);
    }
    let payload_len = usize::from(u16::from_be_bytes([plaintext[4], plaintext[5]]));
    if payload_len > ATTACHMENT_ACTION_PLAINTEXT_BYTES - CODEC_HEADER_BYTES {
        return Err(TransportError::NonCanonical);
    }
    Ok((
        plaintext[1],
        plaintext[2],
        Reader::new(&plaintext[CODEC_HEADER_BYTES..CODEC_HEADER_BYTES + payload_len]),
    ))
}

fn stream_header(direction: Direction, counter: u64) -> [u8; ATTACHMENT_STREAM_HEADER_BYTES] {
    let mut header = [0_u8; ATTACHMENT_STREAM_HEADER_BYTES];
    header[..4].copy_from_slice(STREAM_MAGIC);
    header[4] = TRANSPORT_VERSION;
    header[5] = direction as u8;
    header[6..8].fill(0);
    header[8..16].copy_from_slice(&counter.to_be_bytes());
    header
}

fn decode_stream_record(record: &[u8]) -> Result<DecodedStreamRecord<'_>, TransportError> {
    if record.len() != ATTACHMENT_STREAM_FRAME_BYTES {
        return Err(TransportError::NonCanonical);
    }
    let header = &record[..ATTACHMENT_STREAM_HEADER_BYTES];
    if &header[..4] != STREAM_MAGIC || header[4] != TRANSPORT_VERSION || header[6..8] != [0, 0] {
        return Err(TransportError::NonCanonical);
    }
    let direction = Direction::from_byte(header[5])?;
    let counter = u64::from_be_bytes(
        header[8..16]
            .try_into()
            .map_err(|_| TransportError::NonCanonical)?,
    );
    Ok((
        header,
        direction,
        counter,
        &record[ATTACHMENT_STREAM_HEADER_BYTES..],
    ))
}

fn frame_plaintext(kind: u8, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, TransportError> {
    if payload.len() > ATTACHMENT_STREAM_PAYLOAD_BYTES
        || (kind == FRAME_DATA && payload.is_empty())
        || (kind != FRAME_DATA
            && (!payload.is_empty() || !matches!(kind, FRAME_PADDING | FRAME_END)))
    {
        return Err(TransportError::InvalidInput);
    }
    let mut output = Zeroizing::new(vec![0_u8; ATTACHMENT_STREAM_PLAINTEXT_BYTES]);
    output[0] = kind;
    output[1..4].fill(0);
    output[4..8].copy_from_slice(
        &u32::try_from(payload.len())
            .map_err(|_| TransportError::TooLarge)?
            .to_be_bytes(),
    );
    output[8..8 + payload.len()].copy_from_slice(payload);
    getrandom::fill(&mut output[8 + payload.len()..]).map_err(|_| TransportError::InvalidInput)?;
    Ok(output)
}

fn decode_frame_plaintext(plaintext: &[u8]) -> Result<AttachmentFrame, TransportError> {
    if plaintext.len() != ATTACHMENT_STREAM_PLAINTEXT_BYTES || plaintext[1..4] != [0, 0, 0] {
        return Err(TransportError::NonCanonical);
    }
    let payload_len = usize::try_from(u32::from_be_bytes(
        plaintext[4..8]
            .try_into()
            .map_err(|_| TransportError::NonCanonical)?,
    ))
    .map_err(|_| TransportError::TooLarge)?;
    if payload_len > ATTACHMENT_STREAM_PAYLOAD_BYTES {
        return Err(TransportError::NonCanonical);
    }
    match plaintext[0] {
        FRAME_DATA if payload_len > 0 => Ok(AttachmentFrame::Data(Zeroizing::new(
            plaintext[8..8 + payload_len].to_vec(),
        ))),
        FRAME_PADDING if payload_len == 0 => Ok(AttachmentFrame::Padding),
        FRAME_END if payload_len == 0 => Ok(AttachmentFrame::End),
        _ => Err(TransportError::NonCanonical),
    }
}

fn stream_nonce(direction: Direction, counter: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[3] = direction as u8;
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], TransportError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(TransportError::TooLarge)?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or(TransportError::NonCanonical)?;
        self.offset = end;
        Ok(value)
    }

    fn take_u8(&mut self) -> Result<u8, TransportError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(TransportError::NonCanonical)
    }

    fn take_u16(&mut self) -> Result<u16, TransportError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| TransportError::NonCanonical)?,
        ))
    }

    fn take_u32(&mut self) -> Result<u32, TransportError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| TransportError::NonCanonical)?,
        ))
    }

    fn take_u64(&mut self) -> Result<u64, TransportError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| TransportError::NonCanonical)?,
        ))
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], TransportError> {
        self.take(N)?
            .try_into()
            .map_err(|_| TransportError::NonCanonical)
    }

    fn take_identifier(&mut self, maximum: usize) -> Result<String, TransportError> {
        let length = usize::from(self.take_u16()?);
        let bytes = self.take(length)?;
        let value = std::str::from_utf8(bytes).map_err(|_| TransportError::NonCanonical)?;
        validate_identifier(value, maximum).map_err(|_| TransportError::NonCanonical)?;
        Ok(value.to_owned())
    }

    fn take_nonzero_id(&mut self) -> Result<[u8; 16], TransportError> {
        let id = self.take_array()?;
        if id == [0; 16] {
            return Err(TransportError::NonCanonical);
        }
        Ok(id)
    }

    fn take_optional_id(&mut self) -> Result<Option<[u8; 16]>, TransportError> {
        let present = self.take_u8()?;
        if self.take(3)? != [0, 0, 0] {
            return Err(TransportError::NonCanonical);
        }
        match present {
            0 => Ok(None),
            1 => Ok(Some(self.take_nonzero_id()?)),
            _ => Err(TransportError::NonCanonical),
        }
    }

    fn finish(self) -> Result<(), TransportError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(TransportError::NonCanonical)
        }
    }
}

#[cfg(test)]
impl AttachmentStreamSealer {
    pub(crate) fn exhaust_for_test(&mut self) {
        self.next_counter = u64::MAX;
    }
}

#[cfg(test)]
impl AttachmentStreamOpener {
    pub(crate) fn exhaust_for_test(&mut self) {
        self.next_counter = u64::MAX;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{inspect_http_record, HttpSessionBinding};

    const NODE: [u8; 32] = [3; 32];
    const SESSION: [u8; 32] = [4; 32];
    const ROOT: [u8; 32] = [5; 32];
    const HANDLE: [u8; 16] = [6; 16];

    fn upload(length: u64) -> AttachmentAction {
        AttachmentAction::BeginUpload {
            chat_id: Zeroizing::new("dm_Alice_Bob".to_owned()),
            message_id: Zeroizing::new("message-1".to_owned()),
            media_type: AttachmentMediaType::File,
            cipher_version: 2,
            ciphertext_len: length,
            ciphertext_sha256: [9; 32],
            one_time: false,
            delete_after_download: true,
            requested_ttl_sec: 60,
        }
    }

    fn stream_binding(handle: [u8; 16]) -> AttachmentStreamBinding {
        AttachmentStreamBinding::new(NODE, SESSION, handle).unwrap()
    }

    #[test]
    fn action_codec_is_fixed_and_round_trips_every_action() {
        let actions = [
            upload(17),
            AttachmentAction::BeginDownload {
                attachment_id: [7; 16],
            },
            AttachmentAction::CompleteDownload {
                attachment_id: [7; 16],
                claim_id: Some([8; 16]),
            },
            AttachmentAction::ReleaseDownload {
                attachment_id: [7; 16],
                claim_id: None,
            },
            AttachmentAction::DeleteAttachment {
                attachment_id: [7; 16],
            },
        ];
        for action in actions {
            let encoded = encode_attachment_action(&action).unwrap();
            assert_eq!(encoded.len(), ATTACHMENT_ACTION_PLAINTEXT_BYTES);
            let decoded = decode_attachment_action(&encoded).unwrap();
            assert_eq!(
                std::mem::discriminant(&action),
                std::mem::discriminant(&decoded)
            );
        }
    }

    #[test]
    fn action_codec_preserves_all_fields_and_flag_combinations() {
        let chat_id = "c".repeat(MAX_ATTACHMENT_CHAT_ID_BYTES);
        let message_id = "m".repeat(MAX_ATTACHMENT_MESSAGE_ID_BYTES);
        for (media_type, one_time, delete_after_download) in [
            (AttachmentMediaType::Image, false, false),
            (AttachmentMediaType::Video, true, false),
            (AttachmentMediaType::File, false, true),
            (AttachmentMediaType::Image, true, true),
        ] {
            let action = AttachmentAction::BeginUpload {
                chat_id: Zeroizing::new(chat_id.clone()),
                message_id: Zeroizing::new(message_id.clone()),
                media_type,
                cipher_version: 7,
                ciphertext_len: 1,
                ciphertext_sha256: [9; 32],
                one_time,
                delete_after_download,
                requested_ttl_sec: MAX_ATTACHMENT_TTL_SEC,
            };
            let encoded = encode_attachment_action(&action).unwrap();
            let decoded = decode_attachment_action(&encoded).unwrap();
            let AttachmentAction::BeginUpload {
                chat_id: decoded_chat,
                message_id: decoded_message,
                media_type: decoded_media,
                cipher_version,
                ciphertext_len,
                ciphertext_sha256,
                one_time: decoded_one_time,
                delete_after_download: decoded_delete,
                requested_ttl_sec,
            } = &decoded
            else {
                panic!("expected upload action")
            };
            assert_eq!(&**decoded_chat, &chat_id);
            assert_eq!(&**decoded_message, &message_id);
            assert_eq!(*decoded_media, media_type);
            assert_eq!(*cipher_version, 7);
            assert_eq!(*ciphertext_len, 1);
            assert_eq!(*ciphertext_sha256, [9; 32]);
            assert_eq!(*decoded_one_time, one_time);
            assert_eq!(*decoded_delete, delete_after_download);
            assert_eq!(*requested_ttl_sec, MAX_ATTACHMENT_TTL_SEC);
        }

        let action = AttachmentAction::CompleteDownload {
            attachment_id: [7; 16],
            claim_id: Some([8; 16]),
        };
        let encoded = encode_attachment_action(&action).unwrap();
        let decoded = decode_attachment_action(&encoded).unwrap();
        let AttachmentAction::CompleteDownload {
            attachment_id,
            claim_id,
        } = &decoded
        else {
            panic!("expected complete action")
        };
        assert_eq!(*attachment_id, [7; 16]);
        assert_eq!(*claim_id, Some([8; 16]));
        let action = AttachmentAction::ReleaseDownload {
            attachment_id: [7; 16],
            claim_id: None,
        };
        let encoded = encode_attachment_action(&action).unwrap();
        let decoded = decode_attachment_action(&encoded).unwrap();
        let AttachmentAction::ReleaseDownload {
            attachment_id,
            claim_id,
        } = &decoded
        else {
            panic!("expected release action")
        };
        assert_eq!(*attachment_id, [7; 16]);
        assert_eq!(*claim_id, None);
    }

    #[test]
    fn one_time_and_delete_flags_remain_independent() {
        let action = AttachmentAction::BeginUpload {
            chat_id: Zeroizing::new("room".to_owned()),
            message_id: Zeroizing::new("message".to_owned()),
            media_type: AttachmentMediaType::Image,
            cipher_version: 1,
            ciphertext_len: 17,
            ciphertext_sha256: [9; 32],
            one_time: true,
            delete_after_download: false,
            requested_ttl_sec: 0,
        };
        let encoded = encode_attachment_action(&action).unwrap();
        let AttachmentAction::BeginUpload {
            one_time,
            delete_after_download,
            ..
        } = decode_attachment_action(&encoded).unwrap()
        else {
            panic!("expected upload")
        };
        assert!(one_time);
        assert!(!delete_after_download);
    }

    #[test]
    fn result_codec_is_fixed_and_validates_layout() {
        let data_frame_count = attachment_data_frame_count(17).unwrap();
        let bucket_frame_count = attachment_bucket_frame_count(data_frame_count).unwrap();
        let results = [
            AttachmentResult::Failure,
            AttachmentResult::Success,
            AttachmentResult::UploadAccepted {
                attachment_id: [7; 16],
            },
            AttachmentResult::DownloadAccepted {
                claim_id: Some([8; 16]),
                ciphertext_len: 17,
                ciphertext_sha256: [9; 32],
                data_frame_count,
                bucket_frame_count,
            },
        ];
        for result in results {
            let encoded = encode_attachment_result(&result).unwrap();
            assert_eq!(encoded.len(), ATTACHMENT_ACTION_PLAINTEXT_BYTES);
            let decoded = decode_attachment_result(&encoded).unwrap();
            assert_eq!(
                std::mem::discriminant(&result),
                std::mem::discriminant(&decoded)
            );
        }
        assert!(
            encode_attachment_result(&AttachmentResult::DownloadAccepted {
                claim_id: None,
                ciphertext_len: 17,
                ciphertext_sha256: [9; 32],
                data_frame_count: 2,
                bucket_frame_count: 2,
            })
            .is_err()
        );
    }

    #[test]
    fn result_codec_preserves_optional_claim_and_all_metadata() {
        let result = AttachmentResult::DownloadAccepted {
            claim_id: Some([8; 16]),
            ciphertext_len: ATTACHMENT_STREAM_PAYLOAD_BYTES as u64 + 1,
            ciphertext_sha256: [9; 32],
            data_frame_count: 2,
            bucket_frame_count: 2,
        };
        let encoded = encode_attachment_result(&result).unwrap();
        let AttachmentResult::DownloadAccepted {
            claim_id,
            ciphertext_len,
            ciphertext_sha256,
            data_frame_count,
            bucket_frame_count,
        } = decode_attachment_result(&encoded).unwrap()
        else {
            panic!("expected download result")
        };
        assert_eq!(claim_id, Some([8; 16]));
        assert_eq!(ciphertext_len, ATTACHMENT_STREAM_PAYLOAD_BYTES as u64 + 1);
        assert_eq!(ciphertext_sha256, [9; 32]);
        assert_eq!(data_frame_count, 2);
        assert_eq!(bucket_frame_count, 2);
    }

    #[test]
    fn codecs_reject_reserved_flags_lengths_types_and_invalid_material() {
        let encoded = encode_attachment_action(&upload(17)).unwrap();
        for (index, value) in [(0, 2), (1, 99), (3, 1), (6, 1), (7, 1)] {
            let mut changed = encoded.to_vec();
            changed[index] = value;
            assert!(decode_attachment_action(&changed).is_err(), "index {index}");
        }
        let mut bad_flags = encoded.to_vec();
        bad_flags[2] = 0x80;
        assert!(decode_attachment_action(&bad_flags).is_err());
        let mut bad_length = encoded.to_vec();
        bad_length[4..6].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(decode_attachment_action(&bad_length).is_err());
        assert!(decode_attachment_action(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(decode_attachment_action(&trailing).is_err());
        assert!(encode_attachment_action(&AttachmentAction::BeginDownload {
            attachment_id: [0; 16]
        })
        .is_err());
        assert!(encode_attachment_action(&upload(0)).is_err());
        assert!(encode_attachment_action(&upload(MAX_ATTACHMENT_CIPHERTEXT_BYTES + 1)).is_err());
        assert!(encode_attachment_action(&AttachmentAction::BeginUpload {
            chat_id: Zeroizing::new("../bad".to_owned()),
            message_id: Zeroizing::new("message".to_owned()),
            media_type: AttachmentMediaType::File,
            cipher_version: 1,
            ciphertext_len: 1,
            ciphertext_sha256: [9; 32],
            one_time: false,
            delete_after_download: false,
            requested_ttl_sec: 0,
        })
        .is_err());
    }

    #[test]
    fn codecs_reject_noncanonical_optional_ids_and_result_flags() {
        let action = AttachmentAction::CompleteDownload {
            attachment_id: [7; 16],
            claim_id: Some([8; 16]),
        };
        let encoded = encode_attachment_action(&action).unwrap();
        let mut reserved = encoded.to_vec();
        reserved[8 + 16 + 1] = 1;
        assert!(decode_attachment_action(&reserved).is_err());
        let mut zero_claim = encoded.to_vec();
        zero_claim[8 + 16 + 4..8 + 16 + 4 + 16].fill(0);
        assert!(decode_attachment_action(&zero_claim).is_err());

        let result = AttachmentResult::DownloadAccepted {
            claim_id: Some([8; 16]),
            ciphertext_len: 1,
            ciphertext_sha256: [9; 32],
            data_frame_count: 1,
            bucket_frame_count: 1,
        };
        let encoded = encode_attachment_result(&result).unwrap();
        let mut bad_flags = encoded.to_vec();
        bad_flags[2] = 0x80;
        assert!(decode_attachment_result(&bad_flags).is_err());
        let mut zero_claim = encoded.to_vec();
        zero_claim[8..8 + 16].fill(0);
        assert!(decode_attachment_result(&zero_claim).is_err());
        let mut zero_hash = encoded.to_vec();
        zero_hash[8 + 16 + 8..8 + 16 + 8 + 32].fill(0);
        assert!(decode_attachment_result(&zero_hash).is_err());
    }

    #[test]
    fn bucket_boundaries_and_current_max_are_exact() {
        for (data, bucket) in [
            (1, 1),
            (2, 2),
            (3, 4),
            (4, 4),
            (5, 8),
            (511, 512),
            (512, 512),
            (513, 1024),
            (1024, 1024),
        ] {
            assert_eq!(attachment_bucket_frame_count(data).unwrap(), bucket);
        }
        assert!(attachment_bucket_frame_count(0).is_err());
        assert!(attachment_bucket_frame_count(1025).is_err());
        assert_eq!(
            attachment_data_frame_count(MAX_ATTACHMENT_CIPHERTEXT_BYTES).unwrap(),
            801
        );
        assert_eq!(attachment_bucket_frame_count(801).unwrap(), 1024);
    }

    #[test]
    fn data_frame_boundaries_are_exact() {
        let capacity = ATTACHMENT_STREAM_PAYLOAD_BYTES as u64;
        for (length, expected) in [(1, 1), (capacity - 1, 1), (capacity, 1), (capacity + 1, 2)] {
            assert_eq!(attachment_data_frame_count(length).unwrap(), expected);
        }
        assert!(attachment_data_frame_count(0).is_err());
        assert!(attachment_data_frame_count(MAX_ATTACHMENT_CIPHERTEXT_BYTES + 1).is_err());

        let too_long_chat = AttachmentAction::BeginUpload {
            chat_id: Zeroizing::new("x".repeat(MAX_ATTACHMENT_CHAT_ID_BYTES + 1)),
            message_id: Zeroizing::new("message".to_owned()),
            media_type: AttachmentMediaType::File,
            cipher_version: 1,
            ciphertext_len: 1,
            ciphertext_sha256: [9; 32],
            one_time: false,
            delete_after_download: false,
            requested_ttl_sec: 0,
        };
        assert!(encode_attachment_action(&too_long_chat).is_err());
        let too_long_message = AttachmentAction::BeginUpload {
            chat_id: Zeroizing::new("chat".to_owned()),
            message_id: Zeroizing::new("x".repeat(MAX_ATTACHMENT_MESSAGE_ID_BYTES + 1)),
            media_type: AttachmentMediaType::File,
            cipher_version: 1,
            ciphertext_len: 1,
            ciphertext_sha256: [9; 32],
            one_time: false,
            delete_after_download: false,
            requested_ttl_sec: 0,
        };
        assert!(encode_attachment_action(&too_long_message).is_err());
    }

    #[test]
    fn stream_round_trip_enforces_data_padding_end_sequence() {
        let length = (ATTACHMENT_STREAM_PAYLOAD_BYTES as u64 * 2) + 7;
        let mut sealer = stream_binding(HANDLE)
            .into_sealer(&ROOT, Direction::ClientToServer, length)
            .unwrap();
        assert_eq!(sealer.data_frame_count(), 3);
        assert_eq!(sealer.bucket_frame_count(), 4);
        assert!(sealer.seal_padding().is_err());
        assert!(sealer.seal_data(&[1; 7]).is_err());
        let first = sealer
            .seal_data(&vec![1; ATTACHMENT_STREAM_PAYLOAD_BYTES])
            .unwrap();
        let second = sealer
            .seal_data(&vec![2; ATTACHMENT_STREAM_PAYLOAD_BYTES])
            .unwrap();
        let third = sealer.seal_data(&[3; 7]).unwrap();
        let padding = sealer.seal_padding().unwrap();
        let end = sealer.seal_end().unwrap();
        assert!(sealer.is_complete());
        assert!(sealer.seal_end().is_err());

        let mut opener = stream_binding(HANDLE)
            .into_opener(&ROOT, Direction::ClientToServer, length, 3, 4)
            .unwrap();
        for (record, expected) in [
            (
                first.as_slice(),
                Some((1_u8, ATTACHMENT_STREAM_PAYLOAD_BYTES)),
            ),
            (
                second.as_slice(),
                Some((2_u8, ATTACHMENT_STREAM_PAYLOAD_BYTES)),
            ),
            (third.as_slice(), Some((3_u8, 7))),
        ] {
            let AttachmentFrame::Data(payload) = opener.open(record).unwrap() else {
                panic!("expected data")
            };
            assert_eq!(payload.len(), expected.unwrap().1);
            assert!(payload.iter().all(|byte| *byte == expected.unwrap().0));
        }
        assert_eq!(opener.open(&padding).unwrap(), AttachmentFrame::Padding);
        assert_eq!(opener.open(&end).unwrap(), AttachmentFrame::End);
        assert!(opener.is_complete());
        assert!(opener.open(&end).is_err());
    }

    #[test]
    fn stream_rejects_replay_gap_reorder_tamper_reflection_and_context_changes() {
        let mut sealer = stream_binding(HANDLE)
            .into_sealer(&ROOT, Direction::ClientToServer, 7)
            .unwrap();
        let data = sealer.seal_data(b"payload").unwrap();
        let end = sealer.seal_end().unwrap();
        assert_eq!(data.len(), ATTACHMENT_STREAM_FRAME_BYTES);
        assert_eq!(end.len(), ATTACHMENT_STREAM_FRAME_BYTES);

        let mut opener = stream_binding(HANDLE)
            .into_opener(&ROOT, Direction::ClientToServer, 7, 1, 1)
            .unwrap();
        assert_eq!(opener.open(&end).err(), Some(TransportError::CounterGap));
        let mut tampered = data.to_vec();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            opener.open(&tampered).err(),
            Some(TransportError::AuthenticationFailed)
        );
        assert!(matches!(
            opener.open(&data).unwrap(),
            AttachmentFrame::Data(_)
        ));
        assert_eq!(opener.open(&data).err(), Some(TransportError::Replay));
        assert_eq!(opener.open(&end).unwrap(), AttachmentFrame::End);

        for (root, handle, direction) in [
            ([8; 32], HANDLE, Direction::ClientToServer),
            (ROOT, [7; 16], Direction::ClientToServer),
            (ROOT, HANDLE, Direction::ServerToClient),
        ] {
            let mut wrong = stream_binding(handle)
                .into_opener(&root, direction, 7, 1, 1)
                .unwrap();
            assert!(wrong.open(&data).is_err());
        }
        for (node, session) in [([8; 32], SESSION), (NODE, [8; 32])] {
            let mut wrong = AttachmentStreamBinding::new(node, session, HANDLE)
                .unwrap()
                .into_opener(&ROOT, Direction::ClientToServer, 7, 1, 1)
                .unwrap();
            assert!(wrong.open(&data).is_err());
        }
        assert!(stream_binding(HANDLE)
            .into_opener(&ROOT, Direction::ClientToServer, 7, 2, 2)
            .is_err());
        assert!(opener.open(&data[..data.len() - 1]).is_err());
        let mut trailing = data.to_vec();
        trailing.push(0);
        assert!(opener.open(&trailing).is_err());
        let mut reserved = data.to_vec();
        reserved[6] = 1;
        assert!(opener.open(&reserved).is_err());
    }

    #[test]
    fn stream_headers_and_http_records_hide_semantics() {
        let chat_marker = b"dm_Alice_Bob";
        let message_marker = b"message-secret";
        let digest_marker = [9_u8; 32];
        let attachment_marker = [7_u8; 16];
        let claim_marker = [8_u8; 16];
        let stream_marker = b"dm_Alice_Bob-message-secret";
        let action = AttachmentAction::BeginUpload {
            chat_id: Zeroizing::new("dm_Alice_Bob".to_owned()),
            message_id: Zeroizing::new("message-secret".to_owned()),
            media_type: AttachmentMediaType::File,
            cipher_version: 1,
            ciphertext_len: stream_marker.len() as u64,
            ciphertext_sha256: digest_marker,
            one_time: false,
            delete_after_download: false,
            requested_ttl_sec: 0,
        };
        let plain = encode_attachment_action(&action).unwrap();
        assert!(plain
            .windows(chat_marker.len())
            .any(|window| window == chat_marker.as_slice()));
        assert!(plain
            .windows(message_marker.len())
            .any(|window| window == message_marker.as_slice()));
        assert!(plain
            .windows(digest_marker.len())
            .any(|window| window == digest_marker.as_slice()));

        let mut http = HttpSessionBinding::new(NODE, SESSION)
            .unwrap()
            .into_client(&ROOT)
            .unwrap()
            .sealer;
        let request = http.seal(HANDLE, ATTACHMENT_ACTION_AAD, &plain).unwrap();
        assert_eq!(request.len(), ATTACHMENT_ACTION_RECORD_BYTES);
        assert!(inspect_http_record(&request).is_ok());

        let upload_result = encode_attachment_result(&AttachmentResult::UploadAccepted {
            attachment_id: attachment_marker,
        })
        .unwrap();
        assert!(upload_result
            .windows(attachment_marker.len())
            .any(|window| window == attachment_marker.as_slice()));
        let download_result = encode_attachment_result(&AttachmentResult::DownloadAccepted {
            claim_id: Some(claim_marker),
            ciphertext_len: 1,
            ciphertext_sha256: digest_marker,
            data_frame_count: 1,
            bucket_frame_count: 1,
        })
        .unwrap();
        assert!(download_result
            .windows(digest_marker.len())
            .any(|window| window == digest_marker.as_slice()));
        assert!(download_result
            .windows(claim_marker.len())
            .any(|window| window == claim_marker.as_slice()));
        let mut upload_server = HttpSessionBinding::new(NODE, SESSION)
            .unwrap()
            .into_server(&ROOT)
            .unwrap();
        let upload_response = upload_server
            .sealer
            .seal(HANDLE, ATTACHMENT_ACTION_AAD, &upload_result)
            .unwrap();
        let mut download_server = HttpSessionBinding::new(NODE, SESSION)
            .unwrap()
            .into_server(&ROOT)
            .unwrap();
        let download_response = download_server
            .sealer
            .seal(HANDLE, ATTACHMENT_ACTION_AAD, &download_result)
            .unwrap();
        for sealed in [&request, &upload_response, &download_response] {
            for marker in [
                chat_marker.as_slice(),
                message_marker.as_slice(),
                digest_marker.as_slice(),
                attachment_marker.as_slice(),
                claim_marker.as_slice(),
            ] {
                assert!(!sealed.windows(marker.len()).any(|window| window == marker));
            }
        }

        let mut stream = stream_binding(HANDLE)
            .into_sealer(&ROOT, Direction::ClientToServer, stream_marker.len() as u64)
            .unwrap();
        let frame = stream.seal_data(stream_marker).unwrap();
        assert!(!frame
            .windows(stream_marker.len())
            .any(|window| window == stream_marker.as_slice()));
        assert_eq!(&frame[..4], STREAM_MAGIC);
        assert_eq!(&frame[6..8], &[0, 0]);
    }

    #[test]
    fn malformed_frame_plaintext_and_counter_exhaustion_fail_closed() {
        let valid = frame_plaintext(FRAME_DATA, b"x").unwrap();
        for (index, value) in [(0, 99), (1, 1), (2, 1), (3, 1)] {
            let mut changed = valid.to_vec();
            changed[index] = value;
            assert!(decode_frame_plaintext(&changed).is_err());
        }
        let mut zero_data = valid.to_vec();
        zero_data[4..8].fill(0);
        assert!(decode_frame_plaintext(&zero_data).is_err());
        assert!(frame_plaintext(FRAME_PADDING, b"x").is_err());

        let mut sealer = stream_binding(HANDLE)
            .into_sealer(&ROOT, Direction::ClientToServer, 1)
            .unwrap();
        sealer.exhaust_for_test();
        assert_eq!(
            sealer.seal_data(b"x").err(),
            Some(TransportError::CounterExhausted)
        );
        let mut opener = stream_binding(HANDLE)
            .into_opener(&ROOT, Direction::ClientToServer, 1, 1, 1)
            .unwrap();
        opener.exhaust_for_test();
        assert_eq!(
            opener.open(&vec![0; ATTACHMENT_STREAM_FRAME_BYTES]).err(),
            Some(TransportError::CounterExhausted)
        );
    }

    #[test]
    fn stream_binding_rejects_zero_material() {
        assert!(AttachmentStreamBinding::new([0; 32], SESSION, HANDLE).is_err());
        assert!(AttachmentStreamBinding::new(NODE, [0; 32], HANDLE).is_err());
        assert!(AttachmentStreamBinding::new(NODE, SESSION, [0; 16]).is_err());
        assert!(stream_binding(HANDLE)
            .into_sealer(&[0; 32], Direction::ClientToServer, 1)
            .is_err());
    }
}
