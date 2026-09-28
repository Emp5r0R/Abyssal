//! Fixed-size authenticated HTTP control messages for transport v11.
//!
//! Control semantics are deliberately kept inside the encrypted record.  The
//! outer HTTP record contains only the canonical transport header; this codec
//! owns the bounded operation and attestation fields carried in its padded
//! plaintext.

use crate::TransportError;
use zeroize::Zeroizing;

pub const CONTROL_OPERATION: &[u8] = b"control-v11";
pub const CONTROL_AAD: &[u8] = b"POST /v1/control";
pub const CONTROL_PLAINTEXT_BYTES: usize = 4096;
pub const CONTROL_RECORD_BYTES: usize = 4 + 1 + 1 + 32 + 16 + 4 + CONTROL_PLAINTEXT_BYTES + 16;
pub const MAX_CONTROL_PLATFORM_BYTES: usize = 32;
pub const MAX_CONTROL_VERSION_BYTES: usize = 64;
pub const MAX_CONTROL_SIGNATURE_BYTES: usize = 256;
pub const MAX_CONTROL_TICKET_BYTES: usize = 128;

const CODEC_VERSION: u8 = 1;
const ACTION_ISSUE_WS_TICKET: u8 = 1;
const ACTION_LOGOUT: u8 = 2;
const RESULT_FAILURE: u8 = 0;
const RESULT_WS_TICKET: u8 = 1;
const RESULT_LOGGED_OUT: u8 = 2;
const ENVELOPE_BYTES: usize = 6;
const MAX_PAYLOAD_BYTES: usize = CONTROL_PLAINTEXT_BYTES - ENVELOPE_BYTES;

pub enum ControlAction {
    IssueWsTicket {
        platform: Zeroizing<String>,
        version: Zeroizing<String>,
        build_signature: Zeroizing<String>,
    },
    Logout,
}

pub enum ControlResult {
    Failure,
    WsTicket {
        ticket: Zeroizing<String>,
        expires_in_sec: u32,
    },
    LoggedOut,
}

pub fn encode_control_action(action: &ControlAction) -> Result<Zeroizing<Vec<u8>>, TransportError> {
    let mut payload = Zeroizing::new(Vec::new());
    let kind = match action {
        ControlAction::IssueWsTicket {
            platform,
            version,
            build_signature,
        } => {
            put_text(&mut payload, platform, MAX_CONTROL_PLATFORM_BYTES)?;
            put_text(&mut payload, version, MAX_CONTROL_VERSION_BYTES)?;
            put_text(&mut payload, build_signature, MAX_CONTROL_SIGNATURE_BYTES)?;
            ACTION_ISSUE_WS_TICKET
        }
        ControlAction::Logout => ACTION_LOGOUT,
    };
    pad(payload, kind)
}

pub fn decode_control_action(plaintext: &[u8]) -> Result<ControlAction, TransportError> {
    let (kind, mut reader) = decode_envelope(plaintext)?;
    let action = match kind {
        ACTION_ISSUE_WS_TICKET => ControlAction::IssueWsTicket {
            platform: Zeroizing::new(reader.take_text(MAX_CONTROL_PLATFORM_BYTES)?),
            version: Zeroizing::new(reader.take_text(MAX_CONTROL_VERSION_BYTES)?),
            build_signature: Zeroizing::new(reader.take_text(MAX_CONTROL_SIGNATURE_BYTES)?),
        },
        ACTION_LOGOUT => ControlAction::Logout,
        _ => return Err(TransportError::NonCanonical),
    };
    reader.finish()?;
    Ok(action)
}

pub fn encode_control_result(result: &ControlResult) -> Result<Zeroizing<Vec<u8>>, TransportError> {
    let mut payload = Zeroizing::new(Vec::new());
    let kind = match result {
        ControlResult::Failure => RESULT_FAILURE,
        ControlResult::WsTicket {
            ticket,
            expires_in_sec,
        } => {
            put_text(&mut payload, ticket, MAX_CONTROL_TICKET_BYTES)?;
            if *expires_in_sec == 0 || *expires_in_sec > 24 * 60 * 60 {
                return Err(TransportError::InvalidInput);
            }
            payload.extend_from_slice(&expires_in_sec.to_be_bytes());
            RESULT_WS_TICKET
        }
        ControlResult::LoggedOut => RESULT_LOGGED_OUT,
    };
    pad(payload, kind)
}

pub fn decode_control_result(plaintext: &[u8]) -> Result<ControlResult, TransportError> {
    let (kind, mut reader) = decode_envelope(plaintext)?;
    let result = match kind {
        RESULT_FAILURE => ControlResult::Failure,
        RESULT_WS_TICKET => {
            let ticket = Zeroizing::new(reader.take_text(MAX_CONTROL_TICKET_BYTES)?);
            let expires_in_sec = reader.take_u32()?;
            if expires_in_sec == 0 || expires_in_sec > 24 * 60 * 60 {
                return Err(TransportError::NonCanonical);
            }
            ControlResult::WsTicket {
                ticket,
                expires_in_sec,
            }
        }
        RESULT_LOGGED_OUT => ControlResult::LoggedOut,
        _ => return Err(TransportError::NonCanonical),
    };
    reader.finish()?;
    Ok(result)
}

fn put_text(output: &mut Vec<u8>, value: &str, maximum: usize) -> Result<(), TransportError> {
    if value.is_empty() || value.len() > maximum || !value.is_ascii() {
        return Err(if value.len() > maximum {
            TransportError::TooLarge
        } else {
            TransportError::InvalidInput
        });
    }
    let length = u16::try_from(value.len()).map_err(|_| TransportError::TooLarge)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn pad(payload: Zeroizing<Vec<u8>>, kind: u8) -> Result<Zeroizing<Vec<u8>>, TransportError> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(TransportError::TooLarge);
    }
    let length = u32::try_from(payload.len()).map_err(|_| TransportError::TooLarge)?;
    let mut output = Zeroizing::new(vec![0_u8; CONTROL_PLAINTEXT_BYTES]);
    output[0] = CODEC_VERSION;
    output[1] = kind;
    output[2..6].copy_from_slice(&length.to_be_bytes());
    output[ENVELOPE_BYTES..ENVELOPE_BYTES + payload.len()].copy_from_slice(&payload);
    getrandom::fill(&mut output[ENVELOPE_BYTES + payload.len()..])
        .map_err(|_| TransportError::InvalidInput)?;
    Ok(output)
}

fn decode_envelope(plaintext: &[u8]) -> Result<(u8, Reader<'_>), TransportError> {
    if plaintext.len() != CONTROL_PLAINTEXT_BYTES || plaintext[0] != CODEC_VERSION {
        return Err(TransportError::NonCanonical);
    }
    let kind = plaintext[1];
    let payload_len = usize::try_from(u32::from_be_bytes(
        plaintext[2..6]
            .try_into()
            .map_err(|_| TransportError::NonCanonical)?,
    ))
    .map_err(|_| TransportError::TooLarge)?;
    if payload_len > MAX_PAYLOAD_BYTES {
        return Err(TransportError::NonCanonical);
    }
    if (kind == RESULT_FAILURE || kind == RESULT_LOGGED_OUT || kind == ACTION_LOGOUT)
        && payload_len != 0
    {
        return Err(TransportError::NonCanonical);
    }
    if kind != RESULT_FAILURE
        && kind != RESULT_LOGGED_OUT
        && kind != ACTION_LOGOUT
        && payload_len == 0
    {
        return Err(TransportError::NonCanonical);
    }
    Ok((
        kind,
        Reader::new(
            plaintext
                .get(ENVELOPE_BYTES..ENVELOPE_BYTES + payload_len)
                .ok_or(TransportError::NonCanonical)?,
        ),
    ))
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn take_text(&mut self, maximum: usize) -> Result<String, TransportError> {
        let length = usize::from(self.take_u16()?);
        if length == 0 || length > maximum {
            return Err(if length > maximum {
                TransportError::TooLarge
            } else {
                TransportError::NonCanonical
            });
        }
        let value = self.take(length)?;
        if !value.is_ascii() {
            return Err(TransportError::NonCanonical);
        }
        String::from_utf8(value.to_vec()).map_err(|_| TransportError::NonCanonical)
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

    fn finish(self) -> Result<(), TransportError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(TransportError::NonCanonical)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_codec_is_fixed_size_and_round_trips() {
        let action = ControlAction::IssueWsTicket {
            platform: Zeroizing::new("android".to_owned()),
            version: Zeroizing::new("2.1.0".to_owned()),
            build_signature: Zeroizing::new("sig".to_owned()),
        };
        let encoded = encode_control_action(&action).unwrap();
        assert_eq!(encoded.len(), CONTROL_PLAINTEXT_BYTES);
        assert!(matches!(
            decode_control_action(&encoded).unwrap(),
            ControlAction::IssueWsTicket { .. }
        ));
        let result = encode_control_result(&ControlResult::LoggedOut).unwrap();
        assert_eq!(result.len(), CONTROL_PLAINTEXT_BYTES);
        assert!(matches!(
            decode_control_result(&result).unwrap(),
            ControlResult::LoggedOut
        ));
    }

    #[test]
    fn control_codec_rejects_tampering_and_unbounded_fields() {
        let action = ControlAction::Logout;
        let encoded = encode_control_action(&action).unwrap();
        assert!(decode_control_action(&encoded).is_ok());
        let mut bad = encoded.to_vec();
        bad[1] = ACTION_ISSUE_WS_TICKET;
        assert!(decode_control_action(&bad).is_err());
        assert!(encode_control_action(&ControlAction::IssueWsTicket {
            platform: Zeroizing::new("a".repeat(MAX_CONTROL_PLATFORM_BYTES + 1)),
            version: Zeroizing::new("v".to_owned()),
            build_signature: Zeroizing::new("s".to_owned()),
        })
        .is_err());
    }
}
