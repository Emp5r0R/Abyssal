//! Canonical account bootstrap messages carried inside protocol-v11 HPKE records.
//!
//! This module owns only bounded binary framing. It deliberately knows nothing
//! about UUIDs, OPAQUE semantics, HTTP, or account persistence.

use crate::{TransportError, MAX_BOOTSTRAP_PLAINTEXT_BYTES};
use zeroize::Zeroizing;

pub const ACCOUNT_BOOTSTRAP_OPERATION: &[u8] = b"account-bootstrap-v11";
pub const ACCOUNT_BOOTSTRAP_HEADER_BYTES: usize = 6;
pub const MAX_ACCOUNT_BOOTSTRAP_FIELD_BYTES: usize = 48 * 1024;

const CODEC_VERSION: u8 = 1;
const ACTION_START: u8 = 1;
const ACTION_FINISH_REGISTRATION: u8 = 2;
const ACTION_FINISH_LOGIN: u8 = 3;
const RESULT_FAILURE: u8 = 0;
const RESULT_LOGIN_START: u8 = 1;
const RESULT_REGISTRATION_START: u8 = 2;
const RESULT_REGISTRATION_CONTINUATION: u8 = 3;
const RESULT_SESSION: u8 = 4;
const MIN_MAX_ROOMS_PER_USER: u32 = 1;
const MAX_MAX_ROOMS_PER_USER: u32 = 100;
const MIN_SESSION_INACTIVITY_SEC: u32 = 60;
const MAX_SESSION_INACTIVITY_SEC: u32 = 24 * 60 * 60;
const MAX_PAYLOAD_BYTES: usize = MAX_BOOTSTRAP_PLAINTEXT_BYTES - ACCOUNT_BOOTSTRAP_HEADER_BYTES;

pub enum AccountBootstrapAction {
    Start {
        capability: Zeroizing<[u8; 32]>,
        registration_request: Zeroizing<Vec<u8>>,
        credential_request: Zeroizing<Vec<u8>>,
    },
    FinishRegistration {
        handshake_id: [u8; 16],
        registration_upload: Zeroizing<Vec<u8>>,
        identity_public: Zeroizing<Vec<u8>>,
        identity_prekey_id: Zeroizing<String>,
        identity_envelope: Zeroizing<Vec<u8>>,
        identity_proof: Zeroizing<Vec<u8>>,
    },
    FinishLogin {
        handshake_id: [u8; 16],
        credential_finalization: Zeroizing<Vec<u8>>,
    },
}

pub enum AccountBootstrapResult {
    Failure,
    LoginStart {
        handshake_id: [u8; 16],
        credential_response: Zeroizing<Vec<u8>>,
        identity_public: Zeroizing<Vec<u8>>,
        identity_prekey_id: Zeroizing<String>,
        identity_envelope: Zeroizing<Vec<u8>>,
    },
    RegistrationStart {
        handshake_id: [u8; 16],
        registration_response: Zeroizing<Vec<u8>>,
        challenge: Zeroizing<Vec<u8>>,
    },
    RegistrationContinuation {
        handshake_id: [u8; 16],
        credential_response: Zeroizing<Vec<u8>>,
    },
    Session {
        session_id: Zeroizing<[u8; 32]>,
        created: bool,
        max_rooms_per_user: u32,
        session_inactivity_sec: u32,
        username: Zeroizing<String>,
        identity_public: Zeroizing<Vec<u8>>,
        identity_prekey_id: Zeroizing<String>,
        identity_envelope: Zeroizing<Vec<u8>>,
    },
}

pub fn encode_account_bootstrap_action(
    action: &AccountBootstrapAction,
) -> Result<Zeroizing<Vec<u8>>, TransportError> {
    let mut payload = Zeroizing::new(Vec::new());
    let kind = match action {
        AccountBootstrapAction::Start {
            capability,
            registration_request,
            credential_request,
        } => {
            require_nonzero(capability)?;
            payload.extend_from_slice(capability.as_ref());
            put_bytes(&mut payload, registration_request)?;
            put_bytes(&mut payload, credential_request)?;
            ACTION_START
        }
        AccountBootstrapAction::FinishRegistration {
            handshake_id,
            registration_upload,
            identity_public,
            identity_prekey_id,
            identity_envelope,
            identity_proof,
        } => {
            require_nonzero(handshake_id)?;
            payload.extend_from_slice(handshake_id);
            put_bytes(&mut payload, registration_upload)?;
            put_bytes(&mut payload, identity_public)?;
            put_text(&mut payload, identity_prekey_id)?;
            put_bytes(&mut payload, identity_envelope)?;
            put_bytes(&mut payload, identity_proof)?;
            ACTION_FINISH_REGISTRATION
        }
        AccountBootstrapAction::FinishLogin {
            handshake_id,
            credential_finalization,
        } => {
            require_nonzero(handshake_id)?;
            payload.extend_from_slice(handshake_id);
            put_bytes(&mut payload, credential_finalization)?;
            ACTION_FINISH_LOGIN
        }
    };
    pad(payload, kind)
}

pub fn decode_account_bootstrap_action(
    plaintext: &[u8],
) -> Result<AccountBootstrapAction, TransportError> {
    let (kind, mut reader) = decode_envelope(plaintext)?;
    let value = match kind {
        ACTION_START => AccountBootstrapAction::Start {
            capability: Zeroizing::new(reader.take_nonzero_array::<32>()?),
            registration_request: Zeroizing::new(reader.take_bytes()?),
            credential_request: Zeroizing::new(reader.take_bytes()?),
        },
        ACTION_FINISH_REGISTRATION => AccountBootstrapAction::FinishRegistration {
            handshake_id: reader.take_nonzero_array::<16>()?,
            registration_upload: Zeroizing::new(reader.take_bytes()?),
            identity_public: Zeroizing::new(reader.take_bytes()?),
            identity_prekey_id: Zeroizing::new(reader.take_text()?),
            identity_envelope: Zeroizing::new(reader.take_bytes()?),
            identity_proof: Zeroizing::new(reader.take_bytes()?),
        },
        ACTION_FINISH_LOGIN => AccountBootstrapAction::FinishLogin {
            handshake_id: reader.take_nonzero_array::<16>()?,
            credential_finalization: Zeroizing::new(reader.take_bytes()?),
        },
        _ => return Err(TransportError::NonCanonical),
    };
    reader.finish()?;
    Ok(value)
}

pub fn encode_account_bootstrap_result(
    result: &AccountBootstrapResult,
) -> Result<Zeroizing<Vec<u8>>, TransportError> {
    let mut payload = Zeroizing::new(Vec::new());
    let kind = match result {
        AccountBootstrapResult::Failure => RESULT_FAILURE,
        AccountBootstrapResult::LoginStart {
            handshake_id,
            credential_response,
            identity_public,
            identity_prekey_id,
            identity_envelope,
        } => {
            require_nonzero(handshake_id)?;
            payload.extend_from_slice(handshake_id);
            put_bytes(&mut payload, credential_response)?;
            put_bytes(&mut payload, identity_public)?;
            put_text(&mut payload, identity_prekey_id)?;
            put_bytes(&mut payload, identity_envelope)?;
            RESULT_LOGIN_START
        }
        AccountBootstrapResult::RegistrationStart {
            handshake_id,
            registration_response,
            challenge,
        } => {
            require_nonzero(handshake_id)?;
            payload.extend_from_slice(handshake_id);
            put_bytes(&mut payload, registration_response)?;
            put_bytes(&mut payload, challenge)?;
            RESULT_REGISTRATION_START
        }
        AccountBootstrapResult::RegistrationContinuation {
            handshake_id,
            credential_response,
        } => {
            require_nonzero(handshake_id)?;
            payload.extend_from_slice(handshake_id);
            put_bytes(&mut payload, credential_response)?;
            RESULT_REGISTRATION_CONTINUATION
        }
        AccountBootstrapResult::Session {
            session_id,
            created,
            max_rooms_per_user,
            session_inactivity_sec,
            username,
            identity_public,
            identity_prekey_id,
            identity_envelope,
        } => {
            require_nonzero(session_id)?;
            validate_session_policy(*max_rooms_per_user, *session_inactivity_sec)?;
            payload.extend_from_slice(session_id.as_ref());
            payload.push(u8::from(*created));
            payload.extend_from_slice(&max_rooms_per_user.to_be_bytes());
            payload.extend_from_slice(&session_inactivity_sec.to_be_bytes());
            put_text(&mut payload, username)?;
            put_bytes(&mut payload, identity_public)?;
            put_text(&mut payload, identity_prekey_id)?;
            put_bytes(&mut payload, identity_envelope)?;
            RESULT_SESSION
        }
    };
    pad(payload, kind)
}

pub fn decode_account_bootstrap_result(
    plaintext: &[u8],
) -> Result<AccountBootstrapResult, TransportError> {
    let (kind, mut reader) = decode_envelope(plaintext)?;
    let value = match kind {
        RESULT_FAILURE => AccountBootstrapResult::Failure,
        RESULT_LOGIN_START => AccountBootstrapResult::LoginStart {
            handshake_id: reader.take_nonzero_array::<16>()?,
            credential_response: Zeroizing::new(reader.take_bytes()?),
            identity_public: Zeroizing::new(reader.take_bytes()?),
            identity_prekey_id: Zeroizing::new(reader.take_text()?),
            identity_envelope: Zeroizing::new(reader.take_bytes()?),
        },
        RESULT_REGISTRATION_START => AccountBootstrapResult::RegistrationStart {
            handshake_id: reader.take_nonzero_array::<16>()?,
            registration_response: Zeroizing::new(reader.take_bytes()?),
            challenge: Zeroizing::new(reader.take_bytes()?),
        },
        RESULT_REGISTRATION_CONTINUATION => AccountBootstrapResult::RegistrationContinuation {
            handshake_id: reader.take_nonzero_array::<16>()?,
            credential_response: Zeroizing::new(reader.take_bytes()?),
        },
        RESULT_SESSION => AccountBootstrapResult::Session {
            session_id: Zeroizing::new(reader.take_nonzero_array::<32>()?),
            created: reader.take_bool()?,
            max_rooms_per_user: reader.take_session_max_rooms_per_user()?,
            session_inactivity_sec: reader.take_session_inactivity_sec()?,
            username: Zeroizing::new(reader.take_text()?),
            identity_public: Zeroizing::new(reader.take_bytes()?),
            identity_prekey_id: Zeroizing::new(reader.take_text()?),
            identity_envelope: Zeroizing::new(reader.take_bytes()?),
        },
        _ => return Err(TransportError::NonCanonical),
    };
    reader.finish()?;
    Ok(value)
}

fn pad(payload: Zeroizing<Vec<u8>>, kind: u8) -> Result<Zeroizing<Vec<u8>>, TransportError> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(TransportError::TooLarge);
    }
    let payload_len = u32::try_from(payload.len()).map_err(|_| TransportError::TooLarge)?;
    let mut output = Zeroizing::new(vec![0_u8; MAX_BOOTSTRAP_PLAINTEXT_BYTES]);
    output[0] = CODEC_VERSION;
    output[1] = kind;
    output[2..6].copy_from_slice(&payload_len.to_be_bytes());
    output[ACCOUNT_BOOTSTRAP_HEADER_BYTES..ACCOUNT_BOOTSTRAP_HEADER_BYTES + payload.len()]
        .copy_from_slice(&payload);
    getrandom::fill(&mut output[ACCOUNT_BOOTSTRAP_HEADER_BYTES + payload.len()..])
        .map_err(|_| TransportError::InvalidInput)?;
    Ok(output)
}

fn decode_envelope(plaintext: &[u8]) -> Result<(u8, Reader<'_>), TransportError> {
    if plaintext.len() != MAX_BOOTSTRAP_PLAINTEXT_BYTES || plaintext[0] != CODEC_VERSION {
        return Err(TransportError::NonCanonical);
    }
    let kind = plaintext[1];
    let payload_len = usize::try_from(u32::from_be_bytes(
        plaintext[2..6]
            .try_into()
            .map_err(|_| TransportError::NonCanonical)?,
    ))
    .map_err(|_| TransportError::TooLarge)?;
    if payload_len > MAX_PAYLOAD_BYTES || (kind != RESULT_FAILURE && payload_len == 0) {
        return Err(TransportError::NonCanonical);
    }
    if kind == RESULT_FAILURE && payload_len != 0 {
        return Err(TransportError::NonCanonical);
    }
    Ok((
        kind,
        Reader::new(
            plaintext
                .get(ACCOUNT_BOOTSTRAP_HEADER_BYTES..ACCOUNT_BOOTSTRAP_HEADER_BYTES + payload_len)
                .ok_or(TransportError::NonCanonical)?,
        ),
    ))
}

fn put_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), TransportError> {
    if value.is_empty() || value.len() > MAX_ACCOUNT_BOOTSTRAP_FIELD_BYTES {
        return Err(TransportError::InvalidInput);
    }
    let len = u32::try_from(value.len()).map_err(|_| TransportError::TooLarge)?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn put_text(output: &mut Vec<u8>, value: &str) -> Result<(), TransportError> {
    put_bytes(output, value.as_bytes())
}

fn require_nonzero<const N: usize>(value: &[u8; N]) -> Result<(), TransportError> {
    if *value == [0_u8; N] {
        return Err(TransportError::InvalidInput);
    }
    Ok(())
}

fn validate_session_policy(
    max_rooms_per_user: u32,
    session_inactivity_sec: u32,
) -> Result<(), TransportError> {
    if !(MIN_MAX_ROOMS_PER_USER..=MAX_MAX_ROOMS_PER_USER).contains(&max_rooms_per_user)
        || !(MIN_SESSION_INACTIVITY_SEC..=MAX_SESSION_INACTIVITY_SEC)
            .contains(&session_inactivity_sec)
    {
        return Err(TransportError::InvalidInput);
    }
    Ok(())
}

struct Reader<'a> {
    value: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(value: &'a [u8]) -> Self {
        Self { value, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], TransportError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(TransportError::TooLarge)?;
        let result = self
            .value
            .get(self.offset..end)
            .ok_or(TransportError::NonCanonical)?;
        self.offset = end;
        Ok(result)
    }

    fn take_nonzero_array<const N: usize>(&mut self) -> Result<[u8; N], TransportError> {
        let value: [u8; N] = self
            .take(N)?
            .try_into()
            .map_err(|_| TransportError::NonCanonical)?;
        require_nonzero(&value).map_err(|_| TransportError::NonCanonical)?;
        Ok(value)
    }

    fn take_bool(&mut self) -> Result<bool, TransportError> {
        match self.take(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(TransportError::NonCanonical),
        }
    }

    fn take_u32(&mut self) -> Result<u32, TransportError> {
        self.take(4)?
            .try_into()
            .map(u32::from_be_bytes)
            .map_err(|_| TransportError::NonCanonical)
    }

    fn take_session_max_rooms_per_user(&mut self) -> Result<u32, TransportError> {
        let value = self.take_u32()?;
        if !(MIN_MAX_ROOMS_PER_USER..=MAX_MAX_ROOMS_PER_USER).contains(&value) {
            return Err(TransportError::NonCanonical);
        }
        Ok(value)
    }

    fn take_session_inactivity_sec(&mut self) -> Result<u32, TransportError> {
        let value = self.take_u32()?;
        if !(MIN_SESSION_INACTIVITY_SEC..=MAX_SESSION_INACTIVITY_SEC).contains(&value) {
            return Err(TransportError::NonCanonical);
        }
        Ok(value)
    }

    fn take_bytes(&mut self) -> Result<Vec<u8>, TransportError> {
        let len = usize::try_from(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| TransportError::NonCanonical)?,
        ))
        .map_err(|_| TransportError::TooLarge)?;
        if len == 0 || len > MAX_ACCOUNT_BOOTSTRAP_FIELD_BYTES {
            return Err(TransportError::NonCanonical);
        }
        Ok(self.take(len)?.to_vec())
    }

    fn take_text(&mut self) -> Result<String, TransportError> {
        String::from_utf8(self.take_bytes()?).map_err(|_| TransportError::NonCanonical)
    }

    fn finish(self) -> Result<(), TransportError> {
        if self.offset != self.value.len() {
            return Err(TransportError::NonCanonical);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(value: u8) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(vec![value; 32])
    }

    #[test]
    fn every_action_variant_round_trips_at_fixed_size() {
        let actions = [
            AccountBootstrapAction::Start {
                capability: Zeroizing::new([1; 32]),
                registration_request: bytes(2),
                credential_request: bytes(3),
            },
            AccountBootstrapAction::FinishRegistration {
                handshake_id: [4; 16],
                registration_upload: bytes(5),
                identity_public: bytes(6),
                identity_prekey_id: Zeroizing::new("prekey".to_owned()),
                identity_envelope: bytes(7),
                identity_proof: bytes(8),
            },
            AccountBootstrapAction::FinishLogin {
                handshake_id: [9; 16],
                credential_finalization: bytes(10),
            },
        ];
        for action in actions {
            let encoded = encode_account_bootstrap_action(&action).unwrap();
            assert_eq!(encoded.len(), MAX_BOOTSTRAP_PLAINTEXT_BYTES);
            assert!(decode_account_bootstrap_action(&encoded).is_ok());
        }
    }

    #[test]
    fn explicit_result_tags_round_trip_without_mode_ambiguity() {
        let results = [
            AccountBootstrapResult::Failure,
            AccountBootstrapResult::LoginStart {
                handshake_id: [1; 16],
                credential_response: bytes(2),
                identity_public: bytes(3),
                identity_prekey_id: Zeroizing::new("prekey".to_owned()),
                identity_envelope: bytes(4),
            },
            AccountBootstrapResult::RegistrationStart {
                handshake_id: [5; 16],
                registration_response: bytes(6),
                challenge: bytes(7),
            },
            AccountBootstrapResult::RegistrationContinuation {
                handshake_id: [8; 16],
                credential_response: bytes(9),
            },
            AccountBootstrapResult::Session {
                session_id: Zeroizing::new([10; 32]),
                created: true,
                max_rooms_per_user: 5,
                session_inactivity_sec: 900,
                username: Zeroizing::new("user".to_owned()),
                identity_public: bytes(11),
                identity_prekey_id: Zeroizing::new("prekey".to_owned()),
                identity_envelope: bytes(12),
            },
        ];
        for result in results {
            let encoded = encode_account_bootstrap_result(&result).unwrap();
            assert_eq!(encoded.len(), MAX_BOOTSTRAP_PLAINTEXT_BYTES);
            assert!(decode_account_bootstrap_result(&encoded).is_ok());
        }
    }

    #[test]
    fn malformed_and_noncanonical_messages_fail_closed() {
        let action = AccountBootstrapAction::FinishLogin {
            handshake_id: [1; 16],
            credential_finalization: bytes(2),
        };
        let encoded = encode_account_bootstrap_action(&action).unwrap();
        for index in [0_usize, 1, 2, 5] {
            let mut tampered = encoded.to_vec();
            tampered[index] ^= 0x80;
            assert!(decode_account_bootstrap_action(&tampered).is_err());
        }
        let mut trailing = encoded.to_vec();
        let payload_len = u32::from_be_bytes(trailing[2..6].try_into().unwrap());
        trailing[2..6].copy_from_slice(&(payload_len + 1).to_be_bytes());
        assert!(decode_account_bootstrap_action(&trailing).is_err());

        let mut zero_id = encode_account_bootstrap_action(&action).unwrap().to_vec();
        zero_id[ACCOUNT_BOOTSTRAP_HEADER_BYTES..ACCOUNT_BOOTSTRAP_HEADER_BYTES + 16].fill(0);
        assert!(decode_account_bootstrap_action(&zero_id).is_err());
    }

    #[test]
    fn finish_login_has_a_stable_canonical_payload_vector() {
        let action = AccountBootstrapAction::FinishLogin {
            handshake_id: [0x11; 16],
            credential_finalization: Zeroizing::new(vec![0x22; 4]),
        };
        let encoded = encode_account_bootstrap_action(&action).unwrap();
        let expected = [
            1, 3, 0, 0, 0, 24, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0, 0, 0, 4, 0x22, 0x22, 0x22, 0x22,
        ];
        assert_eq!(&encoded[..expected.len()], expected);
    }

    #[test]
    fn oversized_fields_and_zero_identifiers_are_rejected() {
        assert!(
            encode_account_bootstrap_action(&AccountBootstrapAction::Start {
                capability: Zeroizing::new([0; 32]),
                registration_request: bytes(1),
                credential_request: bytes(2),
            })
            .is_err()
        );
        assert!(
            encode_account_bootstrap_action(&AccountBootstrapAction::FinishLogin {
                handshake_id: [0; 16],
                credential_finalization: bytes(1),
            })
            .is_err()
        );
        assert!(
            encode_account_bootstrap_result(&AccountBootstrapResult::Session {
                session_id: Zeroizing::new([0; 32]),
                created: false,
                max_rooms_per_user: 5,
                session_inactivity_sec: 900,
                username: Zeroizing::new("user".to_owned()),
                identity_public: bytes(1),
                identity_prekey_id: Zeroizing::new("key".to_owned()),
                identity_envelope: bytes(2),
            })
            .is_err()
        );
        assert!(put_bytes(
            &mut Vec::new(),
            &vec![0; MAX_ACCOUNT_BOOTSTRAP_FIELD_BYTES + 1]
        )
        .is_err());
    }

    #[test]
    fn session_policy_fields_are_bounded_and_canonical() {
        let result = AccountBootstrapResult::Session {
            session_id: Zeroizing::new([1; 32]),
            created: false,
            max_rooms_per_user: 5,
            session_inactivity_sec: 900,
            username: Zeroizing::new("user".to_owned()),
            identity_public: bytes(1),
            identity_prekey_id: Zeroizing::new("key".to_owned()),
            identity_envelope: bytes(2),
        };
        let encoded = encode_account_bootstrap_result(&result).unwrap();
        let mut noncanonical = encoded.to_vec();
        noncanonical[ACCOUNT_BOOTSTRAP_HEADER_BYTES + 32] = 2;
        assert!(decode_account_bootstrap_result(&noncanonical).is_err());
        for (max_rooms_per_user, session_inactivity_sec) in
            [(0, 900), (101, 900), (5, 59), (5, 86_401)]
        {
            assert!(
                encode_account_bootstrap_result(&AccountBootstrapResult::Session {
                    session_id: Zeroizing::new([1; 32]),
                    created: false,
                    max_rooms_per_user,
                    session_inactivity_sec,
                    username: Zeroizing::new("user".to_owned()),
                    identity_public: bytes(1),
                    identity_prekey_id: Zeroizing::new("key".to_owned()),
                    identity_envelope: bytes(2),
                })
                .is_err()
            );
        }
    }
}
