//! Abyssal's two text forms, both owned by the shared format: the
//! `abyssal:invite:` deep link and the checksummed `ABY1-` manual form.

use crate::{InviteError, SignedInviteCapsule};
use invite_capsule::SignedInvite;

pub fn encode_deep_link(invite: &SignedInviteCapsule) -> Result<String, InviteError> {
    Ok(invite.to_shared(None)?.to_text()?.to_string())
}

pub fn encode_manual(invite: &SignedInviteCapsule) -> Result<String, InviteError> {
    Ok(invite.to_shared(None)?.to_manual_text()?.to_string())
}

pub fn decode_invite_text(
    input: &str,
    now_unix_seconds: Option<u64>,
) -> Result<SignedInviteCapsule, InviteError> {
    Ok(SignedInviteCapsule::from_shared(&SignedInvite::from_text(
        input,
        now_unix_seconds,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::MANUAL_PREFIX;
    use crate::{
        locator_from_public_url, InviteCapsuleV1, SignedInviteCapsule, DIRECT_PROTOCOL_VERSION,
        ROOM_PROTOCOL_VERSION,
    };
    use ed25519_dalek::SigningKey;

    fn fixture() -> SignedInviteCapsule {
        let key = SigningKey::from_bytes(&[7_u8; 32]);
        let capsule = InviteCapsuleV1::abyssal(
            key.verifying_key().to_bytes(),
            vec![locator_from_public_url("https://chat.example.com:8443").unwrap()],
            [9_u8; 32],
            DIRECT_PROTOCOL_VERSION,
            ROOM_PROTOCOL_VERSION,
            Some(2_000_000_000),
        )
        .unwrap();
        SignedInviteCapsule::sign(capsule, &key).unwrap()
    }

    #[test]
    fn both_text_forms_round_trip_to_identical_binary() {
        let invite = fixture();
        let deep = encode_deep_link(&invite).unwrap();
        let manual = encode_manual(&invite).unwrap();
        let from_deep = decode_invite_text(&deep, Some(1_900_000_000)).unwrap();
        let from_manual = decode_invite_text(&manual.to_lowercase(), Some(1_900_000_000)).unwrap();
        assert_eq!(from_deep, from_manual);
        assert_eq!(
            from_deep.canonical_binary().unwrap(),
            invite.canonical_binary().unwrap()
        );
    }

    #[test]
    fn manual_form_accepts_crockford_transcription_aliases() {
        let invite = fixture();
        let manual = encode_manual(&invite).unwrap();
        let aliased = format!(
            "{}{}",
            MANUAL_PREFIX,
            manual[MANUAL_PREFIX.len()..]
                .replace('0', "O")
                .replace('1', "L")
        );
        assert_eq!(
            decode_invite_text(&aliased, None).unwrap().capsule,
            invite.capsule
        );
    }

    #[test]
    fn malformed_text_and_checksum_fail_closed() {
        let invite = fixture();
        let mut deep = encode_deep_link(&invite).unwrap();
        deep.push('=');
        assert_eq!(decode_invite_text(&deep, None), Err(InviteError::Invalid));

        let mut manual = encode_manual(&invite).unwrap().into_bytes();
        let index = manual
            .iter()
            .position(|byte| *byte != b'-' && *byte != b'A')
            .unwrap();
        manual[index] = if manual[index] == b'Z' { b'Y' } else { b'Z' };
        assert!(matches!(
            decode_invite_text(std::str::from_utf8(&manual).unwrap(), None),
            Err(InviteError::InvalidChecksum | InviteError::Invalid)
        ));
    }

    #[test]
    fn expiry_is_enforced_after_signature_verification() {
        let invite = fixture();
        assert_eq!(
            decode_invite_text(&encode_deep_link(&invite).unwrap(), Some(2_000_000_000)),
            Err(InviteError::Expired)
        );
    }
}
