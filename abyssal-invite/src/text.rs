use crate::{
    InviteError, SignedInviteCapsule, MAX_BINARY_INVITE_BYTES, MAX_ENCODED_INVITE_TEXT_BYTES,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const DEEP_LINK_PREFIX: &str = "abyssal:invite:";
const MANUAL_PREFIX: &str = "ABY1-";
const CHECKSUM_DOMAIN: &[u8] = b"ABYSSAL-INVITE-CHECKSUM-V1";
const CHECKSUM_BYTES: usize = 4;
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub fn encode_deep_link(invite: &SignedInviteCapsule) -> Result<String, InviteError> {
    let binary = Zeroizing::new(invite.canonical_binary()?);
    Ok(format!(
        "{DEEP_LINK_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(binary.as_slice())
    ))
}

pub fn encode_manual(invite: &SignedInviteCapsule) -> Result<String, InviteError> {
    let binary = Zeroizing::new(invite.canonical_binary()?);
    let mut checksummed = Zeroizing::new(Vec::with_capacity(binary.len() + CHECKSUM_BYTES));
    checksummed.extend_from_slice(&binary);
    checksummed.extend_from_slice(&checksum(&binary));
    let encoded = Zeroizing::new(crockford_encode(&checksummed));
    let mut output = String::with_capacity(MANUAL_PREFIX.len() + encoded.len() + encoded.len() / 5);
    output.push_str(MANUAL_PREFIX);
    for (index, character) in encoded.bytes().enumerate() {
        if index > 0 && index % 5 == 0 {
            output.push('-');
        }
        output.push(character as char);
    }
    Ok(output)
}

pub fn decode_invite_text(
    input: &str,
    now_unix_seconds: Option<u64>,
) -> Result<SignedInviteCapsule, InviteError> {
    if input.is_empty() || input.len() > MAX_ENCODED_INVITE_TEXT_BYTES {
        return Err(InviteError::TooLarge);
    }
    let trimmed = input.trim();
    if trimmed.len() != input.len() {
        return Err(InviteError::Invalid);
    }
    let binary = if trimmed
        .get(..MANUAL_PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(MANUAL_PREFIX))
    {
        decode_manual(trimmed)?
    } else {
        let encoded = trimmed.strip_prefix(DEEP_LINK_PREFIX).unwrap_or(trimmed);
        decode_base64(encoded)?
    };
    SignedInviteCapsule::decode(&binary, now_unix_seconds)
}

fn decode_base64(value: &str) -> Result<Zeroizing<Vec<u8>>, InviteError> {
    if value.is_empty()
        || value.len() > MAX_ENCODED_INVITE_TEXT_BYTES
        || value.contains('=')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(InviteError::Invalid);
    }
    let decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| InviteError::Invalid)?,
    );
    let canonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(decoded.as_slice()));
    if decoded.is_empty() || decoded.len() > MAX_BINARY_INVITE_BYTES || canonical.as_str() != value
    {
        return Err(InviteError::Invalid);
    }
    Ok(decoded)
}

fn decode_manual(value: &str) -> Result<Zeroizing<Vec<u8>>, InviteError> {
    let body = &value[MANUAL_PREFIX.len()..];
    if body.is_empty()
        || body.starts_with('-')
        || body.ends_with('-')
        || body.contains("--")
        || body
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'-'))
    {
        return Err(InviteError::Invalid);
    }
    let compact = Zeroizing::new(
        body.bytes()
            .filter(|byte| *byte != b'-')
            .collect::<Vec<_>>(),
    );
    let mut decoded = Zeroizing::new(crockford_decode(&compact)?);
    if decoded.len() <= CHECKSUM_BYTES || decoded.len() > MAX_BINARY_INVITE_BYTES + CHECKSUM_BYTES {
        return Err(InviteError::Invalid);
    }
    let split = decoded.len() - CHECKSUM_BYTES;
    let mut provided = [0_u8; CHECKSUM_BYTES];
    provided.copy_from_slice(&decoded[split..]);
    let expected = checksum(&decoded[..split]);
    let difference = provided
        .iter()
        .zip(expected)
        .fold(0_u8, |difference, (left, right)| {
            difference | (*left ^ right)
        });
    provided.zeroize();
    if difference != 0 {
        return Err(InviteError::InvalidChecksum);
    }
    decoded.truncate(split);
    Ok(decoded)
}

fn checksum(value: &[u8]) -> [u8; CHECKSUM_BYTES] {
    let mut digest = Sha256::new();
    digest.update(CHECKSUM_DOMAIN);
    digest.update(value);
    let digest = digest.finalize();
    let mut result = [0_u8; CHECKSUM_BYTES];
    result.copy_from_slice(&digest[..CHECKSUM_BYTES]);
    result
}

fn crockford_encode(value: &[u8]) -> String {
    let mut output = String::with_capacity(value.len().saturating_mul(8).div_ceil(5));
    let mut buffer = 0_u16;
    let mut bits = 0_u8;
    for byte in value {
        buffer = (buffer << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(CROCKFORD[((buffer >> bits) & 0x1f) as usize] as char);
            buffer &= (1_u16 << bits).saturating_sub(1);
        }
    }
    if bits > 0 {
        output.push(CROCKFORD[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    output
}

fn crockford_decode(value: &[u8]) -> Result<Vec<u8>, InviteError> {
    let max_bytes = value.len().saturating_mul(5).div_ceil(8);
    if max_bytes > MAX_BINARY_INVITE_BYTES + CHECKSUM_BYTES {
        return Err(InviteError::TooLarge);
    }
    let mut output = Vec::with_capacity(max_bytes);
    let mut buffer = 0_u16;
    let mut bits = 0_u8;
    for byte in value {
        let decoded = crockford_value(*byte).ok_or(InviteError::Invalid)?;
        buffer = (buffer << 5) | u16::from(decoded);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1_u16 << bits).saturating_sub(1);
        }
    }
    if bits > 0 && buffer != 0 {
        output.zeroize();
        return Err(InviteError::Invalid);
    }
    Ok(output)
}

fn crockford_value(byte: u8) -> Option<u8> {
    match byte.to_ascii_uppercase() {
        b'O' => Some(0),
        b'I' | b'L' => Some(1),
        value => CROCKFORD
            .iter()
            .position(|candidate| *candidate == value)
            .map(|index| index as u8),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
