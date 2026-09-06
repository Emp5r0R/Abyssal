//! Address codecs only. These never resolve a name or open a transport.
use crate::InviteError;
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::VerifyingKey;
use sha3::{Digest, Sha3_256};

pub(crate) fn validate_onion_key(key: &[u8; 32]) -> Result<(), InviteError> {
    let key = VerifyingKey::from_bytes(key).map_err(|_| InviteError::UnsafeLocator)?;
    if key.is_weak() {
        return Err(InviteError::UnsafeLocator);
    }
    Ok(())
}

pub(crate) fn onion_host(key: &[u8; 32]) -> String {
    let mut bytes = [0_u8; 35];
    bytes[..32].copy_from_slice(key);
    bytes[32..34].copy_from_slice(&onion_checksum(key));
    bytes[34] = 3;
    format!("{}.onion", BASE32_NOPAD.encode(&bytes).to_ascii_lowercase())
}

pub(crate) fn parse_onion_host(host: &str) -> Result<[u8; 32], InviteError> {
    let label = host
        .strip_suffix(".onion")
        .ok_or(InviteError::UnsafeLocator)?;
    let bytes = decode_base32::<35>(label)?;
    let key: [u8; 32] = bytes[..32]
        .try_into()
        .map_err(|_| InviteError::UnsafeLocator)?;
    if bytes[34] != 3 || bytes[32..34] != onion_checksum(&key) {
        return Err(InviteError::UnsafeLocator);
    }
    validate_onion_key(&key)?;
    Ok(key)
}

pub(crate) fn i2p_host(hash: &[u8; 32]) -> String {
    format!("{}.b32.i2p", BASE32_NOPAD.encode(hash).to_ascii_lowercase())
}

pub(crate) fn parse_i2p_host(host: &str) -> Result<[u8; 32], InviteError> {
    let label = host
        .strip_suffix(".b32.i2p")
        .ok_or(InviteError::UnsafeLocator)?;
    let hash = decode_base32::<32>(label)?;
    if hash == [0; 32] {
        return Err(InviteError::UnsafeLocator);
    }
    Ok(hash)
}

fn decode_base32<const N: usize>(text: &str) -> Result<[u8; N], InviteError> {
    if text.len() != (N * 8).div_ceil(5)
        || !text
            .bytes()
            .all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c))
    {
        return Err(InviteError::UnsafeLocator);
    }
    let bytes = BASE32_NOPAD
        .decode(text.to_ascii_uppercase().as_bytes())
        .map_err(|_| InviteError::UnsafeLocator)?;
    if BASE32_NOPAD.encode(&bytes).to_ascii_lowercase() != text {
        return Err(InviteError::UnsafeLocator);
    }
    bytes.try_into().map_err(|_| InviteError::UnsafeLocator)
}

fn onion_checksum(key: &[u8; 32]) -> [u8; 2] {
    let mut digest = Sha3_256::new();
    digest.update(b".onion checksum");
    digest.update(key);
    digest.update([3]);
    let bytes = digest.finalize();
    [bytes[0], bytes[1]]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_onion_and_i2p_vectors_round_trip() {
        for host in [
            "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion",
            "sp3k262uwy4r2k3ycr5awluarykdpag6a7y33jxop4cs2lu5uz5sseqd.onion",
            "xa4r2iadxm55fbnqgwwi5mymqdcofiu3w6rpbtqn7b2dyn7mgwj64jyd.onion",
        ] {
            assert_eq!(onion_host(&parse_onion_host(host).unwrap()), host);
        }
        let host = "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p";
        assert_eq!(i2p_host(&parse_i2p_host(host).unwrap()), host);
    }

    #[test]
    fn invalid_versions_checksums_keys_and_aliases_fail() {
        let valid = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";
        for host in [
            valid.replace("pg6", "ag6"),
            valid.replace("cryd", "crya"),
            valid.to_uppercase(),
            format!("sub.{valid}"),
            "x".repeat(4096),
        ] {
            assert!(parse_onion_host(&host).is_err());
        }
        assert!(parse_onion_host(&onion_host(&[0; 32])).is_err());
        assert!(parse_i2p_host(&i2p_host(&[0; 32])).is_err());
        let canonical = i2p_host(&[7; 32]);
        let mut noncanonical = canonical.clone().into_bytes();
        noncanonical[51] = b'r';
        assert!(parse_i2p_host(std::str::from_utf8(&noncanonical).unwrap()).is_err());
        assert!(parse_i2p_host(&format!("sub.{canonical}")).is_err());
        assert!(parse_i2p_host("site.i2p").is_err());
    }
}
