use crate::{canonical_parts, Direction, TransportError, MAX_SESSION_CONTEXT_BYTES};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

const OPAQUE_ROOT_DOMAIN: &[u8] = b"ABYSSAL-TRANSPORT-V11-OPAQUE-ROOT";
const RECORD_KDF_DOMAIN: &[u8] = b"ABYSSAL-TRANSPORT-V11-RECORD-KEY";

pub fn derive_opaque_transport_root(
    session_key: &[u8],
    context: &[u8],
) -> Result<Zeroizing<[u8; 32]>, TransportError> {
    if session_key.len() < 32
        || session_key.iter().all(|byte| *byte == 0)
        || context.is_empty()
        || context.len() > MAX_SESSION_CONTEXT_BYTES
    {
        return Err(TransportError::InvalidInput);
    }
    let info = Zeroizing::new(canonical_parts(&[OPAQUE_ROOT_DOMAIN, context]));
    let mut root = Zeroizing::new([0_u8; 32]);
    Hkdf::<Sha256>::new(Some(OPAQUE_ROOT_DOMAIN), session_key)
        .expand(&info, root.as_mut())
        .map_err(|_| TransportError::InvalidInput)?;
    Ok(root)
}

pub(crate) fn derive_record_key(
    root: &[u8; 32],
    protocol: &[u8],
    direction: Direction,
    connection_context: &[u8],
) -> Result<Zeroizing<[u8; 32]>, TransportError> {
    if root == &[0; 32]
        || connection_context.is_empty()
        || connection_context.len() > MAX_SESSION_CONTEXT_BYTES
    {
        return Err(TransportError::InvalidInput);
    }
    let info = Zeroizing::new(canonical_parts(&[
        RECORD_KDF_DOMAIN,
        protocol,
        &[direction as u8],
        connection_context,
    ]));
    let mut key = Zeroizing::new([0_u8; 32]);
    Hkdf::<Sha256>::new(Some(RECORD_KDF_DOMAIN), root)
        .expand(&info, key.as_mut())
        .map_err(|_| TransportError::InvalidInput)?;
    Ok(key)
}

pub(crate) fn http_nonce(
    key: &[u8; 32],
    direction: Direction,
    handle: &[u8; 16],
) -> Result<Zeroizing<[u8; 12]>, TransportError> {
    let mut nonce = Zeroizing::new([0_u8; 12]);
    let info = canonical_parts(&[&[direction as u8], handle]);
    Hkdf::<Sha256>::new(Some(b"ABYSSAL-TRANSPORT-V11-HTTP-NONCE"), key)
        .expand(&info, nonce.as_mut())
        .map_err(|_| TransportError::InvalidInput)?;
    Ok(nonce)
}

pub(crate) fn ws_nonce(direction: Direction, counter: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[3] = direction as u8;
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}
