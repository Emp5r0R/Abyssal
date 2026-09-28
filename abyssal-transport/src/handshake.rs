//! Authenticated protocol-v11 WebSocket handshake.
//!
//! The HTTP upgrade carries only the fixed protocol marker.  Authentication
//! starts with a fixed-size binary ClientHello whose routing fields are an
//! opaque transport-session identifier and a fresh client nonce.  The
//! one-time control ticket is encrypted under the OPAQUE-derived transport
//! root and is never present in a header, URL, or unauthenticated frame.

use crate::{canonical_parts, TransportError, TAG_BYTES, TRANSPORT_VERSION};
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

pub const WS_HELLO_MAGIC: &[u8; 4] = b"ABW2";
pub const WS_HELLO_VERSION: u8 = TRANSPORT_VERSION;
pub const MAX_WS_TICKET_BYTES: usize = 43;

const WS_HELLO_HEADER_BYTES: usize = 4 + 1 + 1 + 32 + 32;
const WS_HELLO_PLAINTEXT_BYTES: usize = 64;
const WS_HELLO_CIPHERTEXT_BYTES: usize = WS_HELLO_PLAINTEXT_BYTES + TAG_BYTES;
const WS_CLIENT_KIND: u8 = 1;
const WS_SERVER_KIND: u8 = 2;
const CLIENT_TICKET_DOMAIN: &[u8] = b"ABYSSAL-TRANSPORT-V11-WS-CLIENT-HELLO";
const SERVER_HELLO_DOMAIN: &[u8] = b"ABYSSAL-TRANSPORT-V11-WS-SERVER-HELLO";

pub const WS_CLIENT_HELLO_BYTES: usize = WS_HELLO_HEADER_BYTES + WS_HELLO_CIPHERTEXT_BYTES;
pub const WS_SERVER_HELLO_BYTES: usize = WS_HELLO_HEADER_BYTES + WS_HELLO_CIPHERTEXT_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WsClientHelloHeader {
    pub session_id: [u8; 32],
    pub client_nonce: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WsServerHelloHeader {
    pub session_id: [u8; 32],
    pub client_nonce: [u8; 32],
    pub server_nonce: [u8; 32],
}

#[derive(Debug, Eq, PartialEq)]
pub struct OpenedWsClientHello {
    pub header: WsClientHelloHeader,
    pub ticket: Zeroizing<Vec<u8>>,
}

impl Drop for OpenedWsClientHello {
    fn drop(&mut self) {
        self.header.session_id.zeroize();
        self.header.client_nonce.zeroize();
    }
}

/// Encrypt one control-issued ticket into a fixed-size ClientHello.
pub fn seal_ws_client_hello(
    transport_root: &[u8; 32],
    node_public_key: [u8; 32],
    session_id: [u8; 32],
    client_nonce: [u8; 32],
    ticket: &[u8],
) -> Result<Zeroizing<Vec<u8>>, TransportError> {
    if node_public_key == [0; 32] {
        return Err(TransportError::InvalidInput);
    }
    validate_material(transport_root, &session_id, &client_nonce)?;
    if ticket.is_empty() || ticket.len() > MAX_WS_TICKET_BYTES {
        return Err(if ticket.len() > MAX_WS_TICKET_BYTES {
            TransportError::TooLarge
        } else {
            TransportError::InvalidInput
        });
    }
    let header = client_header(session_id, client_nonce);
    let context = client_context(node_public_key, session_id, client_nonce);
    let (key, nonce) = derive_handshake_material(transport_root, CLIENT_TICKET_DOMAIN, &context)?;
    let mut plaintext = Zeroizing::new([0_u8; WS_HELLO_PLAINTEXT_BYTES]);
    plaintext[..2].copy_from_slice(&(ticket.len() as u16).to_be_bytes());
    plaintext[2..2 + ticket.len()].copy_from_slice(ticket);
    getrandom::fill(&mut plaintext[2 + ticket.len()..])
        .map_err(|_| TransportError::InvalidInput)?;
    let ciphertext = ChaCha20Poly1305::new(key.as_ref().into())
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_ref(),
                aad: &header,
            },
        )
        .map_err(|_| TransportError::AuthenticationFailed)?;
    debug_assert_eq!(ciphertext.len(), WS_HELLO_CIPHERTEXT_BYTES);
    let mut output = Zeroizing::new(header);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Inspect only the unauthenticated, bounded ClientHello routing fields.
pub fn inspect_ws_client_hello(input: &[u8]) -> Result<WsClientHelloHeader, TransportError> {
    let (header, _) = decode_hello(input, WS_CLIENT_KIND)?;
    Ok(WsClientHelloHeader {
        session_id: header.session_id,
        client_nonce: header.client_nonce,
    })
}

/// Authenticate and decrypt a ClientHello using the transport session root.
pub fn open_ws_client_hello(
    transport_root: &[u8; 32],
    node_public_key: [u8; 32],
    input: &[u8],
) -> Result<OpenedWsClientHello, TransportError> {
    if node_public_key == [0; 32] {
        return Err(TransportError::InvalidInput);
    }
    let (header, ciphertext) = decode_hello(input, WS_CLIENT_KIND)?;
    validate_material(transport_root, &header.session_id, &header.client_nonce)?;
    let context = client_context(node_public_key, header.session_id, header.client_nonce);
    let (key, nonce) = derive_handshake_material(transport_root, CLIENT_TICKET_DOMAIN, &context)?;
    let plaintext = ChaCha20Poly1305::new(key.as_ref().into())
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &input[..WS_HELLO_HEADER_BYTES],
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| TransportError::AuthenticationFailed)?;
    let ticket_len = usize::from(u16::from_be_bytes(
        plaintext[..2]
            .try_into()
            .map_err(|_| TransportError::NonCanonical)?,
    ));
    if ticket_len == 0 || ticket_len > MAX_WS_TICKET_BYTES {
        return Err(TransportError::NonCanonical);
    }
    // The random tail is deliberately not interpreted.  Keeping it in the
    // authenticated plaintext prevents ticket length from becoming a wire
    // oracle while still allowing future key rotations without ambiguity.
    Ok(OpenedWsClientHello {
        header: WsClientHelloHeader {
            session_id: header.session_id,
            client_nonce: header.client_nonce,
        },
        ticket: Zeroizing::new(plaintext[2..2 + ticket_len].to_vec()),
    })
}

/// Authenticate a freshly generated server nonce in a fixed-size ServerHello.
pub fn seal_ws_server_hello(
    transport_root: &[u8; 32],
    node_public_key: [u8; 32],
    session_id: [u8; 32],
    client_nonce: [u8; 32],
    server_nonce: [u8; 32],
) -> Result<Zeroizing<Vec<u8>>, TransportError> {
    if node_public_key == [0; 32] {
        return Err(TransportError::InvalidInput);
    }
    validate_material(transport_root, &session_id, &client_nonce)?;
    if server_nonce == [0; 32] {
        return Err(TransportError::InvalidInput);
    }
    let header = server_header(session_id, client_nonce);
    let context = server_context(node_public_key, session_id, client_nonce);
    let (key, nonce) = derive_handshake_material(transport_root, SERVER_HELLO_DOMAIN, &context)?;
    let mut plaintext = Zeroizing::new([0_u8; WS_HELLO_PLAINTEXT_BYTES]);
    plaintext[..32].copy_from_slice(&server_nonce);
    getrandom::fill(&mut plaintext[32..]).map_err(|_| TransportError::InvalidInput)?;
    let ciphertext = ChaCha20Poly1305::new(key.as_ref().into())
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_ref(),
                aad: &header,
            },
        )
        .map_err(|_| TransportError::AuthenticationFailed)?;
    let mut output = Zeroizing::new(header);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Inspect only bounded routing fields from a ServerHello.
pub fn inspect_ws_server_hello(input: &[u8]) -> Result<WsServerHelloHeader, TransportError> {
    let (header, _) = decode_hello(input, WS_SERVER_KIND)?;
    Ok(WsServerHelloHeader {
        session_id: header.session_id,
        client_nonce: header.client_nonce,
        server_nonce: [0; 32],
    })
}

/// Authenticate and open a ServerHello, returning the server nonce.
pub fn open_ws_server_hello(
    transport_root: &[u8; 32],
    node_public_key: [u8; 32],
    expected_session_id: [u8; 32],
    expected_client_nonce: [u8; 32],
    input: &[u8],
) -> Result<ConnectionNonce, TransportError> {
    if node_public_key == [0; 32] {
        return Err(TransportError::InvalidInput);
    }
    let (header, ciphertext) = decode_hello(input, WS_SERVER_KIND)?;
    if header.session_id != expected_session_id || header.client_nonce != expected_client_nonce {
        return Err(TransportError::AuthenticationFailed);
    }
    validate_material(transport_root, &header.session_id, &header.client_nonce)?;
    let context = server_context(node_public_key, header.session_id, header.client_nonce);
    let (key, nonce) = derive_handshake_material(transport_root, SERVER_HELLO_DOMAIN, &context)?;
    let plaintext = ChaCha20Poly1305::new(key.as_ref().into())
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &input[..WS_HELLO_HEADER_BYTES],
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| TransportError::AuthenticationFailed)?;
    let server_nonce: [u8; 32] = plaintext[..32]
        .try_into()
        .map_err(|_| TransportError::NonCanonical)?;
    ConnectionNonce::new(server_nonce)
}

fn validate_material(
    root: &[u8; 32],
    session_id: &[u8; 32],
    client_nonce: &[u8; 32],
) -> Result<(), TransportError> {
    if root == &[0; 32] || session_id == &[0; 32] || client_nonce == &[0; 32] {
        return Err(TransportError::InvalidInput);
    }
    Ok(())
}

fn client_context(
    node_public_key: [u8; 32],
    session_id: [u8; 32],
    client_nonce: [u8; 32],
) -> Vec<u8> {
    canonical_parts(&[
        CLIENT_TICKET_DOMAIN,
        &node_public_key,
        &session_id,
        &client_nonce,
    ])
}

fn server_context(
    node_public_key: [u8; 32],
    session_id: [u8; 32],
    client_nonce: [u8; 32],
) -> Vec<u8> {
    canonical_parts(&[
        SERVER_HELLO_DOMAIN,
        &node_public_key,
        &session_id,
        &client_nonce,
    ])
}

fn derive_handshake_material(
    root: &[u8; 32],
    domain: &[u8],
    context: &[u8],
) -> Result<(Zeroizing<[u8; 32]>, [u8; 12]), TransportError> {
    let info = canonical_parts(&[domain, context]);
    let mut key = Zeroizing::new([0_u8; 32]);
    Hkdf::<Sha256>::new(Some(domain), root)
        .expand(&info, key.as_mut())
        .map_err(|_| TransportError::InvalidInput)?;
    let nonce_info = canonical_parts(&[b"nonce", &info]);
    let mut nonce = [0_u8; 12];
    Hkdf::<Sha256>::new(Some(domain), key.as_ref())
        .expand(&nonce_info, &mut nonce)
        .map_err(|_| TransportError::InvalidInput)?;
    Ok((key, nonce))
}

fn client_header(session_id: [u8; 32], client_nonce: [u8; 32]) -> Vec<u8> {
    let mut header = Vec::with_capacity(WS_HELLO_HEADER_BYTES);
    header.extend_from_slice(WS_HELLO_MAGIC);
    header.push(WS_HELLO_VERSION);
    header.push(WS_CLIENT_KIND);
    header.extend_from_slice(&session_id);
    header.extend_from_slice(&client_nonce);
    header
}

fn server_header(session_id: [u8; 32], client_nonce: [u8; 32]) -> Vec<u8> {
    let mut header = Vec::with_capacity(WS_HELLO_HEADER_BYTES);
    header.extend_from_slice(WS_HELLO_MAGIC);
    header.push(WS_HELLO_VERSION);
    header.push(WS_SERVER_KIND);
    header.extend_from_slice(&session_id);
    header.extend_from_slice(&client_nonce);
    header
}

struct DecodedHello {
    session_id: [u8; 32],
    client_nonce: [u8; 32],
}

fn decode_hello(input: &[u8], expected_kind: u8) -> Result<(DecodedHello, &[u8]), TransportError> {
    if input.len() != WS_HELLO_HEADER_BYTES + WS_HELLO_CIPHERTEXT_BYTES {
        return Err(if input.len() > WS_CLIENT_HELLO_BYTES {
            TransportError::TooLarge
        } else {
            TransportError::NonCanonical
        });
    }
    if input[..4] != *WS_HELLO_MAGIC || input[4] != WS_HELLO_VERSION || input[5] != expected_kind {
        return Err(TransportError::NonCanonical);
    }
    let session_id = input[6..38]
        .try_into()
        .map_err(|_| TransportError::NonCanonical)?;
    let client_nonce = input[38..70]
        .try_into()
        .map_err(|_| TransportError::NonCanonical)?;
    if session_id == [0; 32] || client_nonce == [0; 32] {
        return Err(TransportError::NonCanonical);
    }
    let ciphertext = input
        .get(WS_HELLO_HEADER_BYTES..)
        .ok_or(TransportError::NonCanonical)?;
    Ok((
        DecodedHello {
            session_id,
            client_nonce,
        },
        ciphertext,
    ))
}

use crate::ConnectionNonce;

#[cfg(test)]
mod tests {
    use super::*;

    fn material() -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        ([7; 32], [8; 32], [9; 32], [10; 32])
    }

    #[test]
    fn hello_is_fixed_and_ticket_is_not_visible() {
        let (root, node, session, nonce) = material();
        let ticket = b"ticket-value-that-must-not-cross-the-wire";
        let hello = seal_ws_client_hello(&root, node, session, nonce, ticket).unwrap();
        assert_eq!(hello.len(), WS_CLIENT_HELLO_BYTES);
        assert!(!hello.windows(ticket.len()).any(|window| window == ticket));
        assert_eq!(inspect_ws_client_hello(&hello).unwrap().session_id, session);
        let opened = open_ws_client_hello(&root, node, &hello).unwrap();
        assert_eq!(opened.ticket.as_slice(), ticket);
    }

    #[test]
    fn hello_authentication_binds_context_and_rejects_replay_like_tamper() {
        let (root, node, session, nonce) = material();
        let hello = seal_ws_client_hello(&root, node, session, nonce, b"ticket").unwrap();
        let mut forged = hello.to_vec();
        *forged.last_mut().unwrap() ^= 1;
        assert_eq!(
            open_ws_client_hello(&root, node, &forged).unwrap_err(),
            TransportError::AuthenticationFailed
        );
        assert!(open_ws_client_hello(&[6; 32], node, &hello).is_err());
        assert!(open_ws_client_hello(&root, [5; 32], &hello).is_err());
        assert!(open_ws_client_hello(&root, node, &hello[..hello.len() - 1]).is_err());
    }

    #[test]
    fn server_hello_proves_root_and_returns_fresh_nonce() {
        let (root, node, session, client_nonce) = material();
        let server_nonce = [11; 32];
        let hello = seal_ws_server_hello(&root, node, session, client_nonce, server_nonce).unwrap();
        assert_eq!(hello.len(), WS_SERVER_HELLO_BYTES);
        let opened = open_ws_server_hello(&root, node, session, client_nonce, &hello).unwrap();
        assert_eq!(opened.to_bytes(), server_nonce);
        assert!(open_ws_server_hello(&[6; 32], node, session, client_nonce, &hello).is_err());
        assert!(open_ws_server_hello(&root, node, [5; 32], client_nonce, &hello).is_err());
    }

    #[test]
    fn hello_rejects_zero_node_identity_material() {
        let (root, node, session, client_nonce) = material();
        assert_eq!(
            seal_ws_client_hello(&root, [0; 32], session, client_nonce, b"ticket").unwrap_err(),
            TransportError::InvalidInput
        );
        let hello = seal_ws_client_hello(&root, node, session, client_nonce, b"ticket").unwrap();
        assert_eq!(
            open_ws_client_hello(&root, [0; 32], &hello).unwrap_err(),
            TransportError::InvalidInput
        );
        assert_eq!(
            seal_ws_server_hello(&root, [0; 32], session, client_nonce, [11; 32]).unwrap_err(),
            TransportError::InvalidInput
        );
    }

    #[test]
    fn hello_boundaries_and_wire_shape_fail_closed() {
        let (root, node, session, client_nonce) = material();
        assert_eq!(
            seal_ws_client_hello(&root, node, session, client_nonce, &[]).unwrap_err(),
            TransportError::InvalidInput
        );
        assert_eq!(
            seal_ws_client_hello(
                &root,
                node,
                session,
                client_nonce,
                &[0; MAX_WS_TICKET_BYTES + 1],
            )
            .unwrap_err(),
            TransportError::TooLarge
        );
        let hello = seal_ws_client_hello(
            &root,
            node,
            session,
            client_nonce,
            &[7; MAX_WS_TICKET_BYTES],
        )
        .unwrap();
        assert_eq!(hello.len(), WS_CLIENT_HELLO_BYTES);

        let mut trailing = hello.to_vec();
        trailing.push(0);
        assert!(inspect_ws_client_hello(&trailing).is_err());
        assert!(open_ws_client_hello(&root, node, &trailing).is_err());
        for length in 0..hello.len() {
            assert!(inspect_ws_client_hello(&hello[..length]).is_err());
            assert!(open_ws_client_hello(&root, node, &hello[..length]).is_err());
        }

        let mut wrong_marker = hello.to_vec();
        wrong_marker[4] ^= 1;
        assert_eq!(
            inspect_ws_client_hello(&wrong_marker).unwrap_err(),
            TransportError::NonCanonical
        );
        let mut zero_session = hello.to_vec();
        zero_session[6..38].fill(0);
        assert_eq!(
            inspect_ws_client_hello(&zero_session).unwrap_err(),
            TransportError::NonCanonical
        );
        let mut zero_nonce = hello.to_vec();
        zero_nonce[38..70].fill(0);
        assert_eq!(
            inspect_ws_client_hello(&zero_nonce).unwrap_err(),
            TransportError::NonCanonical
        );

        let server_nonce = [11; 32];
        let server =
            seal_ws_server_hello(&root, node, session, client_nonce, server_nonce).unwrap();
        assert_eq!(
            inspect_ws_server_hello(&server).unwrap().session_id,
            session
        );
        assert!(open_ws_server_hello(&root, node, session, [12; 32], &server).is_err());
        assert!(open_ws_server_hello(&root, node, [12; 32], client_nonce, &server).is_err());
        let mut server_trailing = server.to_vec();
        server_trailing.push(0);
        assert!(
            open_ws_server_hello(&root, node, session, client_nonce, &server_trailing).is_err()
        );
        assert_eq!(
            seal_ws_server_hello(&root, node, session, client_nonce, [0; 32]).unwrap_err(),
            TransportError::InvalidInput
        );
    }
}
