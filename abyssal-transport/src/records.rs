use crate::{
    canonical_parts,
    key_schedule::{derive_record_key, http_nonce, ws_nonce},
    read_u32, read_u64, validate_aad, validate_plaintext, Direction, TransportError,
    MAX_HTTP_HANDLES, MAX_RECORD_PLAINTEXT_BYTES, MAX_WS_RECORD_PLAINTEXT_BYTES, TAG_BYTES,
    TRANSPORT_VERSION,
};
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use std::collections::HashSet;
use zeroize::{Zeroize, Zeroizing};

const HTTP_MAGIC: &[u8; 4] = b"ABR1";
const HTTP_HEADER_BYTES: usize = 4 + 1 + 1 + 32 + 16 + 4;
const WS_MAGIC: &[u8; 4] = b"ABW1";
const HTTP_BINDING_DOMAIN: &[u8] = b"ABYSSAL-TRANSPORT-V11-HTTP-SESSION";
const WS_BINDING_DOMAIN: &[u8] = b"ABYSSAL-TRANSPORT-V11-WS-CONNECTION";
#[derive(Debug, Eq, PartialEq)]
struct DecodedHttpRecord<'a> {
    header: &'a [u8],
    direction: Direction,
    session_id: [u8; 32],
    handle: [u8; 16],
    ciphertext: &'a [u8],
}
type DecodedWsRecord<'a> = (&'a [u8], Direction, u64, &'a [u8]);

/// The bounded, unauthenticated routing fields carried by an HTTP record.
///
/// The session ID and handle are authenticated when the record is opened with
/// the matching typed binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpRecordHeader {
    pub direction: Direction,
    pub session_id: [u8; 32],
    pub handle: [u8; 16],
    pub ciphertext_len: usize,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ConnectionNonce([u8; 32]);

impl Drop for ConnectionNonce {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ConnectionNonce {
    pub fn generate() -> Result<Self, TransportError> {
        let mut value = [0_u8; 32];
        getrandom::fill(&mut value).map_err(|_| TransportError::InvalidInput)?;
        Self::new(value)
    }

    pub fn new(value: [u8; 32]) -> Result<Self, TransportError> {
        if value == [0; 32] {
            return Err(TransportError::InvalidInput);
        }
        Ok(Self(value))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct HttpSessionBinding {
    node_public_key: [u8; 32],
    session_id: [u8; 32],
}

impl Drop for HttpSessionBinding {
    fn drop(&mut self) {
        self.node_public_key.zeroize();
        self.session_id.zeroize();
    }
}

impl HttpSessionBinding {
    pub fn new(node_public_key: [u8; 32], session_id: [u8; 32]) -> Result<Self, TransportError> {
        if node_public_key == [0; 32] || session_id == [0; 32] {
            return Err(TransportError::InvalidInput);
        }
        Ok(Self {
            node_public_key,
            session_id,
        })
    }

    fn key_context(&self) -> Vec<u8> {
        canonical_parts(&[HTTP_BINDING_DOMAIN, &self.node_public_key, &self.session_id])
    }

    pub fn into_client(
        self,
        transport_root: &[u8; 32],
    ) -> Result<HttpClientRecords, TransportError> {
        let session_id = self.session_id;
        let context = self.key_context();
        Ok(HttpClientRecords {
            sealer: HttpSealer::new(
                transport_root,
                Direction::ClientToServer,
                &context,
                session_id,
            )?,
            opener: HttpOpener::new(
                transport_root,
                Direction::ServerToClient,
                &context,
                session_id,
            )?,
        })
    }

    pub fn into_server(
        self,
        transport_root: &[u8; 32],
    ) -> Result<HttpServerRecords, TransportError> {
        let session_id = self.session_id;
        let context = self.key_context();
        Ok(HttpServerRecords {
            sealer: HttpSealer::new(
                transport_root,
                Direction::ServerToClient,
                &context,
                session_id,
            )?,
            opener: HttpOpener::new(
                transport_root,
                Direction::ClientToServer,
                &context,
                session_id,
            )?,
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct WsConnectionBinding {
    session_id: [u8; 32],
    client_nonce: ConnectionNonce,
    server_nonce: ConnectionNonce,
}

impl Drop for WsConnectionBinding {
    fn drop(&mut self) {
        self.session_id.zeroize();
    }
}

impl WsConnectionBinding {
    pub fn new(
        session_id: [u8; 32],
        client_nonce: ConnectionNonce,
        server_nonce: ConnectionNonce,
    ) -> Result<Self, TransportError> {
        if session_id == [0; 32] || client_nonce == server_nonce {
            return Err(TransportError::InvalidInput);
        }
        Ok(Self {
            session_id,
            client_nonce,
            server_nonce,
        })
    }

    fn key_context(&self) -> Vec<u8> {
        canonical_parts(&[
            WS_BINDING_DOMAIN,
            &self.session_id,
            &self.client_nonce.0,
            &self.server_nonce.0,
        ])
    }

    pub fn into_client(self, transport_root: &[u8; 32]) -> Result<WsClientRecords, TransportError> {
        let context = self.key_context();
        Ok(WsClientRecords {
            sealer: WsSealer::new(transport_root, Direction::ClientToServer, &context)?,
            opener: WsOpener::new(transport_root, Direction::ServerToClient, &context)?,
        })
    }

    pub fn into_server(self, transport_root: &[u8; 32]) -> Result<WsServerRecords, TransportError> {
        let context = self.key_context();
        Ok(WsServerRecords {
            sealer: WsSealer::new(transport_root, Direction::ServerToClient, &context)?,
            opener: WsOpener::new(transport_root, Direction::ClientToServer, &context)?,
        })
    }
}

pub struct HttpSealer {
    key: Zeroizing<[u8; 32]>,
    direction: Direction,
    session_id: [u8; 32],
    used_handles: HashSet<[u8; 16]>,
}

impl Drop for HttpSealer {
    fn drop(&mut self) {
        self.session_id.zeroize();
        for handle in self.used_handles.drain() {
            let mut handle = handle;
            handle.zeroize();
        }
    }
}

pub struct HttpOpener {
    key: Zeroizing<[u8; 32]>,
    direction: Direction,
    session_id: [u8; 32],
    used_handles: HashSet<[u8; 16]>,
}

impl Drop for HttpOpener {
    fn drop(&mut self) {
        self.session_id.zeroize();
        for handle in self.used_handles.drain() {
            let mut handle = handle;
            handle.zeroize();
        }
    }
}

impl HttpSealer {
    fn new(
        transport_root: &[u8; 32],
        direction: Direction,
        session_context: &[u8],
        session_id: [u8; 32],
    ) -> Result<Self, TransportError> {
        Ok(Self {
            key: derive_record_key(transport_root, b"HTTP", direction, session_context)?,
            direction,
            session_id,
            used_handles: HashSet::new(),
        })
    }

    pub fn seal(
        &mut self,
        request_handle: [u8; 16],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        validate_record_input(request_handle, aad, plaintext)?;
        ensure_handle_available(&self.used_handles, request_handle)?;
        let header = http_header(
            self.direction,
            self.session_id,
            request_handle,
            plaintext.len() + TAG_BYTES,
        )?;
        let bound_aad = Zeroizing::new(canonical_parts(&[&header, aad]));
        let nonce = http_nonce(&self.key, self.direction, &request_handle)?;
        let ciphertext = ChaCha20Poly1305::new(self.key.as_ref().into())
            .encrypt(
                Nonce::from_slice(nonce.as_ref()),
                Payload {
                    msg: plaintext,
                    aad: &bound_aad,
                },
            )
            .map_err(|_| TransportError::AuthenticationFailed)?;
        insert_handle(&mut self.used_handles, request_handle)?;
        let mut record = header;
        record.extend_from_slice(&ciphertext);
        Ok(record)
    }
}

impl HttpOpener {
    fn new(
        transport_root: &[u8; 32],
        direction: Direction,
        session_context: &[u8],
        session_id: [u8; 32],
    ) -> Result<Self, TransportError> {
        Ok(Self {
            key: derive_record_key(transport_root, b"HTTP", direction, session_context)?,
            direction,
            session_id,
            used_handles: HashSet::new(),
        })
    }

    pub fn open(
        &mut self,
        expected_handle: [u8; 16],
        aad: &[u8],
        record: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        validate_aad(aad)?;
        let decoded = decode_http(record)?;
        if decoded.direction != self.direction
            || decoded.session_id != self.session_id
            || decoded.handle != expected_handle
            || decoded.handle == [0; 16]
        {
            return Err(TransportError::AuthenticationFailed);
        }
        if self.used_handles.contains(&decoded.handle) {
            return Err(TransportError::Replay);
        }
        let bound_aad = Zeroizing::new(canonical_parts(&[decoded.header, aad]));
        let nonce = http_nonce(&self.key, self.direction, &decoded.handle)?;
        let plaintext = ChaCha20Poly1305::new(self.key.as_ref().into())
            .decrypt(
                Nonce::from_slice(nonce.as_ref()),
                Payload {
                    msg: decoded.ciphertext,
                    aad: &bound_aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| TransportError::AuthenticationFailed)?;
        validate_plaintext(&plaintext, MAX_RECORD_PLAINTEXT_BYTES)?;
        insert_handle(&mut self.used_handles, decoded.handle)?;
        Ok(plaintext)
    }
}

pub struct WsSealer {
    key: Zeroizing<[u8; 32]>,
    direction: Direction,
    next_counter: u64,
}

pub struct WsOpener {
    key: Zeroizing<[u8; 32]>,
    direction: Direction,
    next_counter: u64,
}

pub struct WsClientRecords {
    pub sealer: WsSealer,
    pub opener: WsOpener,
}

pub struct WsServerRecords {
    pub sealer: WsSealer,
    pub opener: WsOpener,
}

pub struct HttpClientRecords {
    pub sealer: HttpSealer,
    pub opener: HttpOpener,
}

pub struct HttpServerRecords {
    pub sealer: HttpSealer,
    pub opener: HttpOpener,
}

impl WsSealer {
    fn new(
        transport_root: &[u8; 32],
        direction: Direction,
        connection_context: &[u8],
    ) -> Result<Self, TransportError> {
        Ok(Self {
            key: derive_record_key(transport_root, b"WS", direction, connection_context)?,
            direction,
            next_counter: 0,
        })
    }

    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TransportError> {
        validate_aad(aad)?;
        validate_plaintext(plaintext, MAX_WS_RECORD_PLAINTEXT_BYTES)?;
        if self.next_counter == u64::MAX {
            return Err(TransportError::CounterExhausted);
        }
        let counter = self.next_counter;
        let header = ws_header(self.direction, counter, plaintext.len() + TAG_BYTES)?;
        let bound_aad = Zeroizing::new(canonical_parts(&[&header, aad]));
        let nonce = ws_nonce(self.direction, counter);
        let ciphertext = ChaCha20Poly1305::new(self.key.as_ref().into())
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &bound_aad,
                },
            )
            .map_err(|_| TransportError::AuthenticationFailed)?;
        self.next_counter = self.next_counter.saturating_add(1);
        let mut record = header;
        record.extend_from_slice(&ciphertext);
        Ok(record)
    }
}

impl WsOpener {
    fn new(
        transport_root: &[u8; 32],
        direction: Direction,
        connection_context: &[u8],
    ) -> Result<Self, TransportError> {
        Ok(Self {
            key: derive_record_key(transport_root, b"WS", direction, connection_context)?,
            direction,
            next_counter: 0,
        })
    }

    pub fn open(
        &mut self,
        aad: &[u8],
        record: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        validate_aad(aad)?;
        if self.next_counter == u64::MAX {
            return Err(TransportError::CounterExhausted);
        }
        let (header, direction, counter, ciphertext) = decode_ws(record)?;
        if direction != self.direction {
            return Err(TransportError::AuthenticationFailed);
        }
        if counter < self.next_counter {
            return Err(TransportError::Replay);
        }
        if counter > self.next_counter {
            return Err(TransportError::CounterGap);
        }
        let bound_aad = Zeroizing::new(canonical_parts(&[header, aad]));
        let nonce = ws_nonce(self.direction, counter);
        let plaintext = ChaCha20Poly1305::new(self.key.as_ref().into())
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: &bound_aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| TransportError::AuthenticationFailed)?;
        validate_plaintext(&plaintext, MAX_WS_RECORD_PLAINTEXT_BYTES)?;
        self.next_counter = self.next_counter.saturating_add(1);
        Ok(plaintext)
    }
}

fn http_header(
    direction: Direction,
    session_id: [u8; 32],
    handle: [u8; 16],
    ciphertext_len: usize,
) -> Result<Vec<u8>, TransportError> {
    if session_id == [0; 32] {
        return Err(TransportError::InvalidInput);
    }
    let length = u32::try_from(ciphertext_len).map_err(|_| TransportError::TooLarge)?;
    let mut header = Vec::with_capacity(HTTP_HEADER_BYTES);
    header.extend_from_slice(HTTP_MAGIC);
    header.push(TRANSPORT_VERSION);
    header.push(direction as u8);
    header.extend_from_slice(&session_id);
    header.extend_from_slice(&handle);
    header.extend_from_slice(&length.to_be_bytes());
    Ok(header)
}

fn decode_http(record: &[u8]) -> Result<DecodedHttpRecord<'_>, TransportError> {
    if record.len() < HTTP_HEADER_BYTES + TAG_BYTES + 1
        || record.len() > HTTP_HEADER_BYTES + MAX_RECORD_PLAINTEXT_BYTES + TAG_BYTES
    {
        return Err(TransportError::TooLarge);
    }
    if &record[..4] != HTTP_MAGIC || record[4] != TRANSPORT_VERSION {
        return Err(TransportError::NonCanonical);
    }
    let direction = Direction::from_byte(record[5])?;
    let session_id = record[6..38]
        .try_into()
        .map_err(|_| TransportError::NonCanonical)?;
    let handle = record[38..54]
        .try_into()
        .map_err(|_| TransportError::NonCanonical)?;
    let length = read_u32(&record[54..58])?;
    if length != record.len() - HTTP_HEADER_BYTES {
        return Err(TransportError::NonCanonical);
    }
    Ok(DecodedHttpRecord {
        header: &record[..HTTP_HEADER_BYTES],
        direction,
        session_id,
        handle,
        ciphertext: &record[HTTP_HEADER_BYTES..],
    })
}

/// Inspect only bounded routing fields from an untrusted HTTP record.
pub fn inspect_http_record(record: &[u8]) -> Result<HttpRecordHeader, TransportError> {
    let decoded = decode_http(record)?;
    if decoded.session_id == [0; 32] || decoded.handle == [0; 16] {
        return Err(TransportError::NonCanonical);
    }
    Ok(HttpRecordHeader {
        direction: decoded.direction,
        session_id: decoded.session_id,
        handle: decoded.handle,
        ciphertext_len: decoded.ciphertext.len(),
    })
}

fn ws_header(
    direction: Direction,
    counter: u64,
    ciphertext_len: usize,
) -> Result<Vec<u8>, TransportError> {
    let length = u32::try_from(ciphertext_len).map_err(|_| TransportError::TooLarge)?;
    let mut header = Vec::with_capacity(18);
    header.extend_from_slice(WS_MAGIC);
    header.push(TRANSPORT_VERSION);
    header.push(direction as u8);
    header.extend_from_slice(&counter.to_be_bytes());
    header.extend_from_slice(&length.to_be_bytes());
    Ok(header)
}

fn decode_ws(record: &[u8]) -> Result<DecodedWsRecord<'_>, TransportError> {
    const HEADER: usize = 18;
    if record.len() < HEADER + TAG_BYTES + 1
        || record.len() > HEADER + MAX_WS_RECORD_PLAINTEXT_BYTES + TAG_BYTES
    {
        return Err(TransportError::TooLarge);
    }
    if &record[..4] != WS_MAGIC || record[4] != TRANSPORT_VERSION {
        return Err(TransportError::NonCanonical);
    }
    let direction = Direction::from_byte(record[5])?;
    let counter = read_u64(&record[6..14])?;
    let length = read_u32(&record[14..18])?;
    if length != record.len() - HEADER {
        return Err(TransportError::NonCanonical);
    }
    Ok((&record[..HEADER], direction, counter, &record[HEADER..]))
}

fn validate_record_input(
    handle: [u8; 16],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(), TransportError> {
    if handle == [0; 16] {
        return Err(TransportError::InvalidInput);
    }
    validate_aad(aad)?;
    validate_plaintext(plaintext, MAX_RECORD_PLAINTEXT_BYTES)
}

fn insert_handle(handles: &mut HashSet<[u8; 16]>, handle: [u8; 16]) -> Result<(), TransportError> {
    ensure_handle_available(handles, handle)?;
    handles.insert(handle);
    Ok(())
}

fn ensure_handle_available(
    handles: &HashSet<[u8; 16]>,
    handle: [u8; 16],
) -> Result<(), TransportError> {
    if handles.contains(&handle) {
        return Err(TransportError::Replay);
    }
    if handles.len() >= MAX_HTTP_HANDLES {
        return Err(TransportError::CapacityExhausted);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn decode_http_for_test(record: &[u8]) -> Result<(), TransportError> {
    decode_http(record).map(|_| ())
}

#[cfg(test)]
pub(crate) fn decode_ws_for_test(record: &[u8]) -> Result<DecodedWsRecord<'_>, TransportError> {
    decode_ws(record)
}

#[cfg(test)]
impl WsSealer {
    pub(crate) fn exhaust_for_test(&mut self) {
        self.next_counter = u64::MAX;
    }
}

#[cfg(test)]
impl WsOpener {
    pub(crate) fn exhaust_for_test(&mut self) {
        self.next_counter = u64::MAX;
    }
}
