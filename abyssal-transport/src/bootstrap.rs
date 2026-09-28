use crate::{
    canonical_parts, validate_plaintext, TransportError, MAX_BOOTSTRAP_PLAINTEXT_BYTES,
    MAX_BOOTSTRAP_REPLAY_TTL_MS, MAX_BOOTSTRAP_REQUEST_IDS, MAX_OPERATION_BYTES,
    MIN_BOOTSTRAP_REPLAY_TTL_MS, TAG_BYTES, TRANSPORT_VERSION,
};
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use hpke::{
    aead::ChaCha20Poly1305 as HpkeChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256,
    setup_receiver, setup_sender, Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
};
use std::{collections::HashMap, fmt};
use zeroize::Zeroizing;

const BOOTSTRAP_MAGIC: &[u8; 4] = b"ABH1";
const BOOTSTRAP_HEADER_BYTES: usize = 4 + 1 + 32 + 32 + 4;
const BOOTSTRAP_DOMAIN: &[u8] = b"ABYSSAL-TRANSPORT-V11-BOOTSTRAP";
const RESPONSE_EXPORT_DOMAIN: &[u8] = b"ABYSSAL-TRANSPORT-V11-BOOTSTRAP-RESPONSE";

type KemPublicKey = <X25519HkdfSha256 as KemTrait>::PublicKey;
type KemPrivateKey = <X25519HkdfSha256 as KemTrait>::PrivateKey;
type EncappedKey = <X25519HkdfSha256 as KemTrait>::EncappedKey;
type ResponseMaterial = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 12]>);

pub struct BootstrapPrivateKey(Zeroizing<[u8; 32]>);

impl BootstrapPrivateKey {
    pub fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> Result<Self, TransportError> {
        if *bytes == [0; 32] {
            return Err(TransportError::InvalidInput);
        }
        KemPrivateKey::from_bytes(bytes.as_ref()).map_err(|_| TransportError::InvalidInput)?;
        Ok(Self(bytes))
    }

    fn parsed(&self) -> Result<KemPrivateKey, TransportError> {
        KemPrivateKey::from_bytes(self.0.as_ref()).map_err(|_| TransportError::InvalidInput)
    }
}

impl fmt::Debug for BootstrapPrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BootstrapPrivateKey(<redacted>)")
    }
}

pub struct BootstrapKeyPair {
    private_key: BootstrapPrivateKey,
    pub public_key: [u8; 32],
}

impl BootstrapKeyPair {
    pub fn private_key(&self) -> &BootstrapPrivateKey {
        &self.private_key
    }
}

impl fmt::Debug for BootstrapKeyPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootstrapKeyPair")
            .field("private_key", &"<redacted>")
            .field("public_key", &self.public_key)
            .finish()
    }
}

pub fn generate_bootstrap_keypair() -> BootstrapKeyPair {
    let (private_key, public_key) = X25519HkdfSha256::gen_keypair();
    let private_bytes = Zeroizing::new(exact_serialized(private_key.to_bytes().as_slice()));
    BootstrapKeyPair {
        private_key: BootstrapPrivateKey(private_bytes),
        public_key: exact_serialized(public_key.to_bytes().as_slice()),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapContext {
    pub node_signing_public_key: [u8; 32],
    pub bootstrap_hpke_public_key: [u8; 32],
    pub operation: Vec<u8>,
    pub request_id: [u8; 32],
}

/// The bounded, unauthenticated routing fields carried by a bootstrap record.
///
/// Callers must still authenticate a record with [`BootstrapReplayGuard::open_request`]
/// before acting on any associated request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootstrapRequestHeader {
    pub request_id: [u8; 32],
    pub ciphertext_len: usize,
}

struct DecodedBootstrapRequest<'a> {
    request_id: [u8; 32],
    encapped_key: &'a [u8],
    ciphertext: &'a [u8],
}

impl BootstrapContext {
    pub fn new(
        node_signing_public_key: [u8; 32],
        bootstrap_hpke_public_key: [u8; 32],
        operation: Vec<u8>,
        request_id: [u8; 32],
    ) -> Result<Self, TransportError> {
        let value = Self {
            node_signing_public_key,
            bootstrap_hpke_public_key,
            operation,
            request_id,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), TransportError> {
        if self.node_signing_public_key == [0; 32]
            || self.bootstrap_hpke_public_key == [0; 32]
            || self.request_id == [0; 32]
            || self.operation.is_empty()
            || self.operation.len() > MAX_OPERATION_BYTES
        {
            return Err(TransportError::InvalidInput);
        }
        Ok(())
    }

    fn info(&self) -> Result<Vec<u8>, TransportError> {
        self.validate()?;
        Ok(canonical_parts(&[
            BOOTSTRAP_DOMAIN,
            &self.node_signing_public_key,
            &self.bootstrap_hpke_public_key,
            &self.operation,
            &self.request_id,
        ]))
    }
}

pub struct BootstrapReplayGuard {
    consumed_request_ids: HashMap<[u8; 32], u64>,
    replay_ttl_ms: u64,
    last_seen_ms: Option<u64>,
}

impl BootstrapReplayGuard {
    pub fn new(replay_ttl_ms: u64) -> Result<Self, TransportError> {
        if !(MIN_BOOTSTRAP_REPLAY_TTL_MS..=MAX_BOOTSTRAP_REPLAY_TTL_MS).contains(&replay_ttl_ms) {
            return Err(TransportError::InvalidInput);
        }
        Ok(Self {
            consumed_request_ids: HashMap::new(),
            replay_ttl_ms,
            last_seen_ms: None,
        })
    }

    pub fn open_request(
        &mut self,
        private_key: &BootstrapPrivateKey,
        context: &BootstrapContext,
        request: &[u8],
        now_ms: u64,
    ) -> Result<BootstrapServerExchange, TransportError> {
        context.validate()?;
        if self
            .last_seen_ms
            .is_some_and(|last_seen_ms| now_ms < last_seen_ms)
        {
            return Err(TransportError::ClockRollback);
        }
        self.last_seen_ms = Some(now_ms);

        let decoded = decode_bootstrap(request)?;
        if decoded.request_id != context.request_id {
            return Err(TransportError::AuthenticationFailed);
        }

        // Prune on a private snapshot so failed authentication cannot erase
        // replay evidence; commit the pruned map only after HPKE opens.
        let mut active_request_ids = self.consumed_request_ids.clone();
        active_request_ids.retain(|_, consumed_at_ms| {
            now_ms.saturating_sub(*consumed_at_ms) < self.replay_ttl_ms
        });
        if active_request_ids.contains_key(&context.request_id) {
            return Err(TransportError::Replay);
        }
        if active_request_ids.len() >= MAX_BOOTSTRAP_REQUEST_IDS {
            return Err(TransportError::CapacityExhausted);
        }
        let exchange = open_request(private_key, context, decoded)?;
        active_request_ids.insert(context.request_id, now_ms);
        self.consumed_request_ids = active_request_ids;
        Ok(exchange)
    }

    /// Discard a request ID committed by a successful `open_request` call.
    ///
    /// The timestamp must match the commit being discarded, so a caller
    /// cannot remove a newer or unrelated replay entry while recovering from
    /// a later admission failure.
    pub fn discard_authenticated_request(
        &mut self,
        request_id: [u8; 32],
        consumed_at_ms: u64,
    ) -> bool {
        if self.consumed_request_ids.get(&request_id).copied() != Some(consumed_at_ms) {
            return false;
        }
        self.consumed_request_ids.remove(&request_id).is_some()
    }
}

#[cfg(test)]
impl BootstrapReplayGuard {
    pub(crate) fn fill_to_capacity_for_test(&mut self) {
        for index in 0..MAX_BOOTSTRAP_REQUEST_IDS {
            self.consumed_request_ids.insert(
                (index as u64 + 1)
                    .to_be_bytes()
                    .repeat(4)
                    .try_into()
                    .unwrap(),
                0,
            );
        }
    }
}

pub struct BootstrapClientExchange {
    pub request: Vec<u8>,
    pub response_opener: BootstrapResponseOpener,
}

pub struct BootstrapServerExchange {
    pub plaintext: Zeroizing<Vec<u8>>,
    pub response_sealer: BootstrapResponseSealer,
}

pub struct BootstrapResponseOpener {
    key: Zeroizing<[u8; 32]>,
    nonce: Zeroizing<[u8; 12]>,
    aad: Zeroizing<Vec<u8>>,
}

pub struct BootstrapResponseSealer {
    key: Zeroizing<[u8; 32]>,
    nonce: Zeroizing<[u8; 12]>,
    aad: Zeroizing<Vec<u8>>,
}

pub fn seal_bootstrap_request(
    context: &BootstrapContext,
    plaintext: &[u8],
) -> Result<BootstrapClientExchange, TransportError> {
    validate_plaintext(plaintext, MAX_BOOTSTRAP_PLAINTEXT_BYTES)?;
    let info = Zeroizing::new(context.info()?);
    let public_key = KemPublicKey::from_bytes(&context.bootstrap_hpke_public_key)
        .map_err(|_| TransportError::InvalidInput)?;
    let (encapped_key, mut sender) = setup_sender::<
        HpkeChaCha20Poly1305,
        HkdfSha256,
        X25519HkdfSha256,
    >(&OpModeS::Base, &public_key, &info)
    .map_err(|_| TransportError::AuthenticationFailed)?;
    let ciphertext = sender
        .seal(plaintext, &info)
        .map_err(|_| TransportError::AuthenticationFailed)?;
    let response_opener =
        response_material(&sender, &info).map(|(key, nonce)| BootstrapResponseOpener {
            key,
            nonce,
            aad: Zeroizing::new(info.to_vec()),
        })?;
    let encapped = encapped_key.to_bytes();
    let request = encode_bootstrap(context.request_id, encapped.as_slice(), &ciphertext)?;
    Ok(BootstrapClientExchange {
        request,
        response_opener,
    })
}

fn open_request(
    private_key: &BootstrapPrivateKey,
    context: &BootstrapContext,
    request: DecodedBootstrapRequest<'_>,
) -> Result<BootstrapServerExchange, TransportError> {
    let info = Zeroizing::new(context.info()?);
    if request.request_id != context.request_id {
        return Err(TransportError::AuthenticationFailed);
    }
    let private_key = private_key.parsed()?;
    let encapped_key =
        EncappedKey::from_bytes(request.encapped_key).map_err(|_| TransportError::NonCanonical)?;
    let receiver = setup_receiver::<HpkeChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &private_key,
        &encapped_key,
        &info,
    );
    let mut receiver = receiver.map_err(|_| TransportError::AuthenticationFailed)?;
    let plaintext = Zeroizing::new(
        receiver
            .open(request.ciphertext, &info)
            .map_err(|_| TransportError::AuthenticationFailed)?,
    );
    validate_plaintext(&plaintext, MAX_BOOTSTRAP_PLAINTEXT_BYTES)?;
    let response_sealer =
        response_material(&receiver, &info).map(|(key, nonce)| BootstrapResponseSealer {
            key,
            nonce,
            aad: Zeroizing::new(info.to_vec()),
        })?;
    Ok(BootstrapServerExchange {
        plaintext,
        response_sealer,
    })
}

impl BootstrapResponseSealer {
    pub fn seal(self, plaintext: &[u8]) -> Result<Vec<u8>, TransportError> {
        validate_plaintext(plaintext, MAX_BOOTSTRAP_PLAINTEXT_BYTES)?;
        ChaCha20Poly1305::new(self.key.as_ref().into())
            .encrypt(
                Nonce::from_slice(self.nonce.as_ref()),
                Payload {
                    msg: plaintext,
                    aad: &self.aad,
                },
            )
            .map_err(|_| TransportError::AuthenticationFailed)
    }
}

impl BootstrapResponseOpener {
    pub fn open(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        if ciphertext.len() <= TAG_BYTES
            || ciphertext.len() > MAX_BOOTSTRAP_PLAINTEXT_BYTES + TAG_BYTES
        {
            return Err(TransportError::TooLarge);
        }
        let plaintext = ChaCha20Poly1305::new(self.key.as_ref().into())
            .decrypt(
                Nonce::from_slice(self.nonce.as_ref()),
                Payload {
                    msg: ciphertext,
                    aad: &self.aad,
                },
            )
            .map_err(|_| TransportError::AuthenticationFailed)
            .map(Zeroizing::new)?;
        validate_plaintext(&plaintext, MAX_BOOTSTRAP_PLAINTEXT_BYTES)?;
        Ok(plaintext)
    }
}

trait HpkeExporter {
    fn export_secret(&self, context: &[u8], output: &mut [u8]) -> Result<(), hpke::HpkeError>;
}

impl<A, K, M> HpkeExporter for hpke::aead::AeadCtxS<A, K, M>
where
    A: hpke::aead::Aead,
    K: hpke::kdf::Kdf,
    M: hpke::Kem,
{
    fn export_secret(&self, context: &[u8], output: &mut [u8]) -> Result<(), hpke::HpkeError> {
        self.export(context, output)
    }
}

impl<A, K, M> HpkeExporter for hpke::aead::AeadCtxR<A, K, M>
where
    A: hpke::aead::Aead,
    K: hpke::kdf::Kdf,
    M: hpke::Kem,
{
    fn export_secret(&self, context: &[u8], output: &mut [u8]) -> Result<(), hpke::HpkeError> {
        self.export(context, output)
    }
}

fn response_material(
    context: &impl HpkeExporter,
    info: &[u8],
) -> Result<ResponseMaterial, TransportError> {
    let exporter_context = Zeroizing::new(canonical_parts(&[RESPONSE_EXPORT_DOMAIN, info]));
    let mut material = Zeroizing::new([0_u8; 44]);
    context
        .export_secret(&exporter_context, material.as_mut())
        .map_err(|_| TransportError::AuthenticationFailed)?;
    let mut key = Zeroizing::new([0_u8; 32]);
    let mut nonce = Zeroizing::new([0_u8; 12]);
    key.copy_from_slice(&material[..32]);
    nonce.copy_from_slice(&material[32..]);
    Ok((key, nonce))
}

fn encode_bootstrap(
    request_id: [u8; 32],
    encapped: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, TransportError> {
    if request_id == [0; 32]
        || encapped.len() != 32
        || ciphertext.len() <= TAG_BYTES
        || ciphertext.len() > MAX_BOOTSTRAP_PLAINTEXT_BYTES + TAG_BYTES
    {
        return Err(TransportError::TooLarge);
    }
    let length = u32::try_from(ciphertext.len()).map_err(|_| TransportError::TooLarge)?;
    let mut output = Vec::with_capacity(BOOTSTRAP_HEADER_BYTES + ciphertext.len());
    output.extend_from_slice(BOOTSTRAP_MAGIC);
    output.push(TRANSPORT_VERSION);
    output.extend_from_slice(&request_id);
    output.extend_from_slice(encapped);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(ciphertext);
    Ok(output)
}

fn decode_bootstrap(record: &[u8]) -> Result<DecodedBootstrapRequest<'_>, TransportError> {
    if record.len() < BOOTSTRAP_HEADER_BYTES + TAG_BYTES + 1
        || record.len() > BOOTSTRAP_HEADER_BYTES + MAX_BOOTSTRAP_PLAINTEXT_BYTES + TAG_BYTES
    {
        return Err(TransportError::TooLarge);
    }
    if &record[..4] != BOOTSTRAP_MAGIC || record[4] != TRANSPORT_VERSION {
        return Err(TransportError::NonCanonical);
    }
    let request_id = record[5..37]
        .try_into()
        .map_err(|_| TransportError::NonCanonical)?;
    let length = crate::read_u32(&record[69..73])?;
    if length != record.len() - BOOTSTRAP_HEADER_BYTES {
        return Err(TransportError::NonCanonical);
    }
    Ok(DecodedBootstrapRequest {
        request_id,
        encapped_key: &record[37..69],
        ciphertext: &record[BOOTSTRAP_HEADER_BYTES..],
    })
}

/// Inspect only bounded routing fields from an untrusted bootstrap record.
pub fn inspect_bootstrap_request(record: &[u8]) -> Result<BootstrapRequestHeader, TransportError> {
    let decoded = decode_bootstrap(record)?;
    if decoded.request_id == [0; 32] {
        return Err(TransportError::NonCanonical);
    }
    Ok(BootstrapRequestHeader {
        request_id: decoded.request_id,
        ciphertext_len: decoded.ciphertext.len(),
    })
}

fn exact_serialized(value: &[u8]) -> [u8; 32] {
    let mut output = [0_u8; 32];
    output.copy_from_slice(value);
    output
}

#[cfg(test)]
pub(crate) fn decode_for_test(record: &[u8]) -> Result<(&[u8], &[u8]), TransportError> {
    let decoded = decode_bootstrap(record)?;
    Ok((decoded.encapped_key, decoded.ciphertext))
}
