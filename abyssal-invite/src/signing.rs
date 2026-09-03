use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

const NODE_ID_DOMAIN: &[u8] = b"ABYSSAL-NODE-ID-V1";
const NODE_FINGERPRINT_DOMAIN: &[u8] = b"ABYSSAL-NODE-FINGERPRINT-V1";

pub fn generate_node_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

pub fn node_signing_key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

pub fn derive_node_id(public_key: &[u8; 32]) -> String {
    let mut digest = Sha256::new();
    digest.update(NODE_ID_DOMAIN);
    digest.update(public_key);
    format!(
        "abyssal-node-v1:{}",
        URL_SAFE_NO_PAD.encode(digest.finalize())
    )
}

pub fn node_key_fingerprint(public_key: &[u8; 32]) -> String {
    let mut digest = Sha256::new();
    digest.update(NODE_FINGERPRINT_DOMAIN);
    digest.update(public_key);
    digest.finalize()[..16]
        .chunks(2)
        .map(|chunk| format!("{:02X}{:02X}", chunk[0], chunk[1]))
        .collect::<Vec<_>>()
        .join(":")
}

pub(crate) fn signature_input(domain: &[u8], application_id: &str, payload: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(domain.len() + 2 + application_id.len() + payload.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(&(application_id.len() as u16).to_be_bytes());
    input.extend_from_slice(application_id.as_bytes());
    input.extend_from_slice(payload);
    input
}
