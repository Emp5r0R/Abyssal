use crate::{
    codec::{self, Decoder},
    locator::{validate_locator_set, NodeLocator, MAX_LOCATORS},
    signing::signature_input,
    InviteError,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub const ABYSSAL_APPLICATION_ID: &str = "org.abyssal.chat";
pub const INVITE_FORMAT_VERSION: u8 = 1;
pub const INVITE_CAPABILITY_BYTES: usize = 32;
pub const MAX_BINARY_INVITE_BYTES: usize = 1_024;
pub const MAX_ENCODED_INVITE_TEXT_BYTES: usize = 2_048;
const INVITE_SIGNATURE_DOMAIN: &[u8] = b"INVITE-CAPSULE-V1";
const ACCOUNT_CONTEXT_DOMAIN: &[u8] = b"ABYSSAL-ACCOUNT-CONTEXT-V1";
const INVITE_PAYLOAD_FIELDS: usize = 10;
const SIGNED_INVITE_FIELDS: usize = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InviteCapabilityType {
    AccountBootstrap,
}

impl InviteCapabilityType {
    fn tag(self) -> u64 {
        1
    }

    fn from_tag(tag: u64) -> Result<Self, InviteError> {
        match tag {
            1 => Ok(Self::AccountBootstrap),
            _ => Err(InviteError::UnsupportedCapability),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InviteCapsuleV1 {
    pub application_id: String,
    pub capability_type: InviteCapabilityType,
    pub node_public_key: [u8; 32],
    pub locators: Vec<NodeLocator>,
    pub capability: [u8; INVITE_CAPABILITY_BYTES],
    pub protocol_min: u16,
    pub protocol_max: u16,
    pub flags: u32,
    pub expires_at: Option<u64>,
}

impl InviteCapsuleV1 {
    pub fn abyssal(
        node_public_key: [u8; 32],
        locators: Vec<NodeLocator>,
        capability: [u8; INVITE_CAPABILITY_BYTES],
        protocol_min: u16,
        protocol_max: u16,
        expires_at: Option<u64>,
    ) -> Result<Self, InviteError> {
        let capsule = Self {
            application_id: ABYSSAL_APPLICATION_ID.to_owned(),
            capability_type: InviteCapabilityType::AccountBootstrap,
            node_public_key,
            locators,
            capability,
            protocol_min,
            protocol_max,
            flags: 0,
            expires_at,
        };
        capsule.validate(None)?;
        Ok(capsule)
    }

    pub fn validate(&self, now_unix_seconds: Option<u64>) -> Result<(), InviteError> {
        if self.application_id != ABYSSAL_APPLICATION_ID {
            return Err(InviteError::WrongApplication);
        }
        if self.capability_type != InviteCapabilityType::AccountBootstrap {
            return Err(InviteError::UnsupportedCapability);
        }
        if self.node_public_key == [0_u8; 32]
            || self.capability == [0_u8; INVITE_CAPABILITY_BYTES]
            || self.protocol_min == 0
            || self.protocol_max < self.protocol_min
            || self.flags != 0
        {
            return Err(InviteError::Invalid);
        }
        validate_locator_set(&self.locators)?;
        if now_unix_seconds.is_some_and(|now| self.expires_at.is_some_and(|expiry| expiry <= now)) {
            return Err(InviteError::Expired);
        }
        Ok(())
    }

    pub fn canonical_payload(&self) -> Result<Vec<u8>, InviteError> {
        self.validate(None)?;
        let mut output = Vec::with_capacity(256);
        codec::encode_array(&mut output, INVITE_PAYLOAD_FIELDS);
        codec::encode_uint(&mut output, INVITE_FORMAT_VERSION.into());
        codec::encode_text(&mut output, &self.application_id);
        codec::encode_uint(&mut output, self.capability_type.tag());
        codec::encode_bytes(&mut output, &self.node_public_key);
        codec::encode_array(&mut output, self.locators.len());
        for locator in &self.locators {
            locator.encode(&mut output);
        }
        codec::encode_bytes(&mut output, &self.capability);
        codec::encode_uint(&mut output, self.protocol_min.into());
        codec::encode_uint(&mut output, self.protocol_max.into());
        codec::encode_uint(&mut output, self.flags.into());
        codec::encode_optional_uint(&mut output, self.expires_at);
        if output.len() > MAX_BINARY_INVITE_BYTES.saturating_sub(70) {
            return Err(InviteError::TooLarge);
        }
        Ok(output)
    }

    fn decode_payload(payload: &[u8]) -> Result<Self, InviteError> {
        let mut decoder = Decoder::new(payload);
        decoder.array(INVITE_PAYLOAD_FIELDS)?;
        let version = decoder.uint()?;
        if version != u64::from(INVITE_FORMAT_VERSION) {
            return Err(InviteError::UnsupportedVersion);
        }
        let application_id = decoder.text(codec::MAX_APPLICATION_ID_BYTES)?;
        if application_id != ABYSSAL_APPLICATION_ID {
            return Err(InviteError::WrongApplication);
        }
        let capability_type = InviteCapabilityType::from_tag(decoder.uint()?)?;
        let node_public_key = exact_array(decoder.bytes(32)?)?;
        let locator_count = decoder.array_len()?;
        if locator_count == 0 || locator_count > MAX_LOCATORS {
            return Err(InviteError::Invalid);
        }
        let mut locators = Vec::with_capacity(locator_count);
        for _ in 0..locator_count {
            locators.push(NodeLocator::decode(&mut decoder)?);
        }
        let capability = exact_array(decoder.bytes(INVITE_CAPABILITY_BYTES)?)?;
        let protocol_min = u16::try_from(decoder.uint()?).map_err(|_| InviteError::Invalid)?;
        let protocol_max = u16::try_from(decoder.uint()?).map_err(|_| InviteError::Invalid)?;
        let flags = u32::try_from(decoder.uint()?).map_err(|_| InviteError::Invalid)?;
        let expires_at = decoder.optional_uint()?;
        decoder.finish()?;
        let capsule = Self {
            application_id,
            capability_type,
            node_public_key,
            locators,
            capability,
            protocol_min,
            protocol_max,
            flags,
            expires_at,
        };
        capsule.validate(None)?;
        if capsule.canonical_payload()?.as_slice() != payload {
            return Err(InviteError::Invalid);
        }
        Ok(capsule)
    }
}

impl Drop for InviteCapsuleV1 {
    fn drop(&mut self) {
        self.capability.zeroize();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedInviteCapsule {
    pub capsule: InviteCapsuleV1,
    pub signature: [u8; 64],
}

impl SignedInviteCapsule {
    pub fn sign(capsule: InviteCapsuleV1, signing_key: &SigningKey) -> Result<Self, InviteError> {
        if signing_key.verifying_key().to_bytes() != capsule.node_public_key {
            return Err(InviteError::NodeIdentityMismatch);
        }
        let payload = Zeroizing::new(capsule.canonical_payload()?);
        let input = Zeroizing::new(signature_input(
            INVITE_SIGNATURE_DOMAIN,
            &capsule.application_id,
            &payload,
        ));
        let signature = signing_key.sign(&input).to_bytes();
        Ok(Self { capsule, signature })
    }

    pub fn verify(&self, now_unix_seconds: Option<u64>) -> Result<(), InviteError> {
        self.capsule.validate(now_unix_seconds)?;
        let payload = Zeroizing::new(self.capsule.canonical_payload()?);
        let input = Zeroizing::new(signature_input(
            INVITE_SIGNATURE_DOMAIN,
            &self.capsule.application_id,
            &payload,
        ));
        let key = VerifyingKey::from_bytes(&self.capsule.node_public_key)
            .map_err(|_| InviteError::InvalidSignature)?;
        key.verify(&input, &Signature::from_bytes(&self.signature))
            .map_err(|_| InviteError::InvalidSignature)
    }

    pub fn canonical_binary(&self) -> Result<Vec<u8>, InviteError> {
        self.verify(None)?;
        let payload = Zeroizing::new(self.capsule.canonical_payload()?);
        let mut output = Vec::with_capacity(payload.len() + 70);
        codec::encode_array(&mut output, SIGNED_INVITE_FIELDS);
        codec::encode_bytes(&mut output, &payload);
        codec::encode_bytes(&mut output, &self.signature);
        if output.len() > MAX_BINARY_INVITE_BYTES {
            return Err(InviteError::TooLarge);
        }
        Ok(output)
    }

    pub fn decode(binary: &[u8], now_unix_seconds: Option<u64>) -> Result<Self, InviteError> {
        if binary.is_empty() || binary.len() > MAX_BINARY_INVITE_BYTES {
            return Err(InviteError::TooLarge);
        }
        let mut decoder = Decoder::new(binary);
        decoder.array(SIGNED_INVITE_FIELDS)?;
        let payload = Zeroizing::new(decoder.bytes(MAX_BINARY_INVITE_BYTES)?);
        let signature = exact_array(decoder.bytes(64)?)?;
        decoder.finish()?;
        let capsule = InviteCapsuleV1::decode_payload(&payload)?;
        let signed = Self { capsule, signature };
        signed.verify(now_unix_seconds)?;
        if signed.canonical_binary()?.as_slice() != binary {
            return Err(InviteError::Invalid);
        }
        Ok(signed)
    }
}

impl Drop for SignedInviteCapsule {
    fn drop(&mut self) {
        self.signature.zeroize();
    }
}

pub fn generate_capability() -> Zeroizing<[u8; INVITE_CAPABILITY_BYTES]> {
    let mut capability = Zeroizing::new([0_u8; INVITE_CAPABILITY_BYTES]);
    OsRng.fill_bytes(capability.as_mut());
    capability
}

pub fn account_context_v1(node_public_key: &[u8; 32], capability: &[u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(ACCOUNT_CONTEXT_DOMAIN);
    digest.update(node_public_key);
    digest.update(capability);
    digest.finalize().into()
}

fn exact_array<const N: usize>(mut value: Vec<u8>) -> Result<[u8; N], InviteError> {
    if value.len() != N {
        value.zeroize();
        return Err(InviteError::Invalid);
    }
    let mut result = [0_u8; N];
    result.copy_from_slice(&value);
    value.zeroize();
    Ok(result)
}
