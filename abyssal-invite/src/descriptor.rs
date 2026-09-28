use crate::{
    codec::{self, Decoder},
    locator::{validate_locator_set, NodeLocator, MAX_LOCATORS},
    signing::signature_input,
    InviteError, ABYSSAL_APPLICATION_ID, DIRECT_PROTOCOL_VERSION, INVITE_FORMAT_VERSION,
    MAX_BINARY_INVITE_BYTES, ROOM_PROTOCOL_VERSION, TRANSPORT_PROTOCOL_VERSION,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::Zeroizing;

pub const MAX_BINARY_DESCRIPTOR_BYTES: usize = 1_024;
const DESCRIPTOR_SIGNATURE_DOMAIN: &[u8] = b"ABYSSAL-NODE-DESCRIPTOR-V1";
const DESCRIPTOR_VERSION: u8 = 1;
const DESCRIPTOR_PAYLOAD_FIELDS: usize = 8;
const SIGNED_DESCRIPTOR_FIELDS: usize = 2;
const DESCRIPTOR_V2_SIGNATURE_DOMAIN: &[u8] = b"ABYSSAL-NODE-DESCRIPTOR-V2";
const DESCRIPTOR_V2_VERSION: u8 = 2;
const DESCRIPTOR_V2_PAYLOAD_FIELDS: usize = 10;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeDescriptorV1 {
    pub application_id: String,
    pub node_public_key: [u8; 32],
    pub locators: Vec<NodeLocator>,
    pub invite_format: u8,
    pub direct_protocol: u16,
    pub room_protocol: u16,
    pub flags: u32,
}

impl NodeDescriptorV1 {
    pub fn abyssal(
        node_public_key: [u8; 32],
        locators: Vec<NodeLocator>,
    ) -> Result<Self, InviteError> {
        let descriptor = Self {
            application_id: ABYSSAL_APPLICATION_ID.to_owned(),
            node_public_key,
            locators,
            invite_format: INVITE_FORMAT_VERSION,
            direct_protocol: DIRECT_PROTOCOL_VERSION,
            room_protocol: ROOM_PROTOCOL_VERSION,
            flags: 0,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    fn validate(&self) -> Result<(), InviteError> {
        if self.application_id != ABYSSAL_APPLICATION_ID
            || self.node_public_key == [0_u8; 32]
            || self.invite_format != INVITE_FORMAT_VERSION
            || self.direct_protocol != DIRECT_PROTOCOL_VERSION
            || self.room_protocol != ROOM_PROTOCOL_VERSION
            || self.flags != 0
        {
            return Err(InviteError::InvalidDescriptor);
        }
        validate_locator_set(&self.locators).map_err(|_| InviteError::InvalidDescriptor)
    }

    fn canonical_payload(&self) -> Result<Vec<u8>, InviteError> {
        self.validate()?;
        let mut output = Vec::with_capacity(192);
        codec::encode_array(&mut output, DESCRIPTOR_PAYLOAD_FIELDS);
        codec::encode_uint(&mut output, DESCRIPTOR_VERSION.into());
        codec::encode_text(&mut output, &self.application_id);
        codec::encode_bytes(&mut output, &self.node_public_key);
        codec::encode_array(&mut output, self.locators.len());
        for locator in &self.locators {
            locator.encode(&mut output);
        }
        codec::encode_uint(&mut output, self.invite_format.into());
        codec::encode_uint(&mut output, self.direct_protocol.into());
        codec::encode_uint(&mut output, self.room_protocol.into());
        codec::encode_uint(&mut output, self.flags.into());
        Ok(output)
    }

    fn decode_payload(payload: &[u8]) -> Result<Self, InviteError> {
        let mut decoder = Decoder::new(payload);
        decoder
            .array(DESCRIPTOR_PAYLOAD_FIELDS)
            .map_err(|_| InviteError::InvalidDescriptor)?;
        if decoder.uint().map_err(|_| InviteError::InvalidDescriptor)?
            != u64::from(DESCRIPTOR_VERSION)
        {
            return Err(InviteError::UnsupportedVersion);
        }
        let application_id = decoder
            .text(codec::MAX_APPLICATION_ID_BYTES)
            .map_err(|_| InviteError::InvalidDescriptor)?;
        if application_id != ABYSSAL_APPLICATION_ID {
            return Err(InviteError::WrongApplication);
        }
        let node_public_key = exact_array(
            decoder
                .bytes(32)
                .map_err(|_| InviteError::InvalidDescriptor)?,
        )?;
        let count = decoder
            .array_len()
            .map_err(|_| InviteError::InvalidDescriptor)?;
        if count == 0 || count > MAX_LOCATORS {
            return Err(InviteError::InvalidDescriptor);
        }
        let mut locators = Vec::with_capacity(count);
        for _ in 0..count {
            locators.push(NodeLocator::decode(&mut decoder)?);
        }
        let invite_format =
            u8::try_from(decoder.uint().map_err(|_| InviteError::InvalidDescriptor)?)
                .map_err(|_| InviteError::InvalidDescriptor)?;
        let direct_protocol =
            u16::try_from(decoder.uint().map_err(|_| InviteError::InvalidDescriptor)?)
                .map_err(|_| InviteError::InvalidDescriptor)?;
        let room_protocol =
            u16::try_from(decoder.uint().map_err(|_| InviteError::InvalidDescriptor)?)
                .map_err(|_| InviteError::InvalidDescriptor)?;
        let flags = u32::try_from(decoder.uint().map_err(|_| InviteError::InvalidDescriptor)?)
            .map_err(|_| InviteError::InvalidDescriptor)?;
        decoder
            .finish()
            .map_err(|_| InviteError::InvalidDescriptor)?;
        let descriptor = Self {
            application_id,
            node_public_key,
            locators,
            invite_format,
            direct_protocol,
            room_protocol,
            flags,
        };
        descriptor.validate()?;
        if descriptor.canonical_payload()?.as_slice() != payload {
            return Err(InviteError::InvalidDescriptor);
        }
        Ok(descriptor)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedNodeDescriptor {
    pub descriptor: NodeDescriptorV1,
    pub signature: [u8; 64],
}

impl SignedNodeDescriptor {
    pub fn sign(
        descriptor: NodeDescriptorV1,
        signing_key: &SigningKey,
    ) -> Result<Self, InviteError> {
        if signing_key.verifying_key().to_bytes() != descriptor.node_public_key {
            return Err(InviteError::NodeIdentityMismatch);
        }
        let payload = Zeroizing::new(descriptor.canonical_payload()?);
        let input = Zeroizing::new(signature_input(
            DESCRIPTOR_SIGNATURE_DOMAIN,
            &descriptor.application_id,
            &payload,
        ));
        Ok(Self {
            descriptor,
            signature: signing_key.sign(&input).to_bytes(),
        })
    }

    pub fn verify_for_invite(
        &self,
        expected_node_key: &[u8; 32],
        expected_locator: &NodeLocator,
    ) -> Result<(), InviteError> {
        self.descriptor.validate()?;
        if &self.descriptor.node_public_key != expected_node_key
            || !self.descriptor.locators.contains(expected_locator)
        {
            return Err(InviteError::NodeIdentityMismatch);
        }
        let payload = Zeroizing::new(self.descriptor.canonical_payload()?);
        let input = Zeroizing::new(signature_input(
            DESCRIPTOR_SIGNATURE_DOMAIN,
            &self.descriptor.application_id,
            &payload,
        ));
        let key = VerifyingKey::from_bytes(expected_node_key)
            .map_err(|_| InviteError::InvalidDescriptor)?;
        key.verify(&input, &Signature::from_bytes(&self.signature))
            .map_err(|_| InviteError::InvalidDescriptor)
    }

    pub fn verify_self(&self) -> Result<(), InviteError> {
        let node_public_key = self.descriptor.node_public_key;
        let locator = self
            .descriptor
            .locators
            .first()
            .ok_or(InviteError::InvalidDescriptor)?;
        self.verify_for_invite(&node_public_key, locator)
    }

    pub fn canonical_binary(&self) -> Result<Vec<u8>, InviteError> {
        self.verify_self()?;
        let payload = Zeroizing::new(self.descriptor.canonical_payload()?);
        let mut output = Vec::with_capacity(payload.len() + 70);
        codec::encode_array(&mut output, SIGNED_DESCRIPTOR_FIELDS);
        codec::encode_bytes(&mut output, &payload);
        codec::encode_bytes(&mut output, &self.signature);
        (output.len() <= MAX_BINARY_DESCRIPTOR_BYTES)
            .then_some(output)
            .ok_or(InviteError::TooLarge)
    }

    pub fn decode_for_invite(
        binary: &[u8],
        expected_node_key: &[u8; 32],
        expected_locator: &NodeLocator,
    ) -> Result<Self, InviteError> {
        if binary.is_empty() || binary.len() > MAX_BINARY_DESCRIPTOR_BYTES {
            return Err(InviteError::TooLarge);
        }
        let mut decoder = Decoder::new(binary);
        decoder
            .array(SIGNED_DESCRIPTOR_FIELDS)
            .map_err(|_| InviteError::InvalidDescriptor)?;
        let payload = Zeroizing::new(
            decoder
                .bytes(MAX_BINARY_INVITE_BYTES)
                .map_err(|_| InviteError::InvalidDescriptor)?,
        );
        let signature = exact_array(
            decoder
                .bytes(64)
                .map_err(|_| InviteError::InvalidDescriptor)?,
        )?;
        decoder
            .finish()
            .map_err(|_| InviteError::InvalidDescriptor)?;
        let descriptor = NodeDescriptorV1::decode_payload(&payload)?;
        let signed = Self {
            descriptor,
            signature,
        };
        signed.verify_for_invite(expected_node_key, expected_locator)?;
        if signed.canonical_binary()?.as_slice() != binary {
            return Err(InviteError::InvalidDescriptor);
        }
        Ok(signed)
    }
}

/// A node-authenticated transport bootstrap descriptor.
///
/// V2 is deliberately separate from V1 so accepting it is always an explicit
/// protocol decision and cannot reinterpret a legacy descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeDescriptorV2 {
    pub application_id: String,
    pub node_public_key: [u8; 32],
    pub bootstrap_hpke_public_key: [u8; 32],
    pub locators: Vec<NodeLocator>,
    pub invite_format: u8,
    pub direct_protocol: u16,
    pub transport_protocol: u16,
    pub room_protocol: u16,
    pub flags: u32,
}

impl NodeDescriptorV2 {
    pub fn abyssal(
        node_public_key: [u8; 32],
        bootstrap_hpke_public_key: [u8; 32],
        locators: Vec<NodeLocator>,
    ) -> Result<Self, InviteError> {
        let descriptor = Self {
            application_id: ABYSSAL_APPLICATION_ID.to_owned(),
            node_public_key,
            bootstrap_hpke_public_key,
            locators,
            invite_format: INVITE_FORMAT_VERSION,
            direct_protocol: DIRECT_PROTOCOL_VERSION,
            transport_protocol: TRANSPORT_PROTOCOL_VERSION,
            room_protocol: ROOM_PROTOCOL_VERSION,
            flags: 0,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    fn validate(&self) -> Result<(), InviteError> {
        if self.application_id != ABYSSAL_APPLICATION_ID
            || self.node_public_key == [0_u8; 32]
            || self.bootstrap_hpke_public_key == [0_u8; 32]
            || self.invite_format != INVITE_FORMAT_VERSION
            || self.direct_protocol != DIRECT_PROTOCOL_VERSION
            || self.transport_protocol != TRANSPORT_PROTOCOL_VERSION
            || self.room_protocol != ROOM_PROTOCOL_VERSION
            || self.flags != 0
        {
            return Err(InviteError::InvalidDescriptor);
        }
        validate_locator_set(&self.locators).map_err(|_| InviteError::InvalidDescriptor)
    }

    fn canonical_payload(&self) -> Result<Vec<u8>, InviteError> {
        self.validate()?;
        let mut output = Vec::with_capacity(224);
        codec::encode_array(&mut output, DESCRIPTOR_V2_PAYLOAD_FIELDS);
        codec::encode_uint(&mut output, DESCRIPTOR_V2_VERSION.into());
        codec::encode_text(&mut output, &self.application_id);
        codec::encode_bytes(&mut output, &self.node_public_key);
        codec::encode_bytes(&mut output, &self.bootstrap_hpke_public_key);
        codec::encode_array(&mut output, self.locators.len());
        for locator in &self.locators {
            locator.encode(&mut output);
        }
        codec::encode_uint(&mut output, self.invite_format.into());
        codec::encode_uint(&mut output, self.direct_protocol.into());
        codec::encode_uint(&mut output, self.transport_protocol.into());
        codec::encode_uint(&mut output, self.room_protocol.into());
        codec::encode_uint(&mut output, self.flags.into());
        Ok(output)
    }

    fn decode_payload(payload: &[u8]) -> Result<Self, InviteError> {
        let mut decoder = Decoder::new(payload);
        decoder
            .array(DESCRIPTOR_V2_PAYLOAD_FIELDS)
            .map_err(|_| InviteError::InvalidDescriptor)?;
        if decoder.uint().map_err(|_| InviteError::InvalidDescriptor)?
            != u64::from(DESCRIPTOR_V2_VERSION)
        {
            return Err(InviteError::UnsupportedVersion);
        }
        let application_id = decoder
            .text(codec::MAX_APPLICATION_ID_BYTES)
            .map_err(|_| InviteError::InvalidDescriptor)?;
        if application_id != ABYSSAL_APPLICATION_ID {
            return Err(InviteError::WrongApplication);
        }
        let node_public_key = exact_array(
            decoder
                .bytes(32)
                .map_err(|_| InviteError::InvalidDescriptor)?,
        )?;
        let bootstrap_hpke_public_key = exact_array(
            decoder
                .bytes(32)
                .map_err(|_| InviteError::InvalidDescriptor)?,
        )?;
        let count = decoder
            .array_len()
            .map_err(|_| InviteError::InvalidDescriptor)?;
        if count == 0 || count > MAX_LOCATORS {
            return Err(InviteError::InvalidDescriptor);
        }
        let mut locators = Vec::with_capacity(count);
        for _ in 0..count {
            locators.push(NodeLocator::decode(&mut decoder)?);
        }
        let invite_format =
            u8::try_from(decoder.uint().map_err(|_| InviteError::InvalidDescriptor)?)
                .map_err(|_| InviteError::InvalidDescriptor)?;
        let direct_protocol =
            u16::try_from(decoder.uint().map_err(|_| InviteError::InvalidDescriptor)?)
                .map_err(|_| InviteError::InvalidDescriptor)?;
        let transport_protocol =
            u16::try_from(decoder.uint().map_err(|_| InviteError::InvalidDescriptor)?)
                .map_err(|_| InviteError::InvalidDescriptor)?;
        let room_protocol =
            u16::try_from(decoder.uint().map_err(|_| InviteError::InvalidDescriptor)?)
                .map_err(|_| InviteError::InvalidDescriptor)?;
        let flags = u32::try_from(decoder.uint().map_err(|_| InviteError::InvalidDescriptor)?)
            .map_err(|_| InviteError::InvalidDescriptor)?;
        decoder
            .finish()
            .map_err(|_| InviteError::InvalidDescriptor)?;
        let descriptor = Self {
            application_id,
            node_public_key,
            bootstrap_hpke_public_key,
            locators,
            invite_format,
            direct_protocol,
            transport_protocol,
            room_protocol,
            flags,
        };
        descriptor.validate()?;
        if descriptor.canonical_payload()?.as_slice() != payload {
            return Err(InviteError::InvalidDescriptor);
        }
        Ok(descriptor)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedNodeDescriptorV2 {
    pub descriptor: NodeDescriptorV2,
    pub signature: [u8; 64],
}

impl SignedNodeDescriptorV2 {
    pub fn sign(
        descriptor: NodeDescriptorV2,
        signing_key: &SigningKey,
    ) -> Result<Self, InviteError> {
        if signing_key.verifying_key().to_bytes() != descriptor.node_public_key {
            return Err(InviteError::NodeIdentityMismatch);
        }
        let payload = Zeroizing::new(descriptor.canonical_payload()?);
        let input = Zeroizing::new(signature_input(
            DESCRIPTOR_V2_SIGNATURE_DOMAIN,
            &descriptor.application_id,
            &payload,
        ));
        Ok(Self {
            descriptor,
            signature: signing_key.sign(&input).to_bytes(),
        })
    }

    pub fn verify_for_invite(
        &self,
        expected_node_key: &[u8; 32],
        expected_locator: &NodeLocator,
    ) -> Result<(), InviteError> {
        self.descriptor.validate()?;
        if &self.descriptor.node_public_key != expected_node_key
            || !self.descriptor.locators.contains(expected_locator)
        {
            return Err(InviteError::NodeIdentityMismatch);
        }
        let payload = Zeroizing::new(self.descriptor.canonical_payload()?);
        let input = Zeroizing::new(signature_input(
            DESCRIPTOR_V2_SIGNATURE_DOMAIN,
            &self.descriptor.application_id,
            &payload,
        ));
        let key = VerifyingKey::from_bytes(expected_node_key)
            .map_err(|_| InviteError::InvalidDescriptor)?;
        key.verify(&input, &Signature::from_bytes(&self.signature))
            .map_err(|_| InviteError::InvalidDescriptor)
    }

    pub fn verify_self(&self) -> Result<(), InviteError> {
        let node_public_key = self.descriptor.node_public_key;
        let locator = self
            .descriptor
            .locators
            .first()
            .ok_or(InviteError::InvalidDescriptor)?;
        self.verify_for_invite(&node_public_key, locator)
    }

    pub fn canonical_binary(&self) -> Result<Vec<u8>, InviteError> {
        self.verify_self()?;
        let payload = Zeroizing::new(self.descriptor.canonical_payload()?);
        let mut output = Vec::with_capacity(payload.len() + 70);
        codec::encode_array(&mut output, SIGNED_DESCRIPTOR_FIELDS);
        codec::encode_bytes(&mut output, &payload);
        codec::encode_bytes(&mut output, &self.signature);
        (output.len() <= MAX_BINARY_DESCRIPTOR_BYTES)
            .then_some(output)
            .ok_or(InviteError::TooLarge)
    }

    pub fn decode_for_invite(
        binary: &[u8],
        expected_node_key: &[u8; 32],
        expected_locator: &NodeLocator,
    ) -> Result<Self, InviteError> {
        if binary.is_empty() || binary.len() > MAX_BINARY_DESCRIPTOR_BYTES {
            return Err(InviteError::TooLarge);
        }
        let mut decoder = Decoder::new(binary);
        decoder
            .array(SIGNED_DESCRIPTOR_FIELDS)
            .map_err(|_| InviteError::InvalidDescriptor)?;
        let payload = Zeroizing::new(
            decoder
                .bytes(MAX_BINARY_DESCRIPTOR_BYTES)
                .map_err(|_| InviteError::InvalidDescriptor)?,
        );
        let signature = exact_array(
            decoder
                .bytes(64)
                .map_err(|_| InviteError::InvalidDescriptor)?,
        )?;
        decoder
            .finish()
            .map_err(|_| InviteError::InvalidDescriptor)?;
        let descriptor = NodeDescriptorV2::decode_payload(&payload)?;
        let signed = Self {
            descriptor,
            signature,
        };
        signed.verify_for_invite(expected_node_key, expected_locator)?;
        if signed.canonical_binary()?.as_slice() != binary {
            return Err(InviteError::InvalidDescriptor);
        }
        Ok(signed)
    }
}

fn exact_array<const N: usize>(value: Vec<u8>) -> Result<[u8; N], InviteError> {
    value.try_into().map_err(|_| InviteError::InvalidDescriptor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{locator_from_public_url, node_signing_key_from_seed};

    fn signed_v2() -> SignedNodeDescriptorV2 {
        let key = node_signing_key_from_seed(&[7_u8; 32]);
        let descriptor = NodeDescriptorV2::abyssal(
            key.verifying_key().to_bytes(),
            [8_u8; 32],
            vec![locator_from_public_url("https://node.example.com").unwrap()],
        )
        .unwrap();
        SignedNodeDescriptorV2::sign(descriptor, &key).unwrap()
    }

    #[test]
    fn v2_round_trips_and_binds_bootstrap_key() {
        let signed = signed_v2();
        let binary = signed.canonical_binary().unwrap();
        let decoded = SignedNodeDescriptorV2::decode_for_invite(
            &binary,
            &signed.descriptor.node_public_key,
            &signed.descriptor.locators[0],
        )
        .unwrap();
        assert_eq!(decoded, signed);
        assert_eq!(decoded.descriptor.direct_protocol, DIRECT_PROTOCOL_VERSION);
        assert_eq!(
            decoded.descriptor.transport_protocol,
            TRANSPORT_PROTOCOL_VERSION
        );
        assert_eq!(
            decoded.descriptor.canonical_payload().unwrap(),
            signed.descriptor.canonical_payload().unwrap()
        );

        let mut tampered = binary;
        let position = tampered
            .windows(32)
            .position(|window| window == [8_u8; 32])
            .unwrap();
        tampered[position] ^= 1;
        assert!(SignedNodeDescriptorV2::decode_for_invite(
            &tampered,
            &signed.descriptor.node_public_key,
            &signed.descriptor.locators[0],
        )
        .is_err());
    }

    #[test]
    fn v2_rejects_zero_key_wrong_version_trailing_and_oversized() {
        let signed = signed_v2();
        assert!(NodeDescriptorV2::abyssal(
            signed.descriptor.node_public_key,
            [0_u8; 32],
            signed.descriptor.locators.clone(),
        )
        .is_err());
        let mut wrong_direct = signed.clone();
        wrong_direct.descriptor.direct_protocol = TRANSPORT_PROTOCOL_VERSION;
        assert_eq!(
            wrong_direct.canonical_binary(),
            Err(InviteError::InvalidDescriptor)
        );
        let mut wrong_transport = signed.clone();
        wrong_transport.descriptor.transport_protocol = ROOM_PROTOCOL_VERSION;
        assert_eq!(
            wrong_transport.canonical_binary(),
            Err(InviteError::InvalidDescriptor)
        );

        let binary = signed.canonical_binary().unwrap();
        let mut trailing = binary.clone();
        trailing.push(0);
        assert!(SignedNodeDescriptorV2::decode_for_invite(
            &trailing,
            &signed.descriptor.node_public_key,
            &signed.descriptor.locators[0],
        )
        .is_err());
        assert_eq!(
            SignedNodeDescriptorV2::decode_for_invite(
                &vec![0_u8; MAX_BINARY_DESCRIPTOR_BYTES + 1],
                &signed.descriptor.node_public_key,
                &signed.descriptor.locators[0],
            ),
            Err(InviteError::TooLarge)
        );

        let payload = signed.descriptor.canonical_payload().unwrap();
        let mut wrong_version = payload;
        wrong_version[1] = DESCRIPTOR_VERSION;
        assert_eq!(
            NodeDescriptorV2::decode_payload(&wrong_version),
            Err(InviteError::UnsupportedVersion)
        );

        let key = node_signing_key_from_seed(&[7_u8; 32]);
        let legacy = SignedNodeDescriptor::sign(
            NodeDescriptorV1::abyssal(
                key.verifying_key().to_bytes(),
                signed.descriptor.locators.clone(),
            )
            .unwrap(),
            &key,
        )
        .unwrap()
        .canonical_binary()
        .unwrap();
        assert!(SignedNodeDescriptorV2::decode_for_invite(
            &legacy,
            &signed.descriptor.node_public_key,
            &signed.descriptor.locators[0],
        )
        .is_err());
        assert!(SignedNodeDescriptor::decode_for_invite(
            &binary,
            &signed.descriptor.node_public_key,
            &signed.descriptor.locators[0],
        )
        .is_err());
    }

    #[test]
    fn v2_rejects_every_single_byte_tamper_and_hostile_lengths_without_panicking() {
        let signed = signed_v2();
        let binary = signed.canonical_binary().unwrap();
        for index in 0..binary.len() {
            let mut tampered = binary.clone();
            tampered[index] ^= 1;
            assert!(SignedNodeDescriptorV2::decode_for_invite(
                &tampered,
                &signed.descriptor.node_public_key,
                &signed.descriptor.locators[0],
            )
            .is_err());
        }

        for length in 0..=MAX_BINARY_DESCRIPTOR_BYTES + 1 {
            let hostile = vec![0xff; length];
            assert!(std::panic::catch_unwind(|| {
                let _ = SignedNodeDescriptorV2::decode_for_invite(
                    &hostile,
                    &signed.descriptor.node_public_key,
                    &signed.descriptor.locators[0],
                );
            })
            .is_ok());
        }
    }
}
