//! Abyssal's invite types. The fields stay plain data for callers; every
//! format rule (validation, canonical encoding, signatures) is the shared
//! `invite-capsule` implementation, reached through [`AbyssalInvite`].

use crate::{
    profile::{
        AbyssalInvite, BootstrapCapability, ABYSSAL_APPLICATION_ID, INVITE_CAPABILITY_BYTES,
    },
    InviteError, NodeLocator,
};
use ed25519_dalek::SigningKey;
use invite_capsule::{InviteCapsule, NodePublicKey, NodeSigningKey, SignedInvite};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const ACCOUNT_CONTEXT_DOMAIN: &[u8] = b"ABYSSAL-ACCOUNT-CONTEXT-V1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InviteCapabilityType {
    AccountBootstrap,
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
        let shared = self.to_shared()?;
        if now_unix_seconds.is_some_and(|now| shared.is_expired_at(now)) {
            return Err(InviteError::Expired);
        }
        Ok(())
    }

    /// The shared, validated form of these fields.
    fn to_shared(&self) -> Result<InviteCapsule<AbyssalInvite>, InviteError> {
        if self.application_id != ABYSSAL_APPLICATION_ID {
            return Err(InviteError::WrongApplication);
        }
        if self.flags != 0 {
            return Err(InviteError::Invalid);
        }
        Ok(InviteCapsule::new(
            NodePublicKey::from_bytes(self.node_public_key)?,
            self.locators.clone(),
            BootstrapCapability::new(self.capability)?,
            self.protocol_min,
            self.protocol_max,
            self.expires_at,
        )?)
    }

    fn from_shared(capsule: &InviteCapsule<AbyssalInvite>) -> Self {
        Self {
            application_id: ABYSSAL_APPLICATION_ID.to_owned(),
            capability_type: InviteCapabilityType::AccountBootstrap,
            node_public_key: *capsule.node_public_key().as_bytes(),
            locators: capsule.locators().to_vec(),
            capability: *capsule.capability().expose(),
            protocol_min: capsule.protocol_min(),
            protocol_max: capsule.protocol_max(),
            flags: 0,
            expires_at: capsule.expires_at_epoch_seconds(),
        }
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
        let seed = Zeroizing::new(signing_key.to_bytes());
        let signed = SignedInvite::sign(capsule.to_shared()?, &NodeSigningKey::from_seed(&seed))?;
        Ok(Self {
            capsule,
            signature: *signed.signature(),
        })
    }

    pub fn verify(&self, now_unix_seconds: Option<u64>) -> Result<(), InviteError> {
        self.to_shared(now_unix_seconds).map(drop)
    }

    pub fn canonical_binary(&self) -> Result<Vec<u8>, InviteError> {
        Ok(self.to_shared(None)?.canonical_binary()?.to_vec())
    }

    pub fn decode(binary: &[u8], now_unix_seconds: Option<u64>) -> Result<Self, InviteError> {
        Ok(Self::from_shared(&SignedInvite::decode(
            binary,
            now_unix_seconds,
        )?))
    }

    /// The verified shared form.
    pub(crate) fn to_shared(
        &self,
        now_unix_seconds: Option<u64>,
    ) -> Result<SignedInvite<AbyssalInvite>, InviteError> {
        Ok(SignedInvite::from_parts(
            self.capsule.to_shared()?,
            self.signature,
            now_unix_seconds,
        )?)
    }

    pub(crate) fn from_shared(signed: &SignedInvite<AbyssalInvite>) -> Self {
        Self {
            capsule: InviteCapsuleV1::from_shared(signed.capsule()),
            signature: *signed.signature(),
        }
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
