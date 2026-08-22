use super::{
    canonical_fields, canonical_username, decode_canonical_fields, validate_node_context,
    validate_room_id, validate_username, verify_stable_signature, CREDENTIAL_MAGIC,
    CREDENTIAL_TYPE, MLS_PROTOCOL_VERSION,
};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use mls_rs::{
    identity::{CredentialType, SigningIdentity},
    ExtensionList,
};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CredentialParts {
    pub(super) username: String,
    pub(super) node_context: Vec<u8>,
    pub(super) room_id: String,
    pub(super) group_id: [u8; 32],
    pub(super) stable_identity: [u8; 64],
    pub(super) mls_public: [u8; 32],
    pub(super) proof: [u8; 64],
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid MLS identity")]
pub(super) struct MlsIdentityError;

impl mls_rs_core::error::IntoAnyError for MlsIdentityError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

/// Validates the self-authenticating credential instead of using MLS's
/// intentionally always-valid `BasicIdentityProvider`.
#[derive(Debug, Clone)]
pub(super) struct AbyssalIdentityProvider;

impl mls_rs::IdentityProvider for AbyssalIdentityProvider {
    type Error = MlsIdentityError;

    fn validate_member(
        &self,
        identity: &SigningIdentity,
        _timestamp: Option<mls_rs::time::MlsTime>,
        _context: mls_rs_core::identity::MemberValidationContext<'_>,
    ) -> Result<(), Self::Error> {
        parse_credential(identity).map(|_| ())
    }

    fn validate_external_sender(
        &self,
        identity: &SigningIdentity,
        _timestamp: Option<mls_rs::time::MlsTime>,
        _extensions: Option<&ExtensionList>,
    ) -> Result<(), Self::Error> {
        parse_credential(identity).map(|_| ())
    }

    fn identity(
        &self,
        identity: &SigningIdentity,
        _extensions: &ExtensionList,
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(parse_credential(identity)?.stable_identity.to_vec())
    }

    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
        _extensions: &ExtensionList,
    ) -> Result<bool, Self::Error> {
        let predecessor = parse_credential(predecessor)?;
        let successor = parse_credential(successor)?;
        Ok(predecessor.username == successor.username
            && predecessor.node_context == successor.node_context
            && predecessor.room_id == successor.room_id
            && predecessor.group_id == successor.group_id
            && predecessor.stable_identity == successor.stable_identity
            && predecessor.mls_public == successor.mls_public)
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        vec![CREDENTIAL_TYPE]
    }
}

pub(crate) fn mls_public_for_root(
    root: &[u8; 32],
    username: &str,
    node_context: &[u8],
    room_id: &str,
    group_id: &[u8; 32],
) -> Result<[u8; 32], String> {
    validate_username(username)?;
    validate_node_context(node_context)?;
    validate_room_id(room_id)?;
    let info = canonical_fields(
        b"ABYSSAL-MLS-V10-SIGNING",
        &[
            username.as_bytes(),
            node_context,
            room_id.as_bytes(),
            group_id,
        ],
    )?;
    let mut seed = Zeroizing::new([0_u8; 32]);
    Hkdf::<Sha256>::new(Some(b"ABYSSAL-MLS-V10-SIGNING"), root)
        .expand(&info, seed.as_mut())
        .map_err(|_| "Identity unavailable".to_string())?;
    let key = SigningKey::from_bytes(&seed);
    let public = key.verifying_key().to_bytes();
    seed.zeroize();
    Ok(public)
}

pub(crate) fn credential_transcript(
    username: &str,
    room_id: &str,
    node_context: &[u8],
    group_id: &[u8; 32],
    stable: &[u8; 64],
    mls_public: &[u8; 32],
) -> Result<Vec<u8>, String> {
    validate_username(username)?;
    validate_room_id(room_id)?;
    validate_node_context(node_context)?;
    canonical_fields(
        CREDENTIAL_MAGIC,
        &[
            &[MLS_PROTOCOL_VERSION as u8],
            username.as_bytes(),
            room_id.as_bytes(),
            node_context,
            group_id,
            stable,
            mls_public,
        ],
    )
}

pub(super) fn encode_credential(
    username: &str,
    room_id: &str,
    node_context: &[u8],
    group_id: &[u8],
    stable: &[u8; 64],
    mls_public: &[u8; 32],
    proof: &[u8],
) -> Result<Vec<u8>, String> {
    if proof.len() != 64 {
        return Err("Identity unavailable".to_string());
    }
    let group_id: [u8; 32] = group_id
        .try_into()
        .map_err(|_| "Identity unavailable".to_string())?;
    let mut out = credential_transcript(
        username,
        room_id,
        node_context,
        &group_id,
        stable,
        mls_public,
    )?;
    out.extend_from_slice(proof);
    if out.len() > 1024 {
        return Err("Identity unavailable".to_string());
    }
    Ok(out)
}

pub(super) fn parse_credential(
    identity: &SigningIdentity,
) -> Result<CredentialParts, MlsIdentityError> {
    let custom = identity.credential.as_custom().ok_or(MlsIdentityError)?;
    if custom.credential_type() != CREDENTIAL_TYPE {
        return Err(MlsIdentityError);
    }
    let data = custom.data();
    if data.len() > 1024 || data.len() < 64 + 8 {
        return Err(MlsIdentityError);
    }
    if data.len() < 64 {
        return Err(MlsIdentityError);
    }
    let fields = decode_canonical_fields(&data[..data.len() - 64], CREDENTIAL_MAGIC)
        .map_err(|_| MlsIdentityError)?;
    if fields.len() != 7
        || fields[0] != [MLS_PROTOCOL_VERSION as u8]
        || fields[1].is_empty()
        || fields[2].is_empty()
        || fields[4].len() != 32
        || fields[5].len() != 64
        || fields[6].len() != 32
        || identity.signature_key.as_bytes() != fields[6].as_slice()
    {
        return Err(MlsIdentityError);
    }
    let username =
        canonical_username(std::str::from_utf8(&fields[1]).map_err(|_| MlsIdentityError)?)
            .map_err(|_| MlsIdentityError)?;
    let room_id = std::str::from_utf8(&fields[2])
        .map_err(|_| MlsIdentityError)?
        .to_string();
    validate_room_id(&room_id).map_err(|_| MlsIdentityError)?;
    let node_context = validate_node_context(&fields[3]).map_err(|_| MlsIdentityError)?;
    let group_id: [u8; 32] = fields[4]
        .as_slice()
        .try_into()
        .map_err(|_| MlsIdentityError)?;
    let stable_identity: [u8; 64] = fields[5]
        .as_slice()
        .try_into()
        .map_err(|_| MlsIdentityError)?;
    let mls_public: [u8; 32] = fields[6]
        .as_slice()
        .try_into()
        .map_err(|_| MlsIdentityError)?;
    let proof: [u8; 64] = data[data.len() - 64..]
        .try_into()
        .map_err(|_| MlsIdentityError)?;
    if identity.signature_key.as_bytes() != mls_public
        || stable_identity.iter().all(|byte| *byte == 0)
        || mls_public.iter().all(|byte| *byte == 0)
    {
        return Err(MlsIdentityError);
    }
    let transcript = credential_transcript(
        &username,
        &room_id,
        &node_context,
        &group_id,
        &stable_identity,
        &mls_public,
    )
    .map_err(|_| MlsIdentityError)?;
    verify_stable_signature(&stable_identity, &transcript, &proof).map_err(|_| MlsIdentityError)?;
    Ok(CredentialParts {
        username,
        node_context,
        room_id,
        group_id,
        stable_identity,
        mls_public,
        proof,
    })
}
