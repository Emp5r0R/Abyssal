//! Abyssal's profile of the shared invite format: an account-bootstrap
//! invite carrying a 32-byte random capability, accepted over every locator
//! kind, with both the deep-link and the hand-typeable text forms.

use std::fmt;

use invite_capsule::{cbor, Capability, CapsuleError, InviteProfile, LocatorKinds, ManualText};
use zeroize::Zeroizing;

pub const ABYSSAL_APPLICATION_ID: &str = "org.abyssal.chat";
pub const INVITE_CAPABILITY_BYTES: usize = 32;
pub(crate) const DEEP_LINK_PREFIX: &str = "abyssal:invite:";
pub(crate) const MANUAL_PREFIX: &str = "ABY1-";

/// Abyssal's invite profile.
pub enum AbyssalInvite {}

impl InviteProfile for AbyssalInvite {
    const APPLICATION_ID: &'static str = ABYSSAL_APPLICATION_ID;
    const SIGNATURE_DOMAIN: &'static [u8] = b"INVITE-CAPSULE-V1";
    const CAPABILITY_TYPE: u64 = 1;
    const LOCATORS: LocatorKinds = LocatorKinds::ALL;
    const TEXT_PREFIX: &'static str = DEEP_LINK_PREFIX;
    const MANUAL_TEXT: Option<ManualText> = Some(ManualText {
        prefix: MANUAL_PREFIX,
        checksum_domain: b"ABYSSAL-INVITE-CHECKSUM-V1",
    });
    type Capability = BootstrapCapability;
}

/// The account-bootstrap capability: 32 random, nonzero bytes. Zeroized on
/// drop and never printed.
#[derive(Clone, Eq, PartialEq)]
pub struct BootstrapCapability(Zeroizing<[u8; INVITE_CAPABILITY_BYTES]>);

impl BootstrapCapability {
    pub fn new(bytes: [u8; INVITE_CAPABILITY_BYTES]) -> Result<Self, CapsuleError> {
        (bytes != [0; INVITE_CAPABILITY_BYTES])
            .then(|| Self(Zeroizing::new(bytes)))
            .ok_or(CapsuleError::Invalid)
    }

    pub fn expose(&self) -> &[u8; INVITE_CAPABILITY_BYTES] {
        &self.0
    }
}

impl fmt::Debug for BootstrapCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BootstrapCapability(<redacted>)")
    }
}

impl Capability for BootstrapCapability {
    fn encode(&self, output: &mut Vec<u8>) {
        cbor::encode_bytes(output, self.0.as_slice());
    }

    fn decode(decoder: &mut cbor::Decoder<'_>) -> Result<Self, CapsuleError> {
        let bytes = decoder
            .bytes(INVITE_CAPABILITY_BYTES)?
            .try_into()
            .map_err(|_| CapsuleError::Invalid)?;
        Self::new(bytes)
    }
}
