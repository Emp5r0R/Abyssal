use invite_capsule::CapsuleError;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum InviteError {
    #[error("invalid invite")]
    Invalid,
    #[error("invite is too large")]
    TooLarge,
    #[error("unsupported invite version")]
    UnsupportedVersion,
    #[error("invite belongs to another application")]
    WrongApplication,
    #[error("unsupported invite capability")]
    UnsupportedCapability,
    #[error("invite signature is invalid")]
    InvalidSignature,
    #[error("invite has expired")]
    Expired,
    #[error("unsupported transport")]
    UnsupportedTransport,
    #[error("unsafe node locator")]
    UnsafeLocator,
    #[error("invite checksum is invalid")]
    InvalidChecksum,
    #[error("node identity does not match invite")]
    NodeIdentityMismatch,
    #[error("node descriptor is invalid")]
    InvalidDescriptor,
}

impl InviteError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Invalid => "INVALID_INVITE",
            Self::TooLarge => "INVITE_TOO_LARGE",
            Self::UnsupportedVersion => "UNSUPPORTED_INVITE_VERSION",
            Self::WrongApplication => "WRONG_APPLICATION",
            Self::UnsupportedCapability => "UNSUPPORTED_CAPABILITY",
            Self::InvalidSignature => "INVALID_INVITE_SIGNATURE",
            Self::Expired => "INVITE_EXPIRED",
            Self::UnsupportedTransport => "UNSUPPORTED_TRANSPORT",
            Self::UnsafeLocator => "UNSAFE_LOCATOR",
            Self::InvalidChecksum => "INVALID_CHECKSUM",
            Self::NodeIdentityMismatch => "NODE_IDENTITY_MISMATCH",
            Self::InvalidDescriptor => "INVALID_NODE_DESCRIPTOR",
        }
    }
}

/// Maps the shared format's reasons onto Abyssal's stable codes.
impl From<CapsuleError> for InviteError {
    fn from(error: CapsuleError) -> Self {
        match error {
            CapsuleError::Invalid | CapsuleError::InvalidNodeKey => Self::Invalid,
            CapsuleError::TooLarge => Self::TooLarge,
            CapsuleError::UnsupportedVersion => Self::UnsupportedVersion,
            CapsuleError::WrongApplication => Self::WrongApplication,
            CapsuleError::UnsupportedCapability => Self::UnsupportedCapability,
            CapsuleError::InvalidSignature => Self::InvalidSignature,
            CapsuleError::Expired => Self::Expired,
            CapsuleError::UnsupportedLocator => Self::UnsupportedTransport,
            CapsuleError::UnsafeLocator => Self::UnsafeLocator,
            CapsuleError::NodeIdentityMismatch => Self::NodeIdentityMismatch,
            CapsuleError::InvalidChecksum => Self::InvalidChecksum,
        }
    }
}
