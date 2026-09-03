//! Canonical, signed Abyssal bootstrap invitations.
//!
//! This crate deliberately owns no networking, account, OPAQUE, UI, or
//! transport implementation. It turns untrusted invitation text into a
//! bounded, authenticated protocol object and keeps locator selection separate
//! from parsing so future transports do not change capability semantics.

mod capsule;
mod codec;
mod descriptor;
mod error;
mod locator;
mod signing;
mod text;

pub use capsule::{
    account_context_v1, generate_capability, InviteCapabilityType, InviteCapsuleV1,
    SignedInviteCapsule, ABYSSAL_APPLICATION_ID, INVITE_CAPABILITY_BYTES, INVITE_FORMAT_VERSION,
    MAX_BINARY_INVITE_BYTES, MAX_ENCODED_INVITE_TEXT_BYTES,
};
pub use descriptor::{NodeDescriptorV1, SignedNodeDescriptor};
pub use error::InviteError;
pub use locator::{
    locator_from_public_url, select_locator, LoopbackHost, NodeLocator, RuntimeLocatorPolicy,
    SupportedTransports, MAX_LOCATORS,
};
pub use signing::{
    derive_node_id, generate_node_signing_key, node_key_fingerprint, node_signing_key_from_seed,
};
pub use text::{decode_invite_text, encode_deep_link, encode_manual};

pub const DIRECT_PROTOCOL_VERSION: u16 = 9;
pub const ROOM_PROTOCOL_VERSION: u16 = 10;
