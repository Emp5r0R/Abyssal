//! Canonical, signed Abyssal bootstrap invitations.
//!
//! The invite format itself (canonical CBOR, signatures, locators, text forms)
//! is the `invite-capsule` crate shared with Ket; this crate is Abyssal's
//! profile of it plus Abyssal's node descriptors and locator selection.
//!
//! This crate deliberately owns no networking, account, OPAQUE, UI, or
//! transport implementation. It turns untrusted invitation text into a
//! bounded, authenticated protocol object and keeps locator selection separate
//! from parsing so future transports do not change capability semantics.

mod capsule;
mod descriptor;
mod error;
mod locator;
mod profile;
mod signing;
mod text;

pub use capsule::{
    account_context_v1, generate_capability, InviteCapabilityType, InviteCapsuleV1,
    SignedInviteCapsule,
};
pub use descriptor::{
    NodeDescriptorV1, NodeDescriptorV2, SignedNodeDescriptor, SignedNodeDescriptorV2,
    MAX_BINARY_DESCRIPTOR_BYTES,
};
pub use error::InviteError;
pub use invite_capsule::{MAX_BINARY_INVITE_BYTES, MAX_ENCODED_INVITE_TEXT_BYTES};
pub use locator::{
    locator_from_public_url, select_locator, LoopbackHost, NodeLocator, RuntimeLocatorPolicy,
    SupportedTransports, MAX_LOCATORS,
};
pub use profile::{
    AbyssalInvite, BootstrapCapability, ABYSSAL_APPLICATION_ID, INVITE_CAPABILITY_BYTES,
};
pub use signing::{
    derive_node_id, generate_node_signing_key, node_key_fingerprint, node_signing_key_from_seed,
};
pub use text::{decode_invite_text, encode_deep_link, encode_manual};

/// The shared invite format version, as the `u8` node descriptors carry.
pub const INVITE_FORMAT_VERSION: u8 = 1;
const _: () = assert!(INVITE_FORMAT_VERSION as u64 == invite_capsule::INVITE_FORMAT_VERSION);

pub const DIRECT_PROTOCOL_VERSION: u16 = 9;
pub const ROOM_PROTOCOL_VERSION: u16 = 10;
pub const TRANSPORT_PROTOCOL_VERSION: u16 = 11;
