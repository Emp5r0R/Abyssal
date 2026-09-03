//! Shared client-side Invite Capsule parsing and node verification boundary.

use crate::AbyssalError;
use abyssal_invite::{
    account_context_v1, decode_invite_text, derive_node_id, locator_from_public_url,
    select_locator, InviteError, RuntimeLocatorPolicy, SignedNodeDescriptor, SupportedTransports,
    DIRECT_PROTOCOL_VERSION, ROOM_PROTOCOL_VERSION,
};
use zeroize::Zeroize;

#[derive(Clone, Debug, uniffi::Record)]
pub struct ParsedInvite {
    pub node_id: String,
    pub node_public_key: Vec<u8>,
    pub node_url: String,
    pub capability: Vec<u8>,
    pub account_context: Vec<u8>,
    pub expires_at: Option<u64>,
}

#[uniffi::export]
pub fn parse_invite_capsule(
    mut invite_text: String,
    now_unix_seconds: u64,
    allow_development_loopback: bool,
) -> Result<ParsedInvite, AbyssalError> {
    let result = parse_invite_inner(&invite_text, now_unix_seconds, allow_development_loopback);
    invite_text.zeroize();
    result
}

fn parse_invite_inner(
    invite_text: &str,
    now_unix_seconds: u64,
    allow_development_loopback: bool,
) -> Result<ParsedInvite, AbyssalError> {
    let invite = decode_invite_text(invite_text, Some(now_unix_seconds)).map_err(map_error)?;
    if invite.capsule.protocol_min > DIRECT_PROTOCOL_VERSION
        || invite.capsule.protocol_max < ROOM_PROTOCOL_VERSION
    {
        return Err(failure("Unsupported invite protocol"));
    }
    let supported = if allow_development_loopback {
        SupportedTransports::DEVELOPMENT
    } else {
        SupportedTransports::PRODUCTION
    };
    let policy = if allow_development_loopback {
        RuntimeLocatorPolicy::ExplicitDevelopment
    } else {
        RuntimeLocatorPolicy::Production
    };
    let locator = select_locator(&invite.capsule.locators, supported, policy).map_err(map_error)?;
    let capability = invite.capsule.capability.to_vec();
    let account_context =
        account_context_v1(&invite.capsule.node_public_key, &invite.capsule.capability).to_vec();
    Ok(ParsedInvite {
        node_id: derive_node_id(&invite.capsule.node_public_key),
        node_public_key: invite.capsule.node_public_key.to_vec(),
        node_url: locator.api_base_url(),
        capability,
        account_context,
        expires_at: invite.capsule.expires_at,
    })
}

#[uniffi::export]
pub fn verify_invite_node_descriptor(
    descriptor: Vec<u8>,
    expected_node_public_key: Vec<u8>,
    expected_node_url: String,
) -> Result<(), AbyssalError> {
    if expected_node_public_key.len() != 32 {
        return Err(failure("Node identity mismatch"));
    }
    let mut expected_key = [0_u8; 32];
    expected_key.copy_from_slice(&expected_node_public_key);
    let locator = locator_from_public_url(&expected_node_url).map_err(map_error)?;
    let result = SignedNodeDescriptor::decode_for_invite(&descriptor, &expected_key, &locator)
        .map(|_| ())
        .map_err(map_error);
    expected_key.zeroize();
    result
}

#[cfg(target_arch = "wasm32")]
fn js_error(error: impl core::fmt::Display) -> wasm_bindgen::JsValue {
    wasm_bindgen::JsValue::from_str(&error.to_string())
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(js_name = parseInviteCapsule)]
pub fn wasm_parse_invite_capsule(
    invite_text: String,
    now_unix_seconds: u64,
    allow_development_loopback: bool,
) -> Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue> {
    let mut parsed =
        parse_invite_capsule(invite_text, now_unix_seconds, allow_development_loopback)
            .map_err(js_error)?;
    let output = js_sys::Object::new();
    let result = (|| {
        set_js_value(
            &output,
            "node_id",
            wasm_bindgen::JsValue::from_str(&parsed.node_id),
        )?;
        set_js_value(
            &output,
            "node_public_key",
            js_sys::Uint8Array::from(parsed.node_public_key.as_slice()).into(),
        )?;
        set_js_value(
            &output,
            "node_url",
            wasm_bindgen::JsValue::from_str(&parsed.node_url),
        )?;
        set_js_value(
            &output,
            "capability",
            js_sys::Uint8Array::from(parsed.capability.as_slice()).into(),
        )?;
        set_js_value(
            &output,
            "account_context",
            js_sys::Uint8Array::from(parsed.account_context.as_slice()).into(),
        )?;
        set_js_value(
            &output,
            "expires_at",
            parsed
                .expires_at
                .map(|value| wasm_bindgen::JsValue::from_f64(value as f64))
                .unwrap_or(wasm_bindgen::JsValue::NULL),
        )?;
        Ok(output.into())
    })();
    parsed.capability.zeroize();
    parsed.account_context.zeroize();
    result
}

#[cfg(target_arch = "wasm32")]
fn set_js_value(
    output: &js_sys::Object,
    name: &str,
    value: wasm_bindgen::JsValue,
) -> Result<(), wasm_bindgen::JsValue> {
    js_sys::Reflect::set(output, &wasm_bindgen::JsValue::from_str(name), &value)
        .map(|_| ())
        .map_err(|_| wasm_bindgen::JsValue::from_str("Unable to return parsed invite"))
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(js_name = verifyInviteNodeDescriptor)]
pub fn wasm_verify_invite_node_descriptor(
    descriptor: Vec<u8>,
    expected_node_public_key: Vec<u8>,
    expected_node_url: String,
) -> Result<(), wasm_bindgen::JsValue> {
    verify_invite_node_descriptor(descriptor, expected_node_public_key, expected_node_url)
        .map_err(js_error)
}

fn map_error(error: InviteError) -> AbyssalError {
    let detail = match error {
        InviteError::UnsupportedVersion => "Unsupported invite version",
        InviteError::WrongApplication => "Invite belongs to another application",
        InviteError::InvalidSignature => "Invite signature invalid",
        InviteError::Expired => "Invite expired",
        InviteError::UnsupportedTransport => "Unsupported invite transport",
        InviteError::NodeIdentityMismatch | InviteError::InvalidDescriptor => {
            "Node identity mismatch"
        }
        InviteError::InvalidChecksum => "Invite checksum invalid",
        InviteError::TooLarge
        | InviteError::Invalid
        | InviteError::UnsafeLocator
        | InviteError::UnsupportedCapability => "Invalid invite",
    };
    failure(detail)
}

fn failure(detail: &str) -> AbyssalError {
    AbyssalError::Failure {
        detail: detail.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abyssal_invite::{
        encode_deep_link, locator_from_public_url, node_signing_key_from_seed, InviteCapsuleV1,
        NodeDescriptorV1, SignedInviteCapsule, SignedNodeDescriptor,
    };

    fn fixture() -> (String, Vec<u8>) {
        let key = node_signing_key_from_seed(&[7_u8; 32]);
        let locator = locator_from_public_url("https://node.example.com").unwrap();
        let capsule = InviteCapsuleV1::abyssal(
            key.verifying_key().to_bytes(),
            vec![locator.clone()],
            [9_u8; 32],
            DIRECT_PROTOCOL_VERSION,
            ROOM_PROTOCOL_VERSION,
            Some(2_000_000_000),
        )
        .unwrap();
        let invite = SignedInviteCapsule::sign(capsule, &key).unwrap();
        let descriptor = NodeDescriptorV1::abyssal(key.verifying_key().to_bytes(), vec![locator])
            .and_then(|descriptor| SignedNodeDescriptor::sign(descriptor, &key))
            .and_then(|descriptor| descriptor.canonical_binary())
            .unwrap();
        (encode_deep_link(&invite).unwrap(), descriptor)
    }

    #[test]
    fn shared_parser_returns_network_and_credential_material() {
        let (invite, descriptor) = fixture();
        let parsed = parse_invite_capsule(invite, 1_900_000_000, false).unwrap();
        assert_eq!(parsed.node_url, "https://node.example.com");
        assert_eq!(parsed.capability, vec![9_u8; 32]);
        assert_eq!(parsed.account_context.len(), 32);
        verify_invite_node_descriptor(descriptor, parsed.node_public_key, parsed.node_url).unwrap();
    }

    #[test]
    fn descriptor_mismatch_fails_closed() {
        let (invite, descriptor) = fixture();
        let parsed = parse_invite_capsule(invite, 1_900_000_000, false).unwrap();
        assert!(
            verify_invite_node_descriptor(descriptor, vec![8_u8; 32], parsed.node_url,).is_err()
        );
    }
}
