use crate::AbyssalError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fmt};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

pub use crate::release_root::RELEASE_PUBKEY;

pub const RELEASE_MANIFEST_SCHEMA: &str = "abyssal-release-manifest-v1";
pub const RELEASE_PROJECT: &str = "Emp5r0R/Abyssal";
pub const RELEASE_CHANNEL: &str = "stable";

const MANIFEST_DOMAIN: &[u8] = b"ABYSSAL-RELEASE-MANIFEST-V1\0";
const BUILD_DOMAIN: &[u8] = b"ABYSSAL-RELEASE-BUILD-V1\0";
const MAX_MANIFEST_BYTES: usize = 256 * 1024;
const MAX_BUILDS: usize = 2;
pub const MAX_ASSETS_PER_BUILD: usize = 128;
const MAX_REVOKED_BUILDS: usize = 128;
const MAX_ASSET_BYTES: u64 = 512 * 1024 * 1024;
const MAX_MANIFEST_LIFETIME_MS: u64 = 35 * 24 * 60 * 60 * 1000;
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, uniffi::Record)]
pub struct ReleaseBuildId {
    pub platform: String,
    pub version: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAssetDocument {
    pub name: String,
    pub sha256_hex: String,
    pub size: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseBuildDocument {
    pub build_id: String,
    pub source_commit: String,
    pub build_signature_b64: String,
    pub assets: Vec<ReleaseAssetDocument>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifestDocument {
    pub schema: String,
    pub project: String,
    pub channel: String,
    pub sequence: String,
    pub issued_at_ms: String,
    pub not_before_ms: String,
    pub expires_at_ms: String,
    pub builds: Vec<ReleaseBuildDocument>,
    pub revoked_build_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedReleaseAsset {
    pub name: String,
    pub sha256: [u8; 32],
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedReleaseBuild {
    pub build_id: ReleaseBuildId,
    pub source_commit: String,
    pub build_signature: [u8; 64],
    pub assets: Vec<VerifiedReleaseAsset>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedReleaseManifest {
    pub canonical_json: Vec<u8>,
    pub sequence: u64,
    pub issued_at_ms: u64,
    pub not_before_ms: u64,
    pub expires_at_ms: u64,
    pub builds: Vec<VerifiedReleaseBuild>,
    pub revoked_build_ids: Vec<String>,
}

impl VerifiedReleaseManifest {
    pub fn build_for_platform(&self, platform: &str) -> Option<&VerifiedReleaseBuild> {
        self.builds
            .iter()
            .find(|build| build.build_id.platform == platform)
    }

    pub fn is_revoked(&self, build_id: &str) -> bool {
        self.revoked_build_ids
            .binary_search_by(|candidate| candidate.as_str().cmp(build_id))
            .is_ok()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseVerificationError {
    RootNotConfigured,
    ManifestTooLarge,
    MalformedManifest,
    NonCanonicalManifest,
    InvalidManifestSignature,
    InvalidManifestPolicy,
    ManifestNotActive,
    ManifestExpired,
    InvalidBuildId,
    InvalidBuildSignature,
}

impl fmt::Display for ReleaseVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RootNotConfigured => "release trust root is not configured",
            Self::ManifestTooLarge => "release manifest exceeds its size limit",
            Self::MalformedManifest => "release manifest is malformed",
            Self::NonCanonicalManifest => "release manifest is not canonical",
            Self::InvalidManifestSignature => "release manifest signature is invalid",
            Self::InvalidManifestPolicy => "release manifest violates policy",
            Self::ManifestNotActive => "release manifest is not active",
            Self::ManifestExpired => "release manifest has expired",
            Self::InvalidBuildId => "release build identifier is invalid",
            Self::InvalidBuildSignature => "release build signature is invalid",
        })
    }
}

impl std::error::Error for ReleaseVerificationError {}

#[uniffi::export]
pub fn release_trust_anchor_configured() -> bool {
    RELEASE_PUBKEY.iter().any(|byte| *byte != 0)
}

#[uniffi::export]
pub fn parse_release_build_id(build_id: String) -> Result<ReleaseBuildId, AbyssalError> {
    parse_build_id(&build_id).map_err(public_error)
}

#[uniffi::export]
pub fn release_sha256(data: Vec<u8>) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

#[uniffi::export]
pub fn verify_release_build_signature(
    build_id: String,
    source_commit: String,
    signature: Vec<u8>,
) -> Result<(), AbyssalError> {
    let key = embedded_release_key().map_err(public_error)?;
    verify_build_signature_with_key(&key, &build_id, &source_commit, &signature)
        .map_err(public_error)
}

#[uniffi::export]
pub fn verify_release_manifest(
    manifest_json: Vec<u8>,
    signature: Vec<u8>,
    now_ms: u64,
) -> Result<String, AbyssalError> {
    let verified = verify_release_manifest_with_embedded_key(&manifest_json, &signature, now_ms)
        .map_err(public_error)?;
    String::from_utf8(verified.canonical_json)
        .map_err(|_| public_error(ReleaseVerificationError::MalformedManifest))
}

/// Verifies signature, canonical encoding, build signatures, and manifest
/// policy without accepting it for use at any wall-clock time. Callers must
/// enforce `not_before_ms` and `expires_at_ms` from the returned document.
#[uniffi::export]
pub fn inspect_release_manifest(
    manifest_json: Vec<u8>,
    signature: Vec<u8>,
) -> Result<String, AbyssalError> {
    let verified = inspect_release_manifest_with_embedded_key(&manifest_json, &signature)
        .map_err(public_error)?;
    String::from_utf8(verified.canonical_json)
        .map_err(|_| public_error(ReleaseVerificationError::MalformedManifest))
}

pub fn verify_release_manifest_with_embedded_key(
    manifest_json: &[u8],
    signature: &[u8],
    now_ms: u64,
) -> Result<VerifiedReleaseManifest, ReleaseVerificationError> {
    let key = embedded_release_key()?;
    verify_release_manifest_with_key(&key, manifest_json, signature, now_ms)
}

pub fn inspect_release_manifest_with_embedded_key(
    manifest_json: &[u8],
    signature: &[u8],
) -> Result<VerifiedReleaseManifest, ReleaseVerificationError> {
    let key = embedded_release_key()?;
    inspect_release_manifest_with_key(&key, manifest_json, signature)
}

pub fn verify_release_manifest_with_key(
    key: &VerifyingKey,
    manifest_json: &[u8],
    signature: &[u8],
    now_ms: u64,
) -> Result<VerifiedReleaseManifest, ReleaseVerificationError> {
    let (document, canonical) = parse_canonical_manifest(manifest_json)?;

    verify_signature(
        key,
        &manifest_transcript(manifest_json),
        signature,
        ReleaseVerificationError::InvalidManifestSignature,
    )?;
    validate_manifest(key, document, canonical, now_ms)
}

pub fn inspect_release_manifest_with_key(
    key: &VerifyingKey,
    manifest_json: &[u8],
    signature: &[u8],
) -> Result<VerifiedReleaseManifest, ReleaseVerificationError> {
    let (document, canonical) = parse_canonical_manifest(manifest_json)?;
    verify_signature(
        key,
        &manifest_transcript(manifest_json),
        signature,
        ReleaseVerificationError::InvalidManifestSignature,
    )?;
    let not_before_ms = parse_decimal(&document.not_before_ms, true)?;
    validate_manifest(key, document, canonical, not_before_ms)
}

pub fn validate_release_manifest_for_signing_with_key(
    key: &VerifyingKey,
    manifest_json: &[u8],
) -> Result<VerifiedReleaseManifest, ReleaseVerificationError> {
    let (document, canonical) = parse_canonical_manifest(manifest_json)?;
    let not_before_ms = parse_decimal(&document.not_before_ms, true)?;
    validate_manifest(key, document, canonical, not_before_ms)
}

pub fn verify_build_signature_with_key(
    key: &VerifyingKey,
    build_id: &str,
    source_commit: &str,
    signature: &[u8],
) -> Result<(), ReleaseVerificationError> {
    parse_build_id(build_id)?;
    validate_source_commit(source_commit)?;
    verify_signature(
        key,
        &build_transcript(build_id, source_commit),
        signature,
        ReleaseVerificationError::InvalidBuildSignature,
    )
}

pub fn canonical_manifest_bytes(
    document: &ReleaseManifestDocument,
) -> Result<Vec<u8>, ReleaseVerificationError> {
    serde_json::to_vec(document).map_err(|_| ReleaseVerificationError::MalformedManifest)
}

pub fn manifest_signing_transcript(manifest_json: &[u8]) -> Vec<u8> {
    manifest_transcript(manifest_json)
}

pub fn build_signing_transcript(
    build_id: &str,
    source_commit: &str,
) -> Result<Vec<u8>, ReleaseVerificationError> {
    parse_build_id(build_id)?;
    validate_source_commit(source_commit)?;
    Ok(build_transcript(build_id, source_commit))
}

fn embedded_release_key() -> Result<VerifyingKey, ReleaseVerificationError> {
    if !release_trust_anchor_configured() {
        return Err(ReleaseVerificationError::RootNotConfigured);
    }
    VerifyingKey::from_bytes(&RELEASE_PUBKEY)
        .map_err(|_| ReleaseVerificationError::RootNotConfigured)
}

fn parse_canonical_manifest(
    manifest_json: &[u8],
) -> Result<(ReleaseManifestDocument, Vec<u8>), ReleaseVerificationError> {
    if manifest_json.is_empty() || manifest_json.len() > MAX_MANIFEST_BYTES {
        return Err(ReleaseVerificationError::ManifestTooLarge);
    }
    let document: ReleaseManifestDocument = serde_json::from_slice(manifest_json)
        .map_err(|_| ReleaseVerificationError::MalformedManifest)?;
    let canonical =
        serde_json::to_vec(&document).map_err(|_| ReleaseVerificationError::MalformedManifest)?;
    if canonical != manifest_json {
        return Err(ReleaseVerificationError::NonCanonicalManifest);
    }
    Ok((document, canonical))
}

fn validate_manifest(
    key: &VerifyingKey,
    document: ReleaseManifestDocument,
    canonical_json: Vec<u8>,
    now_ms: u64,
) -> Result<VerifiedReleaseManifest, ReleaseVerificationError> {
    if document.schema != RELEASE_MANIFEST_SCHEMA
        || document.project != RELEASE_PROJECT
        || document.channel != RELEASE_CHANNEL
        || document.builds.len() != MAX_BUILDS
        || document.revoked_build_ids.len() > MAX_REVOKED_BUILDS
    {
        return Err(ReleaseVerificationError::InvalidManifestPolicy);
    }

    let sequence = parse_decimal(&document.sequence, false)?;
    let issued_at_ms = parse_decimal(&document.issued_at_ms, true)?;
    let not_before_ms = parse_decimal(&document.not_before_ms, true)?;
    let expires_at_ms = parse_decimal(&document.expires_at_ms, true)?;
    if issued_at_ms > not_before_ms
        || not_before_ms >= expires_at_ms
        || expires_at_ms.saturating_sub(issued_at_ms) > MAX_MANIFEST_LIFETIME_MS
    {
        return Err(ReleaseVerificationError::InvalidManifestPolicy);
    }
    if now_ms < not_before_ms {
        return Err(ReleaseVerificationError::ManifestNotActive);
    }
    if now_ms >= expires_at_ms {
        return Err(ReleaseVerificationError::ManifestExpired);
    }

    let mut builds = Vec::with_capacity(document.builds.len());
    let mut platforms = HashSet::with_capacity(document.builds.len());
    let mut prior_build_id: Option<&str> = None;
    for build in &document.builds {
        if prior_build_id.is_some_and(|prior| prior >= build.build_id.as_str()) {
            return Err(ReleaseVerificationError::InvalidManifestPolicy);
        }
        prior_build_id = Some(&build.build_id);

        let build_id = parse_build_id(&build.build_id)?;
        if !platforms.insert(build_id.platform.clone())
            || build.assets.is_empty()
            || build.assets.len() > MAX_ASSETS_PER_BUILD
        {
            return Err(ReleaseVerificationError::InvalidManifestPolicy);
        }
        validate_source_commit(&build.source_commit)?;
        let build_signature = decode_exact_signature(&build.build_signature_b64)?;
        verify_build_signature_with_key(
            key,
            &build.build_id,
            &build.source_commit,
            &build_signature,
        )?;

        let mut assets = Vec::with_capacity(build.assets.len());
        let mut prior_asset_name: Option<&str> = None;
        for asset in &build.assets {
            if prior_asset_name.is_some_and(|prior| prior >= asset.name.as_str()) {
                return Err(ReleaseVerificationError::InvalidManifestPolicy);
            }
            prior_asset_name = Some(&asset.name);
            if !valid_asset_name(&asset.name) {
                return Err(ReleaseVerificationError::InvalidManifestPolicy);
            }
            let sha256 = decode_lower_hex_32(&asset.sha256_hex)?;
            let size = parse_decimal(&asset.size, false)?;
            if size > MAX_ASSET_BYTES {
                return Err(ReleaseVerificationError::InvalidManifestPolicy);
            }
            assets.push(VerifiedReleaseAsset {
                name: asset.name.clone(),
                sha256,
                size,
            });
        }
        builds.push(VerifiedReleaseBuild {
            build_id,
            source_commit: build.source_commit.clone(),
            build_signature,
            assets,
        });
    }
    if platforms.len() != MAX_BUILDS || !platforms.contains("android") || !platforms.contains("web")
    {
        return Err(ReleaseVerificationError::InvalidManifestPolicy);
    }

    let mut prior_revoked: Option<&str> = None;
    for revoked in &document.revoked_build_ids {
        if prior_revoked.is_some_and(|prior| prior >= revoked.as_str()) {
            return Err(ReleaseVerificationError::InvalidManifestPolicy);
        }
        prior_revoked = Some(revoked);
        parse_build_id(revoked)?;
    }

    Ok(VerifiedReleaseManifest {
        canonical_json,
        sequence,
        issued_at_ms,
        not_before_ms,
        expires_at_ms,
        builds,
        revoked_build_ids: document.revoked_build_ids,
    })
}

fn parse_build_id(value: &str) -> Result<ReleaseBuildId, ReleaseVerificationError> {
    if value.is_empty() || value.len() > 64 || !value.is_ascii() {
        return Err(ReleaseVerificationError::InvalidBuildId);
    }
    let (platform, version) = value
        .split_once('@')
        .ok_or(ReleaseVerificationError::InvalidBuildId)?;
    if value.matches('@').count() != 1 || !matches!(platform, "android" | "web") {
        return Err(ReleaseVerificationError::InvalidBuildId);
    }
    let mut parts = version.split('.');
    for _ in 0..3 {
        let part = parts
            .next()
            .ok_or(ReleaseVerificationError::InvalidBuildId)?;
        if part.is_empty()
            || !part.bytes().all(|byte| byte.is_ascii_digit())
            || (part.len() > 1 && part.starts_with('0'))
            || part
                .parse::<u32>()
                .ok()
                .filter(|number| *number <= 1_000_000)
                .is_none()
        {
            return Err(ReleaseVerificationError::InvalidBuildId);
        }
    }
    if parts.next().is_some() {
        return Err(ReleaseVerificationError::InvalidBuildId);
    }
    Ok(ReleaseBuildId {
        platform: platform.to_string(),
        version: version.to_string(),
    })
}

fn parse_decimal(value: &str, allow_zero: bool) -> Result<u64, ReleaseVerificationError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(ReleaseVerificationError::InvalidManifestPolicy);
    }
    let parsed = value
        .parse::<u64>()
        .ok()
        .filter(|number| *number <= MAX_SAFE_JSON_INTEGER)
        .ok_or(ReleaseVerificationError::InvalidManifestPolicy)?;
    if !allow_zero && parsed == 0 {
        return Err(ReleaseVerificationError::InvalidManifestPolicy);
    }
    Ok(parsed)
}

fn validate_source_commit(value: &str) -> Result<(), ReleaseVerificationError> {
    if value.len() == 40 && is_lower_hex(value) {
        Ok(())
    } else {
        Err(ReleaseVerificationError::InvalidBuildSignature)
    }
}

fn valid_asset_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 192
        && !value.starts_with('/')
        && value.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && !component.starts_with('.')
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
}

fn decode_lower_hex_32(value: &str) -> Result<[u8; 32], ReleaseVerificationError> {
    if value.len() != 64 || !is_lower_hex(value) {
        return Err(ReleaseVerificationError::InvalidManifestPolicy);
    }
    let mut output = [0_u8; 32];
    for (index, slot) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *slot =
            (hex_nibble(value.as_bytes()[offset]) << 4) | hex_nibble(value.as_bytes()[offset + 1]);
    }
    Ok(output)
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => 0,
    }
}

fn decode_exact_signature(value: &str) -> Result<[u8; 64], ReleaseVerificationError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ReleaseVerificationError::InvalidBuildSignature)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(ReleaseVerificationError::InvalidBuildSignature);
    }
    decoded
        .try_into()
        .map_err(|_| ReleaseVerificationError::InvalidBuildSignature)
}

fn verify_signature(
    key: &VerifyingKey,
    message: &[u8],
    signature: &[u8],
    error: ReleaseVerificationError,
) -> Result<(), ReleaseVerificationError> {
    let signature = Signature::from_slice(signature).map_err(|_| error)?;
    key.verify_strict(message, &signature).map_err(|_| error)
}

fn manifest_transcript(manifest_json: &[u8]) -> Vec<u8> {
    transcript(MANIFEST_DOMAIN, &[manifest_json])
}

fn build_transcript(build_id: &str, source_commit: &str) -> Vec<u8> {
    transcript(
        BUILD_DOMAIN,
        &[
            RELEASE_PROJECT.as_bytes(),
            RELEASE_CHANNEL.as_bytes(),
            build_id.as_bytes(),
            source_commit.as_bytes(),
        ],
    )
}

fn transcript(domain: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let capacity = domain.len()
        + fields
            .iter()
            .map(|field| 8_usize.saturating_add(field.len()))
            .sum::<usize>();
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(domain);
    for field in fields {
        output.extend_from_slice(&(field.len() as u64).to_be_bytes());
        output.extend_from_slice(field);
    }
    output
}

fn public_error(_: ReleaseVerificationError) -> AbyssalError {
    AbyssalError::Failure {
        detail: "Release verification failed".to_string(),
    }
}

#[cfg(target_arch = "wasm32")]
fn js_error(error: impl fmt::Display) -> JsValue {
    JsValue::from_str(&error.to_string())
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = releaseTrustAnchorConfigured)]
pub fn wasm_release_trust_anchor_configured() -> bool {
    release_trust_anchor_configured()
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = parseReleaseBuildId)]
pub fn wasm_parse_release_build_id(build_id: String) -> Result<String, JsValue> {
    let parsed = parse_release_build_id(build_id).map_err(js_error)?;
    serde_json::to_string(&parsed).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = releaseSha256)]
pub fn wasm_release_sha256(data: Vec<u8>) -> Vec<u8> {
    release_sha256(data)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = verifyReleaseBuildSignature)]
pub fn wasm_verify_release_build_signature(
    build_id: String,
    source_commit: String,
    signature: Vec<u8>,
) -> Result<(), JsValue> {
    verify_release_build_signature(build_id, source_commit, signature).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = verifyReleaseManifest)]
pub fn wasm_verify_release_manifest(
    manifest_json: Vec<u8>,
    signature: Vec<u8>,
    now_ms: u64,
) -> Result<String, JsValue> {
    verify_release_manifest(manifest_json, signature, now_ms).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = inspectReleaseManifest)]
pub fn wasm_inspect_release_manifest(
    manifest_json: Vec<u8>,
    signature: Vec<u8>,
) -> Result<String, JsValue> {
    inspect_release_manifest(manifest_json, signature).map_err(js_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const NOW_MS: u64 = 1_800_000_000_000;
    const SOURCE_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7_u8; 32])
    }

    fn asset(name: &str, byte: u8) -> ReleaseAssetDocument {
        ReleaseAssetDocument {
            name: name.to_string(),
            sha256_hex: format!("{byte:02x}").repeat(32),
            size: "1048576".to_string(),
        }
    }

    fn build(
        key: &SigningKey,
        build_id: &str,
        assets: Vec<ReleaseAssetDocument>,
    ) -> ReleaseBuildDocument {
        let signature = key.sign(&build_transcript(build_id, SOURCE_COMMIT));
        ReleaseBuildDocument {
            build_id: build_id.to_string(),
            source_commit: SOURCE_COMMIT.to_string(),
            build_signature_b64: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            assets,
        }
    }

    fn document(key: &SigningKey) -> ReleaseManifestDocument {
        ReleaseManifestDocument {
            schema: RELEASE_MANIFEST_SCHEMA.to_string(),
            project: RELEASE_PROJECT.to_string(),
            channel: RELEASE_CHANNEL.to_string(),
            sequence: "42".to_string(),
            issued_at_ms: (NOW_MS - 1_000).to_string(),
            not_before_ms: (NOW_MS - 500).to_string(),
            expires_at_ms: (NOW_MS + 60_000).to_string(),
            builds: vec![
                build(key, "android@2.1.0", vec![asset("abyssal.apk", 0x11)]),
                build(key, "web@2.1.0", vec![asset("abyssal-web.tar.zst", 0x22)]),
            ],
            revoked_build_ids: vec!["android@1.9.0".to_string()],
        }
    }

    fn signed_manifest(key: &SigningKey) -> (Vec<u8>, Vec<u8>) {
        let manifest = canonical_manifest_bytes(&document(key)).expect("canonical manifest");
        let signature = key
            .sign(&manifest_transcript(&manifest))
            .to_bytes()
            .to_vec();
        (manifest, signature)
    }

    #[test]
    fn build_id_parser_accepts_only_canonical_platform_semver() {
        assert_eq!(
            parse_build_id("android@2.1.0"),
            Ok(ReleaseBuildId {
                platform: "android".to_string(),
                version: "2.1.0".to_string(),
            })
        );
        assert!(parse_build_id("web@0.0.0").is_ok());
        for invalid in [
            "",
            "desktop@2.1.0",
            "android@v2.1.0",
            "android@02.1.0",
            "android@2.1",
            "android@2.1.0-beta",
            "android@2.1.0@web",
            "android @2.1.0",
            "ANDROID@2.1.0",
            "web@1000001.0.0",
        ] {
            assert_eq!(
                parse_build_id(invalid),
                Err(ReleaseVerificationError::InvalidBuildId)
            );
        }
    }

    #[test]
    fn sha256_matches_known_answer() {
        assert_eq!(
            release_sha256(b"abc".to_vec()),
            vec![
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn valid_manifest_round_trips_and_indexes_current_builds() {
        let key = signing_key();
        let (manifest, signature) = signed_manifest(&key);
        let verified =
            verify_release_manifest_with_key(&key.verifying_key(), &manifest, &signature, NOW_MS)
                .expect("valid manifest");
        assert_eq!(verified.sequence, 42);
        assert_eq!(verified.canonical_json, manifest);
        assert_eq!(
            verified
                .build_for_platform("android")
                .map(|build| build.build_id.version.as_str()),
            Some("2.1.0")
        );
        assert!(verified.is_revoked("android@1.9.0"));
        assert!(!verified.is_revoked("android@2.1.0"));
    }

    #[test]
    fn manifest_asset_limit_matches_complete_web_bundle_attestation() {
        let key = signing_key();
        let mut document = document(&key);
        document.builds[1].assets = (0..MAX_ASSETS_PER_BUILD)
            .map(|index| asset(&format!("assets/bundle-{index:03}.gif"), index as u8))
            .collect();

        let manifest = canonical_manifest_bytes(&document).expect("bounded manifest");
        let signature = key.sign(&manifest_transcript(&manifest)).to_bytes();
        let verified =
            verify_release_manifest_with_key(&key.verifying_key(), &manifest, &signature, NOW_MS)
                .expect("manifest at asset limit");
        assert_eq!(
            verified
                .build_for_platform("web")
                .expect("web build")
                .assets
                .len(),
            MAX_ASSETS_PER_BUILD
        );

        document.builds[1].assets.push(asset(
            &format!("assets/bundle-{:03}.gif", MAX_ASSETS_PER_BUILD),
            0xff,
        ));
        let oversized = canonical_manifest_bytes(&document).expect("oversized manifest encoding");
        let oversized_signature = key.sign(&manifest_transcript(&oversized)).to_bytes();
        assert_eq!(
            verify_release_manifest_with_key(
                &key.verifying_key(),
                &oversized,
                &oversized_signature,
                NOW_MS,
            ),
            Err(ReleaseVerificationError::InvalidManifestPolicy)
        );
    }

    #[test]
    fn manifest_rejects_wrong_key_signature_and_trailing_bytes() {
        let key = signing_key();
        let wrong_key = SigningKey::from_bytes(&[8_u8; 32]);
        let (manifest, signature) = signed_manifest(&key);
        assert_eq!(
            verify_release_manifest_with_key(
                &wrong_key.verifying_key(),
                &manifest,
                &signature,
                NOW_MS,
            ),
            Err(ReleaseVerificationError::InvalidManifestSignature)
        );

        let mut tampered_signature = signature.clone();
        tampered_signature[0] ^= 1;
        assert_eq!(
            verify_release_manifest_with_key(
                &key.verifying_key(),
                &manifest,
                &tampered_signature,
                NOW_MS,
            ),
            Err(ReleaseVerificationError::InvalidManifestSignature)
        );

        let mut trailing = manifest.clone();
        trailing.push(b'\n');
        assert_eq!(
            verify_release_manifest_with_key(&key.verifying_key(), &trailing, &signature, NOW_MS,),
            Err(ReleaseVerificationError::NonCanonicalManifest)
        );
    }

    #[test]
    fn manifest_freshness_boundaries_fail_closed() {
        let key = signing_key();
        let (manifest, signature) = signed_manifest(&key);
        assert_eq!(
            verify_release_manifest_with_key(
                &key.verifying_key(),
                &manifest,
                &signature,
                NOW_MS - 501,
            ),
            Err(ReleaseVerificationError::ManifestNotActive)
        );
        assert!(verify_release_manifest_with_key(
            &key.verifying_key(),
            &manifest,
            &signature,
            NOW_MS + 59_999,
        )
        .is_ok());
        assert_eq!(
            verify_release_manifest_with_key(
                &key.verifying_key(),
                &manifest,
                &signature,
                NOW_MS + 60_000,
            ),
            Err(ReleaseVerificationError::ManifestExpired)
        );
    }

    #[test]
    fn inspection_authenticates_expired_manifest_without_admitting_it() {
        let key = SigningKey::from_bytes(&[7_u8; 32]);
        let manifest = canonical_manifest_bytes(&document(&key)).expect("manifest");
        let signature = key.sign(&manifest_signing_transcript(&manifest));
        let inspected = inspect_release_manifest_with_key(
            &key.verifying_key(),
            &manifest,
            &signature.to_bytes(),
        )
        .expect("inspect signed manifest");
        assert_eq!(inspected.expires_at_ms, 1_800_000_060_000);
        assert_eq!(
            verify_release_manifest_with_key(
                &key.verifying_key(),
                &manifest,
                &signature.to_bytes(),
                inspected.expires_at_ms,
            ),
            Err(ReleaseVerificationError::ManifestExpired)
        );

        let mut tampered = signature.to_bytes();
        tampered[0] ^= 1;
        assert_eq!(
            inspect_release_manifest_with_key(&key.verifying_key(), &manifest, &tampered),
            Err(ReleaseVerificationError::InvalidManifestSignature)
        );
    }

    #[test]
    fn malformed_unknown_duplicate_and_reordered_fields_are_rejected() {
        let key = signing_key();
        let (manifest, signature) = signed_manifest(&key);
        assert_eq!(
            verify_release_manifest_with_key(&key.verifying_key(), b"{", &signature, NOW_MS,),
            Err(ReleaseVerificationError::MalformedManifest)
        );

        let mut unknown = serde_json::to_value(document(&key)).expect("value");
        unknown
            .as_object_mut()
            .expect("object")
            .insert("extra".to_string(), serde_json::json!(true));
        let unknown = serde_json::to_vec(&unknown).expect("json");
        let unknown_signature = key.sign(&manifest_transcript(&unknown)).to_bytes();
        assert_eq!(
            verify_release_manifest_with_key(
                &key.verifying_key(),
                &unknown,
                &unknown_signature,
                NOW_MS,
            ),
            Err(ReleaseVerificationError::MalformedManifest)
        );

        let duplicate = format!(
            "{{\"project\":\"{}\",{}}}",
            RELEASE_PROJECT,
            String::from_utf8(manifest.clone()).expect("utf8")[1..].trim_end_matches('}')
        );
        let duplicate_signature = key
            .sign(&manifest_transcript(duplicate.as_bytes()))
            .to_bytes();
        assert_eq!(
            verify_release_manifest_with_key(
                &key.verifying_key(),
                duplicate.as_bytes(),
                &duplicate_signature,
                NOW_MS,
            ),
            Err(ReleaseVerificationError::MalformedManifest)
        );

        let reordered =
            serde_json::to_vec(&serde_json::to_value(document(&key)).expect("manifest value"))
                .expect("reordered json");
        assert_ne!(reordered, manifest);
        let reordered_signature = key.sign(&manifest_transcript(&reordered)).to_bytes();
        assert_eq!(
            verify_release_manifest_with_key(
                &key.verifying_key(),
                &reordered,
                &reordered_signature,
                NOW_MS,
            ),
            Err(ReleaseVerificationError::NonCanonicalManifest)
        );
    }

    #[test]
    fn build_signatures_bind_platform_version_and_source_commit() {
        let key = signing_key();
        let signature = key
            .sign(&build_transcript("android@2.1.0", SOURCE_COMMIT))
            .to_bytes();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
            "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw"
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(signature),
            "17NNIR4TNcwGxI-7dpnK3fr0lr6IDgOLVWTbcDzp8cFkNP0X_9bOZpSKnqpRUpdd9adhPF7eqEfJwC7H9TGkBw"
        );
        assert!(verify_build_signature_with_key(
            &key.verifying_key(),
            "android@2.1.0",
            SOURCE_COMMIT,
            &signature,
        )
        .is_ok());
        assert_eq!(
            verify_build_signature_with_key(
                &key.verifying_key(),
                "web@2.1.0",
                SOURCE_COMMIT,
                &signature,
            ),
            Err(ReleaseVerificationError::InvalidBuildSignature)
        );
        assert_eq!(
            verify_build_signature_with_key(
                &key.verifying_key(),
                "android@2.1.1",
                SOURCE_COMMIT,
                &signature,
            ),
            Err(ReleaseVerificationError::InvalidBuildSignature)
        );
    }

    #[test]
    fn embedded_root_never_accepts_unrelated_test_key() {
        let key = signing_key();
        let (manifest, signature) = signed_manifest(&key);
        assert!(verify_release_manifest(manifest, signature, NOW_MS).is_err());
    }

    #[test]
    fn manifest_policy_rejects_noncanonical_order_limits_and_bad_encoding() {
        let key = signing_key();
        let mut cases = Vec::new();

        let mut reversed_builds = document(&key);
        reversed_builds.builds.reverse();
        cases.push(reversed_builds);

        let mut duplicate_platform = document(&key);
        duplicate_platform.builds[1] =
            build(&key, "android@2.2.0", vec![asset("abyssal-new.apk", 0x33)]);
        cases.push(duplicate_platform);

        let mut unsorted_assets = document(&key);
        unsorted_assets.builds[0].assets = vec![asset("z.apk", 1), asset("a.apk", 2)];
        cases.push(unsorted_assets);

        let mut bad_digest = document(&key);
        bad_digest.builds[0].assets[0].sha256_hex = "AA".repeat(32);
        cases.push(bad_digest);

        let mut unsafe_asset_path = document(&key);
        unsafe_asset_path.builds[1].assets[0].name = "assets/../index.js".to_string();
        cases.push(unsafe_asset_path);

        let mut bad_decimal = document(&key);
        bad_decimal.sequence = "042".to_string();
        cases.push(bad_decimal);

        let mut long_lived = document(&key);
        long_lived.expires_at_ms = (NOW_MS + MAX_MANIFEST_LIFETIME_MS + 1).to_string();
        cases.push(long_lived);

        for document in cases {
            let manifest = canonical_manifest_bytes(&document).expect("json");
            let signature = key.sign(&manifest_transcript(&manifest)).to_bytes();
            assert!(verify_release_manifest_with_key(
                &key.verifying_key(),
                &manifest,
                &signature,
                NOW_MS,
            )
            .is_err());
        }
    }
}
