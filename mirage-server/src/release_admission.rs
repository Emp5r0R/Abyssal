use abyssal_core::release_provenance::{
    parse_release_build_id, release_trust_anchor_configured,
    verify_release_manifest_with_embedded_key, VerifiedReleaseManifest,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use reqwest::{redirect, Client, Response, Url};
use serde::Deserialize;
use std::{fmt, time::Duration};
use tokio::sync::RwLock;

const RELEASE_API_URL: &str = "https://api.github.com/repos/Emp5r0R/Abyssal/releases/latest";
const RELEASE_MANIFEST_ASSET: &str = "release-manifest-v1.json";
const RELEASE_SIGNATURE_ASSET: &str = "release-manifest-v1.sig";
const MAX_RELEASE_API_BYTES: usize = 512 * 1024;
const MAX_RELEASE_MANIFEST_BYTES: usize = 256 * 1024;
const RELEASE_SIGNATURE_BYTES: usize = 64;
const MAX_REDIRECTS: usize = 3;
const FETCH_TIMEOUT: Duration = Duration::from_secs(12);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BuildAttestationRequest {
    pub(crate) platform: String,
    pub(crate) version: String,
    pub(crate) build_signature_b64: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdmissionError {
    Unavailable,
    Expired,
    InvalidBuild,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InstallOutcome {
    Installed,
    Unchanged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InstallError {
    Rollback,
    SequenceConflict,
}

#[derive(Default)]
pub(crate) struct ReleaseAdmissionStore {
    current: RwLock<Option<VerifiedReleaseManifest>>,
}

impl ReleaseAdmissionStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) async fn admit(
        &self,
        request: &BuildAttestationRequest,
        now_ms: u64,
    ) -> Result<(), AdmissionError> {
        let build_id = format!("{}@{}", request.platform, request.version);
        parse_release_build_id(build_id.clone()).map_err(|_| AdmissionError::InvalidBuild)?;
        let presented_signature = URL_SAFE_NO_PAD
            .decode(&request.build_signature_b64)
            .ok()
            .filter(|decoded| URL_SAFE_NO_PAD.encode(decoded) == request.build_signature_b64)
            .and_then(|decoded| <[u8; RELEASE_SIGNATURE_BYTES]>::try_from(decoded).ok())
            .ok_or(AdmissionError::InvalidBuild)?;

        let guard = self.current.read().await;
        let manifest = guard.as_ref().ok_or(AdmissionError::Unavailable)?;
        if now_ms < manifest.not_before_ms {
            return Err(AdmissionError::Unavailable);
        }
        if now_ms >= manifest.expires_at_ms {
            return Err(AdmissionError::Expired);
        }
        if manifest.is_revoked(&build_id) {
            return Err(AdmissionError::InvalidBuild);
        }
        let current = manifest
            .build_for_platform(&request.platform)
            .filter(|build| build.build_id.version == request.version)
            .ok_or(AdmissionError::InvalidBuild)?;
        if current.build_signature != presented_signature {
            return Err(AdmissionError::InvalidBuild);
        }
        Ok(())
    }

    pub(crate) async fn install(
        &self,
        manifest: VerifiedReleaseManifest,
    ) -> Result<InstallOutcome, InstallError> {
        let mut guard = self.current.write().await;
        if let Some(current) = guard.as_ref() {
            if manifest.sequence < current.sequence {
                return Err(InstallError::Rollback);
            }
            if manifest.sequence == current.sequence {
                return if manifest.canonical_json == current.canonical_json {
                    Ok(InstallOutcome::Unchanged)
                } else {
                    Err(InstallError::SequenceConflict)
                };
            }
        }
        *guard = Some(manifest);
        Ok(InstallOutcome::Installed)
    }

    #[cfg(test)]
    pub(crate) async fn install_for_test(&self, manifest: VerifiedReleaseManifest) {
        *self.current.write().await = Some(manifest);
    }

    #[cfg(test)]
    pub(crate) fn ready_for_tests() -> Self {
        use abyssal_core::release_provenance::{ReleaseBuildId, VerifiedReleaseBuild};

        Self {
            current: RwLock::new(Some(VerifiedReleaseManifest {
                canonical_json: b"test".to_vec(),
                sequence: 1,
                issued_at_ms: 0,
                not_before_ms: 0,
                expires_at_ms: u64::MAX,
                builds: vec![
                    VerifiedReleaseBuild {
                        build_id: ReleaseBuildId {
                            platform: "android".to_string(),
                            version: "2.1.0".to_string(),
                        },
                        source_commit: "11".repeat(20),
                        build_signature: [1; RELEASE_SIGNATURE_BYTES],
                        assets: Vec::new(),
                    },
                    VerifiedReleaseBuild {
                        build_id: ReleaseBuildId {
                            platform: "web".to_string(),
                            version: "2.1.0".to_string(),
                        },
                        source_commit: "11".repeat(20),
                        build_signature: [2; RELEASE_SIGNATURE_BYTES],
                        assets: Vec::new(),
                    },
                ],
                revoked_build_ids: Vec::new(),
            })),
        }
    }
}

#[cfg(feature = "integration-release-root")]
pub(crate) async fn install_integration_manifest_from_env(
    store: &ReleaseAdmissionStore,
    now_ms: u64,
) -> Result<bool, RefreshError> {
    use std::{env, fs, path::Path};

    let manifest_path = match env::var("ABYSSAL_INTEGRATION_RELEASE_MANIFEST") {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    let signature_path = env::var("ABYSSAL_INTEGRATION_RELEASE_SIGNATURE")
        .map_err(|_| RefreshError::InvalidResponse)?;
    fn read_regular(path: &str, maximum: usize) -> Result<Vec<u8>, RefreshError> {
        let path = Path::new(path);
        let metadata = fs::symlink_metadata(path).map_err(|_| RefreshError::InvalidResponse)?;
        if !metadata.file_type().is_file() || metadata.len() > maximum as u64 {
            return Err(RefreshError::InvalidResponse);
        }
        let bytes = fs::read(path).map_err(|_| RefreshError::InvalidResponse)?;
        if bytes.is_empty() || bytes.len() > maximum {
            return Err(RefreshError::InvalidResponse);
        }
        Ok(bytes)
    }
    let manifest = read_regular(&manifest_path, MAX_RELEASE_MANIFEST_BYTES)?;
    let signature = read_regular(&signature_path, RELEASE_SIGNATURE_BYTES)?;
    if signature.len() != RELEASE_SIGNATURE_BYTES {
        return Err(RefreshError::InvalidResponse);
    }
    let verified = verify_release_manifest_with_embedded_key(&manifest, &signature, now_ms)
        .map_err(|_| RefreshError::InvalidManifest)?;
    store
        .install(verified)
        .await
        .map_err(|_| RefreshError::Rollback)?;
    Ok(true)
}

#[derive(Clone)]
pub(crate) struct ReleaseManifestMirror {
    client: Client,
}

#[derive(Debug)]
pub(crate) enum RefreshError {
    RootUnavailable,
    ClientConfiguration,
    Request,
    InvalidResponse,
    InvalidManifest,
    Rollback,
}

impl fmt::Display for RefreshError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RootUnavailable => "release trust root unavailable",
            Self::ClientConfiguration => "release mirror client unavailable",
            Self::Request => "release mirror request failed",
            Self::InvalidResponse => "release mirror response invalid",
            Self::InvalidManifest => "release manifest invalid",
            Self::Rollback => "release manifest rollback rejected",
        })
    }
}

impl ReleaseManifestMirror {
    pub(crate) fn new() -> Result<Self, RefreshError> {
        let policy = redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= MAX_REDIRECTS || !trusted_release_url(attempt.url()) {
                attempt.stop()
            } else {
                attempt.follow()
            }
        });
        let client = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(policy)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(FETCH_TIMEOUT)
            .user_agent("Abyssal-Relay-Release-Mirror/1")
            .build()
            .map_err(|_| RefreshError::ClientConfiguration)?;
        Ok(Self { client })
    }

    pub(crate) async fn refresh(
        &self,
        store: &ReleaseAdmissionStore,
        now_ms: u64,
    ) -> Result<InstallOutcome, RefreshError> {
        if !release_trust_anchor_configured() {
            return Err(RefreshError::RootUnavailable);
        }
        let api_url = Url::parse(RELEASE_API_URL).map_err(|_| RefreshError::ClientConfiguration)?;
        if !trusted_release_url(&api_url) {
            return Err(RefreshError::ClientConfiguration);
        }
        let api_response = self
            .client
            .get(api_url)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .send()
            .await
            .map_err(|_| RefreshError::Request)?;
        let api_bytes = bounded_body(api_response, MAX_RELEASE_API_BYTES).await?;
        let assets = release_asset_urls(&api_bytes)?;

        let manifest_response = self
            .client
            .get(assets.manifest)
            .send()
            .await
            .map_err(|_| RefreshError::Request)?;
        let manifest = bounded_body(manifest_response, MAX_RELEASE_MANIFEST_BYTES).await?;
        let signature_response = self
            .client
            .get(assets.signature)
            .send()
            .await
            .map_err(|_| RefreshError::Request)?;
        let signature = bounded_body(signature_response, RELEASE_SIGNATURE_BYTES).await?;
        if signature.len() != RELEASE_SIGNATURE_BYTES {
            return Err(RefreshError::InvalidResponse);
        }

        let verified = verify_release_manifest_with_embedded_key(&manifest, &signature, now_ms)
            .map_err(|_| RefreshError::InvalidManifest)?;
        store.install(verified).await.map_err(|error| match error {
            InstallError::Rollback | InstallError::SequenceConflict => RefreshError::Rollback,
        })
    }
}

#[derive(Deserialize)]
struct GithubRelease {
    draft: bool,
    prerelease: bool,
    assets: Vec<GithubAsset>,
}

#[derive(Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

struct ReleaseAssetUrls {
    manifest: Url,
    signature: Url,
}

fn release_asset_urls(body: &[u8]) -> Result<ReleaseAssetUrls, RefreshError> {
    let release: GithubRelease =
        serde_json::from_slice(body).map_err(|_| RefreshError::InvalidResponse)?;
    if release.draft || release.prerelease || release.assets.len() > 128 {
        return Err(RefreshError::InvalidResponse);
    }
    let mut manifest = None;
    let mut signature = None;
    for asset in release.assets {
        let destination = match asset.name.as_str() {
            RELEASE_MANIFEST_ASSET => &mut manifest,
            RELEASE_SIGNATURE_ASSET => &mut signature,
            _ => continue,
        };
        if destination.is_some() {
            return Err(RefreshError::InvalidResponse);
        }
        let url = Url::parse(&asset.browser_download_url)
            .ok()
            .filter(trusted_release_url)
            .filter(|url| {
                url.host_str() == Some("github.com")
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.port().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none()
            })
            .ok_or(RefreshError::InvalidResponse)?;
        *destination = Some(url);
    }
    Ok(ReleaseAssetUrls {
        manifest: manifest.ok_or(RefreshError::InvalidResponse)?,
        signature: signature.ok_or(RefreshError::InvalidResponse)?,
    })
}

fn trusted_release_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && matches!(
            url.host_str(),
            Some(
                "api.github.com"
                    | "github.com"
                    | "release-assets.githubusercontent.com"
                    | "objects.githubusercontent.com"
            )
        )
}

async fn bounded_body(mut response: Response, maximum: usize) -> Result<Vec<u8>, RefreshError> {
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|length| length > maximum as u64)
    {
        return Err(RefreshError::InvalidResponse);
    }
    let mut body = Vec::with_capacity(response.content_length().unwrap_or(0) as usize);
    while let Some(chunk) = response.chunk().await.map_err(|_| RefreshError::Request)? {
        if body.len().saturating_add(chunk.len()) > maximum {
            return Err(RefreshError::InvalidResponse);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use abyssal_core::release_provenance::{
        ReleaseBuildId, VerifiedReleaseBuild, VerifiedReleaseManifest,
    };

    fn manifest(sequence: u64, canonical: &[u8]) -> VerifiedReleaseManifest {
        VerifiedReleaseManifest {
            canonical_json: canonical.to_vec(),
            sequence,
            issued_at_ms: 900,
            not_before_ms: 1_000,
            expires_at_ms: 2_000,
            builds: vec![
                VerifiedReleaseBuild {
                    build_id: ReleaseBuildId {
                        platform: "android".to_string(),
                        version: "2.1.0".to_string(),
                    },
                    source_commit: "11".repeat(20),
                    build_signature: [1; RELEASE_SIGNATURE_BYTES],
                    assets: Vec::new(),
                },
                VerifiedReleaseBuild {
                    build_id: ReleaseBuildId {
                        platform: "web".to_string(),
                        version: "2.1.0".to_string(),
                    },
                    source_commit: "11".repeat(20),
                    build_signature: [2; RELEASE_SIGNATURE_BYTES],
                    assets: Vec::new(),
                },
            ],
            revoked_build_ids: Vec::new(),
        }
    }

    fn request(platform: &str, version: &str, signature: [u8; 64]) -> BuildAttestationRequest {
        BuildAttestationRequest {
            platform: platform.to_string(),
            version: version.to_string(),
            build_signature_b64: URL_SAFE_NO_PAD.encode(signature),
        }
    }

    #[tokio::test]
    async fn admission_is_strict_current_only_and_fails_closed() {
        let store = ReleaseAdmissionStore::new();
        let valid = request("web", "2.1.0", [2; 64]);
        assert_eq!(
            store.admit(&valid, 1_500).await,
            Err(AdmissionError::Unavailable)
        );
        store.install_for_test(manifest(1, b"one")).await;
        assert_eq!(
            store.admit(&valid, 999).await,
            Err(AdmissionError::Unavailable)
        );
        assert_eq!(
            store.admit(&valid, 2_000).await,
            Err(AdmissionError::Expired)
        );
        assert_eq!(store.admit(&valid, 1_500).await, Ok(()));
        assert_eq!(
            store.admit(&request("web", "2.0.0", [2; 64]), 1_500).await,
            Err(AdmissionError::InvalidBuild)
        );
        assert_eq!(
            store
                .admit(&request("android", "2.1.0", [2; 64]), 1_500)
                .await,
            Err(AdmissionError::InvalidBuild)
        );
        assert_eq!(
            store.admit(&request("web", "2.1.0", [3; 64]), 1_500).await,
            Err(AdmissionError::InvalidBuild)
        );
        assert_eq!(
            store
                .admit(
                    &BuildAttestationRequest {
                        platform: "web".to_string(),
                        version: "2.1.0".to_string(),
                        build_signature_b64: "garbage".to_string(),
                    },
                    1_500,
                )
                .await,
            Err(AdmissionError::InvalidBuild)
        );
    }

    #[tokio::test]
    async fn install_is_monotonic_and_same_sequence_must_be_identical() {
        let store = ReleaseAdmissionStore::new();
        assert_eq!(
            store.install(manifest(2, b"two")).await,
            Ok(InstallOutcome::Installed)
        );
        assert_eq!(
            store.install(manifest(2, b"two")).await,
            Ok(InstallOutcome::Unchanged)
        );
        assert_eq!(
            store.install(manifest(1, b"one")).await,
            Err(InstallError::Rollback)
        );
        assert_eq!(
            store.install(manifest(2, b"altered")).await,
            Err(InstallError::SequenceConflict)
        );
        assert_eq!(
            store.install(manifest(3, b"three")).await,
            Ok(InstallOutcome::Installed)
        );
    }

    #[tokio::test]
    async fn revoked_current_build_is_rejected() {
        let store = ReleaseAdmissionStore::new();
        let mut revoked = manifest(1, b"one");
        revoked.revoked_build_ids.push("web@2.1.0".to_string());
        store.install_for_test(revoked).await;
        assert_eq!(
            store.admit(&request("web", "2.1.0", [2; 64]), 1_500).await,
            Err(AdmissionError::InvalidBuild)
        );
    }

    #[test]
    fn release_urls_are_https_host_pinned_and_assets_are_exact() {
        for accepted in [
            "https://api.github.com/repos/Emp5r0R/Abyssal/releases/latest",
            "https://github.com/Emp5r0R/Abyssal/releases/download/v2/a",
            "https://release-assets.githubusercontent.com/github-production-release-asset/a",
            "https://objects.githubusercontent.com/github-production-release-asset/a",
        ] {
            assert!(trusted_release_url(
                &Url::parse(accepted).expect("accepted URL")
            ));
        }
        for rejected in [
            "http://github.com/a",
            "https://github.com.evil.example/a",
            "https://user@github.com/a",
            "https://github.com:444/a",
            "https://raw.githubusercontent.com/a",
        ] {
            assert!(!trusted_release_url(
                &Url::parse(rejected).expect("rejected URL")
            ));
        }

        let valid = br#"{"draft":false,"prerelease":false,"assets":[{"name":"release-manifest-v1.json","browser_download_url":"https://github.com/Emp5r0R/Abyssal/releases/download/v2/release-manifest-v1.json"},{"name":"release-manifest-v1.sig","browser_download_url":"https://github.com/Emp5r0R/Abyssal/releases/download/v2/release-manifest-v1.sig"}]}"#;
        assert!(release_asset_urls(valid).is_ok());

        let duplicate = br#"{"draft":false,"prerelease":false,"assets":[{"name":"release-manifest-v1.json","browser_download_url":"https://github.com/a"},{"name":"release-manifest-v1.json","browser_download_url":"https://github.com/b"},{"name":"release-manifest-v1.sig","browser_download_url":"https://github.com/c"}]}"#;
        assert!(release_asset_urls(duplicate).is_err());
        let untrusted = br#"{"draft":false,"prerelease":false,"assets":[{"name":"release-manifest-v1.json","browser_download_url":"https://evil.example/a"},{"name":"release-manifest-v1.sig","browser_download_url":"https://github.com/c"}]}"#;
        assert!(release_asset_urls(untrusted).is_err());
    }
}
