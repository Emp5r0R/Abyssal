//! Node infrastructure identity and one-shot bootstrap invitation issuance.

use abyssal_invite::{
    derive_node_id, encode_deep_link, encode_manual, generate_capability, locator_from_public_url,
    node_key_fingerprint, node_signing_key_from_seed, InviteCapsuleV1, NodeDescriptorV1,
    NodeLocator, SignedInviteCapsule, SignedNodeDescriptor, DIRECT_PROTOCOL_VERSION,
    ROOM_PROTOCOL_VERSION,
};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{
    env,
    fs::OpenOptions,
    io::{self, Read, Write},
    path::Path,
};
use zeroize::{Zeroize, Zeroizing};

const NODE_KEY_BYTES: usize = 32;
const DEFAULT_INVITE_COUNT: usize = 5;
const MAX_INVITE_COUNT: usize = 256;
const MAX_INVITE_EXPIRY_HOURS: u64 = 24 * 365;

pub(super) struct IssuedInvite {
    pub(super) capability: Zeroizing<[u8; 32]>,
    pub(super) expires_at: Option<u64>,
    deep_link: Zeroizing<String>,
    manual: Zeroizing<String>,
}

pub(super) struct BootstrapMaterials {
    pub(super) node_id: String,
    pub(super) node_public_key: [u8; 32],
    pub(super) descriptor_binary: Vec<u8>,
    pub(super) issued_invites: Vec<IssuedInvite>,
    pub(super) locator: NodeLocator,
    pub(super) fingerprint: String,
}

impl BootstrapMaterials {
    pub(super) fn from_env(now_unix_seconds: u64) -> Result<Self, String> {
        let key_path = env::var("ABYSSAL_NODE_SIGNING_KEY_FILE")
            .map_err(|_| "ABYSSAL_NODE_SIGNING_KEY_FILE is required".to_owned())?;
        let public_url = env::var("ABYSSAL_PUBLIC_URL")
            .map_err(|_| "ABYSSAL_PUBLIC_URL is required".to_owned())?;
        let signing_key = load_node_signing_key(Path::new(&key_path))?;
        let node_public_key = signing_key.verifying_key().to_bytes();
        let node_id = derive_node_id(&node_public_key);
        let fingerprint = node_key_fingerprint(&node_public_key);
        let locator = locator_from_public_url(&public_url)
            .map_err(|_| "ABYSSAL_PUBLIC_URL is not an allowed V1 locator".to_owned())?;
        let locators = vec![locator.clone()];
        let descriptor = NodeDescriptorV1::abyssal(node_public_key, locators.clone())
            .map_err(|_| "failed to create node descriptor".to_owned())?;
        let descriptor_binary = SignedNodeDescriptor::sign(descriptor, &signing_key)
            .and_then(|value| value.canonical_binary())
            .map_err(|_| "failed to sign node descriptor".to_owned())?;
        let count = read_count_env_alias(
            "ABYSSAL_INVITE_COUNT",
            "ABYSSAL_CODE_COUNT",
            DEFAULT_INVITE_COUNT,
            MAX_INVITE_COUNT,
        )?;
        let expiry_hours = read_count_env(
            "ABYSSAL_INVITE_EXPIRY_HOURS",
            0,
            MAX_INVITE_EXPIRY_HOURS as usize,
        )? as u64;
        let expires_at = if expiry_hours == 0 {
            None
        } else {
            Some(
                now_unix_seconds
                    .checked_add(expiry_hours.saturating_mul(60 * 60))
                    .ok_or_else(|| "ABYSSAL_INVITE_EXPIRY_HOURS overflows time".to_owned())?,
            )
        };

        let mut issued_invites = Vec::with_capacity(count);
        for _ in 0..count {
            let capability = generate_capability();
            let capsule = InviteCapsuleV1::abyssal(
                node_public_key,
                locators.clone(),
                *capability,
                DIRECT_PROTOCOL_VERSION,
                ROOM_PROTOCOL_VERSION,
                expires_at,
            )
            .map_err(|_| "failed to create invite capsule".to_owned())?;
            let signed = SignedInviteCapsule::sign(capsule, &signing_key)
                .map_err(|_| "failed to sign invite capsule".to_owned())?;
            issued_invites.push(IssuedInvite {
                capability,
                expires_at,
                deep_link: Zeroizing::new(
                    encode_deep_link(&signed)
                        .map_err(|_| "failed to encode invite deep link".to_owned())?,
                ),
                manual: Zeroizing::new(
                    encode_manual(&signed)
                        .map_err(|_| "failed to encode manual invite".to_owned())?,
                ),
            });
        }

        Ok(Self {
            node_id,
            node_public_key,
            descriptor_binary,
            issued_invites,
            locator,
            fingerprint,
        })
    }
}

pub(super) fn write_boot_invites<W: Write>(
    output: &mut W,
    invites: &[IssuedInvite],
) -> io::Result<()> {
    writeln!(
        output,
        "ABYSSAL RAM-ONLY INVITES - copy these now; they cannot be recovered"
    )?;
    for invite in invites {
        writeln!(output, "ABYSSAL_INVITE invite={}", invite.manual.as_str())?;
        writeln!(
            output,
            "ABYSSAL_INVITE_DEEP_LINK invite={}",
            invite.deep_link.as_str()
        )?;
    }
    output.flush()
}

fn read_count_env(key: &str, fallback: usize, maximum: usize) -> Result<usize, String> {
    match env::var(key) {
        Ok(value) => value
            .parse::<usize>()
            .ok()
            .filter(|value| *value <= maximum)
            .ok_or_else(|| format!("{key} must be an integer between 0 and {maximum}")),
        Err(env::VarError::NotPresent) => Ok(fallback),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{key} is not valid UTF-8")),
    }
}

fn read_count_env_alias(
    key: &str,
    legacy_key: &str,
    fallback: usize,
    maximum: usize,
) -> Result<usize, String> {
    if env::var_os(key).is_some() {
        read_count_env(key, fallback, maximum)
    } else {
        read_count_env(legacy_key, fallback, maximum)
    }
}

fn load_node_signing_key(path: &Path) -> Result<ed25519_dalek::SigningKey, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .map_err(|_| "node signing key cannot be opened".to_owned())?;
    let metadata = file
        .metadata()
        .map_err(|_| "node signing key file cannot be inspected".to_owned())?;
    if !metadata.file_type().is_file() {
        return Err("node signing key must be a regular non-symlink file".to_owned());
    }
    if metadata.len() != NODE_KEY_BYTES as u64 {
        return Err("node signing key file must contain exactly 32 raw bytes".to_owned());
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err("node signing key permissions must not grant group/other access".to_owned());
    }
    let mut seed = Zeroizing::new([0_u8; NODE_KEY_BYTES]);
    file.read_exact(seed.as_mut())
        .map_err(|_| "node signing key cannot be read".to_owned())?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| "node signing key cannot be read".to_owned())?
        != 0
    {
        trailing.zeroize();
        return Err("node signing key file must contain exactly 32 raw bytes".to_owned());
    }
    trailing.zeroize();
    Ok(node_signing_key_from_seed(&seed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn key_loader_accepts_exact_private_regular_file() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("node.key");
        fs::write(&path, [7_u8; NODE_KEY_BYTES]).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let key = load_node_signing_key(&path).unwrap();
        assert_ne!(key.verifying_key().to_bytes(), [0_u8; 32]);
    }

    #[test]
    fn key_loader_rejects_wrong_size_and_permissions() {
        let directory = tempdir().unwrap();
        let short = directory.path().join("short.key");
        fs::write(&short, [7_u8; NODE_KEY_BYTES - 1]).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&short, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_node_signing_key(&short).is_err());

        #[cfg(unix)]
        {
            let exposed = directory.path().join("exposed.key");
            fs::write(&exposed, [7_u8; NODE_KEY_BYTES]).unwrap();
            fs::set_permissions(&exposed, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(load_node_signing_key(&exposed).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn key_loader_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let target = directory.path().join("target.key");
        let link = directory.path().join("link.key");
        fs::write(&target, [7_u8; NODE_KEY_BYTES]).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &link).unwrap();
        assert!(load_node_signing_key(&link).is_err());
    }

    #[test]
    fn startup_output_contains_only_encoded_invites() {
        let key = node_signing_key_from_seed(&[3_u8; 32]);
        let capability = Zeroizing::new([5_u8; 32]);
        let capsule = InviteCapsuleV1::abyssal(
            key.verifying_key().to_bytes(),
            vec![locator_from_public_url("https://node.example.com").unwrap()],
            *capability,
            DIRECT_PROTOCOL_VERSION,
            ROOM_PROTOCOL_VERSION,
            None,
        )
        .unwrap();
        let signed = SignedInviteCapsule::sign(capsule, &key).unwrap();
        let invite = IssuedInvite {
            capability,
            expires_at: None,
            deep_link: Zeroizing::new(encode_deep_link(&signed).unwrap()),
            manual: Zeroizing::new(encode_manual(&signed).unwrap()),
        };
        let mut output = Vec::new();
        write_boot_invites(&mut output, &[invite]).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("ABYSSAL_INVITE invite=ABY1-"));
        assert!(text.contains("ABYSSAL_INVITE_DEEP_LINK invite=abyssal:invite:"));
        assert!(!text.contains("05050505"));
    }
}
