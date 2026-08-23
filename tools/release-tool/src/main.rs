use abyssal_core::release_provenance::{
    build_signing_transcript, canonical_manifest_bytes, manifest_signing_transcript,
    validate_release_manifest_for_signing_with_key, verify_build_signature_with_key,
    ReleaseAssetDocument, ReleaseBuildDocument, ReleaseManifestDocument, RELEASE_CHANNEL,
    RELEASE_MANIFEST_SCHEMA, RELEASE_PROJECT, RELEASE_PUBKEY,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    env,
    fs::{self, File, OpenOptions},
    io::{self, BufReader, Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

const PRIVATE_KEY_BYTES: usize = 32;
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const MAX_BUILD_RECORD_BYTES: u64 = 64 * 1024;
const MAX_REVOCATION_FILE_BYTES: u64 = 16 * 1024;
const MAX_HASH_FILE_BYTES: u64 = 512 * 1024 * 1024;

struct BuildRecordArguments {
    options: BTreeMap<String, String>,
    assets: Vec<(String, PathBuf)>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("release-tool: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args().skip(1);
    let command = arguments.next().ok_or_else(usage)?;
    let remainder = arguments.collect::<Vec<_>>();
    match command.as_str() {
        "generate-key" => {
            let options = parse_options(&remainder, &["--private-key", "--public-key"])?;
            generate_key(
                path(&options, "--private-key")?,
                path(&options, "--public-key")?,
            )
        }
        "derive-public" => {
            let options = parse_options(&remainder, &["--private-key", "--public-key"])?;
            let key = read_private_key(path(&options, "--private-key")?)?;
            write_public_key(
                path(&options, "--public-key")?,
                &key.verifying_key().to_bytes(),
            )
        }
        "render-root" => {
            let options = parse_options(&remainder, &["--public-key", "--output"])?;
            let public_key = read_public_key(path(&options, "--public-key")?)?;
            write_new(
                path(&options, "--output")?,
                root_source(&public_key).as_bytes(),
                false,
            )
        }
        "fingerprint-public" => {
            let options = parse_options(&remainder, &["--public-key"])?;
            let public_key = read_public_key(path(&options, "--public-key")?)?;
            println!("{}", lower_hex(&Sha256::digest(public_key)));
            Ok(())
        }
        "check-root" => {
            let options = parse_options(&remainder, &["--private-key"])?;
            let key = read_private_key(path(&options, "--private-key")?)?;
            if RELEASE_PUBKEY.iter().all(|byte| *byte == 0)
                || key.verifying_key().to_bytes() != RELEASE_PUBKEY
            {
                return Err("compiled release root does not match the private key".to_string());
            }
            Ok(())
        }
        "sign-build" => {
            let options = parse_options(
                &remainder,
                &["--private-key", "--build-id", "--source-commit", "--output"],
            )?;
            sign_build(
                path(&options, "--private-key")?,
                value(&options, "--build-id")?,
                value(&options, "--source-commit")?,
                path(&options, "--output")?,
            )
        }
        "sign-manifest" => {
            let options = parse_options(
                &remainder,
                &["--private-key", "--manifest", "--signature-output"],
            )?;
            sign_manifest(
                path(&options, "--private-key")?,
                path(&options, "--manifest")?,
                path(&options, "--signature-output")?,
            )
        }
        "create-build-record" => create_build_record(&remainder),
        "assemble-manifest" => assemble_manifest(&remainder),
        "hash-file" => {
            let options = parse_options(&remainder, &["--input"])?;
            println!("{}", hash_file(path(&options, "--input")?)?);
            Ok(())
        }
        _ => Err(usage()),
    }
}

fn usage() -> String {
    "usage: abyssal-release-tool <generate-key|derive-public|render-root|fingerprint-public|check-root|sign-build|sign-manifest|create-build-record|assemble-manifest|hash-file> [options]".to_string()
}

fn parse_options(
    arguments: &[String],
    expected: &[&str],
) -> Result<BTreeMap<String, String>, String> {
    if arguments.len() != expected.len() * 2 {
        return Err(usage());
    }
    let expected = expected.iter().copied().collect::<HashSet<_>>();
    let mut parsed = BTreeMap::new();
    for pair in arguments.chunks_exact(2) {
        if !expected.contains(pair[0].as_str())
            || pair[1].is_empty()
            || parsed.insert(pair[0].clone(), pair[1].clone()).is_some()
        {
            return Err(usage());
        }
    }
    if parsed.len() != expected.len() {
        return Err(usage());
    }
    Ok(parsed)
}

fn value<'a>(options: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str, String> {
    options.get(name).map(String::as_str).ok_or_else(usage)
}

fn path(options: &BTreeMap<String, String>, name: &str) -> Result<PathBuf, String> {
    Ok(PathBuf::from(value(options, name)?))
}

fn generate_key(private_path: PathBuf, public_path: PathBuf) -> Result<(), String> {
    refuse_existing(&private_path)?;
    refuse_existing(&public_path)?;
    let signing_key = SigningKey::generate(&mut OsRng);
    write_new(&private_path, &signing_key.to_bytes(), true)?;
    if let Err(error) = write_public_key(public_path, &signing_key.verifying_key().to_bytes()) {
        return Err(format!(
            "private key was created but public-key write failed; recover it with derive-public: {error}"
        ));
    }
    eprintln!(
        "release public-key fingerprint: {}",
        lower_hex(&Sha256::digest(signing_key.verifying_key().to_bytes()))
    );
    Ok(())
}

fn sign_build(
    private_path: PathBuf,
    build_id: &str,
    source_commit: &str,
    output: PathBuf,
) -> Result<(), String> {
    let signing_key = read_private_key(private_path)?;
    let transcript =
        build_signing_transcript(build_id, source_commit).map_err(|error| error.to_string())?;
    let encoded = format!(
        "{}\n",
        URL_SAFE_NO_PAD.encode(signing_key.sign(&transcript).to_bytes())
    );
    write_new(output, encoded.as_bytes(), false)
}

fn sign_manifest(
    private_path: PathBuf,
    manifest_path: PathBuf,
    signature_output: PathBuf,
) -> Result<(), String> {
    let signing_key = read_private_key(private_path)?;
    let manifest = read_bounded(&manifest_path, MAX_MANIFEST_BYTES)?;
    validate_release_manifest_for_signing_with_key(&signing_key.verifying_key(), &manifest)
        .map_err(|error| error.to_string())?;
    let signature = signing_key.sign(&manifest_signing_transcript(&manifest));
    write_new(signature_output, &signature.to_bytes(), false)
}

fn create_build_record(arguments: &[String]) -> Result<(), String> {
    let parsed = parse_build_record_options(arguments)?;
    let options = parsed.options;
    let private_path = path(&options, "--private-key")?;
    let build_id = value(&options, "--build-id")?;
    let source_commit = value(&options, "--source-commit")?;
    let expected_signature_path = path(&options, "--expected-signature")?;
    let output = path(&options, "--output")?;
    refuse_existing(&output)?;

    let signing_key = read_private_key(private_path)?;
    let transcript =
        build_signing_transcript(build_id, source_commit).map_err(|error| error.to_string())?;
    let signature = signing_key.sign(&transcript).to_bytes();
    verify_build_signature_with_key(
        &signing_key.verifying_key(),
        build_id,
        source_commit,
        &signature,
    )
    .map_err(|error| error.to_string())?;
    let expected_signature = read_base64_signature(&expected_signature_path)?;
    if signature != expected_signature {
        return Err("embedded build signature does not match release key and metadata".to_string());
    }

    let mut assets = Vec::with_capacity(parsed.assets.len());
    for (name, input) in parsed.assets {
        let file = open_regular_nofollow(&input)?;
        let size = file.metadata().map_err(io_error("inspect asset"))?.len();
        drop(file);
        if size == 0 || size > MAX_HASH_FILE_BYTES {
            return Err("asset size is outside release limits".to_string());
        }
        assets.push(ReleaseAssetDocument {
            name,
            sha256_hex: hash_file(input)?,
            size: size.to_string(),
        });
    }
    assets.sort_by(|left, right| left.name.cmp(&right.name));
    if assets.windows(2).any(|pair| pair[0].name == pair[1].name) {
        return Err("release asset names must be unique".to_string());
    }
    let record = ReleaseBuildDocument {
        build_id: build_id.to_string(),
        source_commit: source_commit.to_string(),
        build_signature_b64: URL_SAFE_NO_PAD.encode(signature),
        assets,
    };
    let encoded = serde_json::to_vec(&record).map_err(|_| "encode build record".to_string())?;
    write_new(output, &encoded, false)
}

fn parse_build_record_options(arguments: &[String]) -> Result<BuildRecordArguments, String> {
    let expected = [
        "--private-key",
        "--build-id",
        "--source-commit",
        "--expected-signature",
        "--output",
    ];
    let mut options = BTreeMap::new();
    let mut assets = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        if arguments[index] == "--asset" {
            if index + 2 >= arguments.len()
                || arguments[index + 1].is_empty()
                || arguments[index + 2].is_empty()
            {
                return Err(usage());
            }
            assets.push((
                arguments[index + 1].clone(),
                PathBuf::from(&arguments[index + 2]),
            ));
            index += 3;
            continue;
        }
        if index + 1 >= arguments.len()
            || !expected.contains(&arguments[index].as_str())
            || arguments[index + 1].is_empty()
            || options
                .insert(arguments[index].clone(), arguments[index + 1].clone())
                .is_some()
        {
            return Err(usage());
        }
        index += 2;
    }
    if options.len() != expected.len() || assets.is_empty() || assets.len() > 16 {
        return Err(usage());
    }
    Ok(BuildRecordArguments { options, assets })
}

fn assemble_manifest(arguments: &[String]) -> Result<(), String> {
    let options = parse_options(
        arguments,
        &[
            "--private-key",
            "--sequence",
            "--issued-at-ms",
            "--not-before-ms",
            "--expires-at-ms",
            "--android-record",
            "--web-record",
            "--revocations",
            "--manifest-output",
            "--signature-output",
        ],
    )?;
    let manifest_output = path(&options, "--manifest-output")?;
    let signature_output = path(&options, "--signature-output")?;
    refuse_existing(&manifest_output)?;
    refuse_existing(&signature_output)?;
    let signing_key = read_private_key(path(&options, "--private-key")?)?;

    let mut builds = vec![
        read_build_record(&path(&options, "--android-record")?)?,
        read_build_record(&path(&options, "--web-record")?)?,
    ];
    builds.sort_by(|left, right| left.build_id.cmp(&right.build_id));
    let source_commit = builds[0].source_commit.as_str();
    let release_version = builds[0]
        .build_id
        .split_once('@')
        .map(|(_, version)| version)
        .ok_or_else(|| "build identifier is malformed".to_string())?;
    if builds.iter().any(|build| {
        build.source_commit != source_commit
            || build
                .build_id
                .split_once('@')
                .is_none_or(|(_, version)| version != release_version)
    }) {
        return Err(
            "Android and web records must bind the same version and source commit".to_string(),
        );
    }
    let revoked_build_ids = read_revocations(&path(&options, "--revocations")?)?;
    let document = ReleaseManifestDocument {
        schema: RELEASE_MANIFEST_SCHEMA.to_string(),
        project: RELEASE_PROJECT.to_string(),
        channel: RELEASE_CHANNEL.to_string(),
        sequence: value(&options, "--sequence")?.to_string(),
        issued_at_ms: value(&options, "--issued-at-ms")?.to_string(),
        not_before_ms: value(&options, "--not-before-ms")?.to_string(),
        expires_at_ms: value(&options, "--expires-at-ms")?.to_string(),
        builds,
        revoked_build_ids,
    };
    let manifest = canonical_manifest_bytes(&document).map_err(|error| error.to_string())?;
    validate_release_manifest_for_signing_with_key(&signing_key.verifying_key(), &manifest)
        .map_err(|error| error.to_string())?;
    let signature = signing_key.sign(&manifest_signing_transcript(&manifest));

    write_new(&manifest_output, &manifest, false)?;
    if let Err(error) = write_new(&signature_output, &signature.to_bytes(), false) {
        let _ = fs::remove_file(&manifest_output);
        return Err(error);
    }
    eprintln!(
        "release manifest sha256: {}",
        lower_hex(&Sha256::digest(&manifest))
    );
    Ok(())
}

fn read_build_record(path: &Path) -> Result<ReleaseBuildDocument, String> {
    let bytes = read_bounded(path, MAX_BUILD_RECORD_BYTES)?;
    let record: ReleaseBuildDocument =
        serde_json::from_slice(&bytes).map_err(|_| "build record is malformed".to_string())?;
    let canonical = serde_json::to_vec(&record).map_err(|_| "encode build record".to_string())?;
    if bytes != canonical {
        return Err("build record is not canonical".to_string());
    }
    Ok(record)
}

fn read_revocations(path: &Path) -> Result<Vec<String>, String> {
    let file = open_regular_nofollow(path)?;
    let metadata = file.metadata().map_err(io_error("inspect revocations"))?;
    if metadata.len() > MAX_REVOCATION_FILE_BYTES {
        return Err("revocation file exceeds its size limit".to_string());
    }
    let mut reader = BufReader::new(file.take(MAX_REVOCATION_FILE_BYTES + 1));
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    reader
        .read_to_end(&mut bytes)
        .map_err(io_error("read revocations"))?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > MAX_REVOCATION_FILE_BYTES {
        return Err("revocation file changed while reading".to_string());
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| "revocation file is not UTF-8".to_string())?;
    let mut revoked = text.lines().map(str::to_string).collect::<Vec<_>>();
    if revoked.iter().any(|entry| entry.is_empty()) {
        return Err("revocation entries must not be empty".to_string());
    }
    revoked.sort();
    if revoked.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("revocation entries must be unique".to_string());
    }
    Ok(revoked)
}

fn read_base64_signature(path: &Path) -> Result<[u8; 64], String> {
    let bytes = read_bounded(path, 87)?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| "build signature is not UTF-8".to_string())?;
    let encoded = text.strip_suffix('\n').unwrap_or(text);
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| "build signature is malformed".to_string())?;
    if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err("build signature is not canonical".to_string());
    }
    decoded
        .try_into()
        .map_err(|_| "build signature has the wrong length".to_string())
}

fn hash_file(input: PathBuf) -> Result<String, String> {
    let file = open_regular_nofollow(&input)?;
    let metadata = file.metadata().map_err(io_error("inspect input"))?;
    if metadata.len() == 0 || metadata.len() > MAX_HASH_FILE_BYTES {
        return Err("input file size is outside release limits".to_string());
    }
    let mut reader = BufReader::new(file);
    let mut digest = Sha256::new();
    let mut buffer = Zeroizing::new(vec![0_u8; 64 * 1024]);
    let mut total = 0_u64;
    loop {
        let read = reader.read(&mut buffer).map_err(io_error("hash input"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| "input file size overflow".to_string())?;
        if total > metadata.len() || total > MAX_HASH_FILE_BYTES {
            return Err("input changed or exceeded release limits while hashing".to_string());
        }
        digest.update(&buffer[..read]);
    }
    if total != metadata.len() {
        return Err("input changed while hashing".to_string());
    }
    Ok(lower_hex(&digest.finalize()))
}

fn read_private_key(path: PathBuf) -> Result<SigningKey, String> {
    let file = open_regular_nofollow(&path)?;
    let metadata = file.metadata().map_err(io_error("inspect private key"))?;
    #[cfg(unix)]
    if metadata.mode() & 0o077 != 0 {
        return Err("private key permissions must be 0600 or stricter".to_string());
    }
    if metadata.len() != PRIVATE_KEY_BYTES as u64 {
        return Err("private key must contain exactly 32 raw bytes".to_string());
    }
    let mut reader = BufReader::new(file);
    let mut bytes = Zeroizing::new([0_u8; PRIVATE_KEY_BYTES]);
    reader
        .read_exact(bytes.as_mut())
        .map_err(io_error("read private key"))?;
    let mut trailing = [0_u8; 1];
    if reader
        .read(&mut trailing)
        .map_err(io_error("read private key"))?
        != 0
    {
        return Err("private key contains trailing bytes".to_string());
    }
    Ok(SigningKey::from_bytes(&bytes))
}

fn read_public_key(path: PathBuf) -> Result<[u8; 32], String> {
    let bytes = read_bounded(&path, 65)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "public key is not UTF-8".to_string())?;
    let hex = text.strip_suffix('\n').unwrap_or(text);
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("public key must be exactly 64 lowercase hexadecimal characters".to_string());
    }
    let mut output = [0_u8; 32];
    for (index, slot) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *slot = (hex_nibble(hex.as_bytes()[offset]) << 4) | hex_nibble(hex.as_bytes()[offset + 1]);
    }
    if output.iter().all(|byte| *byte == 0) {
        return Err("all-zero release public key is not valid".to_string());
    }
    ed25519_dalek::VerifyingKey::from_bytes(&output)
        .map_err(|_| "release public key is not a valid Ed25519 key".to_string())?;
    Ok(output)
}

fn write_public_key(path: PathBuf, public_key: &[u8; 32]) -> Result<(), String> {
    let value = format!("{}\n", lower_hex(public_key));
    write_new(path, value.as_bytes(), false)
}

fn root_source(public_key: &[u8; 32]) -> String {
    let values = public_key
        .iter()
        .map(|byte| format!("0x{byte:02x}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "// Generated from the offline Abyssal release public key.\n\
         #[cfg(not(feature = \"integration-release-root\"))]\n\
         pub const RELEASE_PUBKEY: [u8; 32] = [{values}];\n\n\
         #[cfg(all(feature = \"integration-release-root\", not(debug_assertions)))]\n\
         compile_error!(\"the integration release root is forbidden in release builds\");\n\n\
         #[cfg(feature = \"integration-release-root\")]\n\
         pub const RELEASE_PUBKEY: [u8; 32] = [\n\
             0xea, 0x4a, 0x6c, 0x63, 0xe2, 0x9c, 0x52, 0x0a,\n\
             0xbe, 0xf5, 0x50, 0x7b, 0x13, 0x2e, 0xc5, 0xf9,\n\
             0x95, 0x47, 0x76, 0xae, 0xbe, 0xbe, 0x7b, 0x92,\n\
             0x42, 0x1e, 0xea, 0x69, 0x14, 0x46, 0xd2, 0x2c,\n\
         ];\n"
    )
}

fn read_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let file = open_regular_nofollow(path)?;
    let metadata = file.metadata().map_err(io_error("inspect input"))?;
    if metadata.len() == 0 || metadata.len() > max_bytes {
        return Err("input file size is outside limits".to_string());
    }
    let mut reader = BufReader::new(file.take(max_bytes + 1));
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    reader
        .read_to_end(&mut bytes)
        .map_err(io_error("read input"))?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > max_bytes {
        return Err("input changed or exceeded limits while reading".to_string());
    }
    Ok(bytes)
}

fn open_regular_nofollow(path: &Path) -> Result<File, String> {
    let metadata = fs::symlink_metadata(path).map_err(io_error("inspect input path"))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err("input must be a regular non-symlink file".to_string());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    options.open(path).map_err(io_error("open input"))
}

fn write_new(path: impl AsRef<Path>, bytes: &[u8], private: bool) -> Result<(), String> {
    let path = path.as_ref();
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(if private { 0o600 } else { 0o644 });
    let mut file = options.open(path).map_err(io_error("create output"))?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(format!("write output: {error}"));
    }
    Ok(())
}

fn refuse_existing(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(format!("output already exists: {}", path.display())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("inspect output path: {error}")),
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => 0,
    }
}

fn io_error(action: &'static str) -> impl FnOnce(io::Error) -> String {
    move |error| format!("{action}: {error}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use abyssal_core::release_provenance::verify_release_manifest_with_key;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(unix)]
    use std::os::unix::fs::{symlink, PermissionsExt};

    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn create() -> Self {
            let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "abyssal-release-tool-test-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create test directory");
            Self(path)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove test directory");
        }
    }

    fn test_private_key(directory: &TestDirectory) -> (PathBuf, SigningKey) {
        let path = directory.path("release.key");
        let key = SigningKey::from_bytes(&[7_u8; 32]);
        write_new(&path, &key.to_bytes(), true).expect("write private key");
        (path, key)
    }

    fn build_document(key: &SigningKey, build_id: &str, asset_name: &str) -> ReleaseBuildDocument {
        build_document_with_source(
            key,
            build_id,
            asset_name,
            "0123456789abcdef0123456789abcdef01234567",
        )
    }

    fn build_document_with_source(
        key: &SigningKey,
        build_id: &str,
        asset_name: &str,
        source_commit: &str,
    ) -> ReleaseBuildDocument {
        let signature =
            key.sign(&build_signing_transcript(build_id, source_commit).expect("build transcript"));
        ReleaseBuildDocument {
            build_id: build_id.to_string(),
            source_commit: source_commit.to_string(),
            build_signature_b64: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            assets: vec![ReleaseAssetDocument {
                name: asset_name.to_string(),
                sha256_hex: "11".repeat(32),
                size: "1048576".to_string(),
            }],
        }
    }

    fn manifest_document(key: &SigningKey) -> ReleaseManifestDocument {
        ReleaseManifestDocument {
            schema: RELEASE_MANIFEST_SCHEMA.to_string(),
            project: RELEASE_PROJECT.to_string(),
            channel: RELEASE_CHANNEL.to_string(),
            sequence: "9".to_string(),
            issued_at_ms: "1799999999000".to_string(),
            not_before_ms: "1800000000000".to_string(),
            expires_at_ms: "1800000060000".to_string(),
            builds: vec![
                build_document(key, "android@2.1.0", "abyssal.apk"),
                build_document(key, "web@2.1.0", "abyssal-web.tar.zst"),
            ],
            revoked_build_ids: Vec::new(),
        }
    }

    #[test]
    fn option_parser_rejects_missing_duplicate_and_unknown_flags() {
        let expected = &["--a", "--b"];
        assert!(parse_options(
            &["--a".into(), "one".into(), "--b".into(), "two".into()],
            expected,
        )
        .is_ok());
        assert!(parse_options(&["--a".into(), "one".into()], expected).is_err());
        assert!(parse_options(
            &["--a".into(), "one".into(), "--a".into(), "two".into()],
            expected,
        )
        .is_err());
        assert!(parse_options(
            &["--a".into(), "one".into(), "--c".into(), "two".into()],
            expected,
        )
        .is_err());
    }

    #[test]
    fn root_source_contains_each_public_byte_and_no_private_material() {
        let public = [0x5a_u8; 32];
        let source = root_source(&public);
        assert_eq!(source.matches("0x5a").count(), 32);
        assert!(!source.contains("private"));
        assert!(source.contains("RELEASE_PUBKEY"));
        assert!(source.contains("not(debug_assertions)"));
        assert_eq!(source.matches("integration-release-root").count(), 3);
    }

    #[test]
    fn lower_hex_matches_sha256_style_encoding() {
        assert_eq!(lower_hex(&[0x00, 0x09, 0xab, 0xff]), "0009abff");
    }

    #[test]
    fn key_generation_uses_create_new_and_private_permissions() {
        let directory = TestDirectory::create();
        let private = directory.path("generated.key");
        let public = directory.path("generated.pub");
        generate_key(private.clone(), public.clone()).expect("generate key");
        assert_eq!(
            fs::read(&private).expect("private key").len(),
            PRIVATE_KEY_BYTES
        );
        let public_bytes = fs::read_to_string(&public).expect("public key");
        assert_eq!(public_bytes.len(), 65);
        assert!(public_bytes
            .trim_end()
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&private)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let original_private = fs::read(&private).expect("original private key");
        assert!(generate_key(private.clone(), directory.path("other.pub")).is_err());
        assert_eq!(
            fs::read(&private).expect("unchanged private key"),
            original_private
        );
    }

    #[test]
    fn private_key_reader_rejects_wrong_size_and_loose_permissions() {
        let directory = TestDirectory::create();
        let wrong_size = directory.path("wrong-size.key");
        write_new(&wrong_size, &[1_u8; 31], true).expect("write short key");
        assert!(read_private_key(wrong_size).is_err());

        #[cfg(unix)]
        {
            let loose = directory.path("loose.key");
            write_new(&loose, &[2_u8; 32], true).expect("write loose key");
            fs::set_permissions(&loose, fs::Permissions::from_mode(0o644))
                .expect("loosen permissions");
            assert!(read_private_key(loose).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn every_sensitive_input_rejects_symlinks() {
        let directory = TestDirectory::create();
        let (private, _) = test_private_key(&directory);
        let private_link = directory.path("private-link.key");
        symlink(&private, &private_link).expect("private symlink");
        assert!(read_private_key(private_link).is_err());

        let input = directory.path("input.bin");
        write_new(&input, b"abc", false).expect("input");
        let input_link = directory.path("input-link.bin");
        symlink(&input, &input_link).expect("input symlink");
        assert!(hash_file(input_link).is_err());
    }

    #[test]
    fn public_key_reader_rejects_zero_uppercase_and_trailing_data() {
        let directory = TestDirectory::create();
        for (name, value) in [
            ("zero.pub", format!("{}\n", "00".repeat(32))),
            ("upper.pub", format!("{}\n", "AA".repeat(32))),
            ("trailing.pub", format!("{}\nextra", "11".repeat(32))),
        ] {
            let path = directory.path(name);
            write_new(&path, value.as_bytes(), false).expect("write public key");
            assert!(read_public_key(path).is_err());
        }
    }

    #[test]
    fn hash_file_is_bounded_and_matches_known_answer() {
        let directory = TestDirectory::create();
        let input = directory.path("input.bin");
        write_new(&input, b"abc", false).expect("write input");
        assert_eq!(
            hash_file(input).expect("hash"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        let empty = directory.path("empty.bin");
        write_new(&empty, b"", false).expect("write empty");
        assert!(hash_file(empty).is_err());

        let oversized = directory.path("oversized.bin");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&oversized)
            .expect("create sparse file");
        file.set_len(MAX_HASH_FILE_BYTES + 1)
            .expect("size sparse file");
        assert!(hash_file(oversized).is_err());
    }

    #[test]
    fn build_and_manifest_signing_round_trip_through_core_verifier() {
        let directory = TestDirectory::create();
        let (private, key) = test_private_key(&directory);
        let build_signature = directory.path("android.sig.b64");
        sign_build(
            private.clone(),
            "android@2.1.0",
            "0123456789abcdef0123456789abcdef01234567",
            build_signature.clone(),
        )
        .expect("sign build");
        let encoded = fs::read_to_string(build_signature).expect("build signature");
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(encoded.trim_end())
                .expect("decode build signature")
                .len(),
            64
        );

        let manifest = canonical_manifest_bytes(&manifest_document(&key)).expect("manifest");
        let manifest_path = directory.path("release-manifest-v1.json");
        write_new(&manifest_path, &manifest, false).expect("write manifest");
        let signature_path = directory.path("release-manifest-v1.sig");
        sign_manifest(private, manifest_path, signature_path.clone()).expect("sign manifest");
        let signature = fs::read(signature_path).expect("manifest signature");
        let verified = verify_release_manifest_with_key(
            &key.verifying_key(),
            &manifest,
            &signature,
            1_800_000_000_000,
        )
        .expect("verify manifest");
        assert_eq!(verified.sequence, 9);
    }

    #[test]
    fn build_record_hashes_assets_and_requires_exact_embedded_signature() {
        let directory = TestDirectory::create();
        let (private, _) = test_private_key(&directory);
        let signature = directory.path("build.sig.b64");
        sign_build(
            private.clone(),
            "android@2.1.0",
            "0123456789abcdef0123456789abcdef01234567",
            signature.clone(),
        )
        .expect("sign build");
        let asset = directory.path("abyssal.apk");
        write_new(&asset, b"abc", false).expect("write asset");
        let output = directory.path("android-record.json");
        let arguments = vec![
            "--private-key".to_string(),
            private.to_string_lossy().into_owned(),
            "--build-id".to_string(),
            "android@2.1.0".to_string(),
            "--source-commit".to_string(),
            "0123456789abcdef0123456789abcdef01234567".to_string(),
            "--expected-signature".to_string(),
            signature.to_string_lossy().into_owned(),
            "--output".to_string(),
            output.to_string_lossy().into_owned(),
            "--asset".to_string(),
            "abyssal.apk".to_string(),
            asset.to_string_lossy().into_owned(),
        ];
        create_build_record(&arguments).expect("build record");
        let record = read_build_record(&output).expect("read build record");
        assert_eq!(record.build_id, "android@2.1.0");
        assert_eq!(record.assets[0].size, "3");
        assert_eq!(
            record.assets[0].sha256_hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        let tampered_signature = directory.path("tampered.sig.b64");
        let mut encoded = fs::read_to_string(&signature).expect("signature");
        encoded.replace_range(0..1, if encoded.starts_with('A') { "B" } else { "A" });
        write_new(&tampered_signature, encoded.as_bytes(), false).expect("tampered signature");
        let mut rejected = arguments;
        rejected[7] = tampered_signature.to_string_lossy().into_owned();
        rejected[9] = directory
            .path("must-not-exist.json")
            .to_string_lossy()
            .into_owned();
        assert!(create_build_record(&rejected).is_err());
        assert!(!PathBuf::from(&rejected[9]).exists());
    }

    #[test]
    fn manifest_assembly_sorts_revocations_and_verifies_end_to_end() {
        let directory = TestDirectory::create();
        let (private, key) = test_private_key(&directory);
        let android_record = directory.path("android.json");
        let web_record = directory.path("web.json");
        write_new(
            &android_record,
            &serde_json::to_vec(&build_document(&key, "android@2.1.0", "abyssal.apk"))
                .expect("android record"),
            false,
        )
        .expect("write android record");
        write_new(
            &web_record,
            &serde_json::to_vec(&build_document(&key, "web@2.1.0", "abyssal-web.tar.zst"))
                .expect("web record"),
            false,
        )
        .expect("write web record");
        let revocations = directory.path("revocations.txt");
        write_new(&revocations, b"web@1.0.0\nandroid@1.9.0\n", false).expect("write revocations");
        let manifest = directory.path("release-manifest-v1.json");
        let signature = directory.path("release-manifest-v1.sig");
        let arguments = vec![
            "--private-key".to_string(),
            private.to_string_lossy().into_owned(),
            "--sequence".to_string(),
            "9".to_string(),
            "--issued-at-ms".to_string(),
            "1799999999000".to_string(),
            "--not-before-ms".to_string(),
            "1800000000000".to_string(),
            "--expires-at-ms".to_string(),
            "1800000060000".to_string(),
            "--android-record".to_string(),
            android_record.to_string_lossy().into_owned(),
            "--web-record".to_string(),
            web_record.to_string_lossy().into_owned(),
            "--revocations".to_string(),
            revocations.to_string_lossy().into_owned(),
            "--manifest-output".to_string(),
            manifest.to_string_lossy().into_owned(),
            "--signature-output".to_string(),
            signature.to_string_lossy().into_owned(),
        ];
        assemble_manifest(&arguments).expect("assemble manifest");
        let manifest_bytes = fs::read(manifest).expect("manifest");
        let signature_bytes = fs::read(signature).expect("signature");
        let verified = verify_release_manifest_with_key(
            &key.verifying_key(),
            &manifest_bytes,
            &signature_bytes,
            1_800_000_000_000,
        )
        .expect("verify assembled manifest");
        assert_eq!(
            verified.revoked_build_ids,
            vec!["android@1.9.0".to_string(), "web@1.0.0".to_string()]
        );
    }

    #[test]
    fn manifest_assembly_rejects_cross_version_and_cross_source_records() {
        let directory = TestDirectory::create();
        let (private, key) = test_private_key(&directory);
        let android_record = directory.path("android.json");
        let web_record = directory.path("web.json");
        let revocations = directory.path("revocations.txt");
        write_new(&revocations, b"", false).expect("write revocations");

        for (case, web_build_id, web_source) in [
            (
                "version",
                "web@2.1.1",
                "0123456789abcdef0123456789abcdef01234567",
            ),
            (
                "source",
                "web@2.1.0",
                "89abcdef0123456789abcdef0123456789abcdef",
            ),
        ] {
            write_new(
                &android_record,
                &serde_json::to_vec(&build_document(&key, "android@2.1.0", "abyssal.apk"))
                    .expect("android record"),
                false,
            )
            .expect("write android record");
            write_new(
                &web_record,
                &serde_json::to_vec(&build_document_with_source(
                    &key,
                    web_build_id,
                    "abyssal-web.tar.gz",
                    web_source,
                ))
                .expect("web record"),
                false,
            )
            .expect("write web record");
            let manifest = directory.path(&format!("{case}-manifest.json"));
            let signature = directory.path(&format!("{case}-manifest.sig"));
            let arguments = vec![
                "--private-key".to_string(),
                private.to_string_lossy().into_owned(),
                "--sequence".to_string(),
                "9".to_string(),
                "--issued-at-ms".to_string(),
                "1799999999000".to_string(),
                "--not-before-ms".to_string(),
                "1800000000000".to_string(),
                "--expires-at-ms".to_string(),
                "1800000060000".to_string(),
                "--android-record".to_string(),
                android_record.to_string_lossy().into_owned(),
                "--web-record".to_string(),
                web_record.to_string_lossy().into_owned(),
                "--revocations".to_string(),
                revocations.to_string_lossy().into_owned(),
                "--manifest-output".to_string(),
                manifest.to_string_lossy().into_owned(),
                "--signature-output".to_string(),
                signature.to_string_lossy().into_owned(),
            ];
            assert!(assemble_manifest(&arguments).is_err());
            assert!(!manifest.exists());
            assert!(!signature.exists());
            fs::remove_file(&android_record).expect("remove Android record");
            fs::remove_file(&web_record).expect("remove web record");
        }
    }

    #[test]
    fn noncanonical_build_record_and_duplicate_revocations_fail_closed() {
        let directory = TestDirectory::create();
        let (_, key) = test_private_key(&directory);
        let record = directory.path("record.json");
        let mut encoded = serde_json::to_vec(&build_document(&key, "android@2.1.0", "abyssal.apk"))
            .expect("record");
        encoded.push(b'\n');
        write_new(&record, &encoded, false).expect("write record");
        assert!(read_build_record(&record).is_err());

        let revocations = directory.path("revocations.txt");
        write_new(&revocations, b"android@1.0.0\nandroid@1.0.0\n", false)
            .expect("write revocations");
        assert!(read_revocations(&revocations).is_err());
    }

    #[test]
    fn sign_manifest_rejects_noncanonical_input_without_output() {
        let directory = TestDirectory::create();
        let (private, key) = test_private_key(&directory);
        let canonical = canonical_manifest_bytes(&manifest_document(&key)).expect("manifest");
        let mut noncanonical = canonical;
        noncanonical.push(b'\n');
        let manifest_path = directory.path("noncanonical.json");
        write_new(&manifest_path, &noncanonical, false).expect("write manifest");
        let signature_path = directory.path("must-not-exist.sig");
        assert!(sign_manifest(private, manifest_path, signature_path.clone()).is_err());
        assert!(!signature_path.exists());
    }

    #[test]
    fn all_output_operations_refuse_overwrite() {
        let directory = TestDirectory::create();
        let output = directory.path("existing.out");
        write_new(&output, b"first", false).expect("initial output");
        assert!(write_new(&output, b"second", false).is_err());
        assert_eq!(fs::read(output).expect("read output"), b"first");
    }
}
