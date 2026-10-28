use reqwest::Client;
use ring::{digest, signature};
use semver::Version;
use serde::{Deserialize, Serialize};
mod policy;
mod recovery;
pub use policy::{Trust, configured_channel, eligible_for_rollout, rollout_bucket};
pub use recovery::{install_verified, recover_pending};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Error, ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::NamedTempFile;
use tokio::process::Command;
use tokio::time::{sleep, timeout};

pub const MANIFEST_URL: &str = "https://os.druid.garden/manifest.yaml";
pub const BIN_PATH: &str = "/usr/bin/druid-garden-os.app";
pub const BACKUP_PATH: &str = "/usr/bin/druid-garden-os.app.bak";
pub const SERVICE_NAME: &str = "druid_garden_os";
pub const UPDATER_SERVICE_NAME: &str = "druid_garden_edge_updater";
const PUBLIC_KEY_PATH: &str = "/etc/druid-garden/update-public-key";
const MAX_ARTIFACT_SIZE: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Artifact {
    pub sha256: String,
    pub size: u64,
}
#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub version: String,
    pub expires_unix: u64,
    pub channel: String,
    pub key_generation: u64,
    pub rollout_basis_points: u16,
    pub rollout_seed: String,
    pub next_key: Option<Trust>,
    #[serde(default)]
    pub updater_artifacts: BTreeMap<String, Artifact>,
    pub updater_revision: Option<u64>,
    pub artifacts: BTreeMap<String, Artifact>,
}
fn invalid(message: &str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}
fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], Error> {
    if value.len() != N * 2 || !value.is_ascii() {
        return Err(invalid("Invalid hexadecimal length"));
    }
    let mut result = [0; N];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| invalid("Invalid hexadecimal value"))?;
    }
    Ok(result)
}
fn canonical_version(value: &str) -> Result<Version, Error> {
    let version = Version::parse(value).map_err(Error::other)?;
    if version.to_string() != value {
        return Err(invalid("Non-canonical release version"));
    }
    Ok(version)
}
fn verify_manifest(
    raw: &[u8],
    signature_hex: &str,
    public_key: &[u8; 32],
    now: u64,
) -> Result<Manifest, Error> {
    let signature = decode_hex::<64>(signature_hex.trim())?;
    signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
        .verify(raw, &signature)
        .map_err(|_| invalid("Manifest signature verification failed"))?;
    // Authenticate exact YAML bytes before parsing any release metadata.
    let manifest: Manifest = serde_yaml::from_slice(raw).map_err(Error::other)?;
    canonical_version(&manifest.version)?;
    if manifest.expires_unix <= now {
        return Err(invalid("Release metadata has expired"));
    }
    if !matches!(manifest.channel.as_str(), "stable" | "beta")
        || manifest.rollout_basis_points > 10_000
        || manifest.rollout_seed.is_empty()
        || manifest.rollout_seed.len() > 128
    {
        return Err(invalid("Invalid release channel or rollout policy"));
    }
    if manifest.channel == "stable" && !canonical_version(&manifest.version)?.pre.is_empty() {
        return Err(invalid("Prereleases cannot be published to stable"));
    }
    if let Some(next) = &manifest.next_key {
        if manifest.key_generation.checked_add(1) != Some(next.generation) {
            return Err(invalid("Invalid next key generation"));
        }
        decode_hex::<32>(&next.public_key)?;
    }
    if manifest.artifacts.is_empty() {
        return Err(invalid("Release contains no artifacts"));
    }
    for (arch, artifact) in manifest
        .artifacts
        .iter()
        .chain(manifest.updater_artifacts.iter())
    {
        if !matches!(arch.as_str(), "amd64" | "aarch64") {
            return Err(invalid("Unknown release architecture"));
        }
        decode_hex::<32>(&artifact.sha256)?;
        if artifact.size == 0 || artifact.size > MAX_ARTIFACT_SIZE {
            return Err(invalid("Artifact size outside allowed range"));
        }
    }
    Ok(manifest)
}
pub fn update_client() -> Result<Client, Error> {
    Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(Error::other)
}
async fn bounded_metadata(client: &Client, url: &str, limit: usize) -> Result<Vec<u8>, Error> {
    let mut response = client
        .get(url)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(Error::other)?;
    if !response.status().is_success() {
        return Err(invalid("Metadata request failed or redirected"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(Error::other)? {
        if chunk.len() > limit.saturating_sub(bytes.len()) {
            return Err(invalid("Metadata exceeds size limit"));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
pub async fn fetch_manifest(_client: &Client) -> Result<Manifest, Error> {
    // Preserve API compatibility but enforce the client policy regardless of caller.
    let client = update_client()?;
    let trust = policy::trust()?;
    let key = decode_hex::<32>(&trust.public_key)?;
    let channel = configured_channel()?;
    let url = format!("https://os.druid.garden/channels/{channel}/manifest.yaml");
    let raw = bounded_metadata(&client, &url, 64 * 1024).await?;
    let signature = bounded_metadata(&client, &format!("{url}.sig"), 256).await?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(Error::other)?
        .as_secs();
    let signature = std::str::from_utf8(&signature).map_err(Error::other)?;
    match verify_for_policy(&raw, signature, &key, trust.generation, &channel, now) {
        Ok(manifest) => Ok(manifest),
        Err(original) => {
            // Offline devices can follow immutable certificates. Do not replace
            // local trust until the requested manifest verifies under a successor.
            let mut candidate = trust;
            let mut transitions = Vec::new();
            for _ in 0..16 {
                let url = format!(
                    "https://os.druid.garden/trust/{}/rotation.json",
                    candidate.generation
                );
                let certificate = bounded_metadata(&client, &url, 4096).await?;
                let certificate_signature =
                    bounded_metadata(&client, &format!("{url}.sig"), 256).await?;
                candidate = policy::verify_rotation(
                    &certificate,
                    std::str::from_utf8(&certificate_signature).map_err(Error::other)?,
                    &candidate,
                    now,
                )?;
                transitions.push(candidate.clone());
                let key = decode_hex::<32>(&candidate.public_key)?;
                if let Ok(manifest) =
                    verify_for_policy(&raw, signature, &key, candidate.generation, &channel, now)
                {
                    for next in transitions {
                        policy::commit_rotation(Some(&next))?;
                    }
                    return Ok(manifest);
                }
            }
            Err(original)
        }
    }
}

fn verify_for_policy(
    raw: &[u8],
    signature: &str,
    public_key: &[u8; 32],
    generation: u64,
    channel: &str,
    now: u64,
) -> Result<Manifest, Error> {
    let manifest = verify_manifest(raw, signature, public_key, now)?;
    if manifest.channel != channel || manifest.key_generation != generation {
        return Err(invalid("Release channel or trust generation mismatch"));
    }
    Ok(manifest)
}

pub fn architecture() -> Result<&'static str, Error> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("amd64"),
        "aarch64" => Ok("aarch64"),
        _ => Err(Error::new(
            ErrorKind::Unsupported,
            "Unsupported update architecture",
        )),
    }
}
pub fn get_download_url(version: &str) -> Result<String, Error> {
    canonical_version(version)?;
    Ok(format!(
        "https://os.druid.garden/{}/{}/druid-garden-os.app",
        version,
        architecture()?
    ))
}
fn verify_digest(actual_size: u64, hash: &[u8], artifact: &Artifact) -> Result<(), Error> {
    if actual_size != artifact.size || hash != decode_hex::<32>(&artifact.sha256)? {
        return Err(invalid("Artifact length or SHA-256 mismatch"));
    }
    Ok(())
}
pub async fn download_verified(manifest: &Manifest) -> Result<NamedTempFile, Error> {
    let artifact = manifest
        .artifacts
        .get(architecture()?)
        .ok_or_else(|| invalid("Release lacks this architecture"))?;
    let client = update_client()?;
    let mut response = client
        .get(get_download_url(&manifest.version)?)
        .send()
        .await
        .map_err(Error::other)?;
    if !response.status().is_success() {
        return Err(invalid("Artifact request failed or redirected"));
    }
    if response
        .content_length()
        .is_some_and(|length| length != artifact.size)
    {
        return Err(invalid("Artifact Content-Length mismatch"));
    }
    let mut stage = tempfile::Builder::new()
        .prefix(".druid-garden-update-")
        .tempfile_in("/usr/bin")?;
    let mut hash = digest::Context::new(&digest::SHA256);
    let mut size = 0u64;
    while let Some(chunk) = response.chunk().await.map_err(Error::other)? {
        if chunk.len() as u64 > artifact.size.saturating_sub(size) {
            return Err(invalid("Artifact exceeds signed size"));
        }
        size += chunk.len() as u64;
        hash.update(&chunk);
        stage.write_all(&chunk)?;
    }
    verify_digest(size, hash.finish().as_ref(), artifact)?;
    stage
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o755))?;
    stage.as_file().sync_all()?;
    Ok(stage)
}
pub fn acquire_update_lock() -> Result<File, Error> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open("/run/druid-garden-update.lock")?;
    let metadata = lock.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
    {
        return Err(invalid(
            "Update lock must be a root-owned, non-writable regular file with one link",
        ));
    }
    // The open file is retained for the update; closing it releases flock.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(Error::last_os_error());
    }
    Ok(lock)
}
pub async fn get_binary_version(path: &str) -> Result<Version, Error> {
    // Never execute the downloaded file to inspect its version.
    if path != BIN_PATH {
        return Err(invalid("Version queries require the installed binary"));
    }
    let output = timeout(
        Duration::from_secs(15),
        Command::new(path)
            .arg("--version")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(Error::other)??;
    if !output.status.success() {
        return Err(invalid("Installed binary version query failed"));
    }
    canonical_version(
        std::str::from_utf8(&output.stdout)
            .map_err(Error::other)?
            .trim(),
    )
}
pub async fn run_systemctl(action: &str) -> Result<(), Error> {
    let status = timeout(
        Duration::from_secs(60),
        Command::new("/usr/bin/systemctl")
            .arg(action)
            .arg(SERVICE_NAME)
            .kill_on_drop(true)
            .status(),
    )
    .await
    .map_err(Error::other)??;
    if !status.success() {
        return Err(Error::other(format!("systemctl {action} failed: {status}")));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::KeyPair;
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
    #[test]
    fn signed_metadata_rejects_tampering_wrong_key_and_expiry() {
        let signer = signature::Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let key: [u8; 32] = signer.public_key().as_ref().try_into().unwrap();
        let raw = format!(
            "version: '1.2.3'\nexpires_unix: 2000\nchannel: stable\nkey_generation: 0\nrollout_basis_points: 10000\nrollout_seed: default\nartifacts:\n  amd64:\n    size: 3\n    sha256: '{}'\n",
            hex(digest::digest(&digest::SHA256, b"abc").as_ref())
        );
        let signed = hex(signer.sign(raw.as_bytes()).as_ref());
        assert!(verify_manifest(raw.as_bytes(), &signed, &key, 1000).is_ok());
        assert!(
            verify_manifest(
                raw.replace("1.2.3", "9.2.3").as_bytes(),
                &signed,
                &key,
                1000
            )
            .is_err()
        );
        assert!(verify_manifest(raw.as_bytes(), &signed, &[8; 32], 1000).is_err());
        assert!(verify_manifest(raw.as_bytes(), &signed, &key, 2000).is_err());
        assert!(verify_manifest(raw.as_bytes(), "", &key, 1000).is_err());
        // Publication writes signature and manifest as separate objects. Either
        // mixed generation must fail closed until the matching pair is visible.
        let next_raw = raw.replace("1.2.3", "1.2.4");
        let next_signature = hex(signer.sign(next_raw.as_bytes()).as_ref());
        assert!(verify_manifest(raw.as_bytes(), &next_signature, &key, 1000).is_err());
        assert!(verify_manifest(next_raw.as_bytes(), &signed, &key, 1000).is_err());
        assert!(verify_manifest(next_raw.as_bytes(), &next_signature, &key, 1000).is_ok());
    }
    #[test]
    fn signed_policy_binds_channel_generation_rotation_and_rollout() {
        let signer = signature::Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let key: [u8; 32] = signer.public_key().as_ref().try_into().unwrap();
        let raw = format!(
            "version: '1.2.3'\nexpires_unix: 2000\nchannel: stable\nkey_generation: 0\nrollout_basis_points: 5000\nrollout_seed: default\nartifacts:\n  amd64:\n    size: 3\n    sha256: '{}'\nnext_key:\n  generation: 1\n  public_key: '{}'\n",
            hex(digest::digest(&digest::SHA256, b"abc").as_ref()),
            "11".repeat(32)
        );
        let signature = hex(signer.sign(raw.as_bytes()).as_ref());
        let manifest =
            verify_for_policy(raw.as_bytes(), &signature, &key, 0, "stable", 1000).unwrap();
        assert_eq!(
            rollout_bucket("0123456789abcdef0123456789abcdef", &manifest),
            4101
        );
        assert!(verify_for_policy(raw.as_bytes(), &signature, &key, 0, "beta", 1000).is_err());
        assert!(verify_for_policy(raw.as_bytes(), &signature, &key, 1, "stable", 1000).is_err());
        for invalid in [
            raw.replace("generation: 1", "generation: 3"),
            raw.replace("5000", "10001"),
            raw.replace("1.2.3", "1.2.3-beta.1"),
        ] {
            let signed = hex(signer.sign(invalid.as_bytes()).as_ref());
            assert!(verify_manifest(invalid.as_bytes(), &signed, &key, 1000).is_err());
        }
    }
    #[test]
    fn artifact_digest_rejects_modified_or_truncated_payload() {
        let artifact = Artifact {
            size: 3,
            sha256: hex(digest::digest(&digest::SHA256, b"abc").as_ref()),
        };
        assert!(
            verify_digest(
                3,
                digest::digest(&digest::SHA256, b"abc").as_ref(),
                &artifact
            )
            .is_ok()
        );
        assert!(
            verify_digest(
                3,
                digest::digest(&digest::SHA256, b"abd").as_ref(),
                &artifact
            )
            .is_err()
        );
        assert!(
            verify_digest(
                2,
                digest::digest(&digest::SHA256, b"ab").as_ref(),
                &artifact
            )
            .is_err()
        );
    }
}
