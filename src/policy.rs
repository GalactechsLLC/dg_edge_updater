use super::*;
use serde::Serialize;
use std::path::Path;

const TRUST_PATH: &str = "/etc/druid-garden/update-trust.yaml";
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Trust {
    pub generation: u64,
    pub public_key: String,
}

pub(crate) fn read_trusted(path: &Path, limit: u64) -> Result<Vec<u8>, Error> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
        || metadata.len() > limit
    {
        return Err(invalid(
            "Trusted configuration must be a bounded, root-owned regular file with one link and no group/other write",
        ));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid("Trusted file exceeds size limit"));
    }
    Ok(bytes)
}

pub(crate) fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), Error> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("Missing parent directory"))?;
    let mut file = tempfile::Builder::new()
        .prefix(".druid-update-")
        .tempfile_in(parent)?;
    file.write_all(bytes)?;
    file.as_file()
        .set_permissions(std::fs::Permissions::from_mode(mode))?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|error| error.error)?;
    File::open(parent)?.sync_all()
}

pub(crate) fn trust() -> Result<Trust, Error> {
    match read_trusted(Path::new(TRUST_PATH), 4096) {
        Ok(raw) => {
            let trust: Trust = serde_yaml::from_slice(&raw).map_err(Error::other)?;
            decode_hex::<32>(&trust.public_key)?;
            Ok(trust)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            let raw = read_trusted(Path::new(PUBLIC_KEY_PATH), 128)?;
            let public_key = std::str::from_utf8(&raw)
                .map_err(Error::other)?
                .trim()
                .to_owned();
            decode_hex::<32>(&public_key)?;
            Ok(Trust {
                generation: 0,
                public_key,
            })
        }
        Err(error) => Err(error),
    }
}

fn trust_json(trust: &Trust) -> Result<String, Error> {
    // Validate before interpolation: key is fixed-width hexadecimal, generation u64.
    decode_hex::<32>(&trust.public_key)?;
    Ok(format!(
        "{{\"generation\":{},\"public_key\":\"{}\"}}\n",
        trust.generation, trust.public_key
    ))
}

pub(crate) fn commit_rotation(next: Option<&Trust>) -> Result<(), Error> {
    if let Some(next) = next {
        let current = trust()?;
        if next.generation == current.generation && next.public_key == current.public_key {
            return Ok(());
        }
        if current.generation.checked_add(1) != Some(next.generation) {
            return Err(invalid("Key rotation must advance trust generation by one"));
        }
        decode_hex::<32>(&next.public_key)?;
        write_atomic(Path::new(TRUST_PATH), trust_json(next)?.as_bytes(), 0o644)?;
    }
    Ok(())
}

pub fn configured_channel() -> Result<String, Error> {
    let value = match read_trusted(Path::new("/etc/druid-garden/update-channel"), 32) {
        Ok(raw) => String::from_utf8(raw)
            .map_err(Error::other)?
            .trim()
            .to_owned(),
        Err(error) if error.kind() == ErrorKind::NotFound => "stable".to_owned(),
        Err(error) => return Err(error),
    };
    if !matches!(value.as_str(), "stable" | "beta") {
        return Err(invalid("Update channel must be stable or beta"));
    }
    Ok(value)
}

pub fn rollout_bucket(machine_id: &str, manifest: &Manifest) -> u16 {
    let value = format!(
        "druid-rollout-v1\0{}\0{}\0{}\0{}",
        machine_id, manifest.channel, manifest.version, manifest.rollout_seed
    );
    let hash = digest::digest(&digest::SHA256, value.as_bytes());
    (u32::from_be_bytes(hash.as_ref()[..4].try_into().expect("SHA-256 prefix")) % 10_000) as u16
}

pub fn eligible_for_rollout(manifest: &Manifest) -> Result<bool, Error> {
    if manifest.channel != configured_channel()? {
        return Err(invalid("Release channel mismatch"));
    }
    if manifest.rollout_basis_points == 10_000 {
        return Ok(true);
    }
    let raw = read_trusted(Path::new("/etc/machine-id"), 128)?;
    let machine_id = std::str::from_utf8(&raw).map_err(Error::other)?.trim();
    decode_hex::<16>(machine_id)?;
    Ok(rollout_bucket(machine_id, manifest) < manifest.rollout_basis_points)
}

pub(crate) fn readiness_url() -> Result<String, Error> {
    let value = match read_trusted(Path::new("/etc/druid-garden/update-readiness-url"), 1024) {
        Ok(raw) => String::from_utf8(raw)
            .map_err(Error::other)?
            .trim()
            .to_owned(),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            "http://127.0.0.1:8080/system/health".to_owned()
        }
        Err(error) => return Err(error),
    };
    let url = reqwest::Url::parse(&value).map_err(Error::other)?;
    let host = url
        .host_str()
        .unwrap_or_default()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let loopback = host
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback());
    if url.scheme() != "http"
        || !loopback
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(
            "Readiness URL must be HTTP on a literal loopback address without credentials or fragments",
        ));
    }
    Ok(value)
}

#[derive(Deserialize)]
struct RotationCertificate {
    purpose: String,
    from_generation: u64,
    expires_unix: u64,
    next_key: Trust,
}
pub(crate) fn verify_rotation(
    raw: &[u8],
    signature_hex: &str,
    current: &Trust,
    now: u64,
) -> Result<Trust, Error> {
    let key = decode_hex::<32>(&current.public_key)?;
    let signed = decode_hex::<64>(signature_hex.trim())?;
    signature::UnparsedPublicKey::new(&signature::ED25519, key)
        .verify(raw, &signed)
        .map_err(|_| invalid("Key rotation certificate signature failed"))?;
    let certificate: RotationCertificate = serde_yaml::from_slice(raw).map_err(Error::other)?;
    if certificate.purpose != "druid-update-key-rotation-v1"
        || certificate.from_generation != current.generation
        || certificate.expires_unix <= now
        || current.generation.checked_add(1) != Some(certificate.next_key.generation)
        || certificate.next_key.public_key == current.public_key
    {
        return Err(invalid("Invalid or expired key rotation certificate"));
    }
    decode_hex::<32>(&certificate.next_key.public_key)?;
    Ok(certificate.next_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::KeyPair;
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
    #[test]
    fn persisted_trust_matches_bootstrap_json_fixture() {
        let state = Trust {
            generation: 2,
            public_key: "11".repeat(32),
        };
        let encoded = trust_json(&state).unwrap();
        assert_eq!(encoded, include_str!("../tests/fixtures/update-trust.json"));
        let decoded: Trust = serde_yaml::from_str(&encoded).unwrap();
        assert_eq!(decoded.generation, 2);
        assert_eq!(decoded.public_key, state.public_key);
        let invalid = Trust {
            generation: 2,
            public_key: "\"malformed".to_owned(),
        };
        assert!(trust_json(&invalid).is_err());
    }
    #[test]
    fn rotation_certificate_authenticates_successor_without_skipping_generations() {
        let signer = signature::Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let successor = signature::Ed25519KeyPair::from_seed_unchecked(&[8; 32]).unwrap();
        let current = Trust {
            generation: 0,
            public_key: hex(signer.public_key().as_ref()),
        };
        let raw = format!(
            "{{\"purpose\":\"druid-update-key-rotation-v1\",\"from_generation\":0,\"expires_unix\":2000,\"next_key\":{{\"generation\":1,\"public_key\":\"{}\"}}}}",
            hex(successor.public_key().as_ref())
        );
        let signed = hex(signer.sign(raw.as_bytes()).as_ref());
        let next = verify_rotation(raw.as_bytes(), &signed, &current, 1000).unwrap();
        assert_eq!(next.generation, 1);
        assert_eq!(next.public_key, hex(successor.public_key().as_ref()));
        assert!(verify_rotation(raw.as_bytes(), &signed, &current, 2000).is_err());
        assert!(verify_rotation(raw.as_bytes(), &signed, &next, 1000).is_err());
        let skipped = raw.replace("\"generation\":1", "\"generation\":2");
        let signed_skip = hex(signer.sign(skipped.as_bytes()).as_ref());
        assert!(verify_rotation(skipped.as_bytes(), &signed_skip, &current, 1000).is_err());
    }
}
