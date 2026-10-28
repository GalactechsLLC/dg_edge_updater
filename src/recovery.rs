use super::*;
use crate::policy::{read_trusted, readiness_url, write_atomic};
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

const STATE_DIR: &str = "/var/lib/druid-garden-updater";
const JOURNAL: &str = "/var/lib/druid-garden-updater/transaction.yaml";
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Prepared,
    Committed,
}
#[derive(Debug, Deserialize, Serialize)]
struct Transaction {
    phase: Phase,
    old_version: String,
    new_version: String,
    old_artifact: Artifact,
    new_artifact: Artifact,
}
#[derive(Deserialize)]
struct Health {
    status: String,
    version: String,
}

fn state_directory() -> Result<(), Error> {
    match std::fs::DirBuilder::new().mode(0o700).create(STATE_DIR) {
        Ok(()) => (),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error),
    }
    let metadata = std::fs::symlink_metadata(STATE_DIR)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(invalid(
            "Updater journal directory must be root-owned mode 0700",
        ));
    }
    Ok(())
}
fn save(transaction: &Transaction) -> Result<(), Error> {
    write_atomic(
        Path::new(JOURNAL),
        serde_yaml::to_string(transaction)
            .map_err(Error::other)?
            .as_bytes(),
        0o600,
    )
}
fn clear() -> Result<(), Error> {
    std::fs::remove_file(JOURNAL)?;
    File::open(STATE_DIR)?.sync_all()
}
fn hash_file(path: &Path) -> Result<Artifact, Error> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_ARTIFACT_SIZE {
        return Err(invalid("Invalid recovery binary"));
    }
    let mut hash = digest::Context::new(&digest::SHA256);
    let mut size = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size += count as u64;
        if size > MAX_ARTIFACT_SIZE {
            return Err(invalid("Recovery binary exceeds size limit"));
        }
        hash.update(&buffer[..count]);
    }
    Ok(Artifact {
        size,
        sha256: hash
            .finish()
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    })
}
fn matches_artifact(path: &Path, expected: &Artifact) -> Result<(), Error> {
    let actual = hash_file(path)?;
    if actual.size != expected.size || actual.sha256 != expected.sha256 {
        return Err(invalid("Recovery binary digest does not match journal"));
    }
    Ok(())
}
fn copy_atomic(source: &Path, destination: &Path, expected: &Artifact) -> Result<(), Error> {
    let parent = destination
        .parent()
        .ok_or_else(|| invalid("Missing recovery directory"))?;
    let mut output = tempfile::Builder::new()
        .prefix(".druid-recovery-")
        .tempfile_in(parent)?;
    let input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(source)?;
    if !input.metadata()?.is_file() {
        return Err(invalid("Recovery source is not a regular file"));
    }
    std::io::copy(&mut input.take(MAX_ARTIFACT_SIZE + 1), &mut output)?;
    matches_artifact(output.path(), expected)?;
    output
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o755))?;
    output.as_file().sync_all()?;
    output.persist(destination).map_err(|error| error.error)?;
    File::open(parent)?.sync_all()
}
async fn check_health(expected_version: &str) -> Result<(), Error> {
    timeout(
        Duration::from_secs(180),
        check_health_samples(expected_version),
    )
    .await
    .map_err(|_| Error::other("Application readiness deadline exceeded"))?
}
async fn check_health_samples(expected_version: &str) -> Result<(), Error> {
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(Error::other)?;
    let url = readiness_url()?;
    // Allow initialization up to two minutes; then require five consecutive healthy samples.
    let mut healthy = 0;
    for _ in 0..40 {
        sleep(Duration::from_secs(3)).await;
        let result = async {
            run_systemctl("is-active").await?;
            let raw = bounded_metadata(&client, &url, 4096).await?;
            let health: Health = serde_yaml::from_slice(&raw).map_err(Error::other)?;
            if health.status != "ok" || health.version != expected_version {
                return Err(invalid("Application is not ready at the expected version"));
            }
            Ok::<(), Error>(())
        }
        .await;
        if result.is_ok() {
            healthy += 1;
            if healthy == 5 {
                return Ok(());
            }
        } else {
            healthy = 0;
        }
    }
    Err(invalid(
        "Application readiness/version checks did not stabilize",
    ))
}
async fn rollback_service(version: &str) -> Result<(), Error> {
    run_systemctl("restart").await?;
    for _ in 0..5 {
        sleep(Duration::from_secs(3)).await;
        run_systemctl("is-active").await?;
    }
    // Older rollback targets may predate /system/health. This exception never
    // applies to accepting a newly installed release.
    if get_binary_version(BIN_PATH).await?.to_string() != version {
        return Err(invalid("Rollback version mismatch"));
    }
    Ok(())
}

pub async fn recover_pending(boot_only: bool) -> Result<bool, Error> {
    state_directory()?;
    let raw = match read_trusted(Path::new(JOURNAL), 16 * 1024) {
        Ok(raw) => raw,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let transaction: Transaction = serde_yaml::from_slice(&raw).map_err(Error::other)?;
    canonical_version(&transaction.old_version)?;
    canonical_version(&transaction.new_version)?;
    if transaction.phase == Phase::Committed
        && matches_artifact(Path::new(BIN_PATH), &transaction.new_artifact).is_ok()
    {
        clear()?;
        return Ok(true);
    }
    if !boot_only {
        let _ = run_systemctl("stop").await;
    }
    // Keep backup in place so a second power failure during recovery is repeatable.
    let durability = copy_atomic(
        Path::new(BACKUP_PATH),
        Path::new(BIN_PATH),
        &transaction.old_artifact,
    );
    let recovery = if boot_only {
        Ok(())
    } else {
        rollback_service(&transaction.old_version).await
    };
    match (durability, recovery) {
        (Ok(()), Ok(())) => {
            clear()?;
            Ok(true)
        }
        (Err(copy), Ok(())) => Err(Error::other(format!(
            "Recovery file/durability failure: {copy}"
        ))),
        (Ok(()), Err(service)) => Err(service),
        (Err(copy), Err(service)) => Err(Error::other(format!(
            "Recovery file failure: {copy}; service failure: {service}"
        ))),
    }
}

pub async fn install_verified(
    stage: NamedTempFile,
    manifest: &Manifest,
    old_version: &Version,
) -> Result<(), Error> {
    state_directory()?;
    if Path::new(JOURNAL).try_exists()? {
        return Err(invalid(
            "Recover interrupted transaction before another update",
        ));
    }
    let old_artifact = hash_file(Path::new(BIN_PATH))?;
    let new_artifact = manifest
        .artifacts
        .get(architecture()?)
        .ok_or_else(|| invalid("Missing release architecture"))?
        .clone();
    matches_artifact(stage.path(), &new_artifact)?;
    copy_atomic(Path::new(BIN_PATH), Path::new(BACKUP_PATH), &old_artifact)?;
    let mut transaction = Transaction {
        phase: Phase::Prepared,
        old_version: old_version.to_string(),
        new_version: manifest.version.clone(),
        old_artifact,
        new_artifact,
    };
    save(&transaction)?; // Durable before any stop or replacement.
    let result: Result<(), Error> = async {
        run_systemctl("stop").await?;
        stage.persist(BIN_PATH).map_err(|error| error.error)?;
        File::open("/usr/bin")?.sync_all()?;
        check_health_after_start(&manifest.version).await
    }
    .await;
    if let Err(cause) = result {
        return match recover_pending(false).await {
            Ok(_) => Err(Error::other(format!(
                "Update failed and was rolled back: {cause}"
            ))),
            Err(error) => Err(Error::other(format!(
                "Update failed: {cause}; rollback remains pending: {error}"
            ))),
        };
    }
    transaction.phase = Phase::Committed;
    save(&transaction)?;
    clear()
}
async fn check_health_after_start(version: &str) -> Result<(), Error> {
    run_systemctl("start").await?;
    check_health(version).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restoring_backup_is_repeatable_and_rejects_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let backup = dir.path().join("backup");
        let active = dir.path().join("active");
        std::fs::write(&backup, b"trusted old binary").unwrap();
        let expected = hash_file(&backup).unwrap();
        std::fs::write(&active, b"partial new binary").unwrap();
        copy_atomic(&backup, &active, &expected).unwrap();
        copy_atomic(&backup, &active, &expected).unwrap();
        assert_eq!(std::fs::read(&active).unwrap(), b"trusted old binary");
        assert!(backup.exists());
        std::fs::write(&backup, b"tampered").unwrap();
        assert!(copy_atomic(&backup, &active, &expected).is_err());
        assert_eq!(std::fs::read(&active).unwrap(), b"trusted old binary");
    }
}
