use log::info;
use reqwest::Client;
use semver::Version;
use serde::Deserialize;
use std::env;
use std::io::{Error, ErrorKind};
use std::path::Path;
use std::time::Duration;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::sleep;

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct Manifest {
    pub name: Option<String>,
    pub version: String,
    pub date: Option<String>,
    pub author: Option<String>,
}

pub const MANIFEST_URL: &str = "https://os.druid.garden/manifest.yaml";
pub const BIN_PATH: &str = "/usr/bin/druid-garden-os.app";
pub const BACKUP_PATH: &str = "/usr/bin/druid-garden-os.app.bak";
pub const TMP_PATH: &str = "/tmp/druid-garden-os.app";
pub const SERVICE_NAME: &str = "druid_garden_os";
pub const UPDATER_SERVICE_NAME: &str = "druid_garden_edge_updater";

pub async fn fetch_manifest(client: &Client) -> Result<Manifest, Error> {
    let response = client
        .get(MANIFEST_URL)
        .send()
        .await
        .map_err(|e| Error::new(ErrorKind::Other, e))?
        .error_for_status()
        .map_err(|e| Error::new(ErrorKind::Other, e))?
        .text()
        .await
        .map_err(|e| Error::new(ErrorKind::Other, e))?;
    serde_yaml::from_str(&response).map_err(|e| Error::new(ErrorKind::Other, e))
}

pub async fn swap_binaries() -> Result<(), Error> {
    if Path::new(BACKUP_PATH).exists() {
        let _ = fs::remove_file(BACKUP_PATH).await;
    }
    fs::rename(BIN_PATH, BACKUP_PATH).await?;
    fs::copy(TMP_PATH, BIN_PATH).await.map(|_| ())
}

pub async fn get_binary_version(path: &str) -> Option<Version> {
    let output = Command::new(path).arg("--version").output().await.ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Version::parse(stdout.trim()).ok()
}

pub async fn run_systemctl(action: &str) -> Result<(), Error> {
    let status = Command::new("systemctl")
        .arg(action)
        .arg(SERVICE_NAME)
        .status()
        .await?;
    if !status.success() {
        return Err(Error::new(
            ErrorKind::Other,
            format!("systemctl {} failed", action),
        ));
    }
    Ok(())
}

pub async fn download_file(client: &Client, path: &str, download_url: &str) -> Result<(), Error> {
    info!("Downloading from {download_url} to {path}");
    let mut resp = client
        .get(download_url)
        .send()
        .await
        .map_err(|e| Error::new(ErrorKind::Other, e))?
        .error_for_status()
        .map_err(|e| Error::new(ErrorKind::Other, e))?;
    let mut out = fs::File::create(path)
        .await
        .map_err(|e| Error::new(ErrorKind::Other, e))?;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| Error::new(ErrorKind::Other, e))?
    {
        out.write_all(&chunk).await?;
    }
    Ok(())
}

pub fn get_download_url(version: &str) -> Result<String, Error> {
    let arch = env::consts::ARCH;
    Ok(format!(
        "https://os.druid.garden/{}/{}/druid-garden-os.app",
        version,
        if arch == "x86_64" {
            "amd64"
        } else if arch == "aarch64" {
            arch
        } else {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "Unsupported Platform for Auto Updates",
            ));
        }
    ))
}

pub async fn set_executable_bit(path: &str) -> Result<(), Error> {
    let mut perms = fs::metadata(path).await?.permissions();
    perms.set_readonly(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o755);
    }
    fs::set_permissions(path, perms).await
}

pub async fn try_start_with_rollback() -> Result<bool, Error> {
    for attempt in 1..=3 {
        info!("Starting service (attempt {})…", attempt);
        if run_systemctl("start").await.is_ok() {
            return Ok(true);
        }
        sleep(Duration::from_secs(2)).await;
    }
    info!("Rolling back to backup…");
    fs::remove_file(BIN_PATH).await.ok();
    fs::rename(BACKUP_PATH, BIN_PATH).await?;
    // try once more
    if run_systemctl("start").await.is_ok() {
        info!("Rollback succeeded");
        return Ok(true);
    }
    Ok(false)
}
