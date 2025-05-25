use dg_edge_updater::{BIN_PATH, TMP_PATH};
use dg_edge_updater::{
    download_file, fetch_manifest, get_binary_version, get_download_url, run_systemctl,
    set_executable_bit, swap_binaries, try_start_with_rollback,
};
use dg_logger::{DruidGardenLogger, TimestampFormat};
use log::{Level, error, info};
use reqwest::Client;
use semver::Version;
use std::io::{Error, ErrorKind};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let _ = DruidGardenLogger::build()
        .use_colors(true)
        .current_level(Level::Info)
        .timestamp_format(TimestampFormat::Local)
        .with_target_level("zbus", Level::Warn)
        .with_target_level("tracing", Level::Warn)
        .init()
        .map_err(|e| Error::new(ErrorKind::Other, format!("{e:?}")))?;
    let client = Client::new();

    // Check for Updates
    let manifest = fetch_manifest(&client).await?;
    let remote_version =
        Version::parse(&manifest.version).map_err(|e| Error::new(ErrorKind::Other, e))?;
    info!("Found Remote version: {}", remote_version);
    let local_version = get_binary_version(BIN_PATH)
        .await
        .unwrap_or_else(|| Version::new(0, 0, 0));
    info!("Found Local version:  {}", local_version);
    if remote_version <= local_version {
        info!("Up to date! nothing to do.");
        return Ok(());
    }

    // Download the New Binary and make executable
    let download_url = get_download_url(manifest.version.as_str())?;
    download_file(&client, TMP_PATH, &download_url).await?;
    set_executable_bit(TMP_PATH).await?;

    // Verify downloaded binary
    let downloaded_version = get_binary_version(TMP_PATH).await.ok_or(Error::new(
        ErrorKind::Other,
        "Failed to read downloaded binary version",
    ))?;
    if downloaded_version != remote_version {
        return Err(Error::new(
            ErrorKind::Other,
            "Downloaded binary version mismatch",
        ));
    }

    // Stop old OS service
    run_systemctl("stop").await?;

    // Backup the Old binary and swap in the new one
    swap_binaries().await?;

    // Start service with retry + rollback
    if try_start_with_rollback().await? {
        info!("Update successful!");
    } else {
        error!("CRITICAL UPDATE FAILURE - PLEASE REBOOT DEVICE");
    }
    Ok(())
}
