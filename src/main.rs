use dg_edge_updater::{
    BIN_PATH, acquire_update_lock, download_verified, eligible_for_rollout, fetch_manifest,
    get_binary_version, install_verified, recover_pending, update_client,
};
use dg_logger::{DruidGardenLogger, TimestampFormat};
use log::{Level, info};
use semver::Version;
use std::io::Error;

#[tokio::main]
async fn main() -> Result<(), Error> {
    DruidGardenLogger::build()
        .use_colors(true)
        .current_level(Level::Info)
        .timestamp_format(TimestampFormat::Local)
        .with_target_level("zbus", Level::Warn)
        .with_target_level("tracing", Level::Warn)
        .init()
        .map_err(|e| Error::other(format!("{e:?}")))?;
    let _lock = acquire_update_lock()?;
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let boot_only = arguments == ["--recover-only"];
    if !arguments.is_empty() && !boot_only {
        return Err(Error::other("Only --recover-only is supported"));
    }
    let recovered = recover_pending(boot_only).await?;
    if boot_only {
        return Ok(());
    }
    if recovered {
        return Err(Error::other(
            "Recovered an interrupted update; retry explicitly after reviewing device health",
        ));
    }
    let manifest = fetch_manifest(&update_client()?).await?;
    let remote_version = Version::parse(&manifest.version).map_err(Error::other)?;
    let local_version = get_binary_version(BIN_PATH).await?;
    if remote_version <= local_version {
        info!("Up to date: {local_version}");
        return Ok(());
    }
    if !eligible_for_rollout(&manifest)? {
        info!("Release is not yet enabled for this device's rollout cohort");
        return Ok(());
    }
    let stage = download_verified(&manifest).await?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(Error::other)?
        .as_secs();
    if manifest.expires_unix <= now {
        return Err(Error::other("Release metadata expired during download"));
    }
    install_verified(stage, &manifest, &local_version).await?;
    info!("Update to {remote_version} installed and service remained active");
    Ok(())
}
