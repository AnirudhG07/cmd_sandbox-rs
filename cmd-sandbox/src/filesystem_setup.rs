// Filesystem Setup Module
// This module handles filesystem-specific security setup like noexec mounts and permission watchers

use crate::policy::PolicyConfig;
use log::{info, warn};
use std::fs;
use std::process::Command;
use tokio::time::{sleep, Duration};

/// Mount a directory with noexec flag to prevent execution of any files within it.
/// This provides FS-004 enforcement at the filesystem level, eliminating race conditions.
pub fn mount_noexec(path: &str) -> anyhow::Result<()> {
    info!("FS-004: Setting up noexec mount for {}", path);
    
    // First, check if already mounted with noexec
    let mount_output = Command::new("mount")
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to check mounts: {}", e))?;
    
    let mount_str = String::from_utf8_lossy(&mount_output.stdout);
    let already_mounted = mount_str.lines().any(|line| {
        line.contains(path) && line.contains("noexec")
    });
    
    if already_mounted {
        info!("FS-004: {} already mounted with noexec", path);
        return Ok(());
    }
    
    // Use bind mount with noexec
    // First bind mount to itself
    let status = Command::new("mount")
        .args(&["--bind", path, path])
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to bind mount: {}", e))?;
    
    if !status.success() {
        return Err(anyhow::anyhow!("Bind mount failed for {}", path));
    }
    
    // Then remount with noexec
    let status = Command::new("mount")
        .args(&["-o", "remount,noexec,nosuid,nodev", path])
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to remount with noexec: {}", e))?;
    
    if !status.success() {
        return Err(anyhow::anyhow!("Remount with noexec failed for {}", path));
    }
    
    info!("✓ FS-004: Successfully mounted {} with noexec flag", path);
    Ok(())
}

/// FS-004: Watch downloads directory and set specific permissions on all files
/// This prevents execution via interpreters (e.g., bash /tmp/curl_downloads/script.sh)
pub async fn strip_exec_permissions_watcher(dir_path: &str, target_permissions: u32) {
    use std::os::unix::fs::PermissionsExt;
    
    info!("FS-004: Starting permission watcher for {} (setting mode: {:o})", dir_path, target_permissions);
    
    // First, set permissions on any existing files
    if let Ok(entries) = fs::read_dir(dir_path) {
        for entry in entries.flatten() {
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_file() {
                    let mut perms = metadata.permissions();
                    perms.set_mode(target_permissions);
                    if let Err(e) = fs::set_permissions(entry.path(), perms) {
                        warn!("Failed to set permissions on {:?}: {}", entry.path(), e);
                    } else {
                        info!("FS-004: Set permissions {:o} on {:?}", target_permissions, entry.path());
                    }
                }
            }
        }
    }
    
    // Watch for new files every 100ms
    loop {
        sleep(Duration::from_millis(100)).await;
        
        if let Ok(entries) = fs::read_dir(dir_path) {
            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata() {
                    if metadata.is_file() {
                        let mode = metadata.permissions().mode();
                        // Check if permissions don't match target
                        if (mode & 0o777) != target_permissions {
                            let mut perms = metadata.permissions();
                            perms.set_mode(target_permissions);
                            if let Err(e) = fs::set_permissions(entry.path(), perms) {
                                warn!("Failed to set permissions on {:?}: {}", entry.path(), e);
                            } else {
                                info!("FS-004: Set permissions {:o} on {:?}", target_permissions, entry.path());
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Setup filesystem policies including noexec mount and optional permission watcher
pub fn setup_filesystem_policies(config: &PolicyConfig, allowed_path: &str) -> anyhow::Result<()> {
    // FS-004: Mount the directory with noexec to prevent direct execution (if prevent_execution is enabled)
    if config.filesystem_policies.prevent_execution {
        mount_noexec(allowed_path)?;
    }
    
    // FS-004: Start background task to set permissions on downloaded files (if enabled)
    if config.filesystem_policies.enable_permission_watcher {
        let allowed_path_clone = allowed_path.to_string();
        let target_perms = config.filesystem_policies.get_watcher_mode();
        let perms_str = config.filesystem_policies.watcher_permissions.clone();
        tokio::spawn(async move {
            strip_exec_permissions_watcher(&allowed_path_clone, target_perms).await;
        });
        println!("✓ Permission watcher enabled (mode: {})", perms_str);
    }
    
    Ok(())
}
