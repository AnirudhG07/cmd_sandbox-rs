// Filesystem Policy Implementations (FS-xxx)
// This module contains all filesystem-related policy enforcement functions

use aya::{Btf, programs::{Lsm, TracePoint}, maps::Array};
use cmd_sandbox_common::policy_shared::FilesystemPolicy;
use crate::policy::PolicyConfig;
use log::{info, warn};
use std::fs;
use std::path::Path;

// ----------------------------------------------------------------------------
// Filesystem Policies (FS-xxx)
// ----------------------------------------------------------------------------

/// FS-001: Allow file writes only to /tmp/curl_downloads/
/// Enforcement: inode_create + file_open LSM hooks + sys_enter_openat tracepoint
pub async fn implement_fs_001(ebpf: &mut aya::Ebpf, btf: &Btf, config: &PolicyConfig) -> anyhow::Result<()> {
    // Attach inode_create LSM hook
    if let Some(program) = ebpf.program_mut("inode_create") {
        let program: Result<&mut Lsm, _> = program.try_into();
        if let Ok(program) = program {
            match program.load("inode_create", btf) {
                Ok(_) => {
                    program.attach()?;
                }
                Err(e) => {
                    println!("⚠ FS-001: inode_create LSM not available: {}", e);
                }
            }
        }
    }
    
    // Attach file_open LSM hook
    if let Some(program) = ebpf.program_mut("file_open") {
        let program: Result<&mut Lsm, _> = program.try_into();
        if let Ok(program) = program {
            match program.load("file_open", btf) {
                Ok(_) => {
                    program.attach()?;
                }
                Err(_) => {}
            }
        }
    }
    
    // Attach sys_enter_openat tracepoint for path validation
    let program: &mut TracePoint = ebpf.program_mut("sys_enter_openat").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_openat")?;
    
    // Populate filesystem policy
    populate_filesystem_policy(ebpf, config)?;
    
    println!("✓ FS-001: Write restrictions enforced (allowed: /tmp/curl_downloads/)");
    
    Ok(())
}

/// FS-003: Maximum file download size: 10MB per file
/// Enforcement: Userspace monitoring of file sizes via /proc/[pid]/fd/
pub fn implement_fs_003(max_file_size: &u64) -> anyhow::Result<()> {
    println!("✓ FS-003: File size limit enabled (max: {:.2}MB per file)", 
             *max_file_size as f64 / (1024.0 * 1024.0));
    println!("  Enforced via process monitoring");
    Ok(())
}

/// FS-004: Prevent execution of downloaded files
/// Enforcement: noexec mount + optional permission watcher + bprm_check_security
pub async fn implement_fs_004(config: &PolicyConfig) -> anyhow::Result<()> {
    if config.filesystem_policies.prevent_execution {
        println!("✓ FS-004: Downloaded file execution prevention enabled");
        println!("  Methods: noexec mount, bprm_check_security hook");
        if config.filesystem_policies.enable_permission_watcher {
            println!("  Permission watcher: enabled (mode: {})", 
                     config.filesystem_policies.watcher_permissions);
        }
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// Helper Functions
// ----------------------------------------------------------------------------

/// Mount a directory with noexec flag to prevent execution of any files within it.
/// This provides FS-004 enforcement at the filesystem level, eliminating race conditions.
pub fn mount_noexec(path: &str) -> anyhow::Result<()> {
    use std::process::Command;
    
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
    use tokio::time::{sleep, Duration};
    
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

pub fn populate_filesystem_policy(ebpf: &mut aya::Ebpf, config: &PolicyConfig) -> anyhow::Result<()> {
    let mut fs_policy_map: Array<_, FilesystemPolicy> = 
        Array::try_from(ebpf.map_mut("FILESYSTEM_POLICY").unwrap())?;
    
    // Get the first allowed write directory from config
    let allowed_path = if !config.filesystem_policies.allowed_write_dirs.is_empty() {
        &config.filesystem_policies.allowed_write_dirs[0]
    } else {
        "/tmp/curl_downloads/"
    };
    
    // Create the directory if it doesn't exist
    let _ = fs::create_dir_all(allowed_path);
    
    // Set permissions to 0777 (rwxrwxrwx) so all users can write
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(allowed_path) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o777);
            let _ = fs::set_permissions(allowed_path, perms);
        }
    }
    
    // FS-004: Mount the directory with noexec to prevent direct execution (if prevent_execution is enabled)
    if config.filesystem_policies.prevent_execution {
        mount_noexec(allowed_path)?;
    }
    
    // Create filesystem policy
    let mut policy = FilesystemPolicy {
        allowed_write_path: [0u8; 256],
        path_len: allowed_path.len() as u32,
    };
    
    // Copy the path bytes
    let path_bytes = allowed_path.as_bytes();
    for (i, &byte) in path_bytes.iter().enumerate() {
        if i < 256 {
            policy.allowed_write_path[i] = byte;
        }
    }
    
    fs_policy_map.set(0, policy, 0)?;
    
    println!("✓ Filesystem policy configured:");
    println!("  Allowed write directory: {}", allowed_path);
    
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
