// Cgroup Management Module
// This module handles cgroup v2 setup and management for resource limiting

use std::fs;
use std::path::Path;
use log::info;
use crate::policy::PolicyConfig;

pub const CGROUP_BASE: &str = "/sys/fs/cgroup";
pub const CGROUP_NAME: &str = "cmd_sandbox";

/// Setup cgroup for resource limits (MEM-001, MEM-004)
pub fn setup_cgroup(config: &PolicyConfig) -> anyhow::Result<()> {
    let cgroup_path = format!("{}/{}", CGROUP_BASE, CGROUP_NAME);
    
    // Create cgroup if it doesn't exist
    if !Path::new(&cgroup_path).exists() {
        fs::create_dir(&cgroup_path)?;
        info!("Created cgroup: {}", cgroup_path);
    }
    
    // Enable controllers
    let subtree_control = format!("{}/cgroup.subtree_control", CGROUP_BASE);
    if Path::new(&subtree_control).exists() {
        let _ = fs::write(&subtree_control, "+memory +cpu");
    }
    
    // Set memory limit
    let memory_max = format!("{}/memory.max", cgroup_path);
    let memory_limit = format!("{}", config.memory_policies.max_memory);
    fs::write(&memory_max, &memory_limit)?;
    println!("✓ Memory limit set: {}MB (cgroup)", config.memory_policies.max_memory / (1024 * 1024));
    
    // Set CPU time limit
    let cpu_max = format!("{}/cpu.max", cgroup_path);
    let cpu_limit = config.get_cpu_limit_string();
    fs::write(&cpu_max, &cpu_limit)?;
    println!("✓ CPU limit set: {}% of one core (cgroup)", config.memory_policies.cpu_limit_percent);
    println!("✓ Wall clock timeout: {}s", config.memory_policies.max_cpu_time);
    
    Ok(())
}

/// Cleanup cgroup on exit
pub fn cleanup_cgroup() {
    let cgroup_path = format!("{}/{}", CGROUP_BASE, CGROUP_NAME);
    let _ = fs::remove_dir(&cgroup_path);
    info!("Cleaned up cgroup");
}

/// Move a process to the limited cgroup
pub fn move_to_cgroup(pid: &str) {
    use log::warn;
    let cgroup_procs = format!("{}/{}/cgroup.procs", CGROUP_BASE, CGROUP_NAME);
    match fs::write(&cgroup_procs, pid) {
        Ok(_) => {
            info!("✓ Moved PID {} to limited cgroup (policy-enforced limits)", pid);
        }
        Err(e) => {
            warn!("Failed to move PID {} to cgroup: {}", pid, e);
        }
    }
}
