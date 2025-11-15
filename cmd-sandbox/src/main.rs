use tokio::signal;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

mod policy;
mod cgroup;
mod monitoring;
mod ebpf_loader;
mod policy_loader;
mod filesystem_setup;
mod resource_limits;

use policy::PolicyConfig;
use cgroup::{setup_cgroup, cleanup_cgroup};
use monitoring::monitor_processes;
use ebpf_loader::{load_ebpf, attach_all_hooks};
use policy_loader::{populate_network_policy, populate_filesystem_policy};
use filesystem_setup::setup_filesystem_policies;
use resource_limits::{set_memlock_rlimit, set_stack_limit};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Load policy configuration
    let config = PolicyConfig::default()?;
    config.validate()?;
    
    println!("✓ Loaded policy configuration (version {})", config.policy_version);
    println!("  Target command: {}", config.command);
    println!("  Memory limit: {}MB", config.memory_policies.max_memory / (1024 * 1024));
    println!("  CPU limit: {}%", config.memory_policies.cpu_limit_percent);
    println!("  Wall clock timeout: {}s", config.memory_policies.max_cpu_time);
    println!("  Allowed ports: {:?}", config.network_policies.allowed_ports);
    println!("  Block private IPs: {}", config.network_policies.block_private_ips);
    println!();

    // Setup resource limits
    set_memlock_rlimit()?;
    
    // Load eBPF program and attach hooks
    let (mut ebpf, btf) = load_ebpf()?;
    attach_all_hooks(&mut ebpf, &btf)?;
    
    // Populate eBPF maps with policy configuration
    populate_network_policy(&mut ebpf, &config)?;
    let allowed_path = populate_filesystem_policy(&mut ebpf, &config)?;
    
    // Setup filesystem policies (noexec mount, permission watcher)
    setup_filesystem_policies(&config, &allowed_path)?;

    // Setup cgroup for resource limits (MEM-001, MEM-004)
    setup_cgroup(&config)?;
    
    // MEM-006: Set stack size limit to 8MB
    set_stack_limit(8 * 1024 * 1024)?;
    
    // Setup shared state for process monitoring
    let wall_clock_limit = Duration::from_secs(config.memory_policies.max_cpu_time as u64);
    let max_file_size = config.filesystem_policies.max_file_size;
    let process_tracker: Arc<Mutex<HashMap<String, Instant>>> = Arc::new(Mutex::new(HashMap::new()));

    // Spawn task to monitor and limit curl/wget processes
    let tracker_clone = Arc::clone(&process_tracker);
    tokio::spawn(async move {
        monitor_processes(tracker_clone, wall_clock_limit, max_file_size).await;
    });

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    // Cleanup cgroup
    cleanup_cgroup();

    Ok(())
}
