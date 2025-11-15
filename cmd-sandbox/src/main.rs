use aya::Btf;
use log::{debug, warn};
use tokio::signal;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

mod policy;
mod cgroup;
mod monitoring;
mod policy_impl;

use policy::PolicyConfig;
use cgroup::cleanup_cgroup;
use monitoring::monitor_processes;
use policy_impl::{net, sec, fs, mem};

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

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/cmd-sandbox"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let btf = Btf::from_sys_fs()?;
    
    // Setup shared state for process monitoring
    let wall_clock_limit = Duration::from_secs(config.memory_policies.max_cpu_time as u64);
    let max_file_size = config.filesystem_policies.max_file_size;
    let process_tracker: Arc<Mutex<HashMap<String, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    
    // ============================================================================
    // Policy Implementation - Comment out any line to disable that policy
    // ============================================================================
    
    // Network Policies (NET-xxx)
    net::implement_net_001(&mut ebpf, &btf, &config)?;       // NET-001: Domain whitelist
    // implement_net_002 - Not needed (blocked by NET-006 port restrictions)
    // implement_net_003 - Connection timeout (handled in monitoring)
    // implement_net_004 - Max concurrent connections (handled in monitoring)
    net::implement_net_005(&mut ebpf, &btf, &config)?;       // NET-005: Block private IPs
    net::implement_net_006(&mut ebpf, &btf, &config)?;       // NET-006: Port restrictions (80, 443)
    
    // Security Policies (SEC-xxx)
    sec::implement_sec_001(&mut ebpf, &btf)?;                // SEC-001: Non-privileged execution only
    sec::implement_sec_002(&process_tracker)?;               // SEC-002: Block sensitive env vars
    sec::implement_sec_003(&mut ebpf, &btf)?;                // SEC-003: Prevent network config changes
    sec::implement_sec_004(&mut ebpf, &btf)?;                // SEC-004: Restrict signals (TERM/INT only)
    sec::implement_sec_005(&mut ebpf, &btf)?;                // SEC-005: Block kernel access
    // implement_sec_006 - Network namespace isolation (not implemented)
    
    // Filesystem Policies (FS-xxx)
    fs::implement_fs_001(&mut ebpf, &btf, &config).await?;   // FS-001: Restrict write directory
    // implement_fs_002 - Block reads outside home (not implemented)
    fs::implement_fs_003(&max_file_size)?;                   // FS-003: Max file size (10MB)
    fs::implement_fs_004(&config).await?;                    // FS-004: Prevent execution of downloads
    // implement_fs_005 - Total storage quota (not implemented)
    // implement_fs_006 - Block system directories (not implemented)
    
    // Memory Policies (MEM-xxx)
    mem::implement_mem_001(&config)?;                        // MEM-001: Max memory (100MB via cgroup)
    // implement_mem_002 - Block fork/exec (not implemented - would break curl)
    mem::implement_mem_003(&wall_clock_limit)?;              // MEM-003: Max execution time
    mem::implement_mem_004(&config)?;                        // MEM-004: CPU throttling (50%)
    mem::implement_mem_005(&mut ebpf, &btf)?;                // MEM-005: Block executable mmap
    mem::implement_mem_006()?;                               // MEM-006: Stack size limit (8MB)
    
    println!();
    println!("✓ All implemented policies loaded and enforced");
    println!("  See main.rs policy implementation section to enable/disable specific policies");
    println!();
    
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
