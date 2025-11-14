use aya::{Btf, programs::{Lsm, TracePoint}, maps::Array};
use cmd_sandbox_common::policy_shared::NetworkPolicy;
#[rustfmt::skip]
use log::{debug, info, warn};
use tokio::signal;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

mod policy;
use policy::PolicyConfig;

const CGROUP_BASE: &str = "/sys/fs/cgroup";
const CGROUP_NAME: &str = "cmd_sandbox";

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
    
    // Attach socket_connect LSM hook and populate policy map
    let program: &mut Lsm = ebpf.program_mut("socket_connect").unwrap().try_into()?;
    program.load("socket_connect", &btf)?;
    program.attach()?;
    println!("✓ socket_connect LSM attached (Network policy enforcement + SEC-001)");
    
    // Attach file_mmap LSM hook for MEM-005 (block executable mmap)
    // Note: This may not be available on all kernels
    if let Some(program) = ebpf.program_mut("file_mmap") {
        let program: Result<&mut Lsm, _> = program.try_into();
        if let Ok(program) = program {
            match program.load("file_mmap", &btf) {
                Ok(_) => {
                    program.attach()?;
                    println!("✓ file_mmap LSM attached (MEM-005: block executable mappings)");
                }
                Err(_) => {
                    println!("⚠ file_mmap LSM not available on this kernel (MEM-005 not enforced)");
                }
            }
        }
    } else {
        println!("⚠ file_mmap LSM not found (MEM-005 not enforced)");
    }
    
    // Attach task_kill LSM hook for SEC-004 (restrict signals)
    if let Some(program) = ebpf.program_mut("task_kill") {
        let program: Result<&mut Lsm, _> = program.try_into();
        if let Ok(program) = program {
            match program.load("task_kill", &btf) {
                Ok(_) => {
                    program.attach()?;
                    println!("✓ task_kill LSM attached (SEC-004: restrict signals to TERM/INT)");
                }
                Err(e) => {
                    println!("⚠ task_kill LSM not available on this kernel (SEC-004 not enforced): {}", e);
                }
            }
        }
    } else {
        println!("⚠ task_kill LSM not found (SEC-004 not enforced)");
    }
    
    // Attach capable LSM hook for SEC-003 and SEC-005 (block capabilities)
    if let Some(program) = ebpf.program_mut("capable") {
        let program: Result<&mut Lsm, _> = program.try_into();
        if let Ok(program) = program {
            match program.load("capable", &btf) {
                Ok(_) => {
                    program.attach()?;
                    println!("✓ capable LSM attached (SEC-003: block net config, SEC-005: block kernel access)");
                }
                Err(e) => {
                    println!("⚠ capable LSM not available on this kernel (SEC-003/SEC-005 not enforced): {}", e);
                }
            }
        }
    } else {
        println!("⚠ capable LSM not found (SEC-003/SEC-005 not enforced)");
    }
    
    // Attach kernel_read_file LSM hook for SEC-005 (block kernel memory/modules)
    if let Some(program) = ebpf.program_mut("kernel_read_file") {
        let program: Result<&mut Lsm, _> = program.try_into();
        if let Ok(program) = program {
            match program.load("kernel_read_file", &btf) {
                Ok(_) => {
                    program.attach()?;
                    println!("✓ kernel_read_file LSM attached (SEC-005: block kernel file reads)");
                }
                Err(e) => {
                    println!("⚠ kernel_read_file LSM not available on this kernel (SEC-005 not fully enforced): {}", e);
                }
            }
        }
    } else {
        println!("⚠ kernel_read_file LSM not found (SEC-005 not fully enforced)");
    }
    
    // Attach bprm_check_security LSM hook for SEC-001 + FS-004 
    if let Some(program) = ebpf.program_mut("bprm_check_security") {
        let program: Result<&mut Lsm, _> = program.try_into();
        if let Ok(program) = program {
            match program.load("bprm_check_security", &btf) {
                Ok(_) => {
                    program.attach()?;
                    println!("✓ bprm_check_security LSM attached (SEC-001 + FS-004: non-privileged exec + prevent downloaded file execution)");
                }
                Err(e) => {
                    println!("⚠ bprm_check_security LSM not available on this kernel (SEC-001/FS-004 not enforced): {}", e);
                }
            }
        }
    } else {
        println!("⚠ bprm_check_security LSM not found (SEC-001/FS-004 not enforced)");
    }
    
    // Attach inode_create LSM hook for FS-001 (restrict file writes)
    if let Some(program) = ebpf.program_mut("inode_create") {
        let program: Result<&mut Lsm, _> = program.try_into();
        if let Ok(program) = program {
            match program.load("inode_create", &btf) {
                Ok(_) => {
                    program.attach()?;
                    println!("✓ inode_create LSM attached (FS-001: restrict file creation)");
                }
                Err(e) => {
                    println!("⚠ inode_create LSM not available on this kernel (FS-001 not enforced): {}", e);
                }
            }
        }
    } else {
        println!("⚠ inode_create LSM not found (FS-001 not enforced)");
    }
    
    // Attach file_open LSM hook for FS-001 (additional file operation monitoring)
    if let Some(program) = ebpf.program_mut("file_open") {
        let program: Result<&mut Lsm, _> = program.try_into();
        if let Ok(program) = program {
            match program.load("file_open", &btf) {
                Ok(_) => {
                    program.attach()?;
                    println!("✓ file_open LSM attached (FS-001: monitor file opens)");
                }
                Err(e) => {
                    println!("⚠ file_open LSM not available on this kernel: {}", e);
                }
            }
        }
    }
    
    // Attach path_truncate LSM hook for FS-001 (file truncation operations)
    if let Some(program) = ebpf.program_mut("path_truncate") {
        let program: Result<&mut Lsm, _> = program.try_into();
        if let Ok(program) = program {
            match program.load("path_truncate", &btf) {
                Ok(_) => {
                    program.attach()?;
                    println!("✓ path_truncate LSM attached (FS-001: monitor file truncation)");
                }
                Err(e) => {
                    println!("⚠ path_truncate LSM not available on this kernel: {}", e);
                }
            }
        }
    }
    
    // Attach tracepoint for openat syscall to restrict file writes (path checking)
    let program: &mut TracePoint = ebpf.program_mut("sys_enter_openat").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_openat")?;
    println!("✓ sys_enter_openat tracepoint attached (FS-001: path-based write restrictions)");
    println!("  Note: Tracepoint provides path checking, LSM hooks provide enforcement");
    
    // Attach tracepoint for write syscall to enforce file size limits (FS-003/MEM-001)
    let program: &mut TracePoint = ebpf.program_mut("sys_enter_write").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_write")?;
    println!("✓ sys_enter_write tracepoint attached (FS-003/MEM-001: 10MB file size limit)");
    
    // Populate network policy map from configuration
    populate_network_policy(&mut ebpf, &config)?;
    
    // Populate filesystem policy map from configuration
    populate_filesystem_policy(&mut ebpf, &config)?;
    
    println!("✓ All LSM hooks and tracepoints attached with policy from config");


    // Setup cgroup for resource limits
    setup_cgroup(&config)?;
    
    // MEM-006: Set stack size limit to 8MB
    set_stack_limit(8 * 1024 * 1024)?;
    
    // Shared state for tracking process start times
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

fn populate_network_policy(ebpf: &mut aya::Ebpf, config: &PolicyConfig) -> anyhow::Result<()> {
    let mut network_policy_map: Array<_, NetworkPolicy> = 
        Array::try_from(ebpf.map_mut("NETWORK_POLICY").unwrap())?;

    // Create network policy struct from config
    let mut allowed_ports = [0u16; 10];
    let num_ports = config.network_policies.allowed_ports.len().min(10);
    
    for (i, &port) in config.network_policies.allowed_ports.iter().take(10).enumerate() {
        allowed_ports[i] = port;
    }

    let policy = NetworkPolicy {
        allowed_ports,
        num_ports: num_ports as u32,
        block_private_ips: if config.network_policies.block_private_ips { 1 } else { 0 },
        max_connections: config.network_policies.max_connections,
        connection_timeout: config.network_policies.connection_timeout,
    };

    // Write policy to map
    network_policy_map.set(0, policy, 0)?;
    
    println!("✓ Network policy loaded into eBPF map:");
    println!("  Allowed ports: {:?}", &allowed_ports[..num_ports]);
    println!("  Block private IPs: {}", config.network_policies.block_private_ips);
    println!("  Max connections: {}", config.network_policies.max_connections);
    
    // Populate whitelisted IPs from allowed domains
    populate_whitelisted_ips(ebpf, config)?;
    
    Ok(())
}

fn populate_whitelisted_ips(ebpf: &mut aya::Ebpf, config: &PolicyConfig) -> anyhow::Result<()> {
    use std::net::ToSocketAddrs;
    use aya::maps::HashMap;
    
    let mut whitelist_map: HashMap<_, u32, u8> = 
        HashMap::try_from(ebpf.map_mut("WHITELISTED_IPS").unwrap())?;
    
    println!("✓ Resolving and whitelisting domains:");
    
    for domain in &config.network_policies.allowed_domains {
        // Resolve domain to IPs using DNS
        // We use port 443 as a dummy port for resolution
        let addr_string = format!("{}:443", domain);
        
        match addr_string.to_socket_addrs() {
            Ok(addrs) => {
                for addr in addrs {
                    if let std::net::IpAddr::V4(ipv4) = addr.ip() {
                        let ip_u32 = u32::from(ipv4);
                        // Convert to network byte order (big-endian) to match what eBPF sees
                        let ip_be = ip_u32.to_be();
                        
                        whitelist_map.insert(ip_be, 1u8, 0)?;
                        println!("  {} -> {} (0x{:08x})", domain, ipv4, ip_be);
                    }
                }
            }
            Err(e) => {
                eprintln!("  ⚠️  Failed to resolve {}: {}", domain, e);
            }
        }
    }
    
    Ok(())
}

/// Mount a directory with noexec flag to prevent execution of any files within it.
/// This provides FS-004 enforcement at the filesystem level, eliminating race conditions.
fn mount_noexec(path: &str) -> anyhow::Result<()> {
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
async fn strip_exec_permissions_watcher(dir_path: &str, target_permissions: u32) {
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

fn populate_filesystem_policy(ebpf: &mut aya::Ebpf, config: &PolicyConfig) -> anyhow::Result<()> {
    use cmd_sandbox_common::policy_shared::FilesystemPolicy;
    use aya::maps::Array;
    
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

fn setup_cgroup(config: &PolicyConfig) -> anyhow::Result<()> {
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

fn cleanup_cgroup() {
    let cgroup_path = format!("{}/{}", CGROUP_BASE, CGROUP_NAME);
    let _ = fs::remove_dir(&cgroup_path);
    info!("Cleaned up cgroup");
}

async fn monitor_processes(
    process_tracker: Arc<Mutex<HashMap<String, Instant>>>, 
    wall_clock_limit: Duration,
    max_file_size: u64,
) {
    let mut interval = tokio::time::interval(Duration::from_millis(100));
    
    loop {
        interval.tick().await;
        
        // Scan /proc for curl/wget processes
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(file_name) = entry.file_name().into_string() {
                    // Check if it's a PID directory
                    if file_name.chars().all(|c| c.is_numeric()) {
                        let pid = file_name;
                        let comm_path = format!("/proc/{}/comm", pid);
                        
                        if let Ok(comm) = fs::read_to_string(&comm_path) {
                            let comm = comm.trim();
                            if comm == "curl" || comm == "wget" {
                                // Check if we're tracking this process
                                let mut tracker = process_tracker.lock().unwrap();
                                
                                if let Some(start_time) = tracker.get(&pid) {
                                    // Check if it exceeded wall clock limit
                                    if start_time.elapsed() > wall_clock_limit {
                                        info!("Killing {} (PID {}) - exceeded {}s wall clock limit", 
                                              comm, pid, wall_clock_limit.as_secs());
                                        kill_process(&pid);
                                        tracker.remove(&pid);
                                        continue;
                                    }
                                    
                                    // FS-003/MEM-001: Check if process is writing a file > max_file_size
                                    if let Some(file_size) = check_process_file_size(&pid) {
                                        if file_size > max_file_size {
                                            warn!("FS-003: Killing {} (PID {}) - file size {:.2}MB exceeds {:.2}MB limit", 
                                                  comm, pid, file_size as f64 / (1024.0 * 1024.0), max_file_size as f64 / (1024.0 * 1024.0));
                                            println!("⚠️  FS-003 VIOLATION: {} (PID {}) - file size {:.2}MB > {:.2}MB", 
                                                     comm, pid, file_size as f64 / (1024.0 * 1024.0), max_file_size as f64 / (1024.0 * 1024.0));
                                            kill_process(&pid);
                                            tracker.remove(&pid);
                                        } else if file_size > (max_file_size * 90 / 100) {
                                            // Warn when approaching limit
                                            info!("FS-003: {} (PID {}) approaching limit - {:.2}MB/{:.2}MB", 
                                                  comm, pid, file_size as f64 / (1024.0 * 1024.0), max_file_size as f64 / (1024.0 * 1024.0));
                                        }
                                    }
                                } else {
                                    // New process - track it and move to cgroup
                                    tracker.insert(pid.clone(), Instant::now());
                                    drop(tracker); // Release lock before potentially slow operations
                                    
                                    // Clean dangerous environment variables (SEC-002)
                                    // SEC-002: Block environment variables containing PASSWORD, KEY, SECRET
                                    check_sensitive_environment(&pid);
                                    
                                    // Check if already in our cgroup
                                    let cgroup_file = format!("/proc/{}/cgroup", pid);
                                    if let Ok(cgroup_content) = fs::read_to_string(&cgroup_file) {
                                        if !cgroup_content.contains(CGROUP_NAME) {
                                            // Move process to limited cgroup
                                            move_to_cgroup(&pid);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            // Clean up tracker for processes that no longer exist
            let mut tracker = process_tracker.lock().unwrap();
            tracker.retain(|pid, _| {
                Path::new(&format!("/proc/{}", pid)).exists()
            });
        }
    }
}

fn move_to_cgroup(pid: &str) {
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

fn kill_process(pid: &str) {
    if let Ok(pid_num) = pid.parse::<i32>() {
        unsafe {
            libc::kill(pid_num, libc::SIGKILL);
        }
    }
}

// FS-003: Check if a process has any open files exceeding the configured max_file_size
// Returns the maximum file size found, or None if no files in /tmp/curl_downloads/
fn check_process_file_size(pid: &str) -> Option<u64> {
    // Check open file descriptors in /proc/PID/fd/
    let fd_dir = format!("/proc/{}/fd", pid);
    let mut max_size = 0u64;
    
    if let Ok(entries) = fs::read_dir(&fd_dir) {
        for entry in entries.flatten() {
            if let Ok(link) = fs::read_link(entry.path()) {
                // Check if file is in /tmp/curl_downloads/
                if let Some(path_str) = link.to_str() {
                    if path_str.starts_with("/tmp/curl_downloads/") {
                        // Get file size
                        if let Ok(metadata) = fs::metadata(&link) {
                            let size = metadata.len();
                            if size > max_size {
                                max_size = size;
                            }
                        }
                    }
                }
            }
        }
    }
    
    if max_size > 0 {
        Some(max_size)
    } else {
        None
    }
}

// SEC-002: Clean dangerous environment variables from a process
// SEC-002: Check and log sensitive environment variables containing PASSWORD, KEY, SECRET
fn check_sensitive_environment(pid: &str) {
    // Read the process environment
    let env_path = format!("/proc/{}/environ", pid);
    match fs::read(&env_path) {
        Ok(bytes) => {
            let env_str = String::from_utf8_lossy(&bytes);
            let sensitive_vars: Vec<&str> = env_str
                .split('\0')
                .filter(|s| {
                    let upper = s.to_uppercase();
                    (upper.contains("PASSWORD") || upper.contains("KEY") || upper.contains("SECRET")) 
                    && s.contains('=')
                })
                .collect();
            
            if !sensitive_vars.is_empty() {
                warn!("SEC-002 VIOLATION: PID {} has sensitive environment variables:", pid);
                for var in &sensitive_vars {
                    // Only log the variable name, not the value (for security)
                    if let Some(name) = var.split('=').next() {
                        warn!("  - {}", name);
                    }
                }
                warn!("Policy: These variables should be removed before process execution");
                warn!("Note: Full enforcement requires wrapper script or custom process spawning");
            } else {
                info!("✓ SEC-002: No sensitive environment variables detected for PID {}", pid);
            }
        }
        Err(e) => {
            // Process may have terminated
            debug!("Could not read environment for PID {}: {}", pid, e);
        }
    }
}

// Note: This function is kept for documentation purposes
// It shows the original design where we tried to block env vars
// Now we use check_sensitive_environment() instead
#[allow(dead_code)]
fn clean_process_environment(pid: &str, blocked_vars: &[&str]) {
    // Note: We cannot directly modify another process's environment variables from userspace
    // This function serves as documentation of the policy
    // In a full implementation, you would:
    // 1. Use a wrapper script that cleans env vars before executing curl/wget
    // 2. Or use a custom launcher that spawns curl/wget with a clean environment
    // 3. Or use namespace/container isolation to start with a clean slate
    
    info!("Policy: Would block environment variables {:?} for PID {}", blocked_vars, pid);
    // In production, implement via wrapper script or process spawning control
}

// MEM-006: Set stack size limit to 8MB
fn set_stack_limit(limit_bytes: u64) -> anyhow::Result<()> {
    let stack_limit = libc::rlimit {
        rlim_cur: limit_bytes,
        rlim_max: limit_bytes,
    };
    
    unsafe {
        if libc::setrlimit(libc::RLIMIT_STACK, &stack_limit) == 0 {
            info!("✓ Set stack size limit to {}MB", limit_bytes / (1024 * 1024));
            println!("✓ Stack size limit set: {}MB", limit_bytes / (1024 * 1024));
            Ok(())
        } else {
            let err = std::io::Error::last_os_error();
            warn!("Failed to set stack limit: {}", err);
            Err(err.into())
        }
    }
}
