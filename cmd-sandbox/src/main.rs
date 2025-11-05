use aya::{Btf, programs::Lsm, maps::Array};
use aya::util::online_cpus;
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
    
    // Populate network policy map from configuration
    populate_network_policy(&mut ebpf, &config)?;
    
    println!("✓ socket_connect LSM hook attached with policy from config");

    // Setup cgroup for resource limits
    setup_cgroup(&config)?;
    
    // Shared state for tracking process start times
    let wall_clock_limit = Duration::from_secs(config.memory_policies.max_cpu_time as u64);
    let process_tracker: Arc<Mutex<HashMap<String, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    
    // Spawn task to monitor and limit curl/wget processes
    let tracker_clone = Arc::clone(&process_tracker);
    tokio::spawn(async move {
        monitor_processes(tracker_clone, wall_clock_limit).await;
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

async fn monitor_processes(process_tracker: Arc<Mutex<HashMap<String, Instant>>>, wall_clock_limit: Duration) {
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
                                    }
                                } else {
                                    // New process - track it and move to cgroup
                                    tracker.insert(pid.clone(), Instant::now());
                                    drop(tracker); // Release lock before potentially slow operations
                                    
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
