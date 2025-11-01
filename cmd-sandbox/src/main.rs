use aya::{Btf, programs::Lsm};
#[rustfmt::skip]
use log::{debug, info, warn};
use tokio::signal;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const CGROUP_BASE: &str = "/sys/fs/cgroup";
const CGROUP_NAME: &str = "cmd_sandbox";
const MEMORY_LIMIT: &str = "10M";  // 10 MB
const CPU_TIME_LIMIT_US: &str = "2000000 1000000";  // 2 seconds CPU time per 1 second period
const WALL_CLOCK_LIMIT: Duration = Duration::from_secs(10);  // 10 seconds wall clock time

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

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
    
    // Attach socket_connect LSM hook (HTTPS-only policy)
    let program: &mut Lsm = ebpf.program_mut("socket_connect").unwrap().try_into()?;
    program.load("socket_connect", &btf)?;
    program.attach()?;
    println!("✓ socket_connect LSM hook attached (HTTPS-only policy)");

    // Setup cgroup for resource limits
    setup_cgroup()?;
    
    // Shared state for tracking process start times
    let process_tracker: Arc<Mutex<HashMap<String, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    
    // Spawn task to monitor and limit curl/wget processes
    let tracker_clone = Arc::clone(&process_tracker);
    tokio::spawn(async move {
        monitor_processes(tracker_clone).await;
    });

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");
    
    // Cleanup cgroup
    cleanup_cgroup();

    Ok(())
}

fn setup_cgroup() -> anyhow::Result<()> {
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
    fs::write(&memory_max, MEMORY_LIMIT)?;
    println!("✓ Memory limit set: {} (cgroup)", MEMORY_LIMIT);
    
    // Set CPU time limit
    let cpu_max = format!("{}/cpu.max", cgroup_path);
    fs::write(&cpu_max, CPU_TIME_LIMIT_US)?;
    println!("✓ CPU time limit set: 2 seconds (cgroup)");
    println!("✓ Wall clock timeout: 10 seconds");
    
    Ok(())
}

fn cleanup_cgroup() {
    let cgroup_path = format!("{}/{}", CGROUP_BASE, CGROUP_NAME);
    let _ = fs::remove_dir(&cgroup_path);
    info!("Cleaned up cgroup");
}

async fn monitor_processes(process_tracker: Arc<Mutex<HashMap<String, Instant>>>) {
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
                                    if start_time.elapsed() > WALL_CLOCK_LIMIT {
                                        info!("Killing {} (PID {}) - exceeded 10s wall clock limit", comm, pid);
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
            info!("✓ Moved PID {} to limited cgroup (10MB memory, 2s CPU time, 10s wall clock)", pid);
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
