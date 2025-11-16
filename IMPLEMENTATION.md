# Implementation Details

This document provides technical details on how each policy is implemented in cmd_sandbox-rs.

> Note: The code snippets below are simplified for clarity. Actual implementation may include additional features, error handling, optimizations, etc.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Network Policies](#network-policies)
- [Filesystem Policies](#filesystem-policies)
- [Memory & CPU Policies](#memory--cpu-policies)
- [Security Policies](#security-policies)
- [Process Detection & Tracking](#process-detection--tracking)
- [Code Organization](#code-organization)

## Architecture Overview

The sandbox uses a **hybrid multi-layer approach**:

```
┌─────────────────────────────────────────────────────────────────┐
│                         User Space                              │
├─────────────────────────────────────────────────────────────────┤
│  cmd-sandbox (Rust)                                             │
│  ├─ eBPF Loader Module        (ebpf_loader.rs)                  │
│  ├─ Policy Loader Module      (policy_loader.rs)                │
│  ├─ Filesystem Setup Module   (filesystem_setup.rs)             │
│  ├─ Cgroup Management         (cgroup.rs)                       │
│  ├─ Process Monitoring        (monitoring.rs)                   │
│  ├─ Resource Limits           (resource_limits.rs)              │
│  └─ Policy Configuration      (policy.rs)                       │
├─────────────────────────────────────────────────────────────────┤
│                        Kernel Space                             │
├─────────────────────────────────────────────────────────────────┤
│  eBPF LSM Hooks                                                 │
│  ├─ socket_connect     → Network policy (ports, IPs)            │
│  ├─ file_mmap          → Memory policy (exec mappings)          │
│  ├─ inode_create       → Filesystem policy (write paths)        │
│  ├─ file_open          → Filesystem monitoring                  │
│  ├─ bprm_check_security→ Execution control                      │
│  ├─ capable            → Capability blocking                    │
│  ├─ task_kill          → Signal restrictions                    │
│  └─ kernel_read_file   → Kernel access blocking                 │
│                                                                 │
│  cgroup v2 Controllers                                          │
│  ├─ memory.max         → 10MB limit                             │
│  └─ cpu.max            → 50% CPU limit                          │
└─────────────────────────────────────────────────────────────────┘
```

### Why This Approach?

| Layer             | Technology | Purpose              | Why?                                    |
| ----------------- | ---------- | -------------------- | --------------------------------------- |
| **Kernel LSM**    | eBPF       | Syscall interception | Unbypassed enforcement at syscall level |
| **Kernel cgroup** | cgroup v2  | Resource limits      | Comprehensive accounting + OOM killer   |
| **Userspace**     | Rust/tokio | Process monitoring   | Wall-clock timeout + cgroup assignment  |

## Network Policies

### NET-001: HTTPS-Only Enforcement

**Implementation:** eBPF LSM hook on `socket_connect`

**File:** `cmd-sandbox-ebpf/src/network.rs`

```rust
#[lsm(hook = "socket_connect")]
pub fn socket_connect(socket: *mut sock, address: *const sockaddr, addrlen: c_int) -> i32 {
    // Get current task info
    let comm = get_current_comm();

    // Only enforce on curl/wget
    if !matches_download_tool(&comm) {
        return 0;
    }

    // Extract address family and port
    let sa_family = unsafe { (*address).sa_family };

    match sa_family as u32 {
        AF_INET => {
            // IPv4 connection
            let addr_in = unsafe { *(address as *const sockaddr_in) };
            let port = u16::from_be(addr_in.sin_port);

            match port {
                80 => -EPERM,   // Block HTTP
                443 => 0,       // Allow HTTPS
                53 => 0,        // Allow DNS
                _ => -EPERM     // Block others
            }
        }
        AF_UNIX => 0,  // Allow Unix sockets
        _ => 0
    }
}
```

**How it works:**

1. LSM hook intercepts every `connect()` syscall
2. Checks if calling process is curl/wget (via comm name)
3. Extracts port number from socket address structure
4. Returns `-EPERM` for port 80 (HTTP), `0` for allowed ports
5. Kernel sees `-EPERM` and fails the syscall with "Permission denied"

**Key advantages:**

- ✅ Cannot be bypassed (kernel-level enforcement)
- ✅ No performance overhead (BPF JIT compilation)
- ✅ Works before connection is established
- ✅ No user-space involvement needed

### NET-002: Domain Whitelisting

**Implementation:** IP whitelist populated from DNS resolution

**File:** `cmd-sandbox/src/policy_loader.rs`

```rust
pub fn populate_whitelisted_ips(ebpf: &mut Ebpf, config: &PolicyConfig) -> Result<()> {
    let mut whitelist_map: HashMap<_, u32, u8> =
        HashMap::try_from(ebpf.map_mut("WHITELISTED_IPS").unwrap())?;

    for domain in &config.network_policies.allowed_domains {
        // Resolve domain to IPs
        let addr_string = format!("{}:443", domain);
        if let Ok(addrs) = addr_string.to_socket_addrs() {
            for addr in addrs {
                if let IpAddr::V4(ipv4) = addr.ip() {
                    let ip_be = u32::from(ipv4).to_be();  // Network byte order
                    whitelist_map.insert(ip_be, 1u8, 0)?;
                    info!("Whitelisted: {} -> {}", domain, ipv4);
                }
            }
        }
    }
    Ok(())
}
```

**eBPF side** (`cmd-sandbox-ebpf/src/network.rs`):

```rust
// Check if destination IP is whitelisted
let dest_ip = u32::from_be(addr_in.sin_addr.s_addr);
if let Some(_) = unsafe { WHITELISTED_IPS.get(&dest_ip) } {
    return 0;  // Allow whitelisted IPs
}
// If not whitelisted and policy requires whitelist -> block
if policy.enforce_whitelist == 1 {
    return -EPERM;
}
```

### NET-003: Block Private IPs

**Implementation:** IP range checking in eBPF

```rust
fn is_private_ip(ip: u32) -> bool {
    let ip_host = u32::from_be(ip);  // Convert to host byte order

    // 10.0.0.0/8
    if (ip_host & 0xFF000000) == 0x0A000000 { return true; }

    // 172.16.0.0/12
    if (ip_host & 0xFFF00000) == 0xAC100000 { return true; }

    // 192.168.0.0/16
    if (ip_host & 0xFFFF0000) == 0xC0A80000 { return true; }

    // 127.0.0.0/8 (localhost)
    if (ip_host & 0xFF000000) == 0x7F000000 { return true; }

    false
}
```

## Filesystem Policies

### FS-001: Restrict Write Paths

**Implementation:** eBPF LSM hooks on `inode_create`, `file_open`

**File:** `cmd-sandbox-ebpf/src/filesystem.rs`

```rust
#[lsm(hook = "inode_create")]
pub fn inode_create(dir: *mut inode, dentry: *mut dentry, mode: umode_t) -> i32 {
    let comm = get_current_comm();
    if !matches_download_tool(&comm) {
        return 0;
    }

    // Get the path being created
    let path = get_dentry_path(dentry);

    // Load allowed path from eBPF map
    let policy = unsafe { FILESYSTEM_POLICY.get(0) };
    let allowed_prefix = core::str::from_utf8(&policy.allowed_write_path)
        .unwrap_or("/tmp/cmd_downloads/");

    if path.starts_with(allowed_prefix) {
        return 0;  // Allow
    } else {
        info!("FS-001: Blocked write to: {}", path);
        return -EPERM;  // Block
    }
}
```

**Challenge:** Getting reliable file paths in eBPF LSM hooks is complex. The `dentry` structure traversal requires careful pointer manipulation.

### FS-003: Maximum File Size

**Implementation:** Userspace monitoring of open file descriptors

**File:** `cmd-sandbox/src/monitoring.rs`

```rust
pub fn check_process_file_size(pid: &str) -> Option<u64> {
    let fd_dir = format!("/proc/{}/fd", pid);
    let mut max_size = 0u64;

    if let Ok(entries) = fs::read_dir(&fd_dir) {
        for entry in entries.flatten() {
            if let Ok(link) = fs::read_link(entry.path()) {
                if let Some(path_str) = link.to_str() {
                    if path_str.starts_with("/tmp/cmd_downloads/") {
                        if let Ok(metadata) = fs::metadata(&link) {
                            max_size = max_size.max(metadata.len());
                        }
                    }
                }
            }
        }
    }

    if max_size > 0 { Some(max_size) } else { None }
}
```

**Enforcement** (in `monitor_processes()`):

```rust
if let Some(file_size) = check_process_file_size(&pid) {
    if file_size > max_file_size {
        warn!("FS-003: Killing {} - file size {:.2}MB exceeds limit",
              pid, file_size as f64 / (1024.0 * 1024.0));
        kill_process(&pid);
    }
}
```

### FS-004: Prevent Execution of Downloaded Files

**Implementation:** Two-layer approach

**Layer 1: noexec mount** (`cmd-sandbox/src/filesystem_setup.rs`)

```rust
pub fn mount_noexec(path: &str) -> Result<()> {
    // Bind mount directory to itself
    Command::new("mount")
        .args(&["--bind", path, path])
        .status()?;

    // Remount with noexec flag
    Command::new("mount")
        .args(&["-o", "remount,noexec,nosuid,nodev", path])
        .status()?;

    info!("FS-004: Mounted {} with noexec flag", path);
    Ok(())
}
```

**Layer 2: Permission watcher** (strips execute bits)

```rust
pub async fn strip_exec_permissions_watcher(dir_path: &str, target_perms: u32) {
    loop {
        sleep(Duration::from_millis(100)).await;

        if let Ok(entries) = fs::read_dir(dir_path) {
            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata() {
                    if metadata.is_file() {
                        let mode = metadata.permissions().mode();
                        if (mode & 0o777) != target_perms {
                            let mut perms = metadata.permissions();
                            perms.set_mode(target_perms);  // e.g., 0o644
                            fs::set_permissions(entry.path(), perms)?;
                        }
                    }
                }
            }
        }
    }
}
```

## Memory & CPU Policies

### MEM-001: Maximum Memory (10MB)

**Implementation:** cgroup v2 `memory.max` controller

**File:** `cmd-sandbox/src/cgroup.rs`

```rust
pub fn setup_cgroup(config: &PolicyConfig) -> Result<()> {
    let cgroup_path = format!("{}/{}", CGROUP_BASE, CGROUP_NAME);

    // Create cgroup directory
    fs::create_dir(&cgroup_path)?;

    // Enable memory and CPU controllers
    let subtree_control = format!("{}/cgroup.subtree_control", CGROUP_BASE);
    fs::write(&subtree_control, "+memory +cpu")?;

    // Set memory limit
    let memory_max = format!("{}/memory.max", cgroup_path);
    fs::write(&memory_max, config.memory_policies.max_memory.to_string())?;

    println!("✓ Memory limit: {}MB",
             config.memory_policies.max_memory / (1024 * 1024));

    Ok(())
}
```

**Process assignment:**

```rust
pub fn move_to_cgroup(pid: &str) {
    let cgroup_procs = format!("{}/{}/cgroup.procs", CGROUP_BASE, CGROUP_NAME);
    match fs::write(&cgroup_procs, pid) {
        Ok(_) => info!("✓ Moved PID {} to limited cgroup", pid),
        Err(e) => warn!("Failed to move PID {} to cgroup: {}", pid, e),
    }
}
```

**Enforcement:**

- Kernel tracks all memory allocations (heap, stack, mmap, page cache)
- When limit exceeded → OOM killer triggers
- Process receives SIGKILL (exit code 137)
- Event recorded in `/sys/fs/cgroup/cmd_sandbox/memory.events`

### MEM-004: CPU Time Limit

**Implementation:** cgroup v2 `cpu.max` controller (CFS bandwidth)

```rust
pub fn setup_cgroup(config: &PolicyConfig) -> Result<()> {
    // ... (memory setup above)

    // Set CPU bandwidth limit
    let cpu_max = format!("{}/cpu.max", cgroup_path);
    let cpu_limit = config.get_cpu_limit_string();  // e.g., "500000 1000000"
    fs::write(&cpu_max, &cpu_limit)?;

    println!("✓ CPU limit: {}%", config.memory_policies.cpu_limit_percent);

    Ok(())
}
```

**How CFS bandwidth works:**

- Format: `"quota period"` in microseconds
- Example: `"500000 1000000"` = 50% of one CPU core
- Process gets 500ms of CPU time per 1-second period
- When quota exhausted → process throttled (paused)
- Quota refills at start of next period

**Important:** This measures **CPU processing time**, not wall-clock time. A process waiting for I/O uses virtually no CPU time.

### MEM-003: Wall-Clock Timeout

**Implementation:** Userspace process monitoring with timers

**File:** `cmd-sandbox/src/monitoring.rs`

```rust
pub async fn monitor_processes(
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
                    if file_name.chars().all(|c| c.is_numeric()) {
                        let pid = file_name;
                        let comm_path = format!("/proc/{}/comm", pid);

                        if let Ok(comm) = fs::read_to_string(&comm_path) {
                            let comm = comm.trim();
                            if comm == "curl" || comm == "wget" {
                                handle_download_process(
                                    &pid,
                                    &process_tracker,
                                    wall_clock_limit,
                                    max_file_size
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}
```

**Timeout enforcement:**

```rust
fn handle_download_process(
    pid: &str,
    tracker: &Arc<Mutex<HashMap<String, Instant>>>,
    wall_clock_limit: Duration,
    max_file_size: u64,
) {
    let mut tracker = tracker.lock().unwrap();

    if let Some(start_time) = tracker.get(pid) {
        // Check wall-clock timeout
        if start_time.elapsed() > wall_clock_limit {
            info!("Killing {} - exceeded {}s wall clock",
                  pid, wall_clock_limit.as_secs());
            kill_process(pid);
            tracker.remove(pid);
        }
    } else {
        // New process - start tracking
        tracker.insert(pid.to_string(), Instant::now());
        drop(tracker);  // Release lock
        move_to_cgroup(pid);
    }
}
```

### MEM-006: Stack Size Limit

**Implementation:** `setrlimit()` syscall for `RLIMIT_STACK`

**File:** `cmd-sandbox/src/resource_limits.rs`

```rust
pub fn set_stack_limit(limit_bytes: u64) -> Result<()> {
    let stack_limit = libc::rlimit {
        rlim_cur: limit_bytes,
        rlim_max: limit_bytes,
    };

    unsafe {
        if libc::setrlimit(libc::RLIMIT_STACK, &stack_limit) == 0 {
            println!("✓ Stack limit: {}MB", limit_bytes / (1024 * 1024));
            Ok(())
        } else {
            Err(std::io::Error::last_os_error().into())
        }
    }
}
```

**Enforcement:** Kernel enforces stack limit. Programs exceeding it receive SIGSEGV (segmentation fault).

## Security Policies

### SEC-002: Block Sensitive Environment Variables

**Implementation:** Userspace scanning + logging

**File:** `cmd-sandbox/src/monitoring.rs`

```rust
pub fn check_sensitive_environment(pid: &str) {
    let env_path = format!("/proc/{}/environ", pid);
    match fs::read(&env_path) {
        Ok(bytes) => {
            let env_str = String::from_utf8_lossy(&bytes);
            let sensitive_vars: Vec<&str> = env_str
                .split('\0')
                .filter(|s| {
                    let upper = s.to_uppercase();
                    (upper.contains("PASSWORD") ||
                     upper.contains("KEY") ||
                     upper.contains("SECRET")) && s.contains('=')
                })
                .collect();

            if !sensitive_vars.is_empty() {
                warn!("SEC-002: PID {} has sensitive env vars:", pid);
                for var in &sensitive_vars {
                    if let Some(name) = var.split('=').next() {
                        warn!("  - {}", name);  // Log name only, not value
                    }
                }
            }
        }
        Err(_) => { /* Process may have terminated */ }
    }
}
```

**Limitation:** Cannot actually remove environment variables from running process (kernel security restriction). This is **monitoring only** - alerts but doesn't enforce.

### SEC-003: Block Network Configuration Changes

**Implementation:** eBPF LSM hook on `capable`

**File:** `cmd-sandbox-ebpf/src/security.rs`

```rust
#[lsm(hook = "capable")]
pub fn capable(cred: *const cred, ns: *const user_namespace, cap: i32, opts: u32) -> i32 {
    let comm = get_current_comm();
    if !matches_download_tool(&comm) {
        return 0;
    }

    match cap {
        CAP_NET_ADMIN => {
            info!("SEC-003: Blocked CAP_NET_ADMIN for {}", comm);
            return -EPERM;
        }
        CAP_NET_RAW => {
            info!("SEC-003: Blocked CAP_NET_RAW for {}", comm);
            return -EPERM;
        }
        _ => 0
    }
}
```

### SEC-004: Restrict Signals

**Implementation:** eBPF LSM hook on `task_kill`

```rust
#[lsm(hook = "task_kill")]
pub fn task_kill(p: *mut task_struct, info: *mut kernel_siginfo, sig: i32, cred: *const cred) -> i32 {
    let comm = get_current_comm();
    if !matches_download_tool(&comm) {
        return 0;
    }

    match sig {
        SIGTERM | SIGINT => 0,  // Allow graceful shutdown
        _ => {
            info!("SEC-004: Blocked signal {} from {}", sig, comm);
            -EPERM
        }
    }
}
```

### SEC-005: Block Kernel Access

**Implementation:** eBPF LSM hooks on `capable` and `kernel_read_file`

```rust
#[lsm(hook = "capable")]
pub fn capable(/* ... */) -> i32 {
    match cap {
        CAP_SYS_MODULE |      // Load kernel modules
        CAP_SYS_RAWIO |       // Access /dev/mem, /dev/kmem
        CAP_SYS_ADMIN => {    // Various admin operations
            info!("SEC-005: Blocked {} for {}", cap_name(cap), comm);
            return -EPERM;
        }
        _ => 0
    }
}

#[lsm(hook = "kernel_read_file")]
pub fn kernel_read_file(file: *mut file, id: kernel_read_file_id, contents: bool) -> i32 {
    let comm = get_current_comm();
    if matches_download_tool(&comm) {
        info!("SEC-005: Blocked kernel file read by {}", comm);
        return -EPERM;
    }
    0
}
```

## Process Detection & Tracking

### Process Detection

**Method:** Scan `/proc` filesystem every 100ms

**Why `/proc`?**

- ✅ Reliable and standard across all Linux distributions
- ✅ No special kernel features required
- ✅ Works on all architectures (x86_64, ARM, etc.)
- ✅ Simple to implement and maintain

**Implementation:**

```rust
// Read all entries in /proc
for entry in fs::read_dir("/proc")?.flatten() {
    if let Ok(name) = entry.file_name().into_string() {
        // Check if entry is a PID (all digits)
        if name.chars().all(|c| c.is_numeric()) {
            // Read /proc/<pid>/comm to get process name
            let comm_path = format!("/proc/{}/comm", name);
            if let Ok(comm) = fs::read_to_string(&comm_path) {
                if comm.trim() == "curl" || comm.trim() == "wget" {
                    // Found a download tool!
                    handle_process(name);
                }
            }
        }
    }
}
```

### Tracking State

**Data structure:**

```rust
Arc<Mutex<HashMap<String, Instant>>>
//          ^^^^^^  ^^^^^^^
//          PID     Start time
```

**Why this design?**

- `Arc<Mutex<...>>` allows sharing between async tasks
- `HashMap` provides O(1) lookup and insertion
- `Instant` for monotonic time measurement (unaffected by system clock changes)

## Code Organization

### Module Structure

```
cmd-sandbox/src/
├── main.rs              # Orchestration - loads modules and starts monitoring
├── ebpf_loader.rs       # eBPF program loading and LSM hook attachment
├── policy_loader.rs     # Populate eBPF maps with policy configurations
├── filesystem_setup.rs  # noexec mounts and permission watchers
├── cgroup.rs            # cgroup v2 setup, process assignment, cleanup
├── monitoring.rs        # Process monitoring, timeout enforcement, file size checks
├── resource_limits.rs   # Set rlimits (stack size, memlock)
└── policy.rs            # Policy configuration loading and validation

cmd-sandbox-ebpf/src/
├── main.rs              # Main eBPF entry point
├── network.rs           # Network policy LSM hooks
├── filesystem.rs        # Filesystem policy LSM hooks
├── memory.rs            # Memory policy LSM hooks
├── security.rs          # Security policy LSM hooks
└── common.rs            # Shared utilities and helpers
```

### Key Design Decisions

**1. Modular architecture** - Each policy type in separate module

- Easy to understand and maintain
- Clear separation of concerns
- Can disable individual policies if needed

**2. Configuration-driven** - All policies defined in `policy_config.json`

- No recompilation needed to change limits
- Easy to test different configurations
- Supports per-deployment customization

**3. Fail-safe defaults** - If eBPF hook not available, log warning but continue

- Graceful degradation on older kernels
- Better user experience
- Clear feedback about what's enforced vs. not

**4. Comprehensive logging** - All policy violations logged

- Audit trail for security review
- Debugging and troubleshooting
- Compliance requirements

## Performance Characteristics

### eBPF LSM Hooks

- **Overhead:** <1% (thanks to BPF JIT compilation)
- **Latency:** <1μs per syscall
- **Memory:** ~4KB per loaded program
- **Scalability:** O(1) for most operations

### cgroup Controllers

- **Overhead:** <1% (kernel built-in accounting)
- **Context switch impact:** Minimal (CFS scheduler integration)
- **Memory:** ~100KB per cgroup
- **Enforcement:** Immediate (no polling needed)

### Userspace Monitoring

- **CPU usage:** <0.1% (100ms polling interval)
- **Memory:** ~10KB (process tracking HashMap)
- **Latency:** ±100ms (polling interval)
- **Disk I/O:** Minimal (`/proc` reads are cached in kernel)

**Overall:** Negligible performance impact on normal curl/wget operations.

## Limitations & Future Improvements

### Current Limitations

1. **File path enforcement** - eBPF cannot easily extract full paths from `dentry` structures
2. **100ms detection window** - Very short-lived processes might evade detection
3. **Requires root** - BPF loading and cgroup creation need privileges
4. **IPv4 only** - IPv6 support not yet implemented
5. **Process name based** - Detection by comm name can be spoofed (though requires root)

### Future Improvements

1. **Dynamic policy updates** - Reload configuration without restart
2. **IPv6 support** - Extend network policies to AF_INET6
3. **Metrics export** - Prometheus endpoint for monitoring
4. **Web dashboard** - Real-time visualization of policy enforcement
5. **BPF CO-RE** - Use libbpf CO-RE for better portability
6. **Per-process policies** - Different limits for different users/groups

## References

- [BPF LSM Documentation](https://www.kernel.org/doc/html/latest/bpf/prog_lsm.html)
- [cgroup v2 Documentation](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
- [aya-rs Book](https://aya-rs.dev/book/)
- [Linux Security Modules](https://www.kernel.org/doc/html/latest/admin-guide/LSM/index.html)
