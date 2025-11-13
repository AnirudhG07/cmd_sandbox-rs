#![no_std]
#![no_main]

use core::ffi::c_void;

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_uid_gid, bpf_probe_read_kernel, bpf_probe_read_user_str_bytes},
    macros::{lsm, map, tracepoint},
    maps::{Array, HashMap},
    programs::{LsmContext, TracePointContext},
};
use aya_log_ebpf::{info, warn};
use cmd_sandbox_common::policy_shared::{NetworkPolicy, FilesystemPolicy, PathDecision, FileSizeTracker};

const CURL_COMM: &[u8; 4] = b"curl";
const WGET_COMM: &[u8; 4] = b"wget";
const AF_UNIX: u16 = 1;  // Unix domain sockets (local only)
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;  // 10MB limit for FS-003/MEM-001

// eBPF map to store network policy configuration
#[map]
static NETWORK_POLICY: Array<NetworkPolicy> = Array::with_max_entries(1, 0);

// eBPF map to store whitelisted IPs (IP address -> 1 if allowed)
// Userspace will populate this based on DNS resolution of allowed domains
#[map]
static WHITELISTED_IPS: HashMap<u32, u8> = HashMap::with_max_entries(256, 0);

// eBPF map to store filesystem policy configuration
#[map]
static FILESYSTEM_POLICY: Array<FilesystemPolicy> = Array::with_max_entries(1, 0);

// eBPF map to coordinate between tracepoint (path reading) and LSM hooks (enforcement)
// Key: PID, Value: PathDecision
#[map]
static PATH_DECISIONS: HashMap<u32, PathDecision> = HashMap::with_max_entries(1024, 0);

// eBPF map to track file write sizes (FS-003: Max 10MB file size)
// Key: PID, Value: FileSizeTracker
#[map]
static WRITE_TRACKER: HashMap<u32, FileSizeTracker> = HashMap::with_max_entries(1024, 0);

#[repr(C)]
struct SockaddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

#[repr(C)]
struct SockaddrIn6 {
    sin6_family: u16,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    sin6_scope_id: u32,
}

#[lsm(hook = "socket_connect")]
pub fn socket_connect(ctx: LsmContext) -> i32 {
    match try_socket_connect(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_socket_connect(ctx: &LsmContext) -> Result<i32, i32> {
    if !is_download_tool(ctx)? {
        return Ok(0);
    }

    // SEC-001: Block curl/wget if running as root (UID=0) or privileged user
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFFFFFF) as u32;
    
    const UID_NOBODY: u32 = 65534;
    const UID_MIN_UNPRIVILEGED: u32 = 1000;
    
    if uid == 0 {
        warn!(ctx, "SEC-001: 🚫 BLOCKED curl/wget running as root (UID=0)");
        return Err(-1); // -EPERM
    }
    
    if uid < UID_MIN_UNPRIVILEGED && uid != UID_NOBODY {
        warn!(ctx, "SEC-001: 🚫 BLOCKED curl/wget running as privileged user (UID={})", uid);
        return Err(-1); // -EPERM
    }

    info!(ctx, "curl/wget socket_connect intercepted (UID={})", uid);

    // Get network policy from map
    let policy = NETWORK_POLICY.get(0).ok_or(-1)?;

    // Get the sockaddr pointer from LSM context (second argument)
    let sockaddr_ptr = unsafe { ctx.arg::<*const c_void>(1) };
    
    if sockaddr_ptr.is_null() {
        warn!(ctx, "🚫 SANDBOX BLOCKED: curl connection (null sockaddr pointer)");
        return Err(-1); // -EPERM
    }

    match read_family(sockaddr_ptr) {
        Ok(AF_INET) => {
            match read_sockaddr_v4(sockaddr_ptr) {
                Ok(addr) => {
                    let port = u16::from_be(addr.sin_port);
                    // sin_addr is already in network byte order (big-endian), don't convert again
                    let ip = addr.sin_addr;
                    
                    // Allow DNS to local resolver (127.0.0.53 or similar) even if loopback is blocked
                    let is_dns_to_resolver = port == 53 && (ip & 0xFF) == 127;
                    
                    // Check domain whitelist for non-DNS connections
                    if port != 53 && !is_dns_to_resolver && !is_ip_whitelisted(ip) {
                        warn!(ctx, "🚫 SANDBOX BLOCKED: curl attempted connection to non-whitelisted domain/IP");
                        return Err(-1); // -EPERM
                    }
                    
                    // Check if private IP blocking is enabled and if IP is private
                    // Exception: allow DNS queries to local resolver
                    if !is_dns_to_resolver && policy.block_private_ips != 0 && is_private_ipv4(ip) {
                        warn!(ctx, "🚫 SANDBOX BLOCKED: curl attempted connection to private IP (port {})", port);
                        return Err(-1); // -EPERM
                    }
                    
                    // Check if port is in allowed list
                    if !is_port_allowed(ctx, port, policy) {
                        warn!(ctx, "🚫 SANDBOX BLOCKED: curl attempted connection on port {}", port);
                        return Err(-1); // -EPERM (Operation not permitted)
                    }
                    
                    info!(ctx, "✅ curl ALLOWED: port {}", port);
                    return Ok(0);
                }
                Err(_) => {
                    warn!(ctx, "🚫 SANDBOX BLOCKED: curl IPv4 connection (could not read sockaddr)");
                    return Err(-1);
                }
            }
        }
        Ok(AF_INET6) => {
            match read_port_v6(sockaddr_ptr) {
                Ok(port) => {
                    // Check if port is in allowed list first
                    if !is_port_allowed(ctx, port, policy) {
                        warn!(ctx, "🚫 SANDBOX BLOCKED: curl attempted connection on port {} (IPv6)", port);
                        return Err(-1); // -EPERM (Operation not permitted)
                    }
                    
                    info!(ctx, "✅ curl ALLOWED: port {} (IPv6)", port);
                    return Ok(0);
                }
                Err(_) => {
                    warn!(ctx, "🚫 SANDBOX BLOCKED: curl IPv6 connection (could not read port)");
                    return Err(-1);
                }
            }
        }
        Ok(AF_UNIX) => {
            // Allow Unix domain sockets (local IPC, DNS resolution, etc.)
            info!(ctx, "curl ALLOWED: Unix domain socket (local only)");
            return Ok(0);
        }
        Ok(unsupported_family) => {
            warn!(ctx, "🚫 SANDBOX BLOCKED: curl unsupported address family {}", unsupported_family);
            return Err(-1);
        }
        Err(_) => {
            warn!(ctx, "🚫 SANDBOX BLOCKED: curl connection (could not read address family)");
            return Err(-1);
        }
    }
}

fn is_port_allowed(ctx: &LsmContext, port: u16, policy: &NetworkPolicy) -> bool {
    let num_ports = policy.num_ports;
    if num_ports > 10 {
        warn!(ctx, "Invalid num_ports in policy: {}", num_ports);
        return false;
    }

    for i in 0..num_ports {
        if policy.allowed_ports[i as usize] == port {
            return true;
        }
    }
    false
}

fn is_download_tool(ctx: &LsmContext) -> Result<bool, i32> {
    let comm = match bpf_get_current_comm() {
        Ok(comm) => comm,
        Err(ret) => {
            warn!(ctx, "bpf_get_current_comm failed: {}", ret);
            return Ok(false);
        }
    };

    // Check for curl
    if &comm[..CURL_COMM.len()] == CURL_COMM && comm[CURL_COMM.len()] == 0 {
        return Ok(true);
    }
    
    // Check for wget
    if &comm[..WGET_COMM.len()] == WGET_COMM && comm[WGET_COMM.len()] == 0 {
        return Ok(true);
    }

    Ok(false)
}

fn is_ip_whitelisted(ip: u32) -> bool {
    // Check if IP is in the whitelist
    unsafe { WHITELISTED_IPS.get(&ip) }.is_some()
}

fn read_family(sockaddr_ptr: *const c_void) -> Result<u16, i32> {
    let family: u16 = unsafe { 
        bpf_probe_read_kernel(sockaddr_ptr as *const u16)
            .map_err(|e| e as i32)? 
    };
    Ok(family)
}

fn read_sockaddr_v4(sockaddr_ptr: *const c_void) -> Result<SockaddrIn, i32> {
    let addr: SockaddrIn = unsafe { 
        bpf_probe_read_kernel(sockaddr_ptr as *const SockaddrIn)
            .map_err(|e| e as i32)? 
    };
    Ok(addr)
}

fn read_port_v6(sockaddr_ptr: *const c_void) -> Result<u16, i32> {
    let addr: SockaddrIn6 = unsafe { 
        bpf_probe_read_kernel(sockaddr_ptr as *const SockaddrIn6)
            .map_err(|e| e as i32)? 
    };
    Ok(u16::from_be(addr.sin6_port))
}

/// Check if an IPv4 address is in a private range
/// Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8
/// IP is in network byte order (big-endian) where first byte is LSB
fn is_private_ipv4(ip: u32) -> bool {
    // Extract first octet (LSB in network byte order)
    let byte1 = ip & 0xFF;
    
    // 10.0.0.0/8
    if byte1 == 10 {
        return true;
    }
    
    // 172.16.0.0/12: first byte = 172, second byte 16-31
    if byte1 == 172 {
        let byte2 = (ip >> 8) & 0xFF;
        if byte2 >= 16 && byte2 <= 31 {
            return true;
        }
    }
    
    // 192.168.0.0/16: first byte = 192, second byte = 168
    if byte1 == 192 {
        let byte2 = (ip >> 8) & 0xFF;
        if byte2 == 168 {
            return true;
        }
    }
    
    // 127.0.0.0/8: Loopback
    if byte1 == 127 {
        return true;
    }
    
    false
}

// Hook into openat syscall to intercept file writes
#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> i32 {
    match try_sys_enter_openat(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_openat(ctx: &TracePointContext) -> Result<i32, i32> {
    // Only check curl/wget processes
    if !is_download_tool_tp(ctx)? {
        return Ok(0);
    }

    // SEC-001: Check UID - block root and privileged users
    let uid = (bpf_get_current_uid_gid() & 0xFFFFFFFF) as u32;
    
    // Block root (UID 0)
    if uid == 0 {
        warn!(ctx, "FS-001 + SEC-001: 🚫 BLOCKED file operation by root (UID=0)");
        return Err(-1);  // EPERM
    }
    
    // Block UIDs < 1000 (except nobody = 65534)
    if uid < 1000 && uid != 65534 {
        warn!(ctx, "FS-001 + SEC-001: 🚫 BLOCKED file operation by privileged user (UID={})", uid);
        return Err(-1);  // EPERM
    }

    // Read syscall arguments
    // openat(int dfd, const char *filename, int flags, umode_t mode)
    // args are at fixed offsets in the tracepoint context
    
    // Read filename pointer (second argument)
    let filename_ptr: *const u8 = unsafe { 
        ctx.read_at::<*const u8>(24).map_err(|_| 0)?  // offset 24 for filename on aarch64
    };
    
    if filename_ptr.is_null() {
        return Ok(0);
    }

    // Read flags (third argument)
    let flags: i32 = unsafe {
        ctx.read_at::<i32>(32).map_err(|_| 0)?  // offset 32 for flags
    };

    // Check if this is a write operation
    // O_WRONLY = 1, O_RDWR = 2, O_CREAT = 64
    const O_WRONLY: i32 = 0x0001;
    const O_RDWR: i32 = 0x0002;
    const O_CREAT: i32 = 0x0040;
    const O_ACCMODE: i32 = 0x0003;
    
    let access_mode = flags & O_ACCMODE;
    let has_creat = (flags & O_CREAT) != 0;
    
    if access_mode != O_WRONLY && access_mode != O_RDWR && !has_creat {
        // Not a write operation
        return Ok(0);
    }

    // Read the filename string from userspace
    let mut filename_buf = [0u8; 256];
    let filename_bytes = unsafe {
        bpf_probe_read_user_str_bytes(filename_ptr, &mut filename_buf)
            .map_err(|_| 0)?
    };

    // Get filesystem policy
    let policy = FILESYSTEM_POLICY.get(0).ok_or(0)?;
    if policy.path_len == 0 {
        // No policy set, allow everything
        return Ok(0);
    }

    // Check if the filename starts with the allowed path
    let path_len = policy.path_len as usize;
    let mut allowed = true;
    
    if filename_bytes.len() < path_len {
        // Path too short to match
        allowed = false;
    } else {
        // Compare path prefix
        for i in 0..path_len {
            if filename_buf[i] != policy.allowed_write_path[i] {
                allowed = false;
                break;
            }
        }
    }

    // Store decision in map for LSM hooks to enforce
    let pid_tgid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() };
    let pid = (pid_tgid >> 32) as u32;
    let tgid = (pid_tgid & 0xFFFFFFFF) as u32;
    
    let decision = PathDecision {
        allowed: if allowed { 1 } else { 0 },
        timestamp: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
        pid,
        tgid,
    };
    
    // Store decision (ignore errors - LSM hooks will allow if not found)
    let _ = PATH_DECISIONS.insert(&pid, &decision, 0);

    if allowed {
        info!(ctx, "FS-001: ✅ ALLOWED write to authorized path");
        Ok(0)
    } else {
        warn!(ctx, "FS-001: 🚫 BLOCKED write to unauthorized path");
        Err(-13) // -EACCES (tracepoint return value ignored, but logged)
    }
}

fn is_download_tool_tp(_ctx: &TracePointContext) -> Result<bool, i32> {
    let comm = bpf_get_current_comm().map_err(|_| 0)?;
    
    Ok(&comm[..4] == CURL_COMM || &comm[..4] == WGET_COMM)
}

// ============================================================================
// FS-001: Restrict file writes to allowed directory  
// ============================================================================
// Note: Tracepoints cannot block syscalls, they only observe
// We keep the tracepoint for logging but need LSM hooks for enforcement
// Unfortunately, getting full paths in LSM hooks is complex
// The best approach is to use seccomp-bpf or rely on DAC permissions

// ============================================================================
// MEM-005: Block memory mapping of executable pages
// ============================================================================
// LSM hook for file_mmap - prevents mmap with PROT_EXEC
#[lsm(hook = "file_mmap")]
pub fn file_mmap(ctx: LsmContext) -> i32 {
    match try_file_mmap(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_file_mmap(ctx: &LsmContext) -> Result<i32, i32> {
    // Check if this is curl or wget
    let comm = bpf_get_current_comm().map_err(|_| 0)?;
    
    if &comm[..4] != CURL_COMM && &comm[..4] != WGET_COMM {
        return Ok(0); // Not our target process
    }
    
    // file_mmap LSM hook signature:
    // int security_file_mmap(struct file *file, unsigned long reqprot,
    //                        unsigned long prot, unsigned long flags,
    //                        unsigned long addr, unsigned long addr_only);
    //
    // ctx.arg(0) = file pointer (we don't use)
    // ctx.arg(1) = reqprot (requested protection)
    // ctx.arg(2) = prot (actual protection flags)
    // ctx.arg(3) = flags
    // ctx.arg(4) = addr
    // ctx.arg(5) = addr_only
    
    let prot = unsafe { ctx.arg::<u64>(2) };
    
    // PROT_EXEC = 0x4 (from <sys/mman.h>)
    const PROT_EXEC: u64 = 0x4;
    
    // Check if PROT_EXEC is set
    if prot & PROT_EXEC != 0 {
        // Block executable mappings
        warn!(ctx, "MEM-005: 🚫 BLOCKED executable mmap for curl/wget");
        return Err(-13); // -EACCES
    }
    
    Ok(0)
}

// ============================================================================
// SEC-004: Restrict signal handling (allow only TERM, INT)
// ============================================================================
// LSM hook for task_kill - filters which signals can be sent to curl/wget
#[lsm(hook = "task_kill")]
pub fn task_kill(ctx: LsmContext) -> i32 {
    match try_task_kill(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_task_kill(ctx: &LsmContext) -> Result<i32, i32> {
    // task_kill LSM hook signature:
    // int security_task_kill(struct task_struct *p, struct kernel_siginfo *info,
    //                        int sig, const struct cred *cred);
    //
    // ctx.arg(0) = target task_struct pointer
    // ctx.arg(1) = siginfo pointer
    // ctx.arg(2) = signal number
    // ctx.arg(3) = cred pointer
    
    // Check if target process is curl or wget
    let comm = bpf_get_current_comm().map_err(|_| 0)?;
    
    if &comm[..4] != CURL_COMM && &comm[..4] != WGET_COMM {
        return Ok(0); // Not our target process
    }
    
    let sig = unsafe { ctx.arg::<i32>(2) };
    
    // SIGTERM = 15, SIGINT = 2
    const SIGTERM: i32 = 15;
    const SIGINT: i32 = 2;
    
    match sig {
        SIGTERM | SIGINT => {
            info!(ctx, "SEC-004: ✅ ALLOWED signal {} to curl/wget", sig);
            Ok(0)
        }
        _ => {
            warn!(ctx, "SEC-004: 🚫 BLOCKED signal {} to curl/wget (only TERM/INT allowed)", sig);
            Err(-1) // -EPERM
        }
    }
}

// ============================================================================
// SEC-003: Prevent network interface configuration changes
// ============================================================================
// LSM hook for capable - blocks CAP_NET_ADMIN for curl/wget
#[lsm(hook = "capable")]
pub fn capable(ctx: LsmContext) -> i32 {
    match try_capable(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_capable(ctx: &LsmContext) -> Result<i32, i32> {
    // Check if this is curl or wget
    let comm = bpf_get_current_comm().map_err(|_| 0)?;
    
    if &comm[..4] != CURL_COMM && &comm[..4] != WGET_COMM {
        return Ok(0); // Not our target process
    }
    
    // SEC-001: Block curl/wget if running as root (UID=0) or privileged user
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFFFFFF) as u32;
    
    const UID_NOBODY: u32 = 65534;
    const UID_MIN_UNPRIVILEGED: u32 = 1000;
    
    if uid == 0 {
        warn!(ctx, "SEC-001: 🚫 BLOCKED curl/wget capability check - running as root (UID=0)");
        return Err(-1); // -EPERM
    }
    
    if uid < UID_MIN_UNPRIVILEGED && uid != UID_NOBODY {
        warn!(ctx, "SEC-001: 🚫 BLOCKED curl/wget capability check - privileged user (UID={})", uid);
        return Err(-1); // -EPERM
    }
    
    // capable LSM hook signature:
    // int security_capable(const struct cred *cred, struct user_namespace *ns,
    //                      int cap, unsigned int opts);
    //
    // ctx.arg(0) = cred pointer
    // ctx.arg(1) = user_namespace pointer
    // ctx.arg(2) = capability being checked
    // ctx.arg(3) = options
    
    let cap = unsafe { ctx.arg::<i32>(2) };
    
    // CAP_NET_ADMIN = 12 (network administration capability)
    const CAP_NET_ADMIN: i32 = 12;
    const CAP_SYS_ADMIN: i32 = 21;
    const CAP_SYS_MODULE: i32 = 16;
    
    match cap {
        CAP_NET_ADMIN => {
            warn!(ctx, "SEC-003: 🚫 BLOCKED CAP_NET_ADMIN for curl/wget");
            Err(-1) // -EPERM
        }
        CAP_SYS_ADMIN => {
            warn!(ctx, "SEC-005: 🚫 BLOCKED CAP_SYS_ADMIN for curl/wget");
            Err(-1) // -EPERM
        }
        CAP_SYS_MODULE => {
            warn!(ctx, "SEC-005: 🚫 BLOCKED CAP_SYS_MODULE for curl/wget (kernel module access)");
            Err(-1) // -EPERM
        }
        _ => Ok(0) // Allow other capabilities
    }
}

// ============================================================================
// SEC-005: Block access to kernel memory and modules
// ============================================================================
// LSM hook for kernel_read_file - blocks reading kernel memory/modules
#[lsm(hook = "kernel_read_file")]
pub fn kernel_read_file(ctx: LsmContext) -> i32 {
    match try_kernel_read_file(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_kernel_read_file(ctx: &LsmContext) -> Result<i32, i32> {
    // Check if this is curl or wget
    let comm = bpf_get_current_comm().map_err(|_| 0)?;
    
    if &comm[..4] != CURL_COMM && &comm[..4] != WGET_COMM {
        return Ok(0); // Not our target process
    }
    
    // kernel_read_file LSM hook signature:
    // int security_kernel_read_file(struct file *file, enum kernel_read_file_id id,
    //                               bool contents);
    //
    // ctx.arg(0) = file pointer
    // ctx.arg(1) = id (type of kernel file being read)
    // ctx.arg(2) = contents (bool)
    
    // READING_MODULE = 2, READING_KEXEC_IMAGE = 3, READING_KEXEC_INITRAMFS = 4
    // READING_FIRMWARE = 5, READING_POLICY = 7
    let id = unsafe { ctx.arg::<i32>(1) };
    
    // Block all kernel file reads for curl/wget
    warn!(ctx, "SEC-005: 🚫 BLOCKED kernel file read (id={}) for curl/wget", id);
    Err(-1) // -EPERM
}

// ============================================================================
// SEC-001: Prevent curl/wget from running as root/privileged user
// FS-004: Prevent execution of downloaded files from /tmp/curl_downloads/
// ============================================================================
// LSM hook: bprm_check_security
// Called during execve() to validate the binary being executed
// This enforces:
//   - SEC-001: curl/wget must NOT run with UID 0 (root)
//   - FS-004: Files in /tmp/curl_downloads/ must NOT be executable
#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    match try_bprm_check_security(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_bprm_check_security(ctx: &LsmContext) -> Result<i32, i32> {
    // Get the filename being executed
    // bprm_check_security signature: int security_bprm_check(struct linux_binprm *bprm)
    // struct linux_binprm contains:
    //   - filename: path to the binary (char *filename)
    //   - file: file pointer
    //   - cred: credentials for the process
    
    let bprm_ptr = unsafe { ctx.arg::<*const c_void>(0) };
    
    // Read the filename from linux_binprm struct
    // The filename field is a char* pointer, typically at offset 0
    let filename_ptr: *const u8 = unsafe {
        bpf_probe_read_kernel(&*(bprm_ptr as *const *const u8)).map_err(|_| 0)?
    };
    
    // Read the filename string - use kernel read since filename is in kernel space
    let mut filename_buf = [0u8; 256];
    let filename_bytes = unsafe {
        // Use bpf_probe_read_kernel_str_bytes for kernel memory
        aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes(
            filename_ptr,
            &mut filename_buf
        ).map_err(|_| 0)?
    };
    
    let filename_len = filename_bytes.len();
    
    // FS-004: Check if trying to execute a file from /tmp/curl_downloads/
    // This prevents execution of downloaded files
    const DOWNLOADS_PATH: &[u8] = b"/tmp/curl_downloads/";
    let downloads_path_len = DOWNLOADS_PATH.len();
    
    if filename_len >= downloads_path_len {
        let mut is_downloads_path = true;
        for i in 0..downloads_path_len {
            if filename_buf[i] != DOWNLOADS_PATH[i] {
                is_downloads_path = false;
                break;
            }
        }
        
        if is_downloads_path {
            warn!(ctx, "FS-004: 🚫 BLOCKED execution of downloaded file from /tmp/curl_downloads/");
            return Err(-13); // -EACCES
        }
    }
    
    // Check if filename contains "curl" or "wget"
    let mut is_curl_or_wget = false;
    let search_len = if filename_len > 200 { 200 } else { filename_len };
    
    for i in 0..search_len {
        if i + 4 <= search_len {
            if &filename_buf[i..i+4] == b"curl" || &filename_buf[i..i+4] == b"wget" {
                is_curl_or_wget = true;
                break;
            }
        }
    }
    
    if !is_curl_or_wget {
        return Ok(0); // Not curl/wget, allow
    }
    
    // Get current UID - use bpf helper to get current UID
    // This gets the UID of the process attempting to exec curl/wget
    let uid = (aya_ebpf::helpers::bpf_get_current_uid_gid() & 0xFFFFFFFF) as u32;
    
    // SEC-001: Block if trying to run curl/wget as root (UID 0) or other privileged user (UID < 1000)
    // Exception: Allow 'nobody' user (UID 65534)
    const UID_NOBODY: u32 = 65534;
    const UID_MIN_UNPRIVILEGED: u32 = 1000;
    
    if uid == 0 {
        warn!(ctx, "SEC-001: 🚫 BLOCKED curl/wget execution as root (UID=0)");
        return Err(-1); // -EPERM
    }
    
    if uid < UID_MIN_UNPRIVILEGED && uid != UID_NOBODY {
        warn!(ctx, "SEC-001: 🚫 BLOCKED curl/wget execution as privileged user (UID={})", uid);
        return Err(-1); // -EPERM
    }
    
    // Allow execution for non-privileged users
    info!(ctx, "SEC-001: ✅ Allowing curl/wget execution (UID={})", uid);
    Ok(0)
}

// FS-001: Restrict file writes to /tmp/curl_downloads/ directory only
// inode_create LSM hook - called when files are created with path context
#[lsm(hook = "inode_create")]
pub fn inode_create(ctx: LsmContext) -> i32 {
    match try_inode_create(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_inode_create(ctx: &LsmContext) -> Result<i32, i32> {
    // Only check curl/wget processes
    if !is_download_tool(ctx).unwrap_or(false) {
        return Ok(0);
    }

    // SEC-001: Block root and privileged users
    let uid = (bpf_get_current_uid_gid() & 0xFFFFFFFF) as u32;
    if uid == 0 {
        warn!(ctx, "FS-001 + SEC-001: 🚫 BLOCKED file creation by root (UID=0)");
        return Err(-1);
    }
    
    if uid < 1000 && uid != 65534 {
        warn!(ctx, "FS-001 + SEC-001: 🚫 BLOCKED file creation by privileged user (UID={})", uid);
        return Err(-1);
    }

    // Check if tracepoint has made a decision about this operation
    let pid_tgid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() };
    let pid = (pid_tgid >> 32) as u32;
    
    if let Some(decision) = unsafe { PATH_DECISIONS.get(&pid) } {
        // Check if decision is recent (within 10ms - generous window)
        let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        let age_ns = now - decision.timestamp;
        
        if age_ns < 10_000_000 {  // 10ms in nanoseconds
            // Clean up the decision
            let _ = PATH_DECISIONS.remove(&pid);
            
            if decision.allowed == 0 {
                // Tracepoint determined path was unauthorized
                warn!(ctx, "FS-001: 🚫 ENFORCING: Blocked unauthorized file creation");
                return Err(-13);  // -EACCES - THIS ACTUALLY BLOCKS!
            } else {
                info!(ctx, "FS-001: ✅ ENFORCING: Allowed file creation");
                return Ok(0);
            }
        } else {
            // Decision too old, clean it up
            let _ = PATH_DECISIONS.remove(&pid);
        }
    }
    
    // No recent decision found - allow (fail open)
    // This handles cases where LSM hook is called without tracepoint
    Ok(0)
}

// file_open LSM hook - called when a file is opened
#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    match try_file_open(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_file_open(ctx: &LsmContext) -> Result<i32, i32> {
    // Only check for curl/wget processes
    if !is_download_tool(ctx).unwrap_or(false) {
        return Ok(0);
    }

    // Get the file pointer from LSM context (first argument)
    let file_ptr = unsafe { ctx.arg::<*const c_void>(0) };
    
    if file_ptr.is_null() {
        return Ok(0);
    }

    // Read file flags to check if it's being opened for writing
    // O_WRONLY = 0x1, O_RDWR = 0x2, O_CREAT = 0x40, O_TRUNC = 0x200
    let write_flags = 0x1 | 0x2 | 0x40 | 0x200;
    
    // Try reading f_flags at offset 24 (typical for recent kernels)
    let flags_ptr = unsafe { (file_ptr as *const u8).offset(24) as *const u32 };
    let flags: u32 = unsafe {
        bpf_probe_read_kernel(flags_ptr).unwrap_or(0)
    };
    
    // Check if any write flags are set
    if (flags & write_flags) == 0 {
        // Not a write operation, allow
        return Ok(0);
    }

    // This is a write operation - check the decision from tracepoint
    let pid_tgid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() };
    let pid = (pid_tgid >> 32) as u32;
    
    if let Some(decision) = unsafe { PATH_DECISIONS.get(&pid) } {
        // Check if decision is recent (within 10ms)
        let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        let age_ns = now - decision.timestamp;
        
        if age_ns < 10_000_000 {  // 10ms
            // Clean up decision
            let _ = PATH_DECISIONS.remove(&pid);
            
            if decision.allowed == 0 {
                warn!(ctx, "FS-001: 🚫 ENFORCING: Blocked unauthorized file open (write)");
                return Err(-13);  // -EACCES - BLOCKS THE OPERATION
            } else {
                info!(ctx, "FS-001: ✅ ENFORCING: Allowed file open (write)");
                return Ok(0);
            }
        } else {
            let _ = PATH_DECISIONS.remove(&pid);
        }
    }
    
    // No recent decision - allow (fail open)

    Ok(0)
}

// ===========================================================================
// FS-003/MEM-001: Track file write sizes and enforce 10MB limit
// ===========================================================================

/// Tracepoint for sys_enter_write to track cumulative file writes
/// Enforces FS-003: Maximum file size 10MB
/// NOTE: Currently disabled - relying on userspace file size monitoring instead
/// because tracepoint offsets are architecture-dependent and unreliable
#[tracepoint]
pub fn sys_enter_write(ctx: TracePointContext) -> i32 {
    // Disabled - just return OK to avoid false positives from wrong offsets
    // File size enforcement is done in userspace by monitoring /proc/[pid]/fd/
    0
}

fn try_sys_enter_write(_ctx: &TracePointContext) -> Result<i32, i32> {
    // DISABLED - See userspace check_process_file_size() instead
    Ok(0)
}

// Helper function to check if process is curl or wget
fn is_curl_or_wget(comm: &[u8; 16]) -> bool {
    (comm[0..4] == *CURL_COMM) || (comm[0..4] == *WGET_COMM)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
