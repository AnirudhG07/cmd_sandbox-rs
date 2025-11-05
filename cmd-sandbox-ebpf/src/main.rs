#![no_std]
#![no_main]

use core::ffi::c_void;

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_str_bytes},
    macros::{lsm, map, tracepoint},
    maps::{Array, HashMap},
    programs::{LsmContext, TracePointContext},
};
use aya_log_ebpf::{info, warn};
use cmd_sandbox_common::policy_shared::{NetworkPolicy, FilesystemPolicy};

const CURL_COMM: &[u8; 4] = b"curl";
const WGET_COMM: &[u8; 4] = b"wget";
const AF_UNIX: u16 = 1;  // Unix domain sockets (local only)
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

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

    info!(ctx, "curl/wget socket_connect intercepted");

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
    if filename_bytes.len() < path_len {
        // Path too short to match
        warn!(ctx, "🚫 BLOCKED: Write to unauthorized path");
        return Err(-13); // -EACCES
    }

    // Compare path prefix
    for i in 0..path_len {
        if filename_buf[i] != policy.allowed_write_path[i] {
            warn!(ctx, "🚫 BLOCKED: Write to unauthorized path");
            return Err(-13); // -EACCES
        }
    }

    // Path matches allowed directory
    Ok(0)
}

fn is_download_tool_tp(ctx: &TracePointContext) -> Result<bool, i32> {
    let comm = bpf_get_current_comm().map_err(|_| 0)?;
    
    Ok(&comm[..4] == CURL_COMM || &comm[..4] == WGET_COMM)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
