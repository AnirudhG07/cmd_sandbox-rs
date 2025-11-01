#![no_std]
#![no_main]

use core::ffi::c_void;

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::{lsm, map},
    maps::{Array, HashMap},
    programs::LsmContext,
};
use aya_log_ebpf::{info, warn};
use cmd_sandbox_common::policy_shared::NetworkPolicy;

const CURL_COMM: &[u8; 4] = b"curl";
const WGET_COMM: &[u8; 4] = b"wget";
const AF_UNIX: u16 = 1;  // Unix domain sockets (local only)
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

// eBPF map to store network policy configuration
#[map]
static NETWORK_POLICY: Array<NetworkPolicy> = Array::with_max_entries(1, 0);

// eBPF map to track connection count per PID
#[map]
static CONNECTION_COUNT: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

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

#[lsm(hook = "socket_release")]
pub fn socket_release(ctx: LsmContext) -> i32 {
    match try_socket_release(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_socket_release(ctx: &LsmContext) -> Result<i32, i32> {
    if !is_download_tool(ctx)? {
        return Ok(0);
    }

    // Get PID and decrement connection count
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    if let Some(current_count) = unsafe { CONNECTION_COUNT.get(&pid) }.copied() {
        if current_count > 0 {
            let new_count = current_count - 1;
            if new_count == 0 {
                // Remove entry if count reaches 0
                let _ = CONNECTION_COUNT.remove(&pid);
                info!(ctx, "Connection released for PID {}: {} -> 0 (removed)", pid, current_count);
            } else {
                let _ = CONNECTION_COUNT.insert(&pid, &new_count, 0);
                info!(ctx, "Connection released for PID {}: {} -> {}", pid, current_count, new_count);
            }
        }
    }

    Ok(0)
}

fn try_socket_connect(ctx: &LsmContext) -> Result<i32, i32> {
    if !is_download_tool(ctx)? {
        return Ok(0);
    }

    info!(ctx, "curl/wget socket_connect intercepted");

    // Get network policy from map
    let policy = NETWORK_POLICY.get(0).ok_or(-1)?;

    // Get PID for connection tracking
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

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
                    
                    // Only count non-DNS connections towards the limit (after all checks pass)
                    if port != 53 && policy.max_connections > 0 {
                        let current_count = unsafe { CONNECTION_COUNT.get(&pid) }.copied().unwrap_or(0);
                        
                        if current_count >= policy.max_connections {
                            warn!(ctx, "🚫 SANDBOX BLOCKED: curl exceeded max concurrent connections ({}/{})", 
                                  current_count, policy.max_connections);
                            return Err(-104); // -ECONNREFUSED
                        }
                        
                        // Increment connection count only for allowed connections
                        let new_count = current_count + 1;
                        CONNECTION_COUNT.insert(&pid, &new_count, 0).map_err(|_| -1)?;
                        
                        info!(ctx, "Connection count for PID {}: {} -> {}", pid, current_count, new_count);
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
                    
                    // Only count non-DNS connections towards the limit (after check passes)
                    if port != 53 && policy.max_connections > 0 {
                        let current_count = unsafe { CONNECTION_COUNT.get(&pid) }.copied().unwrap_or(0);
                        
                        if current_count >= policy.max_connections {
                            warn!(ctx, "🚫 SANDBOX BLOCKED: curl exceeded max concurrent connections ({}/{})", 
                                  current_count, policy.max_connections);
                            return Err(-104); // -ECONNREFUSED
                        }
                        
                        // Increment connection count only for allowed connections
                        let new_count = current_count + 1;
                        CONNECTION_COUNT.insert(&pid, &new_count, 0).map_err(|_| -1)?;
                        
                        info!(ctx, "Connection count for PID {}: {} -> {}", pid, current_count, new_count);
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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
