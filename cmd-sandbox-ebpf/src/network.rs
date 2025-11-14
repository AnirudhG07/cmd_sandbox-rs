use core::ffi::c_void;

use aya_ebpf::{
    helpers::{bpf_get_current_uid_gid, bpf_probe_read_kernel},
    macros::{lsm, map},
    maps::{Array, HashMap},
    programs::LsmContext,
};
use aya_log_ebpf::{info, warn};
use cmd_sandbox_common::policy_shared::NetworkPolicy;

use crate::common::{is_download_tool, SockaddrIn, SockaddrIn6, AF_INET, AF_INET6, AF_UNIX, UID_MIN_UNPRIVILEGED, UID_NOBODY};

#[map]
static NETWORK_POLICY: Array<NetworkPolicy> = Array::with_max_entries(1, 0);

#[map]
static WHITELISTED_IPS: HashMap<u32, u8> = HashMap::with_max_entries(256, 0);

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

    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFFFFFF) as u32;
    
    if uid == 0 {
        warn!(ctx, "SEC-001: 🚫 BLOCKED curl/wget running as root (UID=0)");
        return Err(-1);
    }
    
    if uid < UID_MIN_UNPRIVILEGED && uid != UID_NOBODY {
        warn!(ctx, "SEC-001: 🚫 BLOCKED curl/wget running as privileged user (UID={})", uid);
        return Err(-1);
    }

    info!(ctx, "curl/wget socket_connect intercepted (UID={})", uid);

    let policy = NETWORK_POLICY.get(0).ok_or(-1)?;
    let sockaddr_ptr = unsafe { ctx.arg::<*const c_void>(1) };
    
    if sockaddr_ptr.is_null() {
        warn!(ctx, "🚫 SANDBOX BLOCKED: curl connection (null sockaddr pointer)");
        return Err(-1);
    }

    match read_family(sockaddr_ptr) {
        Ok(AF_INET) => {
            match read_sockaddr_v4(sockaddr_ptr) {
                Ok(addr) => {
                    let port = u16::from_be(addr.sin_port);
                    let ip = addr.sin_addr;
                    
                    let is_dns_to_resolver = port == 53 && (ip & 0xFF) == 127;
                    
                    if port != 53 && !is_dns_to_resolver && !is_ip_whitelisted(ip) {
                        warn!(ctx, "🚫 SANDBOX BLOCKED: curl attempted connection to non-whitelisted domain/IP");
                        return Err(-1);
                    }
                    
                    if !is_dns_to_resolver && policy.block_private_ips != 0 && is_private_ipv4(ip) {
                        warn!(ctx, "🚫 SANDBOX BLOCKED: curl attempted connection to private IP (port {})", port);
                        return Err(-1);
                    }
                    
                    if !is_port_allowed(ctx, port, policy) {
                        warn!(ctx, "🚫 SANDBOX BLOCKED: curl attempted connection on port {}", port);
                        return Err(-1);
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
                    if !is_port_allowed(ctx, port, policy) {
                        warn!(ctx, "🚫 SANDBOX BLOCKED: curl attempted connection on port {} (IPv6)", port);
                        return Err(-1);
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

fn is_ip_whitelisted(ip: u32) -> bool {
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

fn is_private_ipv4(ip: u32) -> bool {
    let byte1 = ip & 0xFF;
    
    if byte1 == 10 {
        return true;
    }
    
    if byte1 == 172 {
        let byte2 = (ip >> 8) & 0xFF;
        if byte2 >= 16 && byte2 <= 31 {
            return true;
        }
    }
    
    if byte1 == 192 {
        let byte2 = (ip >> 8) & 0xFF;
        if byte2 == 168 {
            return true;
        }
    }
    
    if byte1 == 127 {
        return true;
    }
    
    false
}
