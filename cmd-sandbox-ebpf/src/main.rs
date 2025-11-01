#![no_std]
#![no_main]

use core::ffi::c_void;

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_probe_read_kernel},
    macros::lsm,
    programs::LsmContext,
};
use aya_log_ebpf::{info, warn};

const CURL_COMM: &[u8; 4] = b"curl";
const AF_UNIX: u16 = 1;  // Unix domain sockets (local only)
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const HTTPS_PORT: u16 = 443;

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
    if !is_curl(ctx)? {
        return Ok(0);
    }

    info!(ctx, "curl socket_connect intercepted");

    // Get the sockaddr pointer from LSM context (second argument)
    let sockaddr_ptr = unsafe { ctx.arg::<*const c_void>(1) };
    
    if sockaddr_ptr.is_null() {
        warn!(ctx, "🚫 SANDBOX BLOCKED: curl connection (null sockaddr pointer)");
        return Err(-1); // -EPERM
    }

    match read_family(sockaddr_ptr) {
        Ok(AF_INET) => {
            match read_port_v4(sockaddr_ptr) {
                Ok(port) => {
                    if port == HTTPS_PORT {
                        info!(ctx, "curl ALLOWED: HTTPS port {}", port);
                        return Ok(0);
                    } else {
                        warn!(ctx, "🚫 SANDBOX BLOCKED: curl attempted HTTP connection on port {}", port);
                        return Err(-1); // -EPERM (Operation not permitted)
                    }
                }
                Err(_) => {
                    warn!(ctx, "🚫 SANDBOX BLOCKED: curl IPv4 connection (could not read port)");
                    return Err(-1);
                }
            }
        }
        Ok(AF_INET6) => {
            match read_port_v6(sockaddr_ptr) {
                Ok(port) => {
                    if port == HTTPS_PORT {
                        info!(ctx, "curl ALLOWED: HTTPS port {} (IPv6)", port);
                        return Ok(0);
                    } else {
                        warn!(ctx, "🚫 SANDBOX BLOCKED: curl attempted HTTP connection on port {} (IPv6)", port);
                        return Err(-1); // -EPERM (Operation not permitted)
                    }
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
        Ok(family) => {
            warn!(ctx, "🚫 SANDBOX BLOCKED: curl unsupported address family {}", family);
            return Err(-1);
        }
        Err(_) => {
            warn!(ctx, "🚫 SANDBOX BLOCKED: curl connection (could not read address family)");
            return Err(-1);
        }
    }
}

fn is_curl(ctx: &LsmContext) -> Result<bool, i32> {
    let comm = match bpf_get_current_comm() {
        Ok(comm) => comm,
        Err(ret) => {
            warn!(ctx, "bpf_get_current_comm failed: {}", ret);
            return Ok(false);
        }
    };

    if &comm[..CURL_COMM.len()] != CURL_COMM {
        return Ok(false);
    }
    if comm[CURL_COMM.len()] != 0 {
        return Ok(false);
    }

    Ok(true)
}

fn read_family(sockaddr_ptr: *const c_void) -> Result<u16, i32> {
    let family: u16 = unsafe { 
        bpf_probe_read_kernel(sockaddr_ptr as *const u16)
            .map_err(|e| e as i32)? 
    };
    Ok(family)
}

fn read_port_v4(sockaddr_ptr: *const c_void) -> Result<u16, i32> {
    let addr: SockaddrIn = unsafe { 
        bpf_probe_read_kernel(sockaddr_ptr as *const SockaddrIn)
            .map_err(|e| e as i32)? 
    };
    Ok(u16::from_be(addr.sin_port))
}

fn read_port_v6(sockaddr_ptr: *const c_void) -> Result<u16, i32> {
    let addr: SockaddrIn6 = unsafe { 
        bpf_probe_read_kernel(sockaddr_ptr as *const SockaddrIn6)
            .map_err(|e| e as i32)? 
    };
    Ok(u16::from_be(addr.sin6_port))
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
