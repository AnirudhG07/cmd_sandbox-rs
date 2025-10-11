#![no_std]
#![no_main]

use core::{ffi::c_void, mem};

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_probe_read_kernel},
    macros::lsm,
    programs::LsmContext,
};
use aya_log_ebpf::{info, warn};

const CURL_COMM: &[u8; 4] = b"curl";
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const EACCES: i32 = 13;
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

    // Get sockaddr from context - this may require accessing ctx.arg(1) 
    // depending on the aya-rs version
    info!(ctx, "curl socket_connect intercepted");
    
    // For now, just allow all curl connections and log
    // We'll need to investigate the proper way to access sockaddr
    Ok(0)
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

// Remove unused helper functions for now since we're not accessing sockaddr yet
// fn read_family(sockaddr_ptr: *const c_void) -> Result<u16, i32> { ... }
// fn read_port_v4(sockaddr_ptr: *const c_void) -> Result<u16, i32> { ... }  
// fn read_port_v6(sockaddr_ptr: *const c_void) -> Result<u16, i32> { ... }

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
