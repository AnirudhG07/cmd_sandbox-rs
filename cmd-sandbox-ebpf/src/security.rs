use core::ffi::c_void;

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_uid_gid, bpf_probe_read_kernel},
    macros::lsm,
    programs::LsmContext,
};
use aya_log_ebpf::{info, warn};

use crate::common::{CURL_COMM, WGET_COMM, UID_MIN_UNPRIVILEGED, UID_NOBODY};

#[lsm(hook = "task_kill")]
pub fn task_kill(ctx: LsmContext) -> i32 {
    match try_task_kill(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_task_kill(ctx: &LsmContext) -> Result<i32, i32> {
    let comm = bpf_get_current_comm().map_err(|_| 0)?;
    
    if &comm[..4] != CURL_COMM && &comm[..4] != WGET_COMM {
        return Ok(0);
    }
    
    let sig = unsafe { ctx.arg::<i32>(2) };
    
    const SIGTERM: i32 = 15;
    const SIGINT: i32 = 2;
    
    match sig {
        SIGTERM | SIGINT => {
            info!(ctx, "SEC-004: ✅ ALLOWED signal {} to curl/wget", sig);
            Ok(0)
        }
        _ => {
            warn!(ctx, "SEC-004: 🚫 BLOCKED signal {} to curl/wget (only TERM/INT allowed)", sig);
            Err(-1)
        }
    }
}

#[lsm(hook = "capable")]
pub fn capable(ctx: LsmContext) -> i32 {
    match try_capable(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_capable(ctx: &LsmContext) -> Result<i32, i32> {
    let comm = bpf_get_current_comm().map_err(|_| 0)?;
    
    if &comm[..4] != CURL_COMM && &comm[..4] != WGET_COMM {
        return Ok(0);
    }
    
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFFFFFF) as u32;
    
    if uid == 0 {
        warn!(ctx, "SEC-001: 🚫 BLOCKED curl/wget capability check - running as root (UID=0)");
        return Err(-1);
    }
    
    if uid < UID_MIN_UNPRIVILEGED && uid != UID_NOBODY {
        warn!(ctx, "SEC-001: 🚫 BLOCKED curl/wget capability check - privileged user (UID={})", uid);
        return Err(-1);
    }
    
    let cap = unsafe { ctx.arg::<i32>(2) };
    
    const CAP_NET_ADMIN: i32 = 12;
    const CAP_SYS_ADMIN: i32 = 21;
    const CAP_SYS_MODULE: i32 = 16;
    
    match cap {
        CAP_NET_ADMIN => {
            warn!(ctx, "SEC-003: 🚫 BLOCKED CAP_NET_ADMIN for curl/wget");
            Err(-1)
        }
        CAP_SYS_ADMIN => {
            warn!(ctx, "SEC-005: 🚫 BLOCKED CAP_SYS_ADMIN for curl/wget");
            Err(-1)
        }
        CAP_SYS_MODULE => {
            warn!(ctx, "SEC-005: 🚫 BLOCKED CAP_SYS_MODULE for curl/wget (kernel module access)");
            Err(-1)
        }
        _ => Ok(0)
    }
}

#[lsm(hook = "kernel_read_file")]
pub fn kernel_read_file(ctx: LsmContext) -> i32 {
    match try_kernel_read_file(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_kernel_read_file(ctx: &LsmContext) -> Result<i32, i32> {
    let comm = bpf_get_current_comm().map_err(|_| 0)?;
    
    if &comm[..4] != CURL_COMM && &comm[..4] != WGET_COMM {
        return Ok(0);
    }
    
    let id = unsafe { ctx.arg::<i32>(1) };
    
    warn!(ctx, "SEC-005: 🚫 BLOCKED kernel file read (id={}) for curl/wget", id);
    Err(-1)
}

#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    match try_bprm_check_security(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_bprm_check_security(ctx: &LsmContext) -> Result<i32, i32> {
    let bprm_ptr = unsafe { ctx.arg::<*const c_void>(0) };
    
    let filename_ptr: *const u8 = unsafe {
        bpf_probe_read_kernel(&*(bprm_ptr as *const *const u8)).map_err(|_| 0)?
    };
    
    let mut filename_buf = [0u8; 256];
    let filename_bytes = unsafe {
        aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes(
            filename_ptr,
            &mut filename_buf
        ).map_err(|_| 0)?
    };
    
    let filename_len = filename_bytes.len();
    
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
            return Err(-13);
        }
    }
    
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
        return Ok(0);
    }
    
    let uid = (bpf_get_current_uid_gid() & 0xFFFFFFFF) as u32;
    
    if uid == 0 {
        warn!(ctx, "SEC-001: 🚫 BLOCKED curl/wget execution as root (UID=0)");
        return Err(-1);
    }
    
    if uid < UID_MIN_UNPRIVILEGED && uid != UID_NOBODY {
        warn!(ctx, "SEC-001: 🚫 BLOCKED curl/wget execution as privileged user (UID={})", uid);
        return Err(-1);
    }
    
    info!(ctx, "SEC-001: ✅ Allowing curl/wget execution (UID={})", uid);
    Ok(0)
}
