use aya_ebpf::{
    helpers::{bpf_get_current_uid_gid, bpf_probe_read_kernel, bpf_probe_read_user_str_bytes},
    macros::{lsm, tracepoint, map},
    maps::{Array, HashMap},
    programs::{LsmContext, TracePointContext},
};
use aya_log_ebpf::{info, warn};
use cmd_sandbox_common::policy_shared::{FilesystemPolicy, PathDecision};

use crate::common::{is_download_tool, is_download_tool_tp, UID_MIN_UNPRIVILEGED, UID_NOBODY};

#[map]
static FILESYSTEM_POLICY: Array<FilesystemPolicy> = Array::with_max_entries(1, 0);

#[map]
static PATH_DECISIONS: HashMap<u32, PathDecision> = HashMap::with_max_entries(1024, 0);

#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> i32 {
    match try_sys_enter_openat(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_openat(ctx: &TracePointContext) -> Result<i32, i32> {
    if !is_download_tool_tp(ctx)? {
        return Ok(0);
    }

    let uid = (bpf_get_current_uid_gid() & 0xFFFFFFFF) as u32;
    
    if uid == 0 {
        warn!(ctx, "FS-001 + SEC-001: 🚫 BLOCKED file operation by root (UID=0)");
        return Err(-1);
    }
    
    if uid < UID_MIN_UNPRIVILEGED && uid != UID_NOBODY {
        warn!(ctx, "FS-001 + SEC-001: 🚫 BLOCKED file operation by privileged user (UID={})", uid);
        return Err(-1);
    }

    let filename_ptr: *const u8 = unsafe { 
        ctx.read_at::<*const u8>(24).map_err(|_| 0)?
    };
    
    if filename_ptr.is_null() {
        return Ok(0);
    }

    let flags: i32 = unsafe {
        ctx.read_at::<i32>(32).map_err(|_| 0)?
    };

    const O_WRONLY: i32 = 0x0001;
    const O_RDWR: i32 = 0x0002;
    const O_CREAT: i32 = 0x0040;
    const O_ACCMODE: i32 = 0x0003;
    
    let access_mode = flags & O_ACCMODE;
    let has_creat = (flags & O_CREAT) != 0;
    
    if access_mode != O_WRONLY && access_mode != O_RDWR && !has_creat {
        return Ok(0);
    }

    let mut filename_buf = [0u8; 256];
    let filename_bytes = unsafe {
        bpf_probe_read_user_str_bytes(filename_ptr, &mut filename_buf)
            .map_err(|_| 0)?
    };

    let policy = FILESYSTEM_POLICY.get(0).ok_or(0)?;
    if policy.path_len == 0 {
        return Ok(0);
    }

    let path_len = policy.path_len as usize;
    let mut allowed = true;
    
    if filename_bytes.len() < path_len {
        allowed = false;
    } else {
        for i in 0..path_len {
            if filename_buf[i] != policy.allowed_write_path[i] {
                allowed = false;
                break;
            }
        }
    }

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tgid = (pid_tgid & 0xFFFFFFFF) as u32;
    
    let decision = PathDecision {
        allowed: if allowed { 1 } else { 0 },
        timestamp: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
        pid,
        tgid,
    };
    
    let _ = PATH_DECISIONS.insert(&pid, &decision, 0);

    if allowed {
        info!(ctx, "FS-001: ✅ ALLOWED write to authorized path");
        Ok(0)
    } else {
        warn!(ctx, "FS-001: 🚫 BLOCKED write to unauthorized path");
        Err(-13)
    }
}

#[lsm(hook = "inode_create")]
pub fn inode_create(ctx: LsmContext) -> i32 {
    match try_inode_create(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_inode_create(ctx: &LsmContext) -> Result<i32, i32> {
    if !is_download_tool(ctx).unwrap_or(false) {
        return Ok(0);
    }

    let uid = (bpf_get_current_uid_gid() & 0xFFFFFFFF) as u32;
    if uid == 0 {
        warn!(ctx, "FS-001 + SEC-001: 🚫 BLOCKED file creation by root (UID=0)");
        return Err(-1);
    }
    
    if uid < UID_MIN_UNPRIVILEGED && uid != UID_NOBODY {
        warn!(ctx, "FS-001 + SEC-001: 🚫 BLOCKED file creation by privileged user (UID={})", uid);
        return Err(-1);
    }

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    
    if let Some(decision) = unsafe { PATH_DECISIONS.get(&pid) } {
        let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        let age_ns = now - decision.timestamp;
        
        if age_ns < 10_000_000 {
            let _ = PATH_DECISIONS.remove(&pid);
            
            if decision.allowed == 0 {
                warn!(ctx, "FS-001: 🚫 ENFORCING: Blocked unauthorized file creation");
                return Err(-13);
            } else {
                info!(ctx, "FS-001: ✅ ENFORCING: Allowed file creation");
                return Ok(0);
            }
        } else {
            let _ = PATH_DECISIONS.remove(&pid);
        }
    }
    
    Ok(0)
}

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    match try_file_open(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_file_open(ctx: &LsmContext) -> Result<i32, i32> {
    use core::ffi::c_void;
    
    if !is_download_tool(ctx).unwrap_or(false) {
        return Ok(0);
    }

    let file_ptr = unsafe { ctx.arg::<*const c_void>(0) };
    
    if file_ptr.is_null() {
        return Ok(0);
    }

    let write_flags = 0x1 | 0x2 | 0x40 | 0x200;
    
    let flags_ptr = unsafe { (file_ptr as *const u8).offset(24) as *const u32 };
    let flags: u32 = unsafe {
        bpf_probe_read_kernel(flags_ptr).unwrap_or(0)
    };
    
    if (flags & write_flags) == 0 {
        return Ok(0);
    }

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    
    if let Some(decision) = unsafe { PATH_DECISIONS.get(&pid) } {
        let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        let age_ns = now - decision.timestamp;
        
        if age_ns < 10_000_000 {
            let _ = PATH_DECISIONS.remove(&pid);
            
            if decision.allowed == 0 {
                warn!(ctx, "FS-001: 🚫 ENFORCING: Blocked unauthorized file open (write)");
                return Err(-13);
            } else {
                info!(ctx, "FS-001: ✅ ENFORCING: Allowed file open (write)");
                return Ok(0);
            }
        } else {
            let _ = PATH_DECISIONS.remove(&pid);
        }
    }
    
    Ok(0)
}
