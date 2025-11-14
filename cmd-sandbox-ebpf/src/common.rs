use aya_ebpf::{
    helpers::bpf_get_current_comm,
    programs::{LsmContext, TracePointContext},
};
use aya_log_ebpf::warn;

pub const CURL_COMM: &[u8; 4] = b"curl";
pub const WGET_COMM: &[u8; 4] = b"wget";
pub const AF_UNIX: u16 = 1;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;
pub const UID_NOBODY: u32 = 65534;
pub const UID_MIN_UNPRIVILEGED: u32 = 1000;

#[repr(C)]
pub struct SockaddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: u32,
    pub sin_zero: [u8; 8],
}

#[repr(C)]
pub struct SockaddrIn6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: [u8; 16],
    pub sin6_scope_id: u32,
}

pub fn is_download_tool(ctx: &LsmContext) -> Result<bool, i32> {
    let comm = match bpf_get_current_comm() {
        Ok(comm) => comm,
        Err(ret) => {
            warn!(ctx, "bpf_get_current_comm failed: {}", ret);
            return Ok(false);
        }
    };

    if &comm[..CURL_COMM.len()] == CURL_COMM && comm[CURL_COMM.len()] == 0 {
        return Ok(true);
    }
    
    if &comm[..WGET_COMM.len()] == WGET_COMM && comm[WGET_COMM.len()] == 0 {
        return Ok(true);
    }

    Ok(false)
}

pub fn is_download_tool_tp(_ctx: &TracePointContext) -> Result<bool, i32> {
    let comm = bpf_get_current_comm().map_err(|_| 0)?;
    
    Ok(&comm[..4] == CURL_COMM || &comm[..4] == WGET_COMM)
}
