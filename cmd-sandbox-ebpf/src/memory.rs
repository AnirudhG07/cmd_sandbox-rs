use aya_ebpf::{
    helpers::bpf_get_current_comm,
    macros::lsm,
    programs::LsmContext,
};
use aya_log_ebpf::warn;

use crate::common::{CURL_COMM, WGET_COMM};

#[lsm(hook = "file_mmap")]
pub fn file_mmap(ctx: LsmContext) -> i32 {
    match try_file_mmap(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_file_mmap(ctx: &LsmContext) -> Result<i32, i32> {
    let comm = bpf_get_current_comm().map_err(|_| 0)?;
    
    if &comm[..4] != CURL_COMM && &comm[..4] != WGET_COMM {
        return Ok(0);
    }
    
    let prot = unsafe { ctx.arg::<u64>(2) };
    
    const PROT_EXEC: u64 = 0x4;
    
    if prot & PROT_EXEC != 0 {
        warn!(ctx, "MEM-005: 🚫 BLOCKED executable mmap for curl/wget");
        return Err(-13);
    }
    
    Ok(0)
}
