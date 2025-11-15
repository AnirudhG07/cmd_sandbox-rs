// Resource Limits Module
// This module handles setting system resource limits (rlimits)

use log::{info, warn, debug};

/// Set memlock rlimit to allow eBPF programs to use locked memory
pub fn set_memlock_rlimit() -> anyhow::Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }
    Ok(())
}

/// MEM-006: Set stack size limit to 8MB
pub fn set_stack_limit(limit_bytes: u64) -> anyhow::Result<()> {
    let stack_limit = libc::rlimit {
        rlim_cur: limit_bytes,
        rlim_max: limit_bytes,
    };
    
    unsafe {
        if libc::setrlimit(libc::RLIMIT_STACK, &stack_limit) == 0 {
            info!("✓ Set stack size limit to {}MB", limit_bytes / (1024 * 1024));
            println!("✓ Stack size limit set: {}MB", limit_bytes / (1024 * 1024));
            Ok(())
        } else {
            let err = std::io::Error::last_os_error();
            warn!("Failed to set stack limit: {}", err);
            Err(err.into())
        }
    }
}
