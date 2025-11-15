// Memory Policy Implementations (MEM-xxx)
// This module contains all memory-related policy enforcement functions

use aya::{Btf, programs::Lsm};
use crate::policy::PolicyConfig;
use crate::cgroup::setup_cgroup;
use log::info;
use std::time::Duration;

// ----------------------------------------------------------------------------
// Memory Policies (MEM-xxx)
// ----------------------------------------------------------------------------

/// MEM-001: Maximum memory usage: 100MB
/// Enforcement: cgroup memory.max limit
pub fn implement_mem_001(config: &PolicyConfig) -> anyhow::Result<()> {
    setup_cgroup(config)?;
    println!("✓ MEM-001: Memory limit enforced ({:.2}MB via cgroup)", 
             config.memory_policies.max_memory as f64 / (1024.0 * 1024.0));
    Ok(())
}

/// MEM-003: Maximum process execution time: 2 minutes (configurable)
/// Enforcement: Userspace wall-clock timeout monitoring
pub fn implement_mem_003(wall_clock_limit: &Duration) -> anyhow::Result<()> {
    println!("✓ MEM-003: Execution time limit enabled (max: {}s wall-clock)", 
             wall_clock_limit.as_secs());
    println!("  Enforced via process monitoring");
    Ok(())
}

/// MEM-004: Restrict CPU usage to 50% of single core
/// Enforcement: cgroup cpu.max limit
pub fn implement_mem_004(_config: &PolicyConfig) -> anyhow::Result<()> {
    // CPU limit is set in setup_cgroup() called by MEM-001
    println!("✓ MEM-004: CPU throttling enabled (set via cgroup in MEM-001)");
    Ok(())
}

/// MEM-005: Block memory mapping of executable pages
/// Enforcement: file_mmap LSM hook checks PROT_EXEC flag
pub fn implement_mem_005(ebpf: &mut aya::Ebpf, btf: &Btf) -> anyhow::Result<()> {
    if let Some(program) = ebpf.program_mut("file_mmap") {
        let program: Result<&mut Lsm, _> = program.try_into();
        if let Ok(program) = program {
            match program.load("file_mmap", btf) {
                Ok(_) => {
                    program.attach()?;
                    println!("✓ MEM-005: Executable memory mappings blocked (PROT_EXEC)");
                }
                Err(_) => {
                    println!("⚠ MEM-005: file_mmap LSM not available");
                }
            }
        }
    }
    Ok(())
}

/// MEM-006: Limit stack size to 8MB
/// Enforcement: setrlimit(RLIMIT_STACK)
pub fn implement_mem_006() -> anyhow::Result<()> {
    set_stack_limit(8 * 1024 * 1024)?;
    Ok(())
}

// ----------------------------------------------------------------------------
// Helper Functions
// ----------------------------------------------------------------------------

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
            log::warn!("Failed to set stack limit: {}", err);
            Err(err.into())
        }
    }
}
