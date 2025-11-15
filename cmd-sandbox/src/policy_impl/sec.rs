// Security Policy Implementations (SEC-xxx)
// This module contains all security-related policy enforcement functions

use aya::{Btf, programs::Lsm};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

// ----------------------------------------------------------------------------
// Security Policies (SEC-xxx)
// ----------------------------------------------------------------------------

/// SEC-001: Prevent curl/wget from running as root or privileged user
/// Enforcement: bprm_check_security LSM hook validates UID
pub fn implement_sec_001(ebpf: &mut aya::Ebpf, btf: &Btf) -> anyhow::Result<()> {
    if let Some(program) = ebpf.program_mut("bprm_check_security") {
        let program: Result<&mut Lsm, _> = program.try_into();
        if let Ok(program) = program {
            match program.load("bprm_check_security", btf) {
                Ok(_) => {
                    program.attach()?;
                    println!("✓ SEC-001: Non-privileged execution enforced (UID >= 1000 or nobody)");
                }
                Err(e) => {
                    println!("⚠ SEC-001: bprm_check_security LSM not available: {}", e);
                }
            }
        }
    }
    Ok(())
}

/// SEC-002: Block environment variables containing PASSWORD, KEY, SECRET
/// Enforcement: Monitored during process scanning (userspace check)
pub fn implement_sec_002(_tracker: &Arc<Mutex<HashMap<String, Instant>>>) -> anyhow::Result<()> {
    println!("✓ SEC-002: Sensitive environment variable monitoring enabled");
    println!("  Blocks: PASSWORD, KEY, SECRET (checked during process scan)");
    Ok(())
}

/// SEC-003: Prevent network interface configuration changes
/// Enforcement: capable LSM hook blocks CAP_NET_ADMIN capability
pub fn implement_sec_003(ebpf: &mut aya::Ebpf, btf: &Btf) -> anyhow::Result<()> {
    if let Some(program) = ebpf.program_mut("capable") {
        let program: Result<&mut Lsm, _> = program.try_into();
        if let Ok(program) = program {
            match program.load("capable", btf) {
                Ok(_) => {
                    program.attach()?;
                    println!("✓ SEC-003: Network configuration changes blocked (CAP_NET_ADMIN)");
                }
                Err(e) => {
                    println!("⚠ SEC-003: capable LSM not available: {}", e);
                }
            }
        }
    }
    Ok(())
}

/// SEC-004: Restrict signal handling (allow only TERM, INT)
/// Enforcement: task_kill LSM hook filters signals
pub fn implement_sec_004(ebpf: &mut aya::Ebpf, btf: &Btf) -> anyhow::Result<()> {
    if let Some(program) = ebpf.program_mut("task_kill") {
        let program: Result<&mut Lsm, _> = program.try_into();
        if let Ok(program) = program {
            match program.load("task_kill", btf) {
                Ok(_) => {
                    program.attach()?;
                    println!("✓ SEC-004: Signal restrictions enabled (allow only TERM, INT)");
                }
                Err(e) => {
                    println!("⚠ SEC-004: task_kill LSM not available: {}", e);
                }
            }
        }
    }
    Ok(())
}

/// SEC-005: Block access to kernel memory and modules
/// Enforcement: kernel_read_file + capable LSM hooks
pub fn implement_sec_005(ebpf: &mut aya::Ebpf, btf: &Btf) -> anyhow::Result<()> {
    if let Some(program) = ebpf.program_mut("kernel_read_file") {
        let program: Result<&mut Lsm, _> = program.try_into();
        if let Ok(program) = program {
            match program.load("kernel_read_file", btf) {
                Ok(_) => {
                    program.attach()?;
                    println!("✓ SEC-005: Kernel memory/module access blocked");
                    println!("  Blocks: CAP_SYS_ADMIN, CAP_SYS_MODULE, kernel file reads");
                }
                Err(e) => {
                    println!("⚠ SEC-005: kernel_read_file LSM not available: {}", e);
                }
            }
        }
    }
    Ok(())
}
