// eBPF Program Loading and Hook Attachment
// This module handles loading the eBPF object file and attaching LSM hooks

use aya::{Btf, Ebpf, programs::{Lsm, TracePoint}};
use log::warn;

/// Load the eBPF object file and initialize logging
pub fn load_ebpf() -> anyhow::Result<(Ebpf, Btf)> {
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/cmd-sandbox"
    )))?;
    
    // Initialize eBPF logger
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    
    let btf = Btf::from_sys_fs()?;
    Ok((ebpf, btf))
}

/// Attach all LSM hooks and tracepoints for policy enforcement
pub fn attach_all_hooks(ebpf: &mut Ebpf, btf: &Btf) -> anyhow::Result<()> {
    attach_socket_connect(ebpf, btf)?;
    attach_file_mmap(ebpf, btf)?;
    attach_task_kill(ebpf, btf)?;
    attach_capable(ebpf, btf)?;
    attach_kernel_read_file(ebpf, btf)?;
    attach_bprm_check_security(ebpf, btf)?;
    attach_inode_create(ebpf, btf)?;
    attach_file_open(ebpf, btf)?;
    attach_path_truncate(ebpf, btf)?;
    attach_sys_enter_openat(ebpf)?;
    
    println!("✓ All LSM hooks and tracepoints attached with policy from config");
    Ok(())
}

fn attach_socket_connect(ebpf: &mut Ebpf, btf: &Btf) -> anyhow::Result<()> {
    let program: &mut Lsm = ebpf.program_mut("socket_connect").unwrap().try_into()?;
    program.load("socket_connect", btf)?;
    program.attach()?;
    println!("✓ socket_connect LSM attached (Network policy enforcement + SEC-001)");
    Ok(())
}

fn attach_file_mmap(ebpf: &mut Ebpf, btf: &Btf) -> anyhow::Result<()> {
    if let Some(program) = ebpf.program_mut("file_mmap") {
        let program: Result<&mut Lsm, _> = program.try_into();
        if let Ok(program) = program {
            match program.load("file_mmap", btf) {
                Ok(_) => {
                    program.attach()?;
                    println!("✓ file_mmap LSM attached (MEM-005: block executable mappings)");
                }
                Err(_) => {
                    println!("⚠ file_mmap LSM not available on this kernel (MEM-005 not enforced)");
                }
            }
        }
    } else {
        println!("⚠ file_mmap LSM not found (MEM-005 not enforced)");
    }
    Ok(())
}

fn attach_task_kill(ebpf: &mut Ebpf, btf: &Btf) -> anyhow::Result<()> {
    if let Some(program) = ebpf.program_mut("task_kill") {
        let program: Result<&mut Lsm, _> = program.try_into();
        if let Ok(program) = program {
            match program.load("task_kill", btf) {
                Ok(_) => {
                    program.attach()?;
                    println!("✓ task_kill LSM attached (SEC-004: restrict signals to TERM/INT)");
                }
                Err(e) => {
                    println!("⚠ task_kill LSM not available on this kernel (SEC-004 not enforced): {}", e);
                }
            }
        }
    } else {
        println!("⚠ task_kill LSM not found (SEC-004 not enforced)");
    }
    Ok(())
}

fn attach_capable(ebpf: &mut Ebpf, btf: &Btf) -> anyhow::Result<()> {
    if let Some(program) = ebpf.program_mut("capable") {
        let program: Result<&mut Lsm, _> = program.try_into();
        if let Ok(program) = program {
            match program.load("capable", btf) {
                Ok(_) => {
                    program.attach()?;
                    println!("✓ capable LSM attached (SEC-003: block net config, SEC-005: block kernel access)");
                }
                Err(e) => {
                    println!("⚠ capable LSM not available on this kernel (SEC-003/SEC-005 not enforced): {}", e);
                }
            }
        }
    } else {
        println!("⚠ capable LSM not found (SEC-003/SEC-005 not enforced)");
    }
    Ok(())
}

fn attach_kernel_read_file(ebpf: &mut Ebpf, btf: &Btf) -> anyhow::Result<()> {
    if let Some(program) = ebpf.program_mut("kernel_read_file") {
        let program: Result<&mut Lsm, _> = program.try_into();
        if let Ok(program) = program {
            match program.load("kernel_read_file", btf) {
                Ok(_) => {
                    program.attach()?;
                    println!("✓ kernel_read_file LSM attached (SEC-005: block kernel file reads)");
                }
                Err(e) => {
                    println!("⚠ kernel_read_file LSM not available on this kernel (SEC-005 not fully enforced): {}", e);
                }
            }
        }
    } else {
        println!("⚠ kernel_read_file LSM not found (SEC-005 not fully enforced)");
    }
    Ok(())
}

fn attach_bprm_check_security(ebpf: &mut Ebpf, btf: &Btf) -> anyhow::Result<()> {
    if let Some(program) = ebpf.program_mut("bprm_check_security") {
        let program: Result<&mut Lsm, _> = program.try_into();
        if let Ok(program) = program {
            match program.load("bprm_check_security", btf) {
                Ok(_) => {
                    program.attach()?;
                    println!("✓ bprm_check_security LSM attached (SEC-001 + FS-004: non-privileged exec + prevent downloaded file execution)");
                }
                Err(e) => {
                    println!("⚠ bprm_check_security LSM not available on this kernel (SEC-001/FS-004 not enforced): {}", e);
                }
            }
        }
    } else {
        println!("⚠ bprm_check_security LSM not found (SEC-001/FS-004 not enforced)");
    }
    Ok(())
}

fn attach_inode_create(ebpf: &mut Ebpf, btf: &Btf) -> anyhow::Result<()> {
    if let Some(program) = ebpf.program_mut("inode_create") {
        let program: Result<&mut Lsm, _> = program.try_into();
        if let Ok(program) = program {
            match program.load("inode_create", btf) {
                Ok(_) => {
                    program.attach()?;
                    println!("✓ inode_create LSM attached (FS-001: restrict file creation)");
                }
                Err(e) => {
                    println!("⚠ inode_create LSM not available on this kernel (FS-001 not enforced): {}", e);
                }
            }
        }
    } else {
        println!("⚠ inode_create LSM not found (FS-001 not enforced)");
    }
    Ok(())
}

fn attach_file_open(ebpf: &mut Ebpf, btf: &Btf) -> anyhow::Result<()> {
    if let Some(program) = ebpf.program_mut("file_open") {
        let program: Result<&mut Lsm, _> = program.try_into();
        if let Ok(program) = program {
            match program.load("file_open", btf) {
                Ok(_) => {
                    program.attach()?;
                    println!("✓ file_open LSM attached (FS-001: monitor file opens)");
                }
                Err(e) => {
                    println!("⚠ file_open LSM not available on this kernel: {}", e);
                }
            }
        }
    }
    Ok(())
}

fn attach_path_truncate(ebpf: &mut Ebpf, btf: &Btf) -> anyhow::Result<()> {
    if let Some(program) = ebpf.program_mut("path_truncate") {
        let program: Result<&mut Lsm, _> = program.try_into();
        if let Ok(program) = program {
            match program.load("path_truncate", btf) {
                Ok(_) => {
                    program.attach()?;
                    println!("✓ path_truncate LSM attached (FS-001: monitor file truncation)");
                }
                Err(e) => {
                    println!("⚠ path_truncate LSM not available on this kernel: {}", e);
                }
            }
        }
    }
    Ok(())
}

fn attach_sys_enter_openat(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let program: &mut TracePoint = ebpf.program_mut("sys_enter_openat").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_openat")?;
    println!("✓ sys_enter_openat tracepoint attached (FS-001: path-based write restrictions)");
    println!("  Note: Tracepoint provides path checking, LSM hooks provide enforcement");
    Ok(())
}
