use anyhow::{Context, Result};
use colored::*;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

// Test modules organized by policy category
mod net_tests;
mod mem_tests;
mod fs_tests;
mod sec_tests;

#[derive(Debug)]
pub struct TestResult {
    pub name: String,
    pub passed: bool,
    pub message: String,
    pub duration: Duration,
}

pub struct TestSuite {
    pub results: Vec<TestResult>,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
}

impl TestSuite {
    fn new() -> Self {
        Self {
            results: Vec::new(),
            total: 0,
            passed: 0,
            failed: 0,
            skipped: 0,
        }
    }

    fn record(&mut self, result: TestResult) {
        self.total += 1;
        if result.passed {
            self.passed += 1;
            println!(
                "{}",
                format!("Result: ✅ PASS - {}", result.message).green()
            );
        } else {
            self.failed += 1;
            println!("{}", format!("Result: ❌ FAIL - {}", result.message).red());
        }
        self.results.push(result);
    }

    fn print_summary(&self) {
        println!("\n{}", "═".repeat(70));
        println!("{}", "📋 FINAL TEST SUMMARY".bold().cyan());
        println!("{}", "═".repeat(70));
        println!();
        println!("  Total Tests:   {}", self.total);
        println!("  {}", format!("✅ Passed:      {}", self.passed).green().bold());
        println!("  {}", format!("❌ Failed:      {}", self.failed).red().bold());
        println!("  {}", format!("⊘  Skipped:     {}", self.skipped).yellow());
        println!();

        let pass_rate = if self.total - self.skipped > 0 {
            (self.passed as f64 / (self.total - self.skipped) as f64) * 100.0
        } else {
            0.0
        };

        println!("  Pass Rate: {:.1}%", pass_rate);
        println!();

        if self.failed == 0 && self.passed > 0 {
            println!(
                "  {}",
                "🎉 ALL TESTS PASSED! Sandbox is working correctly.".green().bold()
            );
        } else if self.failed > 0 {
            println!(
                "  {}",
                "⚠️  SOME TESTS FAILED. Review output above for details.".red().bold()
            );
        }
        println!();
        println!("{}", "═".repeat(70));
    }
}

fn check_sandbox_running() -> Result<bool> {
    let output = Command::new("pgrep")
        .args(["-f", "cmd-sandbox"])
        .output()
        .context("Failed to check if sandbox is running")?;
    
    Ok(output.status.success())
}

fn check_cgroup_exists() -> Result<bool> {
    Ok(Path::new("/sys/fs/cgroup/cmd_sandbox").exists())
}

fn get_cgroup_value(file: &str) -> Result<String> {
    let path = format!("/sys/fs/cgroup/cmd_sandbox/{}", file);
    fs::read_to_string(&path)
        .context(format!("Failed to read cgroup file: {}", path))
        .map(|s| s.trim().to_string())
}

fn should_run_test(test_filter: &Option<String>, category: &str) -> bool {
    match test_filter {
        None => true,  // Run all tests if no filter specified
        Some(filter) => filter == category || filter == "all",
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments
    let args: Vec<String> = std::env::args().collect();
    let test_filter = if args.len() > 1 {
        Some(args[1].to_lowercase())
    } else {
        None
    };

    println!("{}", "╔════════════════════════════════════════════════════════════════╗".cyan().bold());
    println!("{}", "║     curl_sandbox-rs - Comprehensive Security Test Suite       ║".cyan().bold());
    println!("{}", "║                        Version 1.0                             ║".cyan().bold());
    println!("{}", "╚════════════════════════════════════════════════════════════════╝".cyan().bold());
    println!();

    if let Some(ref filter) = test_filter {
        println!("{}", format!("🎯 Running only: {} tests", filter.to_uppercase()).yellow().bold());
        println!();
    }

    // ========================================================================
    // PREREQUISITE CHECKS
    // ========================================================================
    println!("{}", "🔍 Checking Prerequisites...".bold().yellow());
    println!();

    if !check_sandbox_running()? {
        eprintln!("{}", "  ❌ ERROR: cmd-sandbox is not running!".red().bold());
        eprintln!("     Start it first: sudo -E RUST_LOG=info ./target/release/cmd-sandbox");
        std::process::exit(1);
    }
    println!("{}", "  ✓ Sandbox process is running".green());

    if !check_cgroup_exists()? {
        eprintln!("{}", "  ❌ ERROR: cgroup not found at /sys/fs/cgroup/cmd_sandbox".red().bold());
        std::process::exit(1);
    }
    println!("{}", "  ✓ Cgroup exists".green());
    println!();

    // Display current limits
    println!("{}", "━".repeat(70));
    println!("{}", "📊 Current Resource Limits".bold());
    println!("{}", "━".repeat(70));
    if let Ok(mem) = get_cgroup_value("memory.max") {
        println!("  Memory limit: {}", mem);
    }
    if let Ok(cpu) = get_cgroup_value("cpu.max") {
        println!("  CPU limit: {}", cpu);
    }
    println!();

    let mut suite = TestSuite::new();

    // ========================================================================
    // NETWORK POLICIES (NET-001 to NET-006)
    // ========================================================================
    if should_run_test(&test_filter, "net") {
        println!("{}", "═".repeat(70));
        println!("{}", "🌐 NETWORK POLICIES".bold().cyan());
        println!("{}", "═".repeat(70));
        println!();

        // NET-001: Domain Whitelist
        println!("{}", "▶ NET-001: Domain Whitelist".bold());
        net_tests::test_net001_whitelisted_domain(&mut suite).await;
        net_tests::test_net001_non_whitelisted_domain(&mut suite).await;

        // NET-002: Protocol Blocking  
        println!("{}", "▶ NET-002: Block Non-HTTP Protocols".bold());
        net_tests::test_net002_ftp_blocked(&mut suite).await;
        net_tests::test_net002_sftp_blocked(&mut suite).await;
        net_tests::test_net002_telnet_blocked(&mut suite).await;

        // NET-005: Private IP Blocking
        println!("{}", "▶ NET-005: Block Private IP Ranges".bold());
        net_tests::test_net005_block_192_168(&mut suite).await;
        net_tests::test_net005_block_10_0(&mut suite).await;
        net_tests::test_net005_block_172_16(&mut suite).await;
        net_tests::test_net005_block_loopback(&mut suite).await;

        // NET-006: HTTPS-Only Policy
        println!("{}", "▶ NET-006: HTTPS-Only Enforcement".bold());
        net_tests::test_net006_https_allowed(&mut suite).await;
        net_tests::test_net006_http_blocked(&mut suite).await;
    }

    // ========================================================================
    // MEMORY & PROCESS POLICIES (MEM-001 to MEM-006)
    // ========================================================================
    if should_run_test(&test_filter, "mem") {
        println!("{}", "═".repeat(70));
        println!("{}", "💾 MEMORY & PROCESS POLICIES".bold().cyan());
        println!("{}", "═".repeat(70));
        println!();

        // MEM-001: Memory Limit
        println!("{}", "▶ MEM-001: Memory Limit (10MB)".bold());
        mem_tests::test_mem001_memory_limit(&mut suite).await;
        
        // MEM-001 + FS-003: File Size Limit (10MB)
        println!("{}", "▶ MEM-001/FS-003: File Size Limit (10MB download)".bold());
        mem_tests::test_mem001_file_size_limit(&mut suite).await;

        // MEM-003: Wall Clock Timeout
        println!("{}", "▶ MEM-003: Wall Clock Timeout (10s)".bold());
        mem_tests::test_mem003_wall_clock_timeout(&mut suite).await;
        mem_tests::test_mem003_quick_operation(&mut suite).await;

        // MEM-004: CPU Throttling
        println!("{}", "▶ MEM-004: CPU Throttling (50%)".bold());
        mem_tests::test_mem004_cpu_throttling(&mut suite).await;

        // MEM-005: Block Executable Memory Mapping
        println!("{}", "▶ MEM-005: Block Executable Memory Mapping".bold());
        mem_tests::test_mem005_block_exec_mmap(&mut suite).await;

        // MEM-006: Stack Size Limit
        println!("{}", "▶ MEM-006: Stack Size Limit (8MB)".bold());
        mem_tests::test_mem006_stack_size_limit(&mut suite).await;
    }

    // ========================================================================
    // SECURITY POLICIES (SEC-001 to SEC-006)
    // ========================================================================
    if should_run_test(&test_filter, "sec") {
        println!("{}", "═".repeat(70));
        println!("{}", "🔒 SECURITY POLICIES".bold().cyan());
        println!("{}", "═".repeat(70));
        println!();

        // SEC-001: Run as non-privileged user
        println!("{}", "▶ SEC-001: Run as Non-Privileged User (nobody)".bold());
        sec_tests::test_sec001_run_as_nobody(&mut suite).await;

        // SEC-002: Environment Variable Controls (PASSWORD/KEY/SECRET)
        println!("{}", "▶ SEC-002: Block Sensitive Environment Variables (PASSWORD/KEY/SECRET)".bold());
        sec_tests::test_sec002_block_password_env(&mut suite).await;
        sec_tests::test_sec002_block_key_env(&mut suite).await;
        sec_tests::test_sec002_block_secret_env(&mut suite).await;


        // SEC-003: Prevent network interface configuration changes
        println!("{}", "▶ SEC-003: Prevent Network Interface Configuration".bold());
        sec_tests::test_sec003_block_net_admin(&mut suite).await;

        // SEC-004: Restrict signal handling (TERM, INT only)
        println!("{}", "▶ SEC-004: Restrict Signal Handling (TERM/INT only)".bold());
        sec_tests::test_sec004_allow_sigterm(&mut suite).await;
        sec_tests::test_sec004_allow_sigint(&mut suite).await;
        sec_tests::test_sec004_block_other_signals(&mut suite).await;

        // SEC-005: Block kernel memory and module access
        println!("{}", "▶ SEC-005: Block Kernel Memory/Module Access".bold());
        sec_tests::test_sec005_block_kernel_access(&mut suite).await;
        sec_tests::test_sec005_block_module_loading(&mut suite).await;


        // Additional Security Tests (LD_PRELOAD/LD_LIBRARY_PATH)
        println!("{}", "▶ SEC-EXTRA: Block Dangerous Loader Variables".bold());
        sec_tests::test_sec_block_ld_preload(&mut suite).await;
        sec_tests::test_sec_block_ld_library_path(&mut suite).await;
    }

    // ========================================================================
    // FILESYSTEM POLICIES (FS-001 to FS-006)
    // ========================================================================
    if should_run_test(&test_filter, "fs") {
        println!("{}", "═".repeat(70));
        println!("{}", "📁 FILESYSTEM POLICIES".bold().cyan());
        println!("{}", "═".repeat(70));
        println!();
        
        println!("{}", "▶ FS-001: Write Directory Restrictions (RESTRICT)".bold());
        fs_tests::test_fs001_write_to_allowed_dir(&mut suite);
        fs_tests::test_fs001_write_to_tmp_root(&mut suite);
        fs_tests::test_fs001_write_to_home(&mut suite);
        
        println!("{}", "▶ FS-003: Maximum File Download Size (QUOTA)".bold());
        fs_tests::test_fs003_max_file_size(&mut suite);
        
        println!("{}", "▶ FS-004: Prevent Execution of Downloaded Files (BLOCK)".bold());
        fs_tests::test_fs004_prevent_execution(&mut suite);
        
        println!("{}", "▶ FS-005: Total Storage Quota (QUOTA)".bold());
        fs_tests::test_fs005_total_storage_quota(&mut suite);
        
        println!("{}", "▶ FS-006: Block System Directory Access (BLOCK)".bold());
        fs_tests::test_fs006_block_etc_write(&mut suite);
        fs_tests::test_fs006_read_etc_allowed(&mut suite);
        fs_tests::test_fs006_block_bin_write(&mut suite);
        fs_tests::test_fs006_block_usr_write(&mut suite);
        println!();
    }

    // Print summary
    suite.print_summary();

    // Exit with appropriate code
    if suite.failed > 0 {
        std::process::exit(1);
    }

    Ok(())
}
