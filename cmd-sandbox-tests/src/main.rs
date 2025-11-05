use anyhow::{Context, Result};
use colored::*;
use std::fs;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};
use tokio::time::timeout;

// Test modules organized by policy category
mod net_tests;
mod mem_tests;

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
}

impl TestSuite {
    fn new() -> Self {
        Self {
            results: Vec::new(),
            total: 0,
            passed: 0,
            failed: 0,
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
        println!("\n{}", "━".repeat(70));
        println!("{}", "📋 Final Summary".bold());
        println!("{}", "━".repeat(70));
        println!();
        println!("Total Tests: {}", self.total);
        println!("{}", format!("✅ Passed: {}", self.passed).green());
        println!("{}", format!("❌ Failed: {}", self.failed).red());
        println!();

        if self.failed == 0 {
            println!(
                "{}",
                "🎉 All tests PASSED! Sandbox is working correctly.".green().bold()
            );
        } else {
            println!(
                "{}",
                "⚠️  Some tests FAILED. Check output above for details.".yellow().bold()
            );
        }
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

async fn run_curl_command(args: &[&str], timeout_secs: u64) -> Result<(ExitStatus, Duration)> {
    let start = Instant::now();
    
    let result = timeout(
        Duration::from_secs(timeout_secs),
        tokio::process::Command::new("curl")
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
    )
    .await;

    let duration = start.elapsed();

    match result {
        Ok(Ok(status)) => Ok((status, duration)),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => {
            // Timeout - try to get exit status anyway
            Ok((ExitStatus::default(), duration))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("{}", "╔════════════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║       curl_sandbox-rs Comprehensive Test Suite (Rust)         ║".cyan());
    println!("{}", "╚════════════════════════════════════════════════════════════════╝".cyan());
    println!();

    // Check prerequisites
    if !check_sandbox_running()? {
        eprintln!("{}", "❌ ERROR: cmd-sandbox is not running!".red());
        eprintln!("   Start it first: sudo -E RUST_LOG=info ./target/release/cmd-sandbox");
        std::process::exit(1);
    }
    println!("{}", "✓ Sandbox is running".green());

    if !check_cgroup_exists()? {
        eprintln!("{}", "❌ ERROR: cgroup not found at /sys/fs/cgroup/cmd_sandbox".red());
        std::process::exit(1);
    }
    println!("{}", "✓ Cgroup exists".green());
    println!();

    // Display current limits
    println!("{}", "━".repeat(70));
    println!("{}", "📊 Current Resource Limits".bold());
    println!("{}", "━".repeat(70));
    if let Ok(mem) = get_cgroup_value("memory.max") {
        println!("Memory limit: {}", mem);
    }
    if let Ok(cpu) = get_cgroup_value("cpu.max") {
        println!("CPU limit: {}", cpu);
    }
    println!();

    let mut suite = TestSuite::new();

    // ========================================================================
    // NETWORK POLICIES (NET-001 to NET-006)
    // ========================================================================
    println!("{}", "━".repeat(70));
    println!("{}", "🌐 NETWORK POLICIES".bold().cyan());
    println!("{}", "━".repeat(70));
    println!();

    // NET-006: HTTPS-Only Policy
    println!("{}", "▶ NET-006: HTTPS-Only Policy".bold());
    net_tests::test_net006_https_allowed(&mut suite).await;
    net_tests::test_net006_http_blocked(&mut suite).await;

    // NET-002: Protocol Blocking
    println!("{}", "▶ NET-002: Protocol Blocking".bold());
    net_tests::test_net002_ftp_blocked(&mut suite).await;
    net_tests::test_net002_sftp_blocked(&mut suite).await;
    net_tests::test_net002_telnet_blocked(&mut suite).await;

    // NET-005: Private IP Blocking
    println!("{}", "▶ NET-005: Private IP Blocking".bold());
    net_tests::test_net005_block_192_168(&mut suite).await;
    net_tests::test_net005_block_10_0(&mut suite).await;
    net_tests::test_net005_block_172_16(&mut suite).await;
    net_tests::test_net005_block_loopback(&mut suite).await;

    // NET-001: Domain Whitelist
    println!("{}", "▶ NET-001: Domain Whitelist".bold());
    net_tests::test_net001_whitelisted_domain(&mut suite).await;
    net_tests::test_net001_non_whitelisted_domain(&mut suite).await;

    // ========================================================================
    // MEMORY & PROCESS POLICIES (MEM-001 to MEM-004)
    // ========================================================================
    println!("{}", "━".repeat(70));
    println!("{}", "💾 MEMORY & PROCESS POLICIES".bold().cyan());
    println!("{}", "━".repeat(70));
    println!();

    // MEM-001: Memory Limit
    println!("{}", "▶ MEM-001: Memory Limit".bold());
    mem_tests::test_mem001_memory_limit(&mut suite).await;

    // MEM-003: Wall Clock Timeout
    println!("{}", "▶ MEM-003: Wall Clock Timeout".bold());
    mem_tests::test_mem003_wall_clock_timeout(&mut suite).await;
    mem_tests::test_mem003_quick_operation(&mut suite).await;

    // MEM-004: CPU Throttling
    println!("{}", "▶ MEM-004: CPU Throttling".bold());
    mem_tests::test_mem004_cpu_throttling(&mut suite).await;

    // ========================================================================
    // FILESYSTEM POLICIES (FS-001 to FS-006) - TODO: Not yet implemented
    // ========================================================================
    println!("{}", "━".repeat(70));
    println!("{}", "📁 FILESYSTEM POLICIES (Not Implemented)".bold().yellow());
    println!("{}", "━".repeat(70));
    println!("   FS-001: Write to /tmp only - TODO");
    println!("   FS-002: Read-only filesystem outside /tmp - TODO");
    println!("   FS-003: File size limits - TODO");
    println!("   FS-004: Inode limits - TODO");
    println!("   FS-005: Path traversal protection - TODO");
    println!("   FS-006: Symlink restrictions - TODO");
    println!();

    // ========================================================================
    // SECURITY POLICIES (SEC-001 to SEC-006) - TODO: Not yet implemented
    // ========================================================================
    println!("{}", "━".repeat(70));
    println!("{}", "🔒 SECURITY POLICIES (Not Implemented)".bold().yellow());
    println!("{}", "━".repeat(70));
    println!("   SEC-001: No privilege escalation - TODO");
    println!("   SEC-002: No ptrace - TODO");
    println!("   SEC-003: No kernel module loading - TODO");
    println!("   SEC-004: Seccomp filter - TODO");
    println!("   SEC-005: Capability dropping - TODO");
    println!("   SEC-006: Namespace isolation - TODO");
    println!();

    // Print summary
    suite.print_summary();

    // Exit with appropriate code
    if suite.failed > 0 {
        std::process::exit(1);
    }

    Ok(())
}
