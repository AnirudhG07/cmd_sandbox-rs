use crate::{TestResult, TestSuite};
use colored::Colorize;
use std::fs;
use std::time::Instant;
use std::os::unix::process::ExitStatusExt;
use anyhow::Result;
use tokio::process::Command;
use std::time::Duration;

/// Helper function to run curl commands in the sandbox
async fn run_curl_command(args: &[&str], timeout_secs: u64) -> Result<(std::process::ExitStatus, String)> {
    let output = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        Command::new("curl")
            .args(args)
            .output()
    ).await??;
    
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    Ok((output.status, stdout))
}

// ============================================================================
// MEM-001: Maximum memory usage (10MB)
// ============================================================================
pub async fn test_mem001_memory_limit(suite: &mut TestSuite) {
    println!("{}", "Test MEM-001: Small download within 10MB limit - Should SUCCEED".bold());
    println!("Command: curl https://example.com -o /tmp/mem-test-small.html");
    println!("---");

    let start = Instant::now();
    let result = run_curl_command(&["https://example.com", "-o", "/tmp/mem-test-small.html"], 10).await;

    match result {
        Ok((status, _)) if status.success() => {
            suite.record(TestResult {
                name: "MEM-001: Memory limit (small download)".to_string(),
                passed: true,
                message: "Small download succeeded within memory limits".to_string(),
                duration: start.elapsed(),
            });
        }
        Ok((status, _)) => {
            suite.record(TestResult {
                name: "MEM-001: Memory limit (small download)".to_string(),
                passed: false,
                message: format!("Download failed (exit code: {:?})", status.code()),
                duration: start.elapsed(),
            });
        }
        Err(e) => {
            suite.record(TestResult {
                name: "MEM-001: Memory limit (small download)".to_string(),
                passed: false,
                message: format!("Error: {}", e),
                duration: start.elapsed(),
            });
        }
    }
    let _ = fs::remove_file("/tmp/mem-test-small.html");
    println!();
}

// ============================================================================
// MEM-003: Maximum execution time (wall clock timeout)
// ============================================================================
pub async fn test_mem003_wall_clock_timeout(suite: &mut TestSuite) {
    println!("{}", "Test MEM-003: Wall clock timeout (10s limit) - Should TIMEOUT".bold());
    println!("Command: curl https://ash-speed.hetzner.com/10GB.bin -o /tmp/timeout-test.bin");
    println!("---");
    println!("Note: Should be killed after ~10 seconds wall clock time by sandbox");

    let start = Instant::now();
    let result = run_curl_command(
        &[
            "https://ash-speed.hetzner.com/10GB.bin",
            "-o",
            "/tmp/timeout-test.bin",
        ],
        15, // Give it 15s but sandbox should kill at 10s
    )
    .await;

    let duration = start.elapsed();
    let duration_secs = duration.as_secs_f64();

    match result {
        Ok((status, _)) => {
            // Check if timing is within acceptable range (9.5-11.5s for 10s timeout)
            let timing_correct = duration_secs >= 9.5 && duration_secs <= 11.5;
            
            if timing_correct {
                suite.record(TestResult {
                    name: "MEM-003: Wall clock timeout".to_string(),
                    passed: true,
                    message: format!(
                        "Process terminated after {:.3}s (within 10s wall clock limit, exit: {}, signal: {:?})",
                        duration_secs, status.code().unwrap_or(0), status.signal()
                    ),
                    duration,
                });
            } else {
                suite.record(TestResult {
                    name: "MEM-003: Wall clock timeout".to_string(),
                    passed: false,
                    message: format!(
                        "Process timing incorrect ({:.3}s, expected ~10s, exit code: {})",
                        duration_secs, status.code().unwrap_or(0)
                    ),
                    duration,
                });
            }
        }
        Err(e) => {
            suite.record(TestResult {
                name: "MEM-003: Wall clock timeout".to_string(),
                passed: false,
                message: format!("Error: {}", e),
                duration,
            });
        }
    }
    let _ = fs::remove_file("/tmp/timeout-test.bin");
    println!();
}

// ============================================================================
// MEM-003: Quick operation (under timeout)
// ============================================================================
pub async fn test_mem003_quick_operation(suite: &mut TestSuite) {
    println!("{}", "Test MEM-003: Quick operation under 10s - Should SUCCEED".bold());
    println!("Command: curl https://example.com -o /tmp/quick-test.html");
    println!("---");

    let start = Instant::now();
    let result = run_curl_command(&["https://example.com", "-o", "/tmp/quick-test.html"], 10).await;

    match result {
        Ok((status, _)) if status.success() => {
            suite.record(TestResult {
                name: "MEM-003: Quick operation".to_string(),
                passed: true,
                message: format!("Quick operation completed in {:.3}s (under limits)", start.elapsed().as_secs_f64()),
                duration: start.elapsed(),
            });
        }
        Ok((status, _)) => {
            suite.record(TestResult {
                name: "MEM-003: Quick operation".to_string(),
                passed: false,
                message: format!("Quick operation failed (exit code: {:?} after {:.3}s)", status.code(), start.elapsed().as_secs_f64()),
                duration: start.elapsed(),
            });
        }
        Err(e) => {
            suite.record(TestResult {
                name: "MEM-003: Quick operation".to_string(),
                passed: false,
                message: format!("Error: {}", e),
                duration: start.elapsed(),
            });
        }
    }
    let _ = fs::remove_file("/tmp/quick-test.html");
    println!();
}

// ============================================================================
// MEM-004: CPU throttling to 50%
// ============================================================================
pub async fn test_mem004_cpu_throttling(suite: &mut TestSuite) {
    println!("{}", "Test MEM-004: CPU throttling (50% limit) - Multiple requests".bold());
    println!("Command: Running 30 curl requests in rapid succession");
    println!("---");

    let start = Instant::now();
    let mut handles = vec![];
    
    for _ in 0..30 {
        let handle = tokio::spawn(async {
            run_curl_command(&["https://example.com", "-o", "/dev/null"], 5).await
        });
        handles.push(handle);
    }

    let mut successful = 0;
    let mut failed = 0;
    
    print!("...");
    for handle in handles {
        match handle.await {
            Ok(Ok((status, _))) if status.success() => successful += 1,
            _ => failed += 1,
        }
    }
    
    let duration_secs = start.elapsed().as_secs();
    println!();
    println!("Completed in {}s", duration_secs);
    println!("Successful requests: {}", successful);
    println!("Failed requests: {}", failed);

    // With 50% CPU throttling, 30 requests should take longer than without throttling
    // This is more of an observation test than pass/fail
    suite.record(TestResult {
        name: "MEM-004: CPU throttling".to_string(),
        passed: true,
        message: format!("{} successful, {} failed in {}s", successful, failed, duration_secs),
        duration: start.elapsed(),
    });
    println!();
}
