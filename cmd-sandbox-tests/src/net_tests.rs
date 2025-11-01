use anyhow::Result;
use colored::Colorize;
use std::fs;
use std::time::Instant;
use tokio::process::Command;
use std::time::Duration;

use crate::{TestResult, TestSuite};

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
// NET-006: Allow only HTTPS (port 443) and DNS (port 53)
// ============================================================================
pub async fn test_net006_https_allowed(suite: &mut TestSuite) {
    println!("{}", "Test NET-006.1: HTTPS (port 443) - Should SUCCEED".bold());
    println!("Command: curl https://example.com -o /tmp/test-https.html");
    println!("---");

    let start = Instant::now();
    let result = run_curl_command(&["https://example.com", "-o", "/tmp/test-https.html"], 10).await;

    match result {
        Ok((status, _)) if status.success() => {
            let file_size = fs::metadata("/tmp/test-https.html")
                .map(|m| m.len())
                .unwrap_or(0);
            suite.record(TestResult {
                name: "NET-006: HTTPS allowed".to_string(),
                passed: true,
                message: format!("Downloaded {} bytes via HTTPS", file_size),
                duration: start.elapsed(),
            });
        }
        Ok((status, _)) => {
            suite.record(TestResult {
                name: "NET-006: HTTPS allowed".to_string(),
                passed: false,
                message: format!("HTTPS request failed with exit code: {:?}", status.code()),
                duration: start.elapsed(),
            });
        }
        Err(e) => {
            suite.record(TestResult {
                name: "NET-006: HTTPS allowed".to_string(),
                passed: false,
                message: format!("Error: {}", e),
                duration: start.elapsed(),
            });
        }
    }
    let _ = fs::remove_file("/tmp/test-https.html");
    println!();
}

pub async fn test_net006_http_blocked(suite: &mut TestSuite) {
    println!("{}", "Test NET-006.2: HTTP (port 80) - Should FAIL".bold());
    println!("Command: curl http://neverssl.com -o /tmp/test-http.html");
    println!("---");

    let start = Instant::now();
    let result = run_curl_command(&["http://neverssl.com", "-o", "/tmp/test-http.html"], 10).await;

    match result {
        Ok((status, _)) if !status.success() => {
            suite.record(TestResult {
                name: "NET-006: HTTP blocked".to_string(),
                passed: true,
                message: format!("HTTP blocked (exit code: {:?})", status.code()),
                duration: start.elapsed(),
            });
        }
        Ok((status, _)) => {
            suite.record(TestResult {
                name: "NET-006: HTTP blocked".to_string(),
                passed: false,
                message: format!("HTTP was not blocked (exit code: {:?})", status.code()),
                duration: start.elapsed(),
            });
        }
        Err(e) => {
            suite.record(TestResult {
                name: "NET-006: HTTP blocked".to_string(),
                passed: false,
                message: format!("Error: {}", e),
                duration: start.elapsed(),
            });
        }
    }
    let _ = fs::remove_file("/tmp/test-http.html");
    println!();
}

// ============================================================================
// NET-002: Protocol Blocking Tests (FTP, SFTP, Telnet)
// ============================================================================
pub async fn test_net002_ftp_blocked(suite: &mut TestSuite) {
    println!("{}", "Test NET-002.1: FTP protocol (port 21) - Should FAIL".bold());
    println!("Command: curl ftp://ftp.gnu.org/ -o /tmp/test-ftp.html --max-time 5");
    println!("---");

    let start = Instant::now();
    let result = run_curl_command(&[
        "ftp://ftp.gnu.org/",
        "-o", "/tmp/test-ftp.html",
        "--max-time", "5"
    ], 10).await;

    match result {
        Ok((status, _)) if !status.success() => {
            suite.record(TestResult {
                name: "NET-002: FTP blocked".to_string(),
                passed: true,
                message: format!("FTP correctly blocked (exit code: {:?})", status.code()),
                duration: start.elapsed(),
            });
        }
        Ok((status, _)) => {
            suite.record(TestResult {
                name: "NET-002: FTP blocked".to_string(),
                passed: false,
                message: format!("FTP was NOT blocked (exit code: {:?})", status.code()),
                duration: start.elapsed(),
            });
        }
        Err(e) => {
            suite.record(TestResult {
                name: "NET-002: FTP blocked".to_string(),
                passed: true,
                message: format!("FTP blocked with error: {}", e),
                duration: start.elapsed(),
            });
        }
    }
    let _ = fs::remove_file("/tmp/test-ftp.html");
    println!();
}

pub async fn test_net002_sftp_blocked(suite: &mut TestSuite) {
    println!("{}", "Test NET-002.2: SFTP/SSH protocol (port 22) - Should FAIL".bold());
    println!("Command: curl sftp://test.rebex.net/ -o /tmp/test-sftp.html --max-time 5");
    println!("---");

    let start = Instant::now();
    let result = run_curl_command(&[
        "sftp://test.rebex.net/",
        "-o", "/tmp/test-sftp.html",
        "--max-time", "5"
    ], 10).await;

    match result {
        Ok((status, _)) if !status.success() => {
            suite.record(TestResult {
                name: "NET-002: SFTP blocked".to_string(),
                passed: true,
                message: format!("SFTP correctly blocked (exit code: {:?})", status.code()),
                duration: start.elapsed(),
            });
        }
        Ok((status, _)) => {
            suite.record(TestResult {
                name: "NET-002: SFTP blocked".to_string(),
                passed: false,
                message: format!("SFTP was NOT blocked (exit code: {:?})", status.code()),
                duration: start.elapsed(),
            });
        }
        Err(e) => {
            suite.record(TestResult {
                name: "NET-002: SFTP blocked".to_string(),
                passed: true,
                message: format!("SFTP blocked with error: {}", e),
                duration: start.elapsed(),
            });
        }
    }
    let _ = fs::remove_file("/tmp/test-sftp.html");
    println!();
}

pub async fn test_net002_telnet_blocked(suite: &mut TestSuite) {
    println!("{}", "Test NET-002.3: Telnet protocol (port 23) - Should FAIL".bold());
    println!("Command: curl telnet://telnetmyip.com --max-time 5");
    println!("---");

    let start = Instant::now();
    let result = run_curl_command(&[
        "telnet://telnetmyip.com",
        "--max-time", "5"
    ], 10).await;

    match result {
        Ok((status, _)) if !status.success() => {
            suite.record(TestResult {
                name: "NET-002: Telnet blocked".to_string(),
                passed: true,
                message: format!("Telnet correctly blocked (exit code: {:?})", status.code()),
                duration: start.elapsed(),
            });
        }
        Ok((status, _)) => {
            suite.record(TestResult {
                name: "NET-002: Telnet blocked".to_string(),
                passed: false,
                message: format!("Telnet was NOT blocked (exit code: {:?})", status.code()),
                duration: start.elapsed(),
            });
        }
        Err(e) => {
            suite.record(TestResult {
                name: "NET-002: Telnet blocked".to_string(),
                passed: true,
                message: format!("Telnet blocked with error: {}", e),
                duration: start.elapsed(),
            });
        }
    }
    println!();
}

// ============================================================================
// NET-005: Private IP Blocking Tests
// ============================================================================
pub async fn test_net005_block_192_168(suite: &mut TestSuite) {
    println!("{}", "Test NET-005.1: Block 192.168.x.x (private IP) - Should FAIL".bold());
    println!("Command: curl http://192.168.1.1 -o /tmp/test-private1.html --max-time 5");
    println!("---");

    let start = Instant::now();
    let result = run_curl_command(&[
        "http://192.168.1.1",
        "-o", "/tmp/test-private1.html",
        "--max-time", "5"
    ], 10).await;

    match result {
        Ok((status, _)) if !status.success() => {
            suite.record(TestResult {
                name: "NET-005: Block 192.168.x.x".to_string(),
                passed: true,
                message: format!("192.168.x.x correctly blocked (exit code: {:?})", status.code()),
                duration: start.elapsed(),
            });
        }
        Ok((status, _)) => {
            suite.record(TestResult {
                name: "NET-005: Block 192.168.x.x".to_string(),
                passed: false,
                message: format!("192.168.x.x was NOT blocked (exit code: {:?})", status.code()),
                duration: start.elapsed(),
            });
        }
        Err(e) => {
            suite.record(TestResult {
                name: "NET-005: Block 192.168.x.x".to_string(),
                passed: true,
                message: format!("192.168.x.x blocked with error: {}", e),
                duration: start.elapsed(),
            });
        }
    }
    let _ = fs::remove_file("/tmp/test-private1.html");
    println!();
}

pub async fn test_net005_block_10_0(suite: &mut TestSuite) {
    println!("{}", "Test NET-005.2: Block 10.x.x.x (private IP) - Should FAIL".bold());
    println!("Command: curl http://10.0.0.1 -o /tmp/test-private2.html --max-time 5");
    println!("---");

    let start = Instant::now();
    let result = run_curl_command(&[
        "http://10.0.0.1",
        "-o", "/tmp/test-private2.html",
        "--max-time", "5"
    ], 10).await;

    match result {
        Ok((status, _)) if !status.success() => {
            suite.record(TestResult {
                name: "NET-005: Block 10.x.x.x".to_string(),
                passed: true,
                message: format!("10.x.x.x correctly blocked (exit code: {:?})", status.code()),
                duration: start.elapsed(),
            });
        }
        Ok((status, _)) => {
            suite.record(TestResult {
                name: "NET-005: Block 10.x.x.x".to_string(),
                passed: false,
                message: format!("10.x.x.x was NOT blocked (exit code: {:?})", status.code()),
                duration: start.elapsed(),
            });
        }
        Err(e) => {
            suite.record(TestResult {
                name: "NET-005: Block 10.x.x.x".to_string(),
                passed: true,
                message: format!("10.x.x.x blocked with error: {}", e),
                duration: start.elapsed(),
            });
        }
    }
    let _ = fs::remove_file("/tmp/test-private2.html");
    println!();
}

pub async fn test_net005_block_172_16(suite: &mut TestSuite) {
    println!("{}", "Test NET-005.3: Block 172.16-31.x.x (private IP) - Should FAIL".bold());
    println!("Command: curl http://172.16.0.1 -o /tmp/test-private3.html --max-time 5");
    println!("---");

    let start = Instant::now();
    let result = run_curl_command(&[
        "http://172.16.0.1",
        "-o", "/tmp/test-private3.html",
        "--max-time", "5"
    ], 10).await;

    match result {
        Ok((status, _)) if !status.success() => {
            suite.record(TestResult {
                name: "NET-005: Block 172.16-31.x.x".to_string(),
                passed: true,
                message: format!("172.16-31.x.x correctly blocked (exit code: {:?})", status.code()),
                duration: start.elapsed(),
            });
        }
        Ok((status, _)) => {
            suite.record(TestResult {
                name: "NET-005: Block 172.16-31.x.x".to_string(),
                passed: false,
                message: format!("172.16-31.x.x was NOT blocked (exit code: {:?})", status.code()),
                duration: start.elapsed(),
            });
        }
        Err(e) => {
            suite.record(TestResult {
                name: "NET-005: Block 172.16-31.x.x".to_string(),
                passed: true,
                message: format!("172.16-31.x.x blocked with error: {}", e),
                duration: start.elapsed(),
            });
        }
    }
    let _ = fs::remove_file("/tmp/test-private3.html");
    println!();
}

pub async fn test_net005_block_loopback(suite: &mut TestSuite) {
    println!("{}", "Test NET-005.4: Block 127.0.0.1 (loopback) - Should FAIL".bold());
    println!("Command: curl http://127.0.0.1:8080 -o /tmp/test-loopback.html --max-time 5");
    println!("---");

    let start = Instant::now();
    let result = run_curl_command(&[
        "http://127.0.0.1:8080",
        "-o", "/tmp/test-loopback.html",
        "--max-time", "5"
    ], 10).await;

    match result {
        Ok((status, _)) if !status.success() => {
            suite.record(TestResult {
                name: "NET-005: Block loopback".to_string(),
                passed: true,
                message: format!("Loopback correctly blocked (exit code: {:?})", status.code()),
                duration: start.elapsed(),
            });
        }
        Ok((status, _)) => {
            suite.record(TestResult {
                name: "NET-005: Block loopback".to_string(),
                passed: false,
                message: format!("Loopback was NOT blocked (exit code: {:?})", status.code()),
                duration: start.elapsed(),
            });
        }
        Err(e) => {
            suite.record(TestResult {
                name: "NET-005: Block loopback".to_string(),
                passed: true,
                message: format!("Loopback blocked with error: {}", e),
                duration: start.elapsed(),
            });
        }
    }
    let _ = fs::remove_file("/tmp/test-loopback.html");
    println!();
}

// ============================================================================
// NET-004: Concurrent Connection Limit (max 3 connections)
// ============================================================================
pub async fn test_net004_within_limit(suite: &mut TestSuite) {
    println!("{}", "Test NET-004.1: 2 concurrent connections - Should SUCCEED".bold());
    println!("Command: Running 2 concurrent curl requests");
    println!("---");

    let start = Instant::now();
    
    // Start 2 concurrent requests (both should succeed since limit is 3)
    let handle1 = tokio::spawn(async {
        run_curl_command(&["https://example.com", "-o", "/tmp/test-conn1.html"], 10).await
    });
    
    let handle2 = tokio::spawn(async {
        run_curl_command(&["https://example.com", "-o", "/tmp/test-conn2.html"], 10).await
    });
    
    let (result1, result2) = tokio::join!(handle1, handle2);
    
    let success1 = result1.ok().and_then(|r| r.ok()).map(|(s, _)| s.success()).unwrap_or(false);
    let success2 = result2.ok().and_then(|r| r.ok()).map(|(s, _)| s.success()).unwrap_or(false);
    
    suite.record(TestResult {
        name: "NET-004: 2 concurrent connections".to_string(),
        passed: success1 && success2,
        message: format!("Conn1: {}, Conn2: {} (both should succeed)", 
                        if success1 { "✓" } else { "✗" },
                        if success2 { "✓" } else { "✗" }),
        duration: start.elapsed(),
    });
    
    let _ = fs::remove_file("/tmp/test-conn1.html");
    let _ = fs::remove_file("/tmp/test-conn2.html");
    println!();
}

pub async fn test_net004_at_limit(suite: &mut TestSuite) {
    println!("{}", "Test NET-004.2: 3 concurrent connections (at limit) - Should SUCCEED".bold());
    println!("Command: Running 3 concurrent curl requests");
    println!("---");

    let start = Instant::now();
    
    // Start 3 concurrent requests (all should succeed since limit is exactly 3)
    let handle1 = tokio::spawn(async {
        run_curl_command(&["https://example.com", "-o", "/tmp/test-conn1.html"], 10).await
    });
    
    let handle2 = tokio::spawn(async {
        run_curl_command(&["https://example.com", "-o", "/tmp/test-conn2.html"], 10).await
    });
    
    let handle3 = tokio::spawn(async {
        run_curl_command(&["https://example.com", "-o", "/tmp/test-conn3.html"], 10).await
    });
    
    let (result1, result2, result3) = tokio::join!(handle1, handle2, handle3);
    
    let success1 = result1.ok().and_then(|r| r.ok()).map(|(s, _)| s.success()).unwrap_or(false);
    let success2 = result2.ok().and_then(|r| r.ok()).map(|(s, _)| s.success()).unwrap_or(false);
    let success3 = result3.ok().and_then(|r| r.ok()).map(|(s, _)| s.success()).unwrap_or(false);
    
    suite.record(TestResult {
        name: "NET-004: 3 concurrent connections".to_string(),
        passed: success1 && success2 && success3,
        message: format!("Conn1: {}, Conn2: {}, Conn3: {} (all should succeed)", 
                        if success1 { "✓" } else { "✗" },
                        if success2 { "✓" } else { "✗" },
                        if success3 { "✓" } else { "✗" }),
        duration: start.elapsed(),
    });
    
    let _ = fs::remove_file("/tmp/test-conn1.html");
    let _ = fs::remove_file("/tmp/test-conn2.html");
    let _ = fs::remove_file("/tmp/test-conn3.html");
    println!();
}

pub async fn test_net004_exceed_limit(suite: &mut TestSuite) {
    println!("{}", "Test NET-004.3: 4 concurrent connections (exceed limit) - Should PARTIALLY FAIL".bold());
    println!("Command: Running 4 concurrent curl requests (1 should fail)");
    println!("---");

    let start = Instant::now();
    
    // Start 4 concurrent requests - the 4th should fail
    // Note: Due to timing, we can't guarantee which one fails, 
    // but at least one should fail
    let handles: Vec<_> = (0..4).map(|i| {
        tokio::spawn(async move {
            run_curl_command(
                &["https://example.com", "-o", &format!("/tmp/test-conn{}.html", i)],
                10
            ).await
        })
    }).collect();
    
    let results = futures::future::join_all(handles).await;
    
    let successes: Vec<bool> = results.iter()
        .map(|r| r.as_ref().ok()
             .and_then(|res| res.as_ref().ok())
             .map(|(s, _)| s.success())
             .unwrap_or(false))
        .collect();
    
    let success_count = successes.iter().filter(|&&s| s).count();
    let fail_count = successes.len() - success_count;
    
    // Test passes if we have exactly 3 successes and 1 failure
    let test_passed = success_count == 3 && fail_count == 1;
    
    suite.record(TestResult {
        name: "NET-004: Exceed concurrent connection limit".to_string(),
        passed: test_passed,
        message: format!("{} succeeded, {} failed (expected: 3 success, 1 fail)", 
                        success_count, fail_count),
        duration: start.elapsed(),
    });
    
    for i in 0..4 {
        let _ = fs::remove_file(format!("/tmp/test-conn{}.html", i));
    }
    println!();
}
