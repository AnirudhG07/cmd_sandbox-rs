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
    println!("Command: curl https://example.com -o /tmp/curl_downloads/test-https.html");
    println!("---");

    let start = Instant::now();
    let result = run_curl_command(&["https://example.com", "-o", "/tmp/curl_downloads/test-https.html"], 10).await;

    match result {
        Ok((status, _)) if status.success() => {
            let file_size = fs::metadata("/tmp/curl_downloads/test-https.html")
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
    let _ = fs::remove_file("/tmp/curl_downloads/test-https.html");
    println!();
}

pub async fn test_net006_http_blocked(suite: &mut TestSuite) {
    println!("{}", "Test NET-006.2: HTTP (port 80) - Should FAIL".bold());
    println!("Command: curl http://neverssl.com -o /tmp/curl_downloads/test-http.html");
    println!("---");

    let start = Instant::now();
    let result = run_curl_command(&["http://neverssl.com", "-o", "/tmp/curl_downloads/test-http.html"], 10).await;

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
    let _ = fs::remove_file("/tmp/curl_downloads/test-http.html");
    println!();
}

// ============================================================================
// NET-002: Protocol Blocking Tests (FTP, SFTP, Telnet)
// ============================================================================
pub async fn test_net002_ftp_blocked(suite: &mut TestSuite) {
    println!("{}", "Test NET-002.1: FTP protocol (port 21) - Should FAIL".bold());
    println!("Command: curl ftp://ftp.gnu.org/ -o /tmp/curl_downloads/test-ftp.html --max-time 5");
    println!("---");

    let start = Instant::now();
    let result = run_curl_command(&[
        "ftp://ftp.gnu.org/",
        "-o", "/tmp/curl_downloads/test-ftp.html",
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
    let _ = fs::remove_file("/tmp/curl_downloads/test-ftp.html");
    println!();
}

pub async fn test_net002_sftp_blocked(suite: &mut TestSuite) {
    println!("{}", "Test NET-002.2: SFTP/SSH protocol (port 22) - Should FAIL".bold());
    println!("Command: curl sftp://test.rebex.net/ -o /tmp/curl_downloads/test-sftp.html --max-time 5");
    println!("---");

    let start = Instant::now();
    let result = run_curl_command(&[
        "sftp://test.rebex.net/",
        "-o", "/tmp/curl_downloads/test-sftp.html",
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
    let _ = fs::remove_file("/tmp/curl_downloads/test-sftp.html");
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
    println!("Command: curl http://192.168.1.1 -o /tmp/curl_downloads/test-private1.html --max-time 5");
    println!("---");

    let start = Instant::now();
    let result = run_curl_command(&[
        "http://192.168.1.1",
        "-o", "/tmp/curl_downloads/test-private1.html",
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
    let _ = fs::remove_file("/tmp/curl_downloads/test-private1.html");
    println!();
}

pub async fn test_net005_block_10_0(suite: &mut TestSuite) {
    println!("{}", "Test NET-005.2: Block 10.x.x.x (private IP) - Should FAIL".bold());
    println!("Command: curl http://10.0.0.1 -o /tmp/curl_downloads/test-private2.html --max-time 5");
    println!("---");

    let start = Instant::now();
    let result = run_curl_command(&[
        "http://10.0.0.1",
        "-o", "/tmp/curl_downloads/test-private2.html",
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
    let _ = fs::remove_file("/tmp/curl_downloads/test-private2.html");
    println!();
}

pub async fn test_net005_block_172_16(suite: &mut TestSuite) {
    println!("{}", "Test NET-005.3: Block 172.16-31.x.x (private IP) - Should FAIL".bold());
    println!("Command: curl http://172.16.0.1 -o /tmp/curl_downloads/test-private3.html --max-time 5");
    println!("---");

    let start = Instant::now();
    let result = run_curl_command(&[
        "http://172.16.0.1",
        "-o", "/tmp/curl_downloads/test-private3.html",
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
    let _ = fs::remove_file("/tmp/curl_downloads/test-private3.html");
    println!();
}

pub async fn test_net005_block_loopback(suite: &mut TestSuite) {
    println!("{}", "Test NET-005.4: Block 127.0.0.1 (loopback) - Should FAIL".bold());
    println!("Command: curl http://127.0.0.1:8080 -o /tmp/curl_downloads/test-loopback.html --max-time 5");
    println!("---");

    let start = Instant::now();
    let result = run_curl_command(&[
        "http://127.0.0.1:8080",
        "-o", "/tmp/curl_downloads/test-loopback.html",
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
    let _ = fs::remove_file("/tmp/curl_downloads/test-loopback.html");
    println!();
}

// ============================================================================
// NET-001: Domain Whitelist (only allowed domains can be accessed)
// ============================================================================
pub async fn test_net001_whitelisted_domain(suite: &mut TestSuite) {
    println!("{}", "Test NET-001.1: Whitelisted domain (example.com) - Should SUCCEED".bold());
    println!("Command: curl https://example.com -o /tmp/curl_downloads/test-whitelist.html");
    println!("---");

    let start = Instant::now();
    let result = run_curl_command(&["https://example.com", "-o", "/tmp/curl_downloads/test-whitelist.html"], 10).await;

    match result {
        Ok((status, _)) if status.success() => {
            let file_size = fs::metadata("/tmp/curl_downloads/test-whitelist.html")
                .map(|m| m.len())
                .unwrap_or(0);
            suite.record(TestResult {
                name: "NET-001: Whitelisted domain allowed".to_string(),
                passed: true,
                message: format!("Downloaded {} bytes from whitelisted domain", file_size),
                duration: start.elapsed(),
            });
        }
        Ok((status, _)) => {
            suite.record(TestResult {
                name: "NET-001: Whitelisted domain allowed".to_string(),
                passed: false,
                message: format!("Whitelisted domain blocked with exit code: {:?}", status.code()),
                duration: start.elapsed(),
            });
        }
        Err(e) => {
            suite.record(TestResult {
                name: "NET-001: Whitelisted domain allowed".to_string(),
                passed: false,
                message: format!("Error: {}", e),
                duration: start.elapsed(),
            });
        }
    }
    
    let _ = fs::remove_file("/tmp/curl_downloads/test-whitelist.html");
    println!();
}

pub async fn test_net001_non_whitelisted_domain(suite: &mut TestSuite) {
    println!("{}", "Test NET-001.2: Non-whitelisted domain (google.com) - Should FAIL".bold());
    println!("Command: curl https://google.com -o /tmp/curl_downloads/test-non-whitelist.html");
    println!("---");

    let start = Instant::now();
    let result = run_curl_command(&["https://google.com", "-o", "/tmp/curl_downloads/test-non-whitelist.html", "--max-time", "5"], 10).await;

    match result {
        Ok((status, _)) if !status.success() => {
            suite.record(TestResult {
                name: "NET-001: Non-whitelisted domain blocked".to_string(),
                passed: true,
                message: format!("Non-whitelisted domain correctly blocked (exit code: {:?})", status.code()),
                duration: start.elapsed(),
            });
        }
        Ok((status, _)) => {
            suite.record(TestResult {
                name: "NET-001: Non-whitelisted domain blocked".to_string(),
                passed: false,
                message: format!("Non-whitelisted domain was NOT blocked! Exit code: {:?}", status.code()),
                duration: start.elapsed(),
            });
        }
        Err(e) => {
            // Timeout is also acceptable (means it was blocked)
            suite.record(TestResult {
                name: "NET-001: Non-whitelisted domain blocked".to_string(),
                passed: true,
                message: format!("Non-whitelisted domain blocked (timeout/error)"),
                duration: start.elapsed(),
            });
        }
    }
    
    let _ = fs::remove_file("/tmp/curl_downloads/test-non-whitelist.html");
    println!();
}
