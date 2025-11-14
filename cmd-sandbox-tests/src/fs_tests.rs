use colored::Colorize;
use std::process::Command;
use std::path::Path;
use std::fs;
use std::time::Instant;

use crate::{TestResult, TestSuite};

// ===========================================================================
// FS-001: Allow file writes only to /tmp/curl_downloads/ directory (RESTRICT)
// ===========================================================================

/// Test FS-001.1: Write to allowed directory should succeed
pub fn test_fs001_write_to_allowed_dir(suite: &mut TestSuite) {
    println!("{}", "[FS-001.1] Write to allowed directory (/tmp/curl_downloads)".bold());
    println!("  Policy: Allow file writes only to /tmp/curl_downloads/ directory");
    println!("  Expected: File should be created successfully");
    println!("---");
    
    let start = Instant::now();
    
    // Ensure the directory exists
    let _ = fs::create_dir_all("/tmp/curl_downloads");
    
    let output_file = "/tmp/curl_downloads/test.html";
    
    // Clean up any existing file
    let _ = fs::remove_file(output_file);
    
    let output = Command::new("curl")
        .args(&[
            "-o", output_file,
            "https://example.com",
            "--max-time", "10",
        ])
        .output()
        .expect("Failed to execute curl");
    
    let file_exists = Path::new(output_file).exists();
    
    if file_exists {
        let file_size = fs::metadata(output_file).map(|m| m.len()).unwrap_or(0);
        suite.record(TestResult {
            name: "FS-001.1: Write to allowed directory".to_string(),
            passed: true,
            message: format!("File created successfully ({} bytes)", file_size),
            duration: start.elapsed(),
        });
        let _ = fs::remove_file(output_file);
    } else {
        suite.record(TestResult {
            name: "FS-001.1: Write to allowed directory".to_string(),
            passed: false,
            message: format!("File not created - curl exit code: {:?}", output.status.code()),
            duration: start.elapsed(),
        });
    }
}

/// Test FS-001.2: Write to /tmp root should be BLOCKED
pub fn test_fs001_write_to_tmp_root(suite: &mut TestSuite) {
    println!("{}", "[FS-001.2] Write to /tmp root (should be BLOCKED)".bold());
    println!("  Policy: Only /tmp/curl_downloads/ is allowed, not /tmp/");
    println!("  Expected: Write should be blocked by eBPF LSM");
    println!("---");
    
    let start = Instant::now();
    let output_file = "/tmp/blocked_test.html";
    
    // Clean up any existing file
    let _ = fs::remove_file(output_file);
    
    let _output = Command::new("curl")
        .args(&[
            "-o", output_file,
            "https://example.com",
            "--max-time", "10",
        ])
        .output()
        .expect("Failed to execute curl");
    
    let file_exists = Path::new(output_file).exists();
    
    if !file_exists {
        suite.record(TestResult {
            name: "FS-001.2: Block write to /tmp root".to_string(),
            passed: true,
            message: "Write correctly blocked by eBPF LSM".to_string(),
            duration: start.elapsed(),
        });
    } else {
        suite.record(TestResult {
            name: "FS-001.2: Block write to /tmp root".to_string(),
            passed: false,
            message: "File was created (should have been blocked)".to_string(),
            duration: start.elapsed(),
        });
        let _ = fs::remove_file(output_file);
    }
}

/// Test FS-001.3: Write to home directory should be BLOCKED
pub fn test_fs001_write_to_home(suite: &mut TestSuite) {
    println!("{}", "[FS-001.3] Write to home directory (should be BLOCKED)".bold());
    println!("  Policy: Writes only allowed to /tmp/curl_downloads/");
    println!("  Expected: Write to home should be blocked");
    println!("---");
    
    let start = Instant::now();
    let home_dir = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
    let output_file = format!("{}/blocked_test.html", home_dir);
    
    // Clean up any existing file
    let _ = fs::remove_file(&output_file);
    
    let _output = Command::new("curl")
        .args(&[
            "-o", &output_file,
            "https://example.com",
            "--max-time", "10",
        ])
        .output()
        .expect("Failed to execute curl");
    
    let file_exists = Path::new(&output_file).exists();
    
    if !file_exists {
        suite.record(TestResult {
            name: "FS-001.3: Block write to home".to_string(),
            passed: true,
            message: "Write correctly blocked by eBPF LSM".to_string(),
            duration: start.elapsed(),
        });
    } else {
        suite.record(TestResult {
            name: "FS-001.3: Block write to home".to_string(),
            passed: false,
            message: "File was created (should have been blocked)".to_string(),
            duration: start.elapsed(),
        });
        let _ = fs::remove_file(&output_file);
    }
}

// ===========================================================================
// FS-003: Maximum file download size: 10MB per file (QUOTA)
// ===========================================================================

/// Test FS-003: Download file larger than 10MB should be blocked
pub fn test_fs003_max_file_size(suite: &mut TestSuite) {
    println!("{}", "[FS-003] Maximum file download size (10MB limit)".bold());
    println!("  Policy: Maximum file download size: 10MB per file");
    println!("  Expected: Download >10MB should fail or be truncated");
    println!("---");
    
    let start = Instant::now();
    let output_file = "/tmp/curl_downloads/large_file.bin";
    let _ = fs::remove_file(output_file);
    
    // Try to download a large file (100MB test file)
    let _output = Command::new("curl")
        .args(&[
            "-o", output_file,
            "https://ash-speed.hetzner.com/100MB.bin",
            "--max-time", "15",
        ])
        .output()
        .expect("Failed to execute curl");
    
    if let Ok(metadata) = fs::metadata(output_file) {
        let file_size = metadata.len();
        let max_size = 10 * 1024 * 1024; // 10MB
        
        if file_size <= max_size {
            suite.record(TestResult {
                name: "FS-003: Max file size (10MB)".to_string(),
                passed: true,
                message: format!("File size limited to {}MB", file_size / (1024 * 1024)),
                duration: start.elapsed(),
            });
        } else {
            suite.record(TestResult {
                name: "FS-003: Max file size (10MB)".to_string(),
                passed: false,
                message: format!("File size {}MB exceeds 10MB limit", file_size / (1024 * 1024)),
                duration: start.elapsed(),
            });
        }
        let _ = fs::remove_file(output_file);
    } else {
        suite.record(TestResult {
            name: "FS-003: Max file size (10MB)".to_string(),
            passed: true,
            message: "Download failed or was prevented (no large file created)".to_string(),
            duration: start.elapsed(),
        });
    }
}

// ===========================================================================
// FS-004: Prevent execution of downloaded files (BLOCK)
// ===========================================================================

/// Test FS-004: Attempt to execute downloaded file should be blocked
pub fn test_fs004_prevent_execution(suite: &mut TestSuite) {
    println!("{}", "[FS-004] Prevention of downloaded file execution".bold());
    println!("  Policy: Prevent execution of downloaded files");
    println!("  Expected: Downloaded files should not be executable");
    println!("---");
    
    let start = Instant::now();
    let script_file = "/tmp/curl_downloads/test_script.sh";

    // Create a simple test script
    let script_content = "#!/bin/bash\necho 'This should not execute'\n";
    let (passed, message) = if fs::write(script_file, script_content).is_ok() {
        // Try to make it executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = fs::metadata(script_file) {
                let mut perms = metadata.permissions();
                perms.set_mode(0o755);
                let _ = fs::set_permissions(script_file, perms);
            }
        }
        
        // Try to execute it
        let output = Command::new(script_file)
            .output();
        
        let result = match output {
            Err(_) => {
                (true, "Execution prevented (file cannot be executed)".to_string())
            }
            Ok(result) => {
                if !result.status.success() {
                    (true, "Execution failed (blocked by eBPF)".to_string())
                } else {
                    (false, "Script executed successfully (should have been blocked)".to_string())
                }
            }
        };
        
        let _ = fs::remove_file(script_file);
        result
    } else {
        (false, "Could not create test file (test skipped)".to_string())
    };
    
    println!("  {}", if passed { "✅ PASS".green() } else { "⚠️  WARNING".yellow() });
    println!("  {}", message);
    
    suite.record(TestResult {
        name: "FS-004: Prevent execution of downloaded files".to_string(),
        passed,
        message,
        duration: start.elapsed(),
    });
}

// ===========================================================================
// FS-005: Restrict total storage usage to 50MB (QUOTA)
// ===========================================================================

/// Test FS-005: Total storage usage should not exceed 50MB
pub fn test_fs005_total_storage_quota(suite: &mut TestSuite) {
    println!("{}", "[FS-005] Testing total storage quota (50MB limit)".bold());
    println!("  Policy: Restrict total storage usage to 50MB");
    println!("  Expected: Total files in /tmp/curl_downloads should not exceed 50MB");
    println!("---");
    
    let start = Instant::now();
    
    // Calculate current usage
    let mut total_size: u64 = 0;
    if let Ok(entries) = fs::read_dir("/tmp/curl_downloads") {
        for entry in entries.flatten() {
            if let Ok(metadata) = entry.metadata() {
                total_size += metadata.len();
            }
        }
    }
    
    let max_size = 50 * 1024 * 1024; // 50MB
    let size_mb = total_size as f64 / (1024.0 * 1024.0);
    
    let passed = total_size <= max_size;
    let message = if passed {
        format!("Current usage: {:.2}MB (under 50MB limit)", size_mb)
    } else {
        format!("Current usage: {:.2}MB (exceeds 50MB limit)", size_mb)
    };
    
    println!("  {}", if passed { "✅ PASS".green() } else { "⚠️  WARNING".yellow() });
    println!("  {}", message);
    
    suite.record(TestResult {
        name: "FS-005: Total storage quota".to_string(),
        passed,
        message,
        duration: start.elapsed(),
    });
}

// ===========================================================================
// FS-006: Block access to system directories (BLOCK)
// ===========================================================================

/// Test FS-006.1: Attempt to write to /etc should be blocked
pub fn test_fs006_block_etc_write(suite: &mut TestSuite) {
    println!("{}", "[FS-006.1] Testing write to /etc (should be BLOCKED)".bold());
    println!("  Policy: Block access to system directory /etc/");
    println!("  Expected: Write blocked by eBPF LSM + DAC permissions");
    println!("---");
    
    let start = Instant::now();
    let output_file = "/etc/blocked_test.html";
    
    let _output = Command::new("curl")
        .args(&[
            "-o", output_file,
            "https://example.com",
            "--max-time", "10",
        ])
        .output()
        .expect("Failed to execute curl");
    
    let file_exists = Path::new(output_file).exists();
    
    let passed = !file_exists;
    let message = if passed {
        "Write to /etc was blocked (system directory protected)".to_string()
    } else {
        let _ = fs::remove_file(output_file);
        "File was created in /etc (should have been blocked)".to_string()
    };
    
    println!("  {}", if passed { "✅ PASS".green() } else { "❌ FAIL".red() });
    println!("  {}", message);
    
    suite.record(TestResult {
        name: "FS-006.1: Block write to /etc".to_string(),
        passed,
        message,
        duration: start.elapsed(),
    });
}

/// Test FS-006.2: Attempt to read from /etc should work (read is allowed)
pub fn test_fs006_read_etc_allowed(_suite: &mut TestSuite) {
    println!("{}", "[FS-006.2] Testing read from /etc (should be ALLOWED)".bold());
    println!("  Policy: Block writes to /etc, but reads are allowed");
    println!("  Expected: Read operations should succeed");
    println!("---");
    
    let test_file = "/etc/hostname";
    
    let (passed, _message) = if Path::new(test_file).exists() {
        match fs::read_to_string(test_file) {
            Ok(content) => {
                (true, format!("Read from /etc allowed (content: {})", content.trim()))
            }
            Err(e) => {
                (false, format!("Read failed: {}", e))
            }
        }
    } else {
        (false, "/etc/hostname not found (test skipped)".to_string())
    };
    
    println!("  {}", if passed { "✅ PASS".green() } else { "⚠️  INFO".yellow() });
}

/// Test FS-006.3: Attempt to write to /bin should be blocked
pub fn test_fs006_block_bin_write(suite: &mut TestSuite) {
    println!("{}", "[FS-006.3] Testing write to /bin (should be BLOCKED)".bold());
    println!("  Policy: Block access to system directory /bin/");
    println!("---");
    
    let start = Instant::now();
    let output_file = "/bin/blocked_test";
    
    let _output = Command::new("curl")
        .args(&[
            "-o", output_file,
            "https://example.com",
            "--max-time", "10",
        ])
        .output()
        .expect("Failed to execute curl");
    
    let file_exists = Path::new(output_file).exists();
    
    let passed = !file_exists;
    let message = if passed {
        "Write to /bin was blocked".to_string()
    } else {
        let _ = fs::remove_file(output_file);
        "File was created in /bin (should have been blocked)".to_string()
    };
    
    println!("  {}", if passed { "✅ PASS".green() } else { "❌ FAIL".red() });
    println!("  {}", message);
    
    suite.record(TestResult {
        name: "FS-006.3: Block write to /bin".to_string(),
        passed,
        message,
        duration: start.elapsed(),
    });
}

/// Test FS-006.4: Attempt to write to /usr should be blocked
pub fn test_fs006_block_usr_write(suite: &mut TestSuite) {
    println!("{}", "[FS-006.4] Testing write to /usr (should be BLOCKED)".bold());
    println!("  Policy: Block access to system directory /usr/");
    println!("---");
    
    let start = Instant::now();
    let output_file = "/usr/blocked_test";
    
    let _output = Command::new("curl")
        .args(&[
            "-o", output_file,
            "https://example.com",
            "--max-time", "10",
        ])
        .output()
        .expect("Failed to execute curl");
    
    let file_exists = Path::new(output_file).exists();
    
    let passed = !file_exists;
    let message = if passed {
        "Write to /usr was blocked".to_string()
    } else {
        let _ = fs::remove_file(output_file);
        "File was created in /usr (should have been blocked)".to_string()
    };
    
    println!("  {}", if passed { "✅ PASS".green() } else { "❌ FAIL".red() });
    println!("  {}", message);
    
    suite.record(TestResult {
        name: "FS-006.4: Block write to /usr".to_string(),
        passed,
        message,
        duration: start.elapsed(),
    });
    
    let file_exists = Path::new(output_file).exists();
    
    if !file_exists {
        println!("  ✅ PASS: Write to /usr was blocked");
        println!("  Result: FS-006 enforced");
    } else {
        println!("  ❌ FAIL: File was created in /usr");
        let _ = fs::remove_file(output_file);
    }
}
