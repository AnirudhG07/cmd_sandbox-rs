use std::process::Command;
use std::path::Path;
use std::fs;

/// FS-001: Write to allowed directory should succeed
pub fn test_fs001_write_to_allowed_dir() {
    println!("\n[FS-001.1] Testing write to allowed directory (/tmp/cmd_sandbox_downloads)");
    
    // Ensure the directory exists
    let _ = fs::create_dir_all("/tmp/cmd_sandbox_downloads");
    
    let output_file = "/tmp/cmd_sandbox_downloads/test.html";
    
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
        println!("  ✅ PASS: File was created in allowed directory");
        let _ = fs::remove_file(output_file);
    } else {
        println!("  ❌ FAIL: File was not created (should be allowed)");
        println!("  curl exit code: {}", output.status);
    }
}

/// FS-001: Write to /tmp root should be blocked
pub fn test_fs001_write_to_tmp_root() {
    println!("\n[FS-001.2] Testing write to /tmp root (should be blocked)");
    
    let output_file = "/tmp/blocked_test.html";
    
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
    
    if !file_exists {
        println!("  ✅ PASS: Write was blocked");
    } else {
        println!("  ❌ FAIL: File was created (should be blocked)");
        let _ = fs::remove_file(output_file);
    }
}

/// FS-001: Write to home directory should be blocked
pub fn test_fs001_write_to_home() {
    println!("\n[FS-001.3] Testing write to home directory (should be blocked)");
    
    let home_dir = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
    let output_file = format!("{}/blocked_test.html", home_dir);
    
    // Clean up any existing file
    let _ = fs::remove_file(&output_file);
    
    let output = Command::new("curl")
        .args(&[
            "-o", &output_file,
            "https://example.com",
            "--max-time", "10",
        ])
        .output()
        .expect("Failed to execute curl");
    
    let file_exists = Path::new(&output_file).exists();
    
    if !file_exists {
        println!("  ✅ PASS: Write was blocked");
    } else {
        println!("  ❌ FAIL: File was created (should be blocked)");
        let _ = fs::remove_file(&output_file);
    }
}

/// FS-001: Write to /etc should be blocked (even though permission would deny it anyway)
pub fn test_fs001_write_to_etc() {
    println!("\n[FS-001.4] Testing write to /etc (should be blocked)");
    
    let output_file = "/etc/blocked_test.html";
    
    let output = Command::new("curl")
        .args(&[
            "-o", output_file,
            "https://example.com",
            "--max-time", "10",
        ])
        .output()
        .expect("Failed to execute curl");
    
    let file_exists = Path::new(output_file).exists();
    
    if !file_exists {
        println!("  ✅ PASS: Write was blocked");
    } else {
        println!("  ❌ FAIL: File was created (should be blocked)");
        let _ = fs::remove_file(output_file);
    }
}
