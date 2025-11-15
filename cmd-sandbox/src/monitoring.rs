// Process Monitoring Module
// This module handles monitoring curl/wget processes for policy violations

use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use log::{info, warn, debug};
use crate::cgroup::{CGROUP_NAME, move_to_cgroup};

/// Main process monitoring loop
pub async fn monitor_processes(
    process_tracker: Arc<Mutex<HashMap<String, Instant>>>, 
    wall_clock_limit: Duration,
    max_file_size: u64,
) {
    let mut interval = tokio::time::interval(Duration::from_millis(100));
    
    loop {
        interval.tick().await;
        
        // Scan /proc for curl/wget processes
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(file_name) = entry.file_name().into_string() {
                    // Check if it's a PID directory
                    if file_name.chars().all(|c| c.is_numeric()) {
                        let pid = file_name;
                        let comm_path = format!("/proc/{}/comm", pid);
                        
                        if let Ok(comm) = fs::read_to_string(&comm_path) {
                            let comm = comm.trim();
                            if comm == "curl" || comm == "wget" {
                                // Check if we're tracking this process
                                let mut tracker = process_tracker.lock().unwrap();
                                
                                if let Some(start_time) = tracker.get(&pid) {
                                    // Check if it exceeded wall clock limit
                                    if start_time.elapsed() > wall_clock_limit {
                                        info!("Killing {} (PID {}) - exceeded {}s wall clock limit", 
                                              comm, pid, wall_clock_limit.as_secs());
                                        kill_process(&pid);
                                        tracker.remove(&pid);
                                        continue;
                                    }
                                    
                                    // FS-003/MEM-001: Check if process is writing a file > max_file_size
                                    if let Some(file_size) = check_process_file_size(&pid) {
                                        if file_size > max_file_size {
                                            warn!("FS-003: Killing {} (PID {}) - file size {:.2}MB exceeds {:.2}MB limit", 
                                                  comm, pid, file_size as f64 / (1024.0 * 1024.0), max_file_size as f64 / (1024.0 * 1024.0));
                                            println!("⚠️  FS-003 VIOLATION: {} (PID {}) - file size {:.2}MB > {:.2}MB", 
                                                     comm, pid, file_size as f64 / (1024.0 * 1024.0), max_file_size as f64 / (1024.0 * 1024.0));
                                            kill_process(&pid);
                                            tracker.remove(&pid);
                                        } else if file_size > (max_file_size * 90 / 100) {
                                            // Warn when approaching limit
                                            info!("FS-003: {} (PID {}) approaching limit - {:.2}MB/{:.2}MB", 
                                                  comm, pid, file_size as f64 / (1024.0 * 1024.0), max_file_size as f64 / (1024.0 * 1024.0));
                                        }
                                    }
                                } else {
                                    // New process - track it and move to cgroup
                                    tracker.insert(pid.clone(), Instant::now());
                                    drop(tracker); // Release lock before potentially slow operations
                                    
                                    // SEC-002: Check for sensitive environment variables
                                    check_sensitive_environment(&pid);
                                    
                                    // Check if already in our cgroup
                                    let cgroup_file = format!("/proc/{}/cgroup", pid);
                                    if let Ok(cgroup_content) = fs::read_to_string(&cgroup_file) {
                                        if !cgroup_content.contains(CGROUP_NAME) {
                                            // Move process to limited cgroup
                                            move_to_cgroup(&pid);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            // Clean up tracker for processes that no longer exist
            let mut tracker = process_tracker.lock().unwrap();
            tracker.retain(|pid, _| {
                Path::new(&format!("/proc/{}", pid)).exists()
            });
        }
    }
}

/// Kill a process by PID
pub fn kill_process(pid: &str) {
    if let Ok(pid_num) = pid.parse::<i32>() {
        unsafe {
            libc::kill(pid_num, libc::SIGKILL);
        }
    }
}

/// FS-003: Check if a process has any open files exceeding the configured max_file_size
/// Returns the maximum file size found, or None if no files in /tmp/curl_downloads/
pub fn check_process_file_size(pid: &str) -> Option<u64> {
    // Check open file descriptors in /proc/PID/fd/
    let fd_dir = format!("/proc/{}/fd", pid);
    let mut max_size = 0u64;
    
    if let Ok(entries) = fs::read_dir(&fd_dir) {
        for entry in entries.flatten() {
            if let Ok(link) = fs::read_link(entry.path()) {
                // Check if file is in /tmp/curl_downloads/
                if let Some(path_str) = link.to_str() {
                    if path_str.starts_with("/tmp/curl_downloads/") {
                        // Get file size
                        if let Ok(metadata) = fs::metadata(&link) {
                            let size = metadata.len();
                            if size > max_size {
                                max_size = size;
                            }
                        }
                    }
                }
            }
        }
    }
    
    if max_size > 0 {
        Some(max_size)
    } else {
        None
    }
}

/// SEC-002: Check and log sensitive environment variables containing PASSWORD, KEY, SECRET
pub fn check_sensitive_environment(pid: &str) {
    // Read the process environment
    let env_path = format!("/proc/{}/environ", pid);
    match fs::read(&env_path) {
        Ok(bytes) => {
            let env_str = String::from_utf8_lossy(&bytes);
            let sensitive_vars: Vec<&str> = env_str
                .split('\0')
                .filter(|s| {
                    let upper = s.to_uppercase();
                    (upper.contains("PASSWORD") || upper.contains("KEY") || upper.contains("SECRET")) 
                    && s.contains('=')
                })
                .collect();
            
            if !sensitive_vars.is_empty() {
                warn!("SEC-002 VIOLATION: PID {} has sensitive environment variables:", pid);
                for var in &sensitive_vars {
                    // Only log the variable name, not the value (for security)
                    if let Some(name) = var.split('=').next() {
                        warn!("  - {}", name);
                    }
                }
                warn!("Policy: These variables should be removed before process execution");
            } else {
                info!("✓ SEC-002: No sensitive environment variables detected for PID {}", pid);
            }
        }
        Err(e) => {
            // Process may have terminated
            debug!("Could not read environment for PID {}: {}", pid, e);
        }
    }
}
