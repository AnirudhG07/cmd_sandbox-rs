#[cfg(feature = "user")]
use aya::Pod;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkPolicy {
    pub allowed_ports: [u16; 10],      // Max 10 allowed ports
    pub num_ports: u32,
    pub block_private_ips: u32,        // 0 or 1 (bool)
    pub max_connections: u32,
    pub connection_timeout: u32,
}

#[cfg(feature = "user")]
unsafe impl Pod for NetworkPolicy {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DomainEntry {
    pub domain: [u8; 64],              // Domain name (null-terminated)
    pub enabled: u32,                   // 0 or 1
}

#[cfg(feature = "user")]
unsafe impl Pod for DomainEntry {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FilesystemPolicy {
    pub allowed_write_path: [u8; 256],  // Path prefix that's allowed for writes
    pub path_len: u32,                   // Length of the path string
}

#[cfg(feature = "user")]
unsafe impl Pod for FilesystemPolicy {}

// Structure to track path validation decisions
// Used to pass decisions from tracepoint to LSM hooks
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PathDecision {
    pub allowed: u32,           // 0 = blocked, 1 = allowed
    pub timestamp: u64,         // ktime_get_ns() when decision was made
    pub pid: u32,               // Process ID
    pub tgid: u32,              // Thread group ID
}

#[cfg(feature = "user")]
unsafe impl Pod for PathDecision {}

// Structure to track file write sizes (FS-003: Max file size 10MB)
// Used to enforce maximum download size by tracking cumulative writes
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileSizeTracker {
    pub total_bytes: u64,       // Total bytes written by this process
    pub max_bytes: u64,         // Maximum allowed bytes (10MB = 10485760)
    pub fd: i32,                // File descriptor being tracked
    pub pid: u32,               // Process ID
}

#[cfg(feature = "user")]
unsafe impl Pod for FileSizeTracker {}
