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
